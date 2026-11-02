// 信号守卫模块：拦截 SIGSEGV/SIGBUS 并通过 sigsetjmp/siglongjmp 安全恢复
// 支持 sigchain（ART 环境）和 sigaction 两种安装模式

use crate::errno::Errno;
use crate::log;
use crate::runtime::MutexPoisonRecover;
use std::cell::UnsafeCell;
use std::ffi::{CStr, c_void};
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

// 预分配的静态 slot 数量上限
const GUARD_BASE_SLOT_MAX: usize = 64;
// 单线程最大嵌套守卫深度
const GUARD_STACK_DEPTH_MAX: usize = 8;
// 备用信号栈最小尺寸（64KB）
const SIGALTSTACK_MIN_SIZE: usize = 64 * 1024;
// SA_EXPOSE_TAGBITS: 允许信号处理器看到 MTE tag 位
const SA_EXPOSE_TAGBITS: libc::c_int = 0x0000_0800;
const SIGCHAIN_ALLOW_NORETURN: u64 = 1;
const HANDLER_MODE_NONE: usize = 0;
const HANDLER_MODE_SIGACTION: usize = 1;
const HANDLER_MODE_SIGCHAIN: usize = 2;
// dlsym RTLD_NEXT 在部分 Android 版本不可用，使用 -1 作为回退
const RTLD_NEXT_FALLBACK: *mut c_void = (-1isize) as *mut c_void;
// sigchain 库的候选路径，按优先级排列
const SIGCHAIN_LIB_CANDIDATES: [&CStr; 7] = [
    c"libsigchain.so",
    c"libart.so",
    c"libartbase.so",
    c"/apex/com.android.art/lib64/libsigchain.so",
    c"/apex/com.android.art/lib64/libart.so",
    c"/system/lib64/libsigchain.so",
    c"/system/lib64/libart.so",
];

// 信号守卫全局开关
static SIGSEGV_ENABLE: AtomicBool = AtomicBool::new(true);
// 信号处理器引用计数，支持多次 add/remove 配对
static HANDLER_REF_COUNT: AtomicUsize = AtomicUsize::new(0);
static HANDLER_INSTALL_MODE: AtomicUsize = AtomicUsize::new(HANDLER_MODE_NONE);
// 保存被替换的原始 sigaction，用于链式转发和卸载恢复
static SIGSEGV_OLD_ACTION: AtomicPtr<libc::sigaction> = AtomicPtr::new(ptr::null_mut());
static SIGBUS_OLD_ACTION: AtomicPtr<libc::sigaction> = AtomicPtr::new(ptr::null_mut());

// 动态解析的 libc 信号函数指针类型
type SigActionFn =
    unsafe extern "C" fn(libc::c_int, *const libc::sigaction, *mut libc::sigaction) -> libc::c_int;
type SigProcMaskFn =
    unsafe extern "C" fn(libc::c_int, *const libc::sigset_t, *mut libc::sigset_t) -> libc::c_int;

// 动态解析到的 sigaction 和 sigprocmask 函数指针
struct SignalAbiFns {
    sigaction_fn: SigActionFn,
    sigprocmask_fn: SigProcMaskFn,
}

// ART sigchain API 的函数指针类型
type SigchainCallbackFn =
    extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) -> bool;
type AddSpecialSignalHandlerFn = unsafe extern "C" fn(libc::c_int, *mut SigchainAction);
type RemoveSpecialSignalHandlerFn = unsafe extern "C" fn(libc::c_int, SigchainCallbackFn);
type EnsureFrontOfChainFn = unsafe extern "C" fn(libc::c_int);

// 传递给 ART sigchain 的回调注册结构，必须与 C ABI 布局一致
#[repr(C)]
struct SigchainAction {
    sc_sigaction: SigchainCallbackFn,
    sc_mask: libc::sigset_t,
    sc_flags: u64,
}

#[derive(Clone, Copy)]
struct SigchainApiFns {
    add_special_handler_fn: AddSpecialSignalHandlerFn,
    remove_special_handler_fn: RemoveSpecialSignalHandlerFn,
    ensure_front_of_chain_fn: Option<EnsureFrontOfChainFn>,
}

// sigjmp_buf 的字长度，取决于目标架构
const fn sigjmp_buf_words() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        33
    }
    #[cfg(target_arch = "x86_64")]
    {
        12
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        65
    }
}

const SIGJMP_BUF_WORDS: usize = sigjmp_buf_words();

#[repr(C)]
struct SigJmpBuf([libc::c_long; SIGJMP_BUF_WORDS]);

// 每线程的信号守卫上下文，包含 sigsetjmp 环境栈
// tid 用于线程归属，depth 支持嵌套守卫
struct GuardSlot {
    tid: AtomicUsize,
    active: AtomicBool,
    depth: AtomicUsize,
    last_signal: AtomicUsize,
    env_stack: [UnsafeCell<MaybeUninit<SigJmpBuf>>; GUARD_STACK_DEPTH_MAX],
}

unsafe impl Sync for GuardSlot {}

impl GuardSlot {
    const fn new() -> Self {
        Self {
            tid: AtomicUsize::new(0),
            active: AtomicBool::new(false),
            depth: AtomicUsize::new(0),
            last_signal: AtomicUsize::new(0),
            env_stack: [const { UnsafeCell::new(MaybeUninit::uninit()) }; GUARD_STACK_DEPTH_MAX],
        }
    }

    #[inline]
    unsafe fn env_ptr(&self, index: usize) -> *mut SigJmpBuf {
        (*self.env_stack[index].get()).as_mut_ptr()
    }
}

// 动态扩展的 slot 链表节点，当静态 slot 耗尽时使用
struct GuardNode {
    slot: GuardSlot,
    next: AtomicPtr<GuardNode>,
}

impl GuardNode {
    fn new() -> Self {
        Self {
            slot: GuardSlot::new(),
            next: AtomicPtr::new(ptr::null_mut()),
        }
    }
}

// 静态预分配的 slot 数组，避免热路径上的堆分配
static GUARD_BASE_SLOTS: [GuardSlot; GUARD_BASE_SLOT_MAX] =
    [const { GuardSlot::new() }; GUARD_BASE_SLOT_MAX];
// 溢出链表头指针，CAS 无锁追加
static GUARD_EXTRA_HEAD: AtomicPtr<GuardNode> = AtomicPtr::new(ptr::null_mut());

unsafe extern "C" {
    fn sigsetjmp(env: *mut SigJmpBuf, savemask: libc::c_int) -> libc::c_int;
    fn siglongjmp(env: *mut SigJmpBuf, val: libc::c_int) -> !;
}

mod abi;
mod altstack;
mod guard_exec;
mod handlers;
mod sigchain;
mod slot;

fn handler_lock() -> &'static Mutex<()> {
    static HANDLER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    HANDLER_LOCK.get_or_init(|| Mutex::new(()))
}

// 将被替换的原始 sigaction 堆分配后存入原子指针
fn store_old_action(slot: &AtomicPtr<libc::sigaction>, action: libc::sigaction) {
    let action_ptr = Box::into_raw(Box::new(action));
    slot.store(action_ptr, Ordering::Release);
}

pub(super) fn load_sigsegv_old_action() -> *const libc::sigaction {
    SIGSEGV_OLD_ACTION.load(Ordering::Acquire) as *const libc::sigaction
}

pub(super) fn load_sigbus_old_action() -> *const libc::sigaction {
    SIGBUS_OLD_ACTION.load(Ordering::Acquire) as *const libc::sigaction
}

pub fn enable(flag: bool) {
    SIGSEGV_ENABLE.store(flag, Ordering::SeqCst);
}

pub fn is_enabled() -> bool {
    SIGSEGV_ENABLE.load(Ordering::SeqCst)
}

// 安装信号处理器，引用计数管理
// 优先尝试 sigchain 模式（ART 环境），失败则回退 sigaction
pub fn add_handler() -> Result<(), Errno> {
    if !is_enabled() {
        return Ok(());
    }

    let _handler_lock = handler_lock().lock_or_poison();
    let current_count = HANDLER_REF_COUNT.load(Ordering::Acquire);
    if current_count > 0 {
        HANDLER_REF_COUNT.store(current_count.saturating_add(1), Ordering::Release);
        return Ok(());
    }

    if sigchain::install_sigchain_handlers() {
        HANDLER_INSTALL_MODE.store(HANDLER_MODE_SIGCHAIN, Ordering::Release);
        HANDLER_REF_COUNT.store(1, Ordering::Release);
        log::debug(format_args!("signal handlers installed via sigchain"));
        return Ok(());
    }

    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handlers::sigsegv_handler as *const () as usize;
        act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_RESTART | SA_EXPOSE_TAGBITS;
        libc::sigfillset(&mut act.sa_mask);

        let mut old_segv: libc::sigaction = std::mem::zeroed();
        if abi::raw_sigaction(libc::SIGSEGV, &act, &mut old_segv) != 0 {
            return Err(Errno::Unknown);
        }

        act.sa_sigaction = handlers::sigbus_handler as *const () as usize;
        let mut old_bus: libc::sigaction = std::mem::zeroed();
        if abi::raw_sigaction(libc::SIGBUS, &act, &mut old_bus) != 0 {
            let _ = abi::raw_sigaction(libc::SIGSEGV, &old_segv, std::ptr::null_mut());
            return Err(Errno::Unknown);
        }

        store_old_action(&SIGSEGV_OLD_ACTION, old_segv);
        store_old_action(&SIGBUS_OLD_ACTION, old_bus);
    }

    HANDLER_INSTALL_MODE.store(HANDLER_MODE_SIGACTION, Ordering::Release);
    HANDLER_REF_COUNT.store(1, Ordering::Release);
    log::debug(format_args!("signal handlers installed via sigaction"));
    Ok(())
}

// 卸载信号处理器，引用计数归零时恢复原始 handler
pub fn remove_handler() {
    let _handler_lock = handler_lock().lock_or_poison();
    let current_count = HANDLER_REF_COUNT.load(Ordering::Acquire);
    if current_count == 0 {
        return;
    }
    if current_count > 1 {
        HANDLER_REF_COUNT.store(current_count - 1, Ordering::Release);
        return;
    }

    let mode = HANDLER_INSTALL_MODE.load(Ordering::Acquire);
    if mode == HANDLER_MODE_SIGCHAIN {
        let _ = sigchain::remove_sigchain_handlers();
    } else if mode == HANDLER_MODE_SIGACTION {
        unsafe {
            let old = load_sigsegv_old_action();
            if !old.is_null() {
                let _ = abi::raw_sigaction(libc::SIGSEGV, old, std::ptr::null_mut());
            }
            let old_bus = load_sigbus_old_action();
            if !old_bus.is_null() {
                let _ = abi::raw_sigaction(libc::SIGBUS, old_bus, std::ptr::null_mut());
            }
        }
    }
    HANDLER_INSTALL_MODE.store(HANDLER_MODE_NONE, Ordering::Release);
    HANDLER_REF_COUNT.store(0, Ordering::Release);
}

// 在信号守卫保护下执行闭包，捕获 SIGSEGV/SIGBUS 后返回 Err
pub fn with_guard<T, F>(f: F) -> Result<T, Errno>
where
    F: FnOnce() -> T,
{
    guard_exec::with_guard_impl(f)
}
