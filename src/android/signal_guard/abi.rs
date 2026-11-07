// 信号相关系统调用的底层封装
// 动态解析 libc 中的 sigaction/sigprocmask 符号，兼容不同 Android 版本

use crate::errno::Errno;
use crate::log;
use std::ffi::{CStr, c_void};
use std::ptr;
use std::sync::atomic::AtomicPtr;

use super::{SigActionFn, SigProcMaskFn, SignalAbiFns};

// EINTR 重试上限
const EINTR_RETRY_LIMIT: usize = 4;
const RTLD_NEXT_FALLBACK: *mut c_void = (-1isize) as *mut c_void;
// libc.so 的候选路径，覆盖 APEX 和传统路径
const LIBC_PATH_CANDIDATES: [&CStr; 3] = [
    c"libc.so",
    c"/apex/com.android.runtime/lib64/bionic/libc.so",
    c"/system/lib64/libc.so",
];
// 优先 64 位变体（sigaction64），兼容 32 位信号集
const SIGACTION_SYMBOLS: [&CStr; 4] = [
    c"sigaction64",
    c"__sigaction64",
    c"sigaction",
    c"__sigaction",
];
const SIGPROCMASK_SYMBOLS: [&CStr; 4] = [
    c"sigprocmask64",
    c"__sigprocmask64",
    c"sigprocmask",
    c"__sigprocmask",
];

fn signal_abi_fns() -> &'static SignalAbiFns {
    static ABI_FNS: AtomicPtr<SignalAbiFns> = AtomicPtr::new(ptr::null_mut());
    super::published_functions(&ABI_FNS, resolve_signal_abi_fns)
}

pub(super) fn prime() {
    let _ = signal_abi_fns();
}

// 从指定 handle 中按候选符号名列表查找第一个可用的函数指针
fn resolve_symbol_from_handle(handle: *mut c_void, symbols: &[&CStr]) -> *mut c_void {
    if handle.is_null() {
        return ptr::null_mut();
    }
    for symbol in symbols {
        let ptr = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
        if !ptr.is_null() {
            return ptr;
        }
    }
    ptr::null_mut()
}

fn fill_signal_abi_from_handle(
    handle: *mut c_void,
    sigaction_ptr: &mut *mut c_void,
    sigprocmask_ptr: &mut *mut c_void,
) {
    if (*sigaction_ptr).is_null() {
        *sigaction_ptr = resolve_symbol_from_handle(handle, &SIGACTION_SYMBOLS);
    }
    if (*sigprocmask_ptr).is_null() {
        *sigprocmask_ptr = resolve_symbol_from_handle(handle, &SIGPROCMASK_SYMBOLS);
    }
}

fn fill_signal_abi_from_library(
    lib_path: &CStr,
    flags: libc::c_int,
    sigaction_ptr: &mut *mut c_void,
    sigprocmask_ptr: &mut *mut c_void,
) {
    let handle = unsafe { libc::dlopen(lib_path.as_ptr(), flags) };
    if handle.is_null() {
        return;
    }
    fill_signal_abi_from_handle(handle, sigaction_ptr, sigprocmask_ptr);
    unsafe {
        libc::dlclose(handle);
    }
}

// 多策略解析信号 ABI 函数指针
// 查找顺序: RTLD_DEFAULT -> 已加载的 libc -> dlopen libc -> RTLD_NEXT
fn resolve_signal_abi_fns() -> SignalAbiFns {
    let _loader_call = crate::runtime::LoaderCall::enter();
    let mut sigaction_ptr: *mut c_void = ptr::null_mut();
    let mut sigprocmask_ptr: *mut c_void = ptr::null_mut();

    fill_signal_abi_from_handle(libc::RTLD_DEFAULT, &mut sigaction_ptr, &mut sigprocmask_ptr);

    for lib_path in LIBC_PATH_CANDIDATES {
        if !sigaction_ptr.is_null() && !sigprocmask_ptr.is_null() {
            break;
        }
        fill_signal_abi_from_library(
            lib_path,
            libc::RTLD_NOW | libc::RTLD_NOLOAD,
            &mut sigaction_ptr,
            &mut sigprocmask_ptr,
        );
    }

    for lib_path in LIBC_PATH_CANDIDATES {
        if !sigaction_ptr.is_null() && !sigprocmask_ptr.is_null() {
            break;
        }
        fill_signal_abi_from_library(
            lib_path,
            libc::RTLD_NOW,
            &mut sigaction_ptr,
            &mut sigprocmask_ptr,
        );
    }

    if sigaction_ptr.is_null() || sigprocmask_ptr.is_null() {
        fill_signal_abi_from_handle(RTLD_NEXT_FALLBACK, &mut sigaction_ptr, &mut sigprocmask_ptr);
    }

    log::debug(format_args!(
        "signal abi resolved sigaction=0x{:x} sigprocmask=0x{:x}",
        sigaction_ptr as usize, sigprocmask_ptr as usize
    ));

    SignalAbiFns {
        sigaction_fn: if sigaction_ptr.is_null() {
            libc::sigaction
        } else {
            unsafe { std::mem::transmute::<*mut c_void, SigActionFn>(sigaction_ptr) }
        },
        sigprocmask_fn: if sigprocmask_ptr.is_null() {
            libc::sigprocmask
        } else {
            unsafe { std::mem::transmute::<*mut c_void, SigProcMaskFn>(sigprocmask_ptr) }
        },
    }
}

fn last_errno() -> libc::c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or_default() as libc::c_int
}

#[inline]
fn should_retry_eintr() -> bool {
    last_errno() == libc::EINTR
}

// 带 EINTR 重试的 C 函数调用包装
#[inline]
unsafe fn retry_c_int_call<F>(mut call: F) -> libc::c_int
where
    F: FnMut() -> libc::c_int,
{
    let mut result = call();
    let mut retries = 0usize;
    while result != 0 && retries < EINTR_RETRY_LIMIT && should_retry_eintr() {
        retries = retries.saturating_add(1);
        result = call();
    }
    result
}

#[inline]
unsafe fn retry_syscall_call<F>(mut call: F) -> libc::c_long
where
    F: FnMut() -> libc::c_long,
{
    let mut result = call();
    let mut retries = 0usize;
    while result != 0 && retries < EINTR_RETRY_LIMIT && should_retry_eintr() {
        retries = retries.saturating_add(1);
        result = call();
    }
    result
}

// 调用动态解析的 sigaction，失败时回退 rt_sigaction 系统调用
#[inline]
pub(super) unsafe fn raw_sigaction(
    signum: libc::c_int,
    new_action: *const libc::sigaction,
    old_action: *mut libc::sigaction,
) -> libc::c_int {
    let fns = signal_abi_fns();
    let result = unsafe { retry_c_int_call(|| (fns.sigaction_fn)(signum, new_action, old_action)) };
    if result == 0 {
        return 0;
    }

    let syscall_result = unsafe {
        retry_syscall_call(|| {
            libc::syscall(
                libc::SYS_rt_sigaction as libc::c_long,
                signum as libc::c_long,
                new_action,
                old_action,
                std::mem::size_of::<libc::sigset_t>(),
            )
        })
    };
    if syscall_result == 0 { 0 } else { result }
}

// 调用动态解析的 sigprocmask，失败时回退 rt_sigprocmask 系统调用
#[inline]
pub(super) unsafe fn raw_sigprocmask(
    how: libc::c_int,
    new_set: *const libc::sigset_t,
    old_set: *mut libc::sigset_t,
) -> libc::c_int {
    let fns = signal_abi_fns();
    let result = unsafe { retry_c_int_call(|| (fns.sigprocmask_fn)(how, new_set, old_set)) };
    if result == 0 {
        return 0;
    }

    let syscall_result = unsafe {
        retry_syscall_call(|| {
            libc::syscall(
                libc::SYS_rt_sigprocmask as libc::c_long,
                how as libc::c_long,
                new_set,
                old_set,
                std::mem::size_of::<libc::sigset_t>(),
            )
        })
    };
    if syscall_result == 0 { 0 } else { result }
}

// 临时屏蔽 SIGSEGV 和 SIGBUS，返回之前的信号掩码
pub(super) fn block_guard_signals(prev_mask: &mut libc::sigset_t) -> Result<(), Errno> {
    let mut block_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut block_mask);
        libc::sigaddset(&mut block_mask, libc::SIGSEGV);
        libc::sigaddset(&mut block_mask, libc::SIGBUS);
        if raw_sigprocmask(libc::SIG_BLOCK, &block_mask, prev_mask) != 0 {
            return Err(Errno::SegvErr);
        }
    }
    Ok(())
}

pub(super) fn restore_guard_signals(prev_mask: &libc::sigset_t) {
    unsafe {
        let _ = raw_sigprocmask(libc::SIG_SETMASK, prev_mask, ptr::null_mut());
    }
}

// 计算两个信号集的并集
pub(super) fn sigset_or(dest: &mut libc::sigset_t, left: &libc::sigset_t, right: &libc::sigset_t) {
    unsafe {
        libc::sigemptyset(dest);
        let sigset_bits = (std::mem::size_of::<libc::sigset_t>() * 8) as libc::c_int;
        for signum in 1..sigset_bits {
            if libc::sigismember(left, signum) == 1 || libc::sigismember(right, signum) == 1 {
                libc::sigaddset(dest, signum);
            }
        }
    }
}

// 从 ucontext 中提取信号掩码，x86_64 使用 uc_sigmask64 字段
pub(super) fn read_ucontext_sigmask(ucontext: *mut libc::c_void) -> libc::sigset_t {
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
    }
    if ucontext.is_null() {
        return mask;
    }

    #[cfg(target_arch = "x86_64")]
    {
        let context = unsafe { &*(ucontext as *const libc::ucontext_t) };
        let copy_len =
            std::mem::size_of::<libc::sigset_t>().min(std::mem::size_of_val(&context.uc_sigmask64));
        unsafe {
            std::ptr::copy_nonoverlapping(
                std::ptr::addr_of!(context.uc_sigmask64) as *const u8,
                (&mut mask as *mut libc::sigset_t).cast::<u8>(),
                copy_len,
            );
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let context = unsafe { &*(ucontext as *const libc::ucontext_t) };
        mask = unsafe { std::ptr::read(std::ptr::addr_of!(context.uc_sigmask)) };
    }

    mask
}

pub(super) fn current_thread_id() -> usize {
    unsafe { libc::syscall(libc::SYS_gettid) as usize }
}
