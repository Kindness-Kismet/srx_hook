// 线程级备用信号栈管理
// 信号处理器在备用栈上运行，避免栈溢出时无法处理 SIGSEGV

use crate::errno::Errno;
use crate::log;
use std::cell::RefCell;
use std::ffi::c_void;
use std::mem;
use std::ptr;

use super::{SIGALTSTACK_MIN_SIZE, abi};

// 每线程的备用信号栈状态
// owns_stack 标记是否由本模块分配（已有备用栈时复用，不接管所有权）
struct ThreadAltStackState {
    installed: bool,
    owns_stack: bool,
    stack_mem: *mut c_void,
    stack_size: usize,
    previous: libc::stack_t,
}

impl ThreadAltStackState {
    fn new() -> Self {
        Self {
            installed: false,
            owns_stack: false,
            stack_mem: ptr::null_mut(),
            stack_size: 0,
            previous: libc::stack_t {
                ss_sp: ptr::null_mut(),
                ss_flags: 0,
                ss_size: 0,
            },
        }
    }

    // 检查当前线程是否已有备用栈；没有则分配并安装
    // SS_DISABLE 表示无备用栈，此时需要自行分配
    unsafe fn install_if_needed(&mut self) -> Result<(), Errno> {
        if self.installed {
            return Ok(());
        }

        let mut current: libc::stack_t = unsafe { mem::zeroed() };
        if unsafe { libc::sigaltstack(ptr::null(), &mut current) } != 0 {
            return Err(Errno::InitErrSig);
        }

        if current.ss_flags & libc::SS_DISABLE == 0 {
            self.installed = true;
            self.owns_stack = false;
            return Ok(());
        }

        let stack_size = signal_stack_size();
        let stack_mem = unsafe { libc::malloc(stack_size) };
        if stack_mem.is_null() {
            return Err(Errno::NoMem);
        }

        let mut stack: libc::stack_t = unsafe { mem::zeroed() };
        stack.ss_sp = stack_mem;
        stack.ss_flags = 0;
        stack.ss_size = stack_size;
        if unsafe { libc::sigaltstack(&stack, ptr::null_mut()) } != 0 {
            unsafe {
                libc::free(stack_mem);
            }
            return Err(Errno::InitErrSig);
        }

        self.previous = current;
        self.stack_mem = stack_mem;
        self.stack_size = stack_size;
        self.owns_stack = true;
        self.installed = true;
        log::debug(format_args!(
            "install thread altstack tid={} size={} ptr=0x{:x}",
            abi::current_thread_id(),
            stack_size,
            stack_mem as usize
        ));
        Ok(())
    }

    // 卸载备用栈：仅释放自行分配的栈内存，恢复之前的栈配置
    unsafe fn uninstall(&mut self) {
        if !self.installed {
            return;
        }

        if self.owns_stack {
            let _ = unsafe { libc::sigaltstack(ptr::addr_of!(self.previous), ptr::null_mut()) };
            if !self.stack_mem.is_null() {
                unsafe {
                    libc::free(self.stack_mem);
                }
            }
            log::debug(format_args!(
                "remove thread altstack tid={} size={} ptr=0x{:x}",
                abi::current_thread_id(),
                self.stack_size,
                self.stack_mem as usize
            ));
        }

        self.installed = false;
        self.owns_stack = false;
        self.stack_mem = ptr::null_mut();
        self.stack_size = 0;
    }
}

impl Drop for ThreadAltStackState {
    fn drop(&mut self) {
        unsafe {
            self.uninstall();
        }
    }
}

thread_local! {
    static THREAD_ALTSTACK_STATE: RefCell<ThreadAltStackState> =
        RefCell::new(ThreadAltStackState::new());
}

// 取系统推荐值与模块最小值中的较大者
fn signal_stack_size() -> usize {
    let min_size = libc::MINSIGSTKSZ.max(libc::SIGSTKSZ);
    min_size.max(SIGALTSTACK_MIN_SIZE)
}

// 确保当前线程已安装备用信号栈，每线程仅安装一次
pub(super) fn ensure_thread_altstack() -> Result<(), Errno> {
    THREAD_ALTSTACK_STATE.with(|state| {
        let mut state = state.borrow_mut();
        unsafe { state.install_if_needed() }
    })
}
