// proxy 调用栈管理，通过栈指针检测防止 hook 重入
use super::super::hub;
use crate::runtime::thread_state;
use crate::runtime::thread_state::ProxyFrame;
use std::ffi::c_void;
use std::ptr;

type ProxyStack = thread_state::FixedStack<ProxyFrame, { thread_state::PROXY_STACK_CAP }>;

#[inline]
fn with_proxy_stack_mut<R, F>(site: &'static str, f: F) -> Option<R>
where
    F: FnOnce(&mut ProxyStack) -> R,
{
    let result = thread_state::with_thread_state(|state| f(state.proxy_stack_mut()));
    if result.is_none() && !thread_state::should_skip_thread_state() {
        thread_state::report_thread_state_unavailable(site);
    }
    result
}

#[inline(always)]
fn current_stack_pointer() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        let sp: usize;
        unsafe {
            core::arch::asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        return sp;
    }

    #[cfg(target_arch = "x86_64")]
    {
        let sp: usize;
        unsafe {
            core::arch::asm!("mov {0}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        return sp;
    }

    #[allow(unreachable_code)]
    {
        let local = 0usize;
        (&local as *const usize) as usize
    }
}

// 清理已返回的栈帧，栈向低地址增长，sp <= current_sp 的帧已失效
#[inline]
fn prune_stale_proxy_frames(stack: &mut ProxyStack, current_sp: usize) {
    while let Some(frame) = stack.last() {
        if frame.stack_sp > current_sp {
            break;
        }
        let _ = stack.pop();
    }
}

pub(super) fn get_prev_func(func: *mut c_void) -> *mut c_void {
    if func.is_null() {
        return ptr::null_mut();
    }
    let _ = proxy_enter(func);
    hub::get_prev_func(func)
}

// RAII 方式管理 proxy enter/leave，确保异常路径也能正确退出
pub(super) fn with_prev_func<R, F>(func: *mut c_void, f: F) -> Option<R>
where
    F: FnOnce(*mut c_void) -> R,
{
    struct ProxyLeaveGuard {
        func: *mut c_void,
        entered: bool,
    }

    impl Drop for ProxyLeaveGuard {
        fn drop(&mut self) {
            if self.entered {
                proxy_leave(self.func);
            } else {
                hub::proxy_leave(self.func);
            }
        }
    }

    if func.is_null() {
        return None;
    }

    let entered = proxy_enter(func);
    let _leave_guard = ProxyLeaveGuard { func, entered };
    let prev = hub::get_prev_func(func);
    let result = f(prev);
    Some(result)
}

pub(super) fn get_return_address() -> *mut c_void {
    hub::get_return_address()
}

pub(super) fn pop_stack(return_address: *mut c_void) {
    hub::pop_stack(return_address)
}

pub(super) fn proxy_enter(func: *mut c_void) -> bool {
    if func.is_null() {
        return false;
    }
    let func = func as usize;
    let current_sp = current_stack_pointer();
    with_proxy_stack_mut("proxy_enter", |stack| {
        prune_stale_proxy_frames(stack, current_sp);
        let exists = stack.rposition_by(|frame| frame.func == func).is_some();
        if exists {
            return false;
        }
        let pushed = stack.push(ProxyFrame {
            func,
            stack_sp: current_sp,
        });
        if !pushed {
            thread_state::report_proxy_stack_overflow();
        }
        pushed
    })
    .unwrap_or(false)
}

pub(super) fn proxy_leave(func: *mut c_void) {
    if func.is_null() {
        return;
    }
    let func_addr = func as usize;
    let current_sp = current_stack_pointer();
    let _ = with_proxy_stack_mut("proxy_leave", |stack| {
        prune_stale_proxy_frames(stack, current_sp);
        if let Some(index) = stack.rposition_by(|frame| frame.func == func_addr) {
            let _ = stack.remove(index);
        }
    });
    hub::proxy_leave(func);
}

pub(super) fn clear_proxy_stack() {
    let _ = with_proxy_stack_mut("clear_proxy_stack", |stack| {
        let _ = stack.clear();
    });
}
