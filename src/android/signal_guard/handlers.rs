// SIGSEGV/SIGBUS 信号处理器实现
// 先尝试守卫跳转，失败则链式转发给之前注册的 handler

use std::mem;
use std::ptr;

use super::abi;
use super::slot;
use super::{load_sigbus_old_action, load_sigsegv_old_action};

// 将信号转发给之前注册的 handler
// 处理 SA_SIGINFO/SA_NODEFER/SA_RESETHAND 标志，正确切换信号掩码
unsafe fn dispatch_old_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
    old: *const libc::sigaction,
    current_handler: usize,
    peer_handler: usize,
) {
    if old.is_null() {
        terminate_current_signal(sig);
    }
    let old_action = unsafe { &*old };
    let handler = old_action.sa_sigaction;

    // SIG_DFL、自身 handler 或对端 handler 均视为无效，直接终止
    if handler == libc::SIG_DFL || handler == current_handler || handler == peer_handler {
        terminate_current_signal(sig);
    }

    if handler == libc::SIG_IGN {
        return;
    }

    let mut previous_mask: libc::sigset_t = unsafe { mem::zeroed() };
    let context_mask = abi::read_ucontext_sigmask(ucontext);

    // 合并 ucontext 掩码与旧 handler 掩码，额外屏蔽 SIGPIPE/SIGUSR1/SIGQUIT
    let mut forward_mask: libc::sigset_t = unsafe { mem::zeroed() };
    abi::sigset_or(&mut forward_mask, &context_mask, &old_action.sa_mask);
    if old_action.sa_flags & libc::SA_NODEFER == 0 {
        unsafe {
            libc::sigaddset(&mut forward_mask, sig);
        }
    }
    unsafe {
        libc::sigaddset(&mut forward_mask, libc::SIGPIPE);
        libc::sigaddset(&mut forward_mask, libc::SIGUSR1);
        libc::sigaddset(&mut forward_mask, libc::SIGQUIT);
    }

    let mask_switched =
        unsafe { abi::raw_sigprocmask(libc::SIG_SETMASK, &forward_mask, &mut previous_mask) == 0 };

    if old_action.sa_flags & libc::SA_RESETHAND != 0 {
        unsafe {
            let mut dfl_action: libc::sigaction = mem::zeroed();
            dfl_action.sa_sigaction = libc::SIG_DFL;
            dfl_action.sa_flags = 0;
            libc::sigemptyset(&mut dfl_action.sa_mask);
            let _ = abi::raw_sigaction(sig, &dfl_action, ptr::null_mut());
        }
    }

    if old_action.sa_flags & libc::SA_SIGINFO != 0 {
        let action: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
            unsafe { mem::transmute(handler) };
        action(sig, info, ucontext);
    } else {
        let action: extern "C" fn(libc::c_int) = unsafe { mem::transmute(handler) };
        action(sig);
    }

    if mask_switched {
        unsafe {
            let _ = abi::raw_sigprocmask(libc::SIG_SETMASK, &previous_mask, ptr::null_mut());
        }
    }
}

// 恢复默认处理后重新投递信号，确保进程以正确的信号终止
// 依次尝试 tgkill -> pthread_kill -> raise -> _exit
fn terminate_current_signal(sig: libc::c_int) -> ! {
    unsafe {
        let mut dfl_action: libc::sigaction = mem::zeroed();
        dfl_action.sa_sigaction = libc::SIG_DFL;
        dfl_action.sa_flags = 0;
        libc::sigemptyset(&mut dfl_action.sa_mask);
        let _ = abi::raw_sigaction(sig, &dfl_action, ptr::null_mut());

        let mut mask: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, sig);
        let _ = abi::raw_sigprocmask(libc::SIG_UNBLOCK, &mask, ptr::null_mut());

        let pid = libc::getpid();
        let tid = abi::current_thread_id();
        let _ = libc::syscall(
            libc::SYS_tgkill as libc::c_long,
            pid as libc::c_long,
            tid as libc::c_long,
            sig as libc::c_long,
        );
        let _ = libc::pthread_kill(libc::pthread_self(), sig);
        let _ = libc::raise(sig);
        libc::_exit(128 + sig);
    }
}

// SIGSEGV 处理入口：优先尝试守卫跳转，否则转发给旧 handler
pub(super) extern "C" fn sigsegv_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    if slot::handle_guard_signal(sig, info) {
        return;
    }
    unsafe {
        let old = load_sigsegv_old_action();
        dispatch_old_handler(
            sig,
            info,
            ucontext,
            old,
            sigsegv_handler as *const () as usize,
            sigbus_handler as *const () as usize,
        );
    }
}

// SIGBUS 处理入口：逻辑同 sigsegv_handler
pub(super) extern "C" fn sigbus_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    if slot::handle_guard_signal(sig, info) {
        return;
    }
    unsafe {
        let old = load_sigbus_old_action();
        dispatch_old_handler(
            sig,
            info,
            ucontext,
            old,
            sigbus_handler as *const () as usize,
            sigsegv_handler as *const () as usize,
        );
    }
}
