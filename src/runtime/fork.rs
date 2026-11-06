// atfork 注册与进程状态接管，锁实现和回归测试分别放在子模块。
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::state::GLOBAL;

mod lock;
pub(super) use lock::{ForkMutex, ForkMutexGuard};

const FORK_HELD_DLCLOSE: u8 = 1;
const FORK_HELD_REFRESH: u8 = 2;
const FORK_HELD_STATE: u8 = 4;
// 每个 fork 调用线程独立保存获取的锁和存活跳板计数。
thread_local! {
    static FORK_SNAPSHOT: Cell<(u8, usize)> = const { Cell::new((0, 0)) };
}
const FORK_REGISTRATION_STATUS_MASK: usize = 0b11;
const FORK_REGISTRATION_UNINITIALIZED: usize = 0;
const FORK_REGISTRATION_RUNNING: usize = 1;
const FORK_REGISTRATION_DONE: usize = 2;
const FORK_REGISTRATION_FAILED: usize = 3;
static FORK_REGISTRATION: AtomicUsize = AtomicUsize::new(FORK_REGISTRATION_UNINITIALIZED);

fn fork_registration_word(pid: usize, status: usize) -> usize {
    (pid << 2) | status
}

fn register_fork_handlers_with(
    registration: &AtomicUsize,
    pid: usize,
    register: impl FnOnce() -> i32,
) -> bool {
    let mut register = Some(register);
    loop {
        let current = registration.load(Ordering::Acquire);
        let owner_pid = current >> 2;
        let status = current & FORK_REGISTRATION_STATUS_MASK;
        if status == FORK_REGISTRATION_DONE {
            return true;
        }
        if status != FORK_REGISTRATION_UNINITIALIZED && owner_pid != pid {
            let uninitialized = fork_registration_word(pid, FORK_REGISTRATION_UNINITIALIZED);
            let _ = registration.compare_exchange(
                current,
                uninitialized,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            continue;
        }

        match status {
            FORK_REGISTRATION_UNINITIALIZED => {
                let running = fork_registration_word(pid, FORK_REGISTRATION_RUNNING);
                if registration
                    .compare_exchange(current, running, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    continue;
                }
                let result = register.take().expect("registration closure")();
                let status = if result == 0 {
                    FORK_REGISTRATION_DONE
                } else {
                    FORK_REGISTRATION_FAILED
                };
                registration.store(fork_registration_word(pid, status), Ordering::Release);
                return result == 0;
            }
            FORK_REGISTRATION_RUNNING => std::thread::yield_now(),
            FORK_REGISTRATION_FAILED => {
                let uninitialized = fork_registration_word(pid, FORK_REGISTRATION_UNINITIALIZED);
                let _ = registration.compare_exchange(
                    current,
                    uninitialized,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
            _ => unreachable!(),
        }
    }
}

/// prepare 只补拿当前线程已持有的最末全局锁之后的锁；
/// parent 释放补拿的锁，child 重置锁并保留调用线程的活跃栈。
pub(crate) fn register_handlers() -> bool {
    let pid = unsafe { libc::getpid() as usize };
    register_fork_handlers_with(&FORK_REGISTRATION, pid, || {
        let result = unsafe {
            libc::pthread_atfork(Some(fork_prepare), Some(fork_parent), Some(fork_child))
        };
        if result != 0 {
            crate::log::warn(format_args!("pthread_atfork registration failed: {result}"));
        }
        result
    })
}

pub(crate) fn handlers_registered() -> bool {
    FORK_REGISTRATION.load(Ordering::Acquire) & FORK_REGISTRATION_STATUS_MASK
        == FORK_REGISTRATION_DONE
}

unsafe extern "C" fn fork_prepare() {
    let active_trampolines = crate::runtime::thread_state::current_active_trampoline_count()
        .unwrap_or_else(crate::runtime::thread_state::active_trampoline_count);
    // fork 可能发生在已经持有全局锁的线程里。只获取当前线程未持有且位于
    // 已持有锁之后的锁，避免在 state -> dlclose 的反向等待中自锁。
    let owns_dlclose = GLOBAL.dlclose_lock.is_owned_by_current();
    let owns_refresh = GLOBAL.refresh_mutex.is_owned_by_current();
    let owns_state = GLOBAL.state.is_owned_by_current();

    let needs_dlclose = !owns_dlclose && !owns_refresh && !owns_state;
    if needs_dlclose {
        GLOBAL.dlclose_lock.lock_raw();
    }

    let needs_refresh = !owns_refresh && !owns_state;
    if needs_refresh {
        GLOBAL.refresh_mutex.lock_raw();
    }

    let needs_state = !owns_state;
    if needs_state {
        GLOBAL.state.lock_raw();
    }
    let held = (u8::from(needs_dlclose) * FORK_HELD_DLCLOSE)
        | (u8::from(needs_refresh) * FORK_HELD_REFRESH)
        | (u8::from(needs_state) * FORK_HELD_STATE);
    FORK_SNAPSHOT.with(|snapshot| snapshot.set((held, active_trampolines)));
}

unsafe extern "C" fn fork_parent() {
    let (held, _) = FORK_SNAPSHOT.with(|snapshot| snapshot.replace((0, 0)));
    if held & FORK_HELD_STATE != 0 {
        GLOBAL.state.unlock_raw();
    }
    if held & FORK_HELD_REFRESH != 0 {
        GLOBAL.refresh_mutex.unlock_raw();
    }
    if held & FORK_HELD_DLCLOSE != 0 {
        GLOBAL.dlclose_lock.unlock_raw();
    }
}

unsafe extern "C" fn fork_child() {
    let pid = unsafe { libc::getpid() as usize };
    FORK_REGISTRATION.store(
        fork_registration_word(pid, FORK_REGISTRATION_DONE),
        Ordering::Release,
    );
    crate::runtime::lifecycle::reset_monitor_after_fork_child();
    let (held, active_trampolines) = FORK_SNAPSHOT.with(|snapshot| snapshot.replace((0, 0)));
    crate::runtime::thread_state::reset_after_fork_child(active_trampolines);
    GLOBAL.state.reset_raw();
    GLOBAL.refresh_mutex.reset_raw();
    GLOBAL.dlclose_lock.reset_raw();
    if held & FORK_HELD_STATE != 0 {
        // prepare 代为获取了 state 锁，当前线程没有继承该锁的 guard，且子进程只有此线程。
        unsafe {
            GLOBAL
                .state
                .with_mut_after_fork(|state| state.clearing = false)
        };
    }
}

#[cfg(test)]
mod tests;
