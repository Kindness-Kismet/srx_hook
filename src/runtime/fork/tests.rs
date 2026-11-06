use super::*;
use crate::runtime::state::MutexPoisonRecover;
use std::sync::{Barrier, Mutex};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn wait_child(pid: libc::pid_t) -> Option<i32> {
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            return Some(status);
        }
        if waited < 0 && unsafe { *libc::__errno() } == libc::EINTR {
            continue;
        }
        return None;
    }
}

#[test]
fn fork_child_can_lock_after_atfork_reset() {
    let _serial = TEST_LOCK.lock().unwrap();
    assert!(register_handlers());
    // 确保 GLOBAL 与锁在 fork 前完成初始化。
    let _state_guard = GLOBAL.state.lock_or_poison();
    let _refresh_guard = GLOBAL.refresh_mutex.lock_or_poison();
    let _dlclose_guard = GLOBAL.dlclose_lock.lock_or_poison();

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // 子进程：atfork child 已 reset 全部锁，这里必须能立即获取。
        let state = GLOBAL.state.lock_or_poison();
        let value = state.process_id;
        drop(state);
        let _ = GLOBAL.refresh_mutex.lock_or_poison();
        let _ = GLOBAL.dlclose_lock.lock_or_poison();
        unsafe { libc::_exit(if value == 0 { 0 } else { 1 }) };
    }
    let status = wait_child(pid).expect("waitpid child");
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}
#[test]
fn fork_waits_for_another_thread_holding_state_lock() {
    let _serial = TEST_LOCK.lock().unwrap();
    assert!(register_handlers());
    let _ = GLOBAL.state.lock_or_poison();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let guard = GLOBAL.state.lock_or_poison();
        ready_tx.send(()).expect("send ready");
        std::thread::sleep(std::time::Duration::from_millis(100));
        drop(guard);
    });
    ready_rx.recv().expect("recv ready");

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let _ = GLOBAL.state.lock_or_poison();
        unsafe { libc::_exit(0) };
    }
    let status = wait_child(pid).expect("waitpid child");
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    holder.join().expect("holder join");
}

#[test]
fn nested_fork_child_can_lock() {
    let _serial = TEST_LOCK.lock().unwrap();
    assert!(register_handlers());
    let _ = GLOBAL.state.lock_or_poison();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let pid2 = unsafe { libc::fork() };
        if pid2 < 0 {
            unsafe { libc::_exit(4) };
        }
        if pid2 == 0 {
            let _ = GLOBAL.state.lock_or_poison();
            unsafe { libc::_exit(0) };
        }
        let ok = wait_child(pid2)
            .map(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0)
            .unwrap_or(false);
        unsafe { libc::_exit(if ok { 0 } else { 4 }) };
    }
    let status = wait_child(pid).expect("waitpid child");
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}
#[test]
fn fork_while_current_thread_holds_state_lock() {
    let _serial = TEST_LOCK.lock().unwrap();
    assert!(register_handlers());
    let guard = GLOBAL.state.lock_or_poison();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let child_guard = GLOBAL.state.lock_or_poison();
        drop(guard);
        let still_owned = GLOBAL.state.is_owned_by_current();
        drop(child_guard);
        unsafe { libc::_exit(if still_owned { 0 } else { 5 }) };
    }
    let status = wait_child(pid).expect("waitpid child");
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    drop(guard);
}

#[test]
fn fork_with_state_lock_skips_earlier_lock() {
    let _serial = TEST_LOCK.lock().unwrap();
    assert!(register_handlers());
    let state_guard = GLOBAL.state.lock_or_poison();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let _dlclose_guard = GLOBAL.dlclose_lock.lock_or_poison();
        ready_tx.send(()).expect("send ready");
        let _state_guard = GLOBAL.state.lock_or_poison();
    });
    ready_rx.recv().expect("recv ready");

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe { libc::_exit(0) };
    }
    let status = wait_child(pid).expect("waitpid child");
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    drop(state_guard);
    holder.join().expect("holder join");
}

#[test]
fn fork_child_can_resume_clear_interrupted_before_state_lock() {
    let _serial = TEST_LOCK.lock().unwrap();
    assert!(register_handlers());
    {
        let mut state = GLOBAL.state.lock_or_poison();
        state.clearing = true;
    }

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let state = GLOBAL.state.lock_or_poison();
        unsafe { libc::_exit(if state.clearing { 6 } else { 0 }) };
    }
    let status = wait_child(pid).expect("waitpid child");
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);

    GLOBAL.state.lock_or_poison().clearing = false;
}

#[test]
fn fork_registration_recovers_if_the_owner_thread_vanished() {
    let registration = AtomicUsize::new(fork_registration_word(101, FORK_REGISTRATION_RUNNING));
    let registered = register_fork_handlers_with(&registration, 102, || 0);
    assert!(registered);
    assert_eq!(
        registration.load(Ordering::Acquire),
        fork_registration_word(102, FORK_REGISTRATION_DONE)
    );
}

#[test]
fn fork_registration_retries_after_a_failed_attempt() {
    let registration = AtomicUsize::new(fork_registration_word(101, FORK_REGISTRATION_FAILED));
    assert!(!register_fork_handlers_with(&registration, 101, || {
        libc::ENOMEM
    }));
    assert!(register_fork_handlers_with(&registration, 101, || 0));
    assert_eq!(
        registration.load(Ordering::Acquire),
        fork_registration_word(101, FORK_REGISTRATION_DONE)
    );
}

#[test]
fn fork_child_completes_in_progress_registration_state() {
    let _serial = TEST_LOCK.lock().unwrap();
    assert!(register_handlers());
    let parent_pid = unsafe { libc::getpid() as usize };
    FORK_REGISTRATION.store(
        fork_registration_word(parent_pid, FORK_REGISTRATION_RUNNING),
        Ordering::Release,
    );

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe { libc::_exit(if handlers_registered() { 0 } else { 7 }) };
    }
    FORK_REGISTRATION.store(
        fork_registration_word(parent_pid, FORK_REGISTRATION_DONE),
        Ordering::Release,
    );
    let status = wait_child(pid).expect("waitpid child");
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

#[test]
fn simultaneous_fork_callers_can_relock_child_state() {
    let _serial = TEST_LOCK.lock().unwrap();
    assert!(register_handlers());
    let barrier = std::sync::Arc::new(Barrier::new(3));
    let workers = (0..2)
        .map(|worker_index| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let expected_trampolines = worker_index + 1;
                for index in 0..expected_trampolines {
                    assert!(crate::runtime::thread_state::trampoline_enter(
                        1,
                        1,
                        100 - index,
                        2
                    ));
                }
                let mut all_ok = true;
                for _ in 0..12 {
                    barrier.wait();
                    let pid = unsafe { libc::fork() };
                    let ok = if pid == 0 {
                        let _state = GLOBAL.state.lock_or_poison();
                        let count = crate::runtime::thread_state::active_trampoline_count();
                        unsafe { libc::_exit(if count == expected_trampolines { 0 } else { 8 }) };
                    } else if pid < 0 {
                        false
                    } else {
                        wait_child(pid).is_some_and(|status| {
                            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
                        })
                    };
                    all_ok &= ok;
                    barrier.wait();
                }
                for index in (0..expected_trampolines).rev() {
                    assert_eq!(
                        crate::runtime::thread_state::trampoline_leave(1, 100 - index),
                        1
                    );
                }
                all_ok
            })
        })
        .collect::<Vec<_>>();

    for _ in 0..12 {
        barrier.wait();
        barrier.wait();
    }
    assert!(workers.into_iter().all(|worker| worker.join().unwrap()));
}
