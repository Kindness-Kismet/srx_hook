use std::ffi::c_void;
use std::sync::atomic::Ordering;

use srx_hook::{HookMode, clear, hook_single, init, refresh, unhook};

use crate::test_ctx::{
    FORK_PROXY_CHILD_STATUS, HOOK_A_COUNT, HOOK_B_COUNT, ensure_ok, hook_puts_a_chain,
    hook_puts_b_chain, hook_puts_fork_from_proxy, hook_puts_quiet, hook_test_trigger,
    load_hook_test, wait_child,
};

// 两个 proxy 串联时，fork 子进程也要按链表继续调用，不能只执行第一个。
pub unsafe fn scenario_fork_child_hook_chain() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init manual fork chain");
    let handle = load_hook_test();

    let stub_a = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_a_chain as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single chain A failed");
    let stub_b = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_b_chain as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single chain B failed");
    ensure_ok(refresh().0, "refresh fork chain");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    HOOK_B_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert!(HOOK_A_COUNT.load(Ordering::Relaxed) > 0, "parent chain A");
    assert!(HOOK_B_COUNT.load(Ordering::Relaxed) > 0, "parent chain B");
    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    HOOK_B_COUNT.store(0, Ordering::Relaxed);

    let pid = libc::fork();
    assert!(pid >= 0, "fork chain failed");
    if pid == 0 {
        hook_test_trigger(handle);
        let ok =
            HOOK_A_COUNT.load(Ordering::Relaxed) > 0 && HOOK_B_COUNT.load(Ordering::Relaxed) > 0;
        if !ok || unhook(stub_b) != srx_hook::SrxHookErrno::Ok {
            libc::_exit(3);
        }
        HOOK_A_COUNT.store(0, Ordering::Relaxed);
        HOOK_B_COUNT.store(0, Ordering::Relaxed);
        hook_test_trigger(handle);
        let remaining_hook_ok =
            HOOK_A_COUNT.load(Ordering::Relaxed) > 0 && HOOK_B_COUNT.load(Ordering::Relaxed) == 0;
        libc::_exit(if remaining_hook_ok { 0 } else { 8 });
    }

    let status = wait_child(pid).expect("fork child chain wait failed or timed out");
    assert!(
        libc::WIFEXITED(status),
        "fork child chain did not exit normally"
    );
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "fork child proxy chain did not run"
    );

    ensure_ok(unhook(stub_b), "unhook fork chain B");
    ensure_ok(unhook(stub_a), "unhook fork chain A");
    libc::dlclose(handle);
    clear();
}

// proxy 内 fork 后，子进程仍能使用当前线程的 proxy 链及返回上下文。
pub unsafe fn scenario_fork_from_proxy_preserves_context() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init manual fork from proxy");
    let handle = load_hook_test();
    let stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_fork_from_proxy as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single fork from proxy failed");
    ensure_ok(refresh().0, "refresh fork from proxy");
    FORK_PROXY_CHILD_STATUS.store(-1, Ordering::Relaxed);

    let parent_pid = libc::getpid();
    hook_test_trigger(handle);
    if libc::getpid() != parent_pid {
        libc::_exit(0);
    }
    assert_eq!(
        FORK_PROXY_CHILD_STATUS.load(Ordering::Relaxed),
        0,
        "child lost the active proxy chain after fork"
    );

    ensure_ok(unhook(stub), "unhook fork from proxy");
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_fork_worker_child_reinit() {
    clear();
    ensure_ok(
        init(HookMode::Automatic, true),
        "init automatic worker fork",
    );
    let handle = load_hook_test();
    let stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single worker fork failed");
    HOOK_A_COUNT.store(0, Ordering::Relaxed);

    let handle_addr = handle as usize;
    let status = std::thread::spawn(move || unsafe {
        // 此线程在 fork 前尚未进入 proxy，覆盖子进程首次分配线程状态。
        let pid = libc::fork();
        assert!(pid >= 0, "worker fork failed");
        if pid == 0 {
            hook_test_trigger(handle_addr as *mut c_void);
            if HOOK_A_COUNT.load(Ordering::Relaxed) == 0 {
                libc::_exit(6);
            }
            clear();
            ensure_ok(init(HookMode::Automatic, true), "child automatic reinit");
            let child_stub = hook_single(
                "libhook_test.so",
                None,
                "puts",
                hook_puts_quiet as *mut c_void,
                None,
                std::ptr::null_mut(),
            )
            .expect("child hook after reinit failed");
            HOOK_A_COUNT.store(0, Ordering::Relaxed);
            hook_test_trigger(handle_addr as *mut c_void);
            let hit = HOOK_A_COUNT.load(Ordering::Relaxed);
            ensure_ok(unhook(child_stub), "child unhook after reinit");
            clear();
            libc::_exit(if hit > 0 { 0 } else { 7 });
        }
        wait_child(pid).expect("worker fork child wait failed or timed out")
    })
    .join()
    .expect("fork worker panicked");
    assert!(
        libc::WIFEXITED(status),
        "worker child did not exit normally"
    );
    assert_eq!(libc::WEXITSTATUS(status), 0, "worker child reinit failed");

    hook_test_trigger(handle);
    assert!(HOOK_A_COUNT.load(Ordering::Relaxed) > 0, "parent hook lost");
    ensure_ok(unhook(stub), "unhook worker fork");
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_fork_child_automatic_refresh() {
    clear();
    let _periodic_guard = crate::test_ctx::ScopedEnv::set("SRX_HOOK_MONITOR_PERIODIC", "0");
    ensure_ok(
        init(HookMode::Automatic, true),
        "init automatic child refresh",
    );
    hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single before child refresh failed");
    for resume_with_init in [false, true] {
        let pid = libc::fork();
        assert!(pid >= 0, "automatic refresh fork failed");
        if pid == 0 {
            if resume_with_init {
                ensure_ok(init(HookMode::Automatic, true), "automatic child init");
            } else {
                ensure_ok(refresh().0, "automatic child refresh");
            }
            let handle = load_hook_test();
            std::thread::sleep(std::time::Duration::from_millis(1200));
            HOOK_A_COUNT.store(0, Ordering::Relaxed);
            hook_test_trigger(handle);
            libc::_exit(if HOOK_A_COUNT.load(Ordering::Relaxed) > 0 {
                0
            } else {
                9
            });
        }
        let status = wait_child(pid).expect("automatic child refresh wait failed or timed out");
        assert!(
            libc::WIFEXITED(status),
            "automatic child did not exit normally"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child automatic monitor stopped"
        );
    }
    clear();
}
