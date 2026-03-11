use std::ffi::c_void;
use std::sync::atomic::Ordering;

use srx_hook::{HookMode, add_ignore, clear, hook_single, init, refresh, unhook};

use crate::test_ctx::{
    HOOK_A_COUNT, HOOK_B_COUNT, HOOK_C_COUNT, ensure_ok, hook_puts_a_chain, hook_puts_b_chain,
    hook_puts_c_chain, hook_puts_no_leave, hook_puts_quiet, load_hook_test,
    verify_cfi_slowpath_disabled, hook_test_trigger,
};

pub unsafe fn scenario_cfi_slowpath_disabled() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init manual cfi");
    verify_cfi_slowpath_disabled();
    clear();
}

pub unsafe fn scenario_single_hook_unhook() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init manual single");
    let handle = load_hook_test();

    let stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single A failed");
    ensure_ok(refresh().0, "refresh single");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    let count = HOOK_A_COUNT.load(Ordering::Relaxed);
    assert!(count >= 1, "single hook not hit");

    ensure_ok(unhook(stub), "unhook single");
    let before = HOOK_A_COUNT.load(Ordering::Relaxed);
    hook_test_trigger(handle);
    let after = HOOK_A_COUNT.load(Ordering::Relaxed);
    assert_eq!(before, after, "single hook still active after unhook");

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_multi_hook_chain_unhook() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init manual chain");
    let handle = load_hook_test();

    let stub_a = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_a_chain as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single A failed");
    let stub_b = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_b_chain as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single B failed");
    let stub_c = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_c_chain as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single C failed");
    ensure_ok(refresh().0, "refresh chain");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    HOOK_B_COUNT.store(0, Ordering::Relaxed);
    HOOK_C_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "hook A not hit in chain"
    );
    assert!(
        HOOK_B_COUNT.load(Ordering::Relaxed) >= 1,
        "hook B not hit in chain"
    );
    assert!(
        HOOK_C_COUNT.load(Ordering::Relaxed) >= 1,
        "hook C not hit in chain"
    );

    ensure_ok(unhook(stub_b), "unhook B");
    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    HOOK_B_COUNT.store(0, Ordering::Relaxed);
    HOOK_C_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "hook A not hit after unhook B"
    );
    assert_eq!(
        HOOK_B_COUNT.load(Ordering::Relaxed),
        0,
        "hook B still hit after unhook"
    );
    assert!(
        HOOK_C_COUNT.load(Ordering::Relaxed) >= 1,
        "hook C lost after unhook middle B"
    );

    ensure_ok(unhook(stub_c), "unhook C");
    ensure_ok(unhook(stub_a), "unhook A");
    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    HOOK_B_COUNT.store(0, Ordering::Relaxed);
    HOOK_C_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert_eq!(
        HOOK_A_COUNT.load(Ordering::Relaxed),
        0,
        "hook A still hit after final unhook"
    );
    assert_eq!(
        HOOK_B_COUNT.load(Ordering::Relaxed),
        0,
        "hook B still hit after final unhook"
    );
    assert_eq!(
        HOOK_C_COUNT.load(Ordering::Relaxed),
        0,
        "hook C still hit after final unhook"
    );

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_same_proxy_multi_stub_unhook() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init manual same proxy");
    let handle = load_hook_test();

    let stub_a = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single same proxy A failed");
    let stub_b = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single same proxy B failed");
    ensure_ok(refresh().0, "refresh same proxy");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "same proxy not hit after hook"
    );

    ensure_ok(unhook(stub_a), "unhook same proxy A");
    let before = HOOK_A_COUNT.load(Ordering::Relaxed);
    hook_test_trigger(handle);
    let after = HOOK_A_COUNT.load(Ordering::Relaxed);
    assert!(
        after > before,
        "same proxy lost after unhook first duplicate stub"
    );

    ensure_ok(unhook(stub_b), "unhook same proxy B");
    let before = HOOK_A_COUNT.load(Ordering::Relaxed);
    hook_test_trigger(handle);
    let after = HOOK_A_COUNT.load(Ordering::Relaxed);
    assert_eq!(before, after, "same proxy still active after unhook all");

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_missing_leave_recovery() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init manual missing leave");
    let handle = load_hook_test();

    let stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_no_leave as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single missing leave failed");
    ensure_ok(refresh().0, "refresh missing leave");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    for _ in 0..8 {
        hook_test_trigger(handle);
    }
    let count = HOOK_A_COUNT.load(Ordering::Relaxed);
    assert!(
        count >= 8,
        "missing proxy_leave causes lost hook, count={count}"
    );

    ensure_ok(unhook(stub), "unhook missing leave");
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_ignore() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init manual ignore");
    ensure_ok(add_ignore("libhook_test.so"), "add_ignore");
    let handle = load_hook_test();

    let stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single ignore case failed");
    ensure_ok(refresh().0, "refresh ignore");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert_eq!(
        HOOK_A_COUNT.load(Ordering::Relaxed),
        0,
        "ignore failed, hook still triggered"
    );

    ensure_ok(unhook(stub), "unhook ignore case");
    libc::dlclose(handle);
    clear();
}
