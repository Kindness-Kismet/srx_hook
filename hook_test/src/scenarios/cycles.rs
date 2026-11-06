use std::ffi::{CString, c_void};
use std::sync::atomic::Ordering;

use srx_hook::{HookMode, clear, hook_single, init, refresh, unhook};

use crate::test_ctx::{
    HOOK_A_COUNT, HOOK_B_COUNT, RECURSIVE_HOOK_TEST_HANDLE, RECURSIVE_PREV_RESULT,
    RECURSIVE_PROXY_CALLS, ensure_ok, hook_puts_cycle_guard, hook_puts_cycle_manual_no_leave,
    hook_puts_recurse_then_prev, hook_strlen_cycle_guard, hook_strlen_cycle_manual_no_leave,
    hook_test_trigger, hook_test_trigger_with_input, load_hook_test,
};

pub unsafe fn scenario_cycle_guard_auto() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init cycle guard");
    let handle = load_hook_test();

    let stub_puts = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_cycle_guard as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single puts cycle failed");
    let stub_strlen = hook_single(
        "libhook_test.so",
        None,
        "strlen",
        hook_strlen_cycle_guard as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single strlen cycle failed");
    ensure_ok(refresh().0, "refresh cycle guard");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    HOOK_B_COUNT.store(0, Ordering::Relaxed);
    let cycle_input = CString::new("cycle-guard-input").expect("cstring failed");
    hook_test_trigger_with_input(handle, &cycle_input);
    let a = HOOK_A_COUNT.load(Ordering::Relaxed);
    let b = HOOK_B_COUNT.load(Ordering::Relaxed);
    assert!(a >= 1, "cycle guard puts hook not hit");
    assert!(b >= 1, "cycle guard strlen hook not hit");
    assert!(
        a < 8 && b < 8,
        "cycle guard failed, possible recursion: a={a} b={b}"
    );

    ensure_ok(unhook(stub_strlen), "unhook cycle strlen");
    ensure_ok(unhook(stub_puts), "unhook cycle puts");
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_same_hub_recursion_preserves_outer_frame() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init recursive frame");
    let handle = load_hook_test();
    let stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_recurse_then_prev as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single recursive frame failed");
    ensure_ok(refresh().0, "refresh recursive frame");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    RECURSIVE_PROXY_CALLS.store(0, Ordering::Relaxed);
    RECURSIVE_PREV_RESULT.store(-1, Ordering::Relaxed);
    RECURSIVE_HOOK_TEST_HANDLE.store(handle as usize, Ordering::Relaxed);
    hook_test_trigger(handle);

    assert_eq!(RECURSIVE_PROXY_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(HOOK_A_COUNT.load(Ordering::Relaxed), 1);
    assert!(
        RECURSIVE_PREV_RESULT.load(Ordering::Acquire) >= 0,
        "recursive trampoline pop removed the outer Hub frame"
    );
    RECURSIVE_HOOK_TEST_HANDLE.store(0, Ordering::Relaxed);
    ensure_ok(unhook(stub), "unhook recursive frame");
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_cycle_guard_manual_no_leave() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init cycle manual");
    let handle = load_hook_test();

    let stub_puts = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_cycle_manual_no_leave as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single puts cycle manual failed");
    let stub_strlen = hook_single(
        "libhook_test.so",
        None,
        "strlen",
        hook_strlen_cycle_manual_no_leave as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single strlen cycle manual failed");
    ensure_ok(refresh().0, "refresh cycle manual");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    HOOK_B_COUNT.store(0, Ordering::Relaxed);
    let cycle_input = CString::new("cycle-manual-input").expect("cstring failed");
    hook_test_trigger_with_input(handle, &cycle_input);
    let a = HOOK_A_COUNT.load(Ordering::Relaxed);
    let b = HOOK_B_COUNT.load(Ordering::Relaxed);
    assert!(a >= 1, "cycle manual puts hook not hit");
    assert!(b >= 1, "cycle manual strlen hook not hit");
    assert!(
        a < 8 && b < 8,
        "cycle manual failed, possible recursion: a={a} b={b}"
    );

    ensure_ok(unhook(stub_strlen), "unhook cycle manual strlen");
    ensure_ok(unhook(stub_puts), "unhook cycle manual puts");
    libc::dlclose(handle);
    clear();
}
