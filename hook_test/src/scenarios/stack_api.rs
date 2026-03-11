use std::ffi::c_void;
use std::sync::atomic::Ordering;

use srx_hook::{HookMode, clear, hook_single, init, pop_stack, refresh, unhook};

use crate::test_ctx::{
    STACK_API_COUNT, ensure_ok, hook_puts_return_address_stack, load_hook_test, hook_test_trigger,
};

pub unsafe fn scenario_return_address_stack_api() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init stack api");
    let handle = load_hook_test();

    let stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_return_address_stack as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single stack api failed");
    ensure_ok(refresh().0, "refresh stack api");

    STACK_API_COUNT.store(0, Ordering::Relaxed);
    for _ in 0..16 {
        hook_test_trigger(handle);
    }
    let count = STACK_API_COUNT.load(Ordering::Relaxed);
    assert!(count >= 16, "stack api hook lost calls: {count}");

    pop_stack(std::ptr::null_mut());
    ensure_ok(unhook(stub), "unhook stack api");
    libc::dlclose(handle);
    clear();
}
