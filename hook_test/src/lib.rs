use std::ffi::c_char;
use std::ptr;

static mut XT_LEN_SINK: usize = 0;

#[unsafe(no_mangle)]
pub extern "C" fn hook_test_trigger() {
    let msg = b"hook-test-trigger\n\0";
    unsafe {
        let _ = libc::puts(msg.as_ptr() as *const c_char);
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn hook_test_trigger_with_input(msg: *const c_char) {
    if msg.is_null() {
        return;
    }
    unsafe {
        let len = libc::strlen(msg);
        ptr::write_volatile(ptr::addr_of_mut!(XT_LEN_SINK), len);
        let _ = libc::puts(msg);
    }
}
