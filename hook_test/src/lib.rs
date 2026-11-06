use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

static mut XT_LEN_SINK: usize = 0;
static HELD_PUTS_READY: AtomicBool = AtomicBool::new(false);
static HELD_PUTS_RELEASE: AtomicBool = AtomicBool::new(false);
static HELD_PUTS_TARGET: AtomicUsize = AtomicUsize::new(0);
static HELD_PUTS_RESULT: AtomicI32 = AtomicI32::new(-1);

#[cfg(target_arch = "aarch64")]
std::arch::global_asm!(
    ".text",
    ".global hook_test_load_puts_slot",
    ".type hook_test_load_puts_slot, %function",
    "hook_test_load_puts_slot:",
    "adrp x0, :got:puts",
    "ldr x0, [x0, :got_lo12:puts]",
    "ret",
);

#[cfg(target_arch = "x86_64")]
std::arch::global_asm!(
    ".text",
    ".global hook_test_load_puts_slot",
    ".type hook_test_load_puts_slot, @function",
    "hook_test_load_puts_slot:",
    "movq puts@GOTPCREL(%rip), %rax",
    "ret",
    options(att_syntax)
);

unsafe extern "C" {
    fn hook_test_load_puts_slot() -> *mut c_void;
}

#[unsafe(no_mangle)]
pub extern "C" fn hook_test_reset_held_puts() {
    HELD_PUTS_READY.store(false, Ordering::Relaxed);
    HELD_PUTS_RELEASE.store(false, Ordering::Relaxed);
    HELD_PUTS_TARGET.store(0, Ordering::Relaxed);
    HELD_PUTS_RESULT.store(-1, Ordering::Relaxed);
}

#[unsafe(no_mangle)]
pub extern "C" fn hook_test_held_puts_ready() -> libc::c_int {
    libc::c_int::from(HELD_PUTS_READY.load(Ordering::Acquire))
}

#[unsafe(no_mangle)]
pub extern "C" fn hook_test_held_puts_target() -> usize {
    HELD_PUTS_TARGET.load(Ordering::Acquire)
}

#[unsafe(no_mangle)]
pub extern "C" fn hook_test_current_puts_target() -> usize {
    unsafe { hook_test_load_puts_slot() as usize }
}

#[unsafe(no_mangle)]
pub extern "C" fn hook_test_release_held_puts() {
    HELD_PUTS_RELEASE.store(true, Ordering::Release);
}

#[unsafe(no_mangle)]
pub extern "C" fn hook_test_held_puts_result() -> libc::c_int {
    HELD_PUTS_RESULT.load(Ordering::Acquire)
}

#[unsafe(no_mangle)]
pub extern "C" fn hook_test_trigger_held_puts() {
    let target = unsafe { hook_test_load_puts_slot() };
    HELD_PUTS_TARGET.store(target as usize, Ordering::Relaxed);
    HELD_PUTS_READY.store(true, Ordering::Release);
    while !HELD_PUTS_RELEASE.load(Ordering::Acquire) {
        unsafe { libc::sched_yield() };
    }

    let puts: unsafe extern "C" fn(*const c_char) -> libc::c_int =
        unsafe { std::mem::transmute(target) };
    let message = b"stale trampoline target\n\0";
    let result = unsafe { puts(message.as_ptr() as *const c_char) };
    HELD_PUTS_RESULT.store(result, Ordering::Release);
}

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
        std::ptr::write_volatile(std::ptr::addr_of_mut!(XT_LEN_SINK), len);
        let _ = libc::puts(msg);
    }
}
