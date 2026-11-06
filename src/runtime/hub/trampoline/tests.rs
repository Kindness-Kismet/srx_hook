use super::*;

#[unsafe(no_mangle)]
static SRX_ABI_TAIL_TARGET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(target_arch = "aarch64")]
std::arch::global_asm!(
    ".text",
    ".global srx_abi_tail_call",
    ".type srx_abi_tail_call, %function",
    "srx_abi_tail_call:",
    "adrp x16, SRX_ABI_TAIL_TARGET",
    "ldr x16, [x16, :lo12:SRX_ABI_TAIL_TARGET]",
    "br x16",
);
#[cfg(target_arch = "x86_64")]
std::arch::global_asm!(
    ".text",
    ".global srx_abi_tail_call",
    ".type srx_abi_tail_call, @function",
    "srx_abi_tail_call:",
    "movq SRX_ABI_TAIL_TARGET(%rip), %r11",
    "jmp *%r11",
    options(att_syntax)
);
unsafe extern "C" {
    fn srx_abi_tail_call();
}
type TenArgs = unsafe extern "C" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> usize;

#[inline(never)]
unsafe extern "C" fn sum_ten(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    g: usize,
    h: usize,
    i: usize,
    j: usize,
) -> usize {
    a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i + 10 * j
}

unsafe extern "C" fn proxy_sum_ten(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    g: usize,
    h: usize,
    i: usize,
    j: usize,
) -> usize {
    let prev = super::super::get_prev_func(proxy_sum_ten as *mut libc::c_void);
    assert!(!prev.is_null());
    let call: TenArgs = unsafe { std::mem::transmute(prev) };
    let result = unsafe { call(a, b, c, d, e, f, g, h, i, j) };
    super::super::proxy_leave(proxy_sum_ten as *mut libc::c_void);
    result + 1
}

#[test]
fn forwards_stack_arguments_without_moving_the_caller_stack() {
    let hub = super::super::create_hub(sum_ten as *const () as usize).unwrap();
    let call: TenArgs = unsafe { std::mem::transmute(super::super::hub_trampo(hub)) };
    let result = unsafe { call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) };
    assert_eq!(result, 385);
    assert_eq!(
        super::super::add_proxy(hub, proxy_sum_ten as *const () as usize),
        Errno::Ok
    );
    let result = unsafe { call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) };
    super::super::destroy_hub(hub);
    assert_eq!(result, 386);
}

#[test]
fn nested_tail_calls_keep_return_frames_at_the_same_stack_pointer() {
    let inner = super::super::create_hub(sum_ten as *const () as usize).unwrap();
    SRX_ABI_TAIL_TARGET.store(
        super::super::hub_trampo(inner),
        std::sync::atomic::Ordering::Relaxed,
    );
    let outer = super::super::create_hub(srx_abi_tail_call as *const () as usize).unwrap();
    let call: TenArgs = unsafe { std::mem::transmute(super::super::hub_trampo(outer)) };
    assert_eq!(unsafe { call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) }, 385);
    super::super::destroy_hub(outer);
    super::super::destroy_hub(inner);
}

#[inline(never)]
unsafe extern "C" fn sum_ten_floats(
    a: f64,
    b: f64,
    c: f64,
    d: f64,
    e: f64,
    f: f64,
    g: f64,
    h: f64,
    i: f64,
    j: f64,
) -> f64 {
    a + 2.0 * b + 3.0 * c + 4.0 * d + 5.0 * e + 6.0 * f + 7.0 * g + 8.0 * h + 9.0 * i + 10.0 * j
}

#[test]
fn forwards_float_register_and_stack_arguments() {
    let hub = super::super::create_hub(sum_ten_floats as *const () as usize).unwrap();
    let call: unsafe extern "C" fn(f64, f64, f64, f64, f64, f64, f64, f64, f64, f64) -> f64 =
        unsafe { std::mem::transmute(super::super::hub_trampo(hub)) };
    assert_eq!(
        unsafe { call(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0) },
        385.0
    );
    super::super::destroy_hub(hub);
}

#[repr(C)]
#[derive(Debug, PartialEq)]
struct LargeResult {
    a: usize,
    b: usize,
    c: usize,
}

#[inline(never)]
unsafe extern "C" fn large_result(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    g: usize,
    h: usize,
    i: usize,
    j: usize,
) -> LargeResult {
    LargeResult {
        a: a + b + c,
        b: d + e + f,
        c: g + h + i + j,
    }
}

#[test]
fn preserves_hidden_memory_return_pointer_and_stack_arguments() {
    let hub = super::super::create_hub(large_result as *const () as usize).unwrap();
    let call: unsafe extern "C" fn(
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    ) -> LargeResult = unsafe { std::mem::transmute(super::super::hub_trampo(hub)) };
    assert_eq!(
        unsafe { call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) },
        LargeResult { a: 6, b: 15, c: 34 }
    );
    super::super::destroy_hub(hub);
}

static RECURSIVE_ENTRY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[inline(never)]
unsafe extern "C" fn recurse_past_capacity(depth: usize) -> usize {
    if depth == 0 {
        return 0;
    }
    let call: unsafe extern "C" fn(usize) -> usize =
        unsafe { std::mem::transmute(RECURSIVE_ENTRY.load(std::sync::atomic::Ordering::Relaxed)) };
    unsafe { call(depth - 1) + 1 }
}

#[test]
fn return_stack_overflow_reaches_original_and_preserves_outer_returns() {
    let before = crate::runtime::thread_state::current_active_trampoline_count();
    let hub = super::super::create_hub(recurse_past_capacity as *const () as usize).unwrap();
    let entry = super::super::hub_trampo(hub);
    RECURSIVE_ENTRY.store(entry, std::sync::atomic::Ordering::Relaxed);
    let call: unsafe extern "C" fn(usize) -> usize = unsafe { std::mem::transmute(entry) };
    let depth = crate::runtime::thread_state::HUB_STACK_CAP + 8;
    assert_eq!(unsafe { call(depth) }, depth);
    assert_eq!(
        crate::runtime::thread_state::current_active_trampoline_count(),
        before
    );
    super::super::destroy_hub(hub);
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, PartialEq)]
struct FourDoubles {
    a: f64,
    b: f64,
    c: f64,
    d: f64,
}

#[cfg(target_arch = "aarch64")]
#[inline(never)]
unsafe extern "C" fn four_doubles() -> FourDoubles {
    FourDoubles {
        a: 1.25,
        b: 2.5,
        c: 3.75,
        d: 5.0,
    }
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" fn pop_clobber_float_registers(hub: *mut super::super::Hub, sp: usize) -> usize {
    let result = super::super::stack::hub_pop_stack(hub, sp);
    unsafe {
        std::arch::asm!("movi v2.16b, #0", "movi v3.16b, #0", out("v2") _, out("v3") _, options(nomem, nostack, preserves_flags))
    };
    result
}

#[cfg(target_arch = "aarch64")]
#[test]
fn preserves_all_four_homogeneous_float_return_registers() {
    let hub = super::super::create_hub(four_doubles as *const () as usize).unwrap();
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let page = unsafe {
        libc::mmap(
            ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    unsafe {
        init_trampo(
            page as usize,
            hub as usize,
            super::super::stack::hub_push_stack as *const () as usize,
            pop_clobber_float_registers as *const () as usize,
        )
        .unwrap()
    };
    crate::android::memory::flush_instruction_cache_range(page as usize, page as usize + page_size);
    assert_eq!(
        unsafe { libc::mprotect(page, page_size, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    let call: unsafe extern "C" fn() -> FourDoubles = unsafe { std::mem::transmute(page) };
    let result = unsafe { call() };
    assert_eq!(unsafe { libc::munmap(page, page_size) }, 0);
    super::super::destroy_hub(hub);
    assert_eq!(result, unsafe { four_doubles() });
}
