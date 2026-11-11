use std::env;
#[cfg(target_arch = "aarch64")]
use std::ffi;
use std::ffi::{CString, c_char, c_void};
use std::fs;
use std::mem;
#[cfg(target_arch = "aarch64")]
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use srx_hook::{
    SrxHookErrno, get_prev_func, get_return_address, pop_stack, proxy_leave, with_prev_func,
};

pub static HOOK_A_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static HOOK_B_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static HOOK_C_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static STACK_API_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static DLOPEN_PRE_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static DLOPEN_POST_COUNT: AtomicUsize = AtomicUsize::new(0);

pub type PutsFn = unsafe extern "C" fn(*const c_char) -> i32;
pub type StrlenFn = unsafe extern "C" fn(*const c_char) -> usize;

#[cfg(target_arch = "aarch64")]
const ARM64_RET_INST: u32 = 0xd65f03c0;
#[cfg(target_arch = "aarch64")]
const ANDROID_API_LEVEL_CFI_DISABLE: i32 = 26;
#[cfg(target_arch = "aarch64")]
const SYSTEM_PROP_VALUE_MAX: usize = 92;

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> libc::c_int;
}

pub unsafe extern "C" fn hook_puts_a_chain(s: *const c_char) -> i32 {
    HOOK_A_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_puts_a_chain as *mut c_void;
    with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            return 0;
        }
        let prev_fn: PutsFn = unsafe { mem::transmute(prev) };
        unsafe { prev_fn(s) }
    })
    .unwrap_or(0)
}

pub unsafe extern "C" fn hook_puts_b_chain(s: *const c_char) -> i32 {
    HOOK_B_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_puts_b_chain as *mut c_void;
    with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            return 0;
        }
        let prev_fn: PutsFn = unsafe { mem::transmute(prev) };
        unsafe { prev_fn(s) }
    })
    .unwrap_or(0)
}

pub unsafe extern "C" fn hook_puts_c_chain(s: *const c_char) -> i32 {
    HOOK_C_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_puts_c_chain as *mut c_void;
    with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            return 0;
        }
        let prev_fn: PutsFn = unsafe { mem::transmute(prev) };
        unsafe { prev_fn(s) }
    })
    .unwrap_or(0)
}

pub unsafe extern "C" fn hook_puts_quiet(s: *const c_char) -> i32 {
    HOOK_A_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_puts_quiet as *mut c_void;
    let _ = s;
    proxy_leave(self_ptr);
    0
}

pub unsafe extern "C" fn hook_puts_no_leave(s: *const c_char) -> i32 {
    HOOK_A_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_puts_no_leave as *mut c_void;
    let prev = get_prev_func(self_ptr);
    if prev.is_null() {
        return 0;
    }
    let prev_fn: PutsFn = unsafe { mem::transmute(prev) };
    unsafe { prev_fn(s) }
}

pub unsafe extern "C" fn hook_puts_return_address_stack(s: *const c_char) -> i32 {
    STACK_API_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_puts_return_address_stack as *mut c_void;
    let return_address = get_return_address();
    assert!(
        !return_address.is_null(),
        "return_address API should be valid in proxy context"
    );
    let prev = get_prev_func(self_ptr);
    let result = if prev.is_null() {
        0
    } else {
        let prev_fn: PutsFn = unsafe { mem::transmute(prev) };
        unsafe { prev_fn(s) }
    };
    pop_stack(return_address);
    result
}

pub unsafe extern "C" fn hook_puts_cycle_guard(s: *const c_char) -> i32 {
    HOOK_A_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_puts_cycle_guard as *mut c_void;
    with_prev_func(self_ptr, |prev| {
        let mut result = 0;
        if !prev.is_null() {
            let prev_fn: PutsFn = unsafe { mem::transmute(prev) };
            result = unsafe { prev_fn(s) };
        }
        if !s.is_null() {
            let _ = unsafe { libc::strlen(s) };
        }
        result
    })
    .unwrap_or(0)
}

pub unsafe extern "C" fn hook_puts_cycle_manual_no_leave(s: *const c_char) -> i32 {
    HOOK_A_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_puts_cycle_manual_no_leave as *mut c_void;
    let prev = get_prev_func(self_ptr);
    let mut result = 0;
    if !prev.is_null() {
        let prev_fn: PutsFn = unsafe { mem::transmute(prev) };
        result = unsafe { prev_fn(s) };
    }
    if !s.is_null() {
        let _ = unsafe { libc::strlen(s) };
    }
    result
}

pub unsafe extern "C" fn hook_strlen_cycle_guard(s: *const c_char) -> usize {
    HOOK_B_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_strlen_cycle_guard as *mut c_void;
    with_prev_func(self_ptr, |prev| {
        let mut result = 0usize;
        if !prev.is_null() {
            let prev_fn: StrlenFn = unsafe { mem::transmute(prev) };
            result = unsafe { prev_fn(s) };
        }
        let msg = b"cycle-guard\n\0";
        let _ = unsafe { libc::puts(msg.as_ptr() as *const c_char) };
        result
    })
    .unwrap_or(0)
}

pub unsafe extern "C" fn hook_strlen_cycle_manual_no_leave(s: *const c_char) -> usize {
    HOOK_B_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_strlen_cycle_manual_no_leave as *mut c_void;
    let prev = get_prev_func(self_ptr);
    let mut result = 0usize;
    if !prev.is_null() {
        let prev_fn: StrlenFn = unsafe { mem::transmute(prev) };
        result = unsafe { prev_fn(s) };
    }
    let msg = b"cycle-manual\n\0";
    let _ = unsafe { libc::puts(msg.as_ptr() as *const c_char) };
    result
}

pub unsafe extern "C" fn hook_test_dlopen_pre(_filename: *const c_char, _arg: *mut c_void) {
    DLOPEN_PRE_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub unsafe extern "C" fn hook_test_dlopen_post(
    _filename: *const c_char,
    _result: i32,
    _arg: *mut c_void,
) {
    DLOPEN_POST_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn ensure_ok(code: SrxHookErrno, op: &str) {
    assert_eq!(code, SrxHookErrno::Ok, "{op} failed: {code:?}");
}

pub fn current_rss_kb() -> usize {
    let content = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in content.lines() {
        if !line.starts_with("VmRSS:") {
            continue;
        }
        let value = line
            .split_whitespace()
            .nth(1)
            .and_then(|num| num.parse::<usize>().ok())
            .unwrap_or(0);
        return value;
    }
    0
}

pub fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

pub fn env_flag(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub struct ScopedEnv {
    name: CString,
    old_value: Option<CString>,
}

impl ScopedEnv {
    pub fn set(name: &str, value: &str) -> Self {
        let name_c = CString::new(name).expect("scoped env name contains interior nul");
        let value_c = CString::new(value).expect("scoped env value contains interior nul");
        let old_value = env::var(name).ok().and_then(|text| CString::new(text).ok());

        let set_ret = unsafe { libc::setenv(name_c.as_ptr(), value_c.as_ptr(), 1) };
        assert_eq!(set_ret, 0, "setenv failed for {name}");
        Self {
            name: name_c,
            old_value,
        }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        unsafe {
            if let Some(old_value) = &self.old_value {
                let _ = libc::setenv(self.name.as_ptr(), old_value.as_ptr(), 1);
            } else {
                let _ = libc::unsetenv(self.name.as_ptr());
            }
        }
    }
}

const HOOK_TEST_WORK_DIR: &str = "/data/local/tmp/srx_hook_test";

#[cfg(target_arch = "aarch64")]
fn android_api_level() -> i32 {
    let prop_name = c"ro.build.version.sdk";
    let mut prop_value = [0 as c_char; SYSTEM_PROP_VALUE_MAX];
    let len = unsafe { __system_property_get(prop_name.as_ptr(), prop_value.as_mut_ptr()) };
    if len <= 0 {
        return 0;
    }
    let len = len as usize;
    if len >= SYSTEM_PROP_VALUE_MAX {
        return 0;
    }

    let value = unsafe { ffi::CStr::from_ptr(prop_value.as_ptr()) };
    value
        .to_str()
        .ok()
        .and_then(|text| text.parse::<i32>().ok())
        .unwrap_or(0)
}

pub unsafe fn verify_cfi_slowpath_disabled() {
    #[cfg(target_arch = "aarch64")]
    {
        if android_api_level() < ANDROID_API_LEVEL_CFI_DISABLE {
            return;
        }

        let handle = libc::dlopen(c"libdl.so".as_ptr(), libc::RTLD_NOW);
        assert!(!handle.is_null(), "verify cfi: dlopen libdl.so failed");
        let slowpath = libc::dlsym(handle, c"__cfi_slowpath".as_ptr());
        let slowpath_diag = libc::dlsym(handle, c"__cfi_slowpath_diag".as_ptr());
        assert!(!slowpath.is_null(), "verify cfi: __cfi_slowpath missing");

        let slowpath_inst = ptr::read_volatile(slowpath as *const u32);
        assert_eq!(
            slowpath_inst, ARM64_RET_INST,
            "verify cfi: __cfi_slowpath not patched"
        );
        if !slowpath_diag.is_null() {
            let slowpath_diag_inst = ptr::read_volatile(slowpath_diag as *const u32);
            assert_eq!(
                slowpath_diag_inst, ARM64_RET_INST,
                "verify cfi: __cfi_slowpath_diag not patched"
            );
        }
        libc::dlclose(handle);
    }
}

pub unsafe fn resolve_symbol_module_base(symbol_name: &str) -> Option<usize> {
    let symbol = CString::new(symbol_name).ok()?;
    let symbol_addr = libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr());
    if symbol_addr.is_null() {
        return None;
    }

    let mut info: libc::Dl_info = mem::zeroed();
    if libc::dladdr(symbol_addr as *const c_void, &mut info) == 0 || info.dli_fbase.is_null() {
        return None;
    }
    Some(info.dli_fbase as usize)
}

pub unsafe fn load_hook_test_with_flags(flags: libc::c_int) -> *mut c_void {
    let lib_name = CString::new("libhook_test.so").expect("cstring failed");
    let handle = libc::dlopen(lib_name.as_ptr(), flags);
    assert!(!handle.is_null(), "dlopen libhook_test.so failed");
    handle
}

pub unsafe fn load_hook_test() -> *mut c_void {
    load_hook_test_with_flags(libc::RTLD_NOW)
}

pub unsafe fn load_hook_test_lazy() -> *mut c_void {
    load_hook_test_with_flags(libc::RTLD_LAZY)
}

pub fn prepare_same_basename_hook_test_instances() -> (CString, CString) {
    let src = format!("{HOOK_TEST_WORK_DIR}/libhook_test.so");
    let dir_a = format!("{HOOK_TEST_WORK_DIR}/ns_a");
    let dir_b = format!("{HOOK_TEST_WORK_DIR}/ns_b");
    let dst_a = format!("{dir_a}/libhook_test.so");
    let dst_b = format!("{dir_b}/libhook_test.so");

    fs::create_dir_all(&dir_a).expect("create ns_a dir failed");
    fs::create_dir_all(&dir_b).expect("create ns_b dir failed");
    fs::copy(&src, &dst_a).expect("copy libhook_test to ns_a failed");
    fs::copy(&src, &dst_b).expect("copy libhook_test to ns_b failed");

    let path_a = CString::new(dst_a).expect("path_a cstring failed");
    let path_b = CString::new(dst_b).expect("path_b cstring failed");
    (path_a, path_b)
}

pub unsafe fn load_hook_test_abs(path: &CString) -> *mut c_void {
    let handle = libc::dlopen(path.as_ptr(), libc::RTLD_NOW);
    assert!(!handle.is_null(), "dlopen abs hook_test failed");
    handle
}

pub unsafe fn module_base_from_handle(handle: *mut c_void) -> Option<usize> {
    if handle.is_null() {
        return None;
    }
    let sym = libc::dlsym(handle, c"hook_test_trigger".as_ptr());
    if sym.is_null() {
        return None;
    }
    let mut info: libc::Dl_info = mem::zeroed();
    if libc::dladdr(sym as *const c_void, &mut info) == 0 || info.dli_fbase.is_null() {
        return None;
    }
    Some(info.dli_fbase as usize)
}

pub unsafe fn module_instance_from_handle(handle: *mut c_void) -> Option<usize> {
    let base = module_base_from_handle(handle)?;
    #[repr(C)]
    struct Query {
        base: usize,
        instance: usize,
    }

    unsafe extern "C" fn iterate_cb(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut c_void,
    ) -> libc::c_int {
        if info.is_null() || data.is_null() {
            return 0;
        }
        let info = unsafe { &*info };
        let query = unsafe { &mut *(data as *mut Query) };
        if info.dlpi_addr as usize != query.base {
            return 0;
        }
        query.instance = info.dlpi_name as usize;
        1
    }

    let mut query = Query { base, instance: 0 };
    unsafe {
        libc::dl_iterate_phdr(Some(iterate_cb), &mut query as *mut _ as *mut c_void);
    }
    if query.instance == 0 {
        None
    } else {
        Some(query.instance)
    }
}

pub unsafe fn hook_test_trigger(handle: *mut c_void) {
    let sym_name = CString::new("hook_test_trigger").expect("cstring failed");
    let sym = libc::dlsym(handle, sym_name.as_ptr());
    assert!(!sym.is_null(), "dlsym hook_test_trigger failed");
    let trigger: unsafe extern "C" fn() = mem::transmute(sym);
    trigger();
}

pub unsafe fn hook_test_trigger_with_input(handle: *mut c_void, msg: &CString) {
    let sym_name = CString::new("hook_test_trigger_with_input").expect("cstring failed");
    let sym = libc::dlsym(handle, sym_name.as_ptr());
    assert!(!sym.is_null(), "dlsym hook_test_trigger_with_input failed");
    let trigger: unsafe extern "C" fn(*const c_char) = mem::transmute(sym);
    trigger(msg.as_ptr());
}
