use std::ffi::{CString, c_char, c_void};
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use srx_hook::{
    SrxHookErrno, get_prev_func, get_return_address, pop_stack, proxy_leave, unhook, with_prev_func,
};

pub static HOOK_A_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static HOOK_B_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static HOOK_C_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static FORK_PROXY_CHILD_STATUS: AtomicI32 = AtomicI32::new(-1);
pub static CLEAR_PROXY_ENTERED: AtomicBool = AtomicBool::new(false);
pub static CLEAR_PROXY_RELEASE: AtomicBool = AtomicBool::new(false);
pub static CLEAR_PROXY_RESULT: AtomicI32 = AtomicI32::new(-1);
pub static CLEAR_SELF_PROXY_ENTERED: AtomicBool = AtomicBool::new(false);
pub static CLEAR_SELF_PROXY_RELEASE: AtomicBool = AtomicBool::new(false);
pub static CLEAR_SELF_PROXY_RESULT: AtomicI32 = AtomicI32::new(-1);
pub static STACK_API_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static DLOPEN_PRE_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static DLOPEN_POST_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static HOOKED_CALLBACK_UNHOOK_STATUS: AtomicI32 = AtomicI32::new(-1);
pub static HOOKED_CALLBACK_CLEAR_REINIT_STATUS: AtomicI32 = AtomicI32::new(-1);
pub static HOOKED_CALLBACK_FROM_OTHER_THREAD: AtomicBool = AtomicBool::new(false);
pub static HOOKED_CALLBACK_MAIN_THREAD: AtomicUsize = AtomicUsize::new(0);
pub static RECURSIVE_HOOK_TEST_HANDLE: AtomicUsize = AtomicUsize::new(0);
pub static RECURSIVE_PROXY_CALLS: AtomicUsize = AtomicUsize::new(0);
pub static RECURSIVE_PREV_RESULT: AtomicI32 = AtomicI32::new(-1);

pub type PutsFn = unsafe extern "C" fn(*const c_char) -> i32;
pub type StrlenFn = unsafe extern "C" fn(*const c_char) -> usize;

pub unsafe fn wait_child(pid: libc::pid_t) -> Option<i32> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return Some(status);
        }
        if waited < 0 && unsafe { *libc::__errno() } == libc::EINTR {
            continue;
        }
        if waited < 0 {
            return None;
        }
        if Instant::now() >= deadline {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            loop {
                let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
                if waited == pid {
                    break;
                }
                if waited < 0 && unsafe { *libc::__errno() } == libc::EINTR {
                    continue;
                }
                return None;
            }
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

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
        let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
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
        let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
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
        let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
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

pub unsafe extern "C" fn hook_puts_recurse_then_prev(s: *const c_char) -> i32 {
    HOOK_A_COUNT.fetch_add(1, Ordering::Relaxed);
    if RECURSIVE_PROXY_CALLS.fetch_add(1, Ordering::Relaxed) == 0 {
        let handle = RECURSIVE_HOOK_TEST_HANDLE.load(Ordering::Relaxed) as *mut c_void;
        unsafe { hook_test_trigger(handle) };
    }

    let self_ptr = hook_puts_recurse_then_prev as *mut c_void;
    let result = with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            return -1;
        }
        let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
        unsafe { prev_fn(s) }
    })
    .unwrap_or(-1);
    RECURSIVE_PREV_RESULT.store(result, Ordering::Release);
    result
}

pub unsafe extern "C" fn unhook_from_hooked_callback(
    task_stub: srx_hook::HookStub,
    status_code: i32,
    _caller_path_name: *const c_char,
    _sym_name: *const c_char,
    _new_func: *mut c_void,
    _prev_func: *mut c_void,
    _arg: *mut c_void,
) {
    if libc::pthread_self() as usize != HOOKED_CALLBACK_MAIN_THREAD.load(Ordering::Relaxed) {
        HOOKED_CALLBACK_FROM_OTHER_THREAD.store(true, Ordering::Relaxed);
    }
    if status_code == SrxHookErrno::Ok.as_i32()
        && HOOKED_CALLBACK_UNHOOK_STATUS
            .compare_exchange(-1, i32::MIN, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        HOOKED_CALLBACK_UNHOOK_STATUS.store(unhook(task_stub).as_i32(), Ordering::Relaxed);
    }
}

pub unsafe extern "C" fn clear_and_reinit_from_hooked_callback(
    _task_stub: srx_hook::HookStub,
    status_code: i32,
    _caller_path_name: *const c_char,
    _sym_name: *const c_char,
    _new_func: *mut c_void,
    _prev_func: *mut c_void,
    _arg: *mut c_void,
) {
    if status_code != SrxHookErrno::Ok.as_i32()
        || HOOKED_CALLBACK_CLEAR_REINIT_STATUS
            .compare_exchange(-1, i32::MIN, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }

    if libc::pthread_self() as usize != HOOKED_CALLBACK_MAIN_THREAD.load(Ordering::Relaxed) {
        HOOKED_CALLBACK_FROM_OTHER_THREAD.store(true, Ordering::Relaxed);
    }
    srx_hook::clear();
    let status = srx_hook::init(srx_hook::HookMode::Automatic, true);
    HOOKED_CALLBACK_CLEAR_REINIT_STATUS.store(status.as_i32(), Ordering::Release);
}

pub unsafe extern "C" fn hook_puts_wait_for_clear(s: *const c_char) -> i32 {
    let self_ptr = hook_puts_wait_for_clear as *mut c_void;
    CLEAR_PROXY_ENTERED.store(true, Ordering::Release);
    while !CLEAR_PROXY_RELEASE.load(Ordering::Acquire) {
        unsafe { libc::sched_yield() };
    }
    let result = with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            return -1;
        }
        let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
        unsafe { prev_fn(s) }
    })
    .unwrap_or(-1);
    CLEAR_PROXY_RESULT.store(result, Ordering::Release);
    result
}

pub unsafe extern "C" fn hook_puts_clear_self_and_wait(s: *const c_char) -> i32 {
    let self_ptr = hook_puts_clear_self_and_wait as *mut c_void;
    srx_hook::clear();
    CLEAR_SELF_PROXY_ENTERED.store(true, Ordering::Release);
    while !CLEAR_SELF_PROXY_RELEASE.load(Ordering::Acquire) {
        unsafe { libc::sched_yield() };
    }
    let result = with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            return -1;
        }
        let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
        unsafe { prev_fn(s) }
    })
    .unwrap_or(-1);
    CLEAR_SELF_PROXY_RESULT.store(result, Ordering::Release);
    result
}

pub unsafe extern "C" fn hook_puts_fork_from_proxy(s: *const c_char) -> i32 {
    let self_ptr = hook_puts_fork_from_proxy as *mut c_void;
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        if srx_hook::refresh().0 != SrxHookErrno::Ok {
            unsafe { libc::_exit(1) };
        }
        let next = get_prev_func(self_ptr);
        let return_address = get_return_address();
        if next.is_null() || return_address.is_null() {
            unsafe { libc::_exit(1) };
        }
        return with_prev_func(self_ptr, |prev| {
            let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
            unsafe { prev_fn(s) }
        })
        .unwrap_or(-1);
    }
    if pid < 0 {
        FORK_PROXY_CHILD_STATUS.store(2, Ordering::Relaxed);
        return -1;
    }

    let Some(status) = (unsafe { wait_child(pid) }) else {
        FORK_PROXY_CHILD_STATUS.store(2, Ordering::Relaxed);
        return -1;
    };
    let child_ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    FORK_PROXY_CHILD_STATUS.store(if child_ok { 0 } else { 1 }, Ordering::Relaxed);

    with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            return 0;
        }
        let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
        unsafe { prev_fn(s) }
    })
    .unwrap_or(0)
}

pub unsafe extern "C" fn hook_puts_no_leave(s: *const c_char) -> i32 {
    HOOK_A_COUNT.fetch_add(1, Ordering::Relaxed);
    let self_ptr = hook_puts_no_leave as *mut c_void;
    let prev = get_prev_func(self_ptr);
    if prev.is_null() {
        return 0;
    }
    let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
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
        let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
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
            let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
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
        let prev_fn: PutsFn = unsafe { std::mem::transmute(prev) };
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
            let prev_fn: StrlenFn = unsafe { std::mem::transmute(prev) };
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
        let prev_fn: StrlenFn = unsafe { std::mem::transmute(prev) };
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
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

pub fn env_flag(name: &str) -> bool {
    std::env::var(name)
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
        let old_value = std::env::var(name)
            .ok()
            .and_then(|text| CString::new(text).ok());

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

    let value = unsafe { std::ffi::CStr::from_ptr(prop_value.as_ptr()) };
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

        let slowpath_inst = std::ptr::read_volatile(slowpath as *const u32);
        assert_eq!(
            slowpath_inst, ARM64_RET_INST,
            "verify cfi: __cfi_slowpath not patched"
        );
        if !slowpath_diag.is_null() {
            let slowpath_diag_inst = std::ptr::read_volatile(slowpath_diag as *const u32);
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

    let mut info: libc::Dl_info = std::mem::zeroed();
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
    // 用测试可执行文件所在目录作为工作目录，避免硬编码目录在非 root 运行时
    // 不可写；ns_a/ns_b 只要求同 basename 的两个独立文件路径。
    let exe = std::env::current_exe().expect("current_exe failed");
    let work_dir = exe
        .parent()
        .expect("current_exe parent failed")
        .to_path_buf();
    let src = work_dir.join("libhook_test.so");
    let dir_a = work_dir.join("ns_a");
    let dir_b = work_dir.join("ns_b");
    let dst_a = dir_a.join("libhook_test.so");
    let dst_b = dir_b.join("libhook_test.so");

    fs::create_dir_all(&dir_a).expect("create ns_a dir failed");
    fs::create_dir_all(&dir_b).expect("create ns_b dir failed");
    fs::copy(&src, &dst_a).expect("copy libhook_test to ns_a failed");
    fs::copy(&src, &dst_b).expect("copy libhook_test to ns_b failed");

    let path_a = CString::new(dst_a.to_string_lossy().as_bytes()).expect("path_a cstring failed");
    let path_b = CString::new(dst_b.to_string_lossy().as_bytes()).expect("path_b cstring failed");
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
    let mut info: libc::Dl_info = std::mem::zeroed();
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
    let trigger: unsafe extern "C" fn() = std::mem::transmute(sym);
    trigger();
}

pub unsafe fn hook_test_trigger_with_input(handle: *mut c_void, msg: &CString) {
    let sym_name = CString::new("hook_test_trigger_with_input").expect("cstring failed");
    let sym = libc::dlsym(handle, sym_name.as_ptr());
    assert!(!sym.is_null(), "dlsym hook_test_trigger_with_input failed");
    let trigger: unsafe extern "C" fn(*const c_char) = std::mem::transmute(sym);
    trigger(msg.as_ptr());
}
