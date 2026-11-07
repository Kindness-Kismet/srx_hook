// dlopen/dlclose 系列函数的真实地址解析与调用封装
// 支持 loader 符号、linker 内部符号和标准 libc 符号三级回退
use crate::log;
use std::ffi::{CStr, c_char, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::monitor;

// 缓存各 dlopen/dlclose 变体的真实函数地址，首次调用时通过 RTLD_NEXT 解析
static REAL_DLOPEN: SymbolAddress = SymbolAddress::new();
static REAL_ANDROID_DLOPEN_EXT: SymbolAddress = SymbolAddress::new();
static REAL_DLCLOSE: SymbolAddress = SymbolAddress::new();
static REAL_LOADER_DLOPEN: SymbolAddress = SymbolAddress::new();
static REAL_LOADER_ANDROID_DLOPEN_EXT: SymbolAddress = SymbolAddress::new();
static REAL_LOADER_DLCLOSE: SymbolAddress = SymbolAddress::new();
static REAL_LINKER_DLOPEN_EXT: SymbolAddress = SymbolAddress::new();
static REAL_LINKER_DO_DLOPEN: SymbolAddress = SymbolAddress::new();
static REAL_LINKER_G_DL_MUTEX: SymbolAddress = SymbolAddress::new();
static REAL_LINKER_GET_ERROR_BUFFER: SymbolAddress = SymbolAddress::new();
const RTLD_NEXT_FALLBACK: *mut c_void = (-1isize) as *mut c_void;

struct SymbolAddress(AtomicUsize);

impl SymbolAddress {
    const UNRESOLVED: usize = usize::MAX;

    const fn new() -> Self {
        Self(AtomicUsize::new(Self::UNRESOLVED))
    }

    // 解析完成后发布地址，fork 继承的缓存始终为空或完整地址。
    fn get_or_init(&self, resolve: impl FnOnce() -> usize) -> usize {
        let current = self.0.load(Ordering::Acquire);
        if current != Self::UNRESOLVED {
            return current;
        }
        let resolved = resolve();
        match self.0.compare_exchange(
            Self::UNRESOLVED,
            resolved,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => resolved,
            Err(published) => published,
        }
    }
}

// 安装任何 loader proxy 前完成解析，子进程直接继承已发布地址。
pub(super) fn prime_for_fork() {
    let symbols = [
        (&REAL_DLOPEN, c"dlopen"),
        (&REAL_ANDROID_DLOPEN_EXT, c"android_dlopen_ext"),
        (&REAL_DLCLOSE, c"dlclose"),
        (&REAL_LOADER_DLOPEN, c"__loader_dlopen"),
        (
            &REAL_LOADER_ANDROID_DLOPEN_EXT,
            c"__loader_android_dlopen_ext",
        ),
        (&REAL_LOADER_DLCLOSE, c"__loader_dlclose"),
        (
            &REAL_LINKER_DLOPEN_EXT,
            c"__dl__ZL10dlopen_extPKciPK17android_dlextinfoPv",
        ),
        (
            &REAL_LINKER_DO_DLOPEN,
            c"__dl__Z9do_dlopenPKciPK17android_dlextinfoPv",
        ),
        (
            &REAL_LINKER_GET_ERROR_BUFFER,
            c"__dl__Z23linker_get_error_bufferv",
        ),
    ];
    for (address, name) in symbols {
        address.get_or_init(|| unsafe { resolve_symbol(name) });
    }
    REAL_LINKER_G_DL_MUTEX
        .get_or_init(|| unsafe { resolve_symbols(&[c"__dl__ZL10g_dl_mutex", c"__dl_g_dl_mutex"]) });
}

pub(super) unsafe fn call_dlopen_fn(
    addr: usize,
    filename: *const c_char,
    flags: libc::c_int,
) -> *mut c_void {
    if addr == 0 {
        return std::ptr::null_mut();
    }
    let func: unsafe extern "C" fn(*const c_char, libc::c_int) -> *mut c_void =
        std::mem::transmute(addr as *mut c_void);
    func(filename, flags)
}

pub(super) unsafe fn call_android_dlopen_ext_fn(
    addr: usize,
    filename: *const c_char,
    flags: libc::c_int,
    extinfo: *const c_void,
) -> *mut c_void {
    if addr == 0 {
        return std::ptr::null_mut();
    }
    let func: unsafe extern "C" fn(*const c_char, libc::c_int, *const c_void) -> *mut c_void =
        std::mem::transmute(addr as *mut c_void);
    func(filename, flags, extinfo)
}

pub(super) unsafe fn call_dlclose_fn(addr: usize, handle: *mut c_void) -> libc::c_int {
    if addr == 0 {
        return -1;
    }
    let func: unsafe extern "C" fn(*mut c_void) -> libc::c_int =
        std::mem::transmute(addr as *mut c_void);
    func(handle)
}

pub(super) unsafe fn call_loader_dlopen_fn(
    addr: usize,
    filename: *const c_char,
    flags: libc::c_int,
    caller_addr: *const c_void,
) -> *mut c_void {
    if addr == 0 {
        return std::ptr::null_mut();
    }
    let func: unsafe extern "C" fn(*const c_char, libc::c_int, *const c_void) -> *mut c_void =
        std::mem::transmute(addr as *mut c_void);
    func(filename, flags, caller_addr)
}

pub(super) unsafe fn call_loader_android_dlopen_ext_fn(
    addr: usize,
    filename: *const c_char,
    flags: libc::c_int,
    extinfo: *const c_void,
    caller_addr: *const c_void,
) -> *mut c_void {
    if addr == 0 {
        return std::ptr::null_mut();
    }
    let func: unsafe extern "C" fn(
        *const c_char,
        libc::c_int,
        *const c_void,
        *const c_void,
    ) -> *mut c_void = std::mem::transmute(addr as *mut c_void);
    func(filename, flags, extinfo, caller_addr)
}

pub(super) unsafe fn call_loader_dlclose_fn(addr: usize, handle: *mut c_void) -> libc::c_int {
    if addr == 0 {
        return -1;
    }
    let func: unsafe extern "C" fn(*mut c_void) -> libc::c_int =
        std::mem::transmute(addr as *mut c_void);
    func(handle)
}

unsafe fn call_linker_dlopen_ext_fn(
    addr: usize,
    filename: *const c_char,
    flags: libc::c_int,
    extinfo: *const c_void,
    caller_addr: *const c_void,
) -> *mut c_void {
    if addr == 0 {
        return std::ptr::null_mut();
    }
    let func: unsafe extern "C" fn(
        *const c_char,
        libc::c_int,
        *const c_void,
        *const c_void,
    ) -> *mut c_void = std::mem::transmute(addr as *mut c_void);
    func(filename, flags, extinfo, caller_addr)
}

unsafe fn resolve_symbol(name: &CStr) -> usize {
    let _loader_call = crate::runtime::LoaderCall::enter();
    let ptr = libc::dlsym(RTLD_NEXT_FALLBACK, name.as_ptr());
    ptr as usize
}

unsafe fn resolve_symbols(names: &[&CStr]) -> usize {
    for name in names {
        let addr = unsafe { resolve_symbol(name) };
        if addr != 0 {
            return addr;
        }
    }
    0
}

// 获取 linker 内部错误缓冲区内容，用于 do_dlopen 回退失败时的诊断
unsafe fn linker_error_message() -> Option<String> {
    let get_error_buffer = REAL_LINKER_GET_ERROR_BUFFER
        .get_or_init(|| unsafe { resolve_symbol(c"__dl__Z23linker_get_error_bufferv") });
    if get_error_buffer == 0 {
        return None;
    }
    let func: unsafe extern "C" fn() -> *const c_char =
        unsafe { std::mem::transmute(get_error_buffer as *mut c_void) };
    let ptr = unsafe { func() };
    if ptr.is_null() {
        return None;
    }
    let text = unsafe { CStr::from_ptr(ptr) }.to_str().ok()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

pub(super) unsafe fn call_real_dlopen(filename: *const c_char, flags: libc::c_int) -> *mut c_void {
    let name = c"dlopen";
    let addr = REAL_DLOPEN.get_or_init(|| unsafe { resolve_symbol(name) });
    call_dlopen_fn(addr, filename, flags)
}

// 带 caller_addr 的 dlopen 调用，依次尝试 dlopen_ext -> do_dlopen -> 标准 dlopen
pub(super) unsafe fn call_real_dlopen_with_caller(
    filename: *const c_char,
    flags: libc::c_int,
    extinfo: *const c_void,
    caller_addr: *const c_void,
) -> *mut c_void {
    let linker_dlopen_ext = REAL_LINKER_DLOPEN_EXT.get_or_init(|| unsafe {
        resolve_symbol(c"__dl__ZL10dlopen_extPKciPK17android_dlextinfoPv")
    });
    if linker_dlopen_ext != 0 {
        let handle = unsafe {
            call_linker_dlopen_ext_fn(linker_dlopen_ext, filename, flags, extinfo, caller_addr)
        };
        if !handle.is_null() {
            return handle;
        }
    }

    let linker_do_dlopen = REAL_LINKER_DO_DLOPEN
        .get_or_init(|| unsafe { resolve_symbol(c"__dl__Z9do_dlopenPKciPK17android_dlextinfoPv") });
    if linker_do_dlopen != 0 {
        let linker_mutex = REAL_LINKER_G_DL_MUTEX.get_or_init(|| unsafe {
            resolve_symbols(&[c"__dl__ZL10g_dl_mutex", c"__dl_g_dl_mutex"])
        });
        if linker_mutex != 0 {
            let _ = unsafe { libc::pthread_mutex_lock(linker_mutex as *mut libc::pthread_mutex_t) };
        }
        let handle = unsafe {
            call_linker_dlopen_ext_fn(linker_do_dlopen, filename, flags, extinfo, caller_addr)
        };
        if linker_mutex != 0 {
            let _ =
                unsafe { libc::pthread_mutex_unlock(linker_mutex as *mut libc::pthread_mutex_t) };
        }
        if !handle.is_null() {
            return handle;
        }
        if let Some(err) = unsafe { linker_error_message() } {
            log::debug(format_args!("linker do_dlopen fallback failed: {}", err));
        }
    }

    unsafe {
        if extinfo.is_null() {
            call_real_dlopen(filename, flags)
        } else {
            call_real_android_dlopen_ext(filename, flags, extinfo)
        }
    }
}

pub(super) unsafe fn call_real_android_dlopen_ext(
    filename: *const c_char,
    flags: libc::c_int,
    extinfo: *const c_void,
) -> *mut c_void {
    let name = c"android_dlopen_ext";
    let addr = REAL_ANDROID_DLOPEN_EXT.get_or_init(|| unsafe { resolve_symbol(name) });
    call_android_dlopen_ext_fn(addr, filename, flags, extinfo)
}

pub(super) unsafe fn call_real_dlclose(handle: *mut c_void) -> libc::c_int {
    let name = c"dlclose";
    let addr = REAL_DLCLOSE.get_or_init(|| unsafe { resolve_symbol(name) });
    call_dlclose_fn(addr, handle)
}

// loader 版 dlopen，失败时回退到 linker 内部函数并上报 fallback 事件
pub(super) unsafe fn call_real_loader_dlopen(
    filename: *const c_char,
    flags: libc::c_int,
    caller_addr: *const c_void,
) -> *mut c_void {
    let name = c"__loader_dlopen";
    let addr = REAL_LOADER_DLOPEN.get_or_init(|| unsafe { resolve_symbol(name) });
    if addr != 0 {
        let handle = call_loader_dlopen_fn(addr, filename, flags, caller_addr);
        if !handle.is_null() {
            monitor::note_loader_call_success();
            return handle;
        }
        monitor::note_loader_call_fallback("loader_dlopen_returned_null");
    } else {
        monitor::note_loader_call_fallback("loader_dlopen_symbol_missing");
    }
    call_real_dlopen_with_caller(filename, flags, std::ptr::null(), caller_addr)
}

pub(super) unsafe fn call_real_loader_android_dlopen_ext(
    filename: *const c_char,
    flags: libc::c_int,
    extinfo: *const c_void,
    caller_addr: *const c_void,
) -> *mut c_void {
    let name = c"__loader_android_dlopen_ext";
    let addr = REAL_LOADER_ANDROID_DLOPEN_EXT.get_or_init(|| unsafe { resolve_symbol(name) });
    if addr != 0 {
        let handle = call_loader_android_dlopen_ext_fn(addr, filename, flags, extinfo, caller_addr);
        if !handle.is_null() {
            monitor::note_loader_call_success();
            return handle;
        }
        monitor::note_loader_call_fallback("loader_android_dlopen_ext_returned_null");
    } else {
        monitor::note_loader_call_fallback("loader_android_dlopen_ext_symbol_missing");
    }
    call_real_dlopen_with_caller(filename, flags, extinfo, caller_addr)
}

pub(super) unsafe fn call_real_loader_dlclose(handle: *mut c_void) -> libc::c_int {
    let name = c"__loader_dlclose";
    let addr = REAL_LOADER_DLCLOSE.get_or_init(|| unsafe { resolve_symbol(name) });
    if addr != 0 {
        let result = call_loader_dlclose_fn(addr, handle);
        if result == 0 {
            monitor::note_loader_call_success();
            return 0;
        }
        monitor::note_loader_call_fallback("loader_dlclose_returned_nonzero");
    } else {
        monitor::note_loader_call_fallback("loader_dlclose_symbol_missing");
    }
    call_real_dlclose(handle)
}
