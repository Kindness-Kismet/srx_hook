// dlopen/dlclose 的 monitor proxy 函数，拦截动态库加载卸载并触发 hook 刷新
use std::ffi::{c_char, c_void};

use super::super::super::hub;
use super::super::super::state::GLOBAL;
use super::super::monitor_calls::{
    call_android_dlopen_ext_fn, call_dlclose_fn, call_dlopen_fn, call_loader_android_dlopen_ext_fn,
    call_loader_dlclose_fn, call_loader_dlopen_fn, call_real_android_dlopen_ext, call_real_dlclose,
    call_real_dlopen, call_real_dlopen_with_caller, call_real_loader_android_dlopen_ext,
    call_real_loader_dlclose, call_real_loader_dlopen,
};
use crate::runtime::state::MutexPoisonRecover;

pub(super) unsafe extern "C" fn monitor_dlopen(
    filename: *const c_char,
    flags: libc::c_int,
) -> *mut c_void {
    super::super::invoke_dlopen_callbacks_pre(filename);
    let result = if should_use_android_n_linker_fallback() {
        let caller_addr = hub::get_return_address() as *const c_void;
        unsafe { call_real_dlopen_with_caller(filename, flags, std::ptr::null(), caller_addr) }
    } else {
        let self_ptr = monitor_dlopen as *mut c_void;
        super::super::with_prev_func(self_ptr, |prev| {
            if prev.is_null() {
                unsafe { call_real_dlopen(filename, flags) }
            } else {
                unsafe { call_dlopen_fn(prev as usize, filename, flags) }
            }
        })
        .unwrap_or_else(|| unsafe { call_real_dlopen(filename, flags) })
    };
    super::super::invoke_dlopen_callbacks_post(filename, if result.is_null() { -1 } else { 0 });
    if !result.is_null() {
        super::super::request_refresh_async_with_handle(result);
    }
    result
}

pub(super) unsafe extern "C" fn monitor_android_dlopen_ext(
    filename: *const c_char,
    flags: libc::c_int,
    extinfo: *const c_void,
) -> *mut c_void {
    super::super::invoke_dlopen_callbacks_pre(filename);
    let result = if should_use_android_n_linker_fallback() {
        let caller_addr = hub::get_return_address() as *const c_void;
        unsafe { call_real_dlopen_with_caller(filename, flags, extinfo, caller_addr) }
    } else {
        let self_ptr = monitor_android_dlopen_ext as *mut c_void;
        super::super::with_prev_func(self_ptr, |prev| {
            if prev.is_null() {
                unsafe { call_real_android_dlopen_ext(filename, flags, extinfo) }
            } else {
                unsafe { call_android_dlopen_ext_fn(prev as usize, filename, flags, extinfo) }
            }
        })
        .unwrap_or_else(|| unsafe { call_real_android_dlopen_ext(filename, flags, extinfo) })
    };
    super::super::invoke_dlopen_callbacks_post(filename, if result.is_null() { -1 } else { 0 });
    if !result.is_null() {
        super::super::request_refresh_async_with_handle(result);
    }
    result
}

// dlclose 与 refresh 互斥，句柄队列必须在释放锁前失效。
pub(super) unsafe extern "C" fn monitor_dlclose(handle: *mut c_void) -> libc::c_int {
    let self_ptr = monitor_dlclose as *mut c_void;
    let dlclose_guard = GLOBAL.dlclose_lock.lock_or_poison();
    let result = super::super::with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            unsafe { call_real_dlclose(handle) }
        } else {
            unsafe { call_dlclose_fn(prev as usize, handle) }
        }
    })
    .unwrap_or_else(|| unsafe { call_real_dlclose(handle) });
    if result == 0 {
        super::super::request_refresh_async_full();
    }
    drop(dlclose_guard);
    result
}

pub(super) unsafe extern "C" fn monitor_loader_dlopen(
    filename: *const c_char,
    flags: libc::c_int,
    caller_addr: *const c_void,
) -> *mut c_void {
    super::super::invoke_dlopen_callbacks_pre(filename);
    let self_ptr = monitor_loader_dlopen as *mut c_void;
    let result = super::super::with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            unsafe { call_real_loader_dlopen(filename, flags, caller_addr) }
        } else {
            unsafe { call_loader_dlopen_fn(prev as usize, filename, flags, caller_addr) }
        }
    })
    .unwrap_or_else(|| unsafe { call_real_loader_dlopen(filename, flags, caller_addr) });
    super::super::invoke_dlopen_callbacks_post(filename, if result.is_null() { -1 } else { 0 });
    if !result.is_null() {
        super::super::request_refresh_async_with_handle(result);
    }
    result
}

pub(super) unsafe extern "C" fn monitor_loader_android_dlopen_ext(
    filename: *const c_char,
    flags: libc::c_int,
    extinfo: *const c_void,
    caller_addr: *const c_void,
) -> *mut c_void {
    super::super::invoke_dlopen_callbacks_pre(filename);
    let self_ptr = monitor_loader_android_dlopen_ext as *mut c_void;
    let result = super::super::with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            unsafe { call_real_loader_android_dlopen_ext(filename, flags, extinfo, caller_addr) }
        } else {
            unsafe {
                call_loader_android_dlopen_ext_fn(
                    prev as usize,
                    filename,
                    flags,
                    extinfo,
                    caller_addr,
                )
            }
        }
    })
    .unwrap_or_else(|| unsafe {
        call_real_loader_android_dlopen_ext(filename, flags, extinfo, caller_addr)
    });
    super::super::invoke_dlopen_callbacks_post(filename, if result.is_null() { -1 } else { 0 });
    if !result.is_null() {
        super::super::request_refresh_async_with_handle(result);
    }
    result
}

pub(super) unsafe extern "C" fn monitor_loader_dlclose(handle: *mut c_void) -> libc::c_int {
    let self_ptr = monitor_loader_dlclose as *mut c_void;
    let dlclose_guard = GLOBAL.dlclose_lock.lock_or_poison();
    let result = super::super::with_prev_func(self_ptr, |prev| {
        if prev.is_null() {
            unsafe { call_real_loader_dlclose(handle) }
        } else {
            unsafe { call_loader_dlclose_fn(prev as usize, handle) }
        }
    })
    .unwrap_or_else(|| unsafe { call_real_loader_dlclose(handle) });
    if result == 0 {
        super::super::request_refresh_async_full();
    }
    drop(dlclose_guard);
    result
}

// Android N (API 24-25) 的 linker 不支持 PLT hook 拦截 dlopen
// 需要直接调用 linker 内部函数并传递 caller_addr
fn should_use_android_n_linker_fallback() -> bool {
    let api_level = super::android_api_level();
    api_level == super::ANDROID_API_LEVEL_N || api_level == super::ANDROID_API_LEVEL_N_MR1
}
