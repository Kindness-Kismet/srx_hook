// 模块 CFI 的 GOT 代理地址由 refresh 事务统一安装。
use std::ffi::c_void;

pub(super) fn proxy_addresses() -> (usize, usize) {
    (
        cfi_slowpath_proxy as *const () as usize,
        cfi_slowpath_diag_proxy as *const () as usize,
    )
}

// CFI 代理直接返回，允许跳板地址继续执行。
extern "C" fn cfi_slowpath_proxy(_call_site_type_id: u64, _ptr: *mut c_void) {}

extern "C" fn cfi_slowpath_diag_proxy(
    _call_site_type_id: u64,
    _ptr: *mut c_void,
    _diag_data: *mut c_void,
) {
}
