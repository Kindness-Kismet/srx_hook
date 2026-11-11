// CFI 候选地址按符号和模块归属复验。
use std::ffi::{CStr, c_void};
use std::mem;

// 判断地址是否可能指向 CFI 运行时代码
// 通过 dladdr 检查符号名或所属库路径来启发式判断
pub(super) fn is_plausible_cfi_runtime_addr(addr: usize) -> bool {
    if addr < 0x1000 {
        return false;
    }
    let mut info: libc::Dl_info = unsafe { mem::zeroed() };
    if unsafe { libc::dladdr(addr as *const c_void, &mut info) } == 0 || info.dli_fname.is_null() {
        return false;
    }
    if !info.dli_sname.is_null()
        && let Ok(symbol_name) = unsafe { CStr::from_ptr(info.dli_sname) }.to_str()
        && (symbol_name == "__cfi_slowpath" || symbol_name == "__cfi_slowpath_diag")
    {
        return true;
    }
    let Ok(pathname) = unsafe { CStr::from_ptr(info.dli_fname) }.to_str() else {
        return false;
    };
    pathname.contains("libdl.so")
        || pathname.contains("libc.so")
        || pathname.contains("libart.so")
        || pathname.contains("libartbase.so")
        || pathname.contains("/apex/com.android.art/")
        || pathname.ends_with("/linker")
        || pathname.ends_with("/linker64")
        || pathname.contains("/linker/")
}
