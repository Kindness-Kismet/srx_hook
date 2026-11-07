// CFI slowpath 全局补丁，通过将 __cfi_slowpath 函数体改写为 RET 指令来禁用 CFI 检查
use crate::android::signal_guard;
use crate::elf;
use crate::errno::Errno;
use crate::log;
use crate::runtime::state::ModuleInfo;
use std::collections::BTreeSet;
use std::ffi::CStr;

use super::RTLD_NEXT_FALLBACK;
mod patch;

const CFI_SLOWPATH_SYMBOL: &CStr = c"__cfi_slowpath";
const CFI_SLOWPATH_DIAG_SYMBOL: &CStr = c"__cfi_slowpath_diag";
// 可能包含 CFI 符号的系统库候选列表
const CFI_SYMBOL_LIB_CANDIDATES: [&CStr; 13] = [
    c"libdl.so",
    c"libc.so",
    c"libart.so",
    c"libartbase.so",
    c"linker64",
    c"linker",
    c"/apex/com.android.runtime/lib64/bionic/libdl.so",
    c"/apex/com.android.runtime/lib64/bionic/libc.so",
    c"/apex/com.android.art/lib64/libart.so",
    c"/apex/com.android.art/lib64/libartbase.so",
    c"/apex/com.android.runtime/bin/linker64",
    c"/system/lib64/libdl.so",
    c"/system/lib64/libc.so",
];

// 返回当前租期内的 CFI 入口，指令写入与权限恢复由发布事务完成。
pub(super) fn global_patch_addresses(modules: &[ModuleInfo]) -> Result<Vec<usize>, Errno> {
    let (mut slowpath, diagnostic) = resolve_cfi_symbols(modules);
    if slowpath.is_empty() {
        return Err(Errno::InitErrCfi);
    }
    if diagnostic.is_empty() {
        log::warn(format_args!(
            "cfi slowpath diag symbol missing, patched slowpath only"
        ));
    }
    slowpath.extend(diagnostic);
    Ok(slowpath.into_iter().collect())
}

// 通过 dlsym、ELF 导出表、GOT import slot 三种途径收集所有 CFI 符号地址
fn resolve_cfi_symbols(modules: &[ModuleInfo]) -> (BTreeSet<usize>, BTreeSet<usize>) {
    let mut slowpath_addrs = BTreeSet::new();
    let mut slowpath_diag_addrs = BTreeSet::new();

    if let Some(addr) = resolve_symbol_with_fallback(CFI_SLOWPATH_SYMBOL) {
        slowpath_addrs.insert(addr);
    }
    if let Some(addr) = resolve_symbol_with_fallback(CFI_SLOWPATH_DIAG_SYMBOL) {
        slowpath_diag_addrs.insert(addr);
    }

    collect_module_symbol_addrs_from_elf(modules, "__cfi_slowpath", &mut slowpath_addrs);
    collect_module_symbol_addrs_from_elf(modules, "__cfi_slowpath_diag", &mut slowpath_diag_addrs);
    collect_module_symbol_addrs_from_import_slots(modules, "__cfi_slowpath", &mut slowpath_addrs);
    collect_module_symbol_addrs_from_import_slots(
        modules,
        "__cfi_slowpath_diag",
        &mut slowpath_diag_addrs,
    );
    (slowpath_addrs, slowpath_diag_addrs)
}

fn resolve_symbol_with_fallback(symbol: &CStr) -> Option<usize> {
    if let Some(addr) = resolve_symbol_from_handle(RTLD_NEXT_FALLBACK, symbol) {
        return Some(addr);
    }
    if let Some(addr) = resolve_symbol_from_handle(libc::RTLD_DEFAULT, symbol) {
        return Some(addr);
    }
    for lib_name in CFI_SYMBOL_LIB_CANDIDATES {
        if let Some(addr) = resolve_symbol_from_library(lib_name, symbol) {
            return Some(addr);
        }
    }
    None
}

fn resolve_symbol_from_handle(handle: *mut libc::c_void, symbol: &CStr) -> Option<usize> {
    let addr = unsafe { libc::dlsym(handle, symbol.as_ptr()) } as usize;
    if addr == 0 { None } else { Some(addr) }
}

fn resolve_symbol_from_library(lib_name: &CStr, symbol: &CStr) -> Option<usize> {
    let handle = unsafe { libc::dlopen(lib_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    if handle.is_null() {
        return None;
    }
    let addr = resolve_symbol_from_handle(handle, symbol);
    unsafe {
        libc::dlclose(handle);
    }
    addr
}

fn collect_module_symbol_addrs_from_elf(
    modules: &[ModuleInfo],
    symbol: &str,
    out: &mut BTreeSet<usize>,
) {
    for module in modules {
        if module.base_addr == 0 {
            continue;
        }
        let found = signal_guard::with_guard(|| unsafe {
            let elf = elf::Elf::init(module.base_addr, &module.pathname).ok()?;
            elf.find_export_function(symbol)
        })
        .ok()
        .flatten();
        if let Some(addr) = found {
            out.insert(addr);
        }
    }
}

fn collect_module_symbol_addrs_from_import_slots(
    modules: &[ModuleInfo],
    symbol: &str,
    out: &mut BTreeSet<usize>,
) {
    for module in modules {
        if module.base_addr == 0 {
            continue;
        }
        let candidates = signal_guard::with_guard(|| unsafe {
            let elf = elf::Elf::init(module.base_addr, &module.pathname).ok()?;
            let slots = elf.find_got_slots(symbol, None).ok()?;
            let mut values = Vec::with_capacity(slots.len());
            for slot in slots {
                let value = std::ptr::read(slot as *const usize);
                if value != 0 {
                    values.push(value);
                }
            }
            Some(values)
        })
        .ok()
        .flatten();
        let Some(candidates) = candidates else {
            continue;
        };
        for candidate in candidates {
            if patch::is_plausible_cfi_runtime_addr(candidate) {
                out.insert(candidate);
            }
        }
    }
}
