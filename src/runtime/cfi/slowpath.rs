// CFI slowpath 全局补丁，通过将 __cfi_slowpath 函数体改写为 RET 指令来禁用 CFI 检查
use crate::android::{memory, signal_guard};
use crate::elf;
use crate::errno::Errno;
use crate::log;
use crate::runtime::state::MutexPoisonRecover;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, c_void};
use std::sync::{Mutex, OnceLock};

use super::{ANDROID_API_LEVEL_CFI_DISABLE, RTLD_NEXT_FALLBACK, android_api_level};
mod patch;

// 单个地址 patch 失败后的最大重试次数
const CFI_PATCH_FAIL_RETRY_LIMIT: u8 = 3;
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

pub(super) fn disable_slowpath_impl() -> Errno {
    patch_cfi_slowpath(true)
}

pub(super) fn refresh_slowpath_patch_impl() -> Errno {
    patch_cfi_slowpath(false)
}

// 核心 patch 逻辑：收集所有 CFI 符号地址并逐一写入 RET 指令
// require_slowpath 为 true 时表示初始化阶段，必须至少成功 patch 一个 slowpath 地址
fn patch_cfi_slowpath(require_slowpath: bool) -> Errno {
    if android_api_level() < ANDROID_API_LEVEL_CFI_DISABLE {
        return Errno::Ok;
    }

    let (slowpath_addrs, slowpath_diag_addrs) = resolve_cfi_symbols();
    if require_slowpath && slowpath_addrs.is_empty() {
        return Errno::InitErrCfi;
    }
    if require_slowpath && slowpath_diag_addrs.is_empty() {
        log::warn(format_args!(
            "cfi slowpath diag symbol missing, patched slowpath only"
        ));
    }

    let mut patched_addrs = patched_cfi_addrs().lock_or_poison();
    let mut failed_addrs = failed_cfi_addrs().lock_or_poison();
    let mut all_addrs = slowpath_addrs.clone();
    all_addrs.extend(slowpath_diag_addrs.iter().copied());
    patched_addrs.retain(|addr| all_addrs.contains(addr));
    failed_addrs.retain(|addr, _| all_addrs.contains(addr));

    let mut patched_slowpath = 0usize;
    let mut patched_diag = 0usize;
    let mut failed_slowpath = 0usize;
    let mut failed_diag = 0usize;
    for addr in &slowpath_addrs {
        if patched_addrs.contains(addr) {
            continue;
        }
        let fail_count = failed_addrs.get(addr).copied().unwrap_or(0);
        if fail_count >= CFI_PATCH_FAIL_RETRY_LIMIT {
            continue;
        }
        if patch::patch_ret_instruction(*addr).is_err() {
            failed_addrs.insert(*addr, fail_count.saturating_add(1));
            failed_slowpath += 1;
            continue;
        }
        memory::flush_instruction_cache_range(*addr, *addr + std::mem::size_of::<u32>());
        patched_addrs.insert(*addr);
        failed_addrs.remove(addr);
        patched_slowpath += 1;
    }
    for addr in &slowpath_diag_addrs {
        if patched_addrs.contains(addr) {
            continue;
        }
        let fail_count = failed_addrs.get(addr).copied().unwrap_or(0);
        if fail_count >= CFI_PATCH_FAIL_RETRY_LIMIT {
            continue;
        }
        if patch::patch_ret_instruction(*addr).is_err() {
            failed_addrs.insert(*addr, fail_count.saturating_add(1));
            failed_diag += 1;
            continue;
        }
        memory::flush_instruction_cache_range(*addr, *addr + std::mem::size_of::<u32>());
        patched_addrs.insert(*addr);
        failed_addrs.remove(addr);
        patched_diag += 1;
    }

    if patched_slowpath > 0 || patched_diag > 0 {
        log::debug(format_args!(
            "cfi patched new slowpath={} diag={}",
            patched_slowpath, patched_diag
        ));
    }
    if failed_slowpath > 0 || failed_diag > 0 {
        log::warn(format_args!(
            "cfi patch failed slowpath={} diag={} failed_total={}",
            failed_slowpath,
            failed_diag,
            failed_addrs.len()
        ));
    }
    if require_slowpath
        && !slowpath_addrs
            .iter()
            .any(|addr| patched_addrs.contains(addr))
    {
        return Errno::InitErrCfi;
    }
    Errno::Ok
}

// 通过 dlsym、ELF 导出表、GOT import slot 三种途径收集所有 CFI 符号地址
fn resolve_cfi_symbols() -> (BTreeSet<usize>, BTreeSet<usize>) {
    let mut slowpath_addrs = BTreeSet::new();
    let mut slowpath_diag_addrs = BTreeSet::new();
    let modules = enumerate_loaded_modules();

    if let Some(addr) = resolve_symbol_with_fallback(CFI_SLOWPATH_SYMBOL) {
        slowpath_addrs.insert(addr);
    }
    if let Some(addr) = resolve_symbol_with_fallback(CFI_SLOWPATH_DIAG_SYMBOL) {
        slowpath_diag_addrs.insert(addr);
    }

    collect_module_symbol_addrs_from_elf(&modules, "__cfi_slowpath", &mut slowpath_addrs);
    collect_module_symbol_addrs_from_elf(&modules, "__cfi_slowpath_diag", &mut slowpath_diag_addrs);
    collect_module_symbol_addrs_from_import_slots(&modules, "__cfi_slowpath", &mut slowpath_addrs);
    collect_module_symbol_addrs_from_import_slots(
        &modules,
        "__cfi_slowpath_diag",
        &mut slowpath_diag_addrs,
    );
    (slowpath_addrs, slowpath_diag_addrs)
}

fn patched_cfi_addrs() -> &'static Mutex<BTreeSet<usize>> {
    static PATCHED_CFI_ADDRS: OnceLock<Mutex<BTreeSet<usize>>> = OnceLock::new();
    PATCHED_CFI_ADDRS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn failed_cfi_addrs() -> &'static Mutex<BTreeMap<usize, u8>> {
    static FAILED_CFI_ADDRS: OnceLock<Mutex<BTreeMap<usize, u8>>> = OnceLock::new();
    FAILED_CFI_ADDRS.get_or_init(|| Mutex::new(BTreeMap::new()))
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
    modules: &[LoadedModule],
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
    modules: &[LoadedModule],
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
                if value != 0 && patch::is_plausible_cfi_runtime_addr(value) {
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
            out.insert(candidate);
        }
    }
}

fn enumerate_loaded_modules() -> Vec<LoadedModule> {
    unsafe extern "C" fn iterate_cb(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut c_void,
    ) -> libc::c_int {
        if info.is_null() || data.is_null() {
            return 0;
        }
        let modules = unsafe { &mut *(data as *mut Vec<LoadedModule>) };
        let info = unsafe { &*info };
        if info.dlpi_name.is_null() {
            return 0;
        }
        let Ok(pathname) = unsafe { CStr::from_ptr(info.dlpi_name) }.to_str() else {
            return 0;
        };
        if pathname.is_empty() || pathname.starts_with('[') {
            return 0;
        }
        modules.push(LoadedModule {
            base_addr: info.dlpi_addr as usize,
            pathname: pathname.to_string(),
        });
        0
    }

    let mut modules = Vec::<LoadedModule>::new();
    unsafe {
        libc::dl_iterate_phdr(Some(iterate_cb), &mut modules as *mut _ as *mut c_void);
    }
    modules
}

#[derive(Debug, Clone)]
struct LoadedModule {
    base_addr: usize,
    pathname: String,
}
