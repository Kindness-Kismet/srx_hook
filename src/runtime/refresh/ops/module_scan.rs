// 模块扫描与身份解析，合并 dl_iterate_phdr 和 /proc/self/maps 两种数据源
use crate::log;
use crate::runtime::state::MutexPoisonRecover;
use std::collections::BTreeMap;
use std::ffi::{CStr, c_void};

use super::super::super::state::ModuleInfo;
use super::ModuleEpoch;

const RTLD_DI_LINKMAP: libc::c_int = 2;
const RTLD_DI_LMID: libc::c_int = 1;
const RTLD_NEXT_FALLBACK: *mut c_void = (-1isize) as *mut c_void;
const OBSERVED_INSTANCE_HINT_LIMIT: usize = 256;
const OBSERVED_INSTANCE_NAMESPACE_LIMIT: usize = 512;
const OBSERVED_PATH_NAMESPACE_LIMIT: usize = 512;
const NOLOAD_NAMESPACE_HINT_LIMIT: usize = 512;

// ELF link_map 结构体，与 linker 内部布局一致
#[repr(C)]
pub(super) struct LinkMap {
    pub(super) l_addr: usize,
    pub(super) l_name: *const libc::c_char,
    pub(super) l_ld: *mut c_void,
    pub(super) l_next: *mut LinkMap,
    pub(super) l_prev: *mut LinkMap,
}

pub(super) type DlinfoFn =
    unsafe extern "C" fn(*mut c_void, libc::c_int, *mut c_void) -> libc::c_int;
pub(super) type Dladdr1Fn = unsafe extern "C" fn(
    *const c_void,
    *mut libc::Dl_info,
    *mut *mut c_void,
    libc::c_int,
) -> libc::c_int;

// 缓存的模块身份信息，通过 dlopen handle 观察获得
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ObservedIdentityHint {
    pub(super) instance_id: usize,
    pub(super) namespace_id: usize,
}

mod hints;
mod maps;
mod noload;
mod resolve;

#[cfg(test)]
mod tests;

use hints::{
    apply_observed_instance_hints, module_noload_key, noload_namespace_hints,
    observe_path_namespace_hint, observed_identity_hints, observed_instance_namespace_hints,
    trim_noload_namespace_hints, trim_observed_instance_hints,
    trim_observed_instance_namespace_hints,
};
use maps::enumerate_modules_maps_cached;
use resolve::{resolve_module_from_handle, resolve_module_from_handle_symbol};

// 通过 dl_iterate_phdr 获取模块加载/卸载计数，仅需遍历第一个条目
pub(super) fn module_epoch() -> Option<ModuleEpoch> {
    let _loader_call = crate::runtime::LoaderCall::enter();
    unsafe extern "C" fn iterate_cb(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut c_void,
    ) -> libc::c_int {
        if info.is_null() || data.is_null() {
            return 1;
        }
        let info = unsafe { &*info };
        let epoch = unsafe { &mut *(data as *mut ModuleEpoch) };
        epoch.adds = info.dlpi_adds;
        epoch.subs = info.dlpi_subs;
        1
    }

    let mut epoch = ModuleEpoch { adds: 0, subs: 0 };
    let ret =
        unsafe { libc::dl_iterate_phdr(Some(iterate_cb), &mut epoch as *mut _ as *mut c_void) };
    if ret == 0 { None } else { Some(epoch) }
}

// 记录模块身份到多级 hint 缓存（base -> identity / instance -> namespace / path -> namespace）
pub(super) fn observe_module_identity(module: &ModuleInfo) {
    if module.base_addr == 0 {
        return;
    }
    if module.instance_id == 0 && module.namespace_id == 0 {
        return;
    }

    let mut hints = observed_identity_hints().lock_or_poison();
    let hint = ObservedIdentityHint {
        instance_id: module.instance_id,
        namespace_id: module.namespace_id,
    };
    let old_identity = hints.insert(module.base_addr, hint);
    trim_observed_instance_hints(&mut hints, module.base_addr);
    drop(hints);
    if old_identity != Some(hint) {
        log::debug(format_args!(
            "observe module identity base=0x{:x} instance=0x{:x} namespace=0x{:x} path={}",
            module.base_addr, module.instance_id, module.namespace_id, module.pathname
        ));
    }

    if module.instance_id != 0 && module.namespace_id != 0 {
        let mut instance_namespaces = observed_instance_namespace_hints().lock_or_poison();
        instance_namespaces.insert(module.instance_id, module.namespace_id);
        trim_observed_instance_namespace_hints(&mut instance_namespaces, module.instance_id);
    }

    if module.namespace_id != 0 {
        let key = module_noload_key(module);
        let mut noload_hints = noload_namespace_hints().lock_or_poison();
        noload_hints.insert(key, module.namespace_id);
        trim_noload_namespace_hints(&mut noload_hints, key);
        drop(noload_hints);

        observe_path_namespace_hint(module.pathname.as_str(), module.namespace_id);
    }
}

pub(super) fn module_identity_from_handle(handle: *mut c_void) -> Option<ModuleInfo> {
    let _loader_call = crate::runtime::LoaderCall::enter();
    resolve_module_from_handle(handle)
}

pub(super) fn module_identity_from_handle_with_symbol(
    handle: *mut c_void,
    probe_symbol: &str,
) -> Option<ModuleInfo> {
    let _loader_call = crate::runtime::LoaderCall::enter();
    if handle.is_null() {
        return None;
    }
    let primary = resolve_module_from_handle(handle);
    let fallback = resolve_module_from_handle_symbol(handle, probe_symbol);
    merge_module_identity(primary, fallback)
}

// 合并 primary 和 fallback 两个身份信息，优先取 primary 的非零字段
fn merge_module_identity(
    primary: Option<ModuleInfo>,
    fallback: Option<ModuleInfo>,
) -> Option<ModuleInfo> {
    match (primary, fallback) {
        (None, None) => None,
        (Some(primary), None) => Some(primary),
        (None, Some(fallback)) => Some(fallback),
        (Some(mut primary), Some(fallback)) => {
            let same_module = primary.base_addr != 0
                && fallback.base_addr != 0
                && primary.base_addr == fallback.base_addr;
            let same_path = !primary.pathname.is_empty()
                && !fallback.pathname.is_empty()
                && primary.pathname == fallback.pathname;
            let compatible = same_module || same_path;
            if !compatible {
                return Some(primary);
            }

            if primary.pathname.is_empty() {
                primary.pathname = fallback.pathname;
            }
            if primary.base_addr == 0 {
                primary.base_addr = fallback.base_addr;
            }
            if primary.instance_id == 0 {
                primary.instance_id = fallback.instance_id;
            }
            if primary.namespace_id == 0 {
                primary.namespace_id = fallback.namespace_id;
            }
            Some(primary)
        }
    }
}

// 合并 phdr 和 maps 两种数据源，应用 hint 缓存补全 namespace_id
pub(super) fn enumerate_modules() -> Vec<ModuleInfo> {
    let _loader_call = crate::runtime::LoaderCall::enter();
    let mut modules_by_base = BTreeMap::<usize, (ModuleInfo, bool)>::new();
    for module in enumerate_modules_phdr() {
        modules_by_base.insert(module.base_addr, (module, true));
    }

    for module in enumerate_modules_maps_cached() {
        modules_by_base
            .entry(module.base_addr)
            .and_modify(|(existing, _)| {
                // maps 路径与 get_mem_protect 一致，优先采用
                if !module.pathname.is_empty() && existing.pathname != module.pathname {
                    existing.pathname = module.pathname.clone();
                }
            })
            .or_insert((module, false));
    }

    let mut modules: Vec<_> = modules_by_base.into_values().collect();
    apply_observed_instance_hints(&mut modules);
    let mut modules: Vec<_> = modules.into_iter().map(|(module, _)| module).collect();
    modules.sort_by(|left, right| {
        left.pathname
            .cmp(&right.pathname)
            .then(left.base_addr.cmp(&right.base_addr))
            .then(left.instance_id.cmp(&right.instance_id))
            .then(left.namespace_id.cmp(&right.namespace_id))
    });
    modules
}

fn enumerate_modules_phdr() -> Vec<ModuleInfo> {
    unsafe extern "C" fn iterate_cb(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut c_void,
    ) -> libc::c_int {
        let modules = unsafe { &mut *(data as *mut Vec<ModuleInfo>) };
        if info.is_null() {
            return 0;
        }
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
        modules.push(ModuleInfo {
            pathname: pathname.to_string(),
            base_addr: info.dlpi_addr as usize,
            instance_id: info.dlpi_name as usize,
            namespace_id: 0,
        });
        0
    }

    let mut modules = Vec::<ModuleInfo>::new();
    unsafe {
        libc::dl_iterate_phdr(Some(iterate_cb), &mut modules as *mut _ as *mut c_void);
    }
    modules
}
