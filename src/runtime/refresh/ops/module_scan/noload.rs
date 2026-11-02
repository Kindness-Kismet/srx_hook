// 通过 RTLD_NOLOAD 重新打开已加载模块来解析 namespace_id
use crate::runtime::state::MutexPoisonRecover;
use std::ffi::CString;

use super::hints::{module_noload_key, noload_namespace_hints, trim_noload_namespace_hints};
use super::resolve::{
    resolve_link_map_from_handle, resolve_namespace_id_from_handle,
    resolve_namespace_id_from_link_map,
};
use super::{DlinfoFn, ModuleInfo};

// 尝试多种路径变体（全路径、去 deleted 后缀、basename）进行 RTLD_NOLOAD 解析
fn resolve_namespace_id_from_noload(module: &ModuleInfo, dlinfo: DlinfoFn) -> Option<usize> {
    if module.base_addr == 0 || module.pathname.is_empty() {
        return None;
    }
    for candidate in noload_path_candidates(module.pathname.as_str()) {
        let handle =
            unsafe { libc::dlopen(candidate.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
        if handle.is_null() {
            continue;
        }

        let resolved_namespace = (|| {
            let link_map_ptr = resolve_link_map_from_handle(dlinfo, handle)?;
            let base = unsafe { (*link_map_ptr).l_addr };
            if base != module.base_addr {
                return None;
            }
            resolve_namespace_id_from_handle(dlinfo, handle)
                .filter(|id| *id != 0)
                .or_else(|| resolve_namespace_id_from_link_map(link_map_ptr))
                .filter(|id| *id != 0)
        })();
        unsafe {
            libc::dlclose(handle);
        }
        if resolved_namespace.is_some() {
            return resolved_namespace;
        }
    }
    None
}

// 带 hint 缓存的 noload 解析，避免重复 dlopen/dlclose 开销
pub(super) fn resolve_namespace_id_from_noload_cached(
    module: &ModuleInfo,
    dlinfo: DlinfoFn,
) -> Option<usize> {
    let key = module_noload_key(module);
    if let Some(namespace_id) = noload_namespace_hints().lock_or_poison().get(&key).copied() {
        return if namespace_id == 0 {
            None
        } else {
            Some(namespace_id)
        };
    }

    let namespace_id = resolve_namespace_id_from_noload(module, dlinfo).unwrap_or(0);
    let mut hints = noload_namespace_hints().lock_or_poison();
    hints.insert(key, namespace_id);
    trim_noload_namespace_hints(&mut hints, key);
    if namespace_id == 0 {
        None
    } else {
        Some(namespace_id)
    }
}

// 生成 RTLD_NOLOAD 候选路径：原路径、去 (deleted)、basename、去 (deleted) 的 basename
pub(super) fn noload_path_candidates(pathname: &str) -> Vec<CString> {
    let mut candidates = Vec::<CString>::new();
    push_noload_candidate(&mut candidates, pathname);

    if let Some(stripped) = pathname.strip_suffix(" (deleted)") {
        push_noload_candidate(&mut candidates, stripped);
    }

    if let Some(basename) = pathname.rsplit('/').next() {
        push_noload_candidate(&mut candidates, basename);
    }

    if let Some(stripped) = pathname.strip_suffix(" (deleted)")
        && let Some(basename) = stripped.rsplit('/').next()
    {
        push_noload_candidate(&mut candidates, basename);
    }

    candidates
}

fn push_noload_candidate(candidates: &mut Vec<CString>, raw: &str) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    let Ok(candidate) = CString::new(trimmed) else {
        return;
    };
    if candidates
        .iter()
        .any(|existing| existing.as_c_str() == candidate.as_c_str())
    {
        return;
    }
    candidates.push(candidate);
}
