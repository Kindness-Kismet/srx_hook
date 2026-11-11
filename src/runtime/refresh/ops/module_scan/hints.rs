// 模块身份 hint 缓存，提供 base_addr / instance_id / pathname / noload 四级 namespace 解析
use super::noload;
use super::resolve;
use crate::runtime::state::{MutexPoisonRecover, PidLocal};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use super::{
    ModuleInfo, NOLOAD_NAMESPACE_HINT_LIMIT, OBSERVED_INSTANCE_HINT_LIMIT,
    OBSERVED_INSTANCE_NAMESPACE_LIMIT, OBSERVED_PATH_NAMESPACE_LIMIT, ObservedIdentityHint,
};

pub(super) fn observed_identity_hints() -> &'static Mutex<BTreeMap<usize, ObservedIdentityHint>> {
    static OBSERVED_HINTS: PidLocal<Mutex<BTreeMap<usize, ObservedIdentityHint>>> =
        PidLocal::new(|| Mutex::new(BTreeMap::new()));
    OBSERVED_HINTS.get()
}

pub(super) fn observed_instance_namespace_hints() -> &'static Mutex<BTreeMap<usize, usize>> {
    static OBSERVED_INSTANCE_NAMESPACE_HINTS: PidLocal<Mutex<BTreeMap<usize, usize>>> =
        PidLocal::new(|| Mutex::new(BTreeMap::new()));
    OBSERVED_INSTANCE_NAMESPACE_HINTS.get()
}

pub(super) fn observed_path_namespace_hints() -> &'static Mutex<BTreeMap<String, usize>> {
    static OBSERVED_PATH_NAMESPACE_HINTS: PidLocal<Mutex<BTreeMap<String, usize>>> =
        PidLocal::new(|| Mutex::new(BTreeMap::new()));
    OBSERVED_PATH_NAMESPACE_HINTS.get()
}

pub(super) fn noload_namespace_hints() -> &'static Mutex<BTreeMap<(usize, usize), usize>> {
    static NOLOAD_NAMESPACE_HINTS: PidLocal<Mutex<BTreeMap<(usize, usize), usize>>> =
        PidLocal::new(|| Mutex::new(BTreeMap::new()));
    NOLOAD_NAMESPACE_HINTS.get()
}

pub(super) fn resolve_namespace_id_by_base(base_addr: usize) -> Option<usize> {
    observed_identity_hints()
        .lock()
        .unwrap()
        .get(&base_addr)
        .map(|hint| hint.namespace_id)
        .filter(|namespace_id| *namespace_id != 0)
}

pub(super) fn resolve_namespace_id_by_instance(instance_id: usize) -> Option<usize> {
    if instance_id == 0 {
        return None;
    }
    observed_instance_namespace_hints()
        .lock()
        .unwrap()
        .get(&instance_id)
        .copied()
        .filter(|namespace_id| *namespace_id != 0)
}

pub(super) fn normalize_pathname(pathname: &str) -> &str {
    pathname
        .trim()
        .strip_suffix(" (deleted)")
        .unwrap_or(pathname.trim())
}

pub(super) fn observe_path_namespace_hint(pathname: &str, namespace_id: usize) {
    if namespace_id == 0 {
        return;
    }
    let normalized = normalize_pathname(pathname);
    if normalized.is_empty() {
        return;
    }
    let basename = normalized
        .rsplit('/')
        .next()
        .filter(|name| *name != normalized);
    let mut hints = observed_path_namespace_hints().lock_or_poison();
    upsert_path_namespace_hint(&mut hints, normalized, namespace_id);
    if let Some(name) = basename {
        upsert_path_namespace_hint(&mut hints, name, namespace_id);
    }
    trim_observed_path_namespace_hints(&mut hints, normalized, basename);
}

// 同一 basename 出现在不同 namespace 时标记为 0（歧义），避免错误匹配
fn upsert_path_namespace_hint(hints: &mut BTreeMap<String, usize>, key: &str, namespace_id: usize) {
    if key.is_empty() {
        return;
    }
    match hints.get(key).copied() {
        Some(existing) if existing != 0 && existing != namespace_id => {
            hints.insert(key.to_string(), 0);
        }
        Some(_) => {}
        None => {
            hints.insert(key.to_string(), namespace_id);
        }
    }
}

pub(super) fn resolve_namespace_id_by_path(pathname: &str) -> Option<usize> {
    let normalized = normalize_pathname(pathname);
    if normalized.is_empty() {
        return None;
    }
    let hints = observed_path_namespace_hints().lock_or_poison();
    if let Some(namespace_id) = hints.get(normalized).copied().filter(|id| *id != 0) {
        return Some(namespace_id);
    }
    let basename = normalized.rsplit('/').next()?;
    hints.get(basename).copied().filter(|id| *id != 0)
}

pub(super) fn trim_observed_instance_hints(
    hints: &mut BTreeMap<usize, ObservedIdentityHint>,
    keep_base: usize,
) {
    while hints.len() > OBSERVED_INSTANCE_HINT_LIMIT {
        let Some(first_base) = hints.keys().next().copied() else {
            break;
        };
        if first_base != keep_base {
            hints.remove(&first_base);
            continue;
        }

        let Some(last_base) = hints.keys().next_back().copied() else {
            break;
        };
        if last_base == keep_base {
            break;
        }
        hints.remove(&last_base);
    }
}

pub(super) fn trim_observed_instance_namespace_hints(
    hints: &mut BTreeMap<usize, usize>,
    keep_instance: usize,
) {
    while hints.len() > OBSERVED_INSTANCE_NAMESPACE_LIMIT {
        let Some(first_instance) = hints.keys().next().copied() else {
            break;
        };
        if first_instance != keep_instance {
            hints.remove(&first_instance);
            continue;
        }

        let Some(last_instance) = hints.keys().next_back().copied() else {
            break;
        };
        if last_instance == keep_instance {
            break;
        }
        hints.remove(&last_instance);
    }
}

fn trim_observed_path_namespace_hints(
    hints: &mut BTreeMap<String, usize>,
    keep_path: &str,
    keep_basename: Option<&str>,
) {
    while hints.len() > OBSERVED_PATH_NAMESPACE_LIMIT {
        let Some(first_path) = hints.keys().next().cloned() else {
            break;
        };
        let keep_first =
            first_path == keep_path || keep_basename.is_some_and(|key| first_path == key);
        if !keep_first {
            hints.remove(first_path.as_str());
            continue;
        }

        let Some(last_path) = hints.keys().next_back().cloned() else {
            break;
        };
        let keep_last = last_path == keep_path || keep_basename.is_some_and(|key| last_path == key);
        if !keep_last {
            hints.remove(last_path.as_str());
            continue;
        }
        break;
    }
}

pub(super) fn trim_noload_namespace_hints(
    hints: &mut BTreeMap<(usize, usize), usize>,
    keep: (usize, usize),
) {
    while hints.len() > NOLOAD_NAMESPACE_HINT_LIMIT {
        let Some(first) = hints.keys().next().copied() else {
            break;
        };
        if first != keep {
            hints.remove(&first);
            continue;
        }

        let Some(last) = hints.keys().next_back().copied() else {
            break;
        };
        if last == keep {
            break;
        }
        hints.remove(&last);
    }
}

pub(super) fn module_noload_key(module: &ModuleInfo) -> (usize, usize) {
    (module.base_addr, module.instance_id.max(module.base_addr))
}

pub(super) fn apply_observed_instance_hints(modules: &mut [(ModuleInfo, bool)]) {
    let mut hints = observed_identity_hints().lock_or_poison().clone();
    apply_instance_hints(modules, &mut hints);
    let alive: BTreeSet<usize> = modules.iter().map(|(module, _)| module.base_addr).collect();
    observed_identity_hints()
        .lock_or_poison()
        .retain(|base, _| alive.contains(base));
}

// 将 hint 缓存应用到模块列表，按优先级依次尝试多种 namespace 解析策略
pub(super) fn apply_instance_hints(
    modules: &mut [(ModuleInfo, bool)],
    hints: &mut BTreeMap<usize, ObservedIdentityHint>,
) {
    let alive_bases: BTreeSet<usize> = modules.iter().map(|(module, _)| module.base_addr).collect();
    hints.retain(|base, _| alive_bases.contains(base));
    let alive_noload_keys: BTreeSet<(usize, usize)> = modules
        .iter()
        .map(|(module, _)| module_noload_key(module))
        .collect();
    noload_namespace_hints()
        .lock()
        .unwrap()
        .retain(|key, _| alive_noload_keys.contains(key));
    let alive_paths: BTreeSet<String> = modules
        .iter()
        .flat_map(|(module, _)| {
            let normalized = normalize_pathname(module.pathname.as_str());
            let basename = normalized
                .rsplit('/')
                .next()
                .filter(|name| *name != normalized);
            [Some(normalized.to_string()), basename.map(str::to_string)]
        })
        .flatten()
        .collect();
    observed_path_namespace_hints()
        .lock()
        .unwrap()
        .retain(|path, _| alive_paths.contains(path));

    let dlinfo = resolve::resolve_dlinfo_fn();
    let instance_namespaces = observed_instance_namespace_hints().lock_or_poison().clone();
    for (module, from_phdr) in modules {
        let Some(identity) = hints.get(&module.base_addr).copied() else {
            if module.namespace_id == 0
                && let Some(namespace_id) = instance_namespaces.get(&module.instance_id).copied()
                && namespace_id != 0
            {
                module.namespace_id = namespace_id;
            }
            if module.namespace_id == 0
                && let Some(namespace_id) = resolve_namespace_id_by_path(module.pathname.as_str())
            {
                module.namespace_id = namespace_id;
            }
            if module.namespace_id == 0
                && let Some(dlinfo) = dlinfo
                && let Some(namespace_id) =
                    noload::resolve_namespace_id_from_noload_cached(module, dlinfo)
            {
                module.namespace_id = namespace_id;
            }
            continue;
        };
        if !*from_phdr && identity.instance_id != 0 {
            module.instance_id = identity.instance_id;
        }
        if module.namespace_id == 0 && identity.namespace_id != 0 {
            module.namespace_id = identity.namespace_id;
        }
        if module.namespace_id == 0
            && let Some(namespace_id) = instance_namespaces.get(&module.instance_id).copied()
            && namespace_id != 0
        {
            module.namespace_id = namespace_id;
        }
        if module.namespace_id == 0
            && let Some(namespace_id) = resolve_namespace_id_by_path(module.pathname.as_str())
        {
            module.namespace_id = namespace_id;
        }
        if module.namespace_id == 0
            && let Some(dlinfo) = dlinfo
            && let Some(namespace_id) =
                noload::resolve_namespace_id_from_noload_cached(module, dlinfo)
        {
            module.namespace_id = namespace_id;
        }
    }
}
