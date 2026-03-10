// hook 刷新核心模块，负责模块扫描、任务匹配、GOT slot 写入与恢复
use crate::api::HookStub;
use crate::errno::Errno;
use crate::log;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::c_void;

use super::cfi;
use super::hub;
use super::rules::should_ignore;
use super::state::{CoreState, HookedEntry, ModuleInfo};
use apply::apply_task_for_module;
use matcher::{
    CalleeResolve, is_single_task_bound_to_other_module, is_task_match_caller, resolve_callee_addrs,
};
use module_registry::{module_key, prune_dead_single_task_targets, prune_dead_slots};
mod apply;
mod matcher;
mod module_registry;
mod ops;

// hook 操作完成后的回调事件，携带状态码和前一个函数地址
pub(super) struct CallbackEvent {
    pub(super) hooked: HookedEntry,
    pub(super) task_stub: HookStub,
    pub(super) status: Errno,
    pub(super) caller_path_name: String,
    pub(super) sym_name: String,
    pub(super) new_func: usize,
    pub(super) prev_func: usize,
}

pub(super) fn refresh_all(state: &mut CoreState) -> (Errno, Vec<CallbackEvent>) {
    refresh_internal(state, false, None)
}

pub(super) fn refresh_new_modules(state: &mut CoreState) -> (Errno, Vec<CallbackEvent>) {
    refresh_internal(state, true, None)
}

pub(super) fn apply_new_task(
    state: &mut CoreState,
    task_stub: HookStub,
) -> (Errno, Vec<CallbackEvent>) {
    refresh_internal(state, false, Some(task_stub))
}

pub(super) fn module_epoch() -> Option<(u64, u64)> {
    ops::module_epoch().map(|epoch| (epoch.adds, epoch.subs))
}

pub(super) fn observe_module_handle(handle: *mut c_void) {
    ops::observe_module_handle(handle);
}

pub(super) fn observe_module_identity(module: &ModuleInfo) {
    ops::observe_module_identity(module);
}

pub(super) fn module_identity_from_handle(handle: *mut c_void) -> Option<ModuleInfo> {
    ops::module_identity_from_handle(handle)
}

pub(super) fn module_identity_from_handle_with_symbol(
    handle: *mut c_void,
    probe_symbol: &str,
) -> Option<ModuleInfo> {
    ops::module_identity_from_handle_with_symbol(handle, probe_symbol)
}

// 移除指定 task 的所有 GOT slot hook，无活跃 proxy 时销毁 hub
pub(super) fn unhook_task(state: &mut CoreState, task_stub: HookStub) -> Errno {
    let slot_keys = match state.task_slots.remove(&task_stub) {
        Some(keys) => keys,
        None => return Errno::Ok,
    };
    let target_func = state
        .tasks
        .get(&task_stub)
        .map(|task| task.new_func)
        .unwrap_or_default();

    let mut first_err = Errno::Ok;
    for key in slot_keys {
        let Some(slot) = state.slots.get_mut(&key) else {
            continue;
        };

        slot.task_chain.retain(|stub| *stub != task_stub);

        if slot.hub_ptr == 0 {
            if let Err(err) = ops::patch_slot(key.slot_addr, slot.orig_func, &key.caller_path_name)
                && first_err.is_ok()
            {
                first_err = err;
            }
            if slot.task_chain.is_empty() {
                state.slots.remove(&key);
            }
            continue;
        }

        let (_, have_enabled_proxy) = hub::del_proxy(slot.hub_ptr as *mut hub::Hub, target_func);
        let target_addr = if have_enabled_proxy {
            hub::hub_trampo(slot.hub_ptr as *mut hub::Hub)
        } else {
            slot.orig_func
        };

        if let Err(err) = ops::patch_slot(key.slot_addr, target_addr, &key.caller_path_name)
            && first_err.is_ok()
        {
            first_err = err;
        }

        if !have_enabled_proxy {
            hub::destroy_hub(slot.hub_ptr as *mut hub::Hub, true);
            slot.hub_ptr = 0;
        }

        if slot.task_chain.is_empty() || !have_enabled_proxy {
            state.slots.remove(&key);
        }
    }

    state.single_task_targets.remove(&task_stub);
    first_err
}

// 恢复所有 GOT slot 为原始值并销毁全部 hub，用于进程 fork 后重建
pub(super) fn restore_all(state: &mut CoreState) -> Errno {
    let mut first_err = Errno::Ok;
    let slot_keys: Vec<_> = state.slots.keys().cloned().collect();

    for key in slot_keys {
        let Some(slot) = state.slots.get(&key) else {
            continue;
        };
        if let Err(err) = ops::patch_slot(key.slot_addr, slot.orig_func, &key.caller_path_name)
            && first_err.is_ok()
        {
            first_err = err;
        }
    }

    for slot in state.slots.values_mut() {
        if slot.hub_ptr != 0 {
            hub::destroy_hub(slot.hub_ptr as *mut hub::Hub, true);
            slot.hub_ptr = 0;
        }
    }
    state.slots.clear();
    state.task_slots.clear();
    state.single_task_targets.clear();
    first_err
}

// 刷新核心流程：扫描模块 -> 清理失效 slot -> 匹配任务 -> 应用 hook
fn refresh_internal(
    state: &mut CoreState,
    only_new: bool,
    target_task: Option<HookStub>,
) -> (Errno, Vec<CallbackEvent>) {
    hub::collect_retired(false);
    let modules = ops::enumerate_modules();
    cfi::retain_module_cfi_hook_state(&modules);
    let mut module_keys = BTreeSet::new();
    for module in &modules {
        module_keys.insert(module_key(module));
    }
    let modules_changed = state.known_modules != module_keys;
    if modules_changed {
        let cfi_status = cfi::refresh_slowpath_patch();
        if cfi_status != Errno::Ok {
            log::warn(format_args!("refresh cfi patch status {:?}", cfi_status));
        }
    }
    prune_dead_slots(state, &module_keys);
    prune_dead_single_task_targets(state, &module_keys);

    let mut events = Vec::new();
    let mut first_err = Errno::Ok;

    let task_list: Vec<HookStub> = match target_task {
        Some(stub) => vec![stub],
        None => state.task_order.clone(),
    };
    log::debug(format_args!(
        "refresh begin only_new={} target_task={} modules={} tasks={}",
        only_new,
        target_task.unwrap_or(0),
        modules.len(),
        task_list.len()
    ));
    let mut callee_cache = BTreeMap::<HookStub, Result<CalleeResolve, Errno>>::new();
    for task_stub in &task_list {
        let Some(task) = state.tasks.get(task_stub) else {
            continue;
        };
        callee_cache.insert(*task_stub, resolve_callee_addrs(task, &modules));
    }

    for module in &modules {
        if should_ignore(
            &module.pathname,
            module.base_addr,
            module.instance_id,
            module.namespace_id,
            &state.ignore_callers,
        ) {
            continue;
        }

        if only_new && state.known_modules.contains(&module_key(module)) {
            continue;
        }

        for task_stub in &task_list {
            let Some(task) = state.tasks.get(task_stub).cloned() else {
                continue;
            };
            if is_single_task_bound_to_other_module(state, &task, module) {
                continue;
            }
            let Some(callee) = callee_cache.get(task_stub) else {
                continue;
            };
            let callee = match callee {
                Ok(callee) => callee,
                Err(err) => {
                    if first_err.is_ok() {
                        first_err = *err;
                        log::warn(format_args!(
                            "callee resolve failed: sym={} err={:?}",
                            task.sym_name, err
                        ));
                    }
                    continue;
                }
            };

            if !is_task_match_caller(&task, module) {
                continue;
            }

            let mut task_events = Vec::new();
            if let Err(err) =
                apply_task_for_module(state, &task, module, callee, &mut task_events)
                && first_err.is_ok()
            {
                first_err = err;
                log::warn(format_args!(
                    "apply task failed: module={} sym={} err={:?}",
                    module.pathname, task.sym_name, err
                ));
            }
            events.extend(task_events);
        }
    }

    state.known_modules = module_keys;
    log::debug(format_args!(
        "refresh end only_new={} target_task={} status={:?} events={} modules_changed={}",
        only_new,
        target_task.unwrap_or(0),
        first_err,
        events.len(),
        modules_changed
    ));
    (first_err, events)
}
