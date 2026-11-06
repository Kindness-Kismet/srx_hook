// 模块唯一键生成与失效 slot/task 清理
use crate::api::HookStub;
use std::collections::BTreeSet;

use super::super::hub;
use super::super::state::{CoreState, ModuleInfo};

pub(super) fn module_key(module: &ModuleInfo) -> String {
    module_instance_key(
        &module.pathname,
        module.base_addr,
        module.instance_id,
        module.namespace_id,
    )
}

// 格式：pathname#base_addr%instance_id^namespace_id
pub(super) fn module_instance_key(
    pathname: &str,
    base_addr: usize,
    instance_id: usize,
    namespace_id: usize,
) -> String {
    format!("{pathname}#{base_addr:x}%{instance_id:x}^{namespace_id:x}")
}

// 清理已卸载模块的 slot，退役关联 Hub 并更新 task_slots 索引。
pub(super) fn prune_dead_slots(state: &mut CoreState, alive_modules: &BTreeSet<String>) {
    let mut stale = Vec::new();
    for key in state.slots.keys() {
        if !alive_modules.contains(&module_instance_key(
            &key.caller_path_name,
            key.caller_base_addr,
            key.caller_instance_id,
            key.caller_namespace_id,
        )) {
            stale.push(key.clone());
        }
    }
    for key in stale {
        let Some(slot) = state.slots.remove(&key) else {
            continue;
        };
        if slot.hub_ptr != 0 {
            hub::destroy_hub(slot.hub_ptr as *mut hub::Hub);
        }
        for stub in slot.task_chain {
            let Some(slot_set) = state.task_slots.get_mut(&stub) else {
                continue;
            };
            slot_set.remove(&key);
            if slot_set.is_empty() {
                state.task_slots.remove(&stub);
            }
        }
    }
}

pub(super) fn prune_dead_single_task_targets(
    state: &mut CoreState,
    alive_modules: &BTreeSet<String>,
) {
    let stale_targets: Vec<HookStub> = state
        .single_task_targets
        .iter()
        .filter_map(|(stub, module)| {
            let has_live_slot = state
                .task_slots
                .get(stub)
                .is_some_and(|slots| !slots.is_empty());
            if !has_live_slot || !alive_modules.contains(module) {
                Some(*stub)
            } else {
                None
            }
        })
        .collect();

    for stub in stale_targets {
        state.single_task_targets.remove(&stub);
    }
}
