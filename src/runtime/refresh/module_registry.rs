// 模块唯一键生成与失效 slot/task 清理
use crate::api::HookStub;
use std::collections::BTreeSet;

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
