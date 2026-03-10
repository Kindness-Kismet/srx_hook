// hook 任务与模块的匹配逻辑，包括 callee 地址解析和 caller 过滤
use crate::errno::Errno;
use crate::log;
use std::collections::BTreeSet;
use std::ffi::{CString, c_void};

use super::module_registry::module_key;
use super::ops;
use super::super::callback_ctx;
use super::super::rules::module_match;
use super::super::state::{CoreState, ModuleInfo, Task, TaskType};

// callee 符号地址解析结果，None 表示不限定 callee
pub(super) struct CalleeResolve {
    pub(super) addrs: Option<BTreeSet<usize>>,
}

// 遍历所有模块查找 callee 导出符号地址，用于 GOT slot 精确匹配
pub(super) fn resolve_callee_addrs(task: &Task, modules: &[ModuleInfo]) -> Result<CalleeResolve, Errno> {
    let Some(callee_path_name) = task.callee_path_name.as_deref() else {
        return Ok(CalleeResolve { addrs: None });
    };

    let mut addrs = BTreeSet::new();
    for module in modules {
        if !module_match(
            &module.pathname,
            module.base_addr,
            module.instance_id,
            module.namespace_id,
            callee_path_name,
        ) {
            continue;
        }
        let elf = match ops::init_elf_guard(module.base_addr, &module.pathname) {
            Ok(elf) => elf,
            Err(err) => {
                log::warn(format_args!(
                    "callee ELF init failed: module={} base={:#x} err={:?}",
                    module.pathname, module.base_addr, err
                ));
                return Err(err);
            }
        };
        if let Some(addr) = ops::find_export_guard(&elf, &task.sym_name)? {
            addrs.insert(addr);
        }
    }
    Ok(CalleeResolve { addrs: Some(addrs) })
}

pub(super) fn is_task_match_caller(task: &Task, caller: &ModuleInfo) -> bool {
    match task.task_type {
        TaskType::Single => task
            .caller_path_name
            .as_deref()
            .map(|name| {
                module_match(
                    &caller.pathname,
                    caller.base_addr,
                    caller.instance_id,
                    caller.namespace_id,
                    name,
                )
            })
            .unwrap_or(false),
        TaskType::Partial => {
            let Some(filter) = task.caller_allow_filter else {
                return false;
            };
            let Ok(caller_cstr) = CString::new(caller.pathname.as_str()) else {
                return false;
            };
            callback_ctx::run_in_external_callback(|| unsafe {
                (filter.filter)(caller_cstr.as_ptr(), filter.arg as *mut c_void)
            })
        }
        TaskType::All => true,
    }
}

// Single 任务已绑定到特定模块时，跳过其他模块避免重复 hook
pub(super) fn is_single_task_bound_to_other_module(
    state: &CoreState,
    task: &Task,
    caller: &ModuleInfo,
) -> bool {
    if task.task_type != TaskType::Single {
        return false;
    }
    let Some(target_key) = state.single_task_targets.get(&task.stub) else {
        return false;
    };
    *target_key != module_key(caller)
}
