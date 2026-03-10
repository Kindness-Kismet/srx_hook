// 单个模块的 hook 任务应用逻辑，完成 ELF 解析、CFI 处理、GOT slot 写入
use crate::api::HookMode;
use crate::errno::Errno;
use crate::log;
use std::collections::BTreeSet;

use super::super::cfi;
use super::super::hub;
use super::super::state::{CoreState, ModuleInfo, SlotEntry, SlotKey, Task, TaskType};
use super::module_registry::module_key;
use super::ops;
use super::CallbackEvent;

// 对指定 caller 模块应用 task：解析 ELF -> 确保 CFI hook -> 查找 GOT slot -> 创建 hub -> 写入
pub(super) fn apply_task_for_module(
    state: &mut CoreState,
    task: &Task,
    caller: &ModuleInfo,
    callee: &super::matcher::CalleeResolve,
    events: &mut Vec<CallbackEvent>,
) -> Result<(), Errno> {
    if task.callee_path_name.is_some() && callee.addrs.as_ref().is_some_and(BTreeSet::is_empty) {
        emit_nosym_event(task, caller, events);
        return Ok(());
    }

    let elf = match ops::init_elf_guard(caller.base_addr, &caller.pathname) {
        Ok(elf) => elf,
        Err(err) => {
            log::warn(format_args!(
                "caller ELF init failed: module={} base={:#x} sym={} err={:?}",
                caller.pathname, caller.base_addr, task.sym_name, err
            ));
            return Err(err);
        }
    };
    let cfi_status = cfi::ensure_module_cfi_hook(caller, &elf);
    if cfi_status != Errno::Ok {
        emit_event(task, caller, cfi_status, 0, events);
        return Err(cfi_status);
    }
    let got_slots = match ops::find_slots_guard(&elf, &task.sym_name, callee.addrs.as_ref()) {
        Ok(slots) => slots,
        Err(err) => {
            log::warn(format_args!(
                "GOT slot lookup failed: module={} sym={} err={:?}",
                caller.pathname, task.sym_name, err
            ));
            return Err(err);
        }
    };

    if got_slots.is_empty() {
        emit_nosym_event(task, caller, events);
        return Ok(());
    }

    let mut hooked_any = false;
    for slot_addr in got_slots {
        let key = SlotKey {
            caller_path_name: caller.pathname.clone(),
            caller_base_addr: caller.base_addr,
            caller_instance_id: caller.instance_id,
            caller_namespace_id: caller.namespace_id,
            slot_addr,
        };

        let slot = state.slots.entry(key.clone()).or_insert_with(|| SlotEntry {
            orig_func: ops::read_slot(slot_addr).unwrap_or_default(),
            task_chain: Vec::new(),
            hub_ptr: 0,
        });
        if slot.task_chain.contains(&task.stub) {
            hooked_any = true;
            continue;
        }

        if slot.hub_ptr == 0 {
            let hub_ptr = hub::create_hub(slot.orig_func)?;
            slot.hub_ptr = hub_ptr as usize;
        }

        let hub_ptr = slot.hub_ptr as *mut hub::Hub;
        let prev_func = hub::first_enabled(hub_ptr);

        if state.init.mode == HookMode::Manual {
            emit_event(task, caller, Errno::OrigAddr, prev_func, events);
        }

        let add_status = hub::add_proxy(hub_ptr, task.new_func);
        if add_status != Errno::Ok && add_status != Errno::Dup {
            return Err(add_status);
        }

        ops::patch_slot(slot_addr, hub::hub_trampo(hub_ptr), &caller.pathname)?;
        slot.task_chain.push(task.stub);
        state.task_slots.entry(task.stub).or_default().insert(key);
        hooked_any = true;
        emit_event(task, caller, Errno::Ok, prev_func, events);
    }

    if hooked_any && task.task_type == TaskType::Single {
        state
            .single_task_targets
            .entry(task.stub)
            .or_insert_with(|| module_key(caller));
    }

    Ok(())
}

fn emit_nosym_event(task: &Task, caller: &ModuleInfo, events: &mut Vec<CallbackEvent>) {
    if task.task_type == TaskType::Single {
        emit_event(task, caller, Errno::NoSym, 0, events);
    }
}

fn emit_event(
    task: &Task,
    caller: &ModuleInfo,
    status: Errno,
    prev_func: usize,
    events: &mut Vec<CallbackEvent>,
) {
    if let Some(hooked) = task.hooked {
        events.push(CallbackEvent {
            hooked,
            task_stub: task.stub,
            status,
            caller_path_name: caller.pathname.clone(),
            sym_name: task.sym_name.clone(),
            new_func: task.new_func,
            prev_func,
        });
    }
}
