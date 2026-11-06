// hook 操作入口，提供 hook_single/hook_partial/hook_all/unhook 等 API 的实现
use crate::api::{CallerAllowFilter, HookStub, HookedCallback, ModuleIdentity, RefreshError};
use crate::errno::Errno;
use std::ffi::c_void;

use super::super::refresh::{self};
use super::super::state::{AllowFilterEntry, GLOBAL, HookedEntry, Task, TaskType};
use super::{add_task, invoke_callbacks};
use super::{monitor, process};
use crate::runtime::state::MutexPoisonRecover;

pub(super) fn hook_single(
    caller_path_name: &str,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    if caller_path_name.is_empty() || sym_name.is_empty() || new_func.is_null() {
        return None;
    }
    let task = Task {
        stub: 0,
        task_type: TaskType::Single,
        caller_path_name: Some(caller_path_name.to_string()),
        caller_allow_filter: None,
        callee_path_name: callee_path_name.map(ToString::to_string),
        sym_name: sym_name.to_string(),
        new_func: new_func as usize,
        hooked: hooked.map(|cb| HookedEntry {
            callback: cb,
            arg: hooked_arg as usize,
        }),
    };
    add_task(task)
}

pub(super) fn hook_partial(
    caller_allow_filter: CallerAllowFilter,
    caller_allow_filter_arg: *mut c_void,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    if sym_name.is_empty() || new_func.is_null() {
        return None;
    }
    let task = Task {
        stub: 0,
        task_type: TaskType::Partial,
        caller_path_name: None,
        caller_allow_filter: Some(AllowFilterEntry {
            filter: caller_allow_filter,
            arg: caller_allow_filter_arg as usize,
        }),
        callee_path_name: callee_path_name.map(ToString::to_string),
        sym_name: sym_name.to_string(),
        new_func: new_func as usize,
        hooked: hooked.map(|cb| HookedEntry {
            callback: cb,
            arg: hooked_arg as usize,
        }),
    };
    add_task(task)
}

pub(super) fn hook_all(
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    if sym_name.is_empty() || new_func.is_null() {
        return None;
    }
    let task = Task {
        stub: 0,
        task_type: TaskType::All,
        caller_path_name: None,
        caller_allow_filter: None,
        callee_path_name: callee_path_name.map(ToString::to_string),
        sym_name: sym_name.to_string(),
        new_func: new_func as usize,
        hooked: hooked.map(|cb| HookedEntry {
            callback: cb,
            arg: hooked_arg as usize,
        }),
    };
    add_task(task)
}

// unhook 需要持有 dlclose_lock 和 refresh_mutex 防止与 refresh 并发冲突
pub(super) fn unhook(stub: HookStub) -> Errno {
    if stub == 0 {
        return Errno::InvalidArg;
    }

    let _dlclose_guard = GLOBAL.dlclose_lock.lock_or_poison();
    let _refresh_guard = GLOBAL.refresh_mutex.lock_or_poison();
    let mut state = GLOBAL.state.lock_or_poison();
    if state.clearing {
        return Errno::Uninit;
    }
    if state.init.status != Errno::Ok {
        return state.init.status;
    }
    if !state.tasks.contains_key(&stub) {
        return Errno::InvalidArg;
    }
    let restart_monitor = process::ensure_process_context(&mut state);

    let status = refresh::unhook_task(&mut state, stub);
    super::super::record::add_unhook_record(&mut state, status.as_i32(), stub);
    state.tasks.remove(&stub);
    state.task_order.retain(|value| *value != stub);
    state.task_slots.remove(&stub);
    drop(state);
    drop(_refresh_guard);
    drop(_dlclose_guard);
    if restart_monitor {
        monitor::start_monitor_thread();
        monitor::install_auto_loader_monitor_hooks();
    }
    status
}

pub(super) fn add_ignore(caller_path_name: &str) -> Errno {
    if caller_path_name.is_empty() {
        return Errno::InvalidArg;
    }

    let mut state = GLOBAL.state.lock_or_poison();
    if state.clearing {
        return Errno::Uninit;
    }
    if state
        .ignore_callers
        .iter()
        .any(|value| value == caller_path_name)
    {
        return Errno::Ok;
    }
    state.ignore_callers.push(caller_path_name.to_string());
    Errno::Ok
}

// 通过 dlinfo 从 handle 解析模块身份信息并缓存到 hint 系统
pub(super) fn get_module_identity(handle: *mut c_void) -> Option<ModuleIdentity> {
    if handle.is_null() {
        return None;
    }
    let _dlclose_guard = GLOBAL.dlclose_lock.lock_or_poison();
    let _refresh_guard = GLOBAL.refresh_mutex.lock_or_poison();
    let state = GLOBAL.state.lock_or_poison();
    if state.clearing {
        return None;
    }
    drop(state);
    let module = refresh::module_identity_from_handle(handle)?;
    refresh::observe_module_identity(&module);
    Some(ModuleIdentity {
        pathname: module.pathname,
        base_addr: module.base_addr,
        instance_id: module.instance_id,
        namespace_id: module.namespace_id,
    })
}

pub(super) fn get_module_identity_with_symbol(
    handle: *mut c_void,
    probe_symbol: &str,
) -> Option<ModuleIdentity> {
    if handle.is_null() || probe_symbol.is_empty() {
        return None;
    }
    let _dlclose_guard = GLOBAL.dlclose_lock.lock_or_poison();
    let _refresh_guard = GLOBAL.refresh_mutex.lock_or_poison();
    let state = GLOBAL.state.lock_or_poison();
    if state.clearing {
        return None;
    }
    drop(state);
    let module = refresh::module_identity_from_handle_with_symbol(handle, probe_symbol)?;
    refresh::observe_module_identity(&module);
    Some(ModuleIdentity {
        pathname: module.pathname,
        base_addr: module.base_addr,
        instance_id: module.instance_id,
        namespace_id: module.namespace_id,
    })
}

pub(super) fn refresh() -> (Errno, Vec<RefreshError>) {
    let _dlclose_guard = GLOBAL.dlclose_lock.lock_or_poison();
    let _refresh_guard = GLOBAL.refresh_mutex.lock_or_poison();
    let mut state = GLOBAL.state.lock_or_poison();
    if state.clearing {
        return (Errno::Uninit, Vec::new());
    }
    if state.init.status != Errno::Ok {
        return (state.init.status, Vec::new());
    }
    let restart_monitor = process::ensure_process_context(&mut state);
    let (status, events, errors) = refresh::refresh_all(&mut state);
    drop(state);
    drop(_refresh_guard);
    drop(_dlclose_guard);
    if restart_monitor {
        monitor::start_monitor_thread();
        monitor::install_auto_loader_monitor_hooks();
    }
    invoke_callbacks(events);
    (status, errors)
}
