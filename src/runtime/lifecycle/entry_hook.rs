// hook 操作入口，提供 hook_single/hook_partial/hook_all/unhook 等 API 的实现
use crate::api::{
    CallerAllowFilter, HookMode, HookStub, HookedCallback, ModuleIdentity, RefreshError,
};
use crate::errno::Errno;
use std::ffi::c_void;

use super::super::refresh::{self};
use super::super::state::{AllowFilterEntry, GLOBAL, HookedEntry, Task, TaskType};
use super::invoke_callbacks;
use super::{monitor, transaction};
use crate::runtime::fork;

pub(super) fn hook_single(
    caller_path_name: &str,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    hook_single_checked(
        caller_path_name,
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
    )
    .or_else(|error| error.stub.ok_or(error))
    .ok()
}

pub(super) fn hook_single_checked(
    caller_path_name: &str,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Result<HookStub, crate::api::HookError> {
    fork::check_management()?;
    if caller_path_name.is_empty() || sym_name.is_empty() || new_func.is_null() {
        return Err(Errno::InvalidArg.into());
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
    super::task_ops::add_task_checked(task)
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
    hook_partial_checked(
        caller_allow_filter,
        caller_allow_filter_arg,
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
    )
    .or_else(|error| error.stub.ok_or(error))
    .ok()
}

pub(super) fn hook_partial_checked(
    caller_allow_filter: CallerAllowFilter,
    caller_allow_filter_arg: *mut c_void,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Result<HookStub, crate::api::HookError> {
    fork::check_management()?;
    if sym_name.is_empty() || new_func.is_null() {
        return Err(Errno::InvalidArg.into());
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
    super::task_ops::add_task_checked(task)
}

pub(super) fn hook_all(
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    hook_all_checked(callee_path_name, sym_name, new_func, hooked, hooked_arg)
        .or_else(|error| error.stub.ok_or(error))
        .ok()
}

pub(super) fn hook_all_checked(
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Result<HookStub, crate::api::HookError> {
    fork::check_management()?;
    if sym_name.is_empty() || new_func.is_null() {
        return Err(Errno::InvalidArg.into());
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
    super::task_ops::add_task_checked(task)
}

pub(super) fn unhook(stub: HookStub) -> Errno {
    if stub == 0 {
        return Errno::InvalidArg;
    }

    if let Err(error) = fork::check_management() {
        return error;
    }
    let runtime = &*GLOBAL;
    let result = transaction::run(runtime, false, |state| {
        let mut prepared = refresh::prepare_unhook(state, stub)?;
        super::super::record::add_unhook_record(
            &mut prepared.draft,
            prepared.status.as_i32(),
            stub,
        );
        Ok(prepared)
    });
    invoke_callbacks(result.events);
    result.status
}

pub(super) fn add_ignore(caller_path_name: &str) -> Errno {
    if caller_path_name.is_empty() {
        return Errno::InvalidArg;
    }

    if let Err(error) = fork::check_management() {
        return error;
    }
    GLOBAL.update(|state| {
        if state.clearing {
            return Errno::Busy;
        }
        if !state
            .ignore_callers
            .iter()
            .any(|value| value == caller_path_name)
        {
            state.ignore_callers.push(caller_path_name.to_string());
        }
        Errno::Ok
    })
}

// 通过 dlinfo 从 handle 解析模块身份信息并缓存到 hint 系统
pub(super) fn get_module_identity(handle: *mut c_void) -> Option<ModuleIdentity> {
    if handle.is_null() {
        return None;
    }
    fork::check_management().ok()?;
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
    fork::check_management().ok()?;
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
    if let Err(error) = fork::check_management() {
        return (error, Vec::new());
    }
    let runtime = &*GLOBAL;
    let result = transaction::run(runtime, false, |state| {
        refresh::prepare_refresh(state, false, None)
    });
    invoke_callbacks(result.events);
    if result.status == Errno::Ok && runtime.snapshot().init.mode == HookMode::Automatic {
        monitor::start_monitor_thread();
    }
    (result.status, result.errors)
}

pub(super) fn refresh_if_needed() -> (Errno, Vec<RefreshError>) {
    if let Err(error) = fork::check_management() {
        return (error, Vec::new());
    }
    match refresh::is_current_refresh_covered(&GLOBAL) {
        Ok(true) => (Errno::Ok, Vec::new()),
        Ok(false) => refresh(),
        Err(error) => (error, Vec::new()),
    }
}
