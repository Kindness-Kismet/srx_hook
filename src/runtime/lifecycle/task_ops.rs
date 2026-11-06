// hook 任务的添加、异步刷新请求与回调分发
use crate::api::{HookMode, HookStub};
use crate::errno::Errno;
use crate::log;
use std::ffi::c_void;

use super::super::record;
use super::super::refresh::{self, CallbackEvent};
use super::super::state::{GLOBAL, Task, TaskType, is_forked_child};
use super::monitor;
use super::process;
use crate::runtime::state::MutexPoisonRecover;

// 注册 hook 任务：分配 stub、立即应用、记录结果，自动模式下唤醒 monitor
pub(super) fn add_task(mut task: Task) -> Option<HookStub> {
    let _dlclose_guard = GLOBAL.dlclose_lock.lock_or_poison();
    let _refresh_guard = GLOBAL.refresh_mutex.lock_or_poison();
    let mut state = GLOBAL.state.lock_or_poison();
    if state.clearing || state.init.status != Errno::Ok {
        return None;
    }
    let stub = state.next_stub;
    state.next_stub = state.next_stub.checked_add(1)?;
    process::ensure_process_context(&mut state);

    task.stub = stub;
    let record_lib_name = match task.task_type {
        TaskType::Single => task
            .caller_path_name
            .as_deref()
            .unwrap_or("unknown")
            .to_string(),
        TaskType::Partial => "PARTIAL".to_string(),
        TaskType::All => "ALL".to_string(),
    };
    let record_sym_name = task.sym_name.clone();
    let record_new_func = task.new_func;
    let record_use_real_status = task.task_type == TaskType::Single;
    state.task_order.push(stub);
    state.tasks.insert(stub, task);

    // Manual 模式下只入队，由后续 refresh() 统一应用
    let is_manual = state.init.mode == HookMode::Manual;
    let (status, events) = if is_manual {
        (Errno::Ok, Vec::new())
    } else {
        let (status, events, _errors) = refresh::apply_new_task(&mut state, stub);
        (status, events)
    };
    let status_code = if record_use_real_status {
        status.as_i32()
    } else {
        Errno::Max.as_i32()
    };
    record::add_hook_record(
        &mut state,
        status_code,
        &record_lib_name,
        &record_sym_name,
        record_new_func,
        stub,
    );
    if status != Errno::Ok && status != Errno::NoSym {
        log::warn(format_args!("hook task {} apply status {:?}", stub, status));
    }

    let need_start_monitor = !is_manual && !state.monitor_running;
    if !is_manual {
        state.refresh_requested = true;
        monitor::wake_monitor_thread(&state);
    }

    drop(state);
    drop(_refresh_guard);
    drop(_dlclose_guard);
    if need_start_monitor {
        monitor::start_monitor_thread();
        monitor::install_auto_loader_monitor_hooks();
    }
    invoke_callbacks(events);
    Some(stub)
}

pub(super) fn request_refresh_async() {
    if is_forked_child() {
        return;
    }
    let mut state = GLOBAL.state.lock_or_poison();
    if state.monitor_running {
        state.refresh_requested = true;
        monitor::wake_monitor_thread(&state);
    }
}

// 将 dlopen 返回的 handle 加入待处理队列，队列满时丢弃最早的条目
pub(super) fn request_refresh_async_with_handle(handle: *mut c_void) {
    if is_forked_child() {
        return;
    }
    let mut state = GLOBAL.state.lock_or_poison();
    if state.monitor_running {
        if !handle.is_null() {
            const PENDING_HANDLE_LIMIT: usize = 256;
            let handle_addr = handle as usize;
            if state.pending_module_handle_set.insert(handle_addr) {
                if state.pending_module_handles.len() >= PENDING_HANDLE_LIMIT
                    && let Some(dropped) = state.pending_module_handles.pop_front()
                {
                    state.pending_module_handle_set.remove(&dropped);
                    log::debug(format_args!(
                        "monitor pending handle queue full, drop 0x{dropped:x}"
                    ));
                }
                state.pending_module_handles.push_back(handle_addr);
                log::debug(format_args!(
                    "enqueue module handle 0x{handle_addr:x}, pending={}",
                    state.pending_module_handles.len()
                ));
            }
        }
        state.refresh_requested = true;
        monitor::wake_monitor_thread(&state);
    }
}

// 清空已知模块集合后请求全量刷新，用于 dlclose 后重新扫描
pub(super) fn request_refresh_async_full() {
    if is_forked_child() {
        return;
    }
    let mut state = GLOBAL.state.lock_or_poison();
    state.known_modules.clear();
    state.pending_module_handles.clear();
    state.pending_module_handle_set.clear();
    if state.monitor_running {
        state.refresh_requested = true;
        monitor::wake_monitor_thread(&state);
    }
}

pub(super) fn invoke_callbacks(events: Vec<CallbackEvent>) {
    for event in events {
        let Ok(caller_path_name) = std::ffi::CString::new(event.caller_path_name) else {
            continue;
        };
        let Ok(sym_name) = std::ffi::CString::new(event.sym_name) else {
            continue;
        };
        unsafe {
            (event.hooked.callback)(
                event.task_stub,
                event.status.as_i32(),
                caller_path_name.as_ptr(),
                sym_name.as_ptr(),
                event.new_func as *mut c_void,
                event.prev_func as *mut c_void,
                event.hooked.arg as *mut c_void,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_stub_counter_rejects_registration_without_replacing_tasks() {
        let original = {
            let mut state = GLOBAL.state.lock_or_poison();
            let original = (state.init.status, state.next_stub, state.tasks.len());
            state.init.status = Errno::Ok;
            state.next_stub = HookStub::MAX;
            original
        };
        let result = add_task(Task {
            stub: 0,
            task_type: TaskType::Single,
            caller_path_name: Some("missing-test-module.so".to_string()),
            caller_allow_filter: None,
            callee_path_name: None,
            sym_name: "puts".to_string(),
            new_func: 1,
            hooked: None,
        });
        let mut state = GLOBAL.state.lock_or_poison();
        assert!(result.is_none());
        assert_eq!(state.tasks.len(), original.2);
        assert_eq!(state.next_stub, HookStub::MAX);
        state.init.status = original.0;
        state.next_stub = original.1;
    }

    #[test]
    fn full_refresh_discards_queued_handles_without_monitor() {
        let original = {
            let mut state = GLOBAL.state.lock_or_poison();
            let original = (
                state.monitor_running,
                state.pending_module_handles.clone(),
                state.pending_module_handle_set.clone(),
                state.known_modules.clone(),
            );
            state.monitor_running = false;
            state.pending_module_handles.push_back(0x1234);
            state.pending_module_handle_set.insert(0x1234);
            state.known_modules.insert("stale.so".to_string());
            original
        };

        request_refresh_async_full();

        let mut state = GLOBAL.state.lock_or_poison();
        assert!(state.pending_module_handles.is_empty());
        assert!(state.pending_module_handle_set.is_empty());
        assert!(state.known_modules.is_empty());
        state.monitor_running = original.0;
        state.pending_module_handles = original.1;
        state.pending_module_handle_set = original.2;
        state.known_modules = original.3;
    }
}
