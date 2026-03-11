// hook 任务的添加、异步刷新请求与回调分发
use crate::api::{HookMode, HookStub};
use crate::errno::Errno;
use crate::log;
use std::ffi::c_void;

use super::super::record;
use super::super::refresh::{self, CallbackEvent};
use super::super::state::{GLOBAL, Task, TaskType};
use super::monitor;
use super::process;
use crate::runtime::state::{MutexPoisonRecover, RwLockPoisonRecover};

// 注册 hook 任务：分配 stub、立即应用、记录结果，自动模式下唤醒 monitor
pub(super) fn add_task(mut task: Task) -> Option<HookStub> {
    let _dlclose_guard = GLOBAL.dlclose_lock.read_or_poison();
    let _refresh_guard = GLOBAL.refresh_mutex.lock_or_poison();
    let mut state = GLOBAL.state.lock_or_poison();
    if state.init.status != Errno::Ok {
        return None;
    }
    process::ensure_process_context(&mut state);

    let stub = state.next_stub;
    state.next_stub = state.next_stub.saturating_add(1);
    if state.next_stub == 0 {
        state.next_stub = 1;
    }

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
        GLOBAL.condvar.notify_one();
    }

    drop(state);
    if need_start_monitor {
        monitor::start_monitor_thread();
        monitor::install_auto_loader_monitor_hooks();
    }
    invoke_callbacks(events);
    Some(stub)
}

pub(super) fn request_refresh_async() {
    let mut state = GLOBAL.state.lock_or_poison();
    if state.monitor_running {
        state.refresh_requested = true;
        GLOBAL.condvar.notify_one();
    }
}

// 将 dlopen 返回的 handle 加入待处理队列，队列满时丢弃最早的条目
pub(super) fn request_refresh_async_with_handle(handle: *mut c_void) {
    let mut state = GLOBAL.state.lock_or_poison();
    if !state.monitor_running {
        return;
    }

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
    GLOBAL.condvar.notify_one();
}

// 清空已知模块集合后请求全量刷新，用于 dlclose 后重新扫描
pub(super) fn request_refresh_async_full() {
    let mut state = GLOBAL.state.lock_or_poison();
    if state.monitor_running {
        state.known_modules.clear();
        state.refresh_requested = true;
        GLOBAL.condvar.notify_one();
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
