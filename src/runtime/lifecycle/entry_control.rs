// 运行时控制入口，提供 clear/debug/record/proxy 等控制操作的实现
use super::super::record;
use super::transaction;
use crate::android::signal_guard;
use crate::api::{
    ClearError, ClearReport, HookMode, PostDlopenCallback, PreDlopenCallback, RefreshError,
};
use crate::errno::Errno;
use crate::log;
use std::ffi::{c_char, c_void};
use std::sync::TryLockError;
use std::sync::atomic::Ordering;

use super::super::fork;
use super::super::refresh;
use super::super::state::{GLOBAL, ProcessRuntime};
use super::dlopen_callbacks;
use super::monitor;
use super::proxy;

// 兼容入口仍保留明确失败信息，调用方需要结果时使用 clear_checked。
pub(super) fn clear() {
    if let Err(error) = clear_checked() {
        log::warn(format_args!(
            "clear failed status={:?} revision={} removed={} remaining={} protections={} errors={}",
            error.status,
            error.report.revision,
            error.report.removed_slots,
            error.report.remaining_slots,
            error.report.remaining_protections,
            error.report.errors.len()
        ));
    }
}

pub(super) fn clear_checked() -> Result<ClearReport, ClearError> {
    fork::check_management().map_err(|status| ClearError {
        status,
        report: ClearReport::default(),
    })?;
    let runtime = &*GLOBAL;
    let initial = runtime.snapshot();
    let before = initial.slots.len();
    let marked = runtime.update(|draft| {
        draft.clearing = true;
        Errno::Ok
    });
    if marked != Errno::Ok {
        return Err(clear_error(runtime, before, marked, Vec::new()));
    }
    stop_monitor(runtime).map_err(|status| clear_error(runtime, before, status, Vec::new()))?;
    let source = runtime.snapshot();
    let errors = if source.slots.is_empty()
        && source
            .pending_protections
            .iter()
            .all(|page| !page.needs_restore)
    {
        Vec::new()
    } else {
        let result = transaction::run(runtime, true, refresh::prepare_clear);
        if result.status != Errno::Ok {
            return Err(clear_error(runtime, before, result.status, result.errors));
        }
        if let Some(error) = result.errors.first() {
            return Err(clear_error(runtime, before, error.errno, result.errors));
        }
        result.errors
    };
    let status = finish_clear(runtime);
    if status != Errno::Ok {
        return Err(clear_error(runtime, before, status, errors));
    }
    Ok(clear_report(runtime, before, errors))
}

fn stop_monitor(runtime: &ProcessRuntime) -> Result<(), Errno> {
    monitor::reset_auto_monitor_installed();
    runtime.monitor_running.store(false, Ordering::Release);
    runtime.refresh_requested.store(false, Ordering::Release);
    let thread = {
        let mut monitor = match runtime.monitor_thread.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => return Err(Errno::Busy),
        };
        monitor.take()
    };
    if let Some(handle) = thread {
        handle.thread().unpark();
        drop(handle);
    }
    Ok(())
}

fn finish_clear(runtime: &ProcessRuntime) -> Errno {
    runtime.update(|draft| {
        if !draft.slots.is_empty() {
            return Errno::Busy;
        }
        if draft
            .pending_protections
            .iter()
            .any(|page| page.needs_restore)
        {
            return Errno::SetProt;
        }
        draft.pending_protections.clear();
        draft.tasks.clear();
        draft.task_order.clear();
        draft.task_slots.clear();
        draft.single_task_targets.clear();
        draft.ignore_callers.clear();
        draft.known_modules.clear();
        draft.recordable = false;
        draft.records.clear();
        draft.dlopen_callbacks.clear();
        draft.init.status = Errno::Uninit;
        draft.init.mode = HookMode::Automatic;
        draft.next_stub = runtime.next_stub.load(Ordering::Acquire);
        draft.clearing = false;
        Errno::Ok
    })
}

fn clear_report(runtime: &ProcessRuntime, before: usize, errors: Vec<RefreshError>) -> ClearReport {
    let current = runtime.snapshot();
    ClearReport {
        revision: current.revision,
        removed_slots: before.saturating_sub(current.slots.len()),
        remaining_slots: current.slots.len(),
        remaining_protections: current
            .pending_protections
            .iter()
            .filter(|page| page.needs_restore)
            .count(),
        errors,
    }
}

fn clear_error(
    runtime: &ProcessRuntime,
    before: usize,
    status: Errno,
    errors: Vec<RefreshError>,
) -> ClearError {
    ClearError {
        status,
        report: clear_report(runtime, before, errors),
    }
}

pub(super) fn get_mode() -> HookMode {
    let state = GLOBAL.snapshot();
    state.init.mode
}

pub(super) fn get_debug() -> bool {
    let state = GLOBAL.snapshot();
    state.debug
}

pub(super) fn set_debug(debug: bool) {
    if fork::check_management().is_err() {
        return;
    }
    let status = GLOBAL.update(|draft| {
        if draft.clearing {
            return Errno::Busy;
        }
        draft.debug = debug;
        Errno::Ok
    });
    if status == Errno::Ok {
        log::set_debug_enabled(debug);
    } else if fork::check_management().is_ok() {
        log::warn(format_args!("set_debug failed status={status:?}"));
    }
}

pub(super) fn get_recordable() -> bool {
    let state = GLOBAL.snapshot();
    state.recordable
}

pub(super) fn set_recordable(recordable: bool) {
    if fork::check_management().is_err() {
        return;
    }
    let status = GLOBAL.update(|draft| {
        if draft.clearing {
            return Errno::Busy;
        }
        draft.recordable = recordable;
        Errno::Ok
    });
    if status != Errno::Ok && fork::check_management().is_ok() {
        log::warn(format_args!("set_recordable failed status={status:?}"));
    }
}

pub(super) fn get_records(item_flags: u32) -> Option<String> {
    let state = GLOBAL.snapshot();
    record::get_records_text(&state, item_flags)
}

pub(super) fn dump_records(fd: i32, item_flags: u32) -> Errno {
    if let Err(status) = fork::check_management() {
        return status;
    }
    let text = {
        let state = GLOBAL.snapshot();
        record::get_records_text(&state, item_flags)
    };
    let Some(text) = text else {
        return Errno::Ok;
    };
    match record::dump_records_text(fd, &text) {
        Ok(()) => Errno::Ok,
        Err(err) => err,
    }
}

pub(super) fn enable_sigsegv_protection(flag: bool) {
    if fork::check_management().is_err() {
        return;
    }
    signal_guard::enable(flag);
}

pub(super) fn get_prev_func(func: *mut c_void) -> *mut c_void {
    proxy::get_prev_func(func)
}

pub(super) fn with_prev_func<R, F>(func: *mut c_void, f: F) -> Option<R>
where
    F: FnOnce(*mut c_void) -> R,
{
    proxy::with_prev_func(func, f)
}

pub(super) fn get_return_address() -> *mut c_void {
    proxy::get_return_address()
}

pub(super) fn pop_stack(return_address: *mut c_void) {
    proxy::pop_stack(return_address)
}

pub(super) fn proxy_enter(func: *mut c_void) -> bool {
    proxy::proxy_enter(func)
}

pub(super) fn proxy_leave(func: *mut c_void) {
    proxy::proxy_leave(func)
}

pub(super) fn add_dlopen_callback(
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: *mut c_void,
) -> Errno {
    dlopen_callbacks::add_dlopen_callback(pre, post, data)
}

pub(super) fn del_dlopen_callback(
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: *mut c_void,
) -> Errno {
    dlopen_callbacks::del_dlopen_callback(pre, post, data)
}

pub(super) fn invoke_dlopen_callbacks_pre(filename: *const c_char) {
    dlopen_callbacks::invoke_dlopen_callbacks_pre(filename)
}

pub(super) fn invoke_dlopen_callbacks_post(filename: *const c_char, result: i32) {
    dlopen_callbacks::invoke_dlopen_callbacks_post(filename, result)
}
