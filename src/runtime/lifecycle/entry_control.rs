// 运行时控制入口，提供 clear/debug/record/proxy 等控制操作的实现
use crate::android::signal_guard;
use crate::api::{HookMode, PostDlopenCallback, PreDlopenCallback};
use crate::errno::Errno;
use std::ffi::{c_char, c_void};

use super::super::hub;
use super::super::refresh;
use super::super::state::{GLOBAL, is_forked_child};
use super::dlopen_callbacks;
use super::monitor;
use super::proxy;
use crate::runtime::state::MutexPoisonRecover;

// 停止 monitor、恢复 GOT 并重置任务；在途调用的返回上下文和退休入口继续保留。
pub(super) fn clear() {
    let thread = {
        let mut state = GLOBAL.state.lock_or_poison();
        if state.clearing {
            return;
        }
        state.clearing = true;
        state.monitor_running = false;
        if is_forked_child() {
            if let Some(thread) = state.monitor_thread.take() {
                std::mem::forget(thread);
            }
            None
        } else {
            state.monitor_thread.take()
        }
    };

    if let Some(handle) = thread {
        handle.thread().unpark();
        if handle.thread().id() != std::thread::current().id() {
            let _ = handle.join();
        }
    }

    let _dlclose_guard = GLOBAL.dlclose_lock.lock_or_poison();
    let _refresh_guard = GLOBAL.refresh_mutex.lock_or_poison();
    let mut state = GLOBAL.state.lock_or_poison();
    let _ = refresh::restore_all(&mut state);
    state.tasks.clear();
    state.task_order.clear();
    state.task_slots.clear();
    state.slots.clear();
    state.single_task_targets.clear();
    state.ignore_callers.clear();
    state.known_modules.clear();
    state.recordable = false;
    state.records.clear();
    state.dlopen_callbacks.clear();
    state.pending_module_handles.clear();
    state.pending_module_handle_set.clear();
    state.refresh_requested = false;
    state.process_id = 0;
    state.init.status = Errno::Uninit;
    state.init.mode = HookMode::Automatic;

    monitor::reset_auto_monitor_installed();
    signal_guard::remove_handler();
    proxy::clear_proxy_stack();
    hub::clear_stack();
    hub::collect_retired();
    state.clearing = false;
}

pub(super) fn get_mode() -> HookMode {
    let state = GLOBAL.state.lock_or_poison();
    state.init.mode
}

pub(super) fn get_debug() -> bool {
    let state = GLOBAL.state.lock_or_poison();
    state.debug
}

pub(super) fn set_debug(debug: bool) {
    let mut state = GLOBAL.state.lock_or_poison();
    state.debug = debug;
    crate::log::set_debug_enabled(debug);
}

pub(super) fn get_recordable() -> bool {
    let state = GLOBAL.state.lock_or_poison();
    state.recordable
}

pub(super) fn set_recordable(recordable: bool) {
    let mut state = GLOBAL.state.lock_or_poison();
    state.recordable = recordable;
}

pub(super) fn get_records(item_flags: u32) -> Option<String> {
    let state = GLOBAL.state.lock_or_poison();
    super::super::record::get_records_text(&state, item_flags)
}

pub(super) fn dump_records(fd: i32, item_flags: u32) -> Errno {
    let text = {
        let state = GLOBAL.state.lock_or_poison();
        super::super::record::get_records_text(&state, item_flags)
    };
    let Some(text) = text else {
        return Errno::Ok;
    };
    match super::super::record::dump_records_text(fd, &text) {
        Ok(()) => Errno::Ok,
        Err(err) => err,
    }
}

pub(super) fn enable_sigsegv_protection(flag: bool) {
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
