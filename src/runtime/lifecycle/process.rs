// 子进程接管继承的 hook，并丢弃已消失的父进程 monitor 句柄。
use crate::api::HookMode;
use crate::log;

use super::super::state::{CoreState, set_install_pid};

pub(super) fn ensure_process_context(state: &mut CoreState) -> bool {
    let current_pid = unsafe { libc::getpid() as usize };
    if current_pid == 0 {
        return false;
    }
    if state.process_id == current_pid {
        return false;
    }
    if state.process_id == 0 {
        state.process_id = current_pid;
        return false;
    }

    log::warn(format_args!(
        "process changed old_pid={} new_pid={}, retain hooks and replace monitor",
        state.process_id, current_pid
    ));

    state.known_modules.clear();
    state.pending_module_handles.clear();
    state.pending_module_handle_set.clear();
    state.refresh_requested = state.init.mode == HookMode::Automatic;
    state.monitor_running = false;
    if let Some(thread) = state.monitor_thread.take() {
        std::mem::forget(thread);
    }
    state.process_id = current_pid;
    set_install_pid(current_pid as i32);
    state.init.mode == HookMode::Automatic
}
