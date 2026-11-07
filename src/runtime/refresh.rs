// 模块发现与准备在发布锁外完成，GOT 与链只经租期内的纯提交发布。
use crate::api::{HookStub, RefreshError};
use crate::errno::Errno;
use std::ffi::c_void;

use super::state::{HookedEntry, ModuleInfo};

mod lease;
mod matcher;
mod module_registry;
mod ops;
mod prepare;
mod transaction;

#[cfg(target_arch = "aarch64")]
pub(super) use prepare::prepare_cfi_init;
pub(super) use prepare::{prepare_clear, prepare_refresh, prepare_unhook};
pub(super) use transaction::PreparedRefresh;

pub(super) struct CallbackEvent {
    pub(super) hooked: HookedEntry,
    pub(super) task_stub: HookStub,
    pub(super) status: Errno,
    pub(super) caller_path_name: String,
    pub(super) sym_name: String,
    pub(super) new_func: usize,
    pub(super) prev_func: usize,
}

pub(super) fn module_epoch() -> Option<(u64, u64)> {
    ops::module_epoch().map(|epoch| (epoch.adds, epoch.subs))
}

pub(super) fn observe_module_identity(module: &ModuleInfo) {
    ops::observe_module_identity(module);
}

pub(super) fn module_identity_from_handle(handle: *mut c_void) -> Option<ModuleInfo> {
    ops::module_identity_from_handle(handle)
}

pub(super) fn module_identity_from_handle_with_symbol(
    handle: *mut c_void,
    probe_symbol: &str,
) -> Option<ModuleInfo> {
    ops::module_identity_from_handle_with_symbol(handle, probe_symbol)
}
