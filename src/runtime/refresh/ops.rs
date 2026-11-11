// GOT slot 读写、ELF 解析和模块扫描的底层操作，所有操作均在信号保护下执行
use super::lease;
use crate::android::signal_guard;
use crate::elf;
use crate::errno::Errno;
use std::collections::BTreeSet;
use std::ffi::c_void;
use std::ptr;

use super::super::state::ModuleInfo;

mod module_scan;

// 模块加载/卸载计数，用于检测模块列表是否发生变化
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ModuleEpoch {
    pub(super) adds: u64,
    pub(super) subs: u64,
}

pub(super) fn read_slot(addr: usize) -> Result<usize, Errno> {
    signal_guard::with_guard(|| unsafe { ptr::read(addr as *const usize) })
        .map_err(|_| Errno::ReadElf)
}

pub(super) fn init_elf_guard(base_addr: usize, pathname: &str) -> Result<elf::Elf, Errno> {
    signal_guard::with_guard(|| unsafe { elf::Elf::init(base_addr, pathname) })
        .map_err(|_| Errno::ReadElf)?
}

pub(super) fn find_slots_guard(
    elf: &elf::Elf,
    symbol_name: &str,
    callee_addrs: Option<&BTreeSet<usize>>,
) -> Result<Vec<usize>, Errno> {
    signal_guard::with_guard(|| unsafe { elf.find_got_slots(symbol_name, callee_addrs) })
        .map_err(|_| Errno::ReadElf)?
}

pub(super) fn find_export_guard(elf: &elf::Elf, symbol_name: &str) -> Result<Option<usize>, Errno> {
    signal_guard::with_guard(|| elf.find_export_function(symbol_name)).map_err(|_| Errno::ReadElf)
}

pub(super) fn module_epoch() -> Option<ModuleEpoch> {
    module_scan::module_epoch()
}

pub(super) fn observe_module_identity(module: &ModuleInfo) {
    module_scan::observe_module_identity(module);
}

pub(super) fn module_identity_from_handle(handle: *mut c_void) -> Option<ModuleInfo> {
    lease::with_loader_lease(|_| Ok(module_scan::module_identity_from_handle(handle)))
        .ok()
        .flatten()
}

pub(super) fn module_identity_from_handle_with_symbol(
    handle: *mut c_void,
    probe_symbol: &str,
) -> Option<ModuleInfo> {
    lease::with_loader_lease(|_| {
        Ok(module_scan::module_identity_from_handle_with_symbol(
            handle,
            probe_symbol,
        ))
    })
    .ok()
    .flatten()
}

pub(super) fn enumerate_modules() -> Vec<ModuleInfo> {
    module_scan::enumerate_modules()
}
