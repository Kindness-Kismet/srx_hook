// 模块级 CFI hook，将各模块 GOT 中的 __cfi_slowpath 替换为空操作 proxy
use crate::android::{memory, signal_guard};
use crate::elf;
use crate::errno::Errno;
use crate::log;
use crate::runtime::state::MutexPoisonRecover;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use super::super::state::ModuleInfo;
use super::{ANDROID_API_LEVEL_CFI_DISABLE, android_api_level};

// 单个模块 CFI hook 失败后的最大重试次数
const CFI_MODULE_HOOK_FAIL_RETRY_LIMIT: u8 = 3;

// 模块 CFI hook 状态的唯一标识，按 base_addr + instance_id 区分
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModuleCfiKey {
    base_addr: usize,
    instance_id: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ModuleCfiHookState {
    status: Errno,
    fail_count: u8,
}

impl ModuleCfiHookState {
    const fn new() -> Self {
        Self {
            status: Errno::Ok,
            fail_count: 0,
        }
    }
}

fn module_cfi_hook_states() -> &'static Mutex<BTreeMap<ModuleCfiKey, ModuleCfiHookState>> {
    static MODULE_CFI_HOOK_STATES: OnceLock<Mutex<BTreeMap<ModuleCfiKey, ModuleCfiHookState>>> =
        OnceLock::new();
    MODULE_CFI_HOOK_STATES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

// 确保指定模块的 CFI GOT slot 已被 hook，带重试限制
pub(super) fn ensure_module_cfi_hook_impl(module: &ModuleInfo, elf: &elf::Elf) -> Errno {
    if android_api_level() < ANDROID_API_LEVEL_CFI_DISABLE {
        return Errno::Ok;
    }

    let key = ModuleCfiKey {
        base_addr: module.base_addr,
        instance_id: module.instance_id,
    };
    if let Some(state) = module_cfi_hook_states().lock_or_poison().get(&key).copied() {
        if state.status == Errno::Ok {
            return Errno::Ok;
        }
        if state.fail_count >= CFI_MODULE_HOOK_FAIL_RETRY_LIMIT {
            return state.status;
        }
    }

    let status = hook_module_cfi_symbols(module, elf);
    let mut states = module_cfi_hook_states().lock_or_poison();
    let entry = states.entry(key).or_insert_with(ModuleCfiHookState::new);
    if status == Errno::Ok {
        entry.status = Errno::Ok;
        entry.fail_count = 0;
    } else {
        entry.status = status;
        entry.fail_count = entry.fail_count.saturating_add(1);
        log::warn(format_args!(
            "cfi module hook failed path={} base=0x{:x} status={:?} retry={}/{}",
            module.pathname,
            module.base_addr,
            status,
            entry.fail_count,
            CFI_MODULE_HOOK_FAIL_RETRY_LIMIT
        ));
    }
    entry.status
}

// 清理已卸载模块的 CFI hook 状态记录
pub(super) fn retain_module_cfi_hook_state_impl(modules: &[ModuleInfo]) {
    let alive_keys: BTreeSet<ModuleCfiKey> = modules
        .iter()
        .map(|module| ModuleCfiKey {
            base_addr: module.base_addr,
            instance_id: module.instance_id,
        })
        .collect();
    module_cfi_hook_states()
        .lock()
        .unwrap()
        .retain(|key, _| alive_keys.contains(key));
}

fn hook_module_cfi_symbols(module: &ModuleInfo, elf: &elf::Elf) -> Errno {
    let slowpath_result = hook_module_cfi_symbol_slots(
        module,
        elf,
        "__cfi_slowpath",
        cfi_slowpath_proxy as *const () as usize,
    );
    let diag_result = hook_module_cfi_symbol_slots(
        module,
        elf,
        "__cfi_slowpath_diag",
        cfi_slowpath_diag_proxy as *const () as usize,
    );
    let Ok(slowpath_count) = slowpath_result else {
        return Errno::CfiHookFailed;
    };
    let Ok(diag_count) = diag_result else {
        return Errno::CfiHookFailed;
    };
    if slowpath_count > 0 || diag_count > 0 {
        log::debug(format_args!(
            "cfi invisible hook module={} base=0x{:x} slowpath={} diag={}",
            module.pathname, module.base_addr, slowpath_count, diag_count
        ));
    }
    Errno::Ok
}

fn hook_module_cfi_symbol_slots(
    module: &ModuleInfo,
    elf: &elf::Elf,
    symbol: &str,
    proxy_addr: usize,
) -> Result<usize, Errno> {
    let slots = signal_guard::with_guard(|| unsafe { elf.find_got_slots(symbol, None) })
        .map_err(|_| Errno::ReadElf)?
        .map_err(|_| Errno::ReadElf)?;
    if slots.is_empty() {
        return Ok(0);
    }
    for slot_addr in &slots {
        patch_module_cfi_slot(*slot_addr, proxy_addr, &module.pathname)?;
    }
    Ok(slots.len())
}

// 将模块 GOT 中的 CFI slot 写入 proxy 地址
fn patch_module_cfi_slot(slot_addr: usize, proxy_addr: usize, pathname: &str) -> Result<(), Errno> {
    // 已经是目标值则跳过
    let current = signal_guard::with_guard(|| unsafe { std::ptr::read(slot_addr as *const usize) })
        .map_err(|_| Errno::ReadElf)?;
    if current == proxy_addr {
        return Ok(());
    }

    let old_prot =
        memory::get_addr_protect(slot_addr, Some(pathname)).map_err(|_| Errno::GetProt)?;
    let writable_prot = memory::PROT_READ_FLAG | memory::PROT_WRITE_FLAG;
    if old_prot != writable_prot {
        memory::set_addr_protect(slot_addr, writable_prot).map_err(|_| Errno::SetProt)?;
    }

    let write_result = signal_guard::with_guard(|| unsafe {
        let atomic_slot = &*(slot_addr as *const AtomicUsize);
        atomic_slot.store(proxy_addr, Ordering::SeqCst);
        atomic_slot.load(Ordering::SeqCst)
    });
    if old_prot != writable_prot {
        let _ = memory::set_addr_protect(slot_addr, old_prot);
    }

    let written_addr = write_result.map_err(|_| Errno::SetGot)?;
    if written_addr != proxy_addr {
        return Err(Errno::GotVerify);
    }
    memory::flush_instruction_cache(slot_addr);
    Ok(())
}

// CFI slowpath 空操作代理，替换原始 __cfi_slowpath 使其不执行检查
extern "C" fn cfi_slowpath_proxy(_call_site_type_id: u64, _ptr: *mut c_void) {}

// CFI slowpath diag 空操作代理
extern "C" fn cfi_slowpath_diag_proxy(
    _call_site_type_id: u64,
    _ptr: *mut c_void,
    _diag_data: *mut c_void,
) {
}
