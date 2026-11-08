// loader 临界区只采集模块数据，用户过滤和新状态构造在租期之外进行。
use crate::android::memory::MemoryProtections;
use crate::api::HookStub;
use crate::elf::Elf;
use crate::errno::Errno;
use crate::runtime::hub;
use crate::runtime::rules::should_ignore;
use crate::runtime::state::{
    CoreState, ModuleInfo, PendingProtection, SlotEntry, SlotKey, Task, TaskType,
};
use std::collections::{BTreeMap, BTreeSet};

use super::lease::{self, LoaderEpoch};
use super::matcher::{CalleeResolve, is_task_match_caller, resolve_callee_addrs};
use super::module_registry::{module_instance_key, module_key, prune_dead_single_task_targets};
#[cfg(target_arch = "aarch64")]
use super::transaction::InstructionPatch;
use super::transaction::{AuxiliaryPatch, ObservedSlot, PreparedRefresh};
use super::{CallbackEvent, RefreshError, ops};

struct ModuleSnapshot {
    modules: Vec<ModuleInfo>,
    ranges: BTreeMap<usize, Vec<(usize, usize)>>,
    epoch: LoaderEpoch,
}

struct TaskSlots {
    task: Task,
    module: ModuleInfo,
    slots: Result<Vec<SlotKey>, Errno>,
}

struct ModuleCapture {
    elf: Result<Elf, Errno>,
    cfi: Option<Result<(), Errno>>,
}

// ELF 指针、CFI 观察结果和权限快照只在本次 loader 租期内共享。
#[derive(Default)]
struct SlotCapture {
    modules: BTreeMap<usize, ModuleCapture>,
    protections: MemoryProtections,
    observed: BTreeMap<SlotKey, ObservedSlot>,
    auxiliary: BTreeMap<usize, AuxiliaryPatch>,
}

pub(in crate::runtime) fn prepare_refresh(
    state: &CoreState,
    _only_new: bool,
    target_task: Option<HookStub>,
) -> Result<PreparedRefresh, Errno> {
    let snapshot = discover_modules()?;
    // 已知路径和地址可被卸载后复用，是否需要改写由实际 slot 与任务链决定。
    let approved = select_tasks(state, &snapshot.modules, target_task);
    let (captured, observed, auxiliary) = capture_slots(state, &snapshot, &approved)?;
    let mut draft = state.clone();
    prune_draft(&mut draft, &snapshot.modules, &observed);
    let mut events = Vec::new();
    let mut errors = Vec::new();
    let mut status = Errno::Ok;
    for capture in captured {
        apply_capture(
            state,
            &mut draft,
            capture,
            &observed,
            &mut events,
            &mut errors,
            &mut status,
        );
    }
    draft.known_modules = snapshot.modules.iter().map(module_key).collect();
    let mut prepared = PreparedRefresh::new(draft, snapshot.epoch, status, events, errors)?;
    prepared.is_full_refresh = target_task.is_none();
    prepared.prepare_changes(
        state,
        &observed,
        &auxiliary,
        &snapshot.modules,
        pending_pages(state, &snapshot)?,
    )?;
    Ok(prepared)
}

pub(in crate::runtime) fn prepare_unhook(
    state: &CoreState,
    stub: HookStub,
) -> Result<PreparedRefresh, Errno> {
    if !state.tasks.contains_key(&stub) {
        return Err(Errno::InvalidArg);
    }
    let snapshot = discover_modules()?;
    let (_, observed, _) = capture_slots(state, &snapshot, &[])?;
    let mut draft = state.clone();
    prune_draft(&mut draft, &snapshot.modules, &observed);
    for slot in draft.slots.values_mut() {
        slot.task_chain.retain(|registered| *registered != stub);
    }
    draft.slots.retain(|_, slot| !slot.task_chain.is_empty());
    draft.task_slots.remove(&stub);
    draft.single_task_targets.remove(&stub);
    draft.tasks.remove(&stub);
    draft.task_order.retain(|registered| *registered != stub);
    let mut prepared =
        PreparedRefresh::new(draft, snapshot.epoch, Errno::Ok, Vec::new(), Vec::new())?;
    prepared.prepare_changes(
        state,
        &observed,
        &[],
        &snapshot.modules,
        pending_pages(state, &snapshot)?,
    )?;
    Ok(prepared)
}

pub(in crate::runtime) fn prepare_clear(state: &CoreState) -> Result<PreparedRefresh, Errno> {
    let snapshot = discover_modules()?;
    let (_, observed, _) = capture_slots(state, &snapshot, &[])?;
    let mut draft = state.clone();
    draft.slots.clear();
    draft.task_slots.clear();
    draft.single_task_targets.clear();
    draft.tasks.clear();
    draft.task_order.clear();
    draft.known_modules.clear();
    let mut prepared =
        PreparedRefresh::new(draft, snapshot.epoch, Errno::Ok, Vec::new(), Vec::new())?;
    prepared.prepare_changes(
        state,
        &observed,
        &[],
        &snapshot.modules,
        pending_pages(state, &snapshot)?,
    )?;
    Ok(prepared)
}

#[cfg(target_arch = "aarch64")]
pub(in crate::runtime) fn prepare_cfi_init(state: &CoreState) -> Result<PreparedRefresh, Errno> {
    let snapshot = discover_modules()?;
    let mut prepared = PreparedRefresh::new(
        state.clone(),
        snapshot.epoch,
        Errno::Ok,
        Vec::new(),
        Vec::new(),
    )?;
    prepared.instructions = capture_cfi_instructions(&snapshot)?;
    prepared.prepare_changes(
        state,
        &BTreeMap::new(),
        &[],
        &snapshot.modules,
        pending_pages(state, &snapshot)?,
    )?;
    Ok(prepared)
}

#[cfg(target_arch = "aarch64")]
fn capture_cfi_instructions(snapshot: &ModuleSnapshot) -> Result<Vec<InstructionPatch>, Errno> {
    lease::with_loader_lease(|epoch| {
        if epoch != snapshot.epoch {
            return Err(Errno::Busy);
        }
        let leased_modules: Vec<ModuleInfo> = snapshot
            .modules
            .iter()
            .filter(|module| snapshot.ranges.contains_key(&module.base_addr))
            .cloned()
            .collect();
        let addresses = crate::runtime::cfi::global_patch_addresses(&leased_modules)?;
        let protections = MemoryProtections::default();
        let mut instructions = Vec::new();
        for address in addresses {
            let size = std::mem::size_of::<u32>();
            let end = address.checked_add(size).ok_or(Errno::ReadElf)?;
            if !address.is_multiple_of(size) {
                return Err(Errno::ReadElf);
            }
            let module = leased_modules
                .iter()
                .find(|module| {
                    snapshot.ranges[&module.base_addr]
                        .iter()
                        .any(|(start, limit)| address >= *start && end <= *limit)
                })
                .ok_or(Errno::ModuleLeaseUnavailable)?;
            let expected = crate::android::signal_guard::with_guard(|| unsafe {
                std::ptr::read_volatile(address as *const u32)
            })?;
            if expected == crate::runtime::cfi::RET_INSTRUCTION {
                continue;
            }
            instructions.push(InstructionPatch {
                address,
                expected,
                value: crate::runtime::cfi::RET_INSTRUCTION,
                protection: protections.get(address, size)?,
                module_base: module.base_addr,
            });
        }
        Ok(instructions)
    })
}

fn discover_modules() -> Result<ModuleSnapshot, Errno> {
    lease::with_loader_lease(|_| {
        let modules = ops::enumerate_modules();
        let ranges = lease::bionic_module_ranges();
        let epoch = ops::module_epoch().ok_or(Errno::ModuleLeaseUnavailable)?;
        Ok(ModuleSnapshot {
            modules,
            ranges,
            epoch: LoaderEpoch {
                adds: epoch.adds,
                subs: epoch.subs,
            },
        })
    })
}

fn pending_pages(
    state: &CoreState,
    snapshot: &ModuleSnapshot,
) -> Result<Vec<PendingProtection>, Errno> {
    let mut pending = Vec::new();
    for page in state
        .pending_protections
        .iter()
        .filter(|page| page.needs_restore)
    {
        let Some(module) = snapshot
            .modules
            .iter()
            .find(|module| module.base_addr == page.module.base_addr)
        else {
            continue;
        };
        // 卸载计数一致时，现有模块仍属于记录中的加载实例。
        if page.loader_epoch.1 != snapshot.epoch.subs {
            return Err(Errno::ModuleLeaseUnavailable);
        }
        let ranges = snapshot
            .ranges
            .get(&module.base_addr)
            .ok_or(Errno::ModuleLeaseUnavailable)?;
        let end = page
            .address
            .checked_add(page.length)
            .ok_or(Errno::ModuleLeaseUnavailable)?;
        if page.length == 0
            || !ranges.iter().any(|(start, limit)| {
                let aligned_start = start / page.length * page.length;
                let aligned_end = limit.saturating_add(page.length - 1) / page.length * page.length;
                page.address >= aligned_start && end <= aligned_end
            })
        {
            return Err(Errno::ModuleLeaseUnavailable);
        }
        let mut retained = page.clone();
        retained.module = module.clone();
        pending.push(retained);
    }
    Ok(pending)
}

fn select_tasks(
    state: &CoreState,
    modules: &[ModuleInfo],
    target: Option<HookStub>,
) -> Vec<(Task, ModuleInfo)> {
    let mut approved = Vec::new();
    let tasks: Vec<&Task> = match target {
        Some(stub) => state.tasks.get(&stub).into_iter().collect(),
        None => state
            .task_order
            .iter()
            .filter_map(|stub| state.tasks.get(stub))
            .collect(),
    };
    for module in modules {
        if should_ignore(
            &module.pathname,
            module.base_addr,
            module.instance_id,
            module.namespace_id,
            state.self_base_addr,
            &state.ignore_callers,
        ) {
            continue;
        }
        for task in &tasks {
            if is_task_match_caller(task, module) {
                approved.push(((*task).clone(), module.clone()));
            }
        }
    }
    approved
}

type CapturedSlots = (
    Vec<TaskSlots>,
    BTreeMap<SlotKey, ObservedSlot>,
    Vec<AuxiliaryPatch>,
);

fn capture_slots(
    state: &CoreState,
    snapshot: &ModuleSnapshot,
    approved: &[(Task, ModuleInfo)],
) -> Result<CapturedSlots, Errno> {
    lease::with_loader_lease(|epoch| {
        if epoch != snapshot.epoch {
            return Err(Errno::Busy);
        }
        let mut capture = SlotCapture::default();
        let alive: BTreeSet<String> = snapshot.modules.iter().map(module_key).collect();
        for key in state.slots.keys() {
            let identity = module_instance_key(
                &key.caller_path_name,
                key.caller_base_addr,
                key.caller_instance_id,
                key.caller_namespace_id,
            );
            if alive.contains(&identity)
                && let Some(ranges) = snapshot.ranges.get(&key.caller_base_addr)
            {
                capture.observed.insert(
                    key.clone(),
                    observe_slot(key, ranges, &capture.protections)?,
                );
            }
        }
        let leased_modules: Vec<ModuleInfo> = snapshot
            .modules
            .iter()
            .filter(|module| snapshot.ranges.contains_key(&module.base_addr))
            .cloned()
            .collect();
        let mut callee_cache = BTreeMap::new();
        let mut captured = Vec::new();
        for (task, module) in approved {
            let slots = if let Some(ranges) = snapshot.ranges.get(&module.base_addr) {
                let callee = callee_cache
                    .entry(task.stub)
                    .or_insert_with(|| resolve_callee_addrs(task, &leased_modules));
                match callee {
                    Ok(callee) => capture_task(task, module, callee, ranges, &mut capture),
                    Err(error) => Err(*error),
                }
            } else {
                Err(Errno::ModuleLeaseUnavailable)
            };
            captured.push(TaskSlots {
                task: task.clone(),
                module: module.clone(),
                slots,
            });
        }
        Ok((
            captured,
            capture.observed,
            capture.auxiliary.into_values().collect(),
        ))
    })
}

fn capture_task(
    task: &Task,
    module: &ModuleInfo,
    callee: &CalleeResolve,
    ranges: &[(usize, usize)],
    capture: &mut SlotCapture,
) -> Result<Vec<SlotKey>, Errno> {
    if task.callee_path_name.is_some() && callee.addrs.as_ref().is_some_and(BTreeSet::is_empty) {
        return Ok(Vec::new());
    }
    let entry = capture
        .modules
        .entry(module.base_addr)
        .or_insert_with(|| ModuleCapture {
            elf: ops::init_elf_guard(module.base_addr, &module.pathname),
            cfi: None,
        });
    let elf = entry.elf.as_ref().map_err(|error| *error)?;
    let slots = ops::find_slots_guard(elf, &task.sym_name, callee.addrs.as_ref())?;
    if !slots.is_empty() {
        (*entry.cfi.get_or_insert_with(|| {
            capture_cfi(
                elf,
                module,
                ranges,
                &capture.protections,
                &mut capture.auxiliary,
            )
        }))?;
    }
    let mut keys = Vec::with_capacity(slots.len());
    for address in slots {
        let key = SlotKey {
            caller_path_name: module.pathname.clone(),
            caller_base_addr: module.base_addr,
            caller_instance_id: module.instance_id,
            caller_namespace_id: module.namespace_id,
            slot_addr: address,
        };
        if !capture.observed.contains_key(&key) {
            capture.observed.insert(
                key.clone(),
                observe_slot(&key, ranges, &capture.protections)?,
            );
        }
        keys.push(key);
    }
    Ok(keys)
}

fn capture_cfi(
    elf: &Elf,
    module: &ModuleInfo,
    ranges: &[(usize, usize)],
    protections: &MemoryProtections,
    patches: &mut BTreeMap<usize, AuxiliaryPatch>,
) -> Result<(), Errno> {
    let Some((slowpath, diagnostic)) = crate::runtime::cfi::module_proxy_addresses() else {
        return Ok(());
    };
    for (symbol, target) in [
        ("__cfi_slowpath", slowpath),
        ("__cfi_slowpath_diag", diagnostic),
    ] {
        for address in ops::find_slots_guard(elf, symbol, None)? {
            validate_slot(address, ranges)?;
            let expected = ops::read_slot(address)?;
            if expected == target {
                continue;
            }
            let protection = protections.get(address, std::mem::size_of::<usize>())?;
            patches.insert(
                address,
                AuxiliaryPatch {
                    address,
                    expected,
                    value: target,
                    protection,
                    module_base: module.base_addr,
                },
            );
        }
    }
    Ok(())
}

fn observe_slot(
    key: &SlotKey,
    ranges: &[(usize, usize)],
    protections: &MemoryProtections,
) -> Result<ObservedSlot, Errno> {
    validate_slot(key.slot_addr, ranges)?;
    Ok(ObservedSlot {
        value: ops::read_slot(key.slot_addr)?,
        protection: protections.get(key.slot_addr, std::mem::size_of::<usize>())?,
    })
}

fn validate_slot(address: usize, ranges: &[(usize, usize)]) -> Result<(), Errno> {
    let size = std::mem::size_of::<usize>();
    let end = address.checked_add(size).ok_or(Errno::ReadElf)?;
    if !address.is_multiple_of(size)
        || !ranges
            .iter()
            .any(|(start, limit)| address >= *start && end <= *limit)
    {
        return Err(Errno::ModuleLeaseUnavailable);
    }
    Ok(())
}

fn prune_draft(
    state: &mut CoreState,
    modules: &[ModuleInfo],
    observed: &BTreeMap<SlotKey, ObservedSlot>,
) {
    state.slots.retain(|key, slot| {
        let Some(current) = observed.get(key) else {
            return false;
        };
        let expected = if slot.hub_ptr == 0 {
            slot.orig_func
        } else {
            hub::hub_trampo(slot.hub_ptr as *mut hub::Hub)
        };
        current.value == expected
    });
    for keys in state.task_slots.values_mut() {
        keys.retain(|key| state.slots.contains_key(key));
    }
    state.task_slots.retain(|_, keys| !keys.is_empty());
    let alive = modules.iter().map(module_key).collect();
    prune_dead_single_task_targets(state, &alive);
}

fn apply_capture(
    original: &CoreState,
    state: &mut CoreState,
    captured: TaskSlots,
    observed: &BTreeMap<SlotKey, ObservedSlot>,
    events: &mut Vec<CallbackEvent>,
    errors: &mut Vec<RefreshError>,
    status: &mut Errno,
) {
    let TaskSlots {
        task,
        module,
        slots,
    } = captured;
    if super::matcher::is_single_task_bound_to_other_module(state, &task, &module) {
        return;
    }
    let slots = match slots {
        Ok(slots) => slots,
        Err(error) => {
            if status.is_ok() {
                *status = error;
            }
            if !errors
                .iter()
                .any(|entry| entry.module_path == module.pathname)
            {
                errors.push(RefreshError {
                    module_path: module.pathname.clone(),
                    errno: error,
                });
            }
            emit_event(&task, &module, error, 0, events);
            return;
        }
    };
    if slots.is_empty() {
        if task.task_type == TaskType::Single {
            emit_event(&task, &module, Errno::NoSym, 0, events);
        }
        return;
    }
    for key in slots {
        let Some(observation) = observed.get(&key) else {
            continue;
        };
        let slot = state.slots.entry(key.clone()).or_insert_with(|| SlotEntry {
            orig_func: observation.value,
            task_chain: Vec::new(),
            hub_ptr: 0,
        });
        if slot.task_chain.contains(&task.stub) {
            continue;
        }
        let previous = planned_first_function(original, &state.tasks, &key, slot);
        if state.init.mode == crate::api::HookMode::Manual {
            emit_event(&task, &module, Errno::OrigAddr, previous, events);
        }
        slot.task_chain.push(task.stub);
        state.task_slots.entry(task.stub).or_default().insert(key);
        emit_event(&task, &module, Errno::Ok, previous, events);
    }
    if task.task_type == TaskType::Single {
        state
            .single_task_targets
            .entry(task.stub)
            .or_insert_with(|| module_key(&module));
    }
}

fn planned_first_function(
    original: &CoreState,
    tasks: &BTreeMap<HookStub, Task>,
    key: &SlotKey,
    slot: &SlotEntry,
) -> usize {
    if slot.hub_ptr == 0 {
        return super::transaction::chain_functions(tasks, &slot.task_chain)
            .first()
            .copied()
            .unwrap_or(slot.orig_func);
    }
    let mut existing: BTreeSet<usize> = original
        .slots
        .get(key)
        .into_iter()
        .flat_map(|slot| &slot.task_chain)
        .filter_map(|stub| original.tasks.get(stub).map(|task| task.new_func))
        .collect();
    let mut latest = None;
    for stub in &slot.task_chain {
        if let Some(task) = tasks.get(stub)
            && existing.insert(task.new_func)
        {
            latest = Some(task.new_func);
        }
    }
    latest.unwrap_or_else(|| hub::first_enabled(slot.hub_ptr as *mut hub::Hub))
}

fn emit_event(
    task: &Task,
    module: &ModuleInfo,
    status: Errno,
    previous: usize,
    events: &mut Vec<CallbackEvent>,
) {
    if let Some(hooked) = task.hooked {
        events.push(CallbackEvent {
            hooked,
            task_stub: task.stub,
            status,
            caller_path_name: module.pathname.clone(),
            sym_name: task.sym_name.clone(),
            new_func: task.new_func,
            prev_func: previous,
        });
    }
}
