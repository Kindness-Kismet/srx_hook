// 解析、分配与过滤在发布 gate 外完成；提交只操作预备页面和原子指针。
use crate::api::HookStub;
use crate::errno::Errno;
use crate::runtime::hub::{self, PreparedChain};
use crate::runtime::state::{CoreState, ModuleInfo, PendingProtection, SlotKey};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use super::lease::{self, LoaderEpoch};
use super::{CallbackEvent, RefreshError};

#[derive(Clone, Copy)]
pub(super) struct ObservedSlot {
    pub(super) value: usize,
    pub(super) protection: u32,
}

struct PreparedPatch {
    address: usize,
    expected: usize,
    value: usize,
}

pub(super) struct AuxiliaryPatch {
    pub(super) address: usize,
    pub(super) expected: usize,
    pub(super) value: usize,
    pub(super) protection: u32,
    pub(super) module_base: usize,
}

pub(super) struct InstructionPatch {
    pub(super) address: usize,
    pub(super) expected: u32,
    pub(super) value: u32,
    pub(super) protection: u32,
    pub(super) module_base: usize,
}

struct PreparedPage {
    pending: PendingProtection,
    write_required: bool,
}

struct UnpublishedHubs {
    pid: libc::pid_t,
    hubs: Vec<usize>,
}

impl Drop for UnpublishedHubs {
    fn drop(&mut self) {
        if self.pid == unsafe { libc::getpid() } {
            for hub in &self.hubs {
                hub::discard_unpublished_hub(*hub as *mut hub::Hub);
            }
        }
    }
}

pub(in crate::runtime) struct PreparedRefresh {
    pub(in crate::runtime) draft: CoreState,
    pub(in crate::runtime) status: Errno,
    pub(in crate::runtime) events: Vec<CallbackEvent>,
    pub(in crate::runtime) errors: Vec<RefreshError>,
    pub(in crate::runtime) committed: bool,
    pub(in crate::runtime) protection_state_changed: bool,
    epoch: LoaderEpoch,
    patches: Vec<PreparedPatch>,
    pub(super) instructions: Vec<InstructionPatch>,
    pages: Vec<PreparedPage>,
    chains: Vec<PreparedChain>,
    unpublished: UnpublishedHubs,
    guard: crate::android::signal_guard::PreparedGuard,
}

impl PreparedRefresh {
    pub(super) fn new(
        draft: CoreState,
        epoch: LoaderEpoch,
        status: Errno,
        events: Vec<CallbackEvent>,
        errors: Vec<RefreshError>,
    ) -> Result<Self, Errno> {
        Ok(Self {
            draft,
            epoch,
            status,
            events,
            errors,
            committed: false,
            protection_state_changed: false,
            patches: Vec::new(),
            instructions: Vec::new(),
            pages: Vec::new(),
            chains: Vec::new(),
            unpublished: UnpublishedHubs {
                pid: unsafe { libc::getpid() },
                hubs: Vec::new(),
            },
            guard: crate::android::signal_guard::prepare()?,
        })
    }

    pub(super) fn prepare_changes(
        &mut self,
        original: &CoreState,
        observed: &BTreeMap<SlotKey, ObservedSlot>,
        auxiliary: &[AuxiliaryPatch],
        modules: &[ModuleInfo],
        pending: Vec<PendingProtection>,
    ) -> Result<(), Errno> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = usize::try_from(page_size).map_err(|_| Errno::GetProt)?;
        if page_size == 0 {
            return Err(Errno::GetProt);
        }
        let mut pages = BTreeMap::new();
        for (key, slot) in &mut self.draft.slots {
            let previous = original.slots.get(key);
            if previous
                .is_some_and(|old| old.task_chain == slot.task_chain && old.hub_ptr == slot.hub_ptr)
            {
                continue;
            }
            let observation = observed.get(key).ok_or(Errno::ModuleLeaseUnavailable)?;
            if slot.hub_ptr == 0 {
                slot.hub_ptr = hub::create_hub(slot.orig_func)? as usize;
                self.unpublished.hubs.push(slot.hub_ptr);
            }
            let proxies = chain_functions(&self.draft.tasks, &slot.task_chain);
            let chain = hub::build_chain(slot.hub_ptr as *mut hub::Hub, &proxies)?;
            let target = chain.trampoline();
            self.chains.push(chain);
            self.patches.push(PreparedPatch {
                address: key.slot_addr,
                expected: observation.value,
                value: target,
            });
            pages.insert(
                key.slot_addr / page_size * page_size,
                (observation.protection, key.caller_base_addr),
            );
        }
        for (key, slot) in &original.slots {
            if self
                .draft
                .slots
                .get(key)
                .is_some_and(|current| current.hub_ptr == slot.hub_ptr)
            {
                continue;
            }
            if slot.hub_ptr != 0 {
                self.chains
                    .push(hub::build_chain(slot.hub_ptr as *mut hub::Hub, &[])?);
            }
            if self.draft.slots.contains_key(key) {
                continue;
            }
            let Some(observation) = observed.get(key) else {
                continue;
            };
            let expected = if slot.hub_ptr == 0 {
                slot.orig_func
            } else {
                hub::hub_trampo(slot.hub_ptr as *mut hub::Hub)
            };
            // 仅在 GOT 仍匹配旧入口时恢复原函数。
            if observation.value != expected {
                continue;
            }
            self.patches.push(PreparedPatch {
                address: key.slot_addr,
                expected,
                value: slot.orig_func,
            });
            pages.insert(
                key.slot_addr / page_size * page_size,
                (observation.protection, key.caller_base_addr),
            );
        }
        for patch in auxiliary {
            self.patches.push(PreparedPatch {
                address: patch.address,
                expected: patch.expected,
                value: patch.value,
            });
            pages.insert(
                patch.address / page_size * page_size,
                (patch.protection, patch.module_base),
            );
        }
        for instruction in &self.instructions {
            pages.insert(
                instruction.address / page_size * page_size,
                (instruction.protection, instruction.module_base),
            );
        }
        self.protection_state_changed = pending.len()
            != original
                .pending_protections
                .iter()
                .filter(|page| page.needs_restore)
                .count();
        let mut prepared_pages: BTreeMap<usize, PreparedPage> = pending
            .into_iter()
            .map(|pending| {
                (
                    pending.address,
                    PreparedPage {
                        pending,
                        write_required: false,
                    },
                )
            })
            .collect();
        for (address, (protection, module_base)) in pages {
            if let Some(page) = prepared_pages.get_mut(&address) {
                page.write_required = true;
                continue;
            }
            let module = modules
                .iter()
                .find(|module| module.base_addr == module_base)
                .ok_or(Errno::ModuleLeaseUnavailable)?;
            prepared_pages.insert(
                address,
                PreparedPage {
                    pending: PendingProtection {
                        address,
                        length: page_size,
                        protection,
                        module: module.clone(),
                        loader_epoch: (self.epoch.adds, self.epoch.subs),
                        needs_restore: false,
                    },
                    write_required: true,
                },
            );
        }
        self.pages = prepared_pages.into_values().collect();
        self.draft.pending_protections =
            self.pages.iter().map(|page| page.pending.clone()).collect();
        Ok(())
    }

    pub(in crate::runtime) fn failure_draft(&self, source: &CoreState) -> CoreState {
        let mut draft = source.clone();
        draft.pending_protections = self.pages.iter().map(|page| page.pending.clone()).collect();
        draft
    }

    pub(in crate::runtime) fn write_protection_results(&self, draft: &mut CoreState) {
        for (target, page) in draft.pending_protections.iter_mut().zip(&self.pages) {
            target.needs_restore = page.pending.needs_restore;
        }
    }

    // callback 尝试获取发布 gate，竞争时立即返回 Busy 并释放 loader 租期。
    pub(in crate::runtime) fn with_loader_lease<R>(
        &mut self,
        callback: impl FnOnce(&mut Self) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        lease::with_loader_lease(|epoch| {
            if epoch != self.epoch {
                return Err(Errno::Busy);
            }
            callback(self)
        })
    }

    // 调用方已持 loader 租期和发布 gate，并验证输入快照仍为当前版本。
    pub(in crate::runtime) fn apply_prepared(&mut self) -> Errno {
        for instruction in &self.instructions {
            let current = match self.guard.run(|| {
                unsafe { &*(instruction.address as *const AtomicU32) }.load(Ordering::SeqCst)
            }) {
                Ok(value) => value,
                Err(error) => return error,
            };
            if current != instruction.expected {
                return Errno::Busy;
            }
        }
        for patch in &self.patches {
            let current = match self
                .guard
                .run(|| unsafe { &*(patch.address as *const AtomicUsize) }.load(Ordering::SeqCst))
            {
                Ok(value) => value,
                Err(error) => return error,
            };
            if current != patch.expected {
                return Errno::Busy;
            }
        }
        for index in 0..self.pages.len() {
            let page = &mut self.pages[index];
            if !page.write_required {
                continue;
            }
            if !protect_page(
                &page.pending,
                page.pending.protection | libc::PROT_WRITE as u32,
            ) {
                for changed in &mut self.pages {
                    if changed.pending.needs_restore {
                        changed.pending.needs_restore =
                            !protect_page(&changed.pending, changed.pending.protection);
                    }
                }
                self.protection_state_changed = true;
                return Errno::SetProt;
            }
            page.pending.needs_restore = true;
            self.protection_state_changed = true;
        }
        for chain in &mut self.chains {
            hub::publish_chain(chain);
        }
        for patch in &self.patches {
            unsafe { &*(patch.address as *const AtomicUsize) }.store(patch.value, Ordering::SeqCst);
        }
        for instruction in &self.instructions {
            unsafe { &*(instruction.address as *const AtomicU32) }
                .store(instruction.value, Ordering::SeqCst);
            crate::android::memory::flush_instruction_cache_range(
                instruction.address,
                instruction.address + std::mem::size_of::<u32>(),
            );
        }
        self.committed = true;
        let mut status = self.status;
        for page in &mut self.pages {
            if !page.pending.needs_restore {
                continue;
            }
            page.pending.needs_restore = !protect_page(&page.pending, page.pending.protection);
            self.protection_state_changed = true;
            if page.pending.needs_restore {
                status = Errno::SetProt;
            }
        }
        self.status = status;
        status
    }

    // 发布 gate 和 loader 租期退出后再格式化故障记录。
    pub(in crate::runtime) fn append_commit_errors(&mut self) {
        for page in self
            .pages
            .iter()
            .map(|page| &page.pending)
            .filter(|page| page.needs_restore)
        {
            crate::log::error(format_args!(
                "page protection restore failed module={} page=0x{:x} protection={}",
                page.module.pathname, page.address, page.protection,
            ));
            if !self.errors.iter().any(|error| {
                error.module_path == page.module.pathname && error.errno == Errno::SetProt
            }) {
                self.errors.push(RefreshError {
                    module_path: page.module.pathname.clone(),
                    errno: Errno::SetProt,
                });
            }
        }
    }
}

pub(super) fn chain_functions(
    tasks: &BTreeMap<HookStub, crate::runtime::state::Task>,
    stubs: &[HookStub],
) -> Vec<usize> {
    let mut counts = BTreeMap::<usize, usize>::new();
    let mut order = Vec::new();
    for stub in stubs {
        let Some(task) = tasks.get(stub) else {
            continue;
        };
        let count = counts.entry(task.new_func).or_default();
        if *count == 0 {
            order.push(task.new_func);
        }
        *count += 1;
    }
    order
        .into_iter()
        .rev()
        .flat_map(|function| std::iter::repeat_n(function, counts[&function]))
        .collect()
}

fn protect_page(page: &PendingProtection, protection: u32) -> bool {
    unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            page.address as *mut libc::c_void,
            page.length,
            protection as libc::c_int,
        ) == 0
    }
}
