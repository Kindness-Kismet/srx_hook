// 跳板页面整体初始化并设为 RX 后再发布，入口内容与地址保持稳定。
use crate::android::memory;
use crate::errno::Errno;
use crate::runtime::hub::{Hub, stack};
use crate::runtime::state::{MutexPoisonRecover, PidLocal};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64};

use super::{init_trampo, trampo_size};

struct TrampoMgr {
    page_size: usize,
    trampo_size: usize,
    unused_hubs: Vec<usize>,
}

impl TrampoMgr {
    fn new() -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        Self {
            page_size: if page_size > 0 {
                page_size as usize
            } else {
                4096
            },
            trampo_size: trampo_size(),
            unused_hubs: Vec::new(),
        }
    }

    fn alloc(&mut self, orig_addr: usize) -> Result<*mut Hub, Errno> {
        if self.unused_hubs.is_empty() {
            self.prepare_page()?;
        }
        let hub = self.unused_hubs.pop().ok_or(Errno::NewTrampo)? as *mut Hub;
        // 发布前设置 Hub 的原函数地址，代码页保持 RX。
        unsafe { (*hub).orig_addr = orig_addr };
        Ok(hub)
    }

    fn prepare_page(&mut self) -> Result<(), Errno> {
        let count = self.page_size.checked_div(self.trampo_size).unwrap_or(0);
        if count == 0 {
            return Err(Errno::NewTrampo);
        }
        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                self.page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(Errno::NewTrampo);
        }

        let mut hubs = Vec::with_capacity(count);
        let result = (|| {
            for index in 0..count {
                let trampo = raw as usize + index * self.trampo_size;
                let hub = Box::new(Hub {
                    orig_addr: 0,
                    trampo,
                    head: AtomicPtr::new(ptr::null_mut()),
                    acquiring: AtomicU64::new(0),
                    published: AtomicBool::new(false),
                });
                unsafe {
                    init_trampo(
                        trampo,
                        ptr::from_ref(&*hub) as usize,
                        stack::hub_push_stack as *const () as usize,
                        stack::hub_pop_stack as *const () as usize,
                    )?;
                }
                hubs.push(hub);
            }
            memory::flush_instruction_cache_range(raw as usize, raw as usize + self.page_size);
            memory::set_addr_protect(
                raw as usize,
                memory::PROT_READ_FLAG | memory::PROT_EXEC_FLAG,
            )
            .map_err(|_| Errno::InitErrTrampo)
        })();
        if let Err(err) = result {
            unsafe { libc::munmap(raw, self.page_size) };
            return Err(err);
        }
        self.unused_hubs
            .extend(hubs.into_iter().map(|hub| Box::into_raw(hub) as usize));
        Ok(())
    }
}

static TRAMPO_MGR: PidLocal<Mutex<TrampoMgr>> = PidLocal::new(|| Mutex::new(TrampoMgr::new()));

pub(super) fn alloc_hub(orig_addr: usize) -> Result<*mut Hub, Errno> {
    TRAMPO_MGR.get().lock_or_poison().alloc(orig_addr)
}

pub(super) fn discard_unpublished_hub(hub_ptr: *mut Hub) {
    TRAMPO_MGR
        .get()
        .lock_or_poison()
        .unused_hubs
        .push(hub_ptr as usize);
}
