// 跳板页面整体初始化并设为 RX 后再发布，已发布的入口不再改写或复用。
use crate::android::memory;
use crate::errno::Errno;
use crate::runtime::hub::{Hub, stack};
use crate::runtime::state::MutexPoisonRecover;
use once_cell::sync::Lazy;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::AtomicPtr;

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
        // 此 Hub 尚未发布，只需设置原函数地址，不改写已设为 RX 的代码。
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
                    lock: Mutex::new(()),
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

static TRAMPO_MGR: Lazy<Mutex<TrampoMgr>> = Lazy::new(|| Mutex::new(TrampoMgr::new()));

pub(super) fn alloc_hub(orig_addr: usize) -> Result<*mut Hub, Errno> {
    TRAMPO_MGR.lock_or_poison().alloc(orig_addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_page_stays_executable_and_unchanged_during_later_allocations() {
        let mut manager = TrampoMgr::new();
        let first = manager.alloc(123).expect("first Hub");
        let first_entry = unsafe { (*first).trampo };
        let page = first_entry / manager.page_size * manager.page_size;
        let snapshot =
            unsafe { std::slice::from_raw_parts(page as *const u8, manager.page_size).to_vec() };
        let second = manager.alloc(456).expect("second Hub");
        assert_eq!(
            unsafe { (*second).trampo } / manager.page_size,
            page / manager.page_size
        );
        assert_eq!(unsafe { (*first).orig_addr }, 123);
        assert_eq!(unsafe { (*second).orig_addr }, 456);

        for _ in 0..manager.page_size / manager.trampo_size {
            manager.alloc(789).expect("later Hub");
        }
        let current = unsafe { std::slice::from_raw_parts(page as *const u8, manager.page_size) };
        assert_eq!(current, snapshot);
        assert_eq!(
            memory::get_addr_protect(first_entry, None).expect("page protection"),
            memory::PROT_READ_FLAG | memory::PROT_EXEC_FLAG
        );
    }
}
