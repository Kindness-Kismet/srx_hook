// 已发布的入口保持稳定，代理链独立发布并按物理调用帧回收。
use crate::errno::Errno;
use crate::runtime::state::{MutexPoisonRecover, PidLocal};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

mod stack;
mod trampoline;

struct ProxyNode {
    func: usize,
    ref_count: usize,
    enabled: AtomicBool,
    next: *mut ProxyNode,
}

struct ProxyChain {
    head: *mut ProxyNode,
    readers: AtomicU64,
    hub: usize,
}

impl Drop for ProxyChain {
    fn drop(&mut self) {
        let mut node = self.head;
        while !node.is_null() {
            let owned = unsafe { Box::from_raw(node) };
            node = owned.next;
        }
    }
}

pub(super) struct Hub {
    pub(super) orig_addr: usize,
    pub(super) trampo: usize,
    head: AtomicPtr<ProxyChain>,
    acquiring: AtomicU64,
    published: AtomicBool,
}

static RETIRED_CHAINS: PidLocal<Mutex<Vec<usize>>> = PidLocal::new(|| Mutex::new(Vec::new()));

fn process_id() -> u32 {
    unsafe { libc::getpid() as u32 }
}

fn counter_value(value: u64, pid: u32) -> u32 {
    if (value >> 32) as u32 == pid {
        value as u32
    } else {
        0
    }
}

fn counter_acquire(counter: &AtomicU64, pid: u32) {
    let mut old = counter.load(Ordering::SeqCst);
    loop {
        let count = counter_value(old, pid);
        let next = ((pid as u64) << 32) | (u64::from(count) + 1);
        match counter.compare_exchange_weak(old, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(current) => old = current,
        }
    }
}

fn counter_release(counter: &AtomicU64, pid: u32) {
    let mut old = counter.load(Ordering::SeqCst);
    loop {
        let count = counter_value(old, pid);
        if count == 0 {
            return;
        }
        let next = ((pid as u64) << 32) | u64::from(count - 1);
        match counter.compare_exchange_weak(old, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(current) => old = current,
        }
    }
}

fn retire_chain(chain: *mut ProxyChain) {
    if !chain.is_null() {
        RETIRED_CHAINS.get().lock_or_poison().push(chain as usize);
    }
}

// 链的回收统一等待返回帧和入口读取窗口释放引用。
pub(super) fn collect_retired(_force: bool) {
    let pid = process_id();
    let mut ready = Vec::new();
    {
        let mut retired = RETIRED_CHAINS.get().lock_or_poison();
        let mut index = 0;
        while index < retired.len() {
            let chain = unsafe { &*(retired[index] as *const ProxyChain) };
            let hub = unsafe { &*(chain.hub as *const Hub) };
            if counter_value(hub.acquiring.load(Ordering::SeqCst), pid) != 0
                || counter_value(chain.readers.load(Ordering::SeqCst), pid) != 0
            {
                index += 1;
                continue;
            }
            ready.push(retired.swap_remove(index));
        }
    }
    for chain in ready {
        unsafe { drop(Box::from_raw(chain as *mut ProxyChain)) };
    }
}

pub(super) fn create_hub(orig_addr: usize) -> Result<*mut Hub, Errno> {
    collect_retired(false);
    trampoline::alloc_hub(orig_addr)
}

// 构建与清理在提交区外，提交仅交换完整链指针。
pub(super) struct PreparedChain {
    hub: usize,
    next: *mut ProxyChain,
    retired: *mut ProxyChain,
    owner_pid: u32,
    published: bool,
}

impl PreparedChain {
    pub(super) fn hub_ptr(&self) -> *mut Hub {
        self.hub as *mut Hub
    }

    pub(super) fn trampoline(&self) -> usize {
        hub_trampo(self.hub_ptr())
    }
}

impl Drop for PreparedChain {
    fn drop(&mut self) {
        if self.owner_pid != process_id() {
            return;
        }
        if !self.published && !self.next.is_null() {
            unsafe { drop(Box::from_raw(self.next)) };
        }
        retire_chain(self.retired);
        collect_retired(false);
    }
}

// 既有函数保持链中顺序，新函数按输入顺序置于链首；重复 task 只增加引用数。
pub(super) fn build_chain(hub_ptr: *mut Hub, proxies: &[usize]) -> Result<PreparedChain, Errno> {
    if hub_ptr.is_null() || proxies.contains(&0) {
        return Err(Errno::InvalidArg);
    }
    let mut entries = Vec::<(usize, usize)>::new();
    for &func in proxies {
        if let Some((_, count)) = entries.iter_mut().find(|(existing, _)| *existing == func) {
            *count += 1;
        } else {
            entries.push((func, 1));
        }
    }
    let previous = current_proxies(unsafe { &*hub_ptr });
    let mut ordered = Vec::with_capacity(entries.len());
    for &(func, count) in &entries {
        if !previous.contains(&func) {
            ordered.push((func, count));
        }
    }
    for func in previous {
        if ordered.iter().any(|&(existing, _)| existing == func) {
            continue;
        }
        if let Some(&entry) = entries.iter().find(|&&(existing, _)| existing == func) {
            ordered.push(entry);
        }
    }
    let entries = ordered;
    let next = if entries.is_empty() {
        ptr::null_mut()
    } else {
        let mut chain = Box::new(ProxyChain {
            head: ptr::null_mut(),
            readers: AtomicU64::new(0),
            hub: hub_ptr as usize,
        });
        for (func, ref_count) in entries.into_iter().rev() {
            chain.head = Box::into_raw(Box::new(ProxyNode {
                func,
                ref_count,
                enabled: AtomicBool::new(true),
                next: chain.head,
            }));
        }
        Box::into_raw(chain)
    };
    Ok(PreparedChain {
        hub: hub_ptr as usize,
        next,
        retired: ptr::null_mut(),
        owner_pid: process_id(),
        published: false,
    })
}

pub(super) fn publish_chain(prepared: &mut PreparedChain) {
    let hub = unsafe { &*(prepared.hub as *const Hub) };
    prepared.retired = hub.head.swap(prepared.next, Ordering::SeqCst);
    hub.published.store(true, Ordering::Release);
    prepared.published = true;
}

// 调用方独占失败计划中的新 Hub；已发布入口保留至进程退出。
pub(super) fn discard_unpublished_hub(hub_ptr: *mut Hub) {
    if hub_ptr.is_null() || unsafe { (*hub_ptr).published.load(Ordering::Acquire) } {
        return;
    }
    trampoline::discard_unpublished_hub(hub_ptr);
}

pub(super) fn destroy_hub(hub_ptr: *mut Hub, _with_delay: bool) {
    if hub_ptr.is_null() {
        return;
    }
    let chain = unsafe { (*hub_ptr).head.swap(ptr::null_mut(), Ordering::SeqCst) };
    retire_chain(chain);
    collect_retired(false);
}

pub(super) fn hub_trampo(hub_ptr: *mut Hub) -> usize {
    if hub_ptr.is_null() {
        0
    } else {
        unsafe { (*hub_ptr).trampo }
    }
}

// 入口先保护获取窗口，防止加载链指针与增加引用之间发生回收。
fn acquire_chain(hub: &Hub) -> *mut ProxyChain {
    let pid = process_id();
    counter_acquire(&hub.acquiring, pid);
    let chain = hub.head.load(Ordering::SeqCst);
    if !chain.is_null() {
        counter_acquire(unsafe { &(*chain).readers }, pid);
    }
    counter_release(&hub.acquiring, pid);
    chain
}

pub(crate) fn release_chain(chain: usize) {
    if chain != 0 {
        counter_release(
            unsafe { &(*(chain as *const ProxyChain)).readers },
            process_id(),
        );
    }
}

// child 只为仍在当前线程返回栈上的链恢复本进程引用。
pub(crate) fn inherit_chain(chain: usize) {
    if chain != 0 {
        counter_acquire(
            unsafe { &(*(chain as *const ProxyChain)).readers },
            process_id(),
        );
    }
}

fn current_proxies(hub: &Hub) -> Vec<usize> {
    let chain = acquire_chain(hub);
    let mut proxies = Vec::new();
    if !chain.is_null() {
        let mut cursor = unsafe { (*chain).head };
        while !cursor.is_null() {
            let node = unsafe { &*cursor };
            proxies.extend(std::iter::repeat_n(node.func, node.ref_count));
            cursor = node.next;
        }
        release_chain(chain as usize);
    }
    proxies
}

// 兼容入口由运行时写者串行调用，产品提交优先使用 PreparedChain。
pub(super) fn add_proxy(hub_ptr: *mut Hub, proxy_func: usize) -> Errno {
    if hub_ptr.is_null() || proxy_func == 0 {
        return Errno::InvalidArg;
    }
    let mut proxies = current_proxies(unsafe { &*hub_ptr });
    let index = proxies
        .iter()
        .position(|&func| func == proxy_func)
        .unwrap_or(0);
    proxies.insert(index, proxy_func);
    let mut prepared = match build_chain(hub_ptr, &proxies) {
        Ok(prepared) => prepared,
        Err(err) => return err,
    };
    publish_chain(&mut prepared);
    Errno::Ok
}

pub(super) fn del_proxy(hub_ptr: *mut Hub, proxy_func: usize) -> (Errno, bool) {
    if hub_ptr.is_null() || proxy_func == 0 {
        return (Errno::InvalidArg, false);
    }
    let mut proxies = current_proxies(unsafe { &*hub_ptr });
    let Some(index) = proxies.iter().position(|&func| func == proxy_func) else {
        return (Errno::NotFound, !proxies.is_empty());
    };
    proxies.remove(index);
    let mut prepared = match build_chain(hub_ptr, &proxies) {
        Ok(prepared) => prepared,
        Err(err) => return (err, !proxies.is_empty()),
    };
    publish_chain(&mut prepared);
    (Errno::Ok, !proxies.is_empty())
}

pub(super) fn first_enabled(hub_ptr: *mut Hub) -> usize {
    if hub_ptr.is_null() {
        return 0;
    }
    let hub = unsafe { &*hub_ptr };
    let chain = acquire_chain(hub);
    let first = if chain.is_null() {
        hub.orig_addr
    } else {
        unsafe { (*(*chain).head).func }
    };
    release_chain(chain as usize);
    first
}

pub(super) fn get_prev_func(func: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    stack::get_prev_func(func)
}

pub(super) fn get_return_address() -> *mut std::ffi::c_void {
    stack::get_return_address()
}

pub(super) fn pop_stack(return_address: *mut std::ffi::c_void) {
    stack::pop_stack_by_return_address(return_address)
}

pub(super) fn proxy_leave(func: *mut std::ffi::c_void) {
    stack::proxy_leave(func)
}

pub(super) fn clear_stack() {
    stack::clear_stack();
}
