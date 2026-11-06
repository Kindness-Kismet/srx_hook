// PLT hook 调度中心（Hub）
// 每个被 hook 的 PLT slot 对应一个 Hub，管理 proxy 链表和 trampoline 入口
use crate::errno::Errno;
use crate::runtime::state::MutexPoisonRecover;
use once_cell::sync::Lazy;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

mod stack;
mod trampoline;

// proxy 链表节点，ref_count 支持同一函数被多个 task 引用
struct ProxyNode {
    func: usize,
    ref_count: AtomicUsize,
    enabled: AtomicBool,
    next: *mut ProxyNode,
}

// Hub 核心结构：orig_addr 为原始函数地址，trampo 为 trampoline 代码地址
// head 为 proxy 链表头，采用无锁读和有锁写
pub(super) struct Hub {
    pub(super) orig_addr: usize,
    pub(super) trampo: usize,
    head: AtomicPtr<ProxyNode>,
    lock: Mutex<()>,
}

// 已从退休 Hub 摘除、等待活跃跳板退出后释放的 proxy 链。
static RETIRED_HUBS: Lazy<Mutex<Vec<usize>>> = Lazy::new(|| Mutex::new(Vec::new()));

unsafe fn destroy_proxy_nodes(mut node: *mut ProxyNode) {
    while !node.is_null() {
        let next = unsafe { (*node).next };
        unsafe {
            drop(Box::from_raw(node));
        }
        node = next;
    }
}

pub(super) fn collect_retired() {
    let ready = {
        let mut retired = RETIRED_HUBS.lock_or_poison();
        if crate::runtime::thread_state::active_trampoline_count() != 0 {
            return;
        }
        std::mem::take(&mut *retired)
    };
    for head in ready {
        unsafe { destroy_proxy_nodes(head as *mut ProxyNode) };
    }
}

// 分配尚未发布的 Hub，跳板已预先绑定该 Hub 和出入口回调。
pub(super) fn create_hub(orig_addr: usize) -> Result<*mut Hub, Errno> {
    collect_retired();
    trampoline::alloc_hub(orig_addr)
}

pub(super) fn destroy_hub(hub_ptr: *mut Hub) {
    if hub_ptr.is_null() {
        return;
    }

    // shortcut: 入口和 Hub 保留到进程退出；安全回收需覆盖已取到地址但尚未进入跳板的调用方。
    let proxy_head = unsafe { (*hub_ptr).head.swap(ptr::null_mut(), Ordering::SeqCst) };
    if !proxy_head.is_null() {
        RETIRED_HUBS.lock_or_poison().push(proxy_head as usize);
    }
    collect_retired();
}

pub(super) fn hub_trampo(hub_ptr: *mut Hub) -> usize {
    if hub_ptr.is_null() {
        return 0;
    }
    unsafe { (*hub_ptr).trampo }
}

// 向 Hub 添加 proxy 函数；已存在则增加引用计数并重新启用
pub(super) fn add_proxy(hub_ptr: *mut Hub, proxy_func: usize) -> Errno {
    if hub_ptr.is_null() || proxy_func == 0 {
        return Errno::InvalidArg;
    }

    let hub = unsafe { &*hub_ptr };
    let _guard = hub.lock.lock_or_poison();

    let mut cursor = hub.head.load(Ordering::Acquire);
    while !cursor.is_null() {
        let node = unsafe { &*cursor };
        if node.func == proxy_func {
            let count = node.ref_count.load(Ordering::Relaxed);
            node.ref_count
                .store(count.saturating_add(1), Ordering::Relaxed);
            node.enabled.store(true, Ordering::SeqCst);
            return Errno::Ok;
        }
        cursor = node.next;
    }

    let node = Box::new(ProxyNode {
        func: proxy_func,
        ref_count: AtomicUsize::new(1),
        enabled: AtomicBool::new(true),
        next: hub.head.load(Ordering::Acquire),
    });
    let node_ptr = Box::into_raw(node);
    hub.head.store(node_ptr, Ordering::Release);
    Errno::Ok
}

// 移除 proxy 函数；引用计数归零时标记 disabled 而非物理删除
// 返回 (操作结果, 是否仍有活跃 proxy)
pub(super) fn del_proxy(hub_ptr: *mut Hub, proxy_func: usize) -> (Errno, bool) {
    if hub_ptr.is_null() || proxy_func == 0 {
        return (Errno::InvalidArg, false);
    }

    let hub = unsafe { &*hub_ptr };
    let _guard = hub.lock.lock_or_poison();

    let mut deleted = false;

    let mut cursor = hub.head.load(Ordering::Acquire);
    while !cursor.is_null() {
        let node = unsafe { &*cursor };
        if node.func == proxy_func && node.enabled.load(Ordering::Acquire) {
            let count = node.ref_count.load(Ordering::Relaxed);
            if count > 1 {
                node.ref_count.store(count - 1, Ordering::Relaxed);
            } else {
                node.ref_count.store(0, Ordering::Relaxed);
                node.enabled.store(false, Ordering::SeqCst);
            }
            deleted = true;
            break;
        }
        cursor = node.next;
    }

    let mut have_enabled_proxy = false;
    let mut scan = hub.head.load(Ordering::Acquire);
    while !scan.is_null() {
        let node = unsafe { &*scan };
        if node.enabled.load(Ordering::Acquire) {
            have_enabled_proxy = true;
            break;
        }
        scan = node.next;
    }

    if deleted {
        return (Errno::Ok, have_enabled_proxy);
    }
    (Errno::NotFound, have_enabled_proxy)
}

pub(super) fn first_enabled(hub_ptr: *mut Hub) -> usize {
    if hub_ptr.is_null() {
        return 0;
    }
    let hub = unsafe { &*hub_ptr };
    let mut cursor = hub.head.load(Ordering::Acquire);
    while !cursor.is_null() {
        let node = unsafe { &*cursor };
        if node.enabled.load(Ordering::Acquire) {
            return node.func;
        }
        cursor = node.next;
    }
    hub.orig_addr
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

#[cfg(test)]
mod retirement_tests {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn thread_exit_releases_unfinished_trampolines() {
        let _serial = TEST_LOCK.lock().unwrap();
        let active_before = crate::runtime::thread_state::active_trampoline_count();
        std::thread::spawn(|| {
            assert!(crate::runtime::thread_state::trampoline_enter(1, 1, 1, 2));
        })
        .join()
        .expect("worker join");
        assert_eq!(
            crate::runtime::thread_state::active_trampoline_count(),
            active_before
        );
    }

    #[test]
    fn retired_hub_stays_valid_and_active_frames_keep_proxy_nodes() {
        let _serial = TEST_LOCK.lock().unwrap();
        let hub_ptr = create_hub(1).expect("allocate test Hub");
        let trampo = hub_trampo(hub_ptr);
        let proxy = Box::into_raw(Box::new(ProxyNode {
            func: 1,
            ref_count: AtomicUsize::new(0),
            enabled: AtomicBool::new(false),
            next: ptr::null_mut(),
        }));
        unsafe { (*hub_ptr).head.store(proxy, Ordering::SeqCst) };

        assert!(crate::runtime::thread_state::trampoline_enter(
            hub_ptr as usize,
            1,
            100,
            2
        ));
        destroy_hub(hub_ptr);
        assert!(unsafe { (*hub_ptr).head.load(Ordering::Acquire) }.is_null());
        assert!(RETIRED_HUBS.lock_or_poison().contains(&(proxy as usize)));
        collect_retired();
        assert_eq!(
            crate::runtime::thread_state::trampoline_leave(hub_ptr as usize, 100),
            1
        );
        collect_retired();

        assert!(!RETIRED_HUBS.lock_or_poison().contains(&(proxy as usize)));
        assert_eq!(unsafe { (*hub_ptr).orig_addr }, 1);
        let next_hub = create_hub(2).expect("allocate next Hub");
        let next_trampo = hub_trampo(next_hub);
        assert_ne!(next_trampo, trampo, "retired trampoline address was reused");
        destroy_hub(next_hub);
    }
}
