// 守卫 slot 的分配、查找与信号跳转逻辑
// slot 按 PID/TID 归属线程，支持静态数组 + 动态链表两级存储。

use std::sync::atomic::Ordering;

use super::abi;
use super::{
    GUARD_BASE_SLOTS, GUARD_EXTRA_HEAD, GUARD_STACK_DEPTH_MAX, GuardNode, GuardSlot,
    SigchainCallbackFn, siglongjmp,
};

const CLAIMING: u64 = 1 << 63;

fn current_owner(tid: usize) -> u64 {
    ((unsafe { libc::getpid() } as u64) << 32) | tid as u64
}

// 认领标记隔离旧 env，子进程按 PID 回收父代槽。
fn claim_slot(slot: &'static GuardSlot, owner: u64) -> bool {
    let previous = slot.owner.load(Ordering::Acquire);
    if previous != 0 && (previous & !CLAIMING) >> 32 == owner >> 32 {
        return false;
    }
    if slot
        .owner
        .compare_exchange(
            previous,
            owner | CLAIMING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return false;
    }
    slot.active.store(false, Ordering::Release);
    slot.depth.store(0, Ordering::Release);
    slot.reservations.store(0, Ordering::Release);
    slot.last_signal.store(0, Ordering::Release);
    slot.owner.store(owner, Ordering::Release);
    true
}

pub(super) fn release_if_idle(slot: &GuardSlot) {
    if slot.depth.load(Ordering::Acquire) != 0 || slot.reservations.load(Ordering::Acquire) != 0 {
        return;
    }
    slot.active.store(false, Ordering::Release);
    slot.last_signal.store(0, Ordering::Release);
    slot.owner.store(0, Ordering::Release);
}

// 在静态数组和动态链表中按 tid 查找已归属的 slot
fn find_slot_by_tid(tid: usize) -> Option<&'static GuardSlot> {
    let owner = current_owner(tid);
    for slot in &GUARD_BASE_SLOTS {
        if slot.owner.load(Ordering::Acquire) == owner {
            return Some(slot);
        }
    }

    let mut node = GUARD_EXTRA_HEAD.load(Ordering::Acquire);
    while !node.is_null() {
        let slot = unsafe { &(*node).slot };
        if slot.owner.load(Ordering::Acquire) == owner {
            return Some(slot);
        }
        node = unsafe { (*node).next.load(Ordering::Acquire) };
    }
    None
}

// 查找 tid 对应的活跃 slot（active == true）
fn find_active_slot_by_tid(tid: usize) -> Option<&'static GuardSlot> {
    let owner = current_owner(tid);
    for slot in &GUARD_BASE_SLOTS {
        if slot.owner.load(Ordering::Acquire) == owner && slot.active.load(Ordering::Acquire) {
            return Some(slot);
        }
    }

    let mut node = GUARD_EXTRA_HEAD.load(Ordering::Acquire);
    while !node.is_null() {
        let slot = unsafe { &(*node).slot };
        if slot.owner.load(Ordering::Acquire) == owner && slot.active.load(Ordering::Acquire) {
            return Some(slot);
        }
        node = unsafe { (*node).next.load(Ordering::Acquire) };
    }

    None
}

// 为指定 tid 获取 slot：先查已有 -> CAS 抢占空闲 -> 堆分配新节点
// 新节点通过 CAS 无锁插入链表头部
pub(super) fn acquire_slot(tid: usize) -> Option<&'static GuardSlot> {
    if let Some(slot) = find_slot_by_tid(tid) {
        return Some(slot);
    }

    let owner = current_owner(tid);
    for slot in &GUARD_BASE_SLOTS {
        if claim_slot(slot, owner) {
            return Some(slot);
        }
    }

    let mut node = GUARD_EXTRA_HEAD.load(Ordering::Acquire);
    while !node.is_null() {
        let slot = unsafe { &(*node).slot };
        if claim_slot(slot, owner) {
            return Some(slot);
        }
        node = unsafe { (*node).next.load(Ordering::Acquire) };
    }

    let node = Box::new(GuardNode::new());
    node.slot.owner.store(owner, Ordering::Release);
    let node_ptr = Box::into_raw(node);

    loop {
        let head = GUARD_EXTRA_HEAD.load(Ordering::Acquire);
        unsafe {
            (*node_ptr).next.store(head, Ordering::Release);
        }
        if GUARD_EXTRA_HEAD
            .compare_exchange(head, node_ptr, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(unsafe { &(*node_ptr).slot });
        }
    }
}

// 将信号号和 si_code 编码为单个 usize：高 16 位为 signum，低 16 位为 code
fn encode_signal_info(signum: libc::c_int, code: libc::c_int) -> usize {
    let signum_u16 = (signum.max(0) as u16) as usize;
    let code_u16 = (code as i16 as u16) as usize;
    (signum_u16 << 16) | code_u16
}

pub(super) fn decode_signal_info(encoded: usize) -> (libc::c_int, libc::c_int) {
    let signum = ((encoded >> 16) & 0xFFFF) as i32;
    let code = (encoded as u16 as i16) as i32;
    (signum, code)
}

// 信号处理器核心：查找当前线程的活跃 slot，记录信号信息后 siglongjmp 跳回
// 在信号上下文中调用，必须是 async-signal-safe
fn maybe_jump_guard_slot(sig: libc::c_int, info: *mut libc::siginfo_t) -> bool {
    let tid = abi::current_thread_id();
    let Some(slot) = find_active_slot_by_tid(tid) else {
        return false;
    };
    let depth = slot.depth.load(Ordering::Acquire);
    if depth == 0 || depth > GUARD_STACK_DEPTH_MAX {
        return false;
    }
    let index = depth - 1;
    unsafe {
        let code = if info.is_null() { 0 } else { (*info).si_code };
        slot.last_signal
            .store(encode_signal_info(sig, code), Ordering::Release);
        let env = slot.env_ptr(index);
        siglongjmp(env, 1);
    }
}

pub(super) extern "C" fn sigsegv_sigchain_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ucontext: *mut libc::c_void,
) -> bool {
    maybe_jump_guard_slot(sig, info)
}

pub(super) extern "C" fn sigbus_sigchain_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ucontext: *mut libc::c_void,
) -> bool {
    maybe_jump_guard_slot(sig, info)
}

pub(super) fn sigsegv_sigchain_callback() -> SigchainCallbackFn {
    sigsegv_sigchain_handler
}

pub(super) fn sigbus_sigchain_callback() -> SigchainCallbackFn {
    sigbus_sigchain_handler
}

// sigaction 模式下的信号处理入口，供 handlers 模块调用
pub(super) fn handle_guard_signal(sig: libc::c_int, info: *mut libc::siginfo_t) -> bool {
    maybe_jump_guard_slot(sig, info)
}
