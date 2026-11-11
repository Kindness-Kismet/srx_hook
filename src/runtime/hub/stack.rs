// 线程级 Hub 调用栈，追踪 trampoline 的嵌套调用关系
// 用于 get_prev_func 链式调用和 return address 恢复
use super::Hub;
use super::ProxyNode;
use super::acquire_chain;
use super::release_chain;
use crate::runtime::thread_state;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::Ordering;

pub(super) use crate::runtime::thread_state::HubFrame;

type HubStack = thread_state::FixedStack<HubFrame, { thread_state::HUB_STACK_CAP }>;

// 逻辑帧可提前移除，存活判定以独立的原生返回栈为准。
#[inline]
fn prune_stale_frames(stack: &mut HubStack) {
    while let Some(frame) = stack.last() {
        if thread_state::has_trampoline_frame(frame.hub_id, frame.return_addr, frame.stack_sp) {
            break;
        }
        let _ = stack.pop();
    }
}

#[inline]
fn with_hub_stack_mut<R, F>(site: &'static str, f: F) -> Option<R>
where
    F: FnOnce(&mut thread_state::ThreadRuntimeState) -> R,
{
    let result = thread_state::with_thread_state(f);
    if result.is_none() {
        thread_state::report_thread_state_unavailable(site);
    }
    result
}

// 汇编约定：两个返回寄存器依次携带目标函数和返回落点。
#[repr(C)]
pub(super) struct Dispatch {
    target: usize,
    return_to: usize,
}

// 入口回调：记录原生返回帧并选取 proxy，同一 Hub 递归时回落原函数。
pub(super) unsafe extern "C" fn hub_push_stack(
    hub_ptr: *mut Hub,
    return_addr: *mut c_void,
    caller_sp: usize,
    return_target: usize,
) -> Dispatch {
    let mut dispatch = Dispatch {
        target: 0,
        return_to: return_addr as usize,
    };
    if hub_ptr.is_null() {
        return dispatch;
    }
    let hub = unsafe { &*hub_ptr };
    let hub_id = hub_ptr as usize;
    dispatch.target = hub.orig_addr;
    thread_state::after_fork_child();
    let chain = acquire_chain(hub);
    if !thread_state::trampoline_enter(
        hub_id,
        return_addr as usize,
        caller_sp,
        return_target,
        chain as usize,
    ) {
        release_chain(chain as usize);
        return dispatch;
    }
    dispatch.return_to = return_target;
    let mut next_func = hub.orig_addr;
    let head = if chain.is_null() {
        ptr::null_mut()
    } else {
        unsafe { (*chain).head }
    };

    let _ = with_hub_stack_mut("hub_push_stack", |state| {
        prune_stale_frames(state.hub_stack_mut());
        let stack = state.hub_stack_mut();

        let mut idx = 0usize;
        while idx < stack.len() {
            if let Some(frame) = stack.get(idx)
                && frame.hub_id == hub_id
            {
                next_func = hub.orig_addr;
                return;
            }
            idx += 1;
        }

        let mut cursor = head;
        while !cursor.is_null() {
            let node = unsafe { &*cursor };
            if node.enabled.load(Ordering::Acquire) {
                next_func = node.func;
                break;
            }
            cursor = node.next;
        }

        if next_func == hub.orig_addr {
            return;
        }

        let pushed = stack.push(HubFrame {
            hub_id,
            head_ptr: head as usize,
            orig_addr: hub.orig_addr,
            first_proxy: next_func,
            return_addr: return_addr as usize,
            stack_sp: caller_sp,
        });

        if pushed {
            return;
        }

        next_func = hub.orig_addr;
        thread_state::report_hub_stack_overflow();
    });
    dispatch.target = next_func;
    dispatch
}

pub(super) fn get_return_address() -> *mut c_void {
    with_hub_stack_mut("get_return_address", |state| {
        let stack = state.hub_stack_mut();
        stack
            .last()
            .map(|frame| frame.return_addr as *mut c_void)
            .unwrap_or(ptr::null_mut())
    })
    .unwrap_or(ptr::null_mut())
}

pub(super) fn pop_stack_by_return_address(return_addr: *mut c_void) {
    if return_addr.is_null() {
        return;
    }
    let return_addr = return_addr as usize;
    let _ = with_hub_stack_mut("pop_stack_by_return_address", |state| {
        let stack = state.hub_stack_mut();
        if let Some(index) = stack.rposition_by(|frame| frame.return_addr == return_addr) {
            let _ = stack.remove(index);
        }
    });
}

// trampoline 出口回调：proxy 函数返回后弹出对应栈帧
pub(super) extern "C" fn hub_pop_stack(hub_ptr: *mut Hub, caller_sp: usize) -> usize {
    if hub_ptr.is_null() {
        return 0;
    }

    let hub_id = hub_ptr as usize;
    let return_addr = thread_state::trampoline_leave(hub_id, caller_sp);
    let _ = with_hub_stack_mut("hub_pop_stack", |state| {
        let stack = state.hub_stack_mut();
        if let Some(index) = stack.rposition_by(|frame| {
            frame.hub_id == hub_id
                && frame.stack_sp == caller_sp
                && frame.return_addr == return_addr
        }) {
            let _ = stack.remove(index);
        }
        prune_stale_frames(stack);
    });
    return_addr
}

// 在栈中查找 func 所在帧，返回 proxy 链表中的下一个活跃节点
// 若 func 是链表末尾则返回 orig_addr
pub(super) fn get_prev_func(func: *mut c_void) -> *mut c_void {
    if func.is_null() {
        return ptr::null_mut();
    }
    let current = func as usize;
    with_hub_stack_mut("get_prev_func", |state| {
        let stack = state.hub_stack_mut();
        let mut idx = stack.len();
        while idx > 0 {
            idx -= 1;
            let Some(frame) = stack.get(idx) else {
                continue;
            };
            let mut found = false;
            let mut cursor = frame.head_ptr as *mut ProxyNode;
            while !cursor.is_null() {
                let node = unsafe { &*cursor };
                if !found {
                    if node.func != current {
                        cursor = node.next;
                        continue;
                    }
                    found = true;
                    cursor = node.next;
                    continue;
                }
                if node.enabled.load(Ordering::Acquire) {
                    return node.func as *mut c_void;
                }
                cursor = node.next;
            }
            if found {
                return frame.orig_addr as *mut c_void;
            }
        }
        ptr::null_mut()
    })
    .unwrap_or(ptr::null_mut())
}

pub(super) fn proxy_leave(func: *mut c_void) {
    if func.is_null() {
        return;
    }
    let func = func as usize;
    let _ = with_hub_stack_mut("proxy_leave", |state| {
        let stack = state.hub_stack_mut();
        if let Some(frame) = stack.last()
            && frame.first_proxy == func
        {
            let _ = stack.pop();
            return;
        }
        if let Some(index) = stack.rposition_by(|frame| frame.first_proxy == func) {
            let _ = stack.remove(index);
        }
    });
}

pub(super) fn clear_stack() {
    let _ = with_hub_stack_mut("clear_stack", |state| {
        if !thread_state::has_active_trampolines() {
            let _ = state.hub_stack_mut().clear();
        }
    });
}

#[cfg(test)]
pub(super) fn with_test_hub_stack<R, F>(f: F) -> R
where
    F: FnOnce(&mut HubStack) -> R,
{
    match thread_state::with_thread_state(|state| f(state.hub_stack_mut())) {
        Some(result) => result,
        None => panic!("测试环境线程状态尚未建立"),
    }
}

#[cfg(test)]
mod tests;
