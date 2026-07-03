// 线程级 Hub 调用栈，追踪 trampoline 的嵌套调用关系
// 用于 get_prev_func 链式调用和 return address 恢复
use crate::runtime::thread_state;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::Ordering;

pub(super) use crate::runtime::thread_state::HubFrame;

type HubStack = thread_state::FixedStack<HubFrame, { thread_state::HUB_STACK_CAP }>;

// 读取当前硬件栈指针，用于检测过期帧
#[inline(always)]
fn current_stack_pointer() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        let sp: usize;
        unsafe {
            core::arch::asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        return sp;
    }

    #[cfg(target_arch = "x86_64")]
    {
        let sp: usize;
        unsafe {
            core::arch::asm!("mov {0}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        return sp;
    }

    #[allow(unreachable_code)]
    {
        let local = 0usize;
        (&local as *const usize) as usize
    }
}

// 从栈顶清除 SP 已失效的帧，栈向低地址增长，SP <= 记录值表示帧已返回
#[inline]
fn prune_stale_frames(stack: &mut HubStack, current_sp: usize) {
    let mut popped = 0usize;
    while let Some(frame) = stack.last() {
        if frame.stack_sp > current_sp {
            break;
        }
        let _ = stack.pop();
        popped += 1;
    }
    if popped > 0 {
        super::mark_stack_frames_pop(popped);
    }
}

#[inline]
fn with_hub_stack_mut<R, F>(site: &'static str, f: F) -> Option<R>
where
    F: FnOnce(&mut HubStack) -> R,
{
    let result = thread_state::with_thread_state(|state| f(state.hub_stack_mut()));
    if result.is_none() && !thread_state::should_skip_thread_state() {
        thread_state::report_thread_state_unavailable(site);
    }
    result
}

// trampoline 入口回调：清理过期帧、检测递归、查找首个活跃 proxy 并压栈
// 同一 hub_id 已在栈中时回退到 orig_addr 防止无限递归
pub(super) unsafe extern "C" fn hub_push_stack(
    hub_ptr: *mut super::Hub,
    return_addr: *mut c_void,
) -> *mut c_void {
    if hub_ptr.is_null() {
        return ptr::null_mut();
    }
    let hub = unsafe { &*hub_ptr };
    let hub_id = hub_ptr as usize;
    let current_sp = current_stack_pointer();
    let mut next_func = hub.orig_addr;
    let head = hub.head.load(Ordering::Acquire);

    let _ = with_hub_stack_mut("hub_push_stack", |stack| {
        prune_stale_frames(stack, current_sp);

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
            stack_sp: current_sp,
        });
        if pushed {
            super::mark_stack_frame_push();
            return;
        }

        next_func = hub.orig_addr;
        thread_state::report_hub_stack_overflow();
    });

    next_func as *mut c_void
}

pub(super) fn get_return_address() -> *mut c_void {
    with_hub_stack_mut("get_return_address", |stack| {
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
    let _ = with_hub_stack_mut("pop_stack_by_return_address", |stack| {
        if let Some(index) = stack.rposition_by(|frame| frame.return_addr == return_addr) {
            let _ = stack.remove(index);
            super::mark_stack_frames_pop(1);
        }
    });
}

// trampoline 出口回调：proxy 函数返回后弹出对应栈帧
pub(super) extern "C" fn hub_pop_stack(hub_ptr: *mut super::Hub) {
    if hub_ptr.is_null() {
        return;
    }

    let hub_id = hub_ptr as usize;
    let current_sp = current_stack_pointer();
    let _ = with_hub_stack_mut("hub_pop_stack", |stack| {
        prune_stale_frames(stack, current_sp);

        if let Some(frame) = stack.last()
            && frame.hub_id == hub_id
        {
            let _ = stack.pop();
            super::mark_stack_frames_pop(1);
            return;
        }

        if let Some(index) = stack.rposition_by(|frame| frame.hub_id == hub_id) {
            let _ = stack.remove(index);
            super::mark_stack_frames_pop(1);
        }
    });
}

// 在栈中查找 func 所在帧，返回 proxy 链表中的下一个活跃节点
// 若 func 是链表末尾则返回 orig_addr
pub(super) fn get_prev_func(func: *mut c_void) -> *mut c_void {
    if func.is_null() {
        return ptr::null_mut();
    }
    let current = func as usize;
    with_hub_stack_mut("get_prev_func", |stack| {
        let mut idx = stack.len();
        while idx > 0 {
            idx -= 1;
            let Some(frame) = stack.get(idx) else {
                continue;
            };
            let mut found = false;
            let mut cursor = frame.head_ptr as *mut super::ProxyNode;
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
    let _ = with_hub_stack_mut("proxy_leave", |stack| {
        if let Some(frame) = stack.last()
            && frame.first_proxy == func
        {
            let _ = stack.pop();
            super::mark_stack_frames_pop(1);
            return;
        }
        if let Some(index) = stack.rposition_by(|frame| frame.first_proxy == func) {
            let _ = stack.remove(index);
            super::mark_stack_frames_pop(1);
        }
    });
}

pub(super) fn clear_stack() {
    let _ = with_hub_stack_mut("clear_stack", |stack| {
        let count = stack.clear();
        super::mark_stack_frames_pop(count);
    });
}

#[cfg(test)]
pub(super) fn with_test_hub_stack<R, F>(f: F) -> R
where
    F: FnOnce(&mut HubStack) -> R,
{
    match thread_state::with_thread_state(|state| f(state.hub_stack_mut())) {
        Some(result) => result,
        None => panic!("测试环境线程状态不可用"),
    }
}

#[cfg(test)]
mod tests;
