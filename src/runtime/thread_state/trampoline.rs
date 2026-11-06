// 原生返回栈独立于逻辑 proxy 栈，负责保存真实返回地址和保护退休链。
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{FixedStack, HUB_STACK_CAP};

static ACTIVE_COUNT: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn active_trampoline_count() -> usize {
    ACTIVE_COUNT.load(Ordering::SeqCst)
}

fn release(count: usize) {
    if count == 0 {
        return;
    }
    #[allow(deprecated)]
    let _ = ACTIVE_COUNT.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
        Some(active.saturating_sub(count))
    });
}

pub(crate) fn reset_after_fork_child(active: usize) {
    ACTIVE_COUNT.store(active, Ordering::SeqCst);
}

#[derive(Clone, Copy)]
struct TrampolineFrame {
    hub_id: usize,
    return_addr: usize,
    caller_sp: usize,
    return_target: usize,
}

struct ActiveTrampolines(RefCell<FixedStack<TrampolineFrame, HUB_STACK_CAP>>);

impl Drop for ActiveTrampolines {
    fn drop(&mut self) {
        release(self.0.get_mut().len());
    }
}

thread_local! {
    static ACTIVE_TRAMPOLINES: ActiveTrampolines = const { ActiveTrampolines(RefCell::new(FixedStack::new())) };
}

pub(crate) fn trampoline_enter(
    hub_id: usize,
    return_addr: usize,
    caller_sp: usize,
    return_target: usize,
) -> bool {
    ACTIVE_TRAMPOLINES
        .try_with(|active| {
            let Ok(mut stack) = active.0.try_borrow_mut() else {
                return false;
            };
            let mut abandoned = 0;
            // 相同 SP 也可能是尾调用，返回到上一跳板时必须保留外层帧。
            while stack.last().is_some_and(|frame| {
                frame.caller_sp <= caller_sp && frame.return_target != return_addr
            }) {
                stack.pop();
                abandoned += 1;
            }
            release(abandoned);
            if !stack.push(TrampolineFrame {
                hub_id,
                return_addr,
                caller_sp,
                return_target,
            }) {
                return false;
            }
            // 与 Hub 链头的摘除及回收检查保持全序，先计数再读取链头。
            ACTIVE_COUNT.fetch_add(1, Ordering::SeqCst);
            true
        })
        .unwrap_or(false)
}

pub(crate) fn trampoline_leave(hub_id: usize, caller_sp: usize) -> usize {
    ACTIVE_TRAMPOLINES
        .try_with(|active| {
            let mut stack = active.0.borrow_mut();
            loop {
                let frame = stack.pop().expect("trampoline return frame");
                release(1);
                if (frame.hub_id, frame.caller_sp) == (hub_id, caller_sp) {
                    return frame.return_addr;
                }
            }
        })
        .expect("trampoline return TLS")
}

pub(crate) fn has_trampoline_frame(hub_id: usize, return_addr: usize, caller_sp: usize) -> bool {
    ACTIVE_TRAMPOLINES
        .try_with(|active| {
            active
                .0
                .borrow()
                .rposition_by(|frame| {
                    (frame.hub_id, frame.return_addr, frame.caller_sp)
                        == (hub_id, return_addr, caller_sp)
                })
                .is_some()
        })
        .unwrap_or(false)
}

pub(crate) fn has_active_trampolines() -> bool {
    ACTIVE_TRAMPOLINES
        .try_with(|active| !active.0.borrow().is_empty())
        .unwrap_or_else(|_| active_trampoline_count() != 0)
}

// prepare 阶段保存调用线程计数，child 阶段只恢复进程计数。
pub(crate) fn current_active_trampoline_count() -> Option<usize> {
    ACTIVE_TRAMPOLINES
        .try_with(|active| active.0.borrow().len())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_entry_discards_abandoned_frames_and_keeps_outer_return() {
        assert_eq!(current_active_trampoline_count(), Some(0));
        assert!(trampoline_enter(1, 11, 100, 21));
        assert!(trampoline_enter(2, 12, 90, 22));
        assert!(trampoline_enter(3, 13, 95, 23));
        assert!(!has_trampoline_frame(2, 12, 90));
        assert_eq!(trampoline_leave(3, 95), 13);
        assert_eq!(trampoline_leave(1, 100), 11);
        assert_eq!(current_active_trampoline_count(), Some(0));
    }
}
