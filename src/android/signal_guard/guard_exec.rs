// 信号守卫的核心执行逻辑
// 通过 sigsetjmp/siglongjmp 实现 SIGSEGV/SIGBUS 的非局部跳转恢复

use crate::errno::Errno;
use crate::log;
use std::sync::atomic::Ordering;

use super::abi;
use super::altstack;
use super::slot;
use super::{GUARD_STACK_DEPTH_MAX, GuardSlot, sigsetjmp};

// 在信号守卫保护下执行闭包
// 流程: 确保备用栈 -> 获取 slot -> 屏蔽信号 -> sigsetjmp -> 执行闭包
pub(super) fn with_guard_impl<T, F>(f: F) -> Result<T, Errno>
where
    F: FnOnce() -> T,
{
    if !super::is_enabled() {
        return Ok(f());
    }

    // RAII 守卫：drop 时递减 slot 深度，深度归零时释放 slot
    struct GuardReset {
        slot: &'static GuardSlot,
        armed: bool,
    }

    impl Drop for GuardReset {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }

            let prev_depth = self.slot.depth.load(Ordering::Acquire);
            if prev_depth == 0 {
                self.slot.active.store(false, Ordering::Release);
                self.slot.tid.store(0, Ordering::Release);
                return;
            }

            let new_depth = prev_depth - 1;
            self.slot.depth.store(new_depth, Ordering::Release);
            if new_depth == 0 {
                self.slot.active.store(false, Ordering::Release);
                self.slot.last_signal.store(0, Ordering::Release);
                self.slot.tid.store(0, Ordering::Release);
            }
        }
    }

    // RAII 信号掩码守卫：构造时屏蔽 SIGSEGV/SIGBUS，drop 时恢复
    struct SignalMaskGuard {
        prev_mask: libc::sigset_t,
        active: bool,
    }

    impl SignalMaskGuard {
        fn block() -> Result<Self, Errno> {
            let mut prev_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
            abi::block_guard_signals(&mut prev_mask)?;
            Ok(Self {
                prev_mask,
                active: true,
            })
        }

        fn restore(&mut self) {
            if !self.active {
                return;
            }
            abi::restore_guard_signals(&self.prev_mask);
            self.active = false;
        }
    }

    impl Drop for SignalMaskGuard {
        fn drop(&mut self) {
            self.restore();
        }
    }

    let tid = abi::current_thread_id();
    altstack::ensure_thread_altstack()?;
    let Some(slot) = slot::acquire_slot(tid) else {
        return Err(Errno::SegvErr);
    };

    let mut signal_guard = SignalMaskGuard::block()?;
    let depth = slot.depth.load(Ordering::Acquire);
    if depth >= GUARD_STACK_DEPTH_MAX {
        signal_guard.restore();
        log::warn(format_args!(
            "guard stack overflow depth={} max={}",
            depth, GUARD_STACK_DEPTH_MAX
        ));
        return Err(Errno::SegvErr);
    }

    slot.last_signal.store(0, Ordering::Release);
    slot.depth.store(depth + 1, Ordering::Release);
    slot.active.store(true, Ordering::Release);
    let _guard_reset = GuardReset { slot, armed: true };

    unsafe {
        let env = slot.env_ptr(depth);
        if sigsetjmp(env, 1) == 0 {
            signal_guard.restore();
            Ok(f())
        } else {
            signal_guard.restore();
            let signal_info = slot.last_signal.load(Ordering::Acquire);
            if signal_info != 0 {
                let (signum, code) = slot::decode_signal_info(signal_info);
                log::debug(format_args!(
                    "guard caught signal signum={} code={}",
                    signum, code
                ));
            }
            Err(Errno::SegvErr)
        }
    }
}
