// 信号守卫先准备线程资源，再用叶子调用保护内存访问。
use super::is_enabled;
use crate::errno::Errno;
use crate::log;
use std::marker::PhantomData;
use std::mem;
use std::rc::Rc;
use std::sync::atomic::Ordering;

use super::{GUARD_STACK_DEPTH_MAX, GuardSlot, abi, altstack, sigsetjmp, slot};

pub struct PreparedGuard {
    slot: Option<&'static GuardSlot>,
    pid: libc::pid_t,
    _not_send: PhantomData<Rc<()>>,
}

impl PreparedGuard {
    // 仅包围叶子内存操作；锁 guard 必须在调用本函数前建立。
    pub fn run<T>(&self, f: impl FnOnce() -> T) -> Result<T, Errno> {
        if self.pid != unsafe { libc::getpid() } {
            return Err(Errno::Busy);
        }
        let Some(slot) = self.slot else {
            return Ok(f());
        };
        run_guard(slot, f)
    }
}

impl Drop for PreparedGuard {
    fn drop(&mut self) {
        if self.pid != unsafe { libc::getpid() } {
            return;
        }
        if let Some(slot) = self.slot {
            slot.reservations.fetch_sub(1, Ordering::AcqRel);
            slot::release_if_idle(slot);
        }
    }
}

// 在发布锁外解析 ABI、分配备用栈并保留 slot。
pub fn prepare() -> Result<PreparedGuard, Errno> {
    let slot = if is_enabled() {
        abi::prime();
        altstack::ensure_thread_altstack()?;
        let slot = slot::acquire_slot(abi::current_thread_id()).ok_or(Errno::SegvErr)?;
        slot.reservations.fetch_add(1, Ordering::AcqRel);
        Some(slot)
    } else {
        None
    };
    Ok(PreparedGuard {
        slot,
        pid: unsafe { libc::getpid() },
        _not_send: PhantomData,
    })
}

struct GuardReset {
    slot: &'static GuardSlot,
}

impl Drop for GuardReset {
    fn drop(&mut self) {
        let depth = self.slot.depth.load(Ordering::Acquire);
        self.slot.depth.store(depth - 1, Ordering::Release);
        if depth == 1 {
            self.slot.active.store(false, Ordering::Release);
        }
        slot::release_if_idle(self.slot);
    }
}

struct SignalMaskGuard {
    prev_mask: libc::sigset_t,
    active: bool,
}

impl SignalMaskGuard {
    fn block() -> Result<Self, Errno> {
        let mut prev_mask: libc::sigset_t = unsafe { mem::zeroed() };
        abi::block_guard_signals(&mut prev_mask)?;
        Ok(Self {
            prev_mask,
            active: true,
        })
    }

    fn restore(&mut self) {
        if self.active {
            abi::restore_guard_signals(&self.prev_mask);
            self.active = false;
        }
    }
}

impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

fn run_guard<T>(slot: &'static GuardSlot, f: impl FnOnce() -> T) -> Result<T, Errno> {
    let mut signal_mask = SignalMaskGuard::block()?;
    let depth = slot.depth.load(Ordering::Acquire);
    if depth >= GUARD_STACK_DEPTH_MAX {
        return Err(Errno::SegvErr);
    }
    slot.last_signal.store(0, Ordering::Release);
    slot.depth.store(depth + 1, Ordering::Release);
    slot.active.store(true, Ordering::Release);
    let _reset = GuardReset { slot };
    unsafe {
        if sigsetjmp(slot.env_ptr(depth), 1) == 0 {
            signal_mask.restore();
            Ok(f())
        } else {
            signal_mask.restore();
            Err(Errno::SegvErr)
        }
    }
}

pub(super) fn with_guard_impl<T>(f: impl FnOnce() -> T) -> Result<T, Errno> {
    let prepared = prepare()?;
    let result = prepared.run(f);
    if result.is_err() {
        let signal_info = prepared
            .slot
            .map(|slot| slot.last_signal.load(Ordering::Acquire))
            .unwrap_or(0);
        if signal_info != 0 {
            let (signum, code) = slot::decode_signal_info(signal_info);
            log::debug(format_args!(
                "guard caught signal signum={} code={}",
                signum, code
            ));
        }
    }
    result
}
