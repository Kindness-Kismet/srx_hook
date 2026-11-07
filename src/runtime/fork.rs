use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

use crate::errno::Errno;

const WRITER: usize = 1;
const FREEZE: usize = 2;
const NO_KEY: usize = usize::MAX;
static GATE: AtomicUsize = AtomicUsize::new(0);
static GATE_PID: AtomicI32 = AtomicI32::new(0);
static REGISTRATION: AtomicUsize = AtomicUsize::new(0);
static DEPTH_KEY: AtomicUsize = AtomicUsize::new(NO_KEY);
static ACTIVE_LOADER: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_INITIALIZATION: AtomicUsize = AtomicUsize::new(0);
static LOADER_UNAVAILABLE: AtomicBool = AtomicBool::new(false);

pub(super) fn register_handlers() -> Result<(), Errno> {
    let pid = unsafe { libc::getpid() };
    let current = REGISTRATION.load(Ordering::Acquire);
    if current & 3 == 2 {
        return Ok(());
    }
    let running = ((pid as usize) << 2) | 1;
    if current & 3 == 1 && current >> 2 == pid as usize {
        return Err(Errno::Busy);
    }
    if REGISTRATION
        .compare_exchange(current, running, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Errno::Busy);
    }
    let mut key = 0;
    if unsafe { libc::pthread_key_create(&mut key, None) } != 0 {
        REGISTRATION.store(0, Ordering::Release);
        return Err(Errno::InitErrSafe);
    }
    DEPTH_KEY.store(key as usize, Ordering::Release);
    let result = unsafe { libc::pthread_atfork(Some(prepare), Some(parent), Some(child)) };
    if result != 0 {
        unsafe { libc::pthread_key_delete(key) };
        DEPTH_KEY.store(NO_KEY, Ordering::Release);
        GATE_PID.store(0, Ordering::Release);
        REGISTRATION.store(0, Ordering::Release);
        return Err(Errno::InitErrSafe);
    }
    // 回调注册成功后才约束进程归属，注册前派生的子进程可以重新初始化。
    GATE_PID.store(pid, Ordering::Release);
    REGISTRATION.store(((pid as usize) << 2) | 2, Ordering::Release);
    Ok(())
}

pub(super) fn handlers_registered() -> bool {
    REGISTRATION.load(Ordering::Acquire) & 3 == 2
}

pub(super) fn is_frozen() -> bool {
    let owner = GATE_PID.load(Ordering::Acquire);
    (owner != 0 && owner != unsafe { libc::getpid() })
        || GATE.load(Ordering::Acquire) & !WRITER != 0
}

pub(super) fn check_management() -> Result<(), Errno> {
    if is_frozen() {
        return Err(Errno::Busy);
    }
    if LOADER_UNAVAILABLE.load(Ordering::Acquire) {
        return Err(Errno::ForkContextUnavailable);
    }
    Ok(())
}

pub(super) struct PublishGuard {
    pid: libc::pid_t,
    marker: std::marker::PhantomData<*mut ()>,
}

pub(super) fn try_publish() -> Option<PublishGuard> {
    if is_frozen() {
        return None;
    }
    GATE.compare_exchange(0, WRITER, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| PublishGuard {
            pid: unsafe { libc::getpid() },
            marker: std::marker::PhantomData,
        })
}

impl Drop for PublishGuard {
    fn drop(&mut self) {
        if self.pid == unsafe { libc::getpid() } {
            GATE.fetch_and(!WRITER, Ordering::Release);
        }
    }
}

pub(crate) struct LoaderCall {
    pid: libc::pid_t,
}

impl LoaderCall {
    pub(crate) fn enter() -> Self {
        ACTIVE_LOADER.fetch_add(1, Ordering::SeqCst);
        Self {
            pid: unsafe { libc::getpid() },
        }
    }
}

impl Drop for LoaderCall {
    fn drop(&mut self) {
        if self.pid == unsafe { libc::getpid() } {
            ACTIVE_LOADER.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

pub(crate) struct InitializationCall {
    pid: libc::pid_t,
}

impl InitializationCall {
    pub(crate) fn enter() -> Self {
        ACTIVE_INITIALIZATION.fetch_add(1, Ordering::SeqCst);
        Self {
            pid: unsafe { libc::getpid() },
        }
    }
}

impl Drop for InitializationCall {
    fn drop(&mut self) {
        if self.pid == unsafe { libc::getpid() } {
            ACTIVE_INITIALIZATION.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn depth() -> usize {
    let key = DEPTH_KEY.load(Ordering::Acquire) as libc::pthread_key_t;
    unsafe { libc::pthread_getspecific(key) as usize }
}

fn set_depth(value: usize) {
    let key = DEPTH_KEY.load(Ordering::Acquire) as libc::pthread_key_t;
    unsafe { libc::pthread_setspecific(key, value as *const libc::c_void) };
}

unsafe extern "C" fn prepare() {
    set_depth(depth() + 1);
    GATE.fetch_add(FREEZE, Ordering::AcqRel);
    // 发布段由当前线程完成预备好的内存写入和原始系统调用。
    while GATE.load(Ordering::Acquire) & WRITER != 0 {
        std::hint::spin_loop();
    }
}

unsafe extern "C" fn parent() {
    set_depth(depth().saturating_sub(1));
    GATE.fetch_sub(FREEZE, Ordering::Release);
}

unsafe extern "C" fn child() {
    let pid = unsafe { libc::getpid() };
    let remaining = depth().saturating_sub(1);
    set_depth(remaining);
    LOADER_UNAVAILABLE.store(
        LOADER_UNAVAILABLE.load(Ordering::Relaxed)
            || ACTIVE_LOADER.load(Ordering::Acquire) != 0
            || ACTIVE_INITIALIZATION.load(Ordering::Acquire) != 0,
        Ordering::Release,
    );
    ACTIVE_LOADER.store(0, Ordering::Release);
    ACTIVE_INITIALIZATION.store(0, Ordering::Release);
    GATE.store(remaining * FREEZE, Ordering::Release);
    GATE_PID.store(pid, Ordering::Release);
    REGISTRATION.store(((pid as usize) << 2) | 2, Ordering::Release);
    super::thread_state::after_fork_child();
}
