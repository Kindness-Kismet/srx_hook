use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use super::{CoreState, MutexPoisonRecover};
use crate::errno::Errno;
use crate::runtime::fork;

pub(in crate::runtime) struct ProcessRuntime {
    pub(in crate::runtime) pid: libc::pid_t,
    published: AtomicPtr<CoreState>,
    readers: AtomicUsize,
    retired: Mutex<Vec<Arc<CoreState>>>,
    pub(in crate::runtime) next_stub: AtomicU64,
    pub(in crate::runtime) initializing: AtomicBool,
    pub(in crate::runtime) refresh_requested: AtomicBool,
    pub(in crate::runtime) monitor_running: AtomicBool,
    pub(in crate::runtime) monitor_thread: Mutex<Option<JoinHandle<()>>>,
}

enum ReplaceFailure {
    Status(Errno),
    Conflict,
}

impl ProcessRuntime {
    pub(in crate::runtime) const PUBLISH_ATTEMPTS: usize = 8;

    fn new(mut state: CoreState, pid: libc::pid_t) -> Self {
        state.process_id = pid as usize;
        let next_stub = state.next_stub.max(1);
        Self {
            pid,
            published: AtomicPtr::new(Arc::into_raw(Arc::new(state)).cast_mut()),
            readers: AtomicUsize::new(0),
            retired: Mutex::new(Vec::new()),
            next_stub: AtomicU64::new(next_stub),
            initializing: AtomicBool::new(false),
            refresh_requested: AtomicBool::new(false),
            monitor_running: AtomicBool::new(false),
            monitor_thread: Mutex::new(None),
        }
    }

    pub(in crate::runtime) fn snapshot(&self) -> Arc<CoreState> {
        self.readers.fetch_add(1, Ordering::SeqCst);
        let ptr = self.published.load(Ordering::SeqCst);
        unsafe { Arc::increment_strong_count(ptr) };
        self.readers.fetch_sub(1, Ordering::SeqCst);
        unsafe { Arc::from_raw(ptr) }
    }

    pub(in crate::runtime) fn is_current(&self) -> bool {
        self.pid == unsafe { libc::getpid() } && std::ptr::eq(CURRENT.load(Ordering::Acquire), self)
    }

    // 调用方已取得发布权；这里只比较版本并交换完整快照。
    pub(in crate::runtime) fn publish_raw(
        &self,
        expected_revision: u64,
        next: &mut Option<Arc<CoreState>>,
    ) -> Result<*const CoreState, Errno> {
        if !self.is_current() {
            return Err(Errno::ForkContextUnavailable);
        }
        let current = self.published.load(Ordering::SeqCst);
        if unsafe { (*current).revision } != expected_revision {
            return Err(Errno::Busy);
        }
        let Some(next) = next.take() else {
            return Err(Errno::InvalidArg);
        };
        let next = Arc::into_raw(next).cast_mut();
        Ok(self.published.swap(next, Ordering::SeqCst))
    }

    pub(in crate::runtime) fn revision_matches(&self, revision: u64) -> bool {
        self.is_current()
            && unsafe { (*self.published.load(Ordering::SeqCst)).revision == revision }
    }

    pub(in crate::runtime) fn retire(&self, ptr: *const CoreState) {
        if ptr.is_null() || !self.is_current() {
            return;
        }
        let old = unsafe { Arc::from_raw(ptr) };
        let mut retired = self.retired.lock_or_poison();
        retired.push(old);
        if self.readers.load(Ordering::SeqCst) != 0 {
            return;
        }
        let ready = std::mem::take(&mut *retired);
        drop(retired);
        drop(ready);
    }

    pub(in crate::runtime) fn update(
        &self,
        mut edit: impl FnMut(&mut CoreState) -> Errno,
    ) -> Errno {
        for _ in 0..Self::PUBLISH_ATTEMPTS {
            if let Err(status) = fork::check_management() {
                return status;
            }
            if !self.is_current() {
                return Errno::ForkContextUnavailable;
            }
            let source = self.snapshot();
            let mut draft = (*source).clone();
            let status = edit(&mut draft);
            if status != Errno::Ok {
                return status;
            }
            match self.replace(source.revision, draft) {
                Ok(()) => return Errno::Ok,
                Err(ReplaceFailure::Status(status)) => return status,
                Err(ReplaceFailure::Conflict) => {}
            }
        }
        Errno::Busy
    }

    fn replace(&self, revision: u64, mut draft: CoreState) -> Result<(), ReplaceFailure> {
        draft.revision = revision.wrapping_add(1);
        let mut next = Some(Arc::new(draft));
        fork::check_management().map_err(ReplaceFailure::Status)?;
        let Some(guard) = fork::try_publish() else {
            return match fork::check_management() {
                Err(status) => Err(ReplaceFailure::Status(status)),
                Ok(()) => Err(ReplaceFailure::Conflict),
            };
        };
        let result = self.publish_raw(revision, &mut next);
        drop(guard);
        match result {
            Ok(old) => {
                self.retire(old);
                Ok(())
            }
            Err(Errno::Busy) => Err(ReplaceFailure::Conflict),
            Err(error) => Err(ReplaceFailure::Status(error)),
        }
    }
}

static CURRENT: AtomicPtr<ProcessRuntime> = AtomicPtr::new(std::ptr::null_mut());

pub(in crate::runtime) struct GlobalRuntime;
pub(in crate::runtime) static GLOBAL: GlobalRuntime = GlobalRuntime;

impl GlobalRuntime {
    // 冻结期间保留父进程事件，child 运行时由普通管理入口初始化。
    pub(in crate::runtime) fn request_refresh_if_current(&self) {
        let current = CURRENT.load(Ordering::Acquire);
        if current.is_null() {
            return;
        }
        let runtime = unsafe { &*current };
        if runtime.pid == unsafe { libc::getpid() } {
            runtime.refresh_requested.store(true, Ordering::Release);
        }
    }

    pub(in crate::runtime) fn snapshot(&self) -> Arc<CoreState> {
        let current = CURRENT.load(Ordering::Acquire);
        if current.is_null() {
            return self.deref().snapshot();
        }
        // 早期 child handler 直接读取父代完整快照。
        unsafe { (*current).snapshot() }
    }
}

impl Deref for GlobalRuntime {
    type Target = ProcessRuntime;

    fn deref(&self) -> &Self::Target {
        loop {
            let pid = unsafe { libc::getpid() };
            let old = CURRENT.load(Ordering::Acquire);
            if !old.is_null() && unsafe { (*old).pid == pid } {
                return unsafe { &*old };
            }
            // 子进程从完整发布的快照创建运行时，单独管理可变状态和线程句柄。
            let mut state = if old.is_null() {
                CoreState::default()
            } else {
                let root = unsafe { (*old).published.load(Ordering::SeqCst) };
                unsafe { (*root).clone() }
            };
            state.known_modules.clear();
            let new = Box::into_raw(Box::new(ProcessRuntime::new(state, pid)));
            if CURRENT
                .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return unsafe { &*new };
            }
            let candidate = unsafe { Box::from_raw(new) };
            let root = candidate.published.load(Ordering::Relaxed);
            unsafe { drop(Arc::from_raw(root)) };
            drop(candidate);
        }
    }
}
