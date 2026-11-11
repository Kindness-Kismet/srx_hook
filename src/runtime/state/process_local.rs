use std::marker;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

struct ProcessValue<T> {
    pid: libc::pid_t,
    value: T,
}

// 初始化函数构造本地状态；父代对象保留，子进程使用独立的锁和状态。
pub(crate) struct PidLocal<T> {
    current: AtomicPtr<ProcessValue<T>>,
    init: fn() -> T,
    marker: marker::PhantomData<T>,
}

unsafe impl<T: Send + Sync> Sync for PidLocal<T> {}

impl<T> PidLocal<T> {
    pub(crate) const fn new(init: fn() -> T) -> Self {
        Self {
            current: AtomicPtr::new(ptr::null_mut()),
            init,
            marker: marker::PhantomData,
        }
    }

    pub(crate) fn get(&self) -> &T {
        loop {
            let pid = unsafe { libc::getpid() };
            let previous = self.current.load(Ordering::Acquire);
            if !previous.is_null() && unsafe { (*previous).pid == pid } {
                return unsafe { &(*previous).value };
            }
            let candidate = Box::into_raw(Box::new(ProcessValue {
                pid,
                value: (self.init)(),
            }));
            match self.current.compare_exchange(
                previous,
                candidate,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return unsafe { &(*candidate).value },
                Err(_) => unsafe { drop(Box::from_raw(candidate)) },
            }
        }
    }
}
