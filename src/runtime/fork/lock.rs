// 全局互斥锁，支持 atfork 子进程重置及旧 guard 的释放保护。
use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct ForkMutex<T> {
    locked: AtomicBool,
    owner: AtomicUsize,
    generation: AtomicUsize,
    data: UnsafeCell<T>,
}

// 常规访问由 guard 串行化，原始重置和无锁访问仅供 atfork 协议使用。
unsafe impl<T: Send> Sync for ForkMutex<T> {}

impl<T> ForkMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            owner: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
            data: UnsafeCell::new(value),
        }
    }

    fn acquire(&self) {
        let mut spins = 0u32;
        loop {
            if !self.locked.swap(true, Ordering::Acquire) {
                self.owner
                    .store(unsafe { libc::pthread_self() as usize }, Ordering::Release);
                return;
            }
            if spins < 64 {
                std::hint::spin_loop();
                spins += 1;
            } else {
                std::thread::yield_now();
            }
        }
    }

    pub fn lock(&self) -> ForkMutexGuard<'_, T> {
        self.acquire();
        ForkMutexGuard {
            lock: self,
            generation: self.generation.load(Ordering::Acquire),
            _not_send: PhantomData,
        }
    }

    pub fn is_owned_by_current(&self) -> bool {
        self.locked.load(Ordering::Acquire)
            && self.owner.load(Ordering::Acquire) == unsafe { libc::pthread_self() as usize }
    }

    /// atfork prepare 使用；不返回 guard，配对 unlock_raw/reset_raw。
    pub fn lock_raw(&self) {
        self.acquire();
    }

    pub fn unlock_raw(&self) {
        self.owner.store(0, Ordering::Release);
        self.locked.store(false, Ordering::Release);
    }

    /// 子进程继承锁时直接清状态；调用方必须已保证没有并发持锁者。
    pub fn reset_raw(&self) {
        // 使继承的 guard 失效，避免它释放子进程重新获取的锁。
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.owner.store(0, Ordering::Release);
        self.locked.store(false, Ordering::Release);
    }

    // 仅供 fork 子进程访问，prepare 必须代为获取此锁，调用线程不能持有旧 guard。
    pub unsafe fn with_mut_after_fork<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        unsafe { f(&mut *self.data.get()) }
    }
}

pub struct ForkMutexGuard<'a, T> {
    lock: &'a ForkMutex<T>,
    generation: usize,
    _not_send: PhantomData<Rc<()>>,
}

impl<T> Deref for ForkMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for ForkMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for ForkMutexGuard<'_, T> {
    fn drop(&mut self) {
        if self.lock.generation.load(Ordering::Acquire) == self.generation {
            self.lock.unlock_raw();
        }
    }
}
