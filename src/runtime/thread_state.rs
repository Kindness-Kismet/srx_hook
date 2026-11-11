use crate::log;
use crate::runtime;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

mod trampoline;
pub(crate) use trampoline::{
    after_fork_child, has_active_trampolines, has_trampoline_frame, trampoline_enter,
    trampoline_leave,
};

pub(crate) fn active_trampoline_count() -> usize {
    trampoline::active_trampoline_count()
}

pub(crate) fn current_active_trampoline_count() -> usize {
    trampoline::current_active_trampoline_count()
}

pub(crate) const HUB_STACK_CAP: usize = 32;
pub(crate) const PROXY_STACK_CAP: usize = 32;

// Hub 栈帧只存原始数据，避免跨模块私有类型耦合
#[derive(Clone, Copy)]
pub(crate) struct HubFrame {
    pub(crate) hub_id: usize,
    pub(crate) head_ptr: usize,
    pub(crate) orig_addr: usize,
    pub(crate) first_proxy: usize,
    pub(crate) return_addr: usize,
    pub(crate) stack_sp: usize,
}

// Proxy 栈帧用于检测递归与过期帧
#[derive(Clone, Copy)]
pub(crate) struct ProxyFrame {
    pub(crate) func: usize,
    pub(crate) stack_sp: usize,
}

// 运行期间使用固定容量的栈。
pub(crate) struct FixedStack<T: Copy, const N: usize> {
    len: usize,
    items: [MaybeUninit<T>; N],
}

impl<T: Copy, const N: usize> FixedStack<T, N> {
    pub(crate) fn new() -> Self {
        let items = unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() };
        Self { len: 0, items }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn clear(&mut self) -> usize {
        let old_len = self.len;
        self.len = 0;
        old_len
    }

    pub(crate) fn push(&mut self, item: T) -> bool {
        if self.len >= N {
            return false;
        }
        self.items[self.len].write(item);
        self.len += 1;
        true
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(unsafe { self.items[self.len].assume_init_read() })
    }

    pub(crate) fn last(&self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        Some(unsafe { *self.items[self.len - 1].as_ptr() })
    }

    pub(crate) fn get(&self, index: usize) -> Option<T> {
        if index >= self.len {
            return None;
        }
        Some(unsafe { *self.items[index].as_ptr() })
    }

    pub(crate) fn remove(&mut self, index: usize) -> Option<T> {
        if index >= self.len {
            return None;
        }

        let removed = unsafe { self.items[index].assume_init_read() };
        let mut i = index;
        while i + 1 < self.len {
            let next = unsafe { self.items[i + 1].assume_init_read() };
            self.items[i].write(next);
            i += 1;
        }
        self.len -= 1;
        Some(removed)
    }

    pub(crate) fn rposition_by<F>(&self, mut pred: F) -> Option<usize>
    where
        F: FnMut(T) -> bool,
    {
        let mut idx = self.len;
        while idx > 0 {
            idx -= 1;
            let item = unsafe { *self.items[idx].as_ptr() };
            if pred(item) {
                return Some(idx);
            }
        }
        None
    }
}

// 线程运行时状态，集中管理两类调用栈
pub(crate) struct ThreadRuntimeState {
    hub_stack: FixedStack<HubFrame, HUB_STACK_CAP>,
    proxy_stack: FixedStack<ProxyFrame, PROXY_STACK_CAP>,
}

impl ThreadRuntimeState {
    fn new() -> Self {
        Self {
            hub_stack: FixedStack::new(),
            proxy_stack: FixedStack::new(),
        }
    }

    pub(crate) fn hub_stack_mut(&mut self) -> &mut FixedStack<HubFrame, HUB_STACK_CAP> {
        &mut self.hub_stack
    }

    pub(crate) fn proxy_stack_mut(&mut self) -> &mut FixedStack<ProxyFrame, PROXY_STACK_CAP> {
        &mut self.proxy_stack
    }
}

#[derive(Clone, Copy)]
struct ThreadStateKeys {
    state_key: libc::pthread_key_t,
    reserved_key: libc::pthread_key_t,
}

static THREAD_STATE_KEYS: AtomicU64 = AtomicU64::new(0);
static THREAD_STATE_KEY_INIT_FAIL: AtomicU64 = AtomicU64::new(0);
static THREAD_STATE_BIND_FAIL: AtomicU64 = AtomicU64::new(0);
static THREAD_STATE_ACCESS_FAIL: AtomicU64 = AtomicU64::new(0);
static THREAD_STATE_RESERVED_HIT: AtomicU64 = AtomicU64::new(0);
static HUB_STACK_OVERFLOW: AtomicU64 = AtomicU64::new(0);
static PROXY_STACK_OVERFLOW: AtomicU64 = AtomicU64::new(0);

type ThreadStatePtr = *mut ThreadRuntimeState;

const RESERVED_SENTINEL: *const c_void = ptr::dangling::<c_void>();

fn thread_state_keys() -> Option<ThreadStateKeys> {
    let word = THREAD_STATE_KEYS.load(Ordering::Acquire);
    if word == 0 {
        return None;
    }
    Some(ThreadStateKeys {
        state_key: ((word >> 32) as u32 - 1) as libc::pthread_key_t,
        reserved_key: (word as u32 - 1) as libc::pthread_key_t,
    })
}

// pthread key 析构：线程退出时释放线程状态，并设置析构保护标记
unsafe extern "C" fn destroy_thread_state(raw_ptr: *mut c_void) {
    if raw_ptr.is_null() {
        return;
    }

    if let Some(keys) = thread_state_keys() {
        unsafe {
            let _ = libc::pthread_setspecific(keys.reserved_key, RESERVED_SENTINEL);
        }
    }

    unsafe {
        drop(Box::from_raw(raw_ptr as ThreadStatePtr));
    }

    if let Some(keys) = thread_state_keys() {
        unsafe {
            let _ = libc::pthread_setspecific(keys.state_key, ptr::null());
        }
    }
}

fn should_log_every_step(count: u64) -> bool {
    count == 1 || count.is_multiple_of(256)
}

fn is_fork_child_text() -> &'static str {
    if runtime::state::is_forked_child() {
        "是"
    } else {
        "否"
    }
}

fn report_thread_state_key_init_fail(phase: &str, ret: i32) {
    let count = THREAD_STATE_KEY_INIT_FAIL.fetch_add(1, Ordering::Relaxed) + 1;
    if should_log_every_step(count) {
        log::warn(format_args!(
            "线程状态 key 初始化失败: phase={} ret={} 次数={} fork_child={}",
            phase,
            ret,
            count,
            is_fork_child_text()
        ));
    }
}

fn ensure_thread_state_keys() -> Option<ThreadStateKeys> {
    if let Some(keys) = thread_state_keys() {
        return Some(keys);
    }

    let mut state_key: libc::pthread_key_t = 0;
    let state_ret = unsafe {
        libc::pthread_key_create(
            &mut state_key as *mut libc::pthread_key_t,
            Some(destroy_thread_state),
        )
    };
    if state_ret != 0 {
        report_thread_state_key_init_fail("state", state_ret);
        return None;
    }

    let mut reserved_key: libc::pthread_key_t = 0;
    let reserved_ret =
        unsafe { libc::pthread_key_create(&mut reserved_key as *mut libc::pthread_key_t, None) };
    if reserved_ret != 0 {
        unsafe {
            let _ = libc::pthread_key_delete(state_key);
        }
        report_thread_state_key_init_fail("reserved", reserved_ret);
        return None;
    }

    let word = (u64::from(state_key as u32 + 1) << 32) | u64::from(reserved_key as u32 + 1);
    if THREAD_STATE_KEYS
        .compare_exchange(0, word, Ordering::Release, Ordering::Relaxed)
        .is_err()
    {
        unsafe {
            let _ = libc::pthread_key_delete(state_key);
            let _ = libc::pthread_key_delete(reserved_key);
        }
    }

    thread_state_keys()
}

fn is_thread_state_reserved(keys: ThreadStateKeys) -> bool {
    let reserved = unsafe { libc::pthread_getspecific(keys.reserved_key) };
    !reserved.is_null()
}

fn report_thread_state_reserved() {
    let count = THREAD_STATE_RESERVED_HIT.fetch_add(1, Ordering::Relaxed) + 1;
    if should_log_every_step(count) {
        log::warn(format_args!(
            "线程状态析构保护命中: 次数={} fork_child={}",
            count,
            is_fork_child_text()
        ));
    }
}

fn get_or_init_thread_state_ptr(keys: ThreadStateKeys) -> Option<ThreadStatePtr> {
    if is_thread_state_reserved(keys) {
        report_thread_state_reserved();
        return None;
    }

    let existing = unsafe { libc::pthread_getspecific(keys.state_key) } as ThreadStatePtr;
    if !existing.is_null() {
        return Some(existing);
    }

    let raw_ptr = Box::into_raw(Box::new(ThreadRuntimeState::new()));
    let ret = unsafe { libc::pthread_setspecific(keys.state_key, raw_ptr as *const c_void) };
    if ret != 0 {
        unsafe {
            drop(Box::from_raw(raw_ptr));
        }
        let count = THREAD_STATE_BIND_FAIL.fetch_add(1, Ordering::Relaxed) + 1;
        if should_log_every_step(count) {
            log::warn(format_args!(
                "线程状态绑定失败: ret={} 次数={} fork_child={}",
                ret,
                count,
                is_fork_child_text()
            ));
        }
        return None;
    }

    Some(raw_ptr)
}

// 预先准备 key，线程实例在首次访问时创建。
pub(crate) fn init_thread_state_key() -> bool {
    if ensure_thread_state_keys().is_none() || !trampoline::init_keys() {
        return false;
    }
    after_fork_child();
    true
}

// 确保当前线程已具备线程状态
pub(crate) fn init_current_thread_state() -> bool {
    with_thread_state(|_| ()).is_some()
}

// 访问当前线程状态，失败时返回 None
pub(crate) fn with_thread_state<R, F>(f: F) -> Option<R>
where
    F: FnOnce(&mut ThreadRuntimeState) -> R,
{
    let keys = ensure_thread_state_keys()?;
    let raw_ptr = get_or_init_thread_state_ptr(keys)?;
    let state = unsafe { &mut *raw_ptr };
    Some(f(state))
}

// 采样记录线程状态访问失败。
pub(crate) fn report_thread_state_unavailable(site: &str) {
    let count = THREAD_STATE_ACCESS_FAIL.fetch_add(1, Ordering::Relaxed) + 1;
    if should_log_every_step(count) {
        log::warn(format_args!(
            "线程状态尚未建立: site={} 次数={} fork_child={}",
            site,
            count,
            is_fork_child_text()
        ));
    }
}

// 记录 Hub 固定栈溢出
pub(crate) fn report_hub_stack_overflow() {
    let count = HUB_STACK_OVERFLOW.fetch_add(1, Ordering::Relaxed) + 1;
    if should_log_every_step(count) {
        log::warn(format_args!(
            "Hub 固定栈溢出: cap={} 次数={} fork_child={}",
            HUB_STACK_CAP,
            count,
            is_fork_child_text()
        ));
    }
}

// 记录 Proxy 固定栈溢出
pub(crate) fn report_proxy_stack_overflow() {
    let count = PROXY_STACK_OVERFLOW.fetch_add(1, Ordering::Relaxed) + 1;
    if should_log_every_step(count) {
        log::warn(format_args!(
            "Proxy 固定栈溢出: cap={} 次数={} fork_child={}",
            PROXY_STACK_CAP,
            count,
            is_fork_child_text()
        ));
    }
}
