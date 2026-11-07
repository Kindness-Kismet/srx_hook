// 原生返回帧单独保存在 pthread key，fork 回调只访问已有实例。
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};

use super::{FixedStack, HUB_STACK_CAP};
use crate::runtime::hub;

static KEYS: AtomicU64 = AtomicU64::new(0);
static ACTIVE_COUNT: AtomicUsize = AtomicUsize::new(0);
static PROCESS_PID: AtomicI32 = AtomicI32::new(0);
const RESERVED: *const c_void = ptr::dangling::<c_void>();

#[derive(Clone, Copy)]
struct TrampolineFrame {
    hub_id: usize,
    return_addr: usize,
    caller_sp: usize,
    return_target: usize,
    chain: usize,
}

struct TrampolineState {
    frames: FixedStack<TrampolineFrame, HUB_STACK_CAP>,
    owner_pid: libc::pid_t,
}

fn keys() -> Option<(libc::pthread_key_t, libc::pthread_key_t)> {
    let word = KEYS.load(Ordering::Acquire);
    if word == 0 {
        return None;
    }
    Some((
        ((word >> 32) as u32 - 1) as libc::pthread_key_t,
        (word as u32 - 1) as libc::pthread_key_t,
    ))
}

pub(super) fn init_keys() -> bool {
    if keys().is_some() {
        return true;
    }
    let mut state_key = 0;
    let mut reserved_key = 0;
    if unsafe { libc::pthread_key_create(&mut state_key, Some(destroy_state)) } != 0 {
        return false;
    }
    if unsafe { libc::pthread_key_create(&mut reserved_key, None) } != 0 {
        unsafe { libc::pthread_key_delete(state_key) };
        return false;
    }
    let word = (u64::from(state_key as u32 + 1) << 32) | u64::from(reserved_key as u32 + 1);
    if KEYS
        .compare_exchange(0, word, Ordering::Release, Ordering::Relaxed)
        .is_err()
    {
        unsafe {
            libc::pthread_key_delete(state_key);
            libc::pthread_key_delete(reserved_key);
        }
    }
    true
}

fn release_frame(frame: TrampolineFrame) {
    hub::release_chain(frame.chain);
    ACTIVE_COUNT.fetch_sub(1, Ordering::SeqCst);
}

unsafe extern "C" fn destroy_state(raw: *mut c_void) {
    if raw.is_null() {
        return;
    }
    if let Some((_, reserved_key)) = keys() {
        libc::pthread_setspecific(reserved_key, RESERVED);
    }
    let mut state = Box::from_raw(raw as *mut TrampolineState);
    while let Some(frame) = state.frames.pop() {
        release_frame(frame);
    }
}

fn existing_state() -> *mut TrampolineState {
    let Some((state_key, _)) = keys() else {
        return ptr::null_mut();
    };
    unsafe { libc::pthread_getspecific(state_key) as *mut TrampolineState }
}

fn state_or_init() -> Option<&'static mut TrampolineState> {
    if !init_keys() {
        return None;
    }
    let (state_key, reserved_key) = keys()?;
    if !unsafe { libc::pthread_getspecific(reserved_key) }.is_null() {
        return None;
    }
    let mut raw = unsafe { libc::pthread_getspecific(state_key) as *mut TrampolineState };
    if raw.is_null() {
        raw = Box::into_raw(Box::new(TrampolineState {
            frames: FixedStack::new(),
            owner_pid: unsafe { libc::getpid() },
        }));
        if unsafe { libc::pthread_setspecific(state_key, raw.cast()) } != 0 {
            unsafe { drop(Box::from_raw(raw)) };
            return None;
        }
    }
    Some(unsafe { &mut *raw })
}

pub(crate) fn trampoline_enter(
    hub_id: usize,
    return_addr: usize,
    caller_sp: usize,
    return_target: usize,
    chain: usize,
) -> bool {
    after_fork_child();
    let Some(state) = state_or_init() else {
        return false;
    };
    // 同 SP 的尾调用保留外层跳板的真实返回地址。
    while state
        .frames
        .last()
        .is_some_and(|frame| frame.caller_sp <= caller_sp && frame.return_target != return_addr)
    {
        if let Some(frame) = state.frames.pop() {
            release_frame(frame);
        }
    }
    if !state.frames.push(TrampolineFrame {
        hub_id,
        return_addr,
        caller_sp,
        return_target,
        chain,
    }) {
        return false;
    }
    ACTIVE_COUNT.fetch_add(1, Ordering::SeqCst);
    true
}

pub(crate) fn trampoline_leave(hub_id: usize, caller_sp: usize) -> usize {
    let raw = existing_state();
    if raw.is_null() {
        unsafe { libc::abort() };
    }
    let state = unsafe { &mut *raw };
    while let Some(frame) = state.frames.pop() {
        release_frame(frame);
        if (frame.hub_id, frame.caller_sp) == (hub_id, caller_sp) {
            return frame.return_addr;
        }
    }
    unsafe { libc::abort() }
}

pub(crate) fn has_trampoline_frame(hub_id: usize, return_addr: usize, caller_sp: usize) -> bool {
    let raw = existing_state();
    if raw.is_null() {
        return false;
    }
    unsafe { &*raw }
        .frames
        .rposition_by(|frame| {
            (frame.hub_id, frame.return_addr, frame.caller_sp) == (hub_id, return_addr, caller_sp)
        })
        .is_some()
}

pub(crate) fn current_active_trampoline_count() -> usize {
    let raw = existing_state();
    if raw.is_null() {
        0
    } else {
        unsafe { &*raw }.frames.len()
    }
}

pub(crate) fn has_active_trampolines() -> bool {
    current_active_trampoline_count() != 0
}

pub(crate) fn active_trampoline_count() -> usize {
    ACTIVE_COUNT.load(Ordering::SeqCst)
}

pub(crate) fn after_fork_child() {
    let pid = unsafe { libc::getpid() };
    if PROCESS_PID.load(Ordering::Acquire) == pid {
        return;
    }
    let raw = existing_state();
    if raw.is_null() {
        ACTIVE_COUNT.store(0, Ordering::SeqCst);
        PROCESS_PID.store(pid, Ordering::Release);
        return;
    }
    let state = unsafe { &mut *raw };
    if state.owner_pid == pid {
        ACTIVE_COUNT.store(state.frames.len(), Ordering::SeqCst);
        PROCESS_PID.store(pid, Ordering::Release);
        return;
    }
    state.owner_pid = pid;
    for index in 0..state.frames.len() {
        if let Some(frame) = state.frames.get(index) {
            hub::inherit_chain(frame.chain);
        }
    }
    ACTIVE_COUNT.store(state.frames.len(), Ordering::SeqCst);
    PROCESS_PID.store(pid, Ordering::Release);
}
