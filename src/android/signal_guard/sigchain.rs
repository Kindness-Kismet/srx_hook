// ART sigchain API 的动态解析与调用
// 在 ART 环境中通过 sigchain 注册信号处理器，避免与 ART 的信号机制冲突

use std::ffi::{CStr, c_void};
use std::ptr;
use std::sync::OnceLock;

use super::slot;
use super::{
    AddSpecialSignalHandlerFn, EnsureFrontOfChainFn, RTLD_NEXT_FALLBACK,
    RemoveSpecialSignalHandlerFn, SIGCHAIN_ALLOW_NORETURN, SIGCHAIN_LIB_CANDIDATES, SigchainAction,
    SigchainApiFns, SigchainCallbackFn,
};

// 延迟解析并缓存 sigchain API 函数指针
fn sigchain_api_fns() -> Option<&'static SigchainApiFns> {
    static SIGCHAIN_API_FNS: OnceLock<Option<SigchainApiFns>> = OnceLock::new();
    SIGCHAIN_API_FNS
        .get_or_init(resolve_sigchain_api_fns)
        .as_ref()
}

// 解析 sigchain API：需要 add 和 remove 两个必选符号，ensure_front 可选
fn resolve_sigchain_api_fns() -> Option<SigchainApiFns> {
    let add_symbol = resolve_sigchain_symbol_candidates(&[
        c"AddSpecialSignalHandlerFn",
        c"AddSpecialSignalHandler",
    ]);
    let remove_symbol = resolve_sigchain_symbol_candidates(&[
        c"RemoveSpecialSignalHandlerFn",
        c"RemoveSpecialSignalHandler",
    ]);
    if add_symbol.is_null() || remove_symbol.is_null() {
        return None;
    }

    let ensure_symbol =
        resolve_sigchain_symbol_candidates(&[c"EnsureFrontOfChain", c"EnsureFrontOfSignalChain"]);
    Some(SigchainApiFns {
        add_special_handler_fn: unsafe {
            std::mem::transmute::<*mut c_void, AddSpecialSignalHandlerFn>(add_symbol)
        },
        remove_special_handler_fn: unsafe {
            std::mem::transmute::<*mut c_void, RemoveSpecialSignalHandlerFn>(remove_symbol)
        },
        ensure_front_of_chain_fn: if ensure_symbol.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut c_void, EnsureFrontOfChainFn>(ensure_symbol) })
        },
    })
}

fn resolve_sigchain_symbol_candidates(candidates: &[&CStr]) -> *mut c_void {
    for symbol in candidates {
        let ptr = resolve_sigchain_symbol(symbol);
        if !ptr.is_null() {
            return ptr;
        }
    }
    ptr::null_mut()
}

// 多策略符号解析：RTLD_DEFAULT -> RTLD_NEXT -> 候选库 NOLOAD -> 候选库 NOW
fn resolve_sigchain_symbol(symbol: &CStr) -> *mut c_void {
    unsafe {
        let default_symbol = libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr());
        if !default_symbol.is_null() {
            return default_symbol;
        }

        let next_symbol = libc::dlsym(RTLD_NEXT_FALLBACK, symbol.as_ptr());
        if !next_symbol.is_null() {
            return next_symbol;
        }
    }

    for lib_name in SIGCHAIN_LIB_CANDIDATES {
        let noload_symbol =
            resolve_symbol_from_library(lib_name, symbol, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        if !noload_symbol.is_null() {
            return noload_symbol;
        }

        let now_symbol = resolve_symbol_from_library(lib_name, symbol, libc::RTLD_NOW);
        if !now_symbol.is_null() {
            return now_symbol;
        }
    }

    ptr::null_mut()
}

fn resolve_symbol_from_library(lib_name: &CStr, symbol: &CStr, flags: libc::c_int) -> *mut c_void {
    let handle = unsafe { libc::dlopen(lib_name.as_ptr(), flags) };
    if handle.is_null() {
        return ptr::null_mut();
    }
    let ptr = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    unsafe {
        libc::dlclose(handle);
    }
    ptr
}

fn make_sigchain_action(callback: SigchainCallbackFn) -> SigchainAction {
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigfillset(&mut mask);
    }
    SigchainAction {
        sc_sigaction: callback,
        sc_mask: mask,
        sc_flags: SIGCHAIN_ALLOW_NORETURN,
    }
}

// 注册单个信号的 sigchain handler，注册后尝试提升到链首
fn add_sigchain_handler(signum: libc::c_int, callback: SigchainCallbackFn) -> bool {
    let Some(fns) = sigchain_api_fns() else {
        return false;
    };
    let mut action = make_sigchain_action(callback);
    unsafe {
        (fns.add_special_handler_fn)(signum, ptr::addr_of_mut!(action));
        if let Some(ensure_front) = fns.ensure_front_of_chain_fn {
            ensure_front(signum);
        }
    }
    true
}

// 同时注册 SIGSEGV 和 SIGBUS 的 sigchain handler
// SIGBUS 注册失败时回滚 SIGSEGV 的注册
pub(super) fn install_sigchain_handlers() -> bool {
    if !add_sigchain_handler(libc::SIGSEGV, slot::sigsegv_sigchain_callback()) {
        return false;
    }
    if !add_sigchain_handler(libc::SIGBUS, slot::sigbus_sigchain_callback()) {
        let _ = remove_sigchain_handlers();
        return false;
    }
    true
}

pub(super) fn remove_sigchain_handlers() -> bool {
    let Some(fns) = sigchain_api_fns() else {
        return false;
    };
    unsafe {
        (fns.remove_special_handler_fn)(libc::SIGSEGV, slot::sigsegv_sigchain_callback());
        (fns.remove_special_handler_fn)(libc::SIGBUS, slot::sigbus_sigchain_callback());
    }
    true
}
