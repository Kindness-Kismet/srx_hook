// dlopen/dlclose 监控模块，自动检测动态库加载卸载并触发 hook 刷新
// 支持 loader hook (API >= 26) 和 legacy hook 两种策略，可自动降级
use crate::errno::Errno;
use crate::log;
use std::env;
use std::ffi::c_void;
use std::ffi::{CStr, c_char};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use super::super::refresh;
use super::super::state::GLOBAL;
use super::super::state::{Task, TaskType};
use crate::runtime::state::MutexPoisonRecover;
mod poll;
mod proxies;

// 原子标志：monitor hook 是否已安装
static AUTO_MONITOR_INSTALLED: AtomicBool = AtomicBool::new(false);
// 是否启用周期性轮询刷新
static MONITOR_PERIODIC_ENABLED: AtomicBool = AtomicBool::new(true);
// 是否因 loader 调用失败而升级到周期性轮询
static MONITOR_PERIODIC_ESCALATED: AtomicBool = AtomicBool::new(false);
// loader 调用连续成功计数，用于判断是否可以降级回纯事件模式
static MONITOR_LOADER_SUCCESS_STREAK: AtomicUsize = AtomicUsize::new(0);
// legacy hook 是否已安装
static MONITOR_LEGACY_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
// 是否有待处理的 legacy hook 安装请求
static MONITOR_LEGACY_HOOK_REQUESTED: AtomicBool = AtomicBool::new(false);
const RTLD_NEXT_FALLBACK: *mut c_void = (-1isize) as *mut c_void;
const ANDROID_API_LEVEL_N: i32 = 24;
const ANDROID_API_LEVEL_N_MR1: i32 = 25;
const ANDROID_API_LEVEL_LOADER: i32 = 26;
const SYSTEM_PROP_VALUE_MAX: usize = 92;
const MONITOR_FALLBACK_REFRESH_INTERVAL_MIN: Duration = Duration::from_millis(500);
const MONITOR_FALLBACK_REFRESH_INTERVAL_MAX: Duration = Duration::from_secs(8);
const MONITOR_FALLBACK_BURST_ROUNDS: u8 = 3;
const LIBDL_BASENAME: &str = "libdl.so";
const MONITOR_PERIODIC_ENV: &str = "SRX_HOOK_MONITOR_PERIODIC";
const LOADER_STABLE_SUCCESS_THRESHOLD: usize = 64;

// 周期性轮询策略，可通过环境变量 SRX_HOOK_MONITOR_PERIODIC 强制开关
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeriodicPolicy {
    Auto,
    Force(bool),
}

unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> libc::c_int;
}

pub(super) fn reset_auto_monitor_installed() {
    AUTO_MONITOR_INSTALLED.store(false, Ordering::SeqCst);
    MONITOR_PERIODIC_ESCALATED.store(false, Ordering::SeqCst);
    MONITOR_LOADER_SUCCESS_STREAK.store(0, Ordering::SeqCst);
    MONITOR_LEGACY_HOOK_INSTALLED.store(false, Ordering::SeqCst);
    MONITOR_LEGACY_HOOK_REQUESTED.store(false, Ordering::SeqCst);
    MONITOR_PERIODIC_ENABLED.store(should_enable_periodic_fallback(false), Ordering::SeqCst);
}

pub(super) fn install_auto_loader_monitor_hooks() {
    if AUTO_MONITOR_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    let use_loader_hooks = should_use_loader_hooks();
    MONITOR_PERIODIC_ENABLED.store(
        should_enable_periodic_fallback(use_loader_hooks),
        Ordering::SeqCst,
    );
    MONITOR_LEGACY_HOOK_INSTALLED.store(false, Ordering::SeqCst);
    MONITOR_LEGACY_HOOK_REQUESTED.store(false, Ordering::SeqCst);
    if use_loader_hooks {
        install_loader_hooks_for_libdl();
        return;
    }

    install_legacy_hooks_for_all_modules();
}

// loader 调用回退时触发：重置成功计数、请求安装 legacy hook、升级到周期性轮询
pub(super) fn note_loader_call_fallback(reason: &str) {
    if !AUTO_MONITOR_INSTALLED.load(Ordering::Acquire) {
        return;
    }
    if !matches!(periodic_policy_from_env(), PeriodicPolicy::Auto) {
        return;
    }
    MONITOR_LOADER_SUCCESS_STREAK.store(0, Ordering::SeqCst);
    request_legacy_hooks_install(reason);
    if MONITOR_PERIODIC_ENABLED.load(Ordering::Acquire) {
        return;
    }
    MONITOR_PERIODIC_ENABLED.store(true, Ordering::SeqCst);
    let first_escalation = !MONITOR_PERIODIC_ESCALATED.swap(true, Ordering::SeqCst);
    if first_escalation {
        log::warn(format_args!(
            "enable periodic monitor fallback due to loader fallback reason={}",
            reason
        ));
    } else {
        log::debug(format_args!(
            "periodic monitor fallback already enabled reason={}",
            reason
        ));
    }
}

// loader 调用成功时累计计数，达到阈值后降级回纯事件模式
pub(super) fn note_loader_call_success() {
    if !AUTO_MONITOR_INSTALLED.load(Ordering::Acquire) {
        return;
    }
    if !matches!(periodic_policy_from_env(), PeriodicPolicy::Auto) {
        return;
    }
    if !MONITOR_PERIODIC_ESCALATED.load(Ordering::Acquire) {
        return;
    }

    let streak = MONITOR_LOADER_SUCCESS_STREAK
        .fetch_add(1, Ordering::AcqRel)
        .saturating_add(1);
    if streak < LOADER_STABLE_SUCCESS_THRESHOLD {
        return;
    }

    MONITOR_LOADER_SUCCESS_STREAK.store(0, Ordering::SeqCst);
    MONITOR_PERIODIC_ESCALATED.store(false, Ordering::SeqCst);
    MONITOR_PERIODIC_ENABLED.store(false, Ordering::SeqCst);
    log::info(format_args!(
        "disable periodic monitor fallback after loader stabilized"
    ));
}

pub(super) fn maybe_install_legacy_hooks_on_demand() {
    if !MONITOR_LEGACY_HOOK_REQUESTED.swap(false, Ordering::SeqCst) {
        return;
    }
    install_legacy_hooks_for_all_modules();
}

fn request_legacy_hooks_install(reason: &str) {
    if MONITOR_LEGACY_HOOK_INSTALLED.load(Ordering::Acquire) {
        return;
    }
    let first_request = !MONITOR_LEGACY_HOOK_REQUESTED.swap(true, Ordering::SeqCst);
    if first_request {
        log::warn(format_args!(
            "request legacy monitor hooks install due to loader fallback reason={}",
            reason
        ));
    }
}

fn should_enable_periodic_fallback(use_loader_hooks: bool) -> bool {
    match periodic_policy_from_env() {
        PeriodicPolicy::Auto => !use_loader_hooks,
        PeriodicPolicy::Force(enabled) => enabled,
    }
}

fn periodic_policy_from_env() -> PeriodicPolicy {
    let Ok(value) = env::var(MONITOR_PERIODIC_ENV) else {
        return PeriodicPolicy::Auto;
    };
    match parse_periodic_env_value(&value) {
        Some(enabled) => PeriodicPolicy::Force(enabled),
        None => PeriodicPolicy::Auto,
    }
}

fn parse_periodic_env_value(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

// legacy 模式：对所有模块 hook dlopen/android_dlopen_ext/dlclose
fn install_legacy_hooks_for_all_modules() {
    if MONITOR_LEGACY_HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    let legacy_hooks = [
        ("dlopen", proxies::monitor_dlopen as *mut c_void),
        (
            "android_dlopen_ext",
            proxies::monitor_android_dlopen_ext as *mut c_void,
        ),
        ("dlclose", proxies::monitor_dlclose as *mut c_void),
    ];

    for &(symbol, proxy) in &legacy_hooks {
        let task = Task {
            stub: 0,
            task_type: TaskType::All,
            caller_path_name: None,
            caller_allow_filter: None,
            callee_path_name: None,
            sym_name: symbol.to_string(),
            new_func: proxy as usize,
            hooked: None,
        };
        let _ = super::add_task(task);
    }

    log::info(format_args!("legacy monitor hooks installed"));
}

// loader 模式：仅 hook libdl.so 中的 __loader_dlopen 等符号 (API >= 26)
fn install_loader_hooks_for_libdl() {
    let loader_hooks = [
        (
            "__loader_dlopen",
            proxies::monitor_loader_dlopen as *mut c_void,
        ),
        (
            "__loader_android_dlopen_ext",
            proxies::monitor_loader_android_dlopen_ext as *mut c_void,
        ),
        (
            "__loader_dlclose",
            proxies::monitor_loader_dlclose as *mut c_void,
        ),
    ];

    for &(symbol, proxy) in &loader_hooks {
        let task = Task {
            stub: 0,
            task_type: TaskType::Single,
            caller_path_name: Some(LIBDL_BASENAME.to_string()),
            caller_allow_filter: None,
            callee_path_name: None,
            sym_name: symbol.to_string(),
            new_func: proxy as usize,
            hooked: None,
        };
        let _ = super::add_task(task);
    }
}

fn should_use_loader_hooks() -> bool {
    let api_level = android_api_level();
    if api_level < ANDROID_API_LEVEL_LOADER {
        return false;
    }

    let loader_symbols = [
        c"__loader_dlopen",
        c"__loader_android_dlopen_ext",
        c"__loader_dlclose",
    ];

    loader_symbols
        .iter()
        .all(|name| !unsafe { libc::dlsym(RTLD_NEXT_FALLBACK, name.as_ptr()) }.is_null())
}

fn android_api_level() -> i32 {
    let prop_name = c"ro.build.version.sdk";
    let mut prop_value = [0 as c_char; SYSTEM_PROP_VALUE_MAX];
    let len = unsafe { __system_property_get(prop_name.as_ptr(), prop_value.as_mut_ptr()) };
    if len <= 0 {
        return 0;
    }

    let len = len as usize;
    if len >= SYSTEM_PROP_VALUE_MAX {
        return 0;
    }

    let value = unsafe { CStr::from_ptr(prop_value.as_ptr()) };
    value
        .to_str()
        .ok()
        .and_then(|text| text.parse::<i32>().ok())
        .unwrap_or(0)
}

pub(super) fn start_monitor_thread() {
    let mut state = GLOBAL.state.lock_or_poison();
    if state.monitor_running {
        return;
    }
    state.monitor_running = true;

    let builder = thread::Builder::new().name("srx_hook_monitor".to_string());
    let handle = builder.spawn(poll::monitor_loop);
    match handle {
        Ok(thread) => state.monitor_thread = Some(thread),
        Err(_) => {
            state.monitor_running = false;
            state.init.status = Errno::InitErrDlMtr;
        }
    }
}

#[cfg(test)]
mod tests;
