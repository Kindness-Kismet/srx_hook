// dlopen/dlclose 监控模块，自动检测动态库加载卸载并触发 hook 刷新
// 支持 loader hook (API >= 26) 和 legacy hook 两种策略，可自动降级
use crate::api::HookMode;
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
use crate::runtime::fork;
use crate::runtime::state::ProcessRuntime;
use crate::runtime::state::{MutexPoisonRecover, PidLocal};
mod poll;
mod proxies;

struct MonitorFlags {
    installed: AtomicBool,
    installing: AtomicUsize,
    periodic_enabled: AtomicBool,
    periodic_escalated: AtomicBool,
    success_streak: AtomicUsize,
    legacy_installed: AtomicBool,
    legacy_requested: AtomicBool,
    policy: AtomicUsize,
    epoch: AtomicUsize,
}

impl MonitorFlags {
    fn new() -> Self {
        Self {
            installed: AtomicBool::new(false),
            installing: AtomicUsize::new(0),
            periodic_enabled: AtomicBool::new(true),
            periodic_escalated: AtomicBool::new(false),
            success_streak: AtomicUsize::new(0),
            legacy_installed: AtomicBool::new(false),
            legacy_requested: AtomicBool::new(false),
            policy: AtomicUsize::new(0),
            epoch: AtomicUsize::new(1),
        }
    }
}

static MONITOR_FLAGS: PidLocal<MonitorFlags> = PidLocal::new(MonitorFlags::new);

fn flags() -> &'static MonitorFlags {
    MONITOR_FLAGS.get()
}

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
    flags().epoch.fetch_add(1, Ordering::AcqRel);
    flags().installing.store(0, Ordering::Release);
    flags().installed.store(false, Ordering::SeqCst);
    flags().periodic_escalated.store(false, Ordering::SeqCst);
    flags().success_streak.store(0, Ordering::SeqCst);
    flags().legacy_installed.store(false, Ordering::SeqCst);
    flags().legacy_requested.store(false, Ordering::SeqCst);
    flags().periodic_enabled.store(true, Ordering::SeqCst);
}

pub(super) fn install_auto_loader_monitor_hooks() {
    if flags().installed.load(Ordering::Acquire) {
        return;
    }
    let Some(installation) = reserve_installation() else {
        return;
    };
    let use_loader_hooks = should_use_loader_hooks();
    let policy = match periodic_policy_from_env() {
        PeriodicPolicy::Auto => 0,
        PeriodicPolicy::Force(false) => 1,
        PeriodicPolicy::Force(true) => 2,
    };
    let periodic_enabled = should_enable_periodic_fallback(use_loader_hooks);
    if !installation.update_flags(|flags| {
        flags.policy.store(policy, Ordering::Release);
        flags
            .periodic_enabled
            .store(periodic_enabled, Ordering::Release);
    }) {
        return;
    }
    let complete = if use_loader_hooks {
        install_loader_hooks_for_libdl(&installation)
    } else {
        install_legacy_hooks_for_all_modules(&installation)
    };
    installation.update_flags(|flags| {
        flags.installed.store(complete, Ordering::Release);
        if !use_loader_hooks {
            flags.legacy_installed.store(complete, Ordering::Release);
        }
    });
}

pub(super) struct Installation {
    pid: libc::pid_t,
    epoch: usize,
    runtime: &'static ProcessRuntime,
    flags: &'static MonitorFlags,
}

impl Installation {
    pub(super) fn is_current(&self) -> bool {
        self.runtime.is_current() && self.flags.epoch.load(Ordering::Acquire) == self.epoch
    }

    // 同代 flags 与 clear 的状态版本串行发布，闭包只更新原子字段。
    fn update_flags(&self, update: impl FnOnce(&MonitorFlags)) -> bool {
        let source = self.runtime.snapshot();
        if source.clearing
            || source.init.status != Errno::Ok
            || source.init.mode != HookMode::Automatic
        {
            return false;
        }
        let Some(_guard) = fork::try_publish() else {
            return false;
        };
        if !self.is_current() || !self.runtime.revision_matches(source.revision) {
            return false;
        }
        update(self.flags);
        true
    }
}

impl Drop for Installation {
    fn drop(&mut self) {
        if self.pid == unsafe { libc::getpid() } {
            let _ = self.flags.installing.compare_exchange(
                self.epoch,
                0,
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }
}

fn reserve_installation() -> Option<Installation> {
    fork::check_management().ok()?;
    let runtime = &*GLOBAL;
    let source = runtime.snapshot();
    if source.clearing || source.init.status != Errno::Ok || source.init.mode != HookMode::Automatic
    {
        return None;
    }
    let flags = flags();
    let epoch = flags.epoch.load(Ordering::Acquire);
    flags
        .installing
        .compare_exchange(0, epoch, Ordering::AcqRel, Ordering::Acquire)
        .ok()?;
    Some(Installation {
        pid: unsafe { libc::getpid() },
        epoch,
        runtime,
        flags,
    })
}

// loader 调用回退时触发：重置成功计数、请求安装 legacy hook、升级到周期性轮询
pub(super) fn note_loader_call_fallback(reason: &str) {
    if !flags().installed.load(Ordering::Acquire) {
        return;
    }
    if flags().policy.load(Ordering::Acquire) != 0 {
        return;
    }
    flags().success_streak.store(0, Ordering::SeqCst);
    request_legacy_hooks_install(reason);
    if flags().periodic_enabled.load(Ordering::Acquire) {
        return;
    }
    flags().periodic_enabled.store(true, Ordering::SeqCst);
    let first_escalation = !flags().periodic_escalated.swap(true, Ordering::SeqCst);
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
    if !flags().installed.load(Ordering::Acquire) {
        return;
    }
    if flags().policy.load(Ordering::Acquire) != 0 {
        return;
    }
    if !flags().periodic_escalated.load(Ordering::Acquire) {
        return;
    }

    let streak = flags()
        .success_streak
        .fetch_add(1, Ordering::AcqRel)
        .saturating_add(1);
    if streak < LOADER_STABLE_SUCCESS_THRESHOLD {
        return;
    }

    flags().success_streak.store(0, Ordering::SeqCst);
    flags().periodic_escalated.store(false, Ordering::SeqCst);
    flags().periodic_enabled.store(false, Ordering::SeqCst);
    log::info(format_args!(
        "disable periodic monitor fallback after loader stabilized"
    ));
}

pub(super) fn maybe_install_legacy_hooks_on_demand() {
    if !flags().legacy_requested.load(Ordering::Acquire) {
        return;
    }
    let Some(installation) = reserve_installation() else {
        return;
    };
    let complete = install_legacy_hooks_for_all_modules(&installation);
    installation.update_flags(|flags| {
        flags.legacy_requested.store(!complete, Ordering::Release);
        flags.legacy_installed.store(complete, Ordering::Release);
    });
}

fn request_legacy_hooks_install(reason: &str) {
    if flags().legacy_installed.load(Ordering::Acquire) {
        return;
    }
    let first_request = !flags().legacy_requested.swap(true, Ordering::SeqCst);
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
fn install_legacy_hooks_for_all_modules(installation: &Installation) -> bool {
    if flags().legacy_installed.load(Ordering::Acquire) {
        return true;
    }
    let legacy_hooks = [
        ("dlopen", proxies::monitor_dlopen as *mut c_void),
        (
            "android_dlopen_ext",
            proxies::monitor_android_dlopen_ext as *mut c_void,
        ),
        ("dlclose", proxies::monitor_dlclose as *mut c_void),
    ];

    let mut complete = true;
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
        complete &= ensure_monitor_task(task, installation);
    }
    complete
}

// loader 模式：仅 hook libdl.so 中的 __loader_dlopen 等符号 (API >= 26)
fn install_loader_hooks_for_libdl(installation: &Installation) -> bool {
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

    let mut complete = true;
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
        complete &= ensure_monitor_task(task, installation);
    }
    complete
}

fn ensure_monitor_task(task: Task, installation: &Installation) -> bool {
    if !installation.is_current() {
        return false;
    }
    if GLOBAL.snapshot().tasks.values().any(|existing| {
        existing.new_func == task.new_func
            && existing.sym_name == task.sym_name
            && existing.caller_path_name == task.caller_path_name
    }) {
        return true;
    }
    super::task_ops::add_monitor_task(task, installation).is_some()
}

fn should_use_loader_hooks() -> bool {
    let _loader_call = crate::runtime::LoaderCall::enter();
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
    if fork::check_management().is_err() {
        return;
    }
    let runtime = &*GLOBAL;
    let source = runtime.snapshot();
    if source.clearing || source.init.status != Errno::Ok || source.init.mode != HookMode::Automatic
    {
        return;
    }
    let epoch = flags().epoch.load(Ordering::Acquire);
    {
        let Some(_guard) = fork::try_publish() else {
            return;
        };
        if !runtime.revision_matches(source.revision)
            || flags().epoch.load(Ordering::Acquire) != epoch
        {
            return;
        }
        if runtime
            .monitor_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
    }
    let builder = thread::Builder::new().name("srx_hook_monitor".to_string());
    match builder.spawn(move || poll::monitor_loop(runtime, epoch)) {
        Ok(handle) => {
            let mut owner = runtime.monitor_thread.lock_or_poison();
            if runtime.is_current()
                && flags().epoch.load(Ordering::Acquire) == epoch
                && runtime.monitor_running.load(Ordering::Acquire)
            {
                *owner = Some(handle);
            }
        }
        Err(error) => {
            if runtime.is_current() && flags().epoch.load(Ordering::Acquire) == epoch {
                runtime.monitor_running.store(false, Ordering::Release);
                let _ = runtime.update(|state| {
                    state.init.status = Errno::InitErrDlMtr;
                    Errno::Ok
                });
            }
            log::warn(format_args!("monitor thread spawn failed: {error}"));
        }
    }
}

#[cfg(test)]
mod tests;
