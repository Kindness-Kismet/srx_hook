// 运行时初始化入口，负责信号处理器安装、CFI 禁用、monitor 线程启动
use crate::android::signal_guard;
use crate::api::HookMode;
use crate::errno::Errno;
use crate::log;
use crate::version;

use super::super::state::GLOBAL;
use super::super::thread_state;
use super::monitor;
use crate::runtime::fork;
use crate::runtime::state::set_install_pid;
use std::sync::atomic::Ordering;

pub(super) fn get_version() -> String {
    version::version_str_full()
}

// 反查自身模块加载基址，用于按基址忽略自身
// 与路径无关，覆盖 memfd 匿名加载（如 neozygisk）场景
fn resolve_self_base_addr() -> usize {
    let _loader_call = fork::LoaderCall::enter();
    let probe = resolve_self_base_addr as *const std::ffi::c_void;
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(probe, &mut info) } == 0 {
        return 0;
    }
    info.dli_fbase as usize
}

pub(super) fn init(mode: HookMode, debug: bool) -> Errno {
    if let Err(error) = fork::check_management() {
        return error;
    }
    let runtime = &*GLOBAL;
    let source = runtime.snapshot();
    if source.clearing {
        return Errno::Busy;
    }
    if source.init.status == Errno::Ok {
        if source.init.mode == HookMode::Automatic {
            monitor::start_monitor_thread();
            monitor::install_auto_loader_monitor_hooks();
        }
        return Errno::Ok;
    }
    if runtime.initializing.swap(true, Ordering::AcqRel) {
        return Errno::Busy;
    }
    let status = initialize_runtime(runtime, mode, debug);
    runtime.initializing.store(false, Ordering::Release);
    if status == Errno::Ok && mode == HookMode::Automatic {
        monitor::start_monitor_thread();
        monitor::install_auto_loader_monitor_hooks();
    }
    status
}

fn initialize_runtime(
    runtime: &super::super::state::ProcessRuntime,
    mode: HookMode,
    debug: bool,
) -> Errno {
    if let Err(error) = fork::register_handlers() {
        return error;
    }
    if !thread_state::init_thread_state_key() || !thread_state::init_current_thread_state() {
        return Errno::InitErrSafe;
    }
    super::monitor_calls::prime_for_fork();
    signal_guard::prime_process_state();
    if let Err(error) = signal_guard::add_handler() {
        return error;
    }
    #[cfg(target_arch = "aarch64")]
    {
        let source = runtime.snapshot();
        let prepared = match super::super::refresh::prepare_cfi_init(&source) {
            Ok(prepared) => prepared,
            Err(error) => return error,
        };
        let result = super::transaction::commit(runtime, &source, prepared);
        if result.status != Errno::Ok {
            return result.status;
        }
    }
    let self_base_addr = resolve_self_base_addr();
    if !runtime.is_current() {
        return Errno::ForkContextUnavailable;
    }
    let status = runtime.update(|state| {
        state.debug = debug;
        state.init.mode = mode;
        state.init.status = Errno::Ok;
        state.self_base_addr = self_base_addr;
        Errno::Ok
    });
    if status == Errno::Ok {
        set_install_pid(runtime.pid);
        log::set_debug_enabled(debug);
        log::info(format_args!("{}", version::version_str_full()));
    }
    status
}
