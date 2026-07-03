// 运行时初始化入口，负责信号处理器安装、CFI 禁用、monitor 线程启动
use crate::api::HookMode;
use crate::android::signal_guard;
use crate::errno::Errno;
use crate::log;
use crate::version;

use super::monitor;
use super::super::cfi;
use super::super::state::GLOBAL;
use super::super::thread_state;
use crate::runtime::state::{MutexPoisonRecover, set_install_pid};

pub(super) fn get_version() -> String {
    version::version_str_full()
}

// 反查自身模块加载基址，用于按基址忽略自身
// 与路径无关，覆盖 memfd 匿名加载（如 neozygisk）场景
fn resolve_self_base_addr() -> usize {
    let probe = resolve_self_base_addr as *const std::ffi::c_void;
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(probe, &mut info) } == 0 {
        return 0;
    }
    info.dli_fbase as usize
}

pub(super) fn init(mode: HookMode, debug: bool) -> Errno {
    let mut should_start_monitor = false;
    let status = {
        let mut state = GLOBAL.state.lock_or_poison();
        if state.init.status != Errno::Uninit {
            return state.init.status;
        }

        state.debug = debug;
        log::set_debug_enabled(debug);
        state.init.mode = mode;
        state.self_base_addr = resolve_self_base_addr();
        let pid = unsafe { libc::getpid() };
        state.process_id = pid as usize;
        set_install_pid(pid);
        if !thread_state::init_thread_state_key() {
            log::warn(format_args!(
                "线程状态 key 初始化失败，后续将退化到无栈路径"
            ));
        }
        if !thread_state::init_current_thread_state() {
            log::warn(format_args!("线程状态绑定失败，后续将退化到无栈路径"));
        }
        state.init.status = match signal_guard::add_handler() {
            Ok(()) => Errno::Ok,
            Err(_) => Errno::InitErrSig,
        };
        if state.init.status == Errno::Ok {
            state.init.status = cfi::disable_slowpath();
        }

        if state.init.status == Errno::Ok && mode == HookMode::Automatic {
            should_start_monitor = true;
        }

        state.init.status
    };

    if status != Errno::Ok {
        return status;
    }

    if should_start_monitor {
        monitor::start_monitor_thread();
        let state = GLOBAL.state.lock_or_poison();
        if state.init.status != Errno::Ok {
            return state.init.status;
        }
        drop(state);
        monitor::install_auto_loader_monitor_hooks();
    }

    log::info(format_args!("{}", version::version_str_full()));
    Errno::Ok
}
