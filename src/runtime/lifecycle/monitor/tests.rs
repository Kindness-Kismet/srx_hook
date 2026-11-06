use super::{monitor_task_installed, parse_periodic_env_value, start_monitor_thread};
use crate::api::HookMode;
use crate::errno::Errno;
use crate::runtime::state::{CoreState, GLOBAL, MutexPoisonRecover, Task, TaskType};

#[test]
fn parse_periodic_env_true_values() {
    assert_eq!(parse_periodic_env_value("1"), Some(true));
    assert_eq!(parse_periodic_env_value("true"), Some(true));
    assert_eq!(parse_periodic_env_value("YES"), Some(true));
    assert_eq!(parse_periodic_env_value(" on "), Some(true));
}

#[test]
fn parse_periodic_env_false_values() {
    assert_eq!(parse_periodic_env_value("0"), Some(false));
    assert_eq!(parse_periodic_env_value("false"), Some(false));
    assert_eq!(parse_periodic_env_value("No"), Some(false));
    assert_eq!(parse_periodic_env_value(" off "), Some(false));
}

#[test]
fn parse_periodic_env_invalid_value() {
    assert_eq!(parse_periodic_env_value("maybe"), None);
    assert_eq!(parse_periodic_env_value(""), None);
}

#[test]
fn clear_blocks_monitor_restart() {
    let (status, mode, clearing) = {
        let mut state = GLOBAL.state.lock_or_poison();
        assert!(!state.monitor_running);
        let original = (state.init.status, state.init.mode, state.clearing);
        state.init.status = Errno::Ok;
        state.init.mode = HookMode::Automatic;
        state.clearing = true;
        original
    };

    start_monitor_thread();

    let mut state = GLOBAL.state.lock_or_poison();
    assert!(!state.monitor_running);
    assert!(state.monitor_thread.is_none());
    state.init.status = status;
    state.init.mode = mode;
    state.clearing = clearing;
}

#[test]
fn monitor_install_skips_tasks_already_inherited_by_child() {
    let task = Task {
        stub: 1,
        task_type: TaskType::Single,
        caller_path_name: Some("libdl.so".to_string()),
        caller_allow_filter: None,
        callee_path_name: None,
        sym_name: "__loader_dlopen".to_string(),
        new_func: 0x1234,
        hooked: None,
    };
    let mut state = CoreState::default();
    state.tasks.insert(task.stub, task.clone());

    assert!(monitor_task_installed(&state, &task));
    let mut different_proxy = task.clone();
    different_proxy.new_func += 1;
    assert!(!monitor_task_installed(&state, &different_proxy));
}
