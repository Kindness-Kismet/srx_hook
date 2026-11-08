// 批量任务共享一次状态发布；用户过滤器和回调仍在发布临界区外执行。
use super::{invoke_callbacks, monitor, transaction};
use crate::api::{HookBatchError, HookCaller, HookMode, HookRequest, HookStub};
use crate::errno::Errno;
use crate::runtime::fork;
use crate::runtime::record;
use crate::runtime::refresh;
use crate::runtime::state::{
    AllowFilterEntry, CoreState, GLOBAL, HookedEntry, ProcessRuntime, Task, TaskType,
};
use std::sync::atomic::Ordering;

pub(super) fn register(requests: &[HookRequest<'_>]) -> Result<Vec<HookStub>, HookBatchError> {
    fork::check_management()?;
    let mut tasks = requests
        .iter()
        .map(make_task)
        .collect::<Result<Vec<_>, _>>()?;
    let runtime = &*GLOBAL;
    let source = runtime.snapshot();
    check_state(&source)?;
    if tasks.is_empty() {
        return Ok(Vec::new());
    }
    let stubs = allocate_stubs(runtime, &mut tasks)?;
    if source.init.mode == HookMode::Manual {
        enqueue_manual(runtime, &tasks)?;
        return Ok(stubs);
    }
    let result = transaction::run(runtime, false, |state| {
        if state.init.mode != HookMode::Automatic {
            return Err(Errno::Busy);
        }
        let mut draft = state.clone();
        enqueue(
            &mut draft,
            &tasks,
            runtime.next_stub.load(Ordering::Acquire),
        );
        let mut prepared = refresh::prepare_refresh(&draft, false, None)?;
        add_records(&mut prepared.draft, &tasks);
        Ok(prepared)
    });
    if !result.committed {
        return Err(HookBatchError {
            status: result.status,
            stubs: Vec::new(),
            errors: result.errors,
        });
    }
    monitor::start_monitor_thread();
    monitor::install_auto_loader_monitor_hooks();
    invoke_callbacks(result.events);
    if result.status != Errno::Ok && result.status != Errno::NoSym {
        return Err(HookBatchError {
            status: result.status,
            stubs,
            errors: result.errors,
        });
    }
    Ok(stubs)
}

fn allocate_stubs(runtime: &ProcessRuntime, tasks: &mut [Task]) -> Result<Vec<HookStub>, Errno> {
    let count = u64::try_from(tasks.len()).map_err(|_| Errno::InvalidArg)?;
    let first = runtime
        .next_stub
        .try_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            next.checked_add(count)
        })
        .map_err(|_| Errno::InvalidArg)?;
    let stubs: Vec<_> = (first..first + count).collect();
    for (task, stub) in tasks.iter_mut().zip(&stubs) {
        task.stub = *stub;
    }
    Ok(stubs)
}

fn enqueue_manual(runtime: &ProcessRuntime, tasks: &[Task]) -> Result<(), Errno> {
    let status = runtime.update(|state| {
        if let Err(status) = check_state(state) {
            return status;
        }
        if state.init.mode != HookMode::Manual {
            return Errno::Busy;
        }
        enqueue(state, tasks, runtime.next_stub.load(Ordering::Acquire));
        add_records(state, tasks);
        Errno::Ok
    });
    if status == Errno::Ok {
        Ok(())
    } else {
        Err(status)
    }
}

fn check_state(state: &CoreState) -> Result<(), Errno> {
    if state.clearing {
        return Err(Errno::Busy);
    }
    if state.init.status != Errno::Ok {
        return Err(state.init.status);
    }
    Ok(())
}

fn make_task(request: &HookRequest<'_>) -> Result<Task, Errno> {
    if request.sym_name.is_empty() || request.new_func.is_null() {
        return Err(Errno::InvalidArg);
    }
    let (task_type, caller_path_name, caller_allow_filter) = match request.caller {
        HookCaller::All => (TaskType::All, None, None),
        HookCaller::Single(path) => {
            if path.is_empty() {
                return Err(Errno::InvalidArg);
            }
            (TaskType::Single, Some(path.to_string()), None)
        }
        HookCaller::Partial { filter, arg } => (
            TaskType::Partial,
            None,
            Some(AllowFilterEntry {
                filter,
                arg: arg as usize,
            }),
        ),
    };
    Ok(Task {
        stub: 0,
        task_type,
        caller_path_name,
        caller_allow_filter,
        callee_path_name: request.callee_path_name.map(ToString::to_string),
        sym_name: request.sym_name.to_string(),
        new_func: request.new_func as usize,
        hooked: request.hooked.map(|callback| HookedEntry {
            callback,
            arg: request.hooked_arg as usize,
        }),
    })
}

fn enqueue(state: &mut CoreState, tasks: &[Task], next_stub: u64) {
    state.next_stub = next_stub;
    for task in tasks {
        state.task_order.push(task.stub);
        state.tasks.insert(task.stub, task.clone());
    }
}

fn add_records(state: &mut CoreState, tasks: &[Task]) {
    for task in tasks {
        let name = match task.task_type {
            TaskType::Single => task.caller_path_name.as_deref().unwrap_or("unknown"),
            TaskType::Partial => "PARTIAL",
            TaskType::All => "ALL",
        };
        // 批量应用的汇总状态不代表单项结果，具体结果通过回调与错误报告提供。
        let record_status = if state.init.mode == HookMode::Manual {
            Errno::Ok
        } else {
            Errno::Max
        };
        record::add_hook_record(
            state,
            record_status.as_i32(),
            name,
            &task.sym_name,
            task.new_func,
            task.stub,
        );
    }
}
