// 运行时核心状态定义，包含所有 hook 任务、slot、模块信息及全局同步原语
use super::fork::{ForkMutex, ForkMutexGuard};
use crate::api::{
    CallerAllowFilter, HookMode, HookStub, HookedCallback, PostDlopenCallback, PreDlopenCallback,
};
use crate::errno::Errno;
use once_cell::sync::Lazy;
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread::JoinHandle;

// 最近一次初始化或接管运行时的进程 PID。
static INSTALL_PID: AtomicI32 = AtomicI32::new(0);

// 初始化或子进程显式接管运行时时更新 PID。
pub(crate) fn set_install_pid(pid: i32) {
    INSTALL_PID.store(pid, Ordering::Release);
}

// 仅调用继承的 hook 不会接管运行时，也不会重启 monitor。
#[inline]
pub(crate) fn is_forked_child() -> bool {
    let install_pid = INSTALL_PID.load(Ordering::Acquire);
    if install_pid <= 0 {
        return false;
    }
    let current_pid = unsafe { libc::getpid() };
    current_pid != install_pid
}

// 统一全局可重置锁与局部标准 Mutex 的 guard 访问接口。
pub(crate) trait MutexPoisonRecover<T> {
    type Guard<'a>: std::ops::Deref<Target = T> + std::ops::DerefMut
    where
        T: 'a,
        Self: 'a;
    fn lock_or_poison(&self) -> Self::Guard<'_>;
}

impl<T> MutexPoisonRecover<T> for Mutex<T> {
    type Guard<'a>
        = std::sync::MutexGuard<'a, T>
    where
        T: 'a,
        Self: 'a;
    fn lock_or_poison(&self) -> Self::Guard<'_> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<T> MutexPoisonRecover<T> for ForkMutex<T> {
    type Guard<'a>
        = ForkMutexGuard<'a, T>
    where
        T: 'a,
        Self: 'a;
    fn lock_or_poison(&self) -> Self::Guard<'_> {
        self.lock()
    }
}

// hook 任务的作用域类型
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TaskType {
    Single,
    Partial,
    All,
}

// hook 成功后的用户回调入口
#[derive(Clone, Copy)]
pub(super) struct HookedEntry {
    pub(super) callback: HookedCallback,
    pub(super) arg: usize,
}

// caller 过滤器，用于 Partial 模式按调用方筛选
#[derive(Clone, Copy)]
pub(super) struct AllowFilterEntry {
    pub(super) filter: CallerAllowFilter,
    pub(super) arg: usize,
}

// dlopen/dlclose 事件的用户回调
#[derive(Clone, Copy)]
pub(super) struct DlopenCallbackEntry {
    pub(super) pre: Option<PreDlopenCallback>,
    pub(super) post: Option<PostDlopenCallback>,
    pub(super) arg: usize,
}

// 单个 hook 任务的完整描述
#[derive(Clone)]
pub(super) struct Task {
    pub(super) stub: HookStub,
    pub(super) task_type: TaskType,
    pub(super) caller_path_name: Option<String>,
    pub(super) caller_allow_filter: Option<AllowFilterEntry>,
    pub(super) callee_path_name: Option<String>,
    pub(super) sym_name: String,
    pub(super) new_func: usize,
    pub(super) hooked: Option<HookedEntry>,
}

// PLT slot 的唯一标识，由 caller 模块信息和 slot 地址组成
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct SlotKey {
    pub(super) caller_path_name: String,
    pub(super) caller_base_addr: usize,
    pub(super) caller_instance_id: usize,
    pub(super) caller_namespace_id: usize,
    pub(super) slot_addr: usize,
}

// PLT slot 的运行时状态，包含原始函数地址、任务链和 hub 指针
#[derive(Default, Clone)]
pub(super) struct SlotEntry {
    pub(super) orig_func: usize,
    pub(super) task_chain: Vec<HookStub>,
    pub(super) hub_ptr: usize,
}

// linker 中已加载模块的标识信息
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ModuleInfo {
    pub(super) pathname: String,
    pub(super) base_addr: usize,
    pub(super) instance_id: usize,
    pub(super) namespace_id: usize,
}

// hook/unhook 操作类型，用于审计记录
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecordOp {
    Hook,
    Unhook,
}

// 单条操作审计记录
#[derive(Clone, Debug)]
pub(super) struct RecordEntry {
    pub(super) op: RecordOp,
    pub(super) ts_ms: u64,
    pub(super) status_code: i32,
    pub(super) caller_lib_name: String,
    pub(super) lib_name: String,
    pub(super) sym_name: String,
    pub(super) new_addr: usize,
    pub(super) stub: HookStub,
}

// 初始化状态，记录当前 hook 模式和初始化结果
pub(super) struct InitInfo {
    pub(super) status: Errno,
    pub(super) mode: HookMode,
}

impl Default for InitInfo {
    fn default() -> Self {
        Self {
            status: Errno::Uninit,
            mode: HookMode::Automatic,
        }
    }
}

// 核心可变状态，由 GlobalState::state 互斥锁保护
#[derive(Default)]
pub(super) struct CoreState {
    pub(super) process_id: usize,
    // 自身模块加载基址，用于 memfd 匿名加载时按基址跳过 hook 自身
    pub(super) self_base_addr: usize,
    pub(super) init: InitInfo,
    pub(super) debug: bool,
    pub(super) next_stub: HookStub,
    // stub -> Task 映射，存储所有已注册的 hook 任务
    pub(super) tasks: BTreeMap<HookStub, Task>,
    pub(super) task_order: Vec<HookStub>,
    // stub -> 该任务已绑定的所有 slot
    pub(super) task_slots: BTreeMap<HookStub, BTreeSet<SlotKey>>,
    pub(super) slots: BTreeMap<SlotKey, SlotEntry>,
    pub(super) single_task_targets: BTreeMap<HookStub, String>,
    pub(super) ignore_callers: Vec<String>,
    pub(super) known_modules: BTreeSet<String>,
    pub(super) recordable: bool,
    pub(super) records: Vec<RecordEntry>,
    pub(super) dlopen_callbacks: Vec<DlopenCallbackEntry>,
    // 待处理的 dlopen handle 队列，用于异步刷新
    pub(super) pending_module_handles: VecDeque<usize>,
    pub(super) pending_module_handle_set: BTreeSet<usize>,
    pub(super) refresh_requested: bool,
    pub(super) clearing: bool,
    pub(super) monitor_running: bool,
    pub(super) monitor_thread: Option<JoinHandle<()>>,
}

// 全局同步容器：state 保护核心状态，refresh_mutex 串行化 refresh
// dlclose_lock 在 dlclose 期间阻止 slot 写入
pub(super) struct GlobalState {
    pub(super) state: ForkMutex<CoreState>,
    pub(super) refresh_mutex: ForkMutex<()>,
    pub(super) dlclose_lock: ForkMutex<()>,
}

pub(super) static GLOBAL: Lazy<GlobalState> = Lazy::new(|| GlobalState {
    state: ForkMutex::new(CoreState {
        next_stub: 1,
        ..CoreState::default()
    }),
    refresh_mutex: ForkMutex::new(()),
    dlclose_lock: ForkMutex::new(()),
});
