// 运行时核心状态定义，包含所有 hook 任务、slot、模块信息及全局同步原语
use crate::api::{
    CallerAllowFilter, HookMode, HookStub, HookedCallback, PostDlopenCallback, PreDlopenCallback,
};
use crate::errno::Errno;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard};

mod process_local;
mod published;

pub(crate) use process_local::PidLocal;
pub(super) use published::{GLOBAL, ProcessRuntime};

// 无锁的安装时 PID，用于检测 fork 子进程
// fork 后子进程的 PID 与此值不同，可快速判断是否在 fork 子进程中
static INSTALL_PID: AtomicI32 = AtomicI32::new(0);

// 记录安装时的 PID（初始化时调用）
pub(crate) fn set_install_pid(pid: i32) {
    INSTALL_PID.store(pid, Ordering::Release);
}

// 无锁检测是否在 fork 子进程中
// 返回 true 表示当前进程是 fork 出来的子进程
#[inline]
pub(crate) fn is_forked_child() -> bool {
    let install_pid = INSTALL_PID.load(Ordering::Acquire);
    if install_pid <= 0 {
        return false;
    }
    let current_pid = unsafe { libc::getpid() };
    current_pid != install_pid
}

// 局部缓存锁保留 panic 后可读取的已构造状态。
pub(crate) trait MutexPoisonRecover<T> {
    fn lock_or_poison(&self) -> MutexGuard<'_, T>;
}

impl<T> MutexPoisonRecover<T> for Mutex<T> {
    fn lock_or_poison(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
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
#[derive(Clone)]
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

#[derive(Clone)]
pub(super) struct PendingProtection {
    pub(super) address: usize,
    pub(super) length: usize,
    pub(super) protection: u32,
    pub(super) module: ModuleInfo,
    pub(super) loader_epoch: (u64, u64),
    pub(super) needs_restore: bool,
}

// 完整发布的配置与绑定状态；事务在独立副本上准备下一版本。
#[derive(Clone, Default)]
pub(super) struct CoreState {
    pub(super) process_id: usize,
    pub(super) revision: u64,
    pub(super) clearing: bool,
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
    pub(super) pending_protections: Vec<PendingProtection>,
    pub(super) single_task_targets: BTreeMap<HookStub, String>,
    pub(super) ignore_callers: Vec<String>,
    pub(super) known_modules: BTreeSet<String>,
    pub(super) recordable: bool,
    pub(super) records: Vec<RecordEntry>,
    pub(super) dlopen_callbacks: Vec<DlopenCallbackEntry>,
}
