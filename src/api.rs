use crate::errno::Errno;
use crate::runtime;
use std::ffi::{c_char, c_void};

// hook 任务的唯一标识，由运行时分配
pub type HookStub = u64;

// refresh 中单个模块的错误详情，用于诊断 ELF 解析失败等问题
#[derive(Debug)]
pub struct RefreshError {
    pub module_path: String,
    pub errno: Errno,
}

// hook 生效后的回调，通知调用方 hook 状态与实际替换地址
pub type HookedCallback = unsafe extern "C" fn(
    task_stub: HookStub,
    status_code: i32,
    caller_path_name: *const c_char,
    sym_name: *const c_char,
    new_func: *mut c_void,
    prev_func: *mut c_void,
    arg: *mut c_void,
);

// 自定义 caller 过滤器，返回 true 表示允许 hook 该 caller
pub type CallerAllowFilter =
    unsafe extern "C" fn(caller_path_name: *const c_char, arg: *mut c_void) -> bool;

// dlopen 前后回调，用于外部观测动态加载行为
pub type PreDlopenCallback = unsafe extern "C" fn(filename: *const c_char, arg: *mut c_void);
pub type PostDlopenCallback =
    unsafe extern "C" fn(filename: *const c_char, result: i32, arg: *mut c_void);

// 模块实例标识，用于区分同名 so 的不同加载实例
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleIdentity {
    pub pathname: String,
    pub base_addr: usize,
    pub instance_id: usize,
    pub namespace_id: usize,
}

impl ModuleIdentity {
    // 生成实例级 caller 规则字符串：path@base%instance[^namespace]
    pub fn caller_rule(&self) -> String {
        let base_rule = format!(
            "{}@0x{:x}%0x{:x}",
            self.pathname, self.base_addr, self.instance_id
        );
        if self.namespace_id == 0 {
            base_rule
        } else {
            format!("{base_rule}^0x{:x}", self.namespace_id)
        }
    }
}

// 操作记录字段掩码
pub const RECORD_ITEM_ALL: u32 = 0xFF;
pub const RECORD_ITEM_TIMESTAMP: u32 = 1 << 0;
pub const RECORD_ITEM_CALLER_LIB_NAME: u32 = 1 << 1;
pub const RECORD_ITEM_OP: u32 = 1 << 2;
pub const RECORD_ITEM_LIB_NAME: u32 = 1 << 3;
pub const RECORD_ITEM_SYM_NAME: u32 = 1 << 4;
pub const RECORD_ITEM_NEW_ADDR: u32 = 1 << 5;
pub const RECORD_ITEM_ERRNO: u32 = 1 << 6;
pub const RECORD_ITEM_STUB: u32 = 1 << 7;

// Automatic: dlopen/dlclose 事件自动触发刷新
// Manual: 需要手动调用 refresh() 应用 hook
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HookMode {
    Automatic = 0,
    Manual = 1,
}

impl HookMode {
    pub fn from_i32(mode: i32) -> Result<Self, Errno> {
        match mode {
            0 => Ok(Self::Automatic),
            1 => Ok(Self::Manual),
            _ => Err(Errno::InitErrInvalidArg),
        }
    }
}

// 在外部回调中调用 API 会导致死锁，此守卫统一拦截
#[inline]
fn in_external_callback() -> bool {
    runtime::in_external_callback()
}

pub fn get_version() -> String {
    runtime::get_version()
}

// 无锁检测当前进程是否为 fork 子进程
pub fn is_forked_child() -> bool {
    runtime::is_forked_child()
}

// 初始化 hook 运行时，只能调用一次
pub fn init(mode: HookMode, debug: bool) -> Errno {
    if in_external_callback() {
        return Errno::InitErrSafe;
    }
    runtime::init(mode, debug)
}

// 按 caller 路径精确匹配单个模块进行 hook
pub fn hook_single(
    caller_path_name: &str,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    if in_external_callback() {
        return None;
    }
    runtime::hook_single(
        caller_path_name,
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
    )
}

// 通过自定义过滤器选择性 hook 多个 caller
pub fn hook_partial(
    caller_allow_filter: CallerAllowFilter,
    caller_allow_filter_arg: *mut c_void,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    if in_external_callback() {
        return None;
    }
    runtime::hook_partial(
        caller_allow_filter,
        caller_allow_filter_arg,
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
    )
}

// hook 所有已加载和未来加载的 caller 模块
pub fn hook_all(
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    if in_external_callback() {
        return None;
    }
    runtime::hook_all(callee_path_name, sym_name, new_func, hooked, hooked_arg)
}

// 卸载指定 hook 任务，同一调用点的其他任务不受影响
pub fn unhook(stub: HookStub) -> Errno {
    if in_external_callback() {
        return Errno::InitErrSafe;
    }
    runtime::unhook(stub)
}

// 将指定 caller 路径加入忽略列表，后续 hook 跳过该模块
pub fn add_ignore(caller_path_name: &str) -> Errno {
    if in_external_callback() {
        return Errno::InitErrSafe;
    }
    runtime::add_ignore(caller_path_name)
}

// 从 dlopen 句柄获取模块实例标识
pub fn get_module_identity(handle: *mut c_void) -> Option<ModuleIdentity> {
    if in_external_callback() {
        return None;
    }
    runtime::get_module_identity(handle)
}

// 从 dlopen 句柄获取模块标识，dlinfo 不可用时回退到符号探测
pub fn get_module_identity_with_symbol(
    handle: *mut c_void,
    probe_symbol: &str,
) -> Option<ModuleIdentity> {
    if in_external_callback() {
        return None;
    }
    runtime::get_module_identity_with_symbol(handle, probe_symbol)
}

// 手动模式下触发一次全量刷新，将待生效的 hook 应用到已加载模块
pub fn refresh() -> (Errno, Vec<RefreshError>) {
    if in_external_callback() {
        return (Errno::InitErrSafe, Vec::new());
    }
    runtime::refresh()
}

// 清除所有 hook 任务并重置运行时状态
pub fn clear() {
    if in_external_callback() {
        return;
    }
    runtime::clear();
}

pub fn get_mode() -> HookMode {
    if in_external_callback() {
        return HookMode::Manual;
    }
    runtime::get_mode()
}

pub fn get_debug() -> bool {
    if in_external_callback() {
        return false;
    }
    runtime::get_debug()
}

pub fn set_debug(debug: bool) {
    if in_external_callback() {
        return;
    }
    runtime::set_debug(debug);
}

pub fn get_recordable() -> bool {
    if in_external_callback() {
        return false;
    }
    runtime::get_recordable()
}

pub fn set_recordable(recordable: bool) {
    if in_external_callback() {
        return;
    }
    runtime::set_recordable(recordable);
}

// 按字段掩码导出操作记录文本
pub fn get_records(item_flags: u32) -> Option<String> {
    if in_external_callback() {
        return None;
    }
    runtime::get_records(item_flags)
}

// 按字段掩码将操作记录写入文件描述符
pub fn dump_records(fd: i32, item_flags: u32) -> Errno {
    if in_external_callback() {
        return Errno::InitErrSafe;
    }
    runtime::dump_records(fd, item_flags)
}

pub fn enable_debug(debug: bool) {
    set_debug(debug);
}

// 启用或禁用 SIGSEGV/SIGBUS 信号保护
pub fn enable_sigsegv_protection(flag: bool) {
    if in_external_callback() {
        return;
    }
    runtime::enable_sigsegv_protection(flag);
}

// 在 proxy 中获取调用链的下一个函数指针
pub fn get_prev_func(func: *mut c_void) -> *mut c_void {
    runtime::get_prev_func(func)
}

// 获取 prev_func 并在闭包中执行，自动管理栈帧释放与环路检测
pub fn with_prev_func<R, F>(func: *mut c_void, f: F) -> Option<R>
where
    F: FnOnce(*mut c_void) -> R,
{
    runtime::with_prev_func(func, f)
}

// 获取当前 proxy 调用的返回地址
pub fn get_return_address() -> *mut c_void {
    runtime::get_return_address()
}

// 手动弹出 trampoline 栈帧
pub fn pop_stack(return_address: *mut c_void) {
    runtime::pop_stack(return_address)
}

// 手动进入 proxy 环路检测，返回 false 表示命中递归环
pub fn proxy_enter(func: *mut c_void) -> bool {
    runtime::proxy_enter(func)
}

// 手动退出 proxy 环路检测，释放当前栈帧
pub fn proxy_leave(func: *mut c_void) {
    runtime::proxy_leave(func)
}

// 注册 dlopen 前后回调
pub fn add_dlopen_callback(
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: *mut c_void,
) -> Errno {
    if in_external_callback() {
        return Errno::InitErrSafe;
    }
    runtime::add_dlopen_callback(pre, post, data)
}

// 注销 dlopen 前后回调
pub fn del_dlopen_callback(
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: *mut c_void,
) -> Errno {
    if in_external_callback() {
        return Errno::InitErrSafe;
    }
    runtime::del_dlopen_callback(pre, post, data)
}
