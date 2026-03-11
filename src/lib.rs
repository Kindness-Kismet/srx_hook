#![allow(dead_code)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

#[cfg(all(not(target_os = "android"), not(any(clippy, test, doc))))]
compile_error!("srx_hook supports Android only (use cargo clippy/test/doc on host for development)");

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("srx_hook supports only 64-bit architectures: aarch64 and x86_64");

// 公共 API 层，提供 hook 注册、刷新、忽略等操作
#[cfg(target_os = "android")]
mod api;
// ELF 解析核心，处理动态段、符号表、重定位表
#[cfg(target_os = "android")]
mod elf;
// 错误码定义
#[cfg(target_os = "android")]
mod errno;
// 日志输出，使用 Android logcat
#[cfg(target_os = "android")]
mod log;
// Android 相关：内存保护与信号守卫
#[cfg(target_os = "android")]
mod android;
// 运行时状态管理：生命周期、刷新管道、规则编译
#[cfg(target_os = "android")]
mod runtime;
// 版本信息
#[cfg(target_os = "android")]
mod version;

#[cfg(target_os = "android")]
pub use api::{
    CallerAllowFilter, HookMode, HookStub, HookedCallback, ModuleIdentity, PostDlopenCallback,
    PreDlopenCallback, RECORD_ITEM_ALL, RECORD_ITEM_CALLER_LIB_NAME, RECORD_ITEM_ERRNO,
    RECORD_ITEM_LIB_NAME, RECORD_ITEM_NEW_ADDR, RECORD_ITEM_OP, RECORD_ITEM_STUB,
    RECORD_ITEM_SYM_NAME, RECORD_ITEM_TIMESTAMP, RefreshError, add_dlopen_callback, add_ignore,
    clear, del_dlopen_callback, dump_records, enable_debug, enable_sigsegv_protection, get_debug,
    get_mode, get_module_identity, get_module_identity_with_symbol, get_prev_func,
    get_recordable, get_records, get_return_address, get_version, hook_all, hook_partial,
    hook_single, init, is_forked_child, pop_stack, proxy_enter, proxy_leave, refresh,
    set_debug, set_recordable, unhook, with_prev_func,
};
#[cfg(target_os = "android")]
pub use errno::Errno as SrxHookErrno;
