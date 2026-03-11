// 生命周期管理模块，作为 runtime 子模块的统一入口
// 将 hook/unhook/refresh/控制/回调等操作分发到各子模块
use crate::api::{
    CallerAllowFilter, HookMode, HookStub, HookedCallback, ModuleIdentity, PostDlopenCallback,
    PreDlopenCallback, RefreshError,
};
use crate::errno::Errno;
use std::ffi::{c_char, c_void};

mod dlopen_callbacks;
mod monitor;
mod monitor_calls;
mod process;
mod proxy;
mod task_ops;

mod entry_control;
mod entry_hook;
mod entry_init;

pub(super) fn get_version() -> String {
    entry_init::get_version()
}

pub(super) fn init(mode: HookMode, debug: bool) -> Errno {
    entry_init::init(mode, debug)
}

pub(super) fn hook_single(
    caller_path_name: &str,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    entry_hook::hook_single(
        caller_path_name,
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
    )
}

pub(super) fn hook_partial(
    caller_allow_filter: CallerAllowFilter,
    caller_allow_filter_arg: *mut c_void,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    entry_hook::hook_partial(
        caller_allow_filter,
        caller_allow_filter_arg,
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
    )
}

pub(super) fn hook_all(
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    entry_hook::hook_all(callee_path_name, sym_name, new_func, hooked, hooked_arg)
}

pub(super) fn unhook(stub: HookStub) -> Errno {
    entry_hook::unhook(stub)
}

pub(super) fn add_ignore(caller_path_name: &str) -> Errno {
    entry_hook::add_ignore(caller_path_name)
}

pub(super) fn get_module_identity(handle: *mut c_void) -> Option<ModuleIdentity> {
    entry_hook::get_module_identity(handle)
}

pub(super) fn get_module_identity_with_symbol(
    handle: *mut c_void,
    probe_symbol: &str,
) -> Option<ModuleIdentity> {
    entry_hook::get_module_identity_with_symbol(handle, probe_symbol)
}

pub(super) fn refresh() -> (Errno, Vec<RefreshError>) {
    entry_hook::refresh()
}

pub(super) fn clear() {
    entry_control::clear();
}

pub(super) fn get_mode() -> HookMode {
    entry_control::get_mode()
}

pub(super) fn get_debug() -> bool {
    entry_control::get_debug()
}

pub(super) fn set_debug(debug: bool) {
    entry_control::set_debug(debug)
}

pub(super) fn get_recordable() -> bool {
    entry_control::get_recordable()
}

pub(super) fn set_recordable(recordable: bool) {
    entry_control::set_recordable(recordable)
}

pub(super) fn get_records(item_flags: u32) -> Option<String> {
    entry_control::get_records(item_flags)
}

pub(super) fn dump_records(fd: i32, item_flags: u32) -> Errno {
    entry_control::dump_records(fd, item_flags)
}

pub(super) fn enable_sigsegv_protection(flag: bool) {
    entry_control::enable_sigsegv_protection(flag)
}

pub(super) fn get_prev_func(func: *mut c_void) -> *mut c_void {
    entry_control::get_prev_func(func)
}

pub(super) fn with_prev_func<R, F>(func: *mut c_void, f: F) -> Option<R>
where
    F: FnOnce(*mut c_void) -> R,
{
    entry_control::with_prev_func(func, f)
}

pub(super) fn get_return_address() -> *mut c_void {
    entry_control::get_return_address()
}

pub(super) fn pop_stack(return_address: *mut c_void) {
    entry_control::pop_stack(return_address)
}

pub(super) fn proxy_enter(func: *mut c_void) -> bool {
    entry_control::proxy_enter(func)
}

pub(super) fn proxy_leave(func: *mut c_void) {
    entry_control::proxy_leave(func)
}

pub(super) fn add_dlopen_callback(
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: *mut c_void,
) -> Errno {
    entry_control::add_dlopen_callback(pre, post, data)
}

pub(super) fn del_dlopen_callback(
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: *mut c_void,
) -> Errno {
    entry_control::del_dlopen_callback(pre, post, data)
}

pub(super) fn invoke_dlopen_callbacks_pre(filename: *const c_char) {
    entry_control::invoke_dlopen_callbacks_pre(filename)
}

pub(super) fn invoke_dlopen_callbacks_post(filename: *const c_char, result: i32) {
    entry_control::invoke_dlopen_callbacks_post(filename, result)
}

fn add_task(task: super::state::Task) -> Option<HookStub> {
    task_ops::add_task(task)
}

pub(super) fn request_refresh_async() {
    task_ops::request_refresh_async();
}

pub(super) fn request_refresh_async_with_handle(handle: *mut c_void) {
    task_ops::request_refresh_async_with_handle(handle);
}

pub(super) fn request_refresh_async_full() {
    task_ops::request_refresh_async_full();
}

fn invoke_callbacks(events: Vec<super::refresh::CallbackEvent>) {
    task_ops::invoke_callbacks(events);
}
