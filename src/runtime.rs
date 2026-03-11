// runtime 模块入口，将内部子模块的功能统一暴露为 crate 级公共接口
use crate::api::{
    CallerAllowFilter, HookMode, HookStub, HookedCallback, ModuleIdentity, PostDlopenCallback,
    PreDlopenCallback,
};
use crate::errno::Errno;
use std::ffi::c_void;

mod cfi;
mod callback_ctx;
mod hub;
mod lifecycle;
mod record;
mod refresh;
mod rules;
mod state;
mod thread_state;

pub(crate) use state::MutexPoisonRecover;

pub(crate) fn is_forked_child() -> bool {
    state::is_forked_child()
}

pub(crate) fn get_version() -> String {
    lifecycle::get_version()
}

pub(crate) fn in_external_callback() -> bool {
    callback_ctx::is_in_external_callback()
}

pub(crate) fn init(mode: HookMode, debug: bool) -> Errno {
    lifecycle::init(mode, debug)
}

pub(crate) fn hook_single(
    caller_path_name: &str,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    lifecycle::hook_single(
        caller_path_name,
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
    )
}

pub(crate) fn hook_partial(
    caller_allow_filter: CallerAllowFilter,
    caller_allow_filter_arg: *mut c_void,
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    lifecycle::hook_partial(
        caller_allow_filter,
        caller_allow_filter_arg,
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
    )
}

pub(crate) fn hook_all(
    callee_path_name: Option<&str>,
    sym_name: &str,
    new_func: *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Option<HookStub> {
    lifecycle::hook_all(callee_path_name, sym_name, new_func, hooked, hooked_arg)
}

pub(crate) fn unhook(stub: HookStub) -> Errno {
    lifecycle::unhook(stub)
}

pub(crate) fn add_ignore(caller_path_name: &str) -> Errno {
    lifecycle::add_ignore(caller_path_name)
}

pub(crate) fn get_module_identity(handle: *mut c_void) -> Option<ModuleIdentity> {
    lifecycle::get_module_identity(handle)
}

pub(crate) fn get_module_identity_with_symbol(
    handle: *mut c_void,
    probe_symbol: &str,
) -> Option<ModuleIdentity> {
    lifecycle::get_module_identity_with_symbol(handle, probe_symbol)
}

pub(crate) fn refresh() -> (Errno, Vec<crate::api::RefreshError>) {
    lifecycle::refresh()
}

pub(crate) fn clear() {
    lifecycle::clear();
}

pub(crate) fn get_mode() -> HookMode {
    lifecycle::get_mode()
}

pub(crate) fn get_debug() -> bool {
    lifecycle::get_debug()
}

pub(crate) fn set_debug(debug: bool) {
    lifecycle::set_debug(debug)
}

pub(crate) fn get_recordable() -> bool {
    lifecycle::get_recordable()
}

pub(crate) fn set_recordable(recordable: bool) {
    lifecycle::set_recordable(recordable)
}

pub(crate) fn get_records(item_flags: u32) -> Option<String> {
    lifecycle::get_records(item_flags)
}

pub(crate) fn dump_records(fd: i32, item_flags: u32) -> Errno {
    lifecycle::dump_records(fd, item_flags)
}

pub(crate) fn enable_sigsegv_protection(flag: bool) {
    lifecycle::enable_sigsegv_protection(flag)
}

pub(crate) fn get_prev_func(func: *mut c_void) -> *mut c_void {
    lifecycle::get_prev_func(func)
}

pub(crate) fn with_prev_func<R, F>(func: *mut c_void, f: F) -> Option<R>
where
    F: FnOnce(*mut c_void) -> R,
{
    lifecycle::with_prev_func(func, f)
}

pub(crate) fn get_return_address() -> *mut c_void {
    lifecycle::get_return_address()
}

pub(crate) fn pop_stack(return_address: *mut c_void) {
    lifecycle::pop_stack(return_address)
}

pub(crate) fn proxy_enter(func: *mut c_void) -> bool {
    lifecycle::proxy_enter(func)
}

pub(crate) fn proxy_leave(func: *mut c_void) {
    lifecycle::proxy_leave(func)
}

pub(crate) fn add_dlopen_callback(
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: *mut c_void,
) -> Errno {
    lifecycle::add_dlopen_callback(pre, post, data)
}

pub(crate) fn del_dlopen_callback(
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: *mut c_void,
) -> Errno {
    lifecycle::del_dlopen_callback(pre, post, data)
}

#[cfg(test)]
mod tests {
    use super::{
        clear, hook_single, init, proxy_enter, proxy_leave,
        rules::{module_match, path_match},
        set_debug,
    };
    use crate::api::HookMode;
    use crate::errno::Errno;
    use std::ffi::c_void;

    #[test]
    fn absolute_path_must_be_equal() {
        assert!(path_match("/data/app/libfoo.so", "/data/app/libfoo.so"));
        assert!(!path_match("/data/app/libfoo.so", "/data/app/libbar.so"));
    }

    #[test]
    fn relative_path_uses_suffix_match() {
        assert!(path_match("/data/app/libfoo.so", "libfoo.so"));
        assert!(!path_match("/data/app/libfoo.so", "libfo.so"));
    }

    #[test]
    fn path_rule_with_base_supports_hex_suffix() {
        assert!(path_match("/data/app/libfoo.so", "libfoo.so@0x1A2B"));
        assert!(path_match("/data/app/libfoo.so", "libfoo.so@1a2b"));
    }

    #[test]
    fn module_match_checks_base_when_rule_has_suffix() {
        assert!(module_match(
            "/data/app/libfoo.so",
            0x1A2B,
            0,
            0,
            "libfoo.so@0x1a2b"
        ));
        assert!(!module_match(
            "/data/app/libfoo.so",
            0x1A2B,
            0,
            0,
            "libfoo.so@0x1a2c"
        ));
    }

    #[test]
    fn module_match_falls_back_to_path_when_suffix_is_invalid() {
        assert!(!module_match(
            "/data/app/libfoo.so",
            0x1A2B,
            0,
            0,
            "/data/app/libfoo.so@invalid"
        ));
        assert!(!module_match(
            "/data/app/libfoo.so",
            0x1A2B,
            0,
            0,
            "libfoo.so@invalid_tail"
        ));
    }

    #[test]
    fn proxy_stack_rejects_cycle() {
        let func = 0x1234usize as *mut c_void;
        assert!(proxy_enter(func));
        assert!(!proxy_enter(func));
        proxy_leave(func);
        assert!(proxy_enter(func));
        proxy_leave(func);
    }

    #[test]
    fn duplicated_proxy_address_is_rejected() {
        unsafe extern "C" fn dummy_proxy(_s: *const i8) -> i32 {
            0
        }

        clear();
        set_debug(false);
        assert_eq!(init(HookMode::Manual, false), Errno::Ok);

        let first = hook_single(
            "libdummy.so",
            None,
            "puts",
            dummy_proxy as *mut c_void,
            None,
            std::ptr::null_mut(),
        );
        assert!(first.is_some());

        let second = hook_single(
            "libdummy.so",
            None,
            "puts",
            dummy_proxy as *mut c_void,
            None,
            std::ptr::null_mut(),
        );
        assert!(second.is_none());
        clear();
    }
}
