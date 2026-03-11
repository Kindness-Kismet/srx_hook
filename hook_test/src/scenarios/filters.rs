use std::ffi::c_void;
use std::sync::atomic::Ordering;

use srx_hook::{
    HookMode, add_ignore, clear, get_module_identity, get_module_identity_with_symbol, hook_all,
    hook_single, init, refresh, unhook,
};

use crate::test_ctx::{
    HOOK_A_COUNT, ensure_ok, hook_puts_quiet, hook_test_trigger, load_hook_test,
    load_hook_test_abs, load_hook_test_lazy, module_base_from_handle, module_instance_from_handle,
    prepare_same_basename_hook_test_instances, resolve_symbol_module_base,
};

pub unsafe fn scenario_callee_filter() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init callee filter");
    let handle = load_hook_test();

    let wrong_stub = hook_single(
        "libhook_test.so",
        Some("libm.so"),
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single wrong callee failed");
    ensure_ok(refresh().0, "refresh callee wrong");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert_eq!(
        HOOK_A_COUNT.load(Ordering::Relaxed),
        0,
        "wrong callee path still hooked"
    );
    ensure_ok(unhook(wrong_stub), "unhook wrong callee");

    let right_stub = hook_single(
        "libhook_test.so",
        Some("libc.so"),
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single right callee failed");
    ensure_ok(refresh().0, "refresh callee right");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "right callee path not hooked"
    );
    ensure_ok(unhook(right_stub), "unhook right callee");

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_callee_filter_lazy_bind() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init callee lazy filter");
    let handle = load_hook_test_lazy();

    let stub = hook_single(
        "libhook_test.so",
        Some("libc.so"),
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single lazy callee failed");
    ensure_ok(refresh().0, "refresh callee lazy");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "lazy bind callee path not hooked"
    );

    ensure_ok(unhook(stub), "unhook lazy callee");
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_base_qualified_path_rule() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init base-qualified rule");
    let handle = load_hook_test();

    let hook_test_base =
        module_base_from_handle(handle).expect("resolve base from handle for libhook_test failed");
    let libc_base = resolve_symbol_module_base("puts").expect("find libc base failed");

    let wrong_caller = format!("libhook_test.so@0x{:x}", hook_test_base + 0x1000);
    let stub_wrong_caller = hook_single(
        wrong_caller.as_str(),
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single wrong caller base failed");
    ensure_ok(refresh().0, "refresh wrong caller base");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert_eq!(
        HOOK_A_COUNT.load(Ordering::Relaxed),
        0,
        "wrong caller base still matched"
    );
    ensure_ok(unhook(stub_wrong_caller), "unhook wrong caller base");

    let right_caller = format!("libhook_test.so@0x{hook_test_base:x}");
    let stub_right_caller = hook_single(
        right_caller.as_str(),
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single right caller base failed");
    ensure_ok(refresh().0, "refresh right caller base");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "right caller base did not match"
    );
    ensure_ok(unhook(stub_right_caller), "unhook right caller base");

    let wrong_callee = format!("libc.so@0x{:x}", libc_base + 0x1000);
    let stub_wrong_callee = hook_single(
        "libhook_test.so",
        Some(wrong_callee.as_str()),
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single wrong callee base failed");
    ensure_ok(refresh().0, "refresh wrong callee base");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert_eq!(
        HOOK_A_COUNT.load(Ordering::Relaxed),
        0,
        "wrong callee base still matched"
    );
    ensure_ok(unhook(stub_wrong_callee), "unhook wrong callee base");

    let right_callee = format!("libc.so@0x{libc_base:x}");
    let stub_right_callee = hook_single(
        "libhook_test.so",
        Some(right_callee.as_str()),
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single right callee base failed");
    ensure_ok(refresh().0, "refresh right callee base");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "right callee base did not match"
    );
    ensure_ok(unhook(stub_right_callee), "unhook right callee base");

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_single_same_basename_multi_instance() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init single same basename");

    let (path_a, path_b) = prepare_same_basename_hook_test_instances();
    let handle_a = load_hook_test_abs(&path_a);
    let handle_b = load_hook_test_abs(&path_b);

    let base_a = module_base_from_handle(handle_a).expect("resolve base for handle_a failed");
    let base_b = module_base_from_handle(handle_b).expect("resolve base for handle_b failed");
    assert_ne!(base_a, base_b, "same basename test needs two loaded module instances");

    let stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single same basename failed");
    ensure_ok(refresh().0, "refresh single same basename");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle_a);
    let count_after_a = HOOK_A_COUNT.load(Ordering::Relaxed);
    hook_test_trigger(handle_b);
    let count_after_b = HOOK_A_COUNT.load(Ordering::Relaxed);
    let hit_a = count_after_a > 0;
    let hit_b = count_after_b > count_after_a;
    assert!(
        hit_a ^ hit_b,
        "single task should bind exactly one instance, hit_a={hit_a}, hit_b={hit_b}"
    );

    if hit_a {
        libc::dlclose(handle_a);
        ensure_ok(refresh().0, "refresh single same basename rebind");
        HOOK_A_COUNT.store(0, Ordering::Relaxed);
        hook_test_trigger(handle_b);
        assert!(
            HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
            "single task should rebind to remaining instance after unload"
        );
        ensure_ok(unhook(stub), "unhook single same basename");
        libc::dlclose(handle_b);
    } else {
        libc::dlclose(handle_b);
        ensure_ok(refresh().0, "refresh single same basename rebind");
        HOOK_A_COUNT.store(0, Ordering::Relaxed);
        hook_test_trigger(handle_a);
        assert!(
            HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
            "single task should rebind to remaining instance after unload"
        );
        ensure_ok(unhook(stub), "unhook single same basename");
        libc::dlclose(handle_a);
    }

    clear();
}

pub unsafe fn scenario_instance_qualified_path_rule() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init instance-qualified rule");

    let (path_a, path_b) = prepare_same_basename_hook_test_instances();
    let handle_a = load_hook_test_abs(&path_a);
    let handle_b = load_hook_test_abs(&path_b);

    let base_a = module_base_from_handle(handle_a).expect("resolve base for handle_a failed");
    let instance_a =
        module_instance_from_handle(handle_a).expect("resolve instance for handle_a failed");
    let instance_b =
        module_instance_from_handle(handle_b).expect("resolve instance for handle_b failed");
    assert_ne!(
        instance_a, instance_b,
        "instance-qualified test needs two different module instances"
    );

    let wrong_rule = format!("libhook_test.so@0x{base_a:x}%0x{instance_b:x}");
    let wrong_stub = hook_single(
        wrong_rule.as_str(),
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single wrong instance rule failed");
    ensure_ok(refresh().0, "refresh wrong instance rule");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle_a);
    hook_test_trigger(handle_b);
    assert_eq!(
        HOOK_A_COUNT.load(Ordering::Relaxed),
        0,
        "wrong instance rule should not match any target"
    );
    ensure_ok(unhook(wrong_stub), "unhook wrong instance rule");

    let right_rule = format!("libhook_test.so@0x{base_a:x}%0x{instance_a:x}");
    let right_stub = hook_single(
        right_rule.as_str(),
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single right instance rule failed");
    ensure_ok(refresh().0, "refresh right instance rule");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle_a);
    let count_after_a = HOOK_A_COUNT.load(Ordering::Relaxed);
    hook_test_trigger(handle_b);
    let count_after_b = HOOK_A_COUNT.load(Ordering::Relaxed);
    assert!(count_after_a > 0, "right instance rule did not hit target instance");
    assert_eq!(
        count_after_b, count_after_a,
        "right instance rule should not affect non-target instance"
    );
    ensure_ok(unhook(right_stub), "unhook right instance rule");

    libc::dlclose(handle_b);
    libc::dlclose(handle_a);
    clear();
}

pub unsafe fn scenario_ignore_instance_qualified_rule() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init ignore instance-qualified rule");

    let (path_a, path_b) = prepare_same_basename_hook_test_instances();
    let handle_a = load_hook_test_abs(&path_a);
    let handle_b = load_hook_test_abs(&path_b);

    let base_a = module_base_from_handle(handle_a).expect("resolve base for handle_a failed");
    let instance_a =
        module_instance_from_handle(handle_a).expect("resolve instance for handle_a failed");
    let ignore_rule = format!("libhook_test.so@0x{base_a:x}%0x{instance_a:x}");
    ensure_ok(
        add_ignore(ignore_rule.as_str()),
        "add_ignore instance-qualified rule",
    );

    let stub = hook_all(
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_all ignore instance-qualified rule failed");
    ensure_ok(refresh().0, "refresh ignore instance-qualified rule");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle_a);
    let count_after_a = HOOK_A_COUNT.load(Ordering::Relaxed);
    hook_test_trigger(handle_b);
    let count_after_b = HOOK_A_COUNT.load(Ordering::Relaxed);

    assert_eq!(
        count_after_a, 0,
        "ignored instance should not be hooked by global task"
    );
    assert!(
        count_after_b > count_after_a,
        "non-ignored instance should still be hooked"
    );

    ensure_ok(unhook(stub), "unhook ignore instance-qualified rule");
    libc::dlclose(handle_b);
    libc::dlclose(handle_a);
    clear();
}

pub unsafe fn scenario_instance_rule_from_handle_api() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init instance rule from handle api");

    let (path_a, path_b) = prepare_same_basename_hook_test_instances();
    let handle_a = load_hook_test_abs(&path_a);
    let handle_b = load_hook_test_abs(&path_b);

    let identity_a = get_module_identity(handle_a)
        .or_else(|| get_module_identity_with_symbol(handle_a, "hook_test_trigger"));
    let identity_a = identity_a.expect("instance-rule-from-handle-api: module identity unavailable");
    let identity_b = get_module_identity(handle_b)
        .or_else(|| get_module_identity_with_symbol(handle_b, "hook_test_trigger"));
    let identity_b = identity_b.expect("instance-rule-from-handle-api: module identity unavailable");
    assert_ne!(
        identity_a.instance_id, identity_b.instance_id,
        "instance-rule-from-handle-api needs two different instances"
    );

    let stub = hook_single(
        identity_a.caller_rule().as_str(),
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single instance rule from handle api failed");
    ensure_ok(refresh().0, "refresh instance rule from handle api");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle_a);
    let count_after_a = HOOK_A_COUNT.load(Ordering::Relaxed);
    hook_test_trigger(handle_b);
    let count_after_b = HOOK_A_COUNT.load(Ordering::Relaxed);
    assert!(count_after_a > 0, "handle api instance rule did not hit target instance");
    assert_eq!(
        count_after_b, count_after_a,
        "handle api instance rule should not affect non-target instance"
    );

    ensure_ok(unhook(stub), "unhook instance rule from handle api");
    libc::dlclose(handle_b);
    libc::dlclose(handle_a);
    clear();
}

pub unsafe fn scenario_identity_with_symbol_api() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init identity with symbol api");

    let handle = load_hook_test();
    assert!(
        get_module_identity_with_symbol(handle, "hook_test_not_found").is_none(),
        "identity with unknown symbol should be none"
    );
    let identity = get_module_identity_with_symbol(handle, "hook_test_trigger")
        .expect("identity with symbol should resolve");
    assert!(identity.base_addr != 0, "identity base_addr should be non-zero");
    assert!(identity.instance_id != 0, "identity instance_id should be non-zero");
    assert!(
        identity.pathname.ends_with("libhook_test.so"),
        "identity path should be libhook_test.so"
    );

    let stub = hook_single(
        identity.caller_rule().as_str(),
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single identity with symbol api failed");
    ensure_ok(refresh().0, "refresh identity with symbol api");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "identity with symbol caller rule did not hook"
    );

    ensure_ok(unhook(stub), "unhook identity with symbol api");
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_identity_api_consistency() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init identity api consistency");

    let handle = load_hook_test();
    let by_handle = get_module_identity(handle);
    let by_symbol =
        get_module_identity_with_symbol(handle, "hook_test_trigger").expect("identity by symbol should resolve");

    if let Some(by_handle) = by_handle {
        assert_eq!(by_handle.pathname, by_symbol.pathname);
        assert_eq!(by_handle.base_addr, by_symbol.base_addr);
        assert_eq!(by_handle.instance_id, by_symbol.instance_id);
        if by_handle.namespace_id != 0 && by_symbol.namespace_id != 0 {
            assert_eq!(by_handle.namespace_id, by_symbol.namespace_id);
        }
    }

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_namespace_rule_from_handle_api() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init namespace rule from handle api");

    let (path_a, path_b) = prepare_same_basename_hook_test_instances();
    let handle_a = load_hook_test_abs(&path_a);
    let handle_b = load_hook_test_abs(&path_b);

    let identity_a = get_module_identity(handle_a)
        .or_else(|| get_module_identity_with_symbol(handle_a, "hook_test_trigger"));
    let identity_a = identity_a.expect("namespace-rule-from-handle-api: module identity unavailable");
    let identity_b = get_module_identity(handle_b)
        .or_else(|| get_module_identity_with_symbol(handle_b, "hook_test_trigger"));
    let identity_b = identity_b.expect("namespace-rule-from-handle-api: module identity unavailable");
    assert_ne!(
        identity_a.instance_id, identity_b.instance_id,
        "namespace-rule-from-handle-api needs two different instances"
    );

    let right_namespace = identity_a.namespace_id;
    let wrong_namespace = right_namespace.wrapping_add(1);
    let wrong_rule = format!(
        "{}@0x{:x}%0x{:x}^0x{:x}",
        identity_a.pathname, identity_a.base_addr, identity_a.instance_id, wrong_namespace
    );
    let wrong_stub = hook_single(
        wrong_rule.as_str(),
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single wrong namespace rule failed");
    ensure_ok(refresh().0, "refresh wrong namespace rule");
    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle_a);
    hook_test_trigger(handle_b);
    assert_eq!(
        HOOK_A_COUNT.load(Ordering::Relaxed),
        0,
        "wrong namespace rule still matched",
    );
    ensure_ok(unhook(wrong_stub), "unhook wrong namespace rule");

    let right_rule = format!(
        "{}@0x{:x}%0x{:x}^0x{:x}",
        identity_a.pathname, identity_a.base_addr, identity_a.instance_id, right_namespace
    );
    assert!(
        right_rule.contains("^0x"),
        "namespace rule should contain namespace suffix"
    );
    let right_stub = hook_single(
        right_rule.as_str(),
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single right namespace rule failed");
    ensure_ok(refresh().0, "refresh right namespace rule");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle_a);
    let count_after_a = HOOK_A_COUNT.load(Ordering::Relaxed);
    hook_test_trigger(handle_b);
    let count_after_b = HOOK_A_COUNT.load(Ordering::Relaxed);
    assert!(
        count_after_a > 0,
        "namespace rule did not hit target namespace"
    );
    assert_eq!(
        count_after_b, count_after_a,
        "namespace rule should not affect non-target namespace"
    );

    ensure_ok(unhook(right_stub), "unhook right namespace rule");
    libc::dlclose(handle_b);
    libc::dlclose(handle_a);
    clear();
}
