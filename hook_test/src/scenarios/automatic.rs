use std::ffi::c_void;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use srx_hook::{
    HookMode, RECORD_ITEM_ALL, SrxHookErrno, add_dlopen_callback, clear, del_dlopen_callback,
    get_recordable, get_records, hook_single, init, set_recordable,
};

use crate::test_ctx::{
    DLOPEN_POST_COUNT, DLOPEN_PRE_COUNT, HOOK_A_COUNT, HOOKED_CALLBACK_CLEAR_REINIT_STATUS,
    HOOKED_CALLBACK_FROM_OTHER_THREAD, HOOKED_CALLBACK_MAIN_THREAD, HOOKED_CALLBACK_UNHOOK_STATUS,
    ScopedEnv, clear_and_reinit_from_hooked_callback, current_rss_kb, ensure_ok, env_usize,
    hook_puts_quiet, hook_test_dlopen_post, hook_test_dlopen_pre, hook_test_trigger,
    load_hook_test, unhook_from_hooked_callback,
};

pub unsafe fn scenario_automatic_refresh() {
    clear();
    ensure_ok(init(HookMode::Automatic, true), "init automatic");

    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single automatic failed");

    let handle = load_hook_test();
    std::thread::sleep(Duration::from_millis(1200));
    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "automatic refresh did not hook new module"
    );

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_auto_callback_can_unhook() {
    clear();
    ensure_ok(init(HookMode::Automatic, true), "init auto callback unhook");
    HOOKED_CALLBACK_UNHOOK_STATUS.store(-1, Ordering::Relaxed);
    HOOKED_CALLBACK_FROM_OTHER_THREAD.store(false, Ordering::Relaxed);
    HOOKED_CALLBACK_MAIN_THREAD.store(libc::pthread_self() as usize, Ordering::Relaxed);

    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        Some(unhook_from_hooked_callback),
        std::ptr::null_mut(),
    )
    .expect("hook_single auto callback unhook failed");
    let handle = load_hook_test();

    let deadline = Instant::now() + Duration::from_secs(5);
    while HOOKED_CALLBACK_UNHOOK_STATUS.load(Ordering::Relaxed) < 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        HOOKED_CALLBACK_UNHOOK_STATUS.load(Ordering::Relaxed),
        SrxHookErrno::Ok.as_i32(),
        "hook callback could not unhook while monitor refreshed"
    );
    assert!(
        HOOKED_CALLBACK_FROM_OTHER_THREAD.load(Ordering::Relaxed),
        "hook callback did not run on the monitor worker"
    );

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert_eq!(HOOK_A_COUNT.load(Ordering::Relaxed), 0);
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_auto_callback_can_clear_and_reinit() {
    clear();
    HOOKED_CALLBACK_CLEAR_REINIT_STATUS.store(-1, Ordering::Relaxed);
    HOOKED_CALLBACK_FROM_OTHER_THREAD.store(false, Ordering::Relaxed);
    HOOKED_CALLBACK_MAIN_THREAD.store(libc::pthread_self() as usize, Ordering::Relaxed);
    let baseline_threads = std::fs::read_dir("/proc/self/task")
        .expect("read process threads")
        .count();
    ensure_ok(init(HookMode::Automatic, true), "init auto callback clear");

    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        Some(clear_and_reinit_from_hooked_callback),
        std::ptr::null_mut(),
    )
    .expect("hook_single auto callback clear failed");
    let handle = load_hook_test();

    let deadline = Instant::now() + Duration::from_secs(5);
    while HOOKED_CALLBACK_CLEAR_REINIT_STATUS.load(Ordering::Acquire) < 0
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        HOOKED_CALLBACK_CLEAR_REINIT_STATUS.load(Ordering::Acquire),
        SrxHookErrno::Ok.as_i32(),
        "hook callback could not clear and reinitialize on the monitor worker"
    );
    assert!(
        HOOKED_CALLBACK_FROM_OTHER_THREAD.load(Ordering::Relaxed),
        "hook callback did not run on the monitor worker"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while std::fs::read_dir("/proc/self/task")
        .expect("read process threads")
        .count()
        > baseline_threads + 1
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        std::fs::read_dir("/proc/self/task")
            .expect("read process threads")
            .count(),
        baseline_threads + 1,
        "stopped monitor worker survived reinitialization"
    );

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    let _child_stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single after callback reinit failed");
    hook_test_trigger(handle);
    assert!(HOOK_A_COUNT.load(Ordering::Relaxed) > 0);
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_auto_reload_immediate_close() {
    clear();
    ensure_ok(init(HookMode::Automatic, true), "init auto immediate close");
    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single auto immediate close failed");

    for _ in 0..64 {
        let handle = load_hook_test();
        assert_eq!(libc::dlclose(handle), 0, "immediate dlclose failed");
    }

    let handle = load_hook_test();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut hit = false;
    while Instant::now() < deadline {
        HOOK_A_COUNT.store(0, Ordering::Relaxed);
        hook_test_trigger(handle);
        if HOOK_A_COUNT.load(Ordering::Relaxed) > 0 {
            hit = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        hit,
        "automatic hook missed after immediate load/unload churn"
    );
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_records_and_dlopen_callbacks() {
    clear();
    ensure_ok(init(HookMode::Automatic, true), "init records callback");
    assert!(!get_recordable(), "recordable should be false by default");
    set_recordable(true);
    assert!(get_recordable(), "recordable should be true after set");

    ensure_ok(
        add_dlopen_callback(
            Some(hook_test_dlopen_pre),
            Some(hook_test_dlopen_post),
            std::ptr::null_mut(),
        ),
        "add_dlopen_callback",
    );

    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single records failed");

    DLOPEN_PRE_COUNT.store(0, Ordering::Relaxed);
    DLOPEN_POST_COUNT.store(0, Ordering::Relaxed);

    let handle = load_hook_test();
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        DLOPEN_PRE_COUNT.load(Ordering::Relaxed) >= 1,
        "dlopen pre callback not fired"
    );
    assert!(
        DLOPEN_POST_COUNT.load(Ordering::Relaxed) >= 1,
        "dlopen post callback not fired"
    );

    let records = get_records(RECORD_ITEM_ALL).unwrap_or_default();
    assert!(
        records.contains("HOOK"),
        "operation records should contain HOOK entry"
    );

    ensure_ok(
        del_dlopen_callback(
            Some(hook_test_dlopen_pre),
            Some(hook_test_dlopen_post),
            std::ptr::null_mut(),
        ),
        "del_dlopen_callback",
    );

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_auto_reload_stability() {
    clear();
    ensure_ok(init(HookMode::Automatic, true), "init auto reload");

    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single auto reload failed");

    let first = load_hook_test();
    std::thread::sleep(Duration::from_millis(1200));
    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(first);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "automatic hook not hit on first load"
    );
    libc::dlclose(first);

    std::thread::sleep(Duration::from_millis(300));
    let second = load_hook_test();
    std::thread::sleep(Duration::from_millis(1200));
    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(second);
    assert!(
        HOOK_A_COUNT.load(Ordering::Relaxed) >= 1,
        "automatic hook not hit after reload"
    );

    libc::dlclose(second);
    clear();
}

pub unsafe fn scenario_auto_reload_forced_periodic_fallback() {
    clear();
    let _periodic_guard = ScopedEnv::set("SRX_HOOK_MONITOR_PERIODIC", "1");
    ensure_ok(
        init(HookMode::Automatic, true),
        "init auto reload periodic forced",
    );

    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single auto reload periodic forced failed");

    let rounds = env_usize("HOOK_TEST_AUTO_PERIODIC_ROUNDS", 24);
    let rss_before = current_rss_kb();
    for round in 0..rounds {
        let handle = load_hook_test();
        let mut hit = false;
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(100));
            HOOK_A_COUNT.store(0, Ordering::Relaxed);
            hook_test_trigger(handle);
            if HOOK_A_COUNT.load(Ordering::Relaxed) > 0 {
                hit = true;
                break;
            }
        }
        assert!(hit, "forced periodic fallback hook miss at round={round}");
        libc::dlclose(handle);
        std::thread::sleep(Duration::from_millis(40));
    }
    let rss_after = current_rss_kb();
    let delta = rss_after.saturating_sub(rss_before);
    println!(
        "auto reload periodic forced: rounds={} rss_delta={}KB",
        rounds, delta
    );
    assert!(
        delta < 4096,
        "forced periodic fallback rss delta too large: {delta}KB"
    );
    clear();
}

pub unsafe fn scenario_auto_reload_forced_periodic_disabled() {
    clear();
    let _periodic_guard = ScopedEnv::set("SRX_HOOK_MONITOR_PERIODIC", "0");
    ensure_ok(
        init(HookMode::Automatic, true),
        "init auto reload periodic disabled",
    );

    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single auto reload periodic disabled failed");

    let rounds = env_usize("HOOK_TEST_AUTO_PERIODIC_DISABLED_ROUNDS", 16);
    for round in 0..rounds {
        let handle = load_hook_test();
        let mut hit = false;
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(80));
            HOOK_A_COUNT.store(0, Ordering::Relaxed);
            hook_test_trigger(handle);
            if HOOK_A_COUNT.load(Ordering::Relaxed) > 0 {
                hit = true;
                break;
            }
        }
        assert!(hit, "forced periodic disabled hook miss at round={round}");
        libc::dlclose(handle);
        std::thread::sleep(Duration::from_millis(30));
    }
    clear();
}

pub unsafe fn scenario_auto_reload_long_stress() {
    clear();
    ensure_ok(
        init(HookMode::Automatic, true),
        "init auto reload long stress",
    );

    ensure_ok(
        add_dlopen_callback(
            Some(hook_test_dlopen_pre),
            Some(hook_test_dlopen_post),
            std::ptr::null_mut(),
        ),
        "add_dlopen_callback long stress",
    );
    DLOPEN_PRE_COUNT.store(0, Ordering::Relaxed);
    DLOPEN_POST_COUNT.store(0, Ordering::Relaxed);

    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single auto reload long stress failed");

    let rounds = env_usize("HOOK_TEST_AUTO_RELOAD_ROUNDS", 120);
    let rss_before = current_rss_kb();
    for round in 0..rounds {
        let handle = load_hook_test();
        let mut hit = 0usize;
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(80));
            HOOK_A_COUNT.store(0, Ordering::Relaxed);
            hook_test_trigger(handle);
            hit = HOOK_A_COUNT.load(Ordering::Relaxed);
            if hit >= 1 {
                break;
            }
        }
        assert!(
            hit >= 1,
            "automatic long stress hook miss at round={round}, dlopen_pre={}, dlopen_post={}",
            DLOPEN_PRE_COUNT.load(Ordering::Relaxed),
            DLOPEN_POST_COUNT.load(Ordering::Relaxed),
        );
        libc::dlclose(handle);
        std::thread::sleep(Duration::from_millis(40));
    }

    let rss_after = current_rss_kb();
    let delta = rss_after.saturating_sub(rss_before);
    let dlopen_pre = DLOPEN_PRE_COUNT.load(Ordering::Relaxed);
    let dlopen_post = DLOPEN_POST_COUNT.load(Ordering::Relaxed);
    println!(
        "auto reload long stress: rounds={} pre={} post={} rss_delta={}KB",
        rounds, dlopen_pre, dlopen_post, delta
    );
    assert!(
        dlopen_pre >= rounds,
        "dlopen pre callback count too small: {dlopen_pre}"
    );
    assert!(
        dlopen_post >= rounds,
        "dlopen post callback count too small: {dlopen_post}"
    );
    assert!(
        delta < 4096,
        "auto reload long stress rss delta too large: {delta}KB"
    );

    ensure_ok(
        del_dlopen_callback(
            Some(hook_test_dlopen_pre),
            Some(hook_test_dlopen_post),
            std::ptr::null_mut(),
        ),
        "del_dlopen_callback long stress",
    );

    clear();
}

pub unsafe fn scenario_auto_reload_marathon() {
    clear();
    ensure_ok(init(HookMode::Automatic, true), "init auto reload marathon");

    ensure_ok(
        add_dlopen_callback(
            Some(hook_test_dlopen_pre),
            Some(hook_test_dlopen_post),
            std::ptr::null_mut(),
        ),
        "add_dlopen_callback auto marathon",
    );
    DLOPEN_PRE_COUNT.store(0, Ordering::Relaxed);
    DLOPEN_POST_COUNT.store(0, Ordering::Relaxed);
    HOOK_A_COUNT.store(0, Ordering::Relaxed);

    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single auto reload marathon failed");

    let rounds = env_usize("HOOK_TEST_AUTO_MARATHON_ROUNDS", 2000);
    let report_step = env_usize("HOOK_TEST_AUTO_MARATHON_REPORT_STEP", 200);
    let rss_before = current_rss_kb();
    let start = Instant::now();
    for round in 0..rounds {
        let handle = load_hook_test();
        let mut hit = false;
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(40));
            let count_before = HOOK_A_COUNT.load(Ordering::Relaxed);
            hook_test_trigger(handle);
            let count_after = HOOK_A_COUNT.load(Ordering::Relaxed);
            if count_after > count_before {
                hit = true;
                break;
            }
        }
        assert!(hit, "auto reload marathon hook miss at round={round}");
        libc::dlclose(handle);

        if (round + 1) % report_step == 0 {
            println!(
                "auto reload marathon progress: rounds={}/{} pre={} post={} elapsed={:?}",
                round + 1,
                rounds,
                DLOPEN_PRE_COUNT.load(Ordering::Relaxed),
                DLOPEN_POST_COUNT.load(Ordering::Relaxed),
                start.elapsed()
            );
        }
    }

    let rss_after = current_rss_kb();
    let delta = rss_after.saturating_sub(rss_before);
    let dlopen_pre = DLOPEN_PRE_COUNT.load(Ordering::Relaxed);
    let dlopen_post = DLOPEN_POST_COUNT.load(Ordering::Relaxed);
    println!(
        "auto reload marathon done: rounds={} pre={} post={} elapsed={:?} rss_delta={}KB",
        rounds,
        dlopen_pre,
        dlopen_post,
        start.elapsed(),
        delta
    );
    assert!(
        dlopen_pre >= rounds,
        "auto reload marathon pre count too small: {dlopen_pre}"
    );
    assert!(
        dlopen_post >= rounds,
        "auto reload marathon post count too small: {dlopen_post}"
    );
    assert!(
        delta < 8192,
        "auto reload marathon rss delta too large: {delta}KB"
    );

    ensure_ok(
        del_dlopen_callback(
            Some(hook_test_dlopen_pre),
            Some(hook_test_dlopen_post),
            std::ptr::null_mut(),
        ),
        "del_dlopen_callback auto marathon",
    );

    clear();
}
