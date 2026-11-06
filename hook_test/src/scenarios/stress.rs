use std::ffi::{CStr, c_void};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use srx_hook::{HookMode, clear, hook_single, init, refresh, unhook};

use crate::test_ctx::{
    CLEAR_PROXY_ENTERED, CLEAR_PROXY_RELEASE, CLEAR_PROXY_RESULT, CLEAR_SELF_PROXY_ENTERED,
    CLEAR_SELF_PROXY_RELEASE, CLEAR_SELF_PROXY_RESULT, HOOK_A_COUNT, current_rss_kb, ensure_ok,
    env_usize, hook_puts_clear_self_and_wait, hook_puts_quiet, hook_puts_wait_for_clear,
    hook_test_trigger, load_hook_test,
};

pub unsafe fn scenario_concurrent_hooking_stress() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init concurrent stress");
    let handle = load_hook_test();

    let worker_count = env_usize("HOOK_TEST_CONCURRENT_WORKERS", 72);
    let worker_calls = env_usize("HOOK_TEST_CONCURRENT_CALLS", 80);
    let hook_rounds = env_usize("HOOK_TEST_CONCURRENT_ROUNDS", 80);

    let start_barrier = Arc::new(Barrier::new(worker_count + 1));
    let mut workers = Vec::with_capacity(worker_count);
    let handle_addr = handle as usize;
    for _ in 0..worker_count {
        let barrier = Arc::clone(&start_barrier);
        let worker_handle = handle_addr;
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..worker_calls {
                unsafe { hook_test_trigger(worker_handle as *mut c_void) };
            }
        }));
    }

    start_barrier.wait();
    for _ in 0..hook_rounds {
        let stub = hook_single(
            "libhook_test.so",
            None,
            "puts",
            hook_puts_quiet as *mut c_void,
            None,
            std::ptr::null_mut(),
        )
        .expect("hook_single concurrent failed");
        ensure_ok(refresh().0, "refresh concurrent");
        std::thread::sleep(Duration::from_millis(2));
        ensure_ok(unhook(stub), "unhook concurrent");
    }

    for worker in workers {
        worker.join().expect("concurrent worker panic");
    }

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_clear_with_proxy_in_flight() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init clear in-flight");
    let handle = load_hook_test();
    hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_wait_for_clear as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single clear in-flight failed");
    ensure_ok(refresh().0, "refresh clear in-flight");
    CLEAR_PROXY_ENTERED.store(false, Ordering::Relaxed);
    CLEAR_PROXY_RELEASE.store(false, Ordering::Relaxed);
    CLEAR_PROXY_RESULT.store(-1, Ordering::Relaxed);

    let handle_addr = handle as usize;
    let worker = std::thread::spawn(move || unsafe {
        hook_test_trigger(handle_addr as *mut c_void);
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !CLEAR_PROXY_ENTERED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    if !CLEAR_PROXY_ENTERED.load(Ordering::Acquire) {
        CLEAR_PROXY_RELEASE.store(true, Ordering::Release);
        worker.join().expect("clear worker join after timeout");
        panic!("proxy did not enter before clear");
    }

    clear();
    CLEAR_PROXY_RELEASE.store(true, Ordering::Release);
    worker.join().expect("clear worker join");
    assert!(
        CLEAR_PROXY_RESULT.load(Ordering::Acquire) >= 0,
        "in-flight proxy lost its previous function during clear"
    );
    libc::dlclose(handle);
}

pub unsafe fn scenario_clear_from_proxy_keeps_live_trampoline() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init clear from proxy");
    let handle = load_hook_test();
    let stale_stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_clear_self_and_wait as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single clear from proxy failed");
    ensure_ok(refresh().0, "refresh clear from proxy");
    CLEAR_SELF_PROXY_ENTERED.store(false, Ordering::Relaxed);
    CLEAR_SELF_PROXY_RELEASE.store(false, Ordering::Relaxed);
    CLEAR_SELF_PROXY_RESULT.store(-1, Ordering::Relaxed);

    let handle_addr = handle as usize;
    let worker =
        std::thread::spawn(move || unsafe { hook_test_trigger(handle_addr as *mut c_void) });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !CLEAR_SELF_PROXY_ENTERED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    if !CLEAR_SELF_PROXY_ENTERED.load(Ordering::Acquire) {
        CLEAR_SELF_PROXY_RELEASE.store(true, Ordering::Release);
        worker
            .join()
            .expect("clear proxy worker join after timeout");
        panic!("proxy did not clear the runtime");
    }

    std::thread::sleep(Duration::from_secs(11));
    ensure_ok(init(HookMode::Manual, true), "reinit after proxy clear");
    let fresh_stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single after proxy clear failed");
    ensure_ok(refresh().0, "refresh after proxy clear");

    CLEAR_SELF_PROXY_RELEASE.store(true, Ordering::Release);
    worker.join().expect("clear proxy worker panic");
    assert_ne!(stale_stub, fresh_stub, "clear reused a stale task identity");
    assert_eq!(unhook(stale_stub), srx_hook::SrxHookErrno::InvalidArg);
    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    hook_test_trigger(handle);
    assert_eq!(
        HOOK_A_COUNT.load(Ordering::Relaxed),
        1,
        "stale unhook removed the new task"
    );
    assert!(
        CLEAR_SELF_PROXY_RESULT.load(Ordering::Acquire) >= 0,
        "live proxy could not return through its previous function after clear"
    );
    clear();
    libc::dlclose(handle);
}

pub unsafe fn scenario_stale_preentry_target_survives_clear() {
    unsafe fn resolve<T: Copy>(handle: *mut c_void, name: &CStr) -> T {
        let symbol = unsafe { libc::dlsym(handle, name.as_ptr()) };
        assert!(!symbol.is_null(), "missing test symbol: {name:?}");
        assert_eq!(
            std::mem::size_of::<T>(),
            std::mem::size_of_val(&symbol),
            "test symbol has the wrong function-pointer type: {name:?}"
        );
        unsafe { std::mem::transmute_copy(&symbol) }
    }

    clear();
    ensure_ok(init(HookMode::Manual, true), "init stale preentry target");
    let handle = load_hook_test();
    let _stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single stale preentry target failed");
    ensure_ok(refresh().0, "refresh stale preentry target");
    HOOK_A_COUNT.store(0, Ordering::Relaxed);

    type Action = unsafe extern "C" fn();
    type GetBool = unsafe extern "C" fn() -> libc::c_int;
    type GetAddress = unsafe extern "C" fn() -> usize;
    let reset = unsafe { resolve::<Action>(handle, c"hook_test_reset_held_puts") };
    let trigger = unsafe { resolve::<Action>(handle, c"hook_test_trigger_held_puts") };
    let ready = unsafe { resolve::<GetBool>(handle, c"hook_test_held_puts_ready") };
    let held_target = unsafe { resolve::<GetAddress>(handle, c"hook_test_held_puts_target") };
    let current_target = unsafe { resolve::<GetAddress>(handle, c"hook_test_current_puts_target") };
    let release = unsafe { resolve::<Action>(handle, c"hook_test_release_held_puts") };
    let result = unsafe { resolve::<GetBool>(handle, c"hook_test_held_puts_result") };

    unsafe { reset() };
    let worker = std::thread::spawn(move || unsafe { trigger() });
    let deadline = Instant::now() + Duration::from_secs(5);
    while unsafe { ready() } == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    if unsafe { ready() } == 0 {
        unsafe { release() };
        worker.join().expect("preentry worker join after timeout");
        panic!("worker did not capture the patched PLT target");
    }

    let old_target = unsafe { held_target() };
    let original = unsafe { libc::dlsym(handle, c"puts".as_ptr()) } as usize;
    clear();
    std::thread::sleep(Duration::from_secs(11));
    ensure_ok(
        init(HookMode::Manual, true),
        "reinit after stale preentry clear",
    );
    let new_stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single after stale preentry clear failed");
    ensure_ok(refresh().0, "refresh after stale preentry clear");
    let new_target = unsafe { current_target() };

    unsafe { release() };
    worker.join().expect("stale preentry worker panic");
    let result = unsafe { result() };
    assert_ne!(old_target, 0, "worker captured a null PLT target");
    assert_ne!(
        old_target, original,
        "worker did not capture the hook trampoline"
    );
    assert_ne!(
        old_target, new_target,
        "retired trampoline address was reused"
    );
    assert!(
        result >= 0,
        "stale trampoline did not reach the original function"
    );
    assert_eq!(
        HOOK_A_COUNT.load(Ordering::Relaxed),
        0,
        "stale trampoline entered the newly installed proxy"
    );

    ensure_ok(unhook(new_stub), "unhook after stale preentry clear");
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_persistent_hook_parallel_stress() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init persistent stress");
    let handle = load_hook_test();

    let stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single persistent stress failed");
    ensure_ok(refresh().0, "refresh persistent stress");

    let worker_count = env_usize("HOOK_TEST_PERSISTENT_WORKERS", 56);
    let worker_calls = env_usize("HOOK_TEST_PERSISTENT_CALLS", 320);
    let expected_min = worker_count * worker_calls;
    let start_barrier = Arc::new(Barrier::new(worker_count));
    HOOK_A_COUNT.store(0, Ordering::Relaxed);

    let mut workers = Vec::with_capacity(worker_count);
    let handle_addr = handle as usize;
    for _ in 0..worker_count {
        let barrier = Arc::clone(&start_barrier);
        let worker_handle = handle_addr;
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..worker_calls {
                unsafe { hook_test_trigger(worker_handle as *mut c_void) };
            }
        }));
    }
    for worker in workers {
        worker.join().expect("persistent worker panic");
    }

    let hit_count = HOOK_A_COUNT.load(Ordering::Relaxed);
    println!("persistent stress: expected>={expected_min} actual={hit_count}");
    assert!(
        hit_count >= expected_min,
        "persistent stress lost calls: expected>={expected_min}, actual={hit_count}"
    );

    ensure_ok(unhook(stub), "unhook persistent stress");
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_perf_smoke() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init perf");
    let handle = load_hook_test();

    let stub = hook_single(
        "libhook_test.so",
        None,
        "puts",
        hook_puts_quiet as *mut c_void,
        None,
        std::ptr::null_mut(),
    )
    .expect("hook_single perf failed");
    ensure_ok(refresh().0, "refresh perf");

    HOOK_A_COUNT.store(0, Ordering::Relaxed);
    let start = Instant::now();
    for _ in 0..1000 {
        hook_test_trigger(handle);
    }
    let elapsed = start.elapsed();
    let count = HOOK_A_COUNT.load(Ordering::Relaxed);
    assert!(count >= 1000, "perf loop hook lost calls: {count}");
    println!("perf smoke: 1000 trigger calls in {:?}", elapsed);

    ensure_ok(unhook(stub), "unhook perf");
    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_leak_smoke() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init leak");
    let handle = load_hook_test();
    let rss_before = current_rss_kb();

    let leak_rounds = env_usize("HOOK_TEST_LEAK_ROUNDS", 320);
    for _ in 0..leak_rounds {
        let stub = hook_single(
            "libhook_test.so",
            None,
            "puts",
            hook_puts_quiet as *mut c_void,
            None,
            std::ptr::null_mut(),
        )
        .expect("hook_single leak failed");
        ensure_ok(refresh().0, "refresh leak");
        hook_test_trigger(handle);
        ensure_ok(unhook(stub), "unhook leak");
    }

    let rss_after = current_rss_kb();
    let delta = rss_after.saturating_sub(rss_before);
    println!(
        "leak smoke: rounds={} rss before={}KB after={}KB delta={}KB",
        leak_rounds, rss_before, rss_after, delta
    );
    assert!(delta < 4096, "rss delta too large: {}KB", delta);

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_manual_churn_marathon() {
    clear();
    ensure_ok(init(HookMode::Manual, true), "init manual churn marathon");
    let handle = load_hook_test();

    let rounds = env_usize("HOOK_TEST_MARATHON_ROUNDS", 4000);
    let report_step = env_usize("HOOK_TEST_MARATHON_REPORT_STEP", 400);
    let rss_before = current_rss_kb();
    let start = Instant::now();

    for round in 0..rounds {
        let stub = hook_single(
            "libhook_test.so",
            None,
            "puts",
            hook_puts_quiet as *mut c_void,
            None,
            std::ptr::null_mut(),
        )
        .expect("hook_single manual churn marathon failed");
        ensure_ok(refresh().0, "refresh manual churn marathon");
        hook_test_trigger(handle);
        ensure_ok(unhook(stub), "unhook manual churn marathon");

        if (round + 1) % report_step == 0 {
            let elapsed = start.elapsed();
            println!(
                "manual churn marathon progress: rounds={}/{} elapsed={:?}",
                round + 1,
                rounds,
                elapsed
            );
        }
    }

    let rss_after = current_rss_kb();
    let delta = rss_after.saturating_sub(rss_before);
    let elapsed = start.elapsed();
    println!(
        "manual churn marathon done: rounds={} elapsed={:?} rss_delta={}KB",
        rounds, elapsed, delta
    );
    assert!(
        delta < 8192,
        "manual churn marathon rss delta too large: {delta}KB"
    );

    libc::dlclose(handle);
    clear();
}

pub unsafe fn scenario_soak_suite() {
    let rounds = env_usize("HOOK_TEST_SOAK_ROUNDS", 6);
    let report_step = env_usize("HOOK_TEST_SOAK_REPORT_STEP", 1);
    let rss_before = current_rss_kb();
    let start = Instant::now();

    for round in 0..rounds {
        super::automatic::scenario_auto_reload_long_stress();
        scenario_concurrent_hooking_stress();
        scenario_persistent_hook_parallel_stress();
        scenario_leak_smoke();

        if (round + 1) % report_step == 0 {
            let rss_now = current_rss_kb();
            let rss_delta = rss_now.saturating_sub(rss_before);
            println!(
                "soak suite progress: rounds={}/{} elapsed={:?} rss_delta={}KB",
                round + 1,
                rounds,
                start.elapsed(),
                rss_delta
            );
        }
    }

    let rss_after = current_rss_kb();
    let delta = rss_after.saturating_sub(rss_before);
    println!(
        "soak suite done: rounds={} elapsed={:?} rss_delta={}KB",
        rounds,
        start.elapsed(),
        delta
    );
    assert!(delta < 32768, "soak suite rss delta too large: {delta}KB");
}
