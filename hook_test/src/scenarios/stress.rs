use std::ffi::c_void;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use srx_hook::{HookMode, clear, hook_single, init, refresh, unhook};

use crate::test_ctx::{
    HOOK_A_COUNT, current_rss_kb, ensure_ok, env_usize, hook_puts_quiet, hook_test_trigger,
    load_hook_test,
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
        leak_rounds,
        rss_before, rss_after, delta
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
    assert!(delta < 8192, "manual churn marathon rss delta too large: {delta}KB");

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
