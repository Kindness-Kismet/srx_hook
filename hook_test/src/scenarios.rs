mod automatic;
mod basic;
mod cycles;
mod filters;
mod stack_api;
mod stress;

use crate::test_ctx::env_flag;

pub unsafe fn run_all() {
    run(
        "cfi-slowpath-disabled",
        basic::scenario_cfi_slowpath_disabled,
    );
    run("single", basic::scenario_single_hook_unhook);
    run("multi-chain", basic::scenario_multi_hook_chain_unhook);
    run(
        "missing-leave-recovery",
        basic::scenario_missing_leave_recovery,
    );
    run(
        "same-proxy-multi-stub",
        basic::scenario_same_proxy_multi_stub_unhook,
    );
    run(
        "return-address-stack",
        stack_api::scenario_return_address_stack_api,
    );
    run("ignore", basic::scenario_ignore);
    run("automatic", automatic::scenario_automatic_refresh);
    run(
        "records-dlopen-callbacks",
        automatic::scenario_records_and_dlopen_callbacks,
    );
    run("callee-filter", filters::scenario_callee_filter);
    run(
        "callee-filter-lazy-bind",
        filters::scenario_callee_filter_lazy_bind,
    );
    run(
        "base-qualified-path-rule",
        filters::scenario_base_qualified_path_rule,
    );
    run(
        "single-same-basename-multi-instance",
        filters::scenario_single_same_basename_multi_instance,
    );
    run(
        "instance-qualified-path-rule",
        filters::scenario_instance_qualified_path_rule,
    );
    run(
        "ignore-instance-qualified-rule",
        filters::scenario_ignore_instance_qualified_rule,
    );
    run(
        "instance-rule-from-handle-api",
        filters::scenario_instance_rule_from_handle_api,
    );
    run(
        "identity-with-symbol-api",
        filters::scenario_identity_with_symbol_api,
    );
    run(
        "identity-api-consistency",
        filters::scenario_identity_api_consistency,
    );
    run(
        "namespace-rule-from-handle-api",
        filters::scenario_namespace_rule_from_handle_api,
    );
    run("auto-reload", automatic::scenario_auto_reload_stability);
    run(
        "auto-reload-periodic-forced",
        automatic::scenario_auto_reload_forced_periodic_fallback,
    );
    run(
        "auto-reload-periodic-disabled",
        automatic::scenario_auto_reload_forced_periodic_disabled,
    );
    run(
        "auto-reload-long-stress",
        automatic::scenario_auto_reload_long_stress,
    );
    run("cycle-guard-auto", cycles::scenario_cycle_guard_auto);
    run(
        "cycle-guard-manual-no-leave",
        cycles::scenario_cycle_guard_manual_no_leave,
    );
    run(
        "concurrent-stress",
        stress::scenario_concurrent_hooking_stress,
    );
    run(
        "persistent-parallel-stress",
        stress::scenario_persistent_hook_parallel_stress,
    );
    run("perf", stress::scenario_perf_smoke);
    run("leak", stress::scenario_leak_smoke);
    if env_flag("HOOK_TEST_AUTO_MARATHON") {
        run(
            "auto-reload-marathon",
            automatic::scenario_auto_reload_marathon,
        );
    }
    if env_flag("HOOK_TEST_MARATHON") {
        run(
            "manual-churn-marathon",
            stress::scenario_manual_churn_marathon,
        );
    }
    if env_flag("HOOK_TEST_SOAK") {
        run("soak-suite", stress::scenario_soak_suite);
    }
}

unsafe fn run(name: &str, scenario: unsafe fn()) {
    println!("scenario: {name}");
    scenario();
}
