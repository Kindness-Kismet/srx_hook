// monitor 线程轮询循环，结合事件驱动与周期性轮询两种刷新策略
use std::sync::atomic::Ordering;
use std::ffi::c_void;
use std::time::Duration;

use super::{
    MONITOR_FALLBACK_BURST_ROUNDS, MONITOR_FALLBACK_REFRESH_INTERVAL_MAX,
    MONITOR_FALLBACK_REFRESH_INTERVAL_MIN, MONITOR_PERIODIC_ENABLED,
};
use crate::runtime::state::{MutexPoisonRecover, RwLockPoisonRecover};

// 周期性轮询状态，管理退避间隔和 burst 轮次
struct FallbackPollState {
    interval: Duration,
    // burst 阶段保持最小间隔，耗尽后开始指数退避
    burst_rounds: u8,
    last_module_epoch: Option<(u64, u64)>,
}

// 模块 epoch 变化分类，用于决定刷新策略
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EpochDelta {
    Unchanged,
    AddedOnly,
    Changed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeriodicRefreshKind {
    NewModulesOnly,
    Full,
}

impl FallbackPollState {
    fn new() -> Self {
        Self {
            interval: MONITOR_FALLBACK_REFRESH_INTERVAL_MIN,
            burst_rounds: MONITOR_FALLBACK_BURST_ROUNDS,
            last_module_epoch: super::refresh::module_epoch(),
        }
    }

    fn timeout(&self) -> Duration {
        self.interval
    }

    fn on_event_refresh(&mut self) {
        self.interval = MONITOR_FALLBACK_REFRESH_INTERVAL_MIN;
        self.burst_rounds = MONITOR_FALLBACK_BURST_ROUNDS;
        self.last_module_epoch = super::refresh::module_epoch();
    }

    fn on_periodic_refresh(&mut self, module_changed: bool) {
        if module_changed {
            self.on_event_refresh();
            return;
        }

        if self.burst_rounds > 0 {
            self.burst_rounds -= 1;
            return;
        }

        let doubled_ms = self
            .interval
            .as_millis()
            .saturating_mul(2)
            .min(MONITOR_FALLBACK_REFRESH_INTERVAL_MAX.as_millis());
        let doubled_ms = doubled_ms as u64;
        self.interval = Duration::from_millis(doubled_ms);
    }

    fn reset_for_event_mode(&mut self) {
        self.interval = MONITOR_FALLBACK_REFRESH_INTERVAL_MIN;
        self.burst_rounds = MONITOR_FALLBACK_BURST_ROUNDS;
    }

    fn poll_epoch_delta(&mut self) -> EpochDelta {
        let Some(epoch) = super::refresh::module_epoch() else {
            self.last_module_epoch = None;
            return EpochDelta::Unknown;
        };
        let delta = classify_epoch_delta(self.last_module_epoch, epoch);
        self.last_module_epoch = Some(epoch);
        delta
    }
}

fn classify_epoch_delta(last: Option<(u64, u64)>, current: (u64, u64)) -> EpochDelta {
    let Some((last_adds, last_subs)) = last else {
        return EpochDelta::Changed;
    };
    let (current_adds, current_subs) = current;
    if current_adds == last_adds && current_subs == last_subs {
        return EpochDelta::Unchanged;
    }
    if current_subs == last_subs && current_adds > last_adds {
        return EpochDelta::AddedOnly;
    }
    EpochDelta::Changed
}

pub(super) fn monitor_loop() {
    let mut fallback_poll = FallbackPollState::new();

    loop {
        super::maybe_install_legacy_hooks_on_demand();

        let mut state = super::GLOBAL.state.lock_or_poison();
        let mut periodic_refresh = false;
        while state.monitor_running && !state.refresh_requested {
            if MONITOR_PERIODIC_ENABLED.load(Ordering::Acquire) {
                let timeout = fallback_poll.timeout();
                let (next_state, wait_result) = super::GLOBAL
                    .condvar
                    .wait_timeout(state, timeout)
                    .unwrap_or_else(|e| e.into_inner());
                state = next_state;
                if state.refresh_requested {
                    break;
                }
                if wait_result.timed_out() {
                    periodic_refresh = true;
                    break;
                }
            } else {
                fallback_poll.reset_for_event_mode();
                state = super::GLOBAL.condvar.wait(state).unwrap_or_else(|e| e.into_inner());
            }
        }
        if !state.monitor_running {
            break;
        }
        let known_module_count_before = state.known_modules.len();
        let event_refresh = state.refresh_requested;
        let pending_handles = std::mem::take(&mut state.pending_module_handles);
        state.pending_module_handle_set.clear();
        state.refresh_requested = false;
        drop(state);

        if !pending_handles.is_empty() {
            super::log::debug(format_args!(
                "consume {} pending module handles",
                pending_handles.len()
            ));
            for handle in pending_handles {
                super::refresh::observe_module_handle(handle as *mut c_void);
            }
        }

        let mut periodic_epoch_changed = false;
        let mut periodic_refresh_kind = PeriodicRefreshKind::Full;
        if periodic_refresh {
            match fallback_poll.poll_epoch_delta() {
                EpochDelta::Unchanged => {
                    fallback_poll.on_periodic_refresh(false);
                    continue;
                }
                EpochDelta::AddedOnly => {
                    periodic_epoch_changed = true;
                    periodic_refresh_kind = PeriodicRefreshKind::NewModulesOnly;
                    super::log::debug(format_args!(
                        "fallback periodic refresh kind=new-modules"
                    ));
                }
                EpochDelta::Changed => {
                    periodic_epoch_changed = true;
                    periodic_refresh_kind = PeriodicRefreshKind::Full;
                    super::log::debug(format_args!("fallback periodic refresh kind=full"));
                }
                EpochDelta::Unknown => {
                    periodic_refresh_kind = PeriodicRefreshKind::Full;
                    super::log::debug(format_args!(
                        "fallback periodic refresh kind=full unknown-epoch"
                    ));
                }
            }
        }

        let _dlclose_guard = super::GLOBAL.dlclose_lock.read_or_poison();
        let _refresh_guard = super::GLOBAL.refresh_mutex.lock_or_poison();
        let mut state = super::GLOBAL.state.lock_or_poison();
        let (status, events, _errors) = if periodic_refresh {
            match periodic_refresh_kind {
                PeriodicRefreshKind::NewModulesOnly => super::refresh::refresh_new_modules(&mut state),
                PeriodicRefreshKind::Full => super::refresh::refresh_all(&mut state),
            }
        } else {
            super::refresh::refresh_new_modules(&mut state)
        };
        if status != super::Errno::Ok {
            super::log::warn(format_args!("auto refresh status {:?}", status));
        }
        let known_module_count_after = state.known_modules.len();
        drop(state);
        super::super::invoke_callbacks(events);

        if !MONITOR_PERIODIC_ENABLED.load(Ordering::Acquire) {
            continue;
        }
        if periodic_refresh {
            fallback_poll.on_periodic_refresh(
                periodic_epoch_changed || known_module_count_after != known_module_count_before,
            );
            continue;
        }
        if event_refresh {
            fallback_poll.on_event_refresh();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_poll_backoff_after_idle_rounds() {
        let mut state = FallbackPollState::new();
        for _ in 0..MONITOR_FALLBACK_BURST_ROUNDS {
            state.on_periodic_refresh(false);
        }

        assert_eq!(state.timeout(), MONITOR_FALLBACK_REFRESH_INTERVAL_MIN);
        state.on_periodic_refresh(false);

        assert_eq!(
            state.timeout(),
            Duration::from_millis(MONITOR_FALLBACK_REFRESH_INTERVAL_MIN.as_millis() as u64 * 2),
        );
    }

    #[test]
    fn fallback_poll_reset_on_event() {
        let mut state = FallbackPollState::new();
        for _ in 0..8 {
            state.on_periodic_refresh(false);
        }
        assert!(state.timeout() > MONITOR_FALLBACK_REFRESH_INTERVAL_MIN);

        state.on_event_refresh();
        assert_eq!(state.timeout(), MONITOR_FALLBACK_REFRESH_INTERVAL_MIN);
    }

    #[test]
    fn fallback_poll_reset_on_module_change() {
        let mut state = FallbackPollState::new();
        for _ in 0..8 {
            state.on_periodic_refresh(false);
        }
        assert!(state.timeout() > MONITOR_FALLBACK_REFRESH_INTERVAL_MIN);

        state.on_periodic_refresh(true);
        assert_eq!(state.timeout(), MONITOR_FALLBACK_REFRESH_INTERVAL_MIN);
    }

    #[test]
    fn classify_epoch_delta_added_only() {
        let delta = classify_epoch_delta(Some((10, 4)), (12, 4));
        assert_eq!(delta, EpochDelta::AddedOnly);
    }

    #[test]
    fn classify_epoch_delta_changed_on_sub() {
        let delta = classify_epoch_delta(Some((10, 4)), (10, 5));
        assert_eq!(delta, EpochDelta::Changed);
    }

    #[test]
    fn classify_epoch_delta_unchanged() {
        let delta = classify_epoch_delta(Some((7, 3)), (7, 3));
        assert_eq!(delta, EpochDelta::Unchanged);
    }
}
