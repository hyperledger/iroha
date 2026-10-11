//! Pacemaker (spec §9): view timeouts `T(L)` growing ×1.5 per level (integer arithmetic),
//! levels, start-level adaptation, the timer formulas of §9.1, retransmit and retry backoffs,
//! and configuration validation (§9.4).
//!
//! All timers are local; nodes need not agree on them, and no validity rule depends on them.

use crate::{
    api::{ConfigError, LocalParams},
    types::{ChainParams, HeightConfig, Millis, fault_threshold},
};

/// `φ = 0.5`, the share of a view's timeout after which the stage-2 backstop fires.
pub const PHI_NUM: u64 = 1;
/// Denominator of `φ`.
pub const PHI_DEN: u64 = 2;
/// Initial `qc_lat_ewma`.
pub const QC_LATENCY_INITIAL: Millis = 250;
/// Lower bound of `t_retx`.
pub const T_RETX_MIN: Millis = 50;
/// First backoff of an execution retry after `Failed` (§4.2).
pub const EXEC_RETRY_INITIAL: Millis = 100;
/// Nominal network delay `Δ_nom` used by config validation (§9.4).
pub const DELTA_NOMINAL: Millis = 500;
/// Nominal local processing delay `δ_nom` used by config validation (§9.4).
pub const LOCAL_DELAY_NOMINAL: Millis = 50;
/// Extra frame budget over `max_block_bytes`: the certificate/header allowance plus the
/// complete bounded control frame and worst-case member key/TC overhead up to the generic core committee bound (§9.4, O10).
#[allow(clippy::cast_possible_truncation, reason = "const operands ≤ 64 KiB")]
pub const FRAME_OVERHEAD: u32 = 64 * 1024
    + crate::types::MAX_COMMITTEE_SIZE as u32 * (crate::types::MAX_PUBLIC_KEY_LEN + 64) as u32
    + crate::types::MAX_CONTROL_WITNESS_BYTES as u32
    + 32;
/// Upper bound of `T_max_eff` (2^40 ms ≈ 35 years). Up to this bound [`view_timeout`] and
/// [`level_cap`] are exact in 128-bit arithmetic.
// SPEC: §9.4 does not bound `T_max_eff`; the clamp only matters for absurd chain parameters.
// (Appendix E, E21)
pub const MAX_VIEW_TIMEOUT: Millis = 1 << 40;

/// `T(L) = min(t_max_eff, t_base · 1.5^L)`, rounded down to whole milliseconds and computed
/// exactly with integers (`t_base · 3^L / 2^L`; exact for `t_max_eff ≤ MAX_VIEW_TIMEOUT`,
/// saturating to `t_max_eff` beyond).
pub fn view_timeout(t_base: Millis, t_max_eff: Millis, level: u32) -> Millis {
    uncapped_timeouts(t_base, t_max_eff)
        .nth(usize::try_from(level).unwrap_or(usize::MAX))
        .unwrap_or(t_max_eff)
}

/// `level_cap = ceil(log_1.5(t_max_eff / t_base))`, with exact integer progression.
pub fn level_cap(t_base: Millis, t_max_eff: Millis) -> u32 {
    if t_base == 0 {
        return 0;
    }
    u32::try_from(uncapped_timeouts(t_base, t_max_eff).count()).expect("u128 growth is bounded")
}

/// Exact rational growth before the cap; numerator/denominator overflow saturates callers.
fn uncapped_timeouts(t_base: Millis, cap: Millis) -> impl Iterator<Item = Millis> {
    std::iter::successors(Some((u128::from(t_base), 1_u128)), |(num, den)| {
        Some((num.checked_mul(3)?, den.checked_mul(2)?))
    })
    .map(|(num, den)| num / den)
    .take_while(move |value| *value < u128::from(cap))
    .map(|value| Millis::try_from(value).expect("below the Millis cap"))
}

/// `⌈log2(x)⌉` for `x ≥ 1` (`0` for `x ≤ 1`).
pub fn ceil_log2(x: u64) -> u32 {
    u64::BITS - x.saturating_sub(1).leading_zeros()
}

/// `T_req(nominal)` (§8.2 L3, §9.4) for a committee of `n` members:
/// `2·(σ + build_timeout + 3Δ + F + A_max + E_max) + 4δ` with `Δ = 500 ms`, `δ = 50 ms`,
/// `σ = rebroadcast_interval + Δ`, `F = ⌈log2(f+1)⌉ · fetch_retry`.
pub fn t_req_nominal(local: &LocalParams, chain: &ChainParams, n: usize) -> Millis {
    let f = u64::try_from(fault_threshold(n)).unwrap_or(u64::MAX);
    let fetch = u64::from(ceil_log2(f.saturating_add(1))).saturating_mul(local.fetch_retry);
    let sigma = local.rebroadcast_interval.saturating_add(DELTA_NOMINAL);
    let inner = sigma
        .saturating_add(local.build_timeout)
        .saturating_add(DELTA_NOMINAL.saturating_mul(3))
        .saturating_add(fetch)
        .saturating_add(chain.a_max)
        .saturating_add(chain.e_max);
    inner
        .saturating_mul(2)
        .saturating_add(LOCAL_DELAY_NOMINAL.saturating_mul(4))
}

/// `T_max_eff = max(t_max, T_req(nominal))` for the given height configuration (§9.4), bounded
/// by [`MAX_VIEW_TIMEOUT`].
pub fn effective_t_max(local: &LocalParams, config: &HeightConfig) -> Millis {
    local
        .t_max
        .max(t_req_nominal(local, &config.params, config.committee.n()))
        .min(MAX_VIEW_TIMEOUT)
}

/// Validate a local configuration against the initial height configurations (§9.4). The core
/// rejects it at `Core::new`.
///
/// # Errors
/// The first violated rule.
// SPEC: in addition to §9.4, zero intervals (`t_base`, `rebroadcast_interval`,
// `status_keepalive`, `fetch_retry`, `sync_retry`, `build_timeout`) and
// `sync_batch > MAX_SYNC_ENTRIES` are rejected: they would busy-loop the timer or exceed the
// decode limit of a SyncResponse; a zero `build_timeout` answers every build with `EMPTY`
// before the builder can (the `Tick` is delivered first, O5), so the leader never proposes a
// transaction. (Appendix E, E22)
pub fn validate_local(local: &LocalParams, configs: &[&HeightConfig]) -> Result<(), ConfigError> {
    let zero = [
        (local.t_base, "t_base"),
        (local.rebroadcast_interval, "rebroadcast_interval"),
        (local.status_keepalive, "status_keepalive"),
        (local.fetch_retry, "fetch_retry"),
        (local.sync_retry, "sync_retry"),
        (local.build_timeout, "build_timeout"),
    ];
    if let Some((_, name)) = zero.iter().find(|(value, _)| *value == 0) {
        return Err(ConfigError::ZeroInterval(name));
    }
    if local.rebroadcast_interval > local.t_base / 2 {
        return Err(ConfigError::RebroadcastTooLong);
    }
    if local.sync_batch < 1 {
        return Err(ConfigError::SyncBatchZero);
    }
    if usize::from(local.sync_batch) > crate::message::MAX_SYNC_ENTRIES {
        return Err(ConfigError::SyncBatchTooLarge);
    }
    if local.fetch_retry > local.rebroadcast_interval {
        return Err(ConfigError::FetchRetryTooLong);
    }
    for config in configs {
        let needed = u64::from(config.params.max_block_bytes) + u64::from(FRAME_OVERHEAD);
        if u64::from(local.sync_max_bytes) < needed {
            return Err(ConfigError::SyncMaxBytesTooSmall);
        }
        let t_req = t_req_nominal(local, &config.params, config.committee.n());
        if local.t_max < t_req {
            return Err(ConfigError::TMaxBelowRequirement {
                t_max: local.t_max,
                t_req,
            });
        }
    }
    Ok(())
}

/// Chain-parameter validation the application MUST apply before committing parameters (§9.4),
/// with `transport_limit` the transport frame limit in bytes (O10).
///
/// # Errors
/// The first violated rule.
pub fn validate_chain(chain: &ChainParams, transport_limit: u64) -> Result<(), ConfigError> {
    if chain.block_time > chain.payload_retry_interval {
        return Err(ConfigError::BlockTimeAbovePayloadRetry);
    }
    if chain.payload_retry_interval == 0 {
        return Err(ConfigError::PayloadRetryIntervalZero);
    }
    if u64::from(chain.max_block_bytes) + u64::from(FRAME_OVERHEAD) > transport_limit {
        return Err(ConfigError::MaxBlockBytesAboveTransport);
    }
    Ok(())
}

/// Validate chain parameters against their exact authenticated epoch layout.
///
/// # Errors
/// Invalid chain/layout bounds or an unencodable admitted payload maximum.
pub fn validate_height(config: &HeightConfig, transport_limit: u64) -> Result<(), ConfigError> {
    validate_chain(&config.params, transport_limit)?;
    config
        .epoch
        .da_layout
        .validate()
        .map_err(ConfigError::AvailabilityLayout)?;
    if u64::from(config.params.max_block_bytes) > config.epoch.da_layout.max_payload_size_bytes {
        return Err(ConfigError::PayloadAboveAvailabilityLimit);
    }
    Ok(())
}

/// `P(0) = payload_retry_interval + build_timeout`; `P(v > 0) = build_timeout`.
pub fn propose_allowance(view: u64, chain: &ChainParams, build_timeout: Millis) -> Millis {
    if view == 0 {
        chain.payload_retry_interval.saturating_add(build_timeout)
    } else {
        build_timeout
    }
}

/// `anchor(h, v) = min(t_enter + P(v), t_prop)`, where `t_prop` is when the round's proposal
/// was accepted. No timer depends on the node's own transaction queue (§9.1).
pub fn anchor(
    t_enter: Millis,
    view: u64,
    t_prop: Option<Millis>,
    chain: &ChainParams,
    build_timeout: Millis,
) -> Millis {
    let entered = t_enter.saturating_add(propose_allowance(view, chain, build_timeout));
    entered.min(t_prop.unwrap_or(Millis::MAX))
}

/// EWMA with weight 1/8: `prev + (sample − prev) / 8`, rounded toward `prev`.
pub fn ewma(prev: Millis, sample: Millis) -> Millis {
    if sample >= prev {
        prev + (sample - prev) / 8
    } else {
        prev - (prev - sample) / 8
    }
}

/// Backoff before the `attempt`-th (0-based) execution retry after `Failed`/`Cancelled`:
/// 100 ms, doubling, capped at `cap` (`rebroadcast_interval`, §4.2).
pub fn exec_retry_delay(attempt: u32, cap: Millis) -> Millis {
    retransmit_spacing(attempt.saturating_add(1), EXEC_RETRY_INITIAL, cap)
}

/// Spacing before the `k`-th (1-based) retransmission of a vote: `t_retx · 2^(k−1)`, capped at
/// `cap` (`rebroadcast_interval`). Re-sends thus happen at `t_vote + t_retx·(2^k − 1)` (§6.11).
pub fn retransmit_spacing(k: u32, t_retx: Millis, cap: Millis) -> Millis {
    let shift = k.saturating_sub(1);
    t_retx
        .checked_shl(shift)
        .filter(|value| *value >> shift == t_retx)
        .unwrap_or(Millis::MAX)
        .min(cap)
}

/// Outcome of the start-level adaptation on a commit (§9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartChange {
    /// `start(h+1) = min(start_cap, start(h) + 1)`.
    Raised,
    /// `start(h+1) = start(h) − 1` after `decay_after` fast commits.
    Decayed,
    /// Unchanged.
    Unchanged,
}

/// Per-instance pacemaker state (§9): start level, fast-commit streak, the longest execution
/// of the height and the latency EWMAs. A restart begins at level 0 (safe; only costs
/// time).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pacemaker {
    t_base: Millis,
    t_max_eff: Millis,
    level_cap: u32,
    start_cap: u32,
    decay_after: u32,
    start_level: u32,
    fast_streak: u32,
    last_exec_ms: Option<Millis>,
    latency_ewma: Option<Millis>,
    qc_lat_ewma: Millis,
    /// ML25: the revision-4.1 raise flag (a view timed out while its proposal was held).
    #[cfg(sumeragi_mutation = "ML25")]
    pub(crate) failed_with_proposal: bool,
}

impl Pacemaker {
    /// A pacemaker at start level 0 for `t_max_eff` (see [`effective_t_max`]; values above
    /// [`MAX_VIEW_TIMEOUT`] are clamped).
    pub fn new(local: &LocalParams, t_max_eff: Millis) -> Self {
        let t_max_eff = t_max_eff.min(MAX_VIEW_TIMEOUT);
        Self {
            t_base: local.t_base,
            t_max_eff,
            level_cap: level_cap(local.t_base, t_max_eff),
            start_cap: local.start_cap,
            decay_after: local.decay_after,
            start_level: 0,
            fast_streak: 0,
            last_exec_ms: None,
            latency_ewma: None,
            qc_lat_ewma: QC_LATENCY_INITIAL,
            #[cfg(sumeragi_mutation = "ML25")]
            failed_with_proposal: false,
        }
    }

    /// Update `T_max_eff` (a later configuration raised `T_req`, §9.4).
    pub fn set_t_max_eff(&mut self, t_max_eff: Millis) {
        let t_max_eff = t_max_eff.min(MAX_VIEW_TIMEOUT);
        self.t_max_eff = t_max_eff;
        self.level_cap = level_cap(self.t_base, t_max_eff);
    }

    /// Current `T_max_eff`.
    pub fn t_max_eff(&self) -> Millis {
        self.t_max_eff
    }

    /// `level_cap`.
    pub fn level_cap(&self) -> u32 {
        self.level_cap
    }

    /// `start(h)`.
    pub fn start_level(&self) -> u32 {
        self.start_level
    }

    /// `level(h, v) = min(level_cap, start(h) + v)`.
    pub fn level(&self, view: u64) -> u32 {
        #[cfg(not(sumeragi_mutation = "ML1"))]
        let sum = u64::from(self.start_level).saturating_add(view);
        #[cfg(sumeragi_mutation = "ML1")]
        let sum = u64::from(self.start_level);
        u32::try_from(sum.min(u64::from(self.level_cap))).unwrap_or(self.level_cap)
    }

    /// `T(L)`.
    pub fn timeout_at(&self, level: u32) -> Millis {
        view_timeout(self.t_base, self.t_max_eff, level)
    }

    /// `T(level(h, v))`.
    pub fn view_timeout(&self, view: u64) -> Millis {
        self.timeout_at(self.level(view))
    }

    /// `t_view(h, v) = anchor + T(level(h, v))`.
    pub fn view_deadline(&self, anchor: Millis, view: u64) -> Millis {
        anchor.saturating_add(self.view_timeout(view))
    }

    /// `t_retx = clamp(3 · qc_lat_ewma, 50 ms, φ · T(level) / 2)`.
    // SPEC: when `φ·T/2 < 50 ms` the clamp bounds cross; the lower bound (50 ms) wins (Appendix E, E23).
    pub fn t_retx(&self, view: u64) -> Millis {
        let upper = self.view_timeout(view).saturating_mul(PHI_NUM) / PHI_DEN / 2;
        self.qc_lat_ewma
            .saturating_mul(3)
            .min(upper)
            .max(T_RETX_MIN)
    }

    /// Stage-1 deadline `t_s1 = min(t_ready + t_retx, t_pqc + t_retx)` over the clauses that
    /// apply (the caller passes `t_ready` only without a `PrepareQC` of the view, `t_pqc` only
    /// without a `CommitQC` of the height); `None` if neither applies.
    pub fn stage1_deadline(
        &self,
        t_ready: Option<Millis>,
        t_pqc: Option<Millis>,
        view: u64,
    ) -> Option<Millis> {
        let t_retx = self.t_retx(view);
        [t_ready, t_pqc]
            .into_iter()
            .flatten()
            .map(|t| t.saturating_add(t_retx))
            .min()
    }

    /// Stage-2 deadline `t_s2 = min(t_lastvote + 2·t_retx, anchor + φ·T(level))`; without a vote
    /// only the backstop applies.
    pub fn stage2_deadline(&self, t_lastvote: Option<Millis>, anchor: Millis, view: u64) -> Millis {
        let backstop =
            anchor.saturating_add(self.view_timeout(view).saturating_mul(PHI_NUM) / PHI_DEN);
        t_lastvote.map_or(backstop, |t| {
            backstop.min(t.saturating_add(self.t_retx(view).saturating_mul(2)))
        })
    }

    /// `pace = max(0, block_time − latency_ewma)` (0 latency before the first sample).
    // SPEC: §9.1 gives no initial `latency_ewma`; the first sample initialises it (Appendix E, E24).
    pub fn pace(&self, block_time: Millis) -> Millis {
        block_time.saturating_sub(self.latency_ewma.unwrap_or(0))
    }

    /// `t_propose = t_enter(h, 0) + pace`.
    pub fn propose_time(&self, t_enter: Millis, block_time: Millis) -> Millis {
        t_enter.saturating_add(self.pace(block_time))
    }

    /// `exec_budget = min(e_max, φ · T_base / 2)`: independent of the level, so a leader at a
    /// high level never builds blocks that voters at level 0 cannot execute in time (§9.1).
    pub fn exec_budget(&self, e_max: Millis) -> Millis {
        #[cfg(not(sumeragi_mutation = "MR-exec-budget"))]
        let base = self.t_base;
        #[cfg(sumeragi_mutation = "MR-exec-budget")]
        let base = self.view_timeout(1);
        e_max.min(base.saturating_mul(PHI_NUM) / PHI_DEN / 2)
    }

    /// Record `t_commit(h) − t_proposal_received(h)`.
    pub fn record_commit_latency(&mut self, sample: Millis) {
        self.latency_ewma = Some(self.latency_ewma.map_or(sample, |prev| ewma(prev, sample)));
    }

    /// Record a vote-to-QC latency sample (every own vote whose phase QC arrives, §9.1), capped
    /// at `2 × qc_lat_ewma` so one slow or adversarially delayed round moves the estimate by at
    /// most 1/8.
    pub fn record_qc_latency(&mut self, sample: Millis) {
        let capped = sample.min(self.qc_lat_ewma.saturating_mul(2));
        self.qc_lat_ewma = ewma(self.qc_lat_ewma, capped);
    }

    /// Record the duration of an execution at the current height, or a lower bound of it for
    /// an execution that was discarded or still pending when its view or height ended
    /// (§6.3 step 1, §6.2 `discard_exec`, §6.8 step 4). `pm.last_exec_ms` is the maximum over
    /// the height, so a fast later execution (for example the `EMPTY` block that finally
    /// commits) never hides a slow earlier one.
    pub fn record_exec(&mut self, ms: Millis) {
        #[cfg(not(sumeragi_mutation = "ML28"))]
        let ms = self.last_exec_ms.map_or(ms, |prev| prev.max(ms));
        self.last_exec_ms = Some(ms);
    }

    /// `pm.last_exec_ms`: the longest execution recorded at the current height.
    pub fn last_exec_ms(&self) -> Option<Millis> {
        self.last_exec_ms
    }

    /// Start-level adaptation on the commit of `h` whose `CommitQC` has view `commit_view`
    /// (§9.2). `view_ms` is `d_c = t_commit(h) − t_body(h, commit_view)`, the time since this
    /// node first held the committing view's proposal of the committed block together with its
    /// body, when it commits while in `commit_view` holding them (`None` otherwise: it never
    /// measured that view). Raises iff an execution at this height or its committing view took
    /// more than `T(start(h)) / 2`; a view that failed never raises by itself (only an
    /// execution it discarded can). Resets the per-height execution duration.
    // SPEC: "Otherwise unchanged" keeps both the start level and `fast_streak`; the per-height
    // `last_exec_ms` is reset at every commit (Appendix E, E25).
    pub fn on_commit(&mut self, commit_view: u64, view_ms: Option<Millis>) -> StartChange {
        let half = self.timeout_at(self.start_level) / 2;
        let slow_exec = self.last_exec_ms.is_some_and(|ms| ms > half);
        let slow_view = view_ms.is_some_and(|ms| ms > half);
        #[cfg(not(sumeragi_mutation = "ML25"))]
        let failed = false;
        #[cfg(sumeragi_mutation = "ML25")]
        let failed = std::mem::take(&mut self.failed_with_proposal);
        self.last_exec_ms = None;
        if slow_exec || slow_view || failed {
            self.start_level = self.start_level.saturating_add(1).min(self.start_cap);
            self.fast_streak = 0;
            return StartChange::Raised;
        }
        if commit_view == 0 {
            self.fast_streak = self.fast_streak.saturating_add(1);
            if self.fast_streak >= self.decay_after {
                self.fast_streak = 0;
                if self.start_level > 0 && !cfg!(sumeragi_mutation = "ML6") {
                    self.start_level -= 1;
                    return StartChange::Decayed;
                }
            }
        }
        StartChange::Unchanged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Committee, PublicKey};

    #[test]
    fn height_configuration_requires_valid_encodable_signed_layout() {
        let mut candidate = config(4, ChainParams::default());
        validate_height(&candidate, u64::MAX).unwrap();
        candidate.epoch.da_layout.max_payload_size_bytes = 1;
        assert_eq!(
            validate_height(&candidate, u64::MAX),
            Err(ConfigError::PayloadAboveAvailabilityLimit)
        );
        candidate.epoch.da_layout.parity_shards = 0;
        assert!(matches!(
            validate_height(&candidate, u64::MAX),
            Err(ConfigError::AvailabilityLayout(_))
        ));
    }

    fn config(n: usize, params: ChainParams) -> HeightConfig {
        let keys = (0..n)
            .map(|i| PublicKey::new(vec![u8::try_from(i).unwrap(); 32]).unwrap())
            .collect();
        HeightConfig {
            epoch: Box::new(crate::testing::TEST_EPOCH),
            committee: Committee::new(keys).unwrap(),
            params,
        }
    }

    #[test]
    fn view_timeout_table_n4() {
        // §9.3: T(L) for n = 4: 2.0, 3.0, 4.5, 6.75, 10.1, 15.2, 22.8, 30 s.
        let expected = [
            2_000, 3_000, 4_500, 6_750, 10_125, 15_187, 22_781, 30_000, 30_000,
        ];
        for (level, want) in expected.iter().enumerate() {
            assert_eq!(
                view_timeout(2_000, 30_000, u32::try_from(level).unwrap()),
                *want
            );
        }
        assert_eq!(level_cap(2_000, 30_000), 7);
        assert_eq!(level_cap(3_000, 30_000), 6);
        assert_eq!(view_timeout(3_000, 30_000, 5), 22_781);
        assert_eq!(view_timeout(3_000, 30_000, 6), 30_000);
    }

    #[test]
    fn view_timeout_edges() {
        assert_eq!(view_timeout(2_000, 1_000, 0), 1_000);
        assert_eq!(view_timeout(0, 30_000, 50), 0);
        assert_eq!(view_timeout(1, u64::MAX, 200), u64::MAX);
        assert_eq!(view_timeout(u64::MAX, u64::MAX, 1), u64::MAX);
        assert_eq!(view_timeout(7, 1 << 40, u32::MAX), 1 << 40);
        assert_eq!(level_cap(2_000, 2_000), 0);
        assert_eq!(level_cap(2_000, 1_000), 0);
        assert_eq!(level_cap(0, 1_000), 0);
        assert_eq!(level_cap(2_000, 2_001), 1);
        assert_eq!(level_cap(2_000, 3_000), 1);
        assert_eq!(level_cap(2_000, 3_001), 2);
        assert_eq!(level_cap(1, MAX_VIEW_TIMEOUT), 69);
        assert_eq!(view_timeout(1, MAX_VIEW_TIMEOUT, 68), 942_335_637_702);
        assert_eq!(view_timeout(1, MAX_VIEW_TIMEOUT, 69), MAX_VIEW_TIMEOUT);
        // Monotone and reaching the cap exactly at level_cap.
        for (base, max) in [
            (1_000u64, 60_000u64),
            (2_000, 30_000),
            (3_000, 19_600),
            (7, 1 << 40),
        ] {
            let cap = level_cap(base, max);
            let mut previous = 0;
            for level in 0..=cap + 3 {
                let t = view_timeout(base, max, level);
                assert!(t >= previous);
                previous = t;
                assert_eq!(
                    t == max,
                    level >= cap,
                    "base {base} max {max} level {level}"
                );
            }
        }
    }

    #[test]
    fn det_l1_levels_grow() {
        // A view that keeps failing gets ×1.5 longer per level until T_max_eff.
        let local = LocalParams::default();
        let pm = Pacemaker::new(&local, 30_000);
        let mut previous = 0;
        for view in 0..10 {
            let t = pm.view_timeout(view);
            if view <= u64::from(pm.level_cap()) {
                assert!(t > previous, "view {view}");
            }
            previous = t;
        }
        assert_eq!(pm.view_timeout(0), 2_000);
        assert_eq!(pm.view_timeout(1), 3_000);
        assert_eq!(pm.view_timeout(100), 30_000);
        assert_eq!(pm.level(u64::MAX), pm.level_cap());
        // With executions slower than T_base, the level eventually outlasts them.
        let e = 1_500 * 2;
        let k = (0..64).find(|v| pm.view_timeout(*v) / 2 > e).unwrap();
        assert!(k <= u64::from(pm.level_cap()));
    }

    #[test]
    fn det_l6_level_decays() {
        let local = LocalParams::default();
        let mut pm = Pacemaker::new(&local, 30_000);
        // A committing view slower than T(0)/2 = 1000 ms raises.
        assert_eq!(pm.on_commit(1, Some(1_001)), StartChange::Raised);
        pm.record_exec(5_000); // > T(1)/2 = 1500
        assert_eq!(pm.on_commit(0, Some(10)), StartChange::Raised);
        assert_eq!(pm.start_level(), 2);
        // decay_after = 8 fast commits lower the level by one each.
        for round in 0..2 {
            for i in 0..7 {
                assert_eq!(
                    pm.on_commit(0, Some(10)),
                    StartChange::Unchanged,
                    "{round}/{i}"
                );
                assert_eq!(pm.fast_streak, i + 1);
            }
            assert_eq!(pm.on_commit(0, None), StartChange::Decayed);
            assert_eq!(pm.fast_streak, 0);
        }
        assert_eq!(pm.start_level(), 0);
        // At level 0 the streak resets without a change.
        for _ in 0..8 {
            assert_eq!(pm.on_commit(0, None), StartChange::Unchanged);
        }
        assert_eq!(pm.start_level(), 0);
    }

    #[test]
    fn start_level_capped_and_failed_views_do_not_raise() {
        let local = LocalParams::default();
        let mut pm = Pacemaker::new(&local, 30_000);
        for _ in 0..10 {
            pm.on_commit(3, Some(30_000));
        }
        assert_eq!(pm.start_level(), local.start_cap);
        assert_eq!(pm.level(0), local.start_cap);
        // A view-2 commit after failed views (silent, equivocating or withholding leaders),
        // itself fast, changes nothing.
        let mut pm = Pacemaker::new(&local, 30_000);
        pm.on_commit(0, Some(100));
        assert_eq!(pm.fast_streak, 1);
        assert_eq!(pm.on_commit(2, Some(900)), StartChange::Unchanged);
        assert_eq!((pm.start_level(), pm.fast_streak), (0, 1));
        // Neither does a commit in a view this node did not measure.
        assert_eq!(pm.on_commit(3, None), StartChange::Unchanged);
        // Fast execution and a view of exactly T(start)/2 do not raise; one more millisecond
        // of either does.
        pm.record_exec(1_000);
        assert_eq!(pm.on_commit(0, Some(1_000)), StartChange::Unchanged);
        pm.record_exec(1_001);
        assert_eq!(pm.on_commit(0, Some(1_000)), StartChange::Raised);
        // The threshold follows the start level: T(1)/2 = 1500 ms.
        assert_eq!(pm.on_commit(0, Some(1_500)), StartChange::Unchanged);
        assert_eq!(pm.on_commit(0, Some(1_501)), StartChange::Raised);
        assert_eq!(pm.start_level(), 2);
    }

    /// §9.2 (ML28): `pm.last_exec_ms` is the maximum over the height, so the fast execution
    /// of the block that finally commits never hides a slow (or discarded) earlier one; it
    /// resets at every commit.
    #[test]
    fn det_l28_exec_duration_is_the_height_maximum() {
        let local = LocalParams::default();
        let mut pm = Pacemaker::new(&local, 30_000);
        pm.record_exec(3_300);
        pm.record_exec(10);
        assert_eq!(pm.last_exec_ms(), Some(3_300));
        assert_eq!(pm.on_commit(2, None), StartChange::Raised);
        assert_eq!(pm.last_exec_ms(), None);
        pm.record_exec(10);
        assert_eq!(pm.on_commit(0, Some(10)), StartChange::Unchanged);
    }

    #[test]
    fn retx_and_stage_deadlines() {
        let local = LocalParams::default();
        let mut pm = Pacemaker::new(&local, 30_000);
        assert_eq!(pm.qc_lat_ewma, 250);
        // 3 · 250 = 750 > T(0)/4 = 500 → 500.
        assert_eq!(pm.t_retx(0), 500);
        // Level 3: T = 6750 → upper 1687; 750.
        assert_eq!(pm.t_retx(3), 750);
        for _ in 0..100 {
            pm.record_qc_latency(1);
        }
        assert_eq!(pm.t_retx(0), T_RETX_MIN);
        assert_eq!(pm.stage1_deadline(Some(1_000), None, 0), Some(1_050));
        assert_eq!(pm.stage1_deadline(None, Some(900), 0), Some(950));
        assert_eq!(pm.stage1_deadline(Some(1_000), Some(900), 0), Some(950));
        assert_eq!(pm.stage1_deadline(None, None, 0), None);
        // Backstop only: anchor + T/2.
        assert_eq!(pm.stage2_deadline(None, 10_000, 0), 11_000);
        assert_eq!(pm.stage2_deadline(Some(10_100), 10_000, 0), 10_200);
        assert_eq!(pm.stage2_deadline(Some(20_000), 10_000, 0), 11_000);
        assert_eq!(pm.view_deadline(10_000, 0), 12_000);
        // Crossed clamp bounds: lower bound wins.
        let tiny = LocalParams {
            t_base: 100,
            ..LocalParams::default()
        };
        let pm = Pacemaker::new(&tiny, 100);
        assert_eq!(pm.t_retx(0), T_RETX_MIN);
    }

    #[test]
    fn pace_budget_and_latency() {
        let local = LocalParams::default();
        let mut pm = Pacemaker::new(&local, 30_000);
        assert_eq!(pm.latency_ewma, None);
        assert_eq!(pm.pace(1_000), 1_000);
        assert_eq!(pm.propose_time(5, 1_000), 1_005);
        pm.record_commit_latency(400);
        assert_eq!(pm.latency_ewma, Some(400));
        assert_eq!(pm.pace(1_000), 600);
        pm.record_commit_latency(1_200);
        assert_eq!(pm.latency_ewma, Some(500));
        pm.record_commit_latency(5_000);
        assert_eq!(pm.pace(1_000), 0);
        // exec_budget = min(e_max, T_base/4), whatever the level.
        assert_eq!(pm.exec_budget(4_000), 500);
        pm.on_commit(1, Some(2_000));
        assert_eq!(pm.start_level(), 1);
        assert_eq!(pm.exec_budget(4_000), 500, "level-independent");
        assert_eq!(pm.exec_budget(100), 100);
    }

    #[test]
    fn qc_latency_samples_are_capped() {
        let local = LocalParams::default();
        let mut pm = Pacemaker::new(&local, 30_000);
        // One huge sample moves the estimate by at most (2·250 − 250)/8.
        pm.record_qc_latency(1_000_000);
        assert_eq!(pm.qc_lat_ewma, 250 + 250 / 8);
        // A persistent change is still learned within a few rounds.
        for _ in 0..40 {
            pm.record_qc_latency(2_000);
        }
        assert!(pm.qc_lat_ewma > 1_500, "{}", pm.qc_lat_ewma);
    }

    #[test]
    fn ewma_rounding() {
        assert_eq!(ewma(250, 250), 250);
        assert_eq!(ewma(250, 330), 260);
        assert_eq!(ewma(250, 170), 240);
        assert_eq!(ewma(0, 7), 0);
        assert_eq!(ewma(7, 0), 7);
        assert_eq!(ewma(u64::MAX, 0), u64::MAX - u64::MAX / 8);
        assert_eq!(ewma(0, u64::MAX), u64::MAX / 8);
    }

    #[test]
    fn anchor_formula() {
        let chain = ChainParams::default();
        // View 0: t_enter + P(0) = t_enter + idle + build, whatever the local queue holds.
        assert_eq!(anchor(1_000, 0, None, &chain, 200), 6_200);
        // Proposal accepted earlier.
        assert_eq!(anchor(1_000, 0, Some(2_000), &chain, 200), 2_000);
        assert_eq!(anchor(1_000, 0, Some(7_000), &chain, 200), 6_200);
        // View > 0: t_enter + build.
        assert_eq!(anchor(1_000, 1, None, &chain, 200), 1_200);
        assert_eq!(anchor(1_000, 1, Some(1_100), &chain, 200), 1_100);
        assert_eq!(propose_allowance(0, &chain, 200), 5_200);
        assert_eq!(propose_allowance(3, &chain, 200), 200);
        assert_eq!(anchor(u64::MAX, 0, None, &chain, 200), u64::MAX);
    }

    #[test]
    fn backoffs() {
        assert_eq!(exec_retry_delay(0, 500), 100);
        assert_eq!(exec_retry_delay(1, 500), 200);
        assert_eq!(exec_retry_delay(2, 500), 400);
        assert_eq!(exec_retry_delay(3, 500), 500);
        assert_eq!(exec_retry_delay(200, 500), 500);
        assert_eq!(exec_retry_delay(60, u64::MAX), u64::MAX);
        assert_eq!(retransmit_spacing(1, 300, 1_000), 300);
        assert_eq!(retransmit_spacing(2, 300, 1_000), 600);
        assert_eq!(retransmit_spacing(3, 300, 1_000), 1_000);
        assert_eq!(retransmit_spacing(0, 300, 1_000), 300);
        assert_eq!(retransmit_spacing(99, 300, 1_000), 1_000);
        assert_eq!(retransmit_spacing(70, 3, u64::MAX), u64::MAX);
    }

    #[test]
    fn ceil_log2_values() {
        let table = [
            (0, 0),
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (8, 3),
            (9, 4),
            (11, 4),
        ];
        for (x, want) in table {
            assert_eq!(ceil_log2(x), want, "x={x}");
        }
        assert_eq!(ceil_log2(u64::MAX), 64);
    }

    #[test]
    fn t_req_defaults_match_spec() {
        // §9.4: n = 4 → 16.1 s; n = 22 → 19.6 s.
        let chain = ChainParams::default();
        assert_eq!(
            t_req_nominal(&LocalParams::for_committee_size(4), &chain, 4),
            16_100
        );
        assert_eq!(
            t_req_nominal(&LocalParams::for_committee_size(22), &chain, 22),
            19_600
        );
        // n = 1: f = 0, no fetch term.
        assert_eq!(
            t_req_nominal(&LocalParams::for_committee_size(1), &chain, 1),
            2 * (1_000 + 200 + 1_500 + 1_000 + 4_000) + 200
        );
        let cfg = config(4, chain);
        let local = LocalParams::default();
        assert_eq!(effective_t_max(&local, &cfg), 30_000);
        let slow = config(
            4,
            ChainParams {
                e_max: 20_000,
                ..chain
            },
        );
        assert_eq!(effective_t_max(&local, &slow), 48_100);
    }

    #[test]
    fn local_validation() {
        let chain = ChainParams::default();
        let cfg4 = config(4, chain);
        let cfg22 = config(22, chain);
        assert_eq!(
            validate_local(&LocalParams::for_committee_size(4), &[&cfg4]),
            Ok(())
        );
        assert_eq!(
            validate_local(&LocalParams::for_committee_size(22), &[&cfg22]),
            Ok(())
        );
        let base = LocalParams::default();
        let cases = [
            (
                LocalParams {
                    t_max: 16_099,
                    ..base
                },
                ConfigError::TMaxBelowRequirement {
                    t_max: 16_099,
                    t_req: 16_100,
                },
            ),
            (
                LocalParams {
                    rebroadcast_interval: 1_001,
                    ..base
                },
                ConfigError::RebroadcastTooLong,
            ),
            (
                LocalParams {
                    sync_batch: 0,
                    ..base
                },
                ConfigError::SyncBatchZero,
            ),
            (
                LocalParams {
                    sync_batch: u16::MAX,
                    ..base
                },
                ConfigError::SyncBatchTooLarge,
            ),
            (
                LocalParams {
                    sync_max_bytes: 4 * 1024 * 1024 + FRAME_OVERHEAD - 1,
                    ..base
                },
                ConfigError::SyncMaxBytesTooSmall,
            ),
            (
                LocalParams {
                    fetch_retry: 501,
                    ..base
                },
                ConfigError::FetchRetryTooLong,
            ),
            (
                LocalParams { t_base: 0, ..base },
                ConfigError::ZeroInterval("t_base"),
            ),
            (
                LocalParams {
                    status_keepalive: 0,
                    ..base
                },
                ConfigError::ZeroInterval("status_keepalive"),
            ),
            (
                LocalParams {
                    sync_retry: 0,
                    ..base
                },
                ConfigError::ZeroInterval("sync_retry"),
            ),
        ];
        for (local, expected) in cases {
            assert_eq!(validate_local(&local, &[&cfg4]), Err(expected));
        }
        // The largest requirement among the initial configurations counts.
        let big = config(
            4,
            ChainParams {
                e_max: 12_000,
                ..chain
            },
        );
        assert!(matches!(
            validate_local(&base, &[&cfg4, &big]),
            Err(ConfigError::TMaxBelowRequirement { .. })
        ));
        assert_eq!(validate_local(&base, &[]), Ok(()));
    }

    /// Transport and sync stages of the resource contract
    /// (`specs/zk_resource_contract.json`): both bounds are inclusive, and the frame overhead
    /// is the sum of its bounded parts.
    #[test]
    fn frame_and_sync_bounds_are_inclusive_at_the_committed_payload_limit() {
        assert_eq!(
            u64::from(FRAME_OVERHEAD),
            64 * 1024
                + crate::types::MAX_COMMITTEE_SIZE as u64
                    * (crate::types::MAX_PUBLIC_KEY_LEN + 64) as u64
                + crate::types::MAX_CONTROL_WITNESS_BYTES as u64
                + 32
        );
        assert_eq!(FRAME_OVERHEAD, 264_224);
        let local = LocalParams::default();
        assert_eq!(local.sync_max_bytes, 16 * 1024 * 1024);
        let with_payload = |max_block_bytes: u32| {
            config(
                4,
                ChainParams {
                    max_block_bytes,
                    ..ChainParams::default()
                },
            )
        };
        // The largest committed payload the default sync response serves, and one byte over.
        let served = local.sync_max_bytes - FRAME_OVERHEAD;
        assert_eq!(validate_local(&local, &[&with_payload(served)]), Ok(()));
        assert_eq!(
            validate_local(&local, &[&with_payload(served + 1)]),
            Err(ConfigError::SyncMaxBytesTooSmall)
        );
        // The transport frame: the payload plus the overhead fits exactly, one byte over does
        // not, whatever the node's sync setting is.
        let transport = 16 * 1024 * 1024 + u64::from(FRAME_OVERHEAD);
        let largest = with_payload(16 * 1024 * 1024);
        assert_eq!(validate_chain(&largest.params, transport), Ok(()));
        assert_eq!(
            validate_chain(&with_payload(16 * 1024 * 1024 + 1).params, transport),
            Err(ConfigError::MaxBlockBytesAboveTransport)
        );
        // Open relation recorded by the contract (owner X.2): the chain rule admits a 16 MiB
        // payload, but the default sync response cannot serve it.
        assert_eq!(
            validate_local(&local, &[&largest]),
            Err(ConfigError::SyncMaxBytesTooSmall)
        );
    }

    #[test]
    fn chain_validation() {
        let chain = ChainParams::default();
        let limit = u64::from(chain.max_block_bytes) + u64::from(FRAME_OVERHEAD);
        assert_eq!(validate_chain(&chain, limit), Ok(()));
        assert_eq!(
            validate_chain(&chain, limit - 1),
            Err(ConfigError::MaxBlockBytesAboveTransport)
        );
        assert_eq!(
            validate_chain(
                &ChainParams {
                    block_time: 6_000,
                    ..chain
                },
                limit
            ),
            Err(ConfigError::BlockTimeAbovePayloadRetry)
        );
        assert_eq!(
            validate_chain(
                &ChainParams {
                    payload_retry_interval: 0,
                    block_time: 0,
                    ..chain
                },
                limit
            ),
            Err(ConfigError::PayloadRetryIntervalZero)
        );
    }

    /// The narrowing casts of `FRAME_OVERHEAD` are lossless: the value matches its `u64` sum.
    #[test]
    fn frame_overhead_is_exact() {
        let operands = crate::types::MAX_PUBLIC_KEY_LEN + 64;
        let exact = [
            64 * 1024,
            crate::types::MAX_COMMITTEE_SIZE * operands,
            crate::types::MAX_CONTROL_WITNESS_BYTES,
            32,
        ]
        .map(|bytes| u64::try_from(bytes).expect("usize fits u64"))
        .iter()
        .sum::<u64>();
        assert_eq!(u64::from(FRAME_OVERHEAD), exact);
    }

    #[test]
    fn t_max_eff_update() {
        let local = LocalParams::default();
        let mut pm = Pacemaker::new(&local, 30_000);
        assert_eq!(pm.t_max_eff(), 30_000);
        pm.set_t_max_eff(48_100);
        assert_eq!(pm.t_max_eff(), 48_100);
        assert_eq!(pm.level_cap(), level_cap(2_000, 48_100));
        assert_eq!(pm.view_timeout(100), 48_100);
    }
}
