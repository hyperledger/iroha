//! The application clock guard of the simulator (§4.5) and its named deterministic tests
//! (§13.4: MS51, MS52; the liveness test of the cross-session clock-guard agreement).

use super::*;
use crate::sim::{
    byz::Strategy,
    driver::{encode_tx_with_due, fixture_body},
    scenario::{ClockGuard, Workload},
    scenarios,
};

/// `max_clock_drift_ms` of the named tests (the chain default).
const DRIFT: Millis = 1_000;
/// A block time no honest clock reaches during a run: a far-future proposal.
const FAR: i64 = 3_600_000;

fn drift_i64() -> i64 {
    i64::try_from(DRIFT).unwrap()
}

/// `gov.due_work_max_lag_ms` at its lower bound `2·max_clock_drift_ms + 4·block_cadence_ms`.
fn lag(drift: Millis, sc: &Scenario) -> Millis {
    2 * drift + 4 * sc.params.block_time
}

/// Every machine may report `ExecutorFailed`: the guard's `Failed` answers are local faults.
fn guarded(sc: &mut Scenario, guard: ClockGuard) {
    sc.checks.may_fault = (0..sc.machines()).collect();
    sc.clock_guard = Some(guard);
}

fn guard_of(w: &World) -> &GuardState {
    w.clock_guard.as_ref().expect("a clock-guard world")
}

/// Committed blocks proposed by machine `m` whose first honest commit is in `[from, until)`
/// (global time).
fn committed_by(w: &World, m: usize, from: Millis, until: Millis) -> Vec<CertifiedTime> {
    guard_of(w)
        .certified
        .iter()
        .filter(|c| c.proposer == Some(m) && c.at >= from && c.at < until)
        .copied()
        .collect()
}

/// The workload's due-work flag (§4.5 CT5) is encoded with the other flags.
#[test]
fn workload_due_flag_and_encoding() {
    let workload = Workload {
        due_every: 3,
        pad: 4,
        ..Workload::default()
    };
    assert!(workload.due(3) && workload.due(6) && !workload.due(4));
    assert!(!Workload::default().due(3), "no due work by default");
    assert_eq!(workload.tx(6, true), encode_tx_with_due(6, true, true, 4));
    assert!(crate::sim::driver::payload_due(&workload.tx(3, false)));
    assert!(!crate::sim::driver::payload_due(&workload.tx(4, false)));
}

#[test]
fn guard_rules_and_leads() {
    let config = ClockGuard {
        max_clock_drift_ms: 100,
        due_work_max_lag_ms: 1_000,
        wall_offsets: vec![5, -5],
        leads: vec![(1, vec![10, -20]), (2, Vec::new())],
    };
    let mut state = GuardState::new(&config, 3);
    assert_eq!(state.wall_offsets, vec![5, -5, 0]);
    assert_eq!(
        (0..3).map(|_| state.next_lead(1)).collect::<Vec<_>>(),
        vec![10, -20, 10],
        "cycled per build"
    );
    assert_eq!(state.next_lead(0), 0, "honest builder");
    assert_eq!(state.next_lead(2), 0, "empty list");
    // CT1 at the boundary: `t > wall + drift` refuses.
    assert_eq!(state.violated(1_100, false, 1_000), None);
    assert_eq!(
        state.violated(1_101, true, 1_000),
        if cfg!(sumeragi_mutation = "MS52") {
            None
        } else {
            Some(GuardRule::ClockAhead)
        }
    );
    // CT5 only for due work: `wall − t > lag` refuses.
    assert_eq!(state.violated(0, true, 1_000), None);
    assert_eq!(
        state.violated(0, true, 1_001),
        Some(GuardRule::StaleDueWork)
    );
    assert_eq!(state.violated(0, false, 1_001), None);
    assert_eq!(GuardRule::ClockAhead.reason(), "ClockAhead");
    assert_eq!(GuardRule::StaleDueWork.reason(), "StaleDueWork");
}

/// Wall clocks, the builder stamp, the executor guard (refused, exempt, Byzantine, unstamped)
/// and O-TIME on a world without running it.
#[test]
fn wall_clock_stamp_refusal_and_o_time() {
    let mut sc = Scenario::base("clock-guard-unit", 1, 4);
    sc.byz = vec![(3, Vec::new())];
    guarded(
        &mut sc,
        ClockGuard {
            max_clock_drift_ms: 100,
            due_work_max_lag_ms: 1_000,
            wall_offsets: vec![0, 50],
            leads: vec![(3, vec![FAR])],
        },
    );
    let mut w = World::new(sc);
    let base = w.wall_ms(0);
    assert_eq!(w.wall_ms(1), base + 50);
    w.set_wall_offset(1, -40);
    assert_eq!(w.wall_ms(1), base - 40);
    assert_eq!(w.min_honest_wall(), Some(base - 40));
    // Honest builders stamp their wall clock; Byzantine ones their lead; empty stays empty.
    let mut payload = encode_tx_with_due(1, false, true, 0);
    w.stamp_block_time(0, &mut payload);
    assert_eq!(block_time(&payload), Some(u64::try_from(base).unwrap()));
    let mut far = encode_tx_with_due(2, false, false, 0);
    w.stamp_block_time(3, &mut far);
    assert_eq!(block_time(&far), Some(u64::try_from(base + FAR).unwrap()));
    let mut empty = Vec::new();
    w.stamp_block_time(0, &mut empty);
    assert!(empty.is_empty());
    assert_eq!(w.block_time_bytes(), u64::try_from(TIME_RECORD).unwrap());
    let header = |height| crate::message::BlockHeader {
        control_witness: crate::types::ControlWitness::empty(),
        epoch: crate::testing::TEST_EPOCH.id,
        instance: Hash32::ZERO,
        height,
        origin_view: 0,
        parent_hash: Hash32::ZERO,
        parent_result: Hash32::ZERO,
        payload_hash: Hash32::ZERO,
        availability_digest: Hash32::ZERO,
        payload_len: 0,
        proposer: 0,
        skipped_leaders: Vec::new(),
    };
    let ahead = fixture_body(header(1), &far);
    let bh = Hash32([7; 32]);
    let r0 = w.machines[0].replicas[0].unwrap();
    let r3 = w.machines[3].replicas[0].unwrap();
    // CT1: refused uncertified, exempt certified, never at a Byzantine executor.
    assert_eq!(
        w.clock_guard_refusal(r0, &ahead, &bh, false),
        (!cfg!(sumeragi_mutation = "MS52")).then(|| ExecOutcome::Failed("ClockAhead".into()))
    );
    assert_eq!(w.clock_guard_refusal(r0, &ahead, &bh, true), None);
    assert_eq!(w.clock_guard_refusal(r3, &ahead, &bh, false), None);
    // CT5: a due-work block older than the lag.
    let stale = encode_time(u64::try_from(base - 2_000).unwrap())
        .into_iter()
        .chain(encode_tx_with_due(3, false, true, 0))
        .collect::<Vec<u8>>();
    let stale = fixture_body(header(2), &stale);
    assert_eq!(
        w.clock_guard_refusal(r0, &stale, &bh, false),
        Some(ExecOutcome::Failed("StaleDueWork".into()))
    );
    assert_eq!(w.clock_guard_refusal(r0, &stale, &bh, true), None);
    // Unstamped payloads are never refused.
    let plain = fixture_body(header(3), &encode_tx_with_due(4, false, true, 0));
    assert_eq!(w.clock_guard_refusal(r0, &plain, &bh, false), None);
    let events = &guard_of(&w).events;
    let expected_events = if cfg!(sumeragi_mutation = "MS52") {
        2
    } else {
        4
    };
    assert_eq!(events.len(), expected_events, "{events:?}");
    assert!(
        events
            .iter()
            .any(|e| e.certified && e.rule == GuardRule::StaleDueWork)
    );
    // O-TIME: within `2·drift` of the smallest honest wall clock passes, above it fails.
    let at_bound = encode_time(u64::try_from(base - 40 + 200).unwrap()).to_vec();
    w.check_certified_time(0, &fixture_body(header(4), &at_bound), bh, Some(0));
    assert!(w.failure.is_none(), "{:?}", w.failure);
    assert_eq!(guard_of(&w).certified.last().map(|c| c.excess), Some(200));
    let above = encode_time(u64::try_from(base - 40 + 201).unwrap()).to_vec();
    w.check_certified_time(0, &fixture_body(header(5), &above), bh, Some(0));
    assert!(
        w.failure.as_deref().is_some_and(|f| f.contains("O-TIME")),
        "{:?}",
        w.failure
    );
}

/// Worlds without a clock guard are unchanged: no stamp, no refusal, no O-TIME record.
#[test]
fn unguarded_world_reads_no_clock() {
    let mut w = World::new(Scenario::base("clock-guard-off", 1, 4));
    let mut payload = encode_tx_with_due(1, false, true, 0);
    let before = payload.clone();
    w.stamp_block_time(0, &mut payload);
    assert_eq!(payload, before);
    assert_eq!(w.block_time_bytes(), 0);
    w.set_wall_offset(0, 1_000);
    assert_eq!(
        w.wall_ms(0),
        i64::try_from(w.machines[0].clock.local(w.now)).unwrap()
    );
    let r0 = w.machines[0].replicas[0].unwrap();
    let block = fixture_body(
        crate::message::BlockHeader {
            control_witness: crate::types::ControlWitness::empty(),
            epoch: crate::testing::TEST_EPOCH.id,
            instance: Hash32::ZERO,
            height: 1,
            origin_view: 0,
            parent_hash: Hash32::ZERO,
            parent_result: Hash32::ZERO,
            payload_hash: Hash32::ZERO,
            availability_digest: Hash32::ZERO,
            payload_len: 0,
            proposer: 0,
            skipped_leaders: Vec::new(),
        },
        &encode_time(u64::MAX / 2),
    );
    assert_eq!(
        w.clock_guard_refusal(r0, &block, &Hash32::ZERO, false),
        None
    );
    w.check_certified_time(0, &block, Hash32::ZERO, None);
    assert!(w.failure.is_none() && w.clock_guard.is_none());
}

/// The liveness scenario of the clock-guard agreement (§4.5 "Liveness"): `f` Byzantine members
/// withhold every vote and propose far-future blocks; `f + 1` honest wall clocks are slow (at
/// real time) and the other honest ones are `max_clock_drift_ms` ahead. From 20 s to 40 s the
/// fast clocks are 30 s ahead (outside the assumption `2ε ≤ max_clock_drift_ms`); at 40 s they
/// converge back to `+max_clock_drift_ms`.
fn liveness_scenario(n: usize, seed: u64) -> (Scenario, Vec<usize>) {
    let f = (n - 1) / 3;
    let mut sc = Scenario::base("clock_guard_liveness", seed, n);
    sc.duration = 80_000;
    // Demoted leaders return quickly, so recovered leaders lead view 0 again.
    sc.demotion_window = 8;
    let byz: Vec<usize> = (n - f..n).collect();
    sc.byz = byz
        .iter()
        .map(|m| (*m, vec![Strategy::WithholdVotes]))
        .collect();
    // Honest: `0..n−f`; the last `f + 1` of them are slow, the others fast.
    let fast: Vec<usize> = (0..n - 2 * f - 1).collect();
    let mut wall_offsets = vec![0; n];
    for m in &fast {
        wall_offsets[*m] = drift_i64();
    }
    let lag = lag(DRIFT, &sc);
    guarded(
        &mut sc,
        ClockGuard {
            max_clock_drift_ms: DRIFT,
            due_work_max_lag_ms: lag,
            wall_offsets,
            leads: byz.iter().map(|m| (*m, vec![FAR])).collect(),
        },
    );
    for (at, offset) in [(20_000, 30_000), (40_000, drift_i64())] {
        let fast = fast.clone();
        sc.script.push((
            at,
            Fault::Custom(Box::new(move |w: &mut World| {
                for m in &fast {
                    w.set_wall_offset(*m, offset);
                }
            })),
        ));
    }
    (sc, fast)
}

/// `clock_guard_liveness_with_f_plus_one_slow_clocks` (§4.5, §13.4; the cross-session clock
/// agreement): n = 4 and 7 under [`liveness_scenario`]. Every oracle holds (O-LIVE throughout,
/// O-TIME, O-FAULT with the guard's local faults); the fast leaders' blocks commit while the
/// skew is within `max_clock_drift_ms` (the `f + 1` slow clocks Prepare them), none of their
/// blocks built 30 s ahead commits, and they commit again after the clocks converge; no
/// far-future Byzantine block ever commits, and the honest executors did refuse them.
#[test]
fn clock_guard_liveness_with_f_plus_one_slow_clocks() {
    for (n, seed) in [(4, 1), (4, 2), (7, 3)] {
        let (sc, fast) = liveness_scenario(n, seed);
        let w = match crate::sim::run(sc) {
            Ok(w) => w,
            Err(report) => panic!("n={n} seed={seed}: {report}"),
        };
        let guard = guard_of(&w);
        let far_refusals = guard
            .events
            .iter()
            .filter(|e| e.rule == GuardRule::ClockAhead && !e.certified)
            .count();
        assert!(far_refusals > 0, "n={n}: the guard refused something");
        let byz: Vec<usize> = (n - (n - 1) / 3..n).collect();
        assert!(
            guard
                .certified
                .iter()
                .all(|c| c.proposer.is_none_or(|m| !byz.contains(&m))),
            "n={n}: a far-future Byzantine block committed"
        );
        for m in &fast {
            let before = committed_by(&w, *m, 0, 20_000);
            let skewed: Vec<_> = guard
                .certified
                .iter()
                .filter(|c| c.proposer == Some(*m) && c.excess > i64::try_from(2 * DRIFT).unwrap())
                .collect();
            let after = committed_by(&w, *m, 42_000, w.duration);
            assert!(
                !before.is_empty(),
                "n={n}: fast leader {m} commits within the drift"
            );
            assert!(skewed.is_empty(), "n={n}: {skewed:?}");
            assert!(
                !after.is_empty(),
                "n={n}: fast leader {m} commits again after its clock converged"
            );
        }
    }
}

/// The bound scenario (§4.5 "Upper bound"): two honest clocks `max_clock_drift_ms` ahead, one
/// at real time, and one Byzantine member (also `max_clock_drift_ms` ahead) that votes and
/// proposes blocks stamped `+2·max_clock_drift_ms` (relative to real time) and far-future
/// ones in turn.
fn bound_scenario(seed: u64) -> Scenario {
    let mut sc = Scenario::base("clock_guard_bound", seed, 4);
    sc.duration = 40_000;
    sc.demotion_window = 8;
    sc.byz = vec![(3, Vec::new())];
    let lag = lag(DRIFT, &sc);
    guarded(
        &mut sc,
        ClockGuard {
            max_clock_drift_ms: DRIFT,
            due_work_max_lag_ms: lag,
            wall_offsets: vec![drift_i64(), drift_i64(), 0, drift_i64()],
            leads: vec![(3, vec![drift_i64(), FAR])],
        },
    );
    sc
}

/// `clock_guard_certified_time_within_two_drifts` (MS52): [`bound_scenario`] → O-TIME holds at
/// every commit (no committed block time exceeds the smallest honest wall clock by more than
/// `2·max_clock_drift_ms`), the far-future proposals are refused and never commit, and the
/// Byzantine `+2·max_clock_drift_ms` blocks commit beyond a single drift (the bound is `2·`,
/// not `1·`, the drift). Without CT1 (MS52) honest members Prepare the far-future blocks and
/// O-TIME fails.
#[test]
fn clock_guard_certified_time_within_two_drifts() {
    let drift = drift_i64();
    for seed in [1, 2, 3] {
        let w = match crate::sim::run(bound_scenario(seed)) {
            Ok(w) => w,
            Err(report) => panic!("seed={seed}: {report}"),
        };
        let guard = guard_of(&w);
        assert!(
            guard
                .events
                .iter()
                .any(|e| e.rule == GuardRule::ClockAhead && !e.certified),
            "seed={seed}: far-future proposals were refused"
        );
        let max = guard
            .certified
            .iter()
            .map(|c| c.excess)
            .max()
            .unwrap_or(i64::MIN);
        assert!(max <= 2 * drift, "seed={seed}: {max}");
        assert!(
            guard.certified.len() >= 10,
            "seed={seed}: the chain progressed ({} blocks)",
            guard.certified.len()
        );
        assert!(
            max > drift,
            "seed={seed}: some certified time exceeds an honest clock by more than one drift \
             ({max} ms)"
        );
    }
}

/// F33 with due work: every transaction applies due work (§4.5 CT5) and the hidden
/// `PrepareQC` keeps its block from being re-proposed for longer than `due_work_max_lag_ms`.
fn hidden_due_work_scenario(seed: u64) -> Scenario {
    // `scenarios::f33` picks n = 4 for seeds ≡ 0 (mod 4).
    let mut sc = scenarios::f33(seed * 4);
    assert_eq!(sc.n, 4);
    sc.name = "f33_due_work".to_owned();
    sc.workload = Some(Workload {
        due_every: 1,
        ..sc.workload.unwrap_or_default()
    });
    let drift = 250;
    let lag = lag(drift, &sc);
    guarded(
        &mut sc,
        ClockGuard {
            max_clock_drift_ms: drift,
            due_work_max_lag_ms: lag,
            ..ClockGuard::default()
        },
    );
    sc
}

/// `f33_hidden_prepareqc_due_work_block_commits_after_lag` (MS51; §4.5 "Certified
/// re-proposals"): n = 4 under [`hidden_due_work_scenario`]: a Byzantine proxy tail hides the
/// `PrepareQC` of a due-work block B from all but one honest member; the views fail until a
/// TC carries it and B is re-proposed, by then older than `due_work_max_lag_ms` at every
/// honest clock → the honest members execute B with `certified = true` (CT5 skipped, recorded
/// as exempt), Prepare it, and B commits in a later view; every oracle holds. With
/// `certified = false` (MS51) CT5 refuses B at every honest executor forever, and the height
/// never commits (O-LIVE).
#[test]
fn f33_hidden_prepareqc_due_work_block_commits_after_lag() {
    let mut exercised = 0;
    for seed in [0, 1, 2, 3] {
        let w = match crate::sim::run(hidden_due_work_scenario(seed)) {
            Ok(w) => w,
            Err(report) => panic!("seed={seed}: {report}"),
        };
        let guard = guard_of(&w);
        let exempt: Vec<&GuardEvent> = guard
            .events
            .iter()
            .filter(|e| e.certified && e.rule == GuardRule::StaleDueWork)
            .collect();
        for e in &exempt {
            let committed = w.oracle.refs[0].get(&e.height).expect("committed height");
            if committed.bh == e.block_hash {
                assert!(
                    committed.view > committed.header.origin_view,
                    "seed={seed}: a re-proposal committed"
                );
                exercised += 1;
            }
        }
    }
    assert!(
        exercised > 0,
        "a certified stale due-work re-proposal was executed and committed"
    );
}
