//! The application clock guard of the simulator (§4.5) and its named deterministic tests
//! (§13.4: MS51, MS52, MS65, MS66, MS68–MS70; the cross-session clock-guard agreement).

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

/// `sumeragi.due_work_max_lag_ms` at its lower bound `2·max_clock_drift_ms + 4·block_cadence_ms`.
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

/// MS66: an honest leader may be exactly one allowed drift ahead of a slow honest voter.
/// Removing the allowance must not turn that admissible execution into `ClockAhead`.
#[test]
fn clock_guard_accepts_exact_drift_allowance() {
    let mut sc = Scenario::base("clock-guard-drift-allowance", 1, 4);
    guarded(
        &mut sc,
        ClockGuard {
            max_clock_drift_ms: DRIFT,
            due_work_max_lag_ms: 4 * DRIFT,
            wall_offsets: vec![drift_i64(), 0, 0, 0],
            ..ClockGuard::default()
        },
    );
    let mut w = World::new(sc);
    let mut payload = encode_tx_with_due(1, false, true, 0);
    w.stamp_block_time(0, &mut payload);
    let t = block_time(&payload).unwrap();
    let slow_wall = w.wall_ms(1);
    assert_eq!(i64::try_from(t).unwrap() - slow_wall, drift_i64());
    assert_eq!(guard_of(&w).violated(t, true, slow_wall), None);
}

/// MS68: a genuine committed parent and original queued creation time survive clock regression.
#[test]
fn clock_guard_committed_parent_wait_retains_work_until_clock_recovery() {
    for creation_at in [0, 5_000] {
        let mut sc = Scenario::base("clock_guard_parent_wait", 17, 4);
        sc.duration = 25_000;
        sc.workload = Some(Workload {
            until: 2_000,
            ..Workload::default()
        });
        let lag = lag(DRIFT, &sc);
        guarded(
            &mut sc,
            ClockGuard {
                max_clock_drift_ms: DRIFT,
                due_work_max_lag_ms: lag,
                ..ClockGuard::default()
            },
        );
        let mut world = World::new(sc);
        world.run_until(5_000);
        assert!(world.failure.is_none(), "{:?}", world.failure);
        assert!(world.replicas.iter().all(|replica| replica.applied.0 > 0));
        let (parent, qc) = world.replicas[0].store.last().unwrap();
        let mut header = parent.header().clone();
        header.height += 1;
        header.parent_hash = qc.block_hash;
        header.parent_result = qc.result;
        let mut too_early = encode_time(block_time(parent.payload().as_slice()).unwrap()).to_vec();
        too_early.extend(encode_tx_with_due(u64::MAX, false, false, 0));
        assert_eq!(
            world.clock_payload_validity(0, &fixture_body(header, &too_early)),
            Some(ExecOutcome::Invalid)
        );
        let built_before = world.oracle.built.len();
        let id = world.next_tx + 1;
        world.next_tx = id;
        world.txs[0].insert(id, (creation_at, false, None));
        for machine in 0..4 {
            world.set_wall_offset(machine, -10_000);
            let replica = world.machines[machine].replicas[0].unwrap();
            world.offer_tx(replica, id, encode_tx_with_due(id, false, false, 0));
        }
        world.run_until(6_000);
        assert!(
            world.oracle.built.len() == built_before
                && world
                    .replicas
                    .iter()
                    .any(|replica| replica.clock_ready.is_some())
                && world
                    .replicas
                    .iter()
                    .all(|replica| replica.txs.contains_key(&id)),
            "CT3 must retain original work without publishing before the parent and creation floors"
        );
        // A stale or duplicate timer cannot consume the current request's wakeup.
        let replica = world
            .replicas
            .iter()
            .position(|replica| replica.clock_ready.is_some())
            .unwrap();
        let original = world.replicas[replica].clock_ready.unwrap();
        world.clock_payload_ready(replica, original.0.wrapping_add(1), original.1);
        assert_eq!(world.replicas[replica].clock_ready, Some(original));
        if creation_at != 0 {
            for machine in 0..4 {
                world.set_wall_offset(machine, 0);
            }
        }
        world.run_until(if creation_at == 0 { 25_000 } else { 10_000 });
        assert!(world.failure.is_none(), "{:?}", world.failure);
        assert!(
            world.txs[0][&id].2.is_some(),
            "original queued work commits after clock recovery"
        );
        assert!(
            world
                .replicas
                .iter()
                .all(|replica| !replica.txs.contains_key(&id))
        );
    }
}

/// Each deterministic floor independently prevents a build until exact equality.
#[test]
fn clock_guard_parent_and_creation_floors_hold_independently_at_equality() {
    for creation_dominates in [false, true] {
        let mut sc = Scenario::base("clock_independent_floors", 17, 4);
        sc.workload = Some(Workload {
            until: 2_000,
            ..Workload::default()
        });
        guarded(
            &mut sc,
            ClockGuard {
                max_clock_drift_ms: DRIFT,
                due_work_max_lag_ms: 6_000,
                ..ClockGuard::default()
            },
        );
        let mut world = World::new(sc);
        world.run_until(5_000);
        assert!(world.failure.is_none(), "{:?}", world.failure);
        let r = world.machines[0].replicas[0].unwrap();
        let parent = &world.replicas[r].store.last().unwrap().0;
        let height = parent.header().height + 1;
        let parent_floor =
            block_time(parent.payload().as_slice()).unwrap() + world.instances[0].params.block_time;
        let creation_floor = if creation_dominates {
            parent_floor + 2_000
        } else {
            parent_floor - 1
        };
        let tx = crate::sim::driver::bind_tx_creation(
            &encode_tx_with_due(u64::MAX, false, false, 0),
            creation_floor - 1,
        )
        .unwrap();
        world.replicas[r].txs.clear();
        world.replicas[r].txs.insert(u64::MAX, tx.clone());
        let floor = parent_floor.max(creation_floor);
        assert_eq!(world.builder_clock_floor(r, height, &tx), Some(floor));
        assert!(parent_floor.min(creation_floor) < floor);
        let local = i64::try_from(world.machines[0].clock.local(world.now)).unwrap();
        world.set_wall_offset(0, i64::try_from(floor - 1).unwrap() - local);
        world.build_payload(r, u64::MAX, height, 65_536, 1_000, world.now);
        assert_eq!(
            world.replicas[r].clock_ready,
            Some((u64::MAX, floor)),
            "the larger original floor must hold while the other already permits publication"
        );
        assert_eq!(world.replicas[r].txs[&u64::MAX], tx);
        world.set_wall_offset(0, i64::try_from(floor).unwrap() - local);
        world.build_payload(r, u64::MAX - 1, height, 65_536, 1_000, world.now);
        assert_eq!(
            world.replicas[r].clock_ready, None,
            "exact equality releases the builder"
        );
        assert_eq!(world.replicas[r].txs[&u64::MAX], tx);

        // Identical block bytes cannot change validity when an unrelated workload ID
        // is registered later: the original creation metadata travels in the payload.
        let (parent, qc) = world.replicas[r].store.last().unwrap();
        let mut header = parent.header().clone();
        header.height = height;
        header.parent_hash = qc.block_hash;
        header.parent_result = qc.result;
        let mut payload = encode_time(floor).to_vec();
        payload.extend(tx);
        let original = fixture_body(header, &payload);
        assert_eq!(world.clock_payload_validity(0, &original), None);
        world.txs[0].insert(u64::MAX, (u64::MAX, false, None));
        assert_eq!(world.clock_payload_validity(0, &original), None);
        world.txs[0].remove(&u64::MAX);
        assert_eq!(world.clock_payload_validity(0, &original), None);
    }
}

/// MS69: a completed original payload remains owned across a build-latency wall backstep.
#[test]
fn clock_guard_completed_payload_waits_after_build_latency_backstep() {
    let mut sc = Scenario::base("clock_completed_backstep", 23, 4);
    sc.workload = Some(Workload {
        until: 100,
        ..Workload::default()
    });
    guarded(
        &mut sc,
        ClockGuard {
            max_clock_drift_ms: DRIFT,
            due_work_max_lag_ms: 6_000,
            ..ClockGuard::default()
        },
    );
    let mut world = World::new(sc);
    for machine in &mut world.machines {
        machine.profile.build_min = 100;
        machine.profile.build_max = 100;
    }
    // Use the actual outstanding Core request: its owner must bind the same parent/view.
    let (r, req, expected, delivery) = loop {
        world.run_until(world.now + 1);
        assert!(
            world.now < 5_000,
            "the actual leader must request a payload"
        );
        if let Some(found) = world.queue.iter().find_map(|((at, _), event)| {
            if let Ev::BuiltPayload {
                r,
                req,
                payload: Some(payload),
                ..
            } = event
            {
                Some((*r, *req, payload.clone(), *at))
            } else {
                None
            }
        }) {
            break found;
        }
    };
    let machine = world.replicas[r].machine;
    let inst = world.replicas[r].inst;
    let stamp = block_time(expected.as_slice()).unwrap();
    let hash = crate::preimage::payload_hash(&world.hasher, expected.as_slice());
    world.set_wall_offset(machine, -500);
    world.run_until(delivery);
    assert!(
        world.replicas[r]
            .completed_build
            .as_ref()
            .is_some_and(|(owner, payload)| *owner == req && payload == &expected)
            && !world.oracle.built.contains(&(inst, machine, hash)),
        "CT3 must retain the original completed payload after a build-latency clock backstep"
    );
    world.completed_clock_ready(r, req.wrapping_add(1));
    assert_eq!(world.replicas[r].completed_build.as_ref().unwrap().0, req);
    let recovery = world.clock_floor_global_time(r, stamp);
    world.run_until(recovery - 1);
    assert!(!world.oracle.built.contains(&(inst, machine, hash)));
    world.run_until(recovery);
    assert!(
        world.oracle.built.contains(&(inst, machine, hash)),
        "original completed bytes publish at exact wall recovery: req={req}, now={}, delivery={delivery}, recovery={recovery}, context={:?}, build={:?}, completed={:?}",
        world.now,
        world.replicas[r]
            .host
            .core()
            .and_then(|core| core.fresh_proposal_context(req)),
        world.replicas[r].build_request,
        world.replicas[r]
            .completed_build
            .as_ref()
            .map(|(req, _)| req)
    );
    assert!(world.replicas[r].completed_build.is_none());
    world.completed_clock_ready(r, req);
    assert!(world.replicas[r].completed_build.is_none());
}

/// MS70: the real fresh proposal signer resamples the clock after queued authoring completes.
#[test]
fn clock_guard_fresh_proposal_waits_after_authored_queue_backstep() {
    let mut sc = Scenario::base("clock_fresh_authored_backstep", 23, 4);
    sc.workload = Some(Workload {
        until: 100,
        ..Workload::default()
    });
    guarded(
        &mut sc,
        ClockGuard {
            max_clock_drift_ms: DRIFT,
            due_work_max_lag_ms: 6_000,
            ..ClockGuard::default()
        },
    );
    let mut world = World::new(sc);
    let (r, req, original, delivery) = loop {
        world.run_until(world.now + 1);
        assert!(
            world.now < 5_000,
            "the actual leader must finish a fresh payload"
        );
        if let Some(found) = world.queue.iter().find_map(|((at, _), event)| {
            if let Ev::Local { r, event, .. } = event
                && let Event::PayloadAuthored { req, body } = &**event
            {
                Some((*r, *req, body.clone(), *at))
            } else {
                None
            }
        }) {
            break found;
        }
    };
    let m = world.replicas[r].machine;
    let header = original.header();
    assert_eq!((header.height, header.origin_view), (1, 0));
    let hash = original.hash(&world.hasher);
    let digest = crate::preimage::att_digest(&world.hasher, None, None);
    let preimage = crate::preimage::prop_preimage(
        &header.instance,
        &header.epoch,
        header.height,
        header.origin_view,
        &hash,
        &digest,
    );
    let key = world.instances[0]
        .committee(1)
        .get(header.proposer)
        .unwrap()
        .clone();
    let stamp = block_time(original.payload().as_slice()).unwrap();
    let proposals = world.stats.proposals;
    world.set_wall_offset(m, -500);
    world.run_until(delivery + 10);
    assert!(
        world.replicas[r]
            .authored_clock
            .as_ref()
            .is_some_and(|(owner, body)| *owner == req && body == &original)
            && !world.log.lock().unwrap().was_signed(&key, &preimage)
            && world.stats.proposals == proposals,
        "CT3 must not sign or publish a fresh proposal after an authored-queue clock backstep"
    );
    world.authored_clock_ready(r, req.wrapping_add(1));
    assert_eq!(world.replicas[r].authored_clock.as_ref().unwrap().0, req);
    let recovery = world.clock_floor_global_time(r, stamp);
    world.run_until(recovery - 1);
    assert!(!world.log.lock().unwrap().was_signed(&key, &preimage));
    world.run_until(recovery + 200);
    assert!(
        world.log.lock().unwrap().was_signed(&key, &preimage),
        "the original fresh proposal signs after exact clock recovery"
    );
    assert!(world.stats.proposals > proposals);
    assert!(world.failure.is_none(), "{:?}", world.failure);
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

/// MS65: the Byzantine leader votes but stamps due-work blocks older than CT5 permits.
/// Honest leaders still make progress; the first genuine honest Prepare oracle rejects
/// stale due-work acceptance without imposing a bound on eventual commit time.
#[test]
fn clock_guard_due_work_lower_bound_at_first_prepare() {
    for seed in [1, 2, 3] {
        let mut sc = Scenario::base("clock_guard_due_work_lower_bound", seed, 4);
        sc.demotion_window = 8;
        sc.byz = vec![(3, Vec::new())];
        sc.workload = None;
        let lag = lag(DRIFT, &sc);
        sc.duration = 104 * lag;
        // Old signed work can be delivered after an idle interval. Its genuine creation
        // floor and the prior committed parent allow the Byzantine leader's stale stamp;
        // only CT5 excludes that otherwise deterministic-valid proposal.
        for batch in 1..=12 {
            sc.script.push((
                8 * lag * batch,
                Fault::Custom(Box::new(move |world: &mut World| {
                    let id = batch;
                    world.next_tx = id;
                    world.txs[0].insert(id, (0, false, None));
                    world.offer_tx(3, id, encode_tx_with_due(id, false, true, 0));
                })),
            ));
            // Give the Byzantine leader the original aged input first so an honest
            // fresh proposal cannot consume every batch before CT5 is exercised.
            sc.script.push((
                8 * lag * batch + 4 * lag,
                Fault::Custom(Box::new(move |world: &mut World| {
                    let id = batch;
                    for replica in 0..world.replicas.len() {
                        world.offer_tx(replica, id, encode_tx_with_due(id, false, true, 0));
                    }
                })),
            ));
        }
        guarded(
            &mut sc,
            ClockGuard {
                max_clock_drift_ms: DRIFT,
                due_work_max_lag_ms: lag,
                leads: vec![(3, vec![-i64::try_from(2 * lag).unwrap()])],
                ..ClockGuard::default()
            },
        );
        let w = crate::sim::run(sc).unwrap_or_else(|report| panic!("seed={seed}: {report}"));
        let guard = guard_of(&w);
        assert!(
            guard
                .events
                .iter()
                .any(|event| { event.rule == GuardRule::StaleDueWork && !event.certified }),
            "seed={seed}: stale due-work proposals reached an honest executor"
        );
        assert!(
            guard.first_due_prepares.len() >= 10,
            "seed={seed}: genuine Prepares checked"
        );
        assert!(
            guard.certified.len() >= 10,
            "seed={seed}: honest leaders progressed"
        );
        assert!(
            guard
                .certified
                .iter()
                .all(|certificate| certificate.proposer != Some(3))
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

/// A real World execution retains the event owner's clock through completion and signing.
#[test]
fn det_ct5_world_retained_execution_rechecks_clock_at_first_prepare() {
    use crate::crypto::{Signer, SigningError};
    let mut scenario = Scenario::base("ct5-retained-first-prepare", 7, 4);
    scenario.workload = None;
    guarded(
        &mut scenario,
        ClockGuard {
            max_clock_drift_ms: 100,
            due_work_max_lag_ms: 1_000,
            ..ClockGuard::default()
        },
    );
    let mut world = World::new(scenario);
    let replica = world.replica_of(0, 0).unwrap();
    let base = u64::try_from(world.wall_ms(0)).unwrap();
    let mut payload = encode_tx_with_due(11, false, true, 0);
    world.stamp_block_time(0, &mut payload);
    let instance = &world.instances[0];
    let body = fixture_body(
        crate::message::BlockHeader {
            control_witness: crate::types::ControlWitness::empty(),
            epoch: instance.config(1).epoch.id,
            instance: instance.id,
            height: 1,
            origin_view: 0,
            parent_hash: instance.genesis_hash,
            parent_result: instance.genesis_result,
            payload_hash: Hash32::ZERO,
            availability_digest: Hash32::ZERO,
            payload_len: 0,
            proposer: 0,
            skipped_leaders: Vec::new(),
        },
        &payload,
    );
    let hash = body.hash(&crate::testing::FakeCrypto::new());
    let parent = world.instances[0].genesis_result;
    let (outcome, _) = world.exec_outcome(replica, &body, &hash, &parent, false);
    let ExecOutcome::Valid { result, admission } = outcome else {
        panic!("real due-work fixture executes");
    };
    let request = |certified| {
        crate::testing::prepare_signing_request(
            body.header().instance,
            body.header().epoch,
            body.header().height,
            0,
            hash,
            result,
            certified,
        )
    };
    assert_eq!(admission.check(&request(false)), Ok(()));
    world.set_wall_offset(0, 1_000);
    assert_eq!(
        admission.check(&request(false)),
        Ok(()),
        "inclusive freshness boundary"
    );
    world.set_wall_offset(0, 1_001);
    let signer = crate::sim::crypto::SimSigner::new(
        world.replicas[replica].keys[0].clone(),
        Some(0),
        world.log.clone(),
    );
    let before = world.log.lock().unwrap().len();
    assert_eq!(
        signer.sign_prepare(&request(false), &admission),
        Err(SigningError::StaleExecution {
            block_time_ms: base,
            observed_ms: base + 1_001,
            max_lag_ms: 1_000,
        }),
        "a retained World result must not sign after its actual wall clock advances"
    );
    assert_eq!(
        world.log.lock().unwrap().len(),
        before,
        "freshness refusal produces no signature"
    );
    assert!(
        signer.sign_prepare(&request(true), &admission).is_ok(),
        "the exact source's genuine-PQC path remains usable"
    );
    let foreign = crate::testing::prepare_signing_request(
        body.header().instance,
        body.header().epoch,
        body.header().height,
        0,
        Hash32::ZERO,
        result,
        true,
    );
    assert_eq!(admission.check(&foreign), Err(SigningError::InvalidInput));
    world.set_wall_offset(0, 0);
    assert_eq!(admission.check(&request(false)), Ok(()));
    world.run_until(2_000);
    assert!(
        matches!(
            admission.check(&request(false)),
            Err(SigningError::StaleExecution { .. })
        ),
        "ordinary event-time advancement also updates the retained signing clock"
    );
}

/// CT1 also guards an ordinary cached execution after the actual signing wall rewinds.
#[test]
fn det_ct1_world_retained_execution_rechecks_rewind_before_first_prepare() {
    use crate::crypto::{Signer, SigningError};

    for due in [false, true] {
        let mut scenario = Scenario::base("ct1-retained-first-prepare", 7, 4);
        scenario.workload = None;
        guarded(
            &mut scenario,
            ClockGuard {
                max_clock_drift_ms: 1_000,
                due_work_max_lag_ms: 60_000,
                ..ClockGuard::default()
            },
        );
        let mut world = World::new(scenario);
        let replica = world.replica_of(0, 0).unwrap();
        let base = u64::try_from(world.wall_ms(0)).unwrap();
        let mut payload = encode_tx_with_due(11, false, due, 0);
        world.stamp_block_time(0, &mut payload);
        let instance = &world.instances[0];
        let body = fixture_body(
            crate::message::BlockHeader {
                control_witness: crate::types::ControlWitness::empty(),
                epoch: instance.config(1).epoch.id,
                instance: instance.id,
                height: 1,
                origin_view: 0,
                parent_hash: instance.genesis_hash,
                parent_result: instance.genesis_result,
                payload_hash: Hash32::ZERO,
                availability_digest: Hash32::ZERO,
                payload_len: 0,
                proposer: 0,
                skipped_leaders: Vec::new(),
            },
            &payload,
        );
        let hash = body.hash(&crate::testing::FakeCrypto::new());
        let parent = world.instances[0].genesis_result;
        let (outcome, _) = world.exec_outcome(replica, &body, &hash, &parent, false);
        let ExecOutcome::Valid { result, admission } = outcome else {
            panic!("original ordinary and due-work fixtures execute before the rewind");
        };
        let request = |certified| {
            crate::testing::prepare_signing_request(
                body.header().instance,
                body.header().epoch,
                body.header().height,
                0,
                hash,
                result,
                certified,
            )
        };
        assert_eq!(admission.check(&request(false)), Ok(()));
        // A later policy must not relax the original execution's captured allowance.
        world.clock_guard.as_mut().unwrap().max_clock_drift_ms = 10_000;
        world.set_wall_offset(0, -1_001);
        let signer = crate::sim::crypto::SimSigner::new(
            world.replicas[replica].keys[0].clone(),
            Some(0),
            world.log.clone(),
        );
        let before = world.log.lock().unwrap().len();
        assert_eq!(
            signer.sign_prepare(&request(false), &admission),
            Err(SigningError::ClockAhead {
                block_time_ms: base,
                observed_ms: base - 1_001,
                max_clock_drift_ms: 1_000,
            }),
            "a retained World result must not sign after its actual wall clock rewinds beyond the original drift"
        );
        assert_eq!(
            world.log.lock().unwrap().len(),
            before,
            "clock-ahead refusal produces no first signature"
        );
        assert_eq!(
            admission.check(&request(true)),
            Ok(()),
            "exact certified execution keeps its clock exemption"
        );
        let foreign = crate::testing::prepare_signing_request(
            body.header().instance,
            body.header().epoch,
            body.header().height,
            0,
            Hash32::ZERO,
            result,
            true,
        );
        assert_eq!(admission.check(&foreign), Err(SigningError::InvalidInput));
        world.set_wall_offset(0, -1_000);
        assert!(
            signer.sign_prepare(&request(false), &admission).is_ok(),
            "the original execution resumes at exact drift equality"
        );
    }
}
