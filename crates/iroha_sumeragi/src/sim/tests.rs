//! Scenario tests (§13.3) over many seeds, the multi-node named deterministic test deferred by
//! the state-machine stage (`det_l12`), and an ignored performance report.
//!
//! Seeds: `SUMERAGI_SIM_SEEDS` per scenario (default 5 in debug, 20 in release),
//! `SUMERAGI_SIM_SEED_BASE`, or `SUMERAGI_SIM_SEED` for exactly one seed.

use super::{
    byz::Strategy,
    host::{FakeHost, Host, Start},
    run,
    scenario::{Perf, Profile, Scenario},
    scenarios::{self, Builder},
    sweep::{Failures, fold_seeds},
    world::{World, seed_iter},
};
use crate::types::Millis;

fn default_seeds() -> u64 {
    if cfg!(debug_assertions) { 5 } else { 20 }
}

/// Run `builder` over the configured seeds; check each World before releasing it.
fn sweep(name: &str, builder: Builder, check: impl Fn(&World) + Sync) {
    sweep_observations(name, builder, check, |()| {});
}

/// Extract bounded observations after every original per-World assertion, then fold in seed
/// order. No host, Core, payload custody or World crosses its worker boundary.
fn sweep_observations<T: Send>(
    name: &str,
    builder: Builder,
    observe: impl Fn(&World) -> T + Sync,
    mut fold: impl FnMut(T),
) {
    let mut failures = Failures::default();
    let mut heights = 0;
    let mut view_changes = 0;
    let mut crashes = 0;
    let mut evidence = 0;
    let mut lost = 0;
    let mut ingress_drops = 0;
    let mut peaks = std::collections::BTreeMap::<u32, usize>::new();
    fold_seeds(
        seed_iter(default_seeds()),
        |seed| {
            run(builder(seed)).map(|world| {
                let observation = observe(&world);
                let heights = world
                    .oracle
                    .refs
                    .iter()
                    .map(|r| r.len() as u64)
                    .sum::<u64>();
                let view_changes = world
                    .oracle
                    .refs
                    .iter()
                    .map(|r| r.values().filter(|b| b.view > 0).count() as u64)
                    .sum::<u64>();
                let ingress_drops = world
                    .replicas
                    .iter()
                    .map(|r| r.host.ingress_drops())
                    .sum::<u64>();
                let mut peaks = std::collections::BTreeMap::<u32, usize>::new();
                for r in world.honest() {
                    *peaks
                        .entry(world.oracle.reps[r].max_start_level)
                        .or_default() += 1;
                }
                let counters = (
                    heights,
                    view_changes,
                    world.stats.crashes,
                    world.stats.evidence,
                    world.stats.lost,
                    ingress_drops,
                );
                drop(world);
                (observation, counters, peaks)
            })
        },
        |seed, result| {
            if let Some((observation, counters, seed_peaks)) = failures.observe(seed, result) {
                heights += counters.0;
                view_changes += counters.1;
                crashes += counters.2;
                evidence += counters.3;
                lost += counters.4;
                ingress_drops += counters.5;
                for (level, count) in seed_peaks {
                    *peaks.entry(level).or_default() += count;
                }
                fold(observation);
            }
        },
    );
    eprintln!(
        "{name}: {} seeds passed, {} failed; heights {heights}, commits after a view \
         change {view_changes}, crashes {crashes}, evidence {evidence}, lost {lost}, \
         ingress drops {ingress_drops}, peak start levels {peaks:?}",
        failures.passed,
        failures.failed(),
    );
    failures.finish(name);
}

/// Retain only aggregate statistics between seeds, so nightly memory is independent of the
/// seed count. Each scenario-specific assertion sees the complete World before it is dropped.
fn sweep_seeds(
    name: &str,
    builder: Builder,
    seeds: impl IntoIterator<Item = u64>,
    mut check: impl FnMut(&World),
) {
    let mut passed = 0;
    let mut failed = Vec::new();
    let mut first_failure = None;
    let mut heights = 0;
    let mut view_changes = 0;
    let mut crashes = 0;
    let mut evidence = 0;
    let mut lost = 0;
    let mut ingress_drops = 0;
    // Peak start level (§9.2) → honest replicas.
    let mut peaks = std::collections::BTreeMap::<u32, usize>::new();
    for seed in seeds {
        match run(builder(seed)) {
            Ok(world) => {
                check(&world);
                passed += 1;
                heights += world
                    .oracle
                    .refs
                    .iter()
                    .map(|r| r.len() as u64)
                    .sum::<u64>();
                view_changes += world
                    .oracle
                    .refs
                    .iter()
                    .map(|r| r.values().filter(|b| b.view > 0).count() as u64)
                    .sum::<u64>();
                crashes += world.stats.crashes;
                evidence += world.stats.evidence;
                lost += world.stats.lost;
                ingress_drops += world
                    .replicas
                    .iter()
                    .map(|r| r.host.ingress_drops())
                    .sum::<u64>();
                for r in world.honest() {
                    *peaks
                        .entry(world.oracle.reps[r].max_start_level)
                        .or_default() += 1;
                }
            }
            Err(report) => {
                failed.push(seed);
                first_failure.get_or_insert(report);
            }
        }
    }
    eprintln!(
        "{name}: {passed} seeds passed, {} failed; heights {heights}, commits after a view \
         change {view_changes}, crashes {crashes}, evidence {evidence}, lost {lost}, \
         ingress drops {ingress_drops}, peak start levels {peaks:?}",
        failed.len(),
    );
    if let Some(report) = first_failure {
        panic!(
            "{name}: failing seeds {failed:?}; first (seed {}):\n{report}",
            failed[0]
        );
    }
}

#[test]
fn sweep_releases_each_world_before_running_the_next_seed() {
    let mut previous = std::sync::Weak::new();
    let mut observed = Vec::new();
    sweep_seeds(
        "bounded sweep",
        |seed| {
            let mut scenario = scenarios::smoke(seed, 4);
            scenario.duration = 1_000;
            scenario.checks.progress = 0;
            scenario
        },
        0..3,
        |world| {
            assert!(
                previous.upgrade().is_none(),
                "the previous World was retained"
            );
            previous = std::sync::Arc::downgrade(&world.log);
            observed.push(world.seed);
        },
    );
    assert_eq!(observed, vec![0, 1, 2]);
    assert!(previous.upgrade().is_none(), "the final World was retained");
}

#[test]
fn smoke_all_honest() {
    for n in [1, 4, 7] {
        let world = run(scenarios::smoke(0, n)).unwrap_or_else(|e| panic!("{e}"));
        let heights: Vec<u64> = world.honest().iter().map(|r| world.committed(*r)).collect();
        assert!(heights.iter().all(|h| *h >= 30), "{heights:?}");
    }
}

#[test]
fn sim_is_deterministic() {
    let a = run(scenarios::f09(3)).unwrap_or_else(|e| panic!("{e}"));
    let b = run(scenarios::f09(3)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(a.stats.events, b.stats.events);
    assert_eq!(a.stats.bytes, b.stats.bytes);
    let tips = |w: &World| -> Vec<_> { w.oracle.refs[0].values().map(|b| b.bh).collect() };
    assert_eq!(tips(&a), tips(&b));
}

macro_rules! scenario_test {
    ($test:ident, $name:literal, $builder:path) => {
        #[test]
        fn $test() {
            sweep($name, $builder, |_| {});
        }
    };
}

scenario_test!(f01_crashed_leaders, "F1", scenarios::f01);
scenario_test!(f02_silent_proxy_tail, "F2", scenarios::f02);
scenario_test!(f03_withholding_proxy_tail, "F3", scenarios::f03);
scenario_test!(f04_silent_or_slow_set_a, "F4", scenarios::f04);

#[test]
fn f04_progress_keeps_eight_heights_for_slow_rotations() {
    for seed in [1_139, 8_479] {
        let mut world = World::new(scenarios::f04(seed));
        let minimum = world.duration;
        world.run_until(minimum);
        assert!(world.failure.is_none());
        assert_eq!(world.now, minimum);
        assert!(world.honest().iter().any(|r| world.committed(*r) < 8));
        for r in world.honest() {
            if world.committed(r) < 8 {
                assert!(world.oracle.reps[r].deadline > minimum);
            }
        }
        world.run().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            world.duration, minimum,
            "minimum observation remains unchanged"
        );
        assert!(world.now > minimum);
        for r in world.honest() {
            assert!(world.committed(r) >= 8, "seed {seed}, replica {r}");
        }
        eprintln!(
            "F04 seed {seed}: all eight heights observed at t={}",
            world.now
        );
    }
}

scenario_test!(f05_equivocating_leader, "F5", scenarios::f05);
scenario_test!(f06_vote_withholders, "F6", scenarios::f06);
scenario_test!(f07_adversarial_tc_composition, "F7", scenarios::f07);
scenario_test!(f08_split_brain, "F8", scenarios::f08);
scenario_test!(f09_loss_dup_reorder, "F9", scenarios::f09);
scenario_test!(f10_delay_spikes, "F10", scenarios::f10);
scenario_test!(f11_partitions, "F11", scenarios::f11);
scenario_test!(f12_clock_skew_drift, "F12", scenarios::f12);
scenario_test!(f13_crash_restart_churn, "F13", scenarios::f13);
scenario_test!(f14_whole_cluster_restart, "F14", scenarios::f14);
#[test]
fn f15_slow_executors() {
    // `(variant, peak start level, final start level)` → honest replicas.
    let mut levels = std::collections::BTreeMap::<(u64, u32, u32), usize>::new();
    sweep_observations(
        "F15",
        scenarios::f15,
        |world| {
            let mut levels = std::collections::BTreeMap::<(u64, u32, u32), usize>::new();
            // §9.2 adaptation: where every executor is slower than `T(0)/2` (variants 1, 4 and 5),
            // the start level rose at every honest replica; in variant 4 executions become fast at
            // 20 s, so it decayed back to 0 by the end. In variant 5 only non-empty blocks are
            // slow (`E ≥ T(1)`), so without the adaptation only `EMPTY` blocks would commit.
            let variant = world.seed % 6;
            if variant == 5 {
                let payload = world.oracle.refs[0]
                    .values()
                    .filter(|b| b.header.payload_len > 0)
                    .count();
                assert!(
                    payload >= 5,
                    "seed {}: only {payload} non-empty blocks of {} committed",
                    world.seed,
                    world.oracle.refs[0].len()
                );
            }
            if variant != 1 && variant != 4 && variant != 5 {
                return levels;
            }
            for r in world.honest() {
                let Some(core) = world.replicas[r].host.core() else {
                    continue;
                };
                let max = world.oracle.reps[r].max_start_level;
                let last = core.status().start_level;
                assert!(
                    max >= 2,
                    "seed {}: replica {r} start level peaked at {max}",
                    world.seed
                );
                if variant == 4 {
                    assert_eq!(last, 0, "seed {}: replica {r} did not decay", world.seed);
                }
                *levels.entry((variant, max, last)).or_default() += 1;
            }
            levels
        },
        |seed_levels| {
            for (key, count) in seed_levels {
                *levels.entry(key).or_default() += count;
            }
        },
    );
    eprintln!("F15 start levels (variant, peak, final) → replicas: {levels:?}");
}
scenario_test!(f16_validator_set_change, "F16", scenarios::f16);
#[test]
fn f17_far_behind_joiner() {
    sweep("F17", scenarios::f17, |world| {
        // The joiner (machine 4, empty store at start) caught up past the pre-built chain.
        let joiner = world.replica_of(4, 0).unwrap_or(0);
        let prebuilt = world.oracle.refs[0].values().filter(|b| b.at == 0).count() as u64;
        assert!(
            world.committed(joiner) > prebuilt,
            "seed {}: joiner at {} of {prebuilt}",
            world.seed,
            world.committed(joiner)
        );
    });
}
scenario_test!(f18_floods, "F18", scenarios::f18);
scenario_test!(f19_poison_payload, "F19", scenarios::f19);
scenario_test!(f20_cross_instance_replay, "F20", scenarios::f20);
scenario_test!(f21_divergent_executor, "F21", scenarios::f21);
/// An idle chain keeps its genesis tip while timers continue within the live-state bound.
fn assert_idle_chain(world: &World) {
    assert!(
        world
            .oracle
            .refs
            .iter()
            .all(std::collections::BTreeMap::is_empty)
    );
    for replica in world.honest() {
        assert_eq!(
            world.committed(replica),
            0,
            "idle replica {replica} committed"
        );
        let core = world.replicas[replica]
            .host
            .core()
            .expect("the idle replica remains running");
        let status = core.status();
        assert_eq!(status.height, 1);
        assert_eq!(status.committed_height, 0);
        assert_eq!(status.applied_height, 0);
        assert!(status.halted.is_none());
        assert!(status.footprint.within(&core.footprint_bound()));
        assert!(world.replicas[replica].bodies.is_empty());
    }
}

#[test]
fn f22_idle_chain() {
    sweep("F22", scenarios::f22, assert_idle_chain);
}
scenario_test!(f23_non_3f1_committees, "F23", scenarios::f23);
#[test]
fn f24_record_corruption_and_loss() {
    sweep("F24", scenarios::f24, |world| {
        // R2 works under every variant (forged, replayed and relayed echoes, rolled-back key
        // stores, reinstalled keys): every honest node that lost a record anchors again.
        for r in world.honest() {
            let Some(core) = world.replicas[r].host.core() else {
                continue;
            };
            let status = core.status();
            assert!(
                status.halted.is_some() || !status.unanchored,
                "seed {}: replica {r} is still unanchored at the end",
                world.seed
            );
        }
    });
}
scenario_test!(f25_relay_tampering, "F25", scenarios::f25);
scenario_test!(f26_byzantine_responders, "F26", scenarios::f26);
scenario_test!(f27_storage_faults, "F27", scenarios::f27);
scenario_test!(f28_key_rotation, "F28", scenarios::f28);
scenario_test!(f29_cpu_flood, "F29", scenarios::f29);
scenario_test!(f32_cluster_restart_lock_or_cqc, "F32", scenarios::f32);
scenario_test!(f33_hidden_pqc, "F33", scenarios::f33);
scenario_test!(f34_late_entrants, "F34", scenarios::f34);
scenario_test!(f35_local_queue_asymmetry, "F35", scenarios::f35);

/// The original sparse-work failures at n = 22 stay covered even in the default short sweep.
#[test]
fn f35_sparse_local_work_regression_seeds() {
    sweep_seeds("F35 regressions", scenarios::f35, [6, 31, 78, 87], |_| {});
}

/// The F35 leader-turn bound (Appendix E, E62) is not vacuous: holders whose builders never
/// return work (each prices payloads at its own 1.5 s base cost, above `exec_budget`, §9.1)
/// let the first holder turn `v*` fail, and the oracle names that view and its leader.
#[test]
fn leader_turns_flags_holders_without_work() {
    let mut sc = scenarios::f35(0);
    let Perf::LeaderTurns(holders) = sc.checks.perf else {
        panic!("F35 checks the leader-turn bound");
    };
    for m in (0..sc.n).filter(|m| holders & (1 << m) != 0) {
        sc.set_profile(
            m,
            Profile {
                exec_base: 1_500,
                ..Profile::default()
            },
        );
    }
    let Err(report) = run(sc) else {
        panic!("holders without work must fail their turn");
    };
    assert!(
        report.contains("O-PERF LeaderTurns") && report.contains("led by running holder"),
        "{report}"
    );
}

#[test]
fn f36_late_leaders() {
    // `(n, peak start level)` → honest replicas.
    let mut levels = std::collections::BTreeMap::<(usize, u32), usize>::new();
    sweep_observations(
        "F36",
        scenarios::f36,
        |world| {
            let mut levels = std::collections::BTreeMap::<(usize, u32), usize>::new();
            // §9.2: a late but valid proposal or body never raises an honest start level before
            // the deliberate crash. A crash during the next certificate exchange may extend
            // actual body-to-commit latency and legitimately raise it; O-PERF still checks
            // every subsequent commit gap.
            let n = world.instances[0].committee(1).n();
            for r in world.honest() {
                let peak = world.oracle.reps[r].max_start_level_before_heal;
                assert!(
                    peak == 0,
                    "seed {}: replica {r} start level peaked at {peak}",
                    world.seed
                );
                *levels.entry((n, peak)).or_default() += 1;
            }
            levels
        },
        |seed_levels| {
            for (key, count) in seed_levels {
                *levels.entry(key).or_default() += count;
            }
        },
    );
    eprintln!("F36 start levels (n, peak) → replicas: {levels:?}");
}

#[test]
fn det_l30_crashed_proxy_latency_is_not_late_body_latency() {
    let world = run(scenarios::f36(1813)).expect("crashed proxy recovery stays within O-PERF");
    for replica in world.honest() {
        assert_eq!(
            world.oracle.reps[replica].max_start_level_before_heal, 0,
            "late body delivery alone must not raise replica {replica}'s start level"
        );
    }
    // Replica 1 gets the body at 60013 ms, after machine 5 crashes at 60000 ms.
    // Retrying votes through the stage ladder delays CommitQC to 61136 ms: this
    // genuinely exceeds T(0)/2 and §9.2 must continue to adapt to that latency.
    assert_eq!(world.oracle.reps[1].max_start_level, 1);
}

#[test]
fn det_l30_late_rows_resume_service_after_release() {
    let world = run(scenarios::f36(70)).expect("released rows remain fetchable");
    for replica in world.honest() {
        assert_eq!(
            world.oracle.reps[replica].max_start_level, 0,
            "replica {replica}: F36 delays row release but does not withhold later fetches"
        );
    }
}

/// §7.4 (Restart), §13.1: every `Init` carries a fresh nonce drawn from the seeded PRNG.
#[test]
fn det_r4_fresh_nonce_per_init() {
    let world = World::new(scenarios::smoke(0, 4));
    let a = world.init_for(0).nonce;
    let b = world.init_for(0).nonce;
    let c = world.init_for(1).nonce;
    assert!(a != b && b != c && a != c, "{a} {b} {c}");
    // Deterministic from the seed.
    let again = World::new(scenarios::smoke(0, 4));
    assert_eq!(again.init_for(0).nonce, a);
}

#[test]
fn f30_max_size_blocks() {
    sweep("F30", scenarios::f30, |world| {
        assert_eq!(
            world.stats.oversize, 0,
            "no honest message exceeds the frame limit"
        );
    });
}

#[test]
fn f31_amx_two_phase_commit() {
    sweep("F31", scenarios::f31, |world| {
        let amx = world.amx.as_ref().expect("F31 runs the AMX application");
        assert!(!amx.seen.begun.is_empty(), "AMX begin coverage");
        assert!(!amx.seen.votes.is_empty(), "AMX prepare coverage");
        assert!(
            amx.seen
                .decided
                .values()
                .any(|(outcome, _, _)| *outcome == super::amx::Outcome::Commit),
            "AMX commit coverage"
        );
        assert!(
            amx.seen
                .decided
                .values()
                .any(|(outcome, _, _)| *outcome == super::amx::Outcome::Abort),
            "AMX abort coverage"
        );
        assert!(!amx.seen.settled.is_empty(), "AMX settlement coverage");
        let expected_handoffs = 4 * (world.instances.len() - 1);
        assert_eq!(
            amx.seen.handoffs,
            u64::try_from(expected_handoffs).unwrap(),
            "each dataspace and G authenticate both foreign epoch handoffs"
        );
        assert_eq!(world.machines[0].crashes, 1);
        assert!(world.machines[0].up);
        // While one instance stalls, the other keeps committing.
        for (inst, (from, until)) in [(1usize, (10_000, 30_000)), (0, (40_000, 60_000))] {
            let during = world.oracle.refs[inst]
                .values()
                .filter(|b| (from..until).contains(&b.at))
                .count();
            assert!(
                during >= 10,
                "instance {inst} committed {during} blocks while the other stalled"
            );
        }
    });
}

/// F39: the application clock guard under skewed honest wall clocks (§4.5): O-TIME at every
/// commit, and no block a Byzantine builder post-dated beyond the guard ever commits.
#[test]
fn f39_clock_guard() {
    sweep("F39", scenarios::f39, |world| {
        let guard = world
            .clock_guard
            .as_ref()
            .expect("F39 runs the clock guard");
        let bound = i64::try_from(2 * guard.max_clock_drift_ms).unwrap_or(i64::MAX);
        assert!(
            guard.certified.iter().all(|c| c.excess <= bound),
            "O-TIME holds at every commit"
        );
        assert!(guard.certified.len() >= 5, "the chain progressed");
    });
}

/// F38: a lane instance next to the global one, followed by every machine.
#[test]
fn f38_lane_next_to_global() {
    sweep("F38", scenarios::f38, |world| {
        let lane: Vec<usize> = (0..world.replicas.len())
            .filter(|r| world.replicas[*r].inst == 1)
            .collect();
        assert_eq!(
            lane.len(),
            world.machines.len(),
            "every machine runs the lane: its committee as members, the rest as observers"
        );
        // Every lane replica, observers included, reached the lane's committed tip (minus the
        // heights still in flight at the end of the run).
        let tip = world.oracle.refs[1].keys().max().copied().unwrap_or(0);
        assert!(tip >= 5, "the lane committed {tip} heights");
        for r in lane {
            assert!(
                world.committed(r) + 3 >= tip,
                "lane replica {r} committed {} of {tip}",
                world.committed(r)
            );
        }
    });
}

/// F22 over 100 000 retry intervals (flat memory, no idle blocks). Heavy: run with `--release
/// --ignored`.
#[test]
#[ignore = "heavy: 10^5 retry intervals"]
fn f22_idle_chain_100k_intervals() {
    let world = run(scenarios::f22_intervals(0, 100_000)).unwrap_or_else(|e| panic!("{e}"));
    assert_idle_chain(&world);
    eprintln!(
        "F22 100k: zero committed idle heights, bounded live state, signatures logged {}",
        world.log.lock().expect("signing log").len()
    );
}

/// `det_l12_tick_ahead_of_flood` (ML12, deferred from the state-machine stage): under an
/// ingress flood at the per-peer bound, the fake driver delivers `Tick` ahead of every message
/// (O5), so every tick is handled within `ε_tick` of `next_wakeup()`. The same run with FIFO
/// ingress (the ML12 mutation, a driver property) misses that bound, which shows the check
/// detects it.
#[test]
fn det_l12_tick_ahead_of_flood() {
    let build = |fifo: bool| {
        let mut sc = Scenario::base("det_l12", 12, 4);
        sc.duration = 30_000;
        sc.byz = vec![(
            3,
            vec![
                Strategy::CpuFlood,
                Strategy::Flood,
                Strategy::ForgeVotes,
                Strategy::ForgeCommitQc,
            ],
        )];
        // Verification is expensive enough that the flood saturates the CPU.
        for m in 0..4 {
            sc.set_profile(
                m,
                Profile {
                    cpu_us_per_pairing: 8_000,
                    fifo_ingress: fifo,
                    ..Profile::default()
                },
            );
        }
        sc.checks.perf = Perf::P6;
        sc.checks.progress = 3;
        sc
    };
    let world = run(build(false)).unwrap_or_else(|e| panic!("{e}"));
    let late = |w: &World| -> Millis {
        w.honest()
            .iter()
            .map(|r| w.replicas[*r].max_tick_late)
            .max()
            .unwrap_or(0)
    };
    let eps = world.bounds(0, 0).eps_tick;
    assert!(
        late(&world) <= eps,
        "priority lanes: {} ≤ {eps}",
        late(&world)
    );
    let mut fifo = World::new(build(true));
    fifo.checks.perf = Perf::None;
    fifo.checks.liveness = false;
    fifo.run_until(30_000);
    assert!(
        late(&fifo) > eps,
        "FIFO ingress must be detected: tick lateness {} vs ε {eps}",
        late(&fifo)
    );
}

/// Performance report: simulated commit latency and messages per height for n = 4 and n = 22
/// in the normal case, with a silent proxy tail, with one crashed set-A member, and with 10 %
/// loss. Run with `cargo test --release -p iroha_sumeragi sim::tests::report -- --ignored
/// --nocapture`.
#[test]
#[ignore = "report"]
fn report() {
    eprintln!(
        "{:<4} {:<22} {:>8} {:>10} {:>10} {:>10} {:>12}",
        "n", "case", "heights", "gap avg", "gap p99", "latency", "msgs/height"
    );
    for n in [4usize, 22] {
        for case in [
            "normal",
            "silent proxy tail",
            "crashed set-A member",
            "10% loss",
        ] {
            let mut sc = Scenario::base("report", 1, n);
            sc.duration = 120_000;
            sc.checks.progress = 0;
            match case {
                "silent proxy tail" => {
                    sc.byz = vec![(1, vec![Strategy::WithholdQcs(super::byz::Deliver::Nobody)])];
                }
                "crashed set-A member" => {
                    // A member that is in set A of height 5 (and not its leader).
                    let (topo, machine_of) = super::world::preview(&sc, 5);
                    let round = topo.round(0);
                    let index = round.set_a().get(1).copied().unwrap_or(0);
                    let m = machine_of[usize::try_from(index).unwrap_or(0)];
                    sc.script.push((0, super::scenario::Fault::Crash(m)));
                }
                "10% loss" => {
                    sc.net.loss_ppm = 100_000;
                    sc.net.post_heal_loss_ppm = 100_000;
                }
                _ => {}
            }
            let world = run(sc).unwrap_or_else(|e| panic!("{e}"));
            let blocks: Vec<_> = world.oracle.refs[0].values().collect();
            let heights = u64::try_from(blocks.len()).unwrap_or(0);
            let mut gaps: Vec<Millis> = blocks.windows(2).map(|w| w[1].at - w[0].at).collect();
            gaps.sort_unstable();
            let avg = gaps.iter().sum::<Millis>() / u64::try_from(gaps.len().max(1)).unwrap_or(1);
            let p99 = gaps
                .get((gaps.len() * 99).div_ceil(100).saturating_sub(1))
                .copied()
                .unwrap_or(0);
            let latency = world.oracle.commit_latency();
            let msgs = world.stats.packets.iter().sum::<u64>() / heights.max(1);
            eprintln!(
                "{n:<4} {case:<22} {heights:>8} {avg:>8}ms {p99:>8}ms {latency:>8}ms {msgs:>12}"
            );
        }
    }
}

std::thread_local! {
    /// Inputs handled by [`Wrapped`] hosts on this test thread.
    static WRAPPED_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// A trivial external node implementation (§13.5): it delegates every call to the fake driver
/// and counts the inputs it handles.
#[derive(Default)]
struct Wrapped(FakeHost);

impl Host for Wrapped {
    fn start(
        &mut self,
        start: Start,
    ) -> Result<Vec<crate::api::Action>, Box<dyn std::error::Error>> {
        self.0.start(start)
    }

    fn crash(&mut self) {
        self.0.crash();
    }

    fn running(&self) -> bool {
        self.0.running()
    }

    fn receive(
        &mut self,
        from: crate::types::PublicKey,
        msg: crate::message::WireMessage,
        class: crate::message::TrafficClass,
    ) {
        self.0.receive(from, msg, class);
    }

    fn deliver(&mut self, event: crate::api::Event) {
        self.0.deliver(event);
    }

    fn has_input(&self) -> bool {
        self.0.has_input()
    }

    fn next_input(&mut self, now: Millis) -> Option<crate::api::Event> {
        self.0.next_input(now)
    }

    fn handle(&mut self, now: Millis, event: crate::api::Event) -> Vec<crate::api::Action> {
        WRAPPED_CALLS.with(|calls| calls.set(calls.get() + 1));
        self.0.handle(now, event)
    }

    fn next_wakeup(&self) -> Millis {
        self.0.next_wakeup()
    }

    fn persisting(&mut self, write: u64) {
        self.0.persisting(write);
    }

    fn gate(&mut self, effect: crate::api::Action) -> Option<crate::api::Action> {
        self.0.gate(effect)
    }

    fn durable(&mut self, write: u64) -> Vec<crate::api::Action> {
        self.0.durable(write)
    }

    fn core(&self) -> Option<&crate::Core> {
        self.0.core()
    }

    fn held(&self) -> Vec<crate::api::Action> {
        self.0.held()
    }

    fn ingress_drops(&self) -> u64 {
        self.0.ingress_drops()
    }
}

fn wrapped_host(_machine: usize, _instance: usize) -> Box<dyn Host> {
    Box::new(Wrapped::default())
}

/// §13.5 host seam: a scenario runs through an external node implementation (here a wrapper
/// that delegates to the fake driver) with every oracle, and the run is identical to the one on
/// the default host — the seam carries every input and effect, crashes and restarts included
/// (F13 churn).
#[test]
fn host_seam_runs_a_wrapped_host() {
    let cases: [(&str, Builder, u64); 2] = [("F9", scenarios::f09, 3), ("F13", scenarios::f13, 1)];
    for (name, builder, seed) in cases {
        let plain = run(builder(seed)).unwrap_or_else(|e| panic!("{e}"));
        WRAPPED_CALLS.with(|calls| calls.set(0));
        let mut sc = builder(seed);
        sc.host = wrapped_host;
        let wrapped = run(sc).unwrap_or_else(|e| panic!("{e}"));
        let calls = WRAPPED_CALLS.with(std::cell::Cell::get);
        assert_eq!(
            calls, wrapped.stats.events,
            "{name}: every input went through the host"
        );
        assert!(calls > 1_000, "{name}: {calls}");
        assert_eq!(plain.stats.events, wrapped.stats.events, "{name}");
        assert_eq!(plain.stats.bytes, wrapped.stats.bytes, "{name}");
        assert_eq!(plain.stats.crashes, wrapped.stats.crashes, "{name}");
        let chain = |w: &World| -> Vec<_> { w.oracle.refs[0].values().map(|b| b.bh).collect() };
        assert_eq!(
            chain(&plain),
            chain(&wrapped),
            "{name}: the same committed chain"
        );
    }
}

/// §13.5 O2 hook: a machine killed at its `n`-th write completion — just before the write is
/// durable, or right after and before anything waiting for it — for every early completion;
/// the oracles (O-PBS above all) hold, the machine restarts and the chain goes on.
#[test]
fn io_kill_at_each_write_completion() {
    use super::scenario::IoKill;
    let plain = run(scenarios::smoke(0, 4)).unwrap_or_else(|e| panic!("{e}"));
    let writes = plain.io_completions[0];
    assert!(writes > 40, "{writes}");
    for nth in 1..=24 {
        for before_durable in [true, false] {
            let mut sc = scenarios::smoke(0, 4);
            // The kill and the restart precede the heal time (as every crash of F13/F14/F27).
            sc.heal_at = 12_000;
            sc.duration = 30_000;
            sc.io_kill = Some(IoKill {
                machine: 0,
                nth,
                before_durable,
                down: 300,
            });
            let world = run(sc).unwrap_or_else(|e| panic!("nth {nth} {before_durable}: {e}"));
            assert_eq!(world.stats.crashes, 1, "nth {nth}");
            assert!(world.committed(0) >= 5, "nth {nth}: {}", world.committed(0));
        }
    }
}

/// O-CERT counts one exact quorum independently of the production certificate verifier.
#[test]
fn o_cert_requires_exactly_q_signers() {
    use super::crypto::SimSigner;
    use crate::{
        crypto::{Crypto, Signer},
        message::{Qc, TcEntry, TimeoutCert, VoteKind},
        preimage,
        testing::FakeCrypto,
        types::{AggregateSignature, Bitmap, Hash32, SIGNATURE_LEN},
    };
    let world = World::new(scenarios::exact_quorum_adversary(0));
    let instance = &world.instances[0];
    let committee = instance.committee(1);
    let (n, q) = (committee.n(), committee.q());
    let crypto = FakeCrypto::new();
    for count in [q - 1, q, q + 1] {
        let indices: Vec<_> = (n - count..n).map(crate::types::index_of).collect();
        for kind in [VoteKind::Prepare, VoteKind::Commit] {
            let mut qc = Qc {
                kind,
                epoch: instance.config(1).epoch.id,
                instance: instance.id,
                height: 1,
                view: 0,
                block_hash: Hash32([2; 32]),
                result: Hash32([3; 32]),
                signers: Bitmap::from_indices(n, indices.iter().copied()).unwrap(),
                agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
            };
            let signatures: Vec<_> = indices
                .iter()
                .map(|index| {
                    SimSigner::new(
                        committee.get(*index).unwrap().clone(),
                        None,
                        world.log.clone(),
                    )
                    .sign(&qc.preimage())
                })
                .collect();
            qc.agg_sig = crypto.aggregate(&signatures);
            assert_eq!(
                world.cert_qc(0, &qc).is_ok(),
                count == q,
                "kind={kind:?}, count={count}"
            );
        }
        let preimage =
            preimage::tmo_preimage(&instance.id, &instance.config(1).epoch.id, 1, 0, None);
        let signatures: Vec<_> = indices
            .iter()
            .map(|index| {
                SimSigner::new(
                    committee.get(*index).unwrap().clone(),
                    None,
                    world.log.clone(),
                )
                .sign(&preimage)
            })
            .collect();
        let tc = TimeoutCert {
            epoch: instance.config(1).epoch.id,
            instance: instance.id,
            height: 1,
            view: 0,
            entries: indices
                .iter()
                .map(|signer| TcEntry {
                    signer: *signer,
                    hq: None,
                })
                .collect(),
            agg_sig: crypto.aggregate(&signatures),
            high_pqc: None,
        };
        assert_eq!(world.cert_tc(0, &tc).is_ok(), count == q, "count={count}");
    }
}

/// Exact-quorum admission rejects genuine signer supersets without stalling honest progress.
#[test]
fn exact_quorum_under_genuine_superset_attack() {
    sweep("exact-quorum", scenarios::exact_quorum_adversary, |_| {});
}
