//! §13.5 driver conformance: the production kernel runs every honest replica of the
//! `iroha_sumeragi` simulator's seeded worlds, under the world's oracles checked after every
//! event — O-AGR, O-SIGN, O-PBS, O-LIVE and O-MEM among them — and the O4 answer oracle of the
//! host. Scenarios F9 (loss, duplication, reordering), F13 (crash-restart churn at action
//! boundaries and write completions), F14 (whole-cluster restarts), F27 (failed writes retried
//! by the driver, store tail loss, key-store rollback), F29 (CPU flood, Tick lateness P6), F32
//! (cluster restarts around a lock or a `CommitQC`) and F37 (genuine signer supersets
//! rejected by exact-quorum checks); and the O2 kill of a replica at each write completion.
//!
//! Seeds: `SUMERAGI_SIM_SEEDS` (count per scenario, default 3 in debug, 8 in release) from
//! `SUMERAGI_SIM_SEED_BASE`, or `SUMERAGI_SIM_SEED` for exactly one.

use iroha_sumeragi::sim::{
    Scenario, World, run,
    scenario::{Fault, IoKill},
    scenarios::{self, Builder},
    world::seeds,
};

use super::sim_host::{PEAK_HELD, STARTS, driver_host};

fn default_seeds() -> u64 {
    if cfg!(debug_assertions) { 3 } else { 8 }
}

/// Run `builder` over the seeds with the driver hosting every honest replica; panic with the
/// first failure report.
fn conformance(name: &str, builder: Builder) -> Vec<World> {
    let mut worlds = Vec::new();
    for seed in seeds(default_seeds()) {
        let mut sc = builder(seed);
        sc.host = driver_host;
        let honest = (0..sc.machines()).filter(|m| !sc.is_byz(*m)).count();
        STARTS.with(|s| s.set(0));
        let world = run(sc).unwrap_or_else(|report| panic!("{name} (driver host): {report}"));
        let starts = STARTS.with(std::cell::Cell::get);
        assert!(
            starts >= u64::try_from(honest).unwrap(),
            "{name} seed {seed}: the driver hosted every honest replica ({starts} starts)"
        );
        let heights = world.oracle.refs[0].len();
        assert!(heights > 0, "{name} seed {seed}: nothing committed");
        eprintln!(
            "{name} seed {seed}: {heights} heights, {} crashes, {} events",
            world.stats.crashes, world.stats.events
        );
        worlds.push(world);
    }
    worlds
}

#[test]
fn f09_loss_duplication_reordering() {
    conformance("F9", scenarios::f09);
}

#[test]
fn f13_crash_restart_churn() {
    let worlds = conformance("F13", scenarios::f13);
    assert!(worlds.iter().any(|w| w.stats.crashes > 0));
}

#[test]
fn f14_whole_cluster_restart() {
    conformance("F14", scenarios::f14);
}

#[test]
fn f27_storage_faults_retried() {
    conformance("F27", scenarios::f27);
}

#[test]
fn f29_cpu_flood() {
    conformance("F29", scenarios::f29);
}

#[test]
fn f32_cluster_restart_lock_or_cqc() {
    conformance("F32", scenarios::f32);
}

#[test]
fn exact_quorum_adversary_commits_through_driver() {
    let worlds = conformance("exact-quorum", scenarios::exact_quorum_adversary);
    assert!(worlds.iter().all(|world| !world.oracle.refs[0].is_empty()));
}

/// O2 on the driver: a replica killed at each of its first write completions — just before the
/// write is durable, or right after it and before anything waiting for it — never exposed
/// anything its durable record did not cover (O-PBS at every exposure), never signed twice
/// (O-SIGN) and rejoins (O-AGR, O-LIVE).
#[test]
fn o2_kill_at_each_write_completion() {
    let base = || {
        let mut sc: Scenario = scenarios::smoke(0, 4);
        sc.host = driver_host;
        sc.heal_at = 12_000;
        sc.duration = 25_000;
        sc
    };
    let plain = run(base()).unwrap_or_else(|e| panic!("{e}"));
    let writes = plain.io_completions[0];
    assert!(writes >= 40, "{writes}");
    let last = if cfg!(debug_assertions) {
        40
    } else {
        writes.min(120)
    };
    for nth in 1..=last {
        for before_durable in [true, false] {
            let mut sc = base();
            sc.io_kill = Some(IoKill {
                machine: 0,
                nth,
                before_durable,
                down: 300,
            });
            let world = run(sc)
                .unwrap_or_else(|e| panic!("kill at write {nth} (before {before_durable}): {e}"));
            assert_eq!(world.stats.crashes, 1, "write {nth}");
            assert!(
                world.committed(0) >= 5,
                "write {nth}: {}",
                world.committed(0)
            );
        }
    }
}

/// A replica's disk fails every write for 20 s while the others commit, then recovers. The
/// core keeps running behind its unwritten record (timeouts, rebroadcasts, requests), yet the
/// driver's queues stay within the O-MEM bounds after every event — held effects, one queued
/// record per key, bodies of unapplied heights only, bounded executor and serving queues — and
/// the replica catches up afterwards (O-AGR, O-LIVE).
#[test]
fn long_write_failure_keeps_queues_bounded() {
    for seed in seeds(default_seeds()) {
        let mut sc: Scenario = scenarios::smoke(seed, 4);
        sc.host = driver_host;
        let victim = usize::try_from(seed % 4).unwrap();
        let fail = move |ppm: u32| -> Fault {
            Fault::Custom(Box::new(move |world: &mut World| {
                world.machines[victim].profile.write_fail_ppm = ppm;
            }))
        };
        sc.script.push((5_000, fail(1_000_000)));
        sc.script.push((25_000, fail(0)));
        sc.heal_at = 25_000;
        sc.duration = 45_000;
        PEAK_HELD.with(|peak| peak.set(0));
        let world = run(sc).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
        let peak = PEAK_HELD.with(std::cell::Cell::get);
        assert!(
            peak >= 20,
            "seed {seed}: the victim held its effects ({peak})"
        );
        let lead = world.committed(if victim == 0 { 1 } else { 0 });
        assert!(
            world.committed(victim) + 3 >= lead,
            "seed {seed}: the victim caught up ({} of {lead})",
            world.committed(victim)
        );
        eprintln!(
            "long write failure seed {seed}: victim {victim}, peak held {peak}, {lead} heights"
        );
    }
}
