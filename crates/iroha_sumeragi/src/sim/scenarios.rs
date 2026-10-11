//! Fault scenarios F1–F39 of §13.3, each a function of the seed. Committee sizes rotate over
//! `n ∈ {1, 4, 5, 7, 22}` where meaningful (small sizes first, so that the few default seeds of
//! a debug run stay fast); every other random choice is drawn from a side stream of the seed.

use super::{
    byz::{Deliver, Late, NetRule, Strategy},
    driver::Clock,
    net::{Partition, Spike},
    oracle::leader_turns_bound,
    rng::{Rng, seed_of},
    scenario::{Churn, ClockGuard, CrashPoint, Fault, Perf, Profile, Scenario, Workload},
    world::preview,
};
use crate::{pacemaker::t_req_nominal, types::Millis};

/// A scenario builder.
pub type Builder = fn(u64) -> Scenario;

/// Every scenario by name.
pub const ALL: &[(&str, Builder)] = &[
    ("F1", f01),
    ("F2", f02),
    ("F3", f03),
    ("F4", f04),
    ("F5", f05),
    ("F6", f06),
    ("F7", f07),
    ("F8", f08),
    ("F9", f09),
    ("F10", f10),
    ("F11", f11),
    ("F12", f12),
    ("F13", f13),
    ("F14", f14),
    ("F15", f15),
    ("F16", f16),
    ("F17", f17),
    ("F18", f18),
    ("F19", f19),
    ("F20", f20),
    ("F21", f21),
    ("F22", f22),
    ("F23", f23),
    ("F24", f24),
    ("F25", f25),
    ("F26", f26),
    ("F27", f27),
    ("F28", f28),
    ("F29", f29),
    ("F30", f30),
    ("F31", f31),
    ("F32", f32),
    ("F33", f33),
    ("F34", f34),
    ("F35", f35),
    ("F36", f36),
    ("exact-quorum", exact_quorum_adversary),
    ("F38", f38),
    ("F39", f39),
];

fn pick<T: Copy>(seed: u64, options: &[T]) -> T {
    let index = usize::try_from(seed % u64::try_from(options.len()).unwrap_or(1)).unwrap_or(0);
    options[index]
}

/// Random choices of a scenario builder (independent of the world's stream).
fn side(name: &str, seed: u64) -> Rng {
    Rng::new(seed_of(name, seed) ^ 0x5bd1_e995_9e37_79b9)
}

/// `count` distinct machines of `0..n`.
fn distinct(rng: &mut Rng, n: usize, count: usize) -> Vec<usize> {
    let mut all: Vec<usize> = (0..n).collect();
    rng.shuffle(&mut all);
    all.truncate(count.min(n));
    all.sort_unstable();
    all
}

fn f_of(n: usize) -> usize {
    n.saturating_sub(1) / 3
}

/// A base scenario of size `n` with a duration that keeps large committees affordable.
fn sized(name: &str, seed: u64, n: usize) -> Scenario {
    let mut sc = Scenario::base(name, seed, n);
    sc.duration = if n >= 20 { 40_000 } else { 60_000 };
    sc
}

/// The machine holding the given role of `(height, view)` (static corruption with hindsight).
fn role(sc: &Scenario, height: u64, view: u64, proxy_tail: bool) -> usize {
    let (topo, machine_of) = preview(sc, height);
    let round = topo.round(view);
    let index = if proxy_tail {
        round.proxy_tail()
    } else {
        round.leader()
    };
    machine_of
        .get(usize::try_from(index).unwrap_or(0))
        .copied()
        .unwrap_or(0)
}

/// A lossless all-honest baseline.
pub fn smoke(seed: u64, n: usize) -> Scenario {
    Scenario::base("smoke", seed, n)
}

/// F1: crashed leaders (≤ f, permanent). Every fourth seed (n = 7) crashes a member and, once
/// it is demoted, makes the member after its permutation slot a silent leader: each height may
/// lose at most one view (a height anchored at the demoted slot must rotate to a third leader,
/// ML18).
pub fn f01(seed: u64) -> Scenario {
    if seed % 4 == 3 {
        return f01_demoted_slot(seed);
    }
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F1", seed, n);
    let mut rng = side("F1", seed);
    let f = f_of(n);
    let at_start = n == 4 && seed.is_multiple_of(2);
    let count = if at_start { 1 } else { 1 + rng.index(f) };
    let mut last = 0;
    for m in distinct(&mut rng, n, count) {
        let at = if at_start { 0 } else { rng.range(0, 15_000) };
        sc.script.push((at, Fault::Crash(m)));
        last = last.max(at);
    }
    sc.heal_at = last;
    sc.checks.perf = if at_start { Perf::P4 } else { Perf::None };
    sc.checks.progress = 8;
    sc
}

fn f01_demoted_slot(seed: u64) -> Scenario {
    let n = 7;
    let mut sc = sized("F1", seed, n);
    sc.duration = 120_000;
    let (topo, machine_of) = preview(&sc, 1);
    let perm = topo.permutation().to_vec();
    let slot = usize::try_from(seed / 4).unwrap_or(0) % n;
    let crashed = machine_of[usize::try_from(perm[slot]).unwrap_or(0)];
    let next = machine_of[usize::try_from(perm[(slot + 1) % n]).unwrap_or(0)];
    sc.script.push((0, Fault::Crash(crashed)));
    sc.byz = vec![(next, vec![Strategy::SilentLeader])];
    // Crashed at 0, its first leader turn is within n heights; demoted two heights later.
    sc.silent_leader_from = 25_000;
    sc.heal_at = 25_000;
    sc.checks.perf = Perf::OneViewFailure;
    sc.checks.progress = 8;
    sc
}

/// F2: silent proxy tail (forms certificates, delivers none).
pub fn f02(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 22, 5]);
    let mut sc = sized("F2", seed, n);
    let mut rng = side("F2", seed);
    let m = rng.index(n);
    sc.byz = vec![(m, vec![Strategy::WithholdQcs(Deliver::Nobody)])];
    sc.checks.perf = Perf::P3;
    sc.checks.progress = 10;
    sc
}

/// F3: withholding proxy tail (delivers to one node / a subset / nobody, or rewrites the
/// result of the certificates it forms).
pub fn f03(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F3", seed, n);
    let mut rng = side("F3", seed);
    let count = if seed.is_multiple_of(3) {
        f_of(n).max(1)
    } else {
        1
    };
    let strategy = match (seed / 3) % 5 {
        0 => Strategy::WithholdQcs(Deliver::One),
        1 => Strategy::WithholdQcs(Deliver::Half),
        2 => Strategy::WithholdQcs(Deliver::Nobody),
        3 => Strategy::RewriteResult,
        _ => Strategy::ShortQcs,
    };
    sc.byz = distinct(&mut rng, n, count)
        .into_iter()
        .map(|m| (m, vec![strategy]))
        .collect();
    sc.checks.perf = if count == 1 { Perf::P3 } else { Perf::None };
    sc.checks.progress = 8;
    sc
}

/// F4: silent or slow set-A members (CPU, executor or links).
pub fn f04(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F4", seed, n);
    let mut rng = side("F4", seed);
    let count = 1 + rng.index(f_of(n).max(1));
    for m in distinct(&mut rng, n, count) {
        match rng.below(4) {
            0 => sc.byz.push((m, vec![Strategy::Silent])),
            1 => sc.set_profile(
                m,
                Profile {
                    cpu_us_per_pairing: 4_000,
                    ..Profile::default()
                },
            ),
            // A slow executor, not a silent leader: execution takes 1.5 s whatever the payload
            // size and its builder does not price that slowness into payloads, as for F15's
            // and F34's slow executors. Priced at its own 1.5 s base cost, above `exec_budget`
            // (§9.1), it would never build work and would lead like a silent member
            // (Appendix E, E63).
            2 => sc.set_profile(
                m,
                Profile {
                    exec_base: 1_500,
                    exec_per_kib: 0,
                    ..Profile::default()
                },
            ),
            _ => sc.net.slow_links.push((m, 300)),
        }
    }
    sc.checks.progress = 8;
    // Eight heights are a progress obligation, not a 40/60 s performance bound. Keep that
    // minimum observation, then finish under the oracle's original per-commit deadlines.
    sc.checks.complete_progress = true;
    sc
}

/// F5: equivocating leader (twin blocks to two halves, then both to everyone); in some runs
/// the Byzantine leaders also build on stale parents or sign defective proposals.
pub fn f05(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F5", seed, n);
    let mut rng = side("F5", seed);
    let count = 1 + rng.index(f_of(n).max(1));
    let extra = match (seed / 4) % 3 {
        0 => None,
        1 => Some(Strategy::StaleParent),
        _ => Some(Strategy::InvalidProposals),
    };
    sc.byz = distinct(&mut rng, n, count)
        .into_iter()
        .map(|m| (m, [Strategy::Equivocate].into_iter().chain(extra).collect()))
        .collect();
    if (seed / 2) % 2 == 1 {
        // Twins across restarts: the durable Prepare must win (SR2, SR27).
        sc.churn = Some(Churn {
            from: 1_000,
            until: 40_000,
            ppm: 50_000,
            down_min: 50,
            down_max: 1_500,
            max_down: f_of(n).max(1),
            points: vec![CrashPoint::VoteRecord, CrashPoint::AfterDurable],
            targets: Vec::new(),
        });
        sc.heal_at = 43_000;
        sc.duration = 90_000;
    }
    sc.checks.progress = 6;
    sc
}

/// F6: `f` Byzantine members withholding their votes while leading correctly.
pub fn f06(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 22, 5]);
    let mut sc = sized("F6", seed, n);
    let mut rng = side("F6", seed);
    let count = if n == 22 && seed.is_multiple_of(2) {
        1
    } else {
        f_of(n).max(1)
    };
    sc.byz = distinct(&mut rng, n, count)
        .into_iter()
        .map(|m| (m, vec![Strategy::WithholdVotes]))
        .collect();
    sc.checks.perf = if count == 1 { Perf::P2 } else { Perf::None };
    if n <= 7 {
        sc.demotion_window = 16;
        sc.checks.cq = true;
        sc.duration = 90_000;
    }
    sc.checks.progress = 10;
    sc
}

/// F7: adversarial TC composition (lowest-`hq` TCs, lock holders' timeouts delayed) with
/// enough disruption (isolated honest members, loss, vote withholding) that views fail.
pub fn f07(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F7", seed, n);
    let mut rng = side("F7", seed);
    let f = f_of(n).max(1);
    let byz = distinct(&mut rng, n, f);
    sc.byz = byz
        .iter()
        .map(|m| {
            (
                *m,
                vec![
                    Strategy::TcMinHq,
                    Strategy::WithholdVotes,
                    Strategy::ReplayOldPqc,
                ],
            )
        })
        .collect();
    let honest: Vec<usize> = (0..n).filter(|m| !byz.contains(m)).collect();
    // A window in which Commit votes are lost: certified views fail one after another, so
    // honest locks differ in view and TCs carry different `hq`s.
    let drop_from = rng.range(3_000, 15_000);
    sc.net_rules = vec![
        NetRule::DelayLockedTimeouts(rng.range(300, 2_000)),
        NetRule::DropCommitVotes {
            from: drop_from,
            until: drop_from + rng.range(5_000, 12_000),
        },
    ];
    sc.net.loss_ppm = 50_000;
    let mut t = 2_000;
    for _ in 0..4 {
        let len = rng.range(3_000, 8_000);
        let victim = *rng.pick(&honest).unwrap_or(&0);
        sc.net
            .partitions
            .push(Partition::isolate(t, t + len, &[victim], n));
        t += len + rng.range(1_000, 4_000);
    }
    sc.heal_at = t;
    sc.duration = t + 50_000;
    sc.checks.progress = 5;
    sc
}

/// F8: split brain — selective `CommitQC` delivery plus isolation of the committer until the
/// others commit (the `MS10a` adversary); in odd seeds the other members also crash and restart
/// meanwhile (lock durability, MS25/MS30).
pub fn f08(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7]);
    let mut sc = sized("F8", seed, n);
    let target = 3 + seed % 5;
    let p = role(&sc, target, 0, true);
    sc.byz = vec![(p, vec![Strategy::SplitBrain, Strategy::ReplayOldPqc])];
    if n == 7 {
        let l = role(&sc, target, 1, false);
        if l != p {
            sc.byz
                .push((l, vec![Strategy::Equivocate, Strategy::TcMinHq]));
        }
    }
    sc.heal_at = 60_000;
    sc.duration = 110_000;
    if seed % 2 == 1 {
        sc.churn = Some(Churn {
            from: 2_000,
            until: 55_000,
            ppm: 40_000,
            down_min: 200,
            down_max: 2_000,
            max_down: 1,
            points: vec![CrashPoint::VoteRecord, CrashPoint::AfterDurable],
            targets: Vec::new(),
        });
    }
    sc.checks.progress = 5;
    sc
}

/// F9: loss 10/20/30 %, 5 % duplication, reordering; 1 % loss after heal.
pub fn f09(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F9", seed, n);
    if seed % 5 == 4 {
        // P1: all honest with 1 % loss throughout, long enough (≈ 350 heights) for a p99.
        sc.net.loss_ppm = 10_000;
        sc.net.post_heal_loss_ppm = 10_000;
        sc.duration = 360_000;
        sc.checks.perf = Perf::P1;
        sc.checks.progress = 40;
        return sc;
    }
    sc.net.loss_ppm = pick(seed / 4, &[100_000, 200_000, 300_000]);
    sc.net.post_heal_loss_ppm = 10_000;
    sc.net.dup_ppm = 50_000;
    sc.net.reorder_ppm = 200_000;
    sc.net.reorder_extra = 200;
    sc.heal_at = 40_000;
    sc.duration = 90_000;
    sc.checks.perf = Perf::P5;
    sc.checks.progress = 8;
    sc
}

/// F10: delay spikes (10× windows) and heavy tails.
pub fn f10(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F10", seed, n);
    let mut rng = side("F10", seed);
    for _ in 0..3 {
        let from = rng.range(3_000, 32_000);
        sc.net.spikes.push(Spike {
            from,
            until: from + rng.range(1_000, 5_000),
            factor: 10,
        });
    }
    sc.net.tail_ppm = 20_000;
    sc.net.tail_factor = 10;
    sc.heal_at = 40_000;
    sc.duration = 80_000;
    sc.checks.perf = Perf::P5;
    sc.checks.progress = 8;
    sc
}

/// F11: asymmetric and minority/majority partitions with heal.
pub fn f11(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F11", seed, n);
    let mut rng = side("F11", seed);
    let f = f_of(n).max(1);
    let mut t = 3_000;
    for _ in 0..3 {
        let len = rng.range(2_000, 10_000);
        let size = if rng.chance(500_000) { f } else { n / 2 };
        let group = distinct(&mut rng, n, size);
        let rest: Vec<usize> = (0..n).filter(|m| !group.contains(m)).collect();
        let part = match rng.below(3) {
            0 => Partition::isolate(t, t + len, &group, n),
            1 => Partition::one_way(t, t + len, &rest, &group),
            _ => Partition::one_way(t, t + len, &group, &rest),
        };
        sc.net.partitions.push(part);
        t += len + rng.range(500, 5_000);
    }
    if (seed / 4) % 2 == 1 {
        // One member is silent: the honest members are exactly the quorums they need, so
        // honest nodes left in different views by a partition can only meet by joining the
        // `f + 1` highest timeouts (ML8).
        let silent = rng.index(n);
        sc.byz = vec![(silent, vec![Strategy::Silent])];
        sc.checks.perf = Perf::None;
    }
    sc.heal_at = t;
    sc.duration = t + 50_000;
    if sc.byz.is_empty() {
        sc.checks.perf = Perf::P5;
    }
    sc.checks.progress = 8;
    sc
}

/// F12: clock skew ±10 s and drift ±1 %.
pub fn f12(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F12", seed, n);
    let mut rng = side("F12", seed);
    sc.clocks = (0..n)
        .map(|_| Clock {
            offset: i64::try_from(rng.range(0, 20_000)).unwrap_or(0) - 10_000,
            drift_ppm: i64::try_from(rng.range(0, 20_000)).unwrap_or(0) - 10_000,
        })
        .collect();
    sc.checks.perf = Perf::P1;
    sc.checks.progress = 30;
    sc
}

/// F13: crash-restart at every action boundary and write completion, random and targeted.
pub fn f13(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F13", seed, n);
    let mut rng = side("F13", seed);
    let points = match seed % 4 {
        0 => vec![CrashPoint::Random],
        1 => vec![
            CrashPoint::ProposalRecord,
            CrashPoint::VoteRecord,
            CrashPoint::TimeoutRecord,
        ],
        2 => vec![CrashPoint::AfterDurable, CrashPoint::InsideApply],
        _ => vec![
            CrashPoint::Random,
            CrashPoint::ProposalRecord,
            CrashPoint::VoteRecord,
            CrashPoint::TimeoutRecord,
            CrashPoint::AfterDurable,
            CrashPoint::InsideApply,
        ],
    };
    let random_only = points == [CrashPoint::Random];
    // Targeted at the leaders of early heights (hindsight) in half of the runs.
    let targets = if rng.chance(500_000) {
        (2..6).map(|h| role(&sc, h, 0, false)).collect()
    } else {
        Vec::new()
    };
    sc.churn = Some(Churn {
        from: 2_000,
        until: 40_000,
        ppm: if random_only { 2_000 } else { 60_000 },
        down_min: 100,
        down_max: 3_000,
        max_down: f_of(n).max(1),
        points,
        targets,
    });
    sc.heal_at = 44_000;
    sc.duration = 100_000;
    sc.checks.progress = 5;
    sc
}

/// F14: whole-cluster simultaneous crash and restart with lost non-durable writes.
pub fn f14(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F14", seed, n);
    let mut rng = side("F14", seed);
    for m in 0..n {
        sc.set_profile(
            m,
            Profile {
                write_min: 5,
                write_max: 40,
                ..Profile::default()
            },
        );
    }
    let mut t = rng.range(4_000, 12_000);
    for _ in 0..2 {
        sc.script.push((t, Fault::CrashAll));
        t += rng.range(300, 3_000);
        sc.script.push((t, Fault::RestartAll));
        t += rng.range(5_000, 15_000);
    }
    sc.heal_at = t;
    sc.duration = t + 50_000;
    sc.checks.progress = 5;
    sc
}

/// F15: slow executors (one node 10×, all nodes `E > T_base`, injected `Failed`, random
/// eviction of cached post-states, all nodes slow for non-empty blocks only).
pub fn f15(seed: u64) -> Scenario {
    let variant = seed % 6;
    // Variant 5 needs `T(1) ≤ E < e_max`, which exists only for `T_base = 2 s` (n < 10).
    let n = if variant == 5 {
        pick(seed / 6, &[4, 5, 7])
    } else {
        pick(seed / 6, &[4, 7, 5, 22])
    };
    let mut sc = sized("F15", seed, n);
    let mut rng = side("F15", seed);
    match variant {
        5 => f15_slow_payload(&mut sc, &mut rng),
        4 => {
            // Transient: all executors slow (the start level rises), then fast again (it must
            // decay), then a member crashes: its leader turn must cost `T(start = 0)` (ML6).
            // 2.6 s executions raise the start level to 3 (`T(2)/2 < 2.6 s < T(3)/2`).
            for m in 0..n {
                sc.set_profile(
                    m,
                    Profile {
                        exec_base: 2_600,
                        exec_per_kib: 0,
                        ..Profile::default()
                    },
                );
            }
            sc.script.push((
                20_000,
                Fault::Custom(Box::new(|w| {
                    for m in &mut w.machines {
                        m.profile.exec_base = 10;
                    }
                })),
            ));
            let victim = rng.index(n);
            sc.script.push((75_000, Fault::Crash(victim)));
            sc.heal_at = 75_000;
            sc.duration = 135_000;
            sc.checks.perf = Perf::P4;
            sc.checks.progress = 10;
        }
        0 => {
            let m = rng.index(n);
            sc.set_profile(
                m,
                Profile {
                    exec_base: 100,
                    exec_per_kib: 10,
                    ..Profile::default()
                },
            );
            sc.checks.progress = 10;
        }
        1 => {
            let slow = sc.local.t_base + 500;
            for m in 0..n {
                sc.set_profile(
                    m,
                    Profile {
                        exec_base: slow,
                        exec_per_kib: 0,
                        ..Profile::default()
                    },
                );
            }
            sc.duration = 120_000;
            sc.checks.progress = 3;
        }
        2 => {
            for m in 0..n {
                sc.set_profile(
                    m,
                    Profile {
                        exec_fail_ppm: 100_000,
                        ..Profile::default()
                    },
                );
            }
            sc.checks.may_fault = (0..n).collect();
            sc.checks.progress = 8;
        }
        _ => {
            for m in 0..n {
                sc.set_profile(
                    m,
                    Profile {
                        evict_ppm: 400_000,
                        exec_base: 30,
                        ..Profile::default()
                    },
                );
            }
            sc.checks.progress = 10;
        }
    }
    sc
}

/// F15 variant 5: every executor takes `E ∈ [T(1), e_max)` for a transaction block;
/// the builder does not foresee it (its budget is 500 ms), and the executor aborts discarded
/// work at once (O4). Early views time out executing, then retry real work. Discarded execution
/// durations remain lower bounds (§9.2, ML27, ML28), raising the level until work commits.
fn f15_slow_payload(sc: &mut Scenario, rng: &mut Rng) {
    let t1 = sc.local.t_base * 3 / 2;
    let e = rng.range(t1, sc.params.e_max - 100);
    for m in 0..sc.n {
        sc.set_profile(
            m,
            Profile {
                exec_nonempty: e,
                abort_discarded: true,
                ..Profile::default()
            },
        );
    }
    sc.duration = 120_000;
    sc.checks.progress = 5;
}

/// F16: validator-set change at an epoch boundary (add, remove, replace a majority) under
/// load and a crash, with joiners that fetch their parent's body; removed members collude.
pub fn f16(seed: u64) -> Scenario {
    let variant = seed % 3;
    let n = if variant == 1 { 5 } else { 4 };
    let mut sc = sized("F16", seed, n);
    let mut rng = side("F16", seed);
    let change = 12 + rng.range(0, 6);
    let genesis: Vec<(usize, usize)> = (0..n).map(|m| (m, 0)).collect();
    let next: Vec<(usize, usize)> = match variant {
        0 => {
            sc.extra = 1;
            (0..=n).map(|m| (m, 0)).collect()
        }
        1 => (0..n - 1).map(|m| (m, 0)).collect(),
        _ => {
            sc.extra = 3;
            let removed = [1, 2, 3];
            sc.byz = removed
                .iter()
                .map(|m| (*m, vec![Strategy::RemovedCollusion]))
                .collect();
            vec![(0, 0), (4, 0), (5, 0), (6, 0)]
        }
    };
    sc.committees = vec![(0, genesis), (change, next)];
    let victim = rng.index(n.min(if variant == 2 { 1 } else { n }));
    let at = rng.range(8_000, 20_000);
    sc.script.push((at, Fault::Crash(victim)));
    sc.script
        .push((at + rng.range(500, 3_000), Fault::Restart(victim)));
    sc.heal_at = at + 3_000;
    sc.duration = 90_000;
    sc.checks.progress = 5;
    sc
}

/// F17: a node joining far behind (10 000 heights in release sweeps); Byzantine sync and body
/// responders.
pub fn f17(seed: u64) -> Scenario {
    let n = 5;
    let mut sc = sized("F17", seed, n);
    let len: u64 = if cfg!(debug_assertions) {
        300
    } else if seed.is_multiple_of(30) {
        10_000
    } else {
        2_000
    };
    sc.prebuilt = len;
    sc.prebuilt_holders = vec![0, 1, 2, 3];
    sc.byz = vec![(3, vec![Strategy::ForgeSync, Strategy::ForgeBodies])];
    sc.demotion_window = 16;
    // Sync responses carry certified manifests; each body is then fetched as signed rows
    // before sequential application (§6.9). Budget a metadata round trip and a body round
    // trip per height, execution, body/block writes and application, plus a minute for
    // source rotation and live work. The old 12 ms/height budget omitted the body network
    // trip (up to 100 ms on the default links), so seed 0 ended at 2 919/10 000 heights.
    let profile = Profile::default();
    let replay_per_height =
        4 * sc.net.delay_max + profile.exec_base + 2 * profile.write_max + profile.apply_ms;
    sc.duration = len * replay_per_height + 60_000;
    sc.checks.progress = 3;
    sc
}

/// F18: floods of votes and timeouts for huge views and heights, far-future proposals and
/// `Status`, forged votes, racing non-leader proposals, oversize messages.
pub fn f18(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F18", seed, n);
    let mut rng = side("F18", seed);
    sc.params.max_block_bytes = 256 * 1024;
    // One mandatory canonical certificate-bearing frame must fit. Flood inputs
    // above this exact bound still exercise the same rejection and progress checks.
    sc.local.sync_max_bytes = sc.params.max_block_bytes + crate::pacemaker::FRAME_OVERHEAD;
    sc.net.frame_limit =
        u64::from(sc.params.max_block_bytes) + u64::from(crate::pacemaker::FRAME_OVERHEAD);
    let count = 1 + rng.index(f_of(n).max(1));
    sc.byz = distinct(&mut rng, n, count)
        .into_iter()
        .map(|m| {
            (
                m,
                vec![
                    Strategy::Flood,
                    Strategy::ForgeVotes,
                    Strategy::RaceProposals,
                    Strategy::ForgeCommitQc,
                    Strategy::ShortQcs,
                ],
            )
        })
        .collect();
    sc.checks.progress = 8;
    sc
}

/// F19: poison payloads cause early timeout and quarantine; real work resumes after repair.
pub fn f19(seed: u64) -> Scenario {
    let n = pick(seed / 2, &[4, 7, 5, 22]);
    let mut sc = sized("F19", seed, n);
    sc.workload = Some(Workload {
        poison_ppm: 50_000,
        ..Workload::default()
    });
    if seed % 2 == 1 {
        // A deterministic executor defect rejects all work for 30 s. Consensus must
        // stop committing, then recover once execution can validate transactions again.
        let stalled_height = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let capture_height = stalled_height.clone();
        sc.script.push((
            12_000,
            Fault::Custom(Box::new(move |w| {
                capture_height.set(w.oracle.refs[0].len());
            })),
        ));
        sc.script.push((
            10_000,
            Fault::Custom(Box::new(|w| {
                for m in &mut w.machines {
                    m.profile.reject_nonempty = true;
                }
            })),
        ));
        sc.script.push((
            40_000,
            Fault::Custom(Box::new(move |w| {
                if w.oracle.refs[0].len() != stalled_height.get() {
                    w.fail("executor outage committed a block without valid work".to_owned());
                }
                for m in &mut w.machines {
                    m.profile.reject_nonempty = false;
                }
            })),
        ));
        sc.checks.may_fault = (0..n).collect();
        sc.checks.windows = vec![(0, 40_000, 90_000, 3)];
    }
    sc.duration = 90_000;
    sc.checks.txp = true;
    sc.checks.progress = 5;
    sc
}

/// F20: cross-instance replay with shared keys (two instances).
pub fn f20(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5]);
    let mut sc = sized("F20", seed, n);
    let mut rng = side("F20", seed);
    sc.instances = 2;
    sc.shared_keys = true;
    sc.byz = vec![(rng.index(n), vec![Strategy::Replay])];
    sc.checks.progress = 10;
    sc
}

/// F21: a nondeterministic executor at one honest node (only it may halt).
pub fn f21(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F21", seed, n);
    let mut rng = side("F21", seed);
    let m = rng.index(n);
    sc.checks.may_halt = vec![m];
    sc.checks.may_fault = vec![m];
    // Certified views fail for a while, so certified blocks are re-proposed to the divergent
    // node (a local mismatch there must stay local, SR36); the executor diverges from the
    // start of that window (before, it would halt at its first apply).
    let from = rng.range(4_000, 12_000);
    sc.net_rules = vec![NetRule::DropCommitVotes {
        from,
        until: from + rng.range(3_000, 8_000),
    }];
    sc.script.push((
        from,
        Fault::Custom(Box::new(move |w| {
            if let Some(machine) = w.machines.get_mut(m) {
                machine.profile.divergent = true;
            }
        })),
    ));
    sc.heal_at = from + 8_000;
    sc.duration = 80_000;
    sc.checks.progress = 10;
    sc
}

/// F22: an idle chain remains at its tip for `intervals` payload retry intervals.
pub fn f22_intervals(seed: u64, intervals: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5]);
    let mut sc = Scenario::base("F22", seed, n);
    sc.workload = None;
    sc.duration = intervals * (sc.params.payload_retry_interval + 400);
    sc.checks.perf = Perf::None;
    sc.checks.progress = 0;
    sc
}

/// F22 with the default number of retry intervals (100 in debug, 1 000 in release).
pub fn f22(seed: u64) -> Scenario {
    f22_intervals(seed, if cfg!(debug_assertions) { 100 } else { 1_000 })
}

/// F23: `n ∉ {3f + 1}` (5, 6, 8) with `f` Byzantine members and partitions.
pub fn f23(seed: u64) -> Scenario {
    let n = pick(seed, &[5, 6, 8]);
    let mut sc = sized("F23", seed, n);
    let mut rng = side("F23", seed);
    let menu = [
        Strategy::Equivocate,
        Strategy::WithholdVotes,
        Strategy::TcMinHq,
        Strategy::WithholdQcs(Deliver::Half),
        Strategy::InvalidProposals,
        Strategy::StaleParent,
        Strategy::RewriteResult,
        Strategy::SplitBrain,
    ];
    sc.byz = distinct(&mut rng, n, f_of(n))
        .into_iter()
        .map(|m| {
            let a = *rng.pick(&menu).unwrap_or(&Strategy::Silent);
            let b = *rng.pick(&menu).unwrap_or(&Strategy::Silent);
            (m, vec![a, b])
        })
        .collect();
    for _ in 0..2 {
        let from = rng.range(3_000, 30_000);
        let group = distinct(&mut rng, n, n / 2);
        sc.net.partitions.push(Partition::isolate(
            from,
            from + rng.range(1_000, 6_000),
            &group,
            n,
        ));
    }
    sc.heal_at = 40_000;
    sc.duration = 90_000;
    sc.checks.progress = 5;
    sc
}

/// F24: record corruption (that node halts), record deletion (that key is unanchored until its
/// probe anchors it), a forged record parent (R5 halts), deletion together with a Kura tail loss
/// under the F8 adversary, key reinstallation (every instance `Absent`), a key store restored
/// from a backup older than a dataspace instance (with that instance's record deleted, or onto a
/// new, empty record store), and probe echoes forged, replayed and relayed by a Byzantine
/// member. A deleted record counts as one of the `f` faults until it anchors: no script pairs it
/// with `f` other members that ignore probes (the Byzantine members here answer them).
pub fn f24(seed: u64) -> Scenario {
    match seed % 7 {
        2 => f24_forged_parent(seed),
        3 => f24_record_and_kura_lost(seed),
        4 => f24_reinstall(seed),
        5 => f24_keystore_rollback(seed),
        6 => f24_echo_adversary(seed),
        _ => f24_corrupt_or_delete(seed),
    }
}

fn f24_corrupt_or_delete(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F24", seed, n);
    let mut rng = side("F24", seed);
    let both = f_of(n) >= 2;
    let victims = distinct(&mut rng, n, 2);
    let (a, b) = (victims[0], victims[1]);
    let t1 = rng.range(6_000, 15_000);
    let corrupt = both || seed.is_multiple_of(2);
    let delete = both || seed % 2 == 1;
    let mut last = if corrupt {
        sc.script.push((t1, Fault::Crash(a)));
        sc.script.push((t1 + 400, Fault::CorruptRecord(a, 0)));
        sc.script.push((t1 + 800, Fault::Restart(a)));
        sc.checks.may_halt = vec![a];
        t1 + 800
    } else {
        0
    };
    if delete {
        let t2 = rng.range(6_000, 15_000);
        sc.script.push((t2, Fault::Crash(b)));
        sc.script.push((t2 + 400, Fault::DeleteRecord(b, 0)));
        sc.script.push((t2 + 800, Fault::Restart(b)));
        last = last.max(t2 + 800);
    }
    sc.heal_at = last;
    sc.duration = last + 45_000;
    sc.checks.progress = 5;
    sc
}

/// A consistent but wrong record: the block store lost its last block and the record's parent
/// `CommitQC` is forged (valid checksum). R5 must refuse it (halt).
fn f24_forged_parent(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F24", seed, n);
    let mut rng = side("F24", seed);
    let a = rng.index(n);
    let t1 = rng.range(6_000, 15_000);
    sc.script.push((t1, Fault::Crash(a)));
    sc.script.push((t1 + 200, Fault::TruncateStore(a, 0, 1)));
    sc.script.push((t1 + 300, Fault::ForgeRecordParent(a, 0)));
    sc.script.push((t1 + 800, Fault::Restart(a)));
    sc.checks.may_halt = vec![a];
    sc.heal_at = t1 + 800;
    sc.duration = t1 + 45_000;
    sc.checks.progress = 5;
    sc
}

/// Record deletion together with a Kura tail loss of up to 40 heights (a whole-volume restore
/// that excludes the records) under the F8 / `MS10a` split-brain adversary (n = 7: the Byzantine
/// proxy tail and the unanchored node are the two faults).
fn f24_record_and_kura_lost(seed: u64) -> Scenario {
    let n = 7;
    let mut sc = sized("F24", seed, n);
    let mut rng = side("F24", seed);
    let target = 3 + seed % 5;
    let p = role(&sc, target, 0, true);
    sc.byz = vec![(p, vec![Strategy::SplitBrain, Strategy::ReplayOldPqc])];
    let honest: Vec<usize> = (0..n).filter(|m| *m != p).collect();
    let victim = *rng.pick(&honest).unwrap_or(&0);
    let t1 = rng.range(20_000, 40_000);
    let lost = 1 + rng.index(40);
    sc.script.push((t1, Fault::Crash(victim)));
    sc.script.push((t1 + 200, Fault::DeleteRecord(victim, 0)));
    sc.script
        .push((t1 + 300, Fault::TruncateStore(victim, 0, lost)));
    sc.script.push((t1 + 800, Fault::Restart(victim)));
    sc.heal_at = 60_000;
    sc.duration = 110_000;
    sc.checks.progress = 5;
    sc
}

/// Key reinstallation (a new disk, keys imported from a KMS): every instance is `Absent`.
fn f24_reinstall(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5]);
    let mut sc = sized("F24", seed, n);
    let mut rng = side("F24", seed);
    sc.instances = 2;
    let victim = rng.index(n);
    let t1 = rng.range(6_000, 15_000);
    sc.script.push((t1, Fault::Crash(victim)));
    sc.script.push((t1 + 300, Fault::ReinstallKey(victim)));
    sc.script.push((t1 + 800, Fault::Restart(victim)));
    sc.heal_at = t1 + 800;
    sc.duration = t1 + 45_000;
    sc.checks.progress = 5;
    sc
}

/// The key store (with its installation log) restored from a backup taken before the instances
/// started: once with the dataspace instance's record deleted, once onto a new, empty record
/// store. The driver marks every key imported; the missing records are `Absent`, never an
/// initial record, and the other existing records stay `Present`.
fn f24_keystore_rollback(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5]);
    let mut sc = sized("F24", seed, n);
    let mut rng = side("F24", seed);
    sc.instances = 2;
    sc.keystore_snapshot = true;
    let victim = rng.index(n);
    let t1 = rng.range(6_000, 15_000);
    sc.script.push((t1, Fault::Crash(victim)));
    sc.script.push((t1 + 200, Fault::RestoreKeyStore(victim)));
    if (seed / 7).is_multiple_of(2) {
        sc.script.push((t1 + 300, Fault::DeleteRecord(victim, 1)));
    } else {
        sc.script
            .push((t1 + 300, Fault::ReplaceRecordStore(victim)));
    }
    sc.script.push((t1 + 800, Fault::Restart(victim)));
    sc.heal_at = t1 + 800;
    sc.duration = t1 + 45_000;
    sc.checks.progress = 5;
    sc
}

/// A deleted record while a Byzantine member answers probes with forged, replayed and own
/// echoes, and relays every honest echo to the prober (the direct copies are lost).
fn f24_echo_adversary(seed: u64) -> Scenario {
    let n = 7;
    let mut sc = sized("F24", seed, n);
    let mut rng = side("F24", seed);
    let pair = distinct(&mut rng, n, 2);
    let (byz, victim) = (pair[0], pair[1]);
    sc.byz = vec![(byz, vec![Strategy::ForgeEchoes])];
    sc.net_rules = vec![NetRule::RelayEchoes(byz)];
    let t1 = rng.range(6_000, 15_000);
    sc.script.push((t1, Fault::Crash(victim)));
    sc.script.push((t1 + 400, Fault::DeleteRecord(victim, 0)));
    sc.script.push((t1 + 800, Fault::Restart(victim)));
    sc.heal_at = t1 + 800;
    sc.duration = t1 + 45_000;
    sc.checks.progress = 5;
    sc
}

/// F25: relay tampering — stripped and corrupted payloads, tampered relays before and after
/// the genuine proposal.
pub fn f25(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F25", seed, n);
    let mut rng = side("F25", seed);
    sc.net_rules = vec![NetRule::TamperPayloads {
        strip_ppm: 150_000,
        corrupt_ppm: 150_000,
    }];
    sc.byz = vec![(rng.index(n), vec![Strategy::TamperRelay])];
    sc.heal_at = 35_000;
    sc.duration = 70_000;
    sc.checks.progress = 8;
    sc
}

/// F26: Byzantine body and sync responders (forged payloads under genuine headers, solicited
/// and unsolicited) against nodes that must fetch every body, a Kura tail loss (R5 fetch).
pub fn f26(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F26", seed, n);
    let mut rng = side("F26", seed);
    let byz = distinct(&mut rng, n, f_of(n).max(1));
    sc.byz = byz
        .iter()
        .map(|m| (*m, vec![Strategy::ForgeBodies, Strategy::ForgeSync]))
        .collect();
    let honest: Vec<usize> = (0..n).filter(|m| !byz.contains(m)).collect();
    let starved = *rng.pick(&honest).unwrap_or(&0);
    sc.net_rules = vec![NetRule::DropRowsTo(starved)];
    let victim = *rng.pick(&honest).unwrap_or(&0);
    let at = rng.range(8_000, 20_000);
    sc.script.push((at, Fault::Crash(victim)));
    sc.script
        .push((at + 200, Fault::TruncateStore(victim, 0, 1)));
    sc.script.push((at + 700, Fault::Restart(victim)));
    sc.heal_at = 35_000;
    sc.duration = 75_000;
    sc.checks.progress = 8;
    sc
}

/// F27: benign storage faults (failed writes retried), Kura tail loss, restore from backup (the
/// records are never restored; in every third seed the key store comes back from the backup
/// too, which makes the driver mark its keys imported).
pub fn f27(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F27", seed, n);
    let mut rng = side("F27", seed);
    let keystore_backup = seed % 3 == 2;
    sc.keystore_snapshot = keystore_backup;
    for m in 0..n {
        sc.set_profile(
            m,
            Profile {
                write_fail_ppm: 150_000,
                write_retry: 50,
                ..Profile::default()
            },
        );
    }
    let victims = distinct(&mut rng, n, 2);
    let t1 = rng.range(8_000, 15_000);
    sc.script.push((t1, Fault::Crash(victims[0])));
    sc.script.push((
        t1 + 100,
        Fault::TruncateStore(victims[0], 0, 1 + rng.index(2)),
    ));
    sc.script.push((t1 + 600, Fault::Restart(victims[0])));
    let t2 = t1 + rng.range(5_000, 10_000);
    sc.script.push((t2, Fault::Crash(victims[1])));
    sc.script
        .push((t2 + 100, Fault::TruncateStore(victims[1], 0, 12)));
    if keystore_backup {
        sc.script
            .push((t2 + 200, Fault::RestoreKeyStore(victims[1])));
    }
    sc.script.push((t2 + 600, Fault::Restart(victims[1])));
    // The restored node cannot sync for a while: its timers run at heights where it must
    // abstain (R6).
    sc.net
        .partitions
        .push(Partition::isolate(t2 + 600, t2 + 12_000, &[victims[1]], n));
    sc.heal_at = t2 + 12_000;
    sc.duration = t2 + 70_000;
    sc.checks.progress = 5;
    sc
}

/// F28: key rotation across `h_new` with restarts on both sides of the change; in odd seeds
/// the rotating node crashes right after it signed at `h_new` and loses its last Kura block, so
/// the new key's record is R5 and the old key's is classified against the new tip (one key at
/// R4, the other at R5, composed into one round); in every third seed the old key is retired
/// before the last restart (restored, never signing).
pub fn f28(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5]);
    let mut sc = sized("F28", seed, n);
    let mut rng = side("F28", seed);
    let m = rng.index(n);
    let change = 10 + rng.range(0, 8);
    let genesis: Vec<(usize, usize)> = (0..n).map(|x| (x, 0)).collect();
    let next: Vec<(usize, usize)> = (0..n).map(|x| (x, usize::from(x == m))).collect();
    sc.committees = vec![(0, genesis), (change, next)];
    let retire = seed % 3 == 2;
    let mut t = rng.range(3_000, 8_000);
    for round in 0..3 {
        sc.script.push((t, Fault::Crash(m)));
        t += rng.range(300, 2_000);
        if retire && round == 2 {
            sc.script.push((t, Fault::RetireKey(m, 0)));
        }
        sc.script.push((t, Fault::Restart(m)));
        t += rng.range(4_000, 12_000);
    }
    if seed % 2 == 1 {
        // Poll until the node has a durable record of its new key at `h_new` and a block store
        // at `h_new − 1`; then crash it and drop that last block.
        let done = std::rc::Rc::new(std::cell::Cell::new(false));
        for k in 0..400u64 {
            let done = std::rc::Rc::clone(&done);
            sc.script.push((
                5_000 + k * 100,
                Fault::Custom(Box::new(move |w| {
                    if done.get() {
                        return;
                    }
                    let Some(r) = w.replica_of(m, 0) else {
                        return;
                    };
                    let new_key = w.machines[m].keys.get(1).cloned();
                    let at_change = new_key.is_some_and(|key| {
                        w.replicas[r]
                            .records
                            .get(&key)
                            .is_some_and(|d| d.record.height == change)
                    });
                    let stored = u64::try_from(w.replicas[r].store.len()).unwrap_or(0);
                    if w.machines[m].up && at_change && stored + 1 == change {
                        done.set(true);
                        w.crash(m);
                        let keep = w.replicas[r].store.len().saturating_sub(1);
                        w.replicas[r].store.truncate(keep);
                        w.restart(m);
                    }
                })),
            ));
        }
        t = t.max(45_000);
    }
    sc.heal_at = t;
    sc.duration = t + 40_000;
    sc.checks.progress = 5;
    sc
}

/// F29: CPU flood at the per-peer rate limit (maximal-group TCs in `Status`, forged timeouts,
/// huge views); ticks stay on time (P6).
pub fn f29(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 22, 5]);
    let mut sc = sized("F29", seed, n);
    let mut rng = side("F29", seed);
    sc.byz = distinct(&mut rng, n, f_of(n).max(1))
        .into_iter()
        .map(|m| (m, vec![Strategy::CpuFlood, Strategy::Flood]))
        .collect();
    sc.checks.perf = Perf::P6;
    sc.checks.progress = 8;
    sc
}

/// F30: maximum-size blocks with the transport frame limit and sync byte caps.
pub fn f30(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5]);
    let mut sc = sized("F30", seed, n);
    let mut rng = side("F30", seed);
    let max = if cfg!(debug_assertions) { 64 } else { 256 } * 1024;
    sc.params.max_block_bytes = max;
    sc.local.sync_max_bytes = max + crate::pacemaker::FRAME_OVERHEAD;
    sc.net.frame_limit = u64::from(max) + u64::from(crate::pacemaker::FRAME_OVERHEAD);
    sc.net.bandwidth = 20_000;
    sc.workload = Some(Workload {
        every_min: 10,
        every_max: 30,
        pad: u16::try_from(max / 32).unwrap_or(u16::MAX),
        ..Workload::default()
    });
    for m in 0..n {
        sc.set_profile(
            m,
            Profile {
                exec_per_kib: 0,
                ..Profile::default()
            },
        );
    }
    let victim = rng.index(n);
    let at = rng.range(5_000, 10_000);
    sc.script.push((at, Fault::Crash(victim)));
    sc.script.push((at + 15_000, Fault::Restart(victim)));
    sc.heal_at = at + 15_000;
    sc.duration = at + 60_000;
    sc.checks.progress = 5;
    sc
}

/// F31: independent finality and two-phase settlement over G and two or three dataspaces.
/// Stalled instances, delayed/forged relay proofs and relayer restart cannot break O-AMX.
pub fn f31(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5]);
    let mut sc = sized("F31", seed, n);
    sc.instances = if seed.is_multiple_of(2) { 3 } else { 4 };
    sc.amx = Some(super::amx::AmxConfig {
        forger: Some(n - 1),
        relayer_down: vec![(0, 20_000, 45_000), (1, 35_000, 55_000)],
        ..super::amx::AmxConfig::default()
    });
    let initial: Vec<_> = (0..n).map(|machine| (machine, 0)).collect();
    let next = if seed.is_multiple_of(2) {
        initial.clone()
    } else {
        sc.extra = 1;
        (0..n - 1)
            .chain(std::iter::once(n))
            .map(|machine| (machine, 0))
            .collect()
    };
    sc.committees = vec![(0, initial), (12, next.clone()), (32, next)];
    // The relayer loses volatile jobs with its machine and reconstructs them from
    // each instance's committed signed-availability history after restart.
    sc.script.push((65_000, Fault::Crash(0)));
    sc.script.push((68_000, Fault::Restart(0)));
    sc.net_rules = vec![
        NetRule::StallInstance {
            inst: 0,
            from: 10_000,
            until: 30_000,
        },
        NetRule::StallInstance {
            inst: 1,
            from: 40_000,
            until: 60_000,
        },
    ];
    sc.checks.stalled = vec![(0, 30_000), (1, 60_000)];
    sc.heal_at = 0;
    sc.duration = 100_000;
    sc.checks.progress = 5;
    sc
}

/// F32: whole-cluster restart (a) after a `PrepareQC` was locked everywhere but before any
/// `CommitQC` formed, (b) after a `CommitQC` formed but before any block store made it durable.
pub fn f32(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F32", seed, n);
    let mut rng = side("F32", seed);
    let t1 = rng.range(4_000, 10_000);
    if seed.is_multiple_of(2) {
        // Commit votes stay blocked well past the restart: the restarted nodes time out, and
        // their timeouts must carry the restored lock.
        sc.net_rules = vec![
            NetRule::DropCommitVotes {
                from: t1,
                until: t1 + 9_000,
            },
            NetRule::DropVotes {
                from: t1 + 2_000,
                until: t1 + 6_000,
            },
        ];
        sc.script.push((t1 + 2_000, Fault::CrashAll));
        sc.script.push((t1 + 2_500, Fault::RestartAll));
        sc.heal_at = t1 + 9_000;
    } else {
        let slow: Millis = 4_000;
        sc.script.push((
            t1,
            Fault::Custom(Box::new(move |w| {
                for m in &mut w.machines {
                    m.profile.block_write_extra = slow;
                }
            })),
        ));
        sc.script.push((t1 + 2_500, Fault::CrashAll));
        sc.script.push((
            t1 + 2_600,
            Fault::Custom(Box::new(|w| {
                for m in &mut w.machines {
                    m.profile.block_write_extra = 0;
                }
            })),
        ));
        sc.script.push((t1 + 3_000, Fault::RestartAll));
        sc.heal_at = t1 + 3_000;
    }
    sc.duration = sc.heal_at + 50_000;
    sc.checks.progress = 5;
    sc
}

/// F33: hidden `PrepareQC` — a Byzantine proxy tail delivers `PQC(B, v)` to one honest node
/// X only; the others time out without it (X's timeout is delayed), discard `B`'s execution on
/// entering `v + 1`, view `v + 1` fails (its proposal is delayed), and `TC(v + 1)` carries X's
/// lock, so `B` is re-proposed and must be executed again (ML17).
pub fn f33(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F33", seed, n);
    let target = 2 + seed % 4;
    let p = role(&sc, target, 0, true);
    sc.byz = vec![(p, vec![Strategy::HiddenPqc])];
    sc.heal_at = 45_000;
    sc.duration = 95_000;
    sc.checks.progress = 5;
    sc
}

/// F34: apply-bound late entrants (§8.2 L4, P1, P4; ML19, ML23): one member's `BlockApplied` is
/// delayed by up to `A_max` at every height with `f` members crashed; joiners and a long-crashed
/// node re-entering at the frontier after sync; a member whose executions are still pending at
/// commit.
pub fn f34(seed: u64) -> Scenario {
    let n = pick(seed / 3, &[4, 7, 5, 22]);
    let mut sc = sized("F34", seed, n);
    let mut rng = side("F34", seed);
    let f = f_of(n);
    let a_max = sc.params.a_max;
    match seed % 3 {
        0 => {
            let chosen = distinct(&mut rng, n, f + 1);
            let slow = chosen[0];
            sc.set_profile(
                slow,
                Profile {
                    apply_ms: a_max,
                    ..Profile::default()
                },
            );
            for &m in &chosen[1..] {
                sc.script.push((0, Fault::Crash(m)));
            }
            sc.checks.perf = if f == 1 { Perf::P4 } else { Perf::None };
            sc.duration = 90_000;
        }
        1 => {
            sc.extra = 1;
            let change = 12 + rng.range(0, 6);
            sc.committees = vec![
                (0, (0..n).map(|m| (m, 0)).collect()),
                (change, (0..=n).map(|m| (m, 0)).collect()),
            ];
            sc.set_profile(
                n,
                Profile {
                    apply_ms: a_max,
                    ..Profile::default()
                },
            );
            let victim = rng.index(n);
            sc.set_profile(
                victim,
                Profile {
                    apply_ms: a_max / 2,
                    ..Profile::default()
                },
            );
            sc.script.push((3_000, Fault::Crash(victim)));
            sc.script.push((25_000, Fault::Restart(victim)));
            sc.heal_at = 25_000;
            sc.duration = 80_000;
        }
        _ => {
            let m = rng.index(n);
            sc.set_profile(
                m,
                Profile {
                    exec_base: 900,
                    exec_per_kib: 0,
                    apply_ms: a_max,
                    ..Profile::default()
                },
            );
            // A slow executor delays only its Prepare (its Commit needs no execution), so no
            // P2 frequency bound applies (as for F4's slow members).
        }
    }
    sc.checks.progress = 8;
    sc
}

/// F35: local-queue asymmetry (§9.1; ML21): an idle chain whose transactions are submitted only
/// to `f + 1` random members (the holders), with and without one crashed non-holder. Queued
/// transactions commit without manufacturing idle blocks; leaders without local work time out,
/// so a height may take up to `2f` workless leader turns, each view's timer growing ×1.5 up to
/// `T_max` (§8.1, §9.1). Every height and transaction is held to the leader-turn bound
/// ([`Perf::LeaderTurns`], Appendix E, E62), and the run lasts until the first two heights are
/// due by it.
pub fn f35(seed: u64) -> Scenario {
    let n = pick(seed / 2, &[4, 7, 5, 22]);
    let mut sc = sized("F35", seed, n);
    let mut rng = side("F35", seed);
    let f = f_of(n);
    let chosen = distinct(&mut rng, n, f + 2);
    let mask = chosen[..=f].iter().fold(0u64, |acc, m| {
        acc | (1u64 << u32::try_from(*m).unwrap_or(0))
    });
    let workload = Workload {
        every_min: 3_000,
        every_max: 9_000,
        targets: mask,
        ..Workload::default()
    };
    sc.workload = Some(workload);
    if seed % 2 == 1 {
        sc.script.push((0, Fault::Crash(chosen[f + 1])));
    }
    sc.checks.perf = Perf::LeaderTurns(mask);
    sc.checks.txp = true;
    let t_max = sc.local.t_max.max(t_req_nominal(&sc.local, &sc.params, n));
    // The next transaction reaches every holder within `every_max` of the parent block's
    // build, before view 1 of the next height ends (with a second for the commit itself): a
    // holder leading any view `≥ 1` has work in time.
    assert!(
        workload.every_max + 1_000 <= leader_turns_bound(&sc.local, &sc.params, t_max, 0, 1, 0),
        "F35: the workload interval must fit before the end of view 1"
    );
    // Heights 1 and 2 have no demotions (§2.1), so their first holder turns are known from the
    // permutation; their start levels are 0 and at most 1 (§9.2). Two seconds per view cover
    // `σ + Δ` of the lossless default network at every committee size.
    let due: Millis = [(1, 0), (2, 1)]
        .into_iter()
        .map(|(height, start)| {
            let turns = first_holder_view(&sc, height, mask);
            leader_turns_bound(&sc.local, &sc.params, t_max, start, turns, 2_000)
        })
        .sum();
    sc.duration = due.saturating_add(20_000).max(120_000);
    sc.checks.progress = 2;
    sc
}

/// `v*(height)` without demotions: the first view `v ≥ 1` whose leader is in `holders`.
fn first_holder_view(sc: &Scenario, height: u64, holders: u64) -> u64 {
    let (topo, machine_of) = preview(sc, height);
    let rotation = u64::try_from(topo.n()).unwrap_or(u64::MAX);
    (1..=rotation)
        .find(|view| {
            let m = machine_of
                .get(usize::try_from(topo.leader(*view)).unwrap_or(usize::MAX))
                .copied()
                .unwrap_or(usize::MAX);
            u32::try_from(m)
                .ok()
                .and_then(|bit| 1u64.checked_shl(bit))
                .is_some_and(|bit| holders & bit != 0)
        })
        .unwrap_or(rotation)
}

/// F36: late leaders (§9.2; ML29, ML30): up to `f` members deliver their view-0 proposals as
/// late as the view still commits — the whole proposal `T(start)/2 + 100 ms` after the honest
/// anchor `t_enter + P(0)`, or the proposal at once without its payload and the body that much
/// later — never failing a view, so they are never demoted. They must not raise any honest
/// start level before one honest member crashes. The crash can extend certificate latency
/// beyond half a timeout and legitimately raise the level (§9.2), but every subsequent gap
/// must remain within the P4 leader-turn bound.
pub fn f36(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 5, 22]);
    let mut sc = sized("F36", seed, n);
    let mut rng = side("F36", seed);
    let late = if (seed / 4).is_multiple_of(2) {
        Late::Proposal
    } else {
        Late::Body
    };
    let byz = distinct(&mut rng, n, f_of(n).max(1));
    sc.byz = byz
        .iter()
        .map(|m| (*m, vec![Strategy::LateLeader(late)]))
        .collect();
    let honest: Vec<usize> = (0..n).filter(|m| !byz.contains(m)).collect();
    let victim = honest[rng.index(honest.len())];
    // Late enough for the start level to have reached `start_cap` if late leaders could raise
    // it (16 heights, a quarter to a third of them led late).
    let crash = if n >= 20 { 50_000 } else { 60_000 };
    sc.script.push((crash, Fault::Crash(victim)));
    sc.heal_at = crash;
    sc.duration = crash + 30_000;
    sc.checks.perf = Perf::OneViewFailure;
    sc.checks.progress = 3;
    sc
}

/// F38: a lane instance next to the global one (`specs/sumeragi_lanes.md` §4.1). The lane's
/// pinned committee is four of the global validators; every other machine follows the lane as an
/// observer. The lane stalls for a while and the global instance keeps finalizing; a lane
/// observer crashes and restarts. Every honest replica of both instances, observers included,
/// commits after the lane recovers.
pub fn f38(seed: u64) -> Scenario {
    let n = pick(seed, &[5, 7, 6]);
    let mut sc = sized("F38", seed, n);
    sc.instances = 2;
    sc.follow_all_instances = true;
    // The lane committee: the last four global validators (their lane keys are distinct from
    // their global keys: instances do not share keys here).
    sc.instance_committees = vec![(1, vec![(0, (n - 4..n).map(|m| (m, 0)).collect())])];
    sc.net_rules = vec![NetRule::StallInstance {
        inst: 1,
        from: 10_000,
        until: 25_000,
    }];
    // Machine 0 validates the global instance and only observes the lane.
    sc.script = vec![(15_000, Fault::Crash(0)), (20_000, Fault::Restart(0))];
    sc.checks.stalled = vec![(1, 25_000)];
    sc.checks.windows = vec![(0, 10_000, 25_000, 3)];
    sc.heal_at = 22_000;
    sc.duration = 60_000;
    sc.checks.progress = 5;
    sc
}

/// F39: the application clock guard (§4.5) under skewed honest wall clocks. Every honest wall
/// clock is within `[0, max_clock_drift_ms]` of real time (the liveness assumption
/// `2ε ≤ max_clock_drift_ms`), a third of the transactions apply due work (CT5), and `f`
/// Byzantine members run no guard and build blocks post-dated by up to `2·max_clock_drift_ms`,
/// far-future or back-dated past `due_work_max_lag_ms`, in turn. By variant (`seed % 3`): (0)
/// the Byzantine members vote or withhold every vote; (1) as (0), and one honest wall clock
/// jumps 30 s ahead (outside the assumption) for 15 s, then converges back; (2) a Byzantine
/// proxy tail hides `PrepareQC`s (F33) of blocks that all apply due work, so their
/// re-proposals are older than the lag and execute only as certified (§4.5 "Certified
/// re-proposals", MS51). Oracles: O-TIME, O-LIVE, O-AGR, O-FAULT (the guard's refusals are
/// local faults).
pub fn f39(seed: u64) -> Scenario {
    let n = pick(seed / 3, &[4, 7, 10]);
    let mut sc = sized("F39", seed, n);
    let mut rng = side("F39", seed);
    let f = f_of(n);
    let drift: Millis = 1_000;
    let lag = 2 * drift + 4 * sc.params.block_time;
    let drift_ms = i64::try_from(drift).unwrap_or(i64::MAX);
    let lag_ms = i64::try_from(lag).unwrap_or(i64::MAX);
    let variant = seed % 3;
    let byz = if variant == 2 {
        vec![role(&sc, 2 + seed % 4, 0, true)]
    } else {
        distinct(&mut rng, n, f)
    };
    sc.byz = byz
        .iter()
        .map(|m| {
            let strategies = match variant {
                2 => vec![Strategy::HiddenPqc],
                _ if rng.chance(500_000) => vec![Strategy::WithholdVotes],
                _ => Vec::new(),
            };
            (*m, strategies)
        })
        .collect();
    let wall_offsets: Vec<i64> = (0..n)
        .map(|_| i64::try_from(rng.range(0, drift)).unwrap_or(0))
        .collect();
    let leads = if variant == 2 {
        Vec::new()
    } else {
        byz.iter()
            .map(|m| {
                let lead = |rng: &mut Rng| i64::try_from(rng.range(0, drift)).unwrap_or(0);
                let leads = vec![
                    lead(&mut rng),
                    3_600_000,
                    -lag_ms - 2_000,
                    drift_ms + lead(&mut rng),
                ];
                (*m, leads)
            })
            .collect()
    };
    if variant == 1 {
        let honest: Vec<usize> = (0..n).filter(|m| !byz.contains(m)).collect();
        if let Some(&fast) = rng.pick(&honest) {
            let back = wall_offsets[fast];
            for (at, offset) in [(15_000, 30_000), (30_000, back)] {
                sc.script.push((
                    at,
                    Fault::Custom(Box::new(move |w| w.set_wall_offset(fast, offset))),
                ));
            }
        }
    }
    sc.workload = Some(Workload {
        due_every: if variant == 2 { 1 } else { 3 },
        ..Workload::default()
    });
    sc.clock_guard = Some(ClockGuard {
        max_clock_drift_ms: drift,
        due_work_max_lag_ms: lag,
        wall_offsets,
        leads,
    });
    sc.checks.may_fault = (0..n).collect();
    sc.demotion_window = 8;
    if variant == 2 {
        sc.heal_at = 45_000;
        sc.duration = 95_000;
    }
    sc.checks.progress = 5;
    sc
}

/// Genuine signer supersets remain invalid while an honest quorum makes progress.
pub fn exact_quorum_adversary(seed: u64) -> Scenario {
    let n = pick(seed, &[4, 7, 10]);
    let mut sc = sized("exact-quorum", seed, n);
    let mut rng = side("exact-quorum", seed);
    sc.byz = distinct(&mut rng, n, f_of(n))
        .into_iter()
        .map(|machine| (machine, vec![Strategy::OverAggregate]))
        .collect();
    sc.workload = Some(Workload::default());
    sc.checks.progress = 10;
    sc
}
