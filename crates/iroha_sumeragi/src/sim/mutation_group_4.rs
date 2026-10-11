//! Mutation group 4 (§13.4): the named deterministic test of MS24 on the simulator's fake
//! driver.
//!
//! MS24 weakens the fake driver's O2 barrier (§12.3) to hold only `Send`/`Broadcast`. The
//! state-machine test `det_s24_local_cqc_not_exposed_before_durable` checks the core's action
//! order on the test harness, whose writes are durable at once and which has no barrier, so it
//! cannot see a driver defect. The tests here run the barrier itself: [`Io`] directly, and the
//! §13.4 scenario of SR24 in a [`World`] whose proxy tail has a slow disk, so that it forms a
//! `CommitQC` containing its own undurable Commit.

use super::{
    crypto::parse_preimage,
    driver::{Barrier, Io, Write},
    oracle::covers,
    scenario::{Profile, Scenario},
    world::{World, preview},
};
use crate::{
    api::Action,
    availability::{AvailabilitySource, AvailableBody},
    message::{BlockHeader, Evidence, Qc, SyncRequest, Vote, VoteKind, WireMessage},
    safety::SafetyRecord,
    types::{
        AggregateSignature, Bitmap, Hash32, Millis, PublicKey, SIGNATURE_LEN, Signature,
        ValidatorIndex,
    },
};

/// Write latency of the proxy tail's disk: far above a network round trip (5–50 ms each way),
/// so the Commit votes of the others reach it while its own Commit record is still in flight.
const SLOW_WRITE: Millis = 400;

/// Heal time of the SR24 scenario: after X's crash and restart.
const HEAL_AT: Millis = 8_000;

/// Give-up time of the stepping loops (virtual ms).
const GIVE_UP: Millis = 20_000;

fn key(byte: u8) -> PublicKey {
    PublicKey::new(vec![byte; 32]).unwrap_or_else(|_| unreachable!("32-byte key"))
}

fn qc(kind: VoteKind, height: u64, block_hash: Hash32) -> Qc {
    Qc {
        epoch: crate::testing::TEST_EPOCH.id,
        kind,
        instance: Hash32::ZERO,
        height,
        view: 0,
        block_hash,
        result: Hash32([7; 32]),
        signers: Bitmap::from_indices(4, [0, 1, 2]).unwrap_or_else(|| Bitmap::new(4)),
        agg_sig: AggregateSignature([1; SIGNATURE_LEN]),
    }
}

fn vote(block_hash: Hash32) -> Vote {
    Vote {
        epoch: crate::testing::TEST_EPOCH.id,
        kind: VoteKind::Commit,
        instance: Hash32::ZERO,
        height: 1,
        view: 0,
        block_hash,
        result: Hash32([7; 32]),
        signer: 0,
        sig: Signature([2; SIGNATURE_LEN]),
    }
}

fn block() -> AvailableBody {
    super::driver::fixture_body(
        BlockHeader {
            control_witness: crate::types::ControlWitness::empty(),
            epoch: crate::testing::TEST_EPOCH.id,
            instance: Hash32::ZERO,
            height: 1,
            origin_view: 0,
            parent_hash: Hash32::ZERO,
            parent_result: Hash32::ZERO,
            payload_hash: Hash32::ZERO,
            availability_digest: crate::types::Hash32::ZERO,
            payload_len: 0,
            proposer: 0,
            skipped_leaders: Vec::new(),
        },
        &super::driver::encode_tx(1, false, 0),
    )
}

/// One action of every externally visible kind that O2 (§12.3) makes wait for durability.
fn every_effect() -> Vec<Action> {
    let (a, b) = (Hash32([3; 32]), Hash32([4; 32]));
    vec![
        Action::Send {
            to: key(1),
            msg: WireMessage::Vote(vote(a)),
        },
        Action::Broadcast {
            to: vec![key(1), key(2)],
            msg: WireMessage::Qc(qc(VoteKind::Commit, 1, a)),
        },
        Action::CommitBlock {
            block: block(),
            commit_qc: qc(VoteKind::Commit, 1, a),
        },
        Action::ServeBlocks {
            to: key(1),
            from_height: 1,
            max_count: 8,
            max_bytes: 1 << 20,
        },
        Action::ServePayload {
            to: key(2),
            height: 1,
            block_hash: a,
        },
        Action::FetchPayload {
            source: AvailabilitySource::new(Hash32::ZERO, 1, a, block().source().config().clone())
                .unwrap(),
            peers: vec![key(1)],
        },
        Action::ReportEvidence(Box::new(Evidence::ConflictingCertificates(
            qc(VoteKind::Commit, 1, a),
            qc(VoteKind::Commit, 1, b),
        ))),
        Action::ReportEvidence(Box::new(Evidence::VoteEquivocation(vote(a), vote(b)))),
    ]
}

/// SR24 at the driver: behind a pending `PersistSafety` the write device holds **every**
/// externally visible effect of §12.3 O2 — messages, `CommitBlock` (the block store is served),
/// `ServeBlocks`, `ServePayload`, `FetchPayload` and evidence — and releases them in order once the
/// record is durable; a crash before that loses them all.
#[test]
fn det_s24_o2_barrier_holds_every_effect() {
    let effects = every_effect();
    let record = SafetyRecord::fresh(Hash32::ZERO, crate::testing::TEST_EPOCH.id, key(9), 0, None);
    let mut io = Io::default();
    let mut barrier = Barrier::default();
    // No pending record: nothing waits.
    for effect in &effects {
        assert_eq!(barrier.hold(effect.clone()).as_ref(), Some(effect));
    }
    // A body write is no barrier by itself.
    let (body, _) = io.write(0, 5, Write::Body(Box::new(block())));
    for effect in &effects {
        assert!(barrier.hold(effect.clone()).is_some());
    }
    let (first, _) = io.write(1, 5, Write::Record(Box::new(record.clone()), Vec::new()));
    barrier.persisting(first);
    for effect in &effects {
        assert!(
            barrier.hold(effect.clone()).is_none(),
            "{effect:?} escaped the O2 barrier before the record was durable"
        );
    }
    // A later record moves the barrier: effects after it wait for it, not for the first one.
    let (second, _) = io.write(2, 5, Write::Record(Box::new(record), Vec::new()));
    barrier.persisting(second);
    for effect in &effects {
        assert!(barrier.hold(effect.clone()).is_none());
    }
    assert_eq!(
        (io.complete(body).len(), barrier.release(body).len()),
        (1, 0),
        "a body write releases nothing"
    );
    assert_eq!(io.complete(first).len(), 1);
    assert_eq!(
        barrier.release(first),
        effects,
        "released in order once the first record is durable"
    );
    assert!(
        effects.iter().all(|e| barrier.hold(e.clone()).is_none()),
        "the second record is still pending"
    );
    // Crash: every held effect is lost with the non-durable record.
    io.clear();
    barrier.clear();
    assert!(barrier.held.is_empty() && io.pending.is_empty());
    assert!(io.complete(second).is_empty() && barrier.release(second).is_empty());
    for effect in &effects {
        assert!(
            barrier.hold(effect.clone()).is_some(),
            "no barrier after a crash"
        );
    }
}

/// The §13.4 scenario of SR24 and its roles: `(scenario, X, W)` where X is the proxy tail of
/// `(1, 0)` with a slow disk and W a set-B member that sync-requests it.
fn s24_setup() -> (Scenario, usize, usize) {
    let mut sc = Scenario::base("det_s24", 24, 4);
    sc.duration = 30_000;
    // X crashes and restarts before `heal_at`, so the progress oracle judges it like every
    // other node (≥ `checks.progress` heights after heal).
    sc.heal_at = HEAL_AT;
    let (topo, machine_of) = preview(&sc, 1);
    let round = topo.round(0);
    let at = |i: ValidatorIndex| machine_of[usize::try_from(i).unwrap_or(0)];
    let x = at(round.proxy_tail());
    let w = at(round
        .set_b()
        .first()
        .copied()
        .unwrap_or_else(|| round.leader()));
    assert_ne!(x, w);
    sc.set_profile(
        x,
        Profile {
            write_min: SLOW_WRITE,
            write_max: SLOW_WRITE,
            ..Profile::default()
        },
    );
    (sc, x, w)
}

/// Panic with the failure report if an oracle fired.
fn assert_ok(world: &World) {
    if let Some(violation) = &world.failure {
        panic!("{}", world.report(violation));
    }
}

/// Advance one virtual millisecond at a time until `found` returns something.
fn step_until<T>(world: &mut World, what: &str, found: impl Fn(&World) -> Option<T>) -> T {
    loop {
        let t = world.now + 1;
        world.run_until(t);
        assert_ok(world);
        if let Some(value) = found(world) {
            return value;
        }
        assert!(t < GIVE_UP, "{what} never happened");
    }
}

/// X, the proxy tail of `(1, 0)` in the SR24 test.
struct Tail {
    /// Its machine.
    machine: usize,
    /// Its replica of instance 0.
    replica: usize,
    /// Its key.
    key: PublicKey,
    /// Its canonical index in `C_1`.
    index: ValidatorIndex,
}

impl Tail {
    /// Whether X's durable record covers the signature over `preimage` (O-PBS).
    fn durable(&self, world: &World, preimage: &[u8]) -> bool {
        let slot = parse_preimage(preimage).expect("a vote preimage");
        world.replicas[self.replica]
            .records
            .get(&self.key)
            .is_some_and(|d| covers(&d.record, &slot))
    }

    /// Step 1: run until X holds the `CommitBlock` of height 1 behind its barrier; check that
    /// its own Commit is in the certificate and not yet durable, that the certificate's
    /// broadcast waits too and that nothing is written to the block store.
    fn form_cqc_behind_barrier(&self, world: &mut World) -> (AvailableBody, Qc) {
        let xr = self.replica;
        let (block, cqc) = step_until(world, "a CommitBlock held behind X's barrier", |w| {
            w.replicas[xr]
                .host
                .held()
                .into_iter()
                .find_map(|action| match action {
                    Action::CommitBlock { block, commit_qc } => Some((block, commit_qc)),
                    _ => None,
                })
        });
        assert_eq!((cqc.kind, cqc.height), (VoteKind::Commit, 1));
        assert!(
            cqc.signers.get(self.index),
            "X's own Commit is part of the CommitQC it formed"
        );
        assert!(
            !self.durable(world, &cqc.preimage()),
            "premise: X's Commit is not yet durable"
        );
        let io = &world.replicas[xr].io;
        assert!(
            world.replicas[xr].host.held().iter().any(|a| matches!(
                a,
                Action::Broadcast { msg: WireMessage::Qc(q), .. } if *q == cqc
            )),
            "the CommitQC broadcast waits too"
        );
        assert!(
            !io.pending
                .iter()
                .any(|(_, _, w)| matches!(w, Write::Commit(_))),
            "nothing is written to the block store before the Commit record is durable"
        );
        assert!(world.replicas[xr].store.is_empty());
        (block, cqc)
    }

    /// Step 2: W sync-requests X; the `ServeBlocks` answer waits behind the barrier as well.
    fn serve_behind_barrier(&self, world: &mut World, w_key: &PublicKey, cqc: &Qc) {
        let request = WireMessage::SyncRequest(SyncRequest {
            instance: world.instances[0].id,
            from_height: 1,
            max_count: 8,
            max_bytes: 1 << 20,
        });
        world.inject(self.replica, w_key.clone(), request, 1);
        let xr = self.replica;
        step_until(world, "X's ServeBlocks for W", |w| {
            w.replicas[xr]
                .host
                .held()
                .iter()
                .any(|a| matches!(a, Action::ServeBlocks { to, from_height: 1, .. } if to == w_key))
                .then_some(())
        });
        assert!(
            !self.durable(world, &cqc.preimage()),
            "premise: X serves W before its Commit record is durable"
        );
    }

    /// Step 3: X crashes before durability; nothing carrying its Commit signature left it.
    fn crash_and_check(&self, world: &mut World, cqc: &Qc) {
        world.crash(self.machine);
        assert!(
            !world
                .log
                .lock()
                .expect("signing log")
                .was_signed(&self.key, &cqc.preimage()),
            "X's Commit signature left X before its record was durable"
        );
        let carried = |q: &Qc| q.height == 1 && q.signers.get(self.index);
        for (r, rep) in world.replicas.iter().enumerate() {
            if r == self.replica {
                continue;
            }
            assert!(
                !rep.store.iter().any(|(_, q)| carried(q)),
                "replica {r} stored a CommitQC carrying X's Commit"
            );
            assert!(
                !rep.io.pending.iter().any(|(_, _, write)| matches!(
                    write,
                    Write::Commit(entry) if carried(&entry.1)
                )),
                "replica {r} is storing a CommitQC carrying X's Commit"
            );
        }
    }
}

/// SR24 / MS24 (§13.4) on the simulator: X = P forms `CommitQC(B, 0)` including its own
/// undurable Commit, W sync-requests X, X crashes before the Commit record is durable → nothing
/// carrying X's signature left X: the `CommitBlock` (the block store is served, O3), the
/// `CommitQC` broadcast and the `ServeBlocks` answer all wait behind the O2 barrier (so the
/// O-PBS oracle never sees an uncovered exposure), the block store is untouched, and the
/// provenance log retracts the Commit signature at the crash. After X restarts every oracle
/// holds to the end of the run (O-AGR: the two-block commit of the revision-2 review scenario
/// is impossible).
#[test]
fn det_s24_local_cqc_not_exposed_before_durable_strong() {
    let (sc, x, w) = s24_setup();
    let mut world = World::new(sc);
    let xr = world.replica_of(x, 0).expect("X takes part in instance 0");
    let wr = world.replica_of(w, 0).expect("W takes part in instance 0");
    let key = world.replicas[xr].keys[0].clone();
    let index = world.instances[0]
        .committee(1)
        .index_of(&key)
        .expect("X is a member of C_1");
    let tail = Tail {
        machine: x,
        replica: xr,
        key,
        index,
    };
    let (block, cqc) = tail.form_cqc_behind_barrier(&mut world);
    let w_key = world.net_key(wr);
    tail.serve_behind_barrier(&mut world, &w_key, &cqc);
    tail.crash_and_check(&mut world, &cqc);

    // Step 4: X restarts on a healthy disk; every oracle holds to the end of the run.
    world.run_until(world.now + 500);
    assert_ok(&world);
    assert!(world.now < HEAL_AT, "X restarts before heal");
    world.machines[x].profile = Profile::default();
    world.restart(x);
    if let Err(report) = world.run() {
        panic!("{report}");
    }
    let h1: Vec<Hash32> = world
        .replicas
        .iter()
        .filter_map(|rep| rep.store.first().map(|(_, q)| q.block_hash))
        .collect();
    assert_eq!(
        h1.len(),
        world.replicas.len(),
        "every node committed height 1"
    );
    let bh = block.hash(&world.hasher);
    assert!(h1.iter().all(|h| *h == bh), "one block at height 1: {h1:?}");
}
