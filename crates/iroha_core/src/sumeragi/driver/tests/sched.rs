//! The execution scheduler with the fake executor, one operation at a time through the
//! executor thread's `run_exec` (§12.3 O3, O4).

use std::collections::BTreeMap;

use iroha_sumeragi::{
    api::{Event, ExecOutcome},
    availability::AvailableBody,
    message::Qc,
    sim::driver::{encode_tx, reference_exec},
    types::{ChainParams, Committee, Hash32, HeightConfig, Millis, PublicKey},
};

use super::{
    super::{
        exec::{ExecDone, ExecOp, ExecSched},
        persist::Backoff,
        run_exec,
        traits::{BlockStore, Executor, PublicationError},
    },
    block, commit_qc,
    fakes::{FakeBlocks, FakeExecutor},
    hash,
};

const G: Hash32 = Hash32([0xa0; 32]);
const RG: Hash32 = Hash32([0xa1; 32]);

fn config() -> HeightConfig {
    HeightConfig {
        epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
        committee: Committee::new(vec![PublicKey::new(vec![1; 32]).unwrap()]).unwrap(),
        params: ChainParams::default(),
    }
}

fn result_of(parent_result: &Hash32, block: &AvailableBody) -> Hash32 {
    match reference_exec(parent_result, &block.payload().as_slice()) {
        ExecOutcome::Valid(r) => r,
        other => panic!("{other:?}"),
    }
}

/// A block of `height` on `(parent, parent_result)` and its result.
fn child(height: u64, parent: (Hash32, Hash32), tag: u64) -> (AvailableBody, Hash32, Hash32) {
    let b = block(height, parent.0, parent.1, encode_tx(tag, false, 4));
    let r = result_of(&parent.1, &b);
    let bh = hash(&b);
    (b, bh, r)
}

struct Rig {
    sched: ExecSched,
    exec: FakeExecutor,
    blocks: FakeBlocks,
    events: Vec<Event>,
    now: Millis,
}

impl Rig {
    fn new() -> Self {
        Self {
            sched: ExecSched::new(0, Backoff::default(), super::test_registrations()),
            exec: FakeExecutor::new(G, RG, config()),
            blocks: FakeBlocks::default(),
            events: Vec::new(),
            now: 0,
        }
    }

    /// Start the next operation, if any.
    fn start(&mut self) -> Option<ExecOp> {
        self.sched.next(self.now)
    }

    /// Perform `op` on the fake executor and hand the answer back.
    fn finish(&mut self, op: ExecOp) -> Option<u64> {
        let done = run_exec(&mut self.exec, &self.blocks, op);
        let applied = self.sched.done(self.now, done);
        self.events.extend(self.sched.take_events());
        applied
    }

    /// Run operations until the scheduler is idle.
    fn drain(&mut self) {
        while let Some(op) = self.start() {
            self.finish(op);
        }
        self.events.extend(self.sched.take_events());
    }

    /// Answers per request so far.
    fn answers(&self) -> BTreeMap<u64, Vec<ExecOutcome>> {
        let mut out: BTreeMap<u64, Vec<ExecOutcome>> = BTreeMap::new();
        for event in &self.events {
            if let Event::Executed { req, outcome, .. } = event {
                out.entry(*req).or_default().push(outcome.clone());
            }
        }
        out
    }
}

/// O4: the most recent `Execute` runs first; one whose parent post-state is not held is parked
/// (never `Failed`) and runs once the parent executed.
#[test]
fn most_recent_first_and_parking() {
    let mut rig = Rig::new();
    let (b1, bh1, r1) = child(1, (G, RG), 1);
    let (b2, bh2, r2) = child(2, (bh1, r1), 2);
    rig.sched.execute(1, bh1, b1, false);
    rig.sched.execute(2, bh2, b2, false);
    let first = rig.start().unwrap();
    assert!(matches!(&first, ExecOp::Execute { block_hash, .. } if *block_hash == bh2));
    rig.finish(first);
    assert!(rig.events.is_empty(), "parked, not answered");
    assert_eq!(rig.sched.outstanding(), 2);
    rig.drain();
    let answers = rig.answers();
    assert_eq!(answers[&1], vec![ExecOutcome::Valid(r1)]);
    assert_eq!(answers[&2], vec![ExecOutcome::Valid(r2)]);
    assert_eq!(rig.sched.outstanding(), 0);
}

/// Parking for a missing parent preserves the exact certified status supplied by the core.
#[test]
fn execution_certification_survives_parking() {
    for certified in [false, true] {
        let mut rig = Rig::new();
        let (parent, parent_hash, parent_result) = child(1, (G, RG), 1);
        let (block, block_hash, result) = child(2, (parent_hash, parent_result), 2);
        rig.sched.execute(1, parent_hash, parent, false);
        rig.sched.execute(2, block_hash, block, certified);
        let first = rig.start().unwrap();
        assert!(
            matches!(&first, ExecOp::Execute { certified: actual, block_hash: actual_hash, .. }
            if *actual == certified && *actual_hash == block_hash)
        );
        rig.finish(first);
        assert!(
            rig.events.is_empty(),
            "missing parent parks the original request"
        );
        let parent_op = rig.start().unwrap();
        assert!(matches!(
            &parent_op,
            ExecOp::Execute {
                certified: false,
                ..
            }
        ));
        rig.finish(parent_op);
        let resumed = rig.start().unwrap();
        assert!(
            matches!(&resumed, ExecOp::Execute { certified: actual, block_hash: actual_hash, .. }
            if *actual == certified && *actual_hash == block_hash)
        );
        rig.finish(resumed);
        assert_eq!(rig.answers()[&2], vec![ExecOutcome::Valid(result)]);
        assert_eq!(rig.sched.outstanding(), 0);
    }
}

/// O4: a discard answers waiting jobs left out `Cancelled` at once and a running one when it
/// finishes; the kept job still runs; the executor drops the post-states.
#[test]
fn discard_cancels_waiting_and_running() {
    let mut rig = Rig::new();
    let (a, bha, ra) = child(1, (G, RG), 1);
    let (b, bhb, _) = child(1, (G, RG), 2);
    let (c, bhc, _) = child(1, (G, RG), 3);
    rig.sched.execute(1, bha, a, false);
    rig.sched.execute(2, bhb, b, false);
    let running = rig.start().unwrap();
    rig.sched.execute(3, bhc, c, false);
    rig.sched.discard(1, vec![bha]);
    rig.events.extend(rig.sched.take_events());
    assert_eq!(
        rig.answers()[&3],
        vec![ExecOutcome::Cancelled],
        "queued job"
    );
    rig.finish(running);
    assert_eq!(
        rig.answers()[&2],
        vec![ExecOutcome::Cancelled],
        "running job"
    );
    let next = rig.start().unwrap();
    assert!(
        matches!(next, ExecOp::Discard { height: 1, .. }),
        "{next:?}"
    );
    rig.finish(next);
    assert!(!rig.exec.state.lock().cache.contains_key(&bhb));
    rig.drain();
    assert_eq!(rig.answers()[&1], vec![ExecOutcome::Valid(ra)]);
    assert!(rig.answers().values().all(|a| a.len() == 1));
}

/// O3: `CommitBlock` arrives while that block executes: the execution finishes, its post-state
/// is reused — one execution, not two — and `BlockApplied` carries the header.
#[test]
fn commit_during_execution_executes_once() {
    let mut rig = Rig::new();
    let (b1, bh1, r1) = child(1, (G, RG), 1);
    rig.sched.execute(1, bh1, b1.clone(), false);
    let running = rig.start().unwrap();
    rig.sched.commit(b1.clone(), commit_qc(&b1, r1));
    assert!(rig.start().is_none(), "one operation at a time");
    assert_eq!(rig.finish(running), None);
    rig.drain();
    assert_eq!(rig.exec.executions(&bh1), 1);
    assert_eq!(rig.answers()[&1], vec![ExecOutcome::Valid(r1)]);
    assert!(rig.events.iter().any(|e| matches!(
        e,
        Event::BlockApplied { height: 1, block_hash, header, .. }
            if *block_hash == bh1 && **header == *b1.header()
    )));
    assert_eq!(rig.blocks.height(), 1, "durable in the block store first");
    assert_eq!(rig.sched.applied(), 1);
}

/// O3: an `Execute` of the committed block still queued is not started again: the apply
/// executes the block once and answers it.
#[test]
fn commit_answers_a_queued_execution() {
    let mut rig = Rig::new();
    let (b1, bh1, r1) = child(1, (G, RG), 1);
    rig.sched.execute(1, bh1, b1.clone(), false);
    rig.sched.commit(b1.clone(), commit_qc(&b1, r1));
    let first = rig.start().unwrap();
    assert!(matches!(first, ExecOp::Prepare(_)), "{first:?}");
    rig.finish(first);
    rig.drain();
    assert_eq!(rig.exec.executions(&bh1), 1);
    assert_eq!(rig.answers()[&1], vec![ExecOutcome::Valid(r1)]);
}

/// O3: a missing post-state is recomputed (no divergence); a local commitment other than the
/// certified one is `ApplyDiverged` and apply stops.
#[test]
fn missing_cache_recomputes_and_mismatch_diverges() {
    let mut rig = Rig::new();
    let (b1, bh1, r1) = child(1, (G, RG), 1);
    rig.sched.commit(b1.clone(), commit_qc(&b1, r1));
    rig.drain();
    assert_eq!(rig.sched.applied(), 1, "re-executed, not diverged");
    let (b2, bh2, r2) = child(2, (bh1, r1), 2);
    rig.sched
        .commit(b2.clone(), commit_qc(&b2, Hash32([7; 32])));
    rig.drain();
    assert!(rig.events.iter().any(|e| matches!(
        e,
        Event::ApplyDiverged { height: 2, block_hash, local_result }
            if *block_hash == bh2 && *local_result == r2
    )));
    let (b3, _, _) = child(3, (bh2, r2), 3);
    rig.sched
        .commit(b3.clone(), commit_qc(&b3, Hash32([8; 32])));
    rig.drain();
    assert_eq!(rig.sched.applied(), 1);
    assert_eq!(
        rig.blocks.height(),
        1,
        "nothing appended after a divergence"
    );
}

/// Local apply failures (executor and block store) are retried with backoff and never
/// skipped.
#[test]
fn apply_failures_are_retried() {
    let mut rig = Rig::new();
    let (b1, _, r1) = child(1, (G, RG), 1);
    rig.exec.state.lock().fail_apply = 1;
    rig.blocks.fail_next(1);
    rig.sched.commit(b1.clone(), commit_qc(&b1, r1));
    rig.drain();
    assert_eq!(rig.sched.applied(), 0);
    assert_eq!(rig.sched.wakeup(), 10);
    rig.now = 10;
    rig.drain();
    assert_eq!(rig.sched.applied(), 0, "the append failed next");
    assert_eq!(
        rig.sched.wakeup(),
        20,
        "the backoff restarts after a success"
    );
    rig.now = 20;
    rig.drain();
    assert_eq!(rig.sched.applied(), 1);
    assert_eq!(rig.sched.wakeup(), Millis::MAX);
}

/// Building waits for the parent's apply; `PayloadReady` follows an `EMPTY` build at most
/// once, and a newer request supersedes an older one.
#[test]
fn build_after_parent_apply_and_payload_ready() {
    let mut rig = Rig::new();
    let (b1, _, r1) = child(1, (G, RG), 1);
    rig.sched.build(4, 2, 0, 1024, 100);
    rig.sched.build(5, 2, 1, 1024, 100);
    assert!(rig.start().is_none(), "height 1 is not applied yet");
    rig.sched.commit(b1.clone(), commit_qc(&b1, r1));
    rig.drain();
    rig.sched
        .retain_control_context(Some((applied_parent_context(&b1, r1), 1)));
    rig.drain();
    let built: Vec<u64> = rig
        .events
        .iter()
        .filter_map(|e| match e {
            Event::PayloadBuilt { req, payload, .. } if payload.is_none() => Some(*req),
            _ => None,
        })
        .collect();
    assert_eq!(built, vec![5]);
    rig.sched.transactions_available();
    rig.sched.transactions_available();
    let ready = rig.sched.take_events();
    assert_eq!(ready, vec![Event::PayloadReady { req: 5 }]);
    rig.exec.add_tx(9);
    rig.sched
        .retain_control_context(Some((applied_parent_context(&b1, r1), 2)));
    rig.sched.build(6, 2, 2, 1024, 100);
    rig.drain();
    assert!(
        rig.events
            .iter()
            .any(|e| matches!(e, Event::PayloadBuilt { req: 6, payload, .. } if payload.is_some()))
    );
    rig.sched.transactions_available();
    assert!(rig.sched.take_events().is_empty(), "no EMPTY build pending");
}

/// A transaction arriving while a build runs (its queue read may predate it) is not lost: an
/// `EMPTY` answer is followed by `PayloadReady` at once (E4).
#[test]
fn arrival_during_a_build_follows_an_empty_answer() {
    let mut rig = Rig::new();
    let (b1, _, r1) = child(1, (G, RG), 1);
    rig.sched.commit(b1.clone(), commit_qc(&b1, r1));
    rig.drain();
    rig.events.clear();
    rig.sched
        .retain_control_context(Some((applied_parent_context(&b1, r1), 0)));
    rig.sched.build(7, 2, 0, 1024, 100);
    let op = rig.start().expect("the build starts");
    rig.sched.transactions_available();
    assert!(rig.sched.take_events().is_empty(), "nothing is pending yet");
    rig.finish(op);
    assert_eq!(
        rig.events
            .iter()
            .filter(|e| matches!(e, Event::PayloadBuilt { .. } | Event::PayloadReady { .. }))
            .cloned()
            .collect::<Vec<_>>(),
        vec![
            Event::PayloadBuilt {
                req: 7,
                payload: None,
            },
            Event::PayloadReady { req: 7 },
        ]
    );
    rig.sched.transactions_available();
    assert!(
        rig.sched.take_events().is_empty(),
        "at most once per request"
    );
    // Without an arrival the answer waits for one, as before.
    rig.events.clear();
    rig.sched
        .retain_control_context(Some((applied_parent_context(&b1, r1), 1)));
    rig.sched.build(8, 2, 1, 1024, 100);
    rig.drain();
    assert!(
        !rig.events
            .iter()
            .any(|e| matches!(e, Event::PayloadReady { .. }))
    );
    rig.sched.transactions_available();
    assert_eq!(
        rig.sched.take_events(),
        vec![Event::PayloadReady { req: 8 }]
    );
}

/// Requests of heights applied meanwhile are answered on the apply (never left waiting), and
/// new ones at once.
#[test]
fn applied_heights_answer_waiting_requests() {
    let mut rig = Rig::new();
    let (b1, bh1, r1) = child(1, (G, RG), 1);
    let (x1, bhx, _) = child(1, (G, RG), 99);
    rig.sched.execute(7, bhx, x1.clone(), false);
    rig.sched.commit(b1.clone(), commit_qc(&b1, r1));
    rig.sched.reject(1, 0, bhx);
    rig.drain();
    let answers = rig.answers();
    assert_eq!(answers[&7], vec![ExecOutcome::Cancelled]);
    rig.sched.execute(8, bh1, b1, false);
    rig.events.extend(rig.sched.take_events());
    assert_eq!(rig.answers()[&8], vec![ExecOutcome::Cancelled]);
    assert_eq!(rig.exec.state.lock().rejected, vec![bhx]);
    assert_eq!(rig.sched.outstanding(), 0);
}

/// O4 under random interleavings: every `Execute` is answered exactly once, whatever the
/// discards, commits and the order of operations.
#[test]
fn every_execute_is_answered_exactly_once() {
    for seed in 0..200u64 {
        let mut rng = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut next = |bound: u64| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % bound
        };
        let mut rig = Rig::new();
        // The canonical chain c1..c4 and a fork block per height.
        let mut chain = vec![(G, RG)];
        let mut blocks: Vec<(AvailableBody, Hash32, Hash32)> = Vec::new();
        let mut forks: Vec<(AvailableBody, Hash32)> = Vec::new();
        for h in 1..=4u64 {
            let parent = chain[usize::try_from(h - 1).unwrap()];
            let (b, bh, r) = child(h, parent, h);
            let (x, bhx, _) = child(h, parent, 100 + h);
            chain.push((bh, r));
            blocks.push((b, bh, r));
            forks.push((x, bhx));
        }
        let mut requests = 0u64;
        let mut committed = 0usize;
        let mut running: Option<ExecOp> = None;
        for _ in 0..60 {
            match next(6) {
                0 | 1 => {
                    let i = usize::try_from(next(4)).unwrap();
                    requests += 1;
                    let (b, bh) = if next(2) == 0 {
                        (blocks[i].0.clone(), blocks[i].1)
                    } else {
                        (forks[i].0.clone(), forks[i].1)
                    };
                    rig.sched.execute(requests, bh, b, false);
                }
                2 => {
                    let h = next(4) + 1;
                    let i = usize::try_from(h - 1).unwrap();
                    let keep = if next(2) == 0 {
                        vec![blocks[i].1]
                    } else {
                        Vec::new()
                    };
                    rig.sched.discard(h, keep);
                }
                3 if committed < 4 => {
                    let (b, _, r) = &blocks[committed];
                    rig.sched.commit(b.clone(), commit_qc(b, *r));
                    committed += 1;
                }
                _ => {
                    if let Some(op) = running.take() {
                        rig.finish(op);
                    } else {
                        running = rig.start();
                    }
                }
            }
            rig.events.extend(rig.sched.take_events());
        }
        if let Some(op) = running.take() {
            rig.finish(op);
        }
        for (b, _, r) in &blocks[committed..] {
            rig.sched.commit(b.clone(), commit_qc(b, *r));
        }
        rig.drain();
        let answers = rig.answers();
        assert_eq!(rig.sched.outstanding(), 0, "seed {seed}");
        for req in 1..=requests {
            let got = answers.get(&req).map_or(0, Vec::len);
            assert_eq!(got, 1, "seed {seed}: request {req} answered {got} times");
        }
        assert!(
            answers
                .values()
                .flatten()
                .all(|o| !matches!(o, ExecOutcome::Failed(_) | ExecOutcome::Invalid)),
            "seed {seed}: a missing post-state is never Failed or Invalid"
        );
    }
}

/// An executor that panics.
struct Panicking;

impl Executor for Panicking {
    fn build_control_witness(
        &mut self,
        _: &iroha_sumeragi::api::ControlWitnessContext,
    ) -> Result<iroha_sumeragi::types::ControlWitness, PublicationError> {
        panic!("boom")
    }
    fn drive_control(
        &mut self,
        _: &iroha_sumeragi::api::ApplicationControlContext,
    ) -> Result<Option<iroha_sumeragi::message::ApplicationControl>, PublicationError> {
        panic!("boom")
    }
    fn receive_application_control(
        &mut self,
        _: &iroha_sumeragi::types::PublicKey,
        _: &iroha_sumeragi::message::ApplicationControl,
    ) -> Result<(), PublicationError> {
        panic!("boom")
    }

    fn execute(&mut self, _: &AvailableBody, _: &Hash32) -> Option<ExecOutcome> {
        panic!("boom")
    }
    fn discard(&mut self, _: u64, _: &[Hash32]) {}
    fn prepare(&mut self, _: &AvailableBody, _: &Qc) -> Result<Option<Hash32>, PublicationError> {
        panic!("boom")
    }
    fn commit(
        &mut self,
        _: &AvailableBody,
        _: &Qc,
    ) -> Result<iroha_sumeragi::types::AppliedConfig, PublicationError> {
        panic!("boom")
    }
    fn build(
        &mut self,
        _: u64,
        _: u64,
        _: u32,
        _: u32,
    ) -> Result<Option<iroha_sumeragi::availability::PayloadBytes>, PublicationError> {
        panic!("boom")
    }
    fn reject(&mut self, _: u64, _: u64, _: &Hash32) {}
}

/// Executor panics are local failures (`Failed`, recovery-required publication, `EMPTY` build), never
/// invalidity, and never kill the executor thread.
#[test]
fn executor_panics_become_local_failures() {
    let blocks = FakeBlocks::default();
    let (b1, bh1, r1) = child(1, (G, RG), 1);
    let mut exec = Panicking;
    let done = run_exec(
        &mut exec,
        &blocks,
        ExecOp::Execute {
            block: std::sync::Arc::new(b1.clone()),
            block_hash: bh1,
            certified: false,
        },
    );
    assert!(matches!(
        done,
        ExecDone::Executed(Some(ExecOutcome::Failed(_)))
    ));
    let commit = std::sync::Arc::new(super::super::exec::Commit {
        qc: commit_qc(&b1, r1),
        block: b1,
    });
    assert!(matches!(
        run_exec(&mut exec, &blocks, ExecOp::Prepare(commit.clone())),
        ExecDone::Prepared(Err(PublicationError::RecoveryRequired(_)))
    ));
    assert!(matches!(
        run_exec(&mut exec, &blocks, ExecOp::Commit(commit)),
        ExecDone::Committed(Err(PublicationError::RecoveryRequired(_)))
    ));
    let built = run_exec(
        &mut exec,
        &blocks,
        ExecOp::Build {
            req: 1,
            height: 1,
            view: 0,
            max_bytes: 10,
            exec_budget_ms: 10,
        },
    );
    assert!(
        matches!(
            built,
            ExecDone::Built(Err(PublicationError::RecoveryRequired(_)))
        ),
        "a panicked builder must not fabricate an empty proposal"
    );
}

/// An executor with a single live overlay (the shape of the node's State executor): any call
/// other than `commit` after a `prepare` drops the prepared post-state, and `commit` fails
/// without it; `fail_commits` commits fail after consuming it.
struct Overlay {
    inner: FakeExecutor,
    prepared: Option<Hash32>,
    fail_commits: u32,
    calls: Vec<&'static str>,
}

impl Overlay {
    fn new() -> Self {
        Self {
            inner: FakeExecutor::new(G, RG, config()),
            prepared: None,
            fail_commits: 0,
            calls: Vec::new(),
        }
    }

    fn other(&mut self, call: &'static str) {
        self.prepared = None;
        self.calls.push(call);
    }
}

impl Executor for Overlay {
    fn build_control_witness(
        &mut self,
        _: &iroha_sumeragi::api::ControlWitnessContext,
    ) -> Result<iroha_sumeragi::types::ControlWitness, PublicationError> {
        Ok(iroha_sumeragi::types::ControlWitness::empty())
    }
    fn drive_control(
        &mut self,
        _: &iroha_sumeragi::api::ApplicationControlContext,
    ) -> Result<Option<iroha_sumeragi::message::ApplicationControl>, PublicationError> {
        Ok(None)
    }
    fn receive_application_control(
        &mut self,
        _: &iroha_sumeragi::types::PublicKey,
        _: &iroha_sumeragi::message::ApplicationControl,
    ) -> Result<(), PublicationError> {
        Ok(())
    }

    fn execute(&mut self, block: &AvailableBody, block_hash: &Hash32) -> Option<ExecOutcome> {
        self.other("execute");
        self.inner.execute(block, block_hash)
    }
    fn discard(&mut self, height: u64, keep: &[Hash32]) {
        self.other("discard");
        self.inner.discard(height, keep);
    }
    fn prepare(
        &mut self,
        block: &AvailableBody,
        commit_qc: &Qc,
    ) -> Result<Option<Hash32>, PublicationError> {
        self.calls.push("prepare");
        let result = self.inner.prepare(block, commit_qc);
        self.prepared = matches!(result, Ok(Some(_))).then_some(commit_qc.block_hash);
        result
    }
    fn commit(
        &mut self,
        block: &AvailableBody,
        commit_qc: &Qc,
    ) -> Result<iroha_sumeragi::types::AppliedConfig, PublicationError> {
        self.calls.push("commit");
        if self.prepared.take() != Some(commit_qc.block_hash) {
            return Err(PublicationError::Retryable(
                "no prepared overlay".to_owned(),
            ));
        }
        if self.fail_commits > 0 {
            self.fail_commits -= 1;
            return Err(PublicationError::Retryable("injected".to_owned()));
        }
        self.inner.commit(block, commit_qc)
    }
    fn build(
        &mut self,
        height: u64,
        view: u64,
        max_bytes: u32,
        budget: u32,
    ) -> Result<Option<iroha_sumeragi::availability::PayloadBytes>, PublicationError> {
        self.other("build");
        self.inner.build(height, view, max_bytes, budget)
    }
    fn reject(&mut self, height: u64, view: u64, block_hash: &Hash32) {
        self.other("reject");
        self.inner.reject(height, view, block_hash);
    }
}

/// Run the scheduler's operations at `now` until it has none.
fn drive(
    sched: &mut ExecSched,
    exec: &mut Overlay,
    blocks: &FakeBlocks,
    now: Millis,
) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(op) = sched.next(now) {
        let done = run_exec(exec, blocks, op);
        sched.done(now, done);
        events.extend(sched.take_events());
    }
    events
}

/// While an append backs off, nothing else runs on the executor (no execution, discard,
/// rejection or build between a prepare and its commit), so a single-overlay executor commits
/// once the append succeeds; the other work runs afterwards.
#[test]
fn apply_runs_alone_while_backing_off() {
    let mut sched = ExecSched::new(0, Backoff::default(), super::test_registrations());
    let mut exec = Overlay::new();
    let blocks = FakeBlocks::default();
    let (b1, bh1, r1) = child(1, (G, RG), 1);
    let (b2, bh2, r2) = child(2, (bh1, r1), 2);
    let (x2, bhx, _) = child(2, (bh1, r1), 99);
    blocks.fail_next(1);
    sched.commit(b1.clone(), commit_qc(&b1, r1));
    sched.execute(1, bh2, b2, false);
    sched.reject(1, 0, Hash32([9; 32]));
    let first = drive(&mut sched, &mut exec, &blocks, 0);
    assert!(first.is_empty(), "{first:?}");
    assert_eq!(
        exec.calls,
        vec!["prepare"],
        "the append failed; nothing else ran"
    );
    // Work arriving during the backoff waits too.
    sched.execute(2, bhx, x2, false);
    sched.discard(2, vec![bh2]);
    sched.build(5, 2, 0, 1024, 100);
    assert!(drive(&mut sched, &mut exec, &blocks, 9).is_empty());
    assert_eq!(exec.calls, vec!["prepare"]);
    assert_eq!(sched.wakeup(), 10);
    let mut events = drive(&mut sched, &mut exec, &blocks, 10);
    sched.retain_control_context(Some((applied_parent_context(&b1, r1), 0)));
    events.extend(drive(&mut sched, &mut exec, &blocks, 10));
    assert_eq!(&exec.calls[..2], &["prepare", "commit"]);
    assert_eq!(sched.applied(), 1);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::BlockApplied { height: 1, .. }))
    );
    assert!(events.iter().any(|e| matches!(
        e,
        Event::Executed { req: 1, outcome: ExecOutcome::Valid(r), .. } if *r == r2
    )));
    assert!(exec.calls.contains(&"build") && exec.calls.contains(&"reject"));
}

/// A commit that fails is retried after a fresh prepare — the prepared post-state may be gone
/// — and without a second append (the block is durable already).
#[test]
fn failed_commit_prepares_again_without_a_second_append() {
    let mut sched = ExecSched::new(0, Backoff::default(), super::test_registrations());
    let mut exec = Overlay::new();
    exec.fail_commits = 1;
    let blocks = FakeBlocks::default();
    let (b1, bh1, r1) = child(1, (G, RG), 1);
    sched.commit(b1.clone(), commit_qc(&b1, r1));
    let (b2, _, _) = child(2, (bh1, r1), 2);
    let events = drive(&mut sched, &mut exec, &blocks, 0);
    assert!(events.is_empty());
    assert_eq!(exec.calls, vec!["prepare", "commit"]);
    assert_eq!(blocks.height(), 1, "appended once");
    sched.execute(1, hash(&b2), b2, false);
    assert!(
        drive(&mut sched, &mut exec, &blocks, 5).is_empty(),
        "backing off alone"
    );
    let events = drive(&mut sched, &mut exec, &blocks, 10);
    assert_eq!(
        &exec.calls[..4],
        &["prepare", "commit", "prepare", "commit"]
    );
    assert_eq!(blocks.height(), 1, "no second append");
    assert_eq!(sched.applied(), 1);
    let applied = events
        .iter()
        .filter(|e| matches!(e, Event::BlockApplied { .. }))
        .count();
    assert_eq!(applied, 1);
}

/// Successful re-preparation does not recover a failing commit or its pending archive
/// capture. Keep increasing the delay through the cap, then reset it for the next block.
#[test]
fn repeated_commit_failures_preserve_backoff_and_reset_after_success() {
    let mut sched = ExecSched::new(0, Backoff::default(), super::test_registrations());
    let mut exec = Overlay::new();
    exec.fail_commits = 9;
    let blocks = FakeBlocks::default();
    let (b1, bh1, r1) = child(1, (G, RG), 1);
    sched.commit(b1.clone(), commit_qc(&b1, r1));

    let mut now = 0;
    for (attempt, delay) in [10, 20, 40, 80, 160, 320, 640, 1_000, 1_000]
        .into_iter()
        .enumerate()
    {
        assert!(drive(&mut sched, &mut exec, &blocks, now).is_empty());
        assert_eq!(sched.applied(), 0, "commit has not completed");
        assert_eq!(blocks.height(), 1, "the same block remains durable");
        assert_eq!(exec.calls.len(), 2 * (attempt + 1));
        assert!(
            exec.calls
                .chunks_exact(2)
                .all(|calls| calls == ["prepare", "commit"])
        );
        assert_eq!(sched.wakeup(), now + delay);
        assert!(sched.next(now + delay - 1).is_none(), "no early retry");
        now += delay;
    }
    let events = drive(&mut sched, &mut exec, &blocks, now);
    assert_eq!(sched.applied(), 1);
    assert_eq!(sched.wakeup(), Millis::MAX);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::BlockApplied { height: 1, .. }))
            .count(),
        1,
        "one completion after recovery"
    );

    let (b2, _, r2) = child(2, (bh1, r1), 2);
    exec.fail_commits = 1;
    sched.commit(b2.clone(), commit_qc(&b2, r2));
    assert!(drive(&mut sched, &mut exec, &blocks, now).is_empty());
    assert_eq!(sched.applied(), 1);
    assert_eq!(
        sched.wakeup(),
        now + 10,
        "new block starts at the initial delay"
    );
    let events = drive(&mut sched, &mut exec, &blocks, now + 10);
    assert_eq!(sched.applied(), 2);
    assert_eq!(sched.wakeup(), Millis::MAX);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::BlockApplied { height: 2, .. }))
            .count(),
        1
    );
}

/// A failed re-prepare is still part of completing the already durable block. Its next
/// successful prepare must not discard either the commit or prepare failure history.
#[test]
fn commit_backoff_survives_a_failed_reprepare() {
    let mut sched = ExecSched::new(0, Backoff::default(), super::test_registrations());
    let mut exec = Overlay::new();
    exec.fail_commits = 2;
    let blocks = FakeBlocks::default();
    let (b1, _, r1) = child(1, (G, RG), 1);
    sched.commit(b1.clone(), commit_qc(&b1, r1));
    assert!(drive(&mut sched, &mut exec, &blocks, 0).is_empty());
    assert_eq!(sched.wakeup(), 10);

    exec.inner.state.lock().fail_apply = 1;
    assert!(drive(&mut sched, &mut exec, &blocks, 10).is_empty());
    assert_eq!(exec.calls, ["prepare", "commit", "prepare"]);
    assert_eq!(sched.wakeup(), 30);
    assert!(sched.next(29).is_none());
    assert!(drive(&mut sched, &mut exec, &blocks, 30).is_empty());
    assert_eq!(sched.wakeup(), 70);
    assert!(sched.next(69).is_none());
    assert_eq!(blocks.height(), 1);
    assert_eq!(sched.applied(), 0);

    let events = drive(&mut sched, &mut exec, &blocks, 70);
    assert_eq!(sched.applied(), 1);
    assert_eq!(sched.wakeup(), Millis::MAX);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::BlockApplied { height: 1, .. }))
            .count(),
        1
    );
}

/// Discards of one height merge while they wait (keeping what both keep), and rejections are
/// deduplicated and capped: the queues other than the `Execute`s stay bounded.
#[test]
fn discards_merge_and_rejections_are_bounded() {
    let mut rig = Rig::new();
    let (b1, bh1, r1) = child(1, (G, RG), 1);
    let (a, bha, _) = child(2, (bh1, r1), 2);
    let (b, bhb, _) = child(2, (bh1, r1), 3);
    rig.sched.execute(1, bh1, b1, false);
    let running = rig.start().unwrap();
    for _ in 0..100 {
        rig.sched.discard(2, vec![bha, bhb]);
    }
    rig.sched.discard(2, vec![bha]);
    for i in 0..200u8 {
        rig.sched.reject(2, 0, Hash32([i; 32]));
        rig.sched.reject(2, 0, Hash32([i; 32]));
    }
    assert_eq!(rig.sched.queued_ops(), 1 + 64, "one discard, 64 rejections");
    rig.finish(running);
    rig.sched.execute(2, bha, a, false);
    rig.sched.execute(3, bhb, b, false);
    let next = rig.start().unwrap();
    assert_eq!(
        next,
        ExecOp::Discard {
            height: 2,
            keep: vec![bha]
        }
    );
    rig.finish(next);
    rig.drain();
    let rejected = rig.exec.state.lock().rejected.clone();
    assert_eq!(rejected.len(), 64);
    assert_eq!(rejected[0], Hash32([136; 32]), "the oldest were dropped");
}

/// A terminal prepare/commit answer stops every executor queue and creates no retry deadline.
#[test]
fn terminal_publication_errors_stop_all_scheduled_work() {
    for failure_in_commit in [false, true] {
        let mut rig = Rig::new();
        let (block, bh, result) = child(1, (G, RG), 1);
        rig.sched.commit(block.clone(), commit_qc(&block, result));
        assert!(matches!(rig.start(), Some(ExecOp::Prepare(_))));
        if failure_in_commit {
            rig.sched.done(0, ExecDone::Prepared(Ok(Some(result))));
            assert!(matches!(rig.start(), Some(ExecOp::Append(_))));
            rig.sched.done(
                0,
                ExecDone::Appended {
                    durable: true,
                    deferred: None,
                },
            );
            assert!(matches!(rig.start(), Some(ExecOp::Commit(_))));
        }
        // These queues must not invoke the worker after the terminal answer.
        rig.sched.execute(99, bh, block.clone(), false);
        rig.sched.discard(2, Vec::new());
        rig.sched.build(88, 1, 1, 1024, 10);
        rig.sched.reject(1, 0, bh);
        let error = PublicationError::RecoveryRequired("original owner consumed".into());
        let answer = if failure_in_commit {
            ExecDone::Committed(Err(error))
        } else {
            ExecDone::Prepared(Err(error))
        };
        assert_eq!(rig.sched.done(0, answer), None);
        assert_eq!(
            rig.sched.halted(),
            Some(iroha_sumeragi::api::HaltReason::PublicationRecoveryRequired { height: 1 })
        );
        assert_eq!(rig.sched.applied(), 0);
        assert_eq!(rig.sched.wakeup(), Millis::MAX);
        assert_eq!(rig.sched.outstanding(), 0);
        let events = rig.sched.take_events();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::PublicationRecoveryRequired { height: 1 }))
                .count(),
            1
        );
        assert!(!events.iter().any(|event| matches!(
            event,
            Event::BlockApplied { .. } | Event::ApplyDiverged { .. }
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Executed {
                req: 99,
                outcome: ExecOutcome::Cancelled,
                ..
            }
        )));
        for now in [0, 1, 1000, Millis::MAX - 1] {
            rig.sched.transactions_available();
            assert!(rig.sched.next(now).is_none());
        }
        assert!(rig.sched.take_events().is_empty());
    }
}

/// A different certified R does not replace a held original execution before divergence.
#[test]
fn cached_result_mismatch_diverges_without_reexecution() {
    let mut rig = Rig::new();
    let (block, hash, result) = child(1, (G, RG), 1);
    rig.sched.execute(1, hash, block.clone(), false);
    rig.drain();
    assert_eq!(rig.exec.executions(&hash), 1);
    rig.sched
        .commit(block.clone(), commit_qc(&block, Hash32([0x77; 32])));
    rig.drain();
    assert_eq!(rig.exec.executions(&hash), 1);
    assert_eq!(rig.sched.applied(), 0);
    assert!(rig.events.iter().any(|event| matches!(event, Event::ApplyDiverged { local_result, .. } if *local_result == result)));
}

/// The driver transports the original typed application result verbatim. Refusal must not
/// manufacture a successor from the last committee or publish a partial boundary.
#[test]
fn original_boundary_config_survives_retry_and_is_delivered_atomically() {
    use iroha_sumeragi::types::{AppliedConfig, ConfigSlot, EpochId};
    let mut next = config();
    next.epoch.id = EpochId {
        epoch: 1,
        context: Hash32([0x73; 32]),
    };
    next.epoch.first_height = 2;
    next.epoch.last_height = 8;
    next.epoch.leader_seed = Hash32([0x74; 32]);
    let mut after_next = next.clone();
    after_next.params.max_block_bytes -= 1;
    let outputs = [
        AppliedConfig::Continuation {
            after_next: ConfigSlot::PendingBoundary {
                boundary_height: 2,
                predecessor: iroha_sumeragi::testing::TEST_EPOCH.id,
            },
        },
        AppliedConfig::Boundary { next, after_next },
    ];
    for original in outputs {
        let mut rig = Rig::new();
        let (block, block_hash, result) = child(1, (G, RG), 1);
        let certificate = commit_qc(&block, result);
        rig.sched.commit(block.clone(), certificate.clone());
        let mut refused = false;
        loop {
            let op = rig.start().expect("original publication remains scheduled");
            if let ExecOp::Commit(commit) = op {
                assert_eq!(commit.block, block);
                assert_eq!(commit.qc, certificate);
                if !refused {
                    rig.sched.done(
                        rig.now,
                        ExecDone::Committed(Err(PublicationError::Retryable(
                            "physical refusal".into(),
                        ))),
                    );
                    assert!(
                        rig.sched
                            .take_events()
                            .iter()
                            .all(|event| !matches!(event, Event::BlockApplied { .. }))
                    );
                    assert_eq!(rig.sched.applied(), 0);
                    rig.now += 1_000;
                    refused = true;
                } else {
                    assert_eq!(
                        rig.sched
                            .done(rig.now, ExecDone::Committed(Ok(Box::new(original.clone())))),
                        Some(1)
                    );
                    break;
                }
            } else {
                rig.finish(op);
            }
        }
        let applied: Vec<_> = rig
            .sched
            .take_events()
            .into_iter()
            .filter_map(|event| match event {
                Event::BlockApplied {
                    height,
                    block_hash: hash,
                    header,
                    config,
                } => Some((height, hash, header, config)),
                _ => None,
            })
            .collect();
        assert_eq!(
            applied,
            vec![(1, block_hash, Box::new(block.header().clone()), original)]
        );
        assert_eq!(rig.sched.applied(), 1);
        assert_eq!(rig.blocks.height(), 1);
    }
}

fn control_context(height: u64, view: u64) -> iroha_sumeragi::api::ControlWitnessContext {
    iroha_sumeragi::api::ControlWitnessContext {
        height,
        view,
        epoch: iroha_sumeragi::testing::TEST_EPOCH.id,
        parent_hash: G,
        parent_result: RG,
    }
}
fn applied_parent_context(
    parent: &AvailableBody,
    result: Hash32,
) -> iroha_sumeragi::api::ApplicationControlContext {
    iroha_sumeragi::api::ApplicationControlContext {
        instance: parent.source().instance(),
        epoch: parent.header().epoch,
        height: parent.header().height + 1,
        parent_hash: hash(parent),
        parent_result: result,
    }
}

fn partial_context(height: u64) -> iroha_sumeragi::api::ApplicationControlContext {
    iroha_sumeragi::api::ApplicationControlContext {
        instance: Hash32([5; 32]),
        epoch: iroha_sumeragi::testing::TEST_EPOCH.id,
        height,
        parent_hash: G,
        parent_result: RG,
    }
}
fn partial(height: u64) -> iroha_sumeragi::message::ApplicationControl {
    iroha_sumeragi::message::ApplicationControl {
        context: partial_context(height),
        bytes: iroha_sumeragi::types::ControlWitness::try_from_slice(
            b"proof-carrying partial fixture",
        )
        .unwrap(),
    }
}

#[test]
fn control_build_refusal_keeps_exact_request_and_does_not_block_transaction_work() {
    let mut sched = ExecSched::new(0, Backoff::default(), super::test_registrations());
    let context = control_context(1, 3);
    sched.retain_control_context(Some((partial_context(1), 3)));
    sched.build_control(17, context);
    sched.build(17, 1, 3, 1024, 100);
    assert_eq!(
        sched.next(0),
        Some(ExecOp::BuildControlWitness { req: 17, context })
    );
    sched.done(
        0,
        ExecDone::ControlWitnessBuilt(Err(PublicationError::Retryable("awaiting shares".into()))),
    );
    assert!(
        sched.take_events().is_empty(),
        "no invented empty control response"
    );
    assert_eq!(sched.wakeup(), 0, "transaction work is ready immediately");
    assert!(matches!(sched.next(0), Some(ExecOp::Build { req: 17, .. })));
    sched.done(0, ExecDone::Built(Ok(super::payload(vec![1]))));
    assert_eq!(
        sched.wakeup(),
        10,
        "the refused control request retains its retry deadline"
    );
    assert!(sched.next(9).is_none());
    assert_eq!(
        sched.next(10),
        Some(ExecOp::BuildControlWitness { req: 17, context })
    );
    let witness =
        iroha_sumeragi::types::ControlWitness::try_from_slice(b"canonical pulse").unwrap();
    sched.done(10, ExecDone::ControlWitnessBuilt(Ok(witness)));
    assert!(sched.take_events().iter().any(|event| matches!(event, Event::ControlWitnessBuilt { req: 17, context: exact, witness: bytes } if *exact == context && *bytes == witness)));
}

#[test]
fn control_build_view_change_cancels_queued_and_running_retry() {
    for success in [false, true] {
        let mut sched = ExecSched::new(0, Backoff::default(), super::test_registrations());
        let context = control_context(1, 1);
        sched.retain_control_context(Some((partial_context(1), 1)));
        sched.build_control(3, context);
        assert!(matches!(
            sched.next(0),
            Some(ExecOp::BuildControlWitness { req: 3, .. })
        ));
        sched.retain_control_context(Some((partial_context(1), 2)));
        let done = if success {
            Ok(iroha_sumeragi::types::ControlWitness::empty())
        } else {
            Err(PublicationError::Retryable("awaiting old shares".into()))
        };
        sched.done(0, ExecDone::ControlWitnessBuilt(done));
        assert!(sched.take_events().is_empty());
        assert!(sched.next(10_000).is_none());
        assert_eq!(sched.wakeup(), u64::MAX);
        sched.build_control(4, control_context(1, 2));
        sched.retain_control_context(None);
        assert!(sched.next(10_000).is_none());
    }
}

#[test]
fn all_validator_control_waits_for_applied_parent_and_shares_do_not_starve_work() {
    let mut sched = ExecSched::new(0, Backoff::default(), super::test_registrations());
    sched.retain_control_context(Some((partial_context(2), 0)));
    sched.drive_control(partial_context(2));
    sched.receive_control(PublicKey::new(vec![2; 32]).unwrap(), partial(2));
    assert!(sched.next(0).is_none());
    let mut sched = ExecSched::new(1, Backoff::default(), super::test_registrations());
    sched.retain_control_context(Some((partial_context(2), 0)));
    sched.drive_control(partial_context(2));
    sched.build(9, 2, 0, 64, 100);
    for index in 1..=4 {
        let key = PublicKey::new(vec![index; 32]).unwrap();
        sched.receive_control(key.clone(), partial(2));
        sched.receive_control(key, partial(2)); // one retained input per sender
    }
    assert_eq!(sched.queued_ops(), 6);
    assert_eq!(
        sched.next(0),
        Some(ExecOp::DriveApplicationControl(partial_context(2)))
    );
    sched.done(0, ExecDone::ApplicationControlDriven(Ok(Some(partial(2)))));
    assert!(matches!(sched.next(0), Some(ExecOp::Build { req: 9, .. })));
    sched.done(0, ExecDone::Built(Ok(None)));
    let Some(ExecOp::ReceiveApplicationControl {
        occurrence,
        from,
        message,
    }) = sched.next(0)
    else {
        panic!("original queued partial");
    };
    sched.done(
        0,
        ExecDone::ApplicationControlReceived {
            occurrence,
            from,
            message,
            result: Ok(()),
        },
    );
    sched.retain_control_context(Some((partial_context(2), 1))); // partials survive a view change
    assert_eq!(sched.queued_ops(), 3);
    sched.retain_control_context(Some((partial_context(3), 0))); // old-source partials do not survive a height
    assert_eq!(sched.queued_ops(), 0);
}

#[test]
fn application_control_ingress_has_a_hard_protocol_cap() {
    let mut sched = ExecSched::new(0, Backoff::default(), super::test_registrations());
    sched.retain_control_context(Some((partial_context(1), 0)));
    for index in 0..iroha_sumeragi::types::MAX_COMMITTEE_SIZE + 1 {
        let mut bytes = vec![0xAB; 32];
        bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
        sched.receive_control(PublicKey::new(bytes).unwrap(), partial(1));
    }
    assert_eq!(
        sched.queued_ops(),
        iroha_sumeragi::types::MAX_COMMITTEE_SIZE
    );
    sched.retain_control_context(None);
    assert_eq!(sched.queued_ops(), 0);
    assert!(sched.next(0).is_none());
}

#[test]
fn control_worker_unwind_requires_recovery_and_cannot_invent_empty() {
    let blocks = FakeBlocks::default();
    for op in [
        ExecOp::BuildControlWitness {
            req: 4,
            context: control_context(1, 0),
        },
        ExecOp::DriveApplicationControl(partial_context(1)),
        ExecOp::ReceiveApplicationControl {
            occurrence: super::super::exec::ControlOccurrence(0),
            from: PublicKey::new(vec![1; 32]).unwrap(),
            message: partial(1),
        },
    ] {
        let original = match &op {
            ExecOp::ReceiveApplicationControl {
                occurrence,
                from,
                message,
            } => Some((
                *occurrence,
                from.as_bytes().as_ptr(),
                message.context,
                message.bytes,
            )),
            _ => None,
        };
        let done = run_exec(&mut Panicking, &blocks, op);
        if let Some((expected, sender, context, bytes)) = original {
            let ExecDone::ApplicationControlReceived {
                occurrence,
                from,
                message,
                ..
            } = &done
            else {
                panic!("unwind must return the original input owner");
            };
            assert_eq!(*occurrence, expected);
            assert_eq!(from.as_bytes().as_ptr(), sender);
            assert_eq!(message.context, context);
            assert_eq!(message.bytes, bytes);
        }
        assert!(matches!(
            done,
            ExecDone::ControlWitnessBuilt(Err(PublicationError::RecoveryRequired(_)))
                | ExecDone::ApplicationControlDriven(Err(PublicationError::RecoveryRequired(_)))
                | ExecDone::ApplicationControlReceived {
                    result: Err(PublicationError::RecoveryRequired(_)),
                    ..
                }
        ));
    }
}

#[test]
fn due_control_build_progresses_under_replenished_drive_and_partial_ingress() {
    let mut sched = ExecSched::new(0, Backoff::default(), super::test_registrations());
    let context = control_context(1, 0);
    sched.retain_control_context(Some((partial_context(1), 0)));
    sched.build_control(71, context);
    for step in 0..3 {
        // The queues are replenished after every completion, including the previously served
        // kind: a fixed drive/inbox/build priority would never reach the due witness build.
        sched.drive_control(partial_context(1));
        sched.receive_control(PublicKey::new(vec![1; 32]).unwrap(), partial(1));
        match (step, sched.next(0).unwrap()) {
            (0, ExecOp::DriveApplicationControl(_)) => {
                sched.done(0, ExecDone::ApplicationControlDriven(Ok(None)));
            }
            (
                1,
                ExecOp::ReceiveApplicationControl {
                    occurrence,
                    from,
                    message,
                },
            ) => {
                sched.done(
                    0,
                    ExecDone::ApplicationControlReceived {
                        occurrence,
                        from,
                        message,
                        result: Ok(()),
                    },
                );
            }
            (
                2,
                ExecOp::BuildControlWitness {
                    req: 71,
                    context: exact,
                },
            ) => {
                assert_eq!(exact, context);
                sched.done(
                    0,
                    ExecDone::ControlWitnessBuilt(Ok(
                        iroha_sumeragi::types::ControlWitness::empty(),
                    )),
                );
            }
            other => panic!("control class starved a ready kind: {other:?}"),
        }
    }
    assert!(
        sched
            .take_events()
            .iter()
            .any(|event| matches!(event, Event::ControlWitnessBuilt { req: 71, .. }))
    );
}

/// The execution worker's apply completion precedes Core's BlockApplied acceptance.
/// An original queued build must survive that first source activation without running early.
#[test]
fn successor_build_waits_for_core_parent_activation_and_keeps_empty_readiness() {
    let mut rig = Rig::new();
    let (parent, _, result) = child(1, (G, RG), 1);
    rig.sched.build(77, 2, 0, 1024, 100);
    rig.sched.commit(parent.clone(), commit_qc(&parent, result));
    rig.drain();
    assert_eq!(rig.sched.applied(), 1);
    assert!(
        rig.events
            .iter()
            .any(|event| matches!(event, Event::BlockApplied { height: 1, .. }))
    );
    assert!(
        !rig.events
            .iter()
            .any(|event| matches!(event, Event::PayloadBuilt { .. })),
        "worker apply alone cannot dispatch the original queued successor"
    );
    assert!(rig.start().is_none());
    assert_eq!(rig.sched.wakeup(), Millis::MAX);
    rig.events.clear();
    rig.sched
        .retain_control_context(Some((applied_parent_context(&parent, result), 0)));
    let operation = rig
        .start()
        .expect("Core's exact parent activates the original request");
    assert!(matches!(
        operation,
        ExecOp::Build {
            req: 77,
            height: 2,
            view: 0,
            ..
        }
    ));
    rig.finish(operation);
    assert_eq!(
        rig.events,
        vec![Event::PayloadBuilt {
            req: 77,
            payload: None,
        }]
    );
    rig.sched.transactions_available();
    assert_eq!(
        rig.sched.take_events(),
        vec![Event::PayloadReady { req: 77 }]
    );
    rig.sched.transactions_available();
    assert!(
        rig.sched.take_events().is_empty(),
        "original readiness is emitted once"
    );
}

/// Arrivals while the real queued request awaits Core's parent remain owed to that request.
#[test]
fn successor_build_activation_preserves_arrival_and_rejects_another_height_or_view() {
    for arrival_before_activation in [false, true] {
        let mut sched = ExecSched::new(1, Backoff::default(), super::test_registrations());
        sched.build(78, 2, 4, 1024, 100);
        if arrival_before_activation {
            sched.transactions_available();
        }
        assert!(sched.next(0).is_none());
        assert_eq!(sched.wakeup(), Millis::MAX);
        sched.retain_control_context(Some((partial_context(2), 4)));
        assert!(matches!(sched.next(0), Some(ExecOp::Build { req: 78, .. })));
        sched.done(0, ExecDone::Built(Ok(None)));
        let events = sched.take_events();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::PayloadReady { req: 78 }))
                .count(),
            usize::from(arrival_before_activation)
        );
        if !arrival_before_activation {
            sched.transactions_available();
            assert_eq!(sched.take_events(), vec![Event::PayloadReady { req: 78 }]);
        }
    }
    for (height, view) in [(3, 4), (2, 5)] {
        let mut sched = ExecSched::new(1, Backoff::default(), super::test_registrations());
        sched.build(79, 2, 4, 1024, 100);
        sched.retain_control_context(Some((partial_context(height), view)));
        assert!(sched.next(0).is_none());
        assert_eq!(
            sched.queued_ops(),
            0,
            "another parent/view cannot activate the original"
        );
        sched.retain_control_context(Some((partial_context(2), 4)));
        assert!(sched.next(0).is_none(), "a discarded request cannot revive");
    }
}

/// Binding a queued parent once does not weaken irreversible source or view cancellation.
#[test]
fn activated_build_withdrawal_cancels_original_running_and_empty_owners() {
    for empty_completed in [false, true] {
        let mut sched = ExecSched::new(1, Backoff::default(), super::test_registrations());
        sched.build(80, 2, 4, 1024, 100);
        sched.retain_control_context(Some((partial_context(2), 4)));
        assert!(matches!(sched.next(0), Some(ExecOp::Build { req: 80, .. })));
        if empty_completed {
            sched.done(0, ExecDone::Built(Ok(None)));
            assert!(matches!(
                sched.take_events().as_slice(),
                [Event::PayloadBuilt { req: 80, .. }]
            ));
        }
        sched.retain_control_context(None);
        sched.retain_control_context(Some((partial_context(2), 4)));
        if !empty_completed {
            sched.done(0, ExecDone::Built(Ok(None)));
        }
        sched.transactions_available();
        assert!(
            sched.take_events().is_empty(),
            "withdrawal retires the original request forever"
        );
        assert!(sched.next(Millis::MAX - 1).is_none());
        assert_eq!(sched.wakeup(), Millis::MAX);
    }
}
