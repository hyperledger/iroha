//! A tiny deterministic multi-core loop: `n` unmodified cores with an instant-durability fake
//! driver, a fixed message latency, per-link filters and an event hook. Used by the tests that
//! inherently need several live cores (`det_l9`, `det_l10`, `det_l19`, `det_l21`, `det_l24`)
//! and as an end-to-end smoke test.

use std::collections::BTreeMap;

use super::{G_HASH, G_RESULT, I, W, initial_record, result_of};
use crate::{
    api::{Action, CommittedTip, Event, ExecOutcome, HaltReason, Init, LocalParams},
    availability::{
        AvailabilityFrame, AvailableBody, BodyRestoration, PayloadAcquisition, PayloadAuthoring,
        PayloadBytes, RowBytes,
    },
    crypto::Signer,
    machine::Core,
    message::{PayloadChunk, PayloadManifest, Qc, SyncEntry, SyncResponse, VoteKind, WireMessage},
    safety::RecordState,
    testing::FakeValidators,
    types::{ChainParams, Hash32, HeightConfig, Millis, PublicKey},
};

pub(super) type Filter = Box<dyn Fn(usize, usize, &WireMessage) -> bool>;
/// Event hook: `true` = the event is held (in `Cluster::held`) instead of delivered.
pub(super) type Hook = Box<dyn Fn(Millis, usize, &Event) -> bool>;

pub(super) struct Node {
    pub core: Option<Core>,
    budget: iroha_allocation::AllocationBudget,
    acquisitions: BTreeMap<Hash32, PayloadAcquisition>,
    pub key: PublicKey,
    pub record: Option<Vec<u8>>,
    pub bodies: BTreeMap<Hash32, AvailableBody>,
    pub store: Vec<(AvailableBody, Qc)>,
    pub halted: Option<HaltReason>,
    pub evidence: usize,
}

pub(super) struct Cluster {
    pub v: FakeValidators,
    pub nodes: Vec<Node>,
    pub now: Millis,
    queue: BTreeMap<(Millis, u64), (usize, Event)>,
    seq: u64,
    pub latency: Millis,
    pub exec_delay: Millis,
    /// `true` = drop the message from `from` to `to`.
    pub filter: Filter,
    /// Called for every event about to be delivered (after the filter).
    pub hook: Hook,
    /// Events the hook held back, with their target node.
    pub held: Vec<(usize, Event)>,
    /// The builder answers `EMPTY` (an idle chain).
    pub idle: bool,
    pub local: LocalParams,
    pub params: ChainParams,
    /// Committed value per height (agreement oracle).
    pub committed: BTreeMap<u64, (Hash32, Hash32)>,
    /// Sequence numbers of injected events (not passed to the hook).
    bypass: Vec<u64>,
    /// Committed blocks per height (the first to commit).
    pub blocks: BTreeMap<u64, AvailableBody>,
    /// View of the first `CommitQC` of every height.
    pub commit_views: BTreeMap<u64, u64>,
    nonce: u64,
}

impl Cluster {
    pub fn new(n: usize) -> Self {
        Self::with(n, LocalParams::default(), ChainParams::default(), false)
    }

    /// `n` nodes with the given parameters; `idle`: the builder always answers `EMPTY`.
    pub fn with(n: usize, local: LocalParams, params: ChainParams, idle: bool) -> Self {
        let v = FakeValidators::new(n, 7, None);
        let mut cluster = Self {
            nodes: (0..n)
                .map(|i| Node {
                    core: None,
                    budget: iroha_allocation::AllocationBudget::new(1 << 30),
                    acquisitions: BTreeMap::new(),
                    key: v.key(u32::try_from(i).unwrap()),
                    record: None,
                    bodies: BTreeMap::new(),
                    store: Vec::new(),
                    halted: None,
                    evidence: 0,
                })
                .collect(),
            v,
            now: 0,
            queue: BTreeMap::new(),
            seq: 0,
            latency: 10,
            exec_delay: 20,
            filter: Box::new(|_, _, _| false),
            hook: Box::new(|_, _, _| false),
            held: Vec::new(),
            idle,
            local,
            params,
            committed: BTreeMap::new(),
            bypass: Vec::new(),
            blocks: BTreeMap::new(),
            commit_views: BTreeMap::new(),
            nonce: 0,
        };
        for i in 0..n {
            let key = cluster.nodes[i].key.clone();
            cluster.nodes[i].record = Some(initial_record(&cluster.v, &key));
        }
        for i in 0..n {
            cluster.start(i);
        }
        cluster
    }

    fn config(&self) -> HeightConfig {
        HeightConfig {
            epoch: Box::new(crate::testing::TEST_EPOCH),
            committee: self.v.committee.clone(),
            params: self.params,
        }
    }

    /// (Re)start node `i` from its durable stores.
    pub fn start(&mut self, i: usize) {
        let node = &self.nodes[i];
        let tip = match node.store.last() {
            None => CommittedTip {
                height: 0,
                block_hash: G_HASH,
                result: G_RESULT,
                header: None,
                commit_qc: None,
            },
            Some((block, qc)) => CommittedTip {
                height: block.header().height,
                block_hash: qc.block_hash,
                result: qc.result,
                header: Some(block.header().clone()),
                commit_qc: Some(qc.clone()),
            },
        };
        let t = tip.height;
        let mut configs = vec![
            (t + 1, crate::types::ConfigSlot::Ready(self.config())),
            (t + 2, crate::types::ConfigSlot::Ready(self.config())),
        ];
        if t > 0 {
            configs.push((t, crate::types::ConfigSlot::Ready(self.config())));
        }
        let state = node
            .record
            .clone()
            .map_or(RecordState::Absent, RecordState::Present);
        self.nonce += 1;
        let init = Init {
            instance: I,
            records: vec![(node.key.clone(), state, false)],
            genesis_height: 0,
            demotion_window: W,
            nonce: self.nonce,
            tip,
            configs,
            recent_headers: node.store.iter().map(|(b, _)| b.header().clone()).collect(),
        };
        let signer: std::sync::Arc<dyn Signer> =
            std::sync::Arc::new(self.v.signer(u32::try_from(i).unwrap()).clone());
        let (core, actions) = Core::new(
            self.local,
            init,
            vec![signer],
            Box::new(self.v.crypto.clone()),
            node.budget.clone(),
            self.now,
        )
        .expect("valid configuration");
        self.nodes[i].core = Some(core);
        self.apply(i, actions);
    }

    /// Crash node `i`: its volatile state and queued events are lost.
    pub fn crash(&mut self, i: usize) {
        self.nodes[i].core = None;
        self.nodes[i].acquisitions.clear();
        self.queue.retain(|_, (to, _)| *to != i);
    }

    fn schedule(&mut self, at: Millis, to: usize, event: Event) {
        self.seq += 1;
        self.queue.insert((at, self.seq), (to, event));
    }

    /// Deliver `event` to node `to` at `at` (bypassing the hook).
    pub fn inject(&mut self, at: Millis, to: usize, event: Event) {
        self.seq += 1;
        self.queue.insert((at.max(self.now), self.seq), (to, event));
        self.bypass.push(self.seq);
    }

    fn index_of(&self, key: &PublicKey) -> Option<usize> {
        self.nodes.iter().position(|n| &n.key == key)
    }

    fn send(&mut self, from: usize, to: &PublicKey, msg: &WireMessage) {
        let Some(j) = self.index_of(to) else {
            return;
        };
        if j == from || (self.filter)(from, j, msg) {
            return;
        }
        let bytes = msg.encode().unwrap();
        let mut msg = WireMessage::decode(&bytes, 32 << 20).unwrap();
        msg.admit_owned_bytes(&self.nodes[j].budget).unwrap();
        let from_key = self.nodes[from].key.clone();
        self.schedule(
            self.now + self.latency,
            j,
            Event::Message {
                from: from_key,
                msg,
            },
        );
    }

    /// The fake driver: execute node `i`'s actions (durability is instant).
    #[allow(clippy::too_many_lines)] // one arm per action kind
    fn apply(&mut self, i: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::PersistSafety(record) => {
                    self.nodes[i].record = Some(record.encode(&self.v.crypto).unwrap());
                }
                Action::StoreBody { block } => {
                    let bh = block.hash(&self.v.crypto);
                    self.nodes[i].bodies.insert(bh, block);
                }
                Action::Send { to, msg } => self.send(i, &to, &msg),
                Action::Broadcast { to, msg } => {
                    for key in &to {
                        self.send(i, key, &msg);
                    }
                }
                // The fixture has no application control work: return its explicit
                // empty response at the current time, as the full simulator does.
                Action::BuildControlWitness { req, context } => self.schedule(
                    self.now,
                    i,
                    Event::ControlWitnessBuilt {
                        req,
                        context,
                        witness: crate::types::ControlWitness::empty(),
                    },
                ),
                Action::BuildPayload {
                    req, height, view, ..
                } => {
                    let payload = if self.idle {
                        Vec::new()
                    } else {
                        vec![
                            u8::try_from(i).unwrap(),
                            height.to_be_bytes()[7],
                            view.to_be_bytes()[7],
                        ]
                    };
                    let payload = if payload.is_empty() {
                        None
                    } else {
                        let mut bytes = PayloadBytes::from_untrusted(payload).unwrap();
                        bytes.admit(&self.nodes[i].budget).unwrap();
                        Some(bytes)
                    };
                    self.schedule(self.now + 1, i, Event::PayloadBuilt { req, payload });
                }
                Action::Execute { block, req, .. } => {
                    let bh = block.hash(&self.v.crypto);
                    self.schedule(
                        self.now + self.exec_delay,
                        i,
                        Event::Executed {
                            block_hash: bh,
                            req,
                            outcome: ExecOutcome::Valid(result_of(&block)),
                        },
                    );
                }
                Action::CommitBlock { block, commit_qc } => {
                    let height = block.header().height;
                    let value = commit_qc.value();
                    let known = *self.committed.entry(height).or_insert(value);
                    assert_eq!(known, value, "agreement violated at height {height}");
                    assert_eq!(
                        commit_qc.kind,
                        VoteKind::Commit,
                        "committed without a CommitQC"
                    );
                    self.blocks.entry(height).or_insert_with(|| block.clone());
                    self.commit_views.entry(height).or_insert(commit_qc.view);
                    let header = Box::new(block.header().clone());
                    self.nodes[i].store.push((block, commit_qc));
                    self.schedule(
                        self.now + 1,
                        i,
                        Event::BlockApplied {
                            height,
                            block_hash: value.0,
                            header,
                            config: crate::types::AppliedConfig::Continuation {
                                after_next: crate::types::ConfigSlot::Ready(self.config()),
                            },
                        },
                    );
                }
                Action::AuthorPayload {
                    req,
                    config,
                    header,
                    payload,
                } => {
                    let body = PayloadAuthoring::new(header, payload)
                        .complete(
                            I,
                            &config,
                            &self.nodes[i].budget,
                            &self.v.crypto,
                            self.v.signer(u32::try_from(i).unwrap()),
                        )
                        .unwrap_or_else(|(_, e)| panic!("author: {e:?}"))
                        .body;
                    self.schedule(self.now + 1, i, Event::PayloadAuthored { req, body });
                }
                Action::AcquirePayload { source, manifest } => {
                    let bh = source.block_hash();
                    let mut job = PayloadAcquisition::new(source, manifest);
                    match job.prepare(&self.nodes[i].budget, &self.v.crypto) {
                        Ok(()) => {
                            self.nodes[i].acquisitions.entry(bh).or_insert(job);
                        }
                        Err(e) if e.rejects_manifest() => self.schedule(
                            self.now + 1,
                            i,
                            Event::ManifestRejected {
                                manifest: job.manifest().clone(),
                            },
                        ),
                        Err(e) => panic!("acquisition: {e:?}"),
                    }
                }
                Action::ReceivePayloadChunk { chunk, .. } => {
                    let bh = chunk.block_hash;
                    if let Some(mut job) = self.nodes[i].acquisitions.remove(&bh) {
                        let _ = job.push(chunk, &self.nodes[i].budget, &self.v.crypto);
                        match job.complete(&self.nodes[i].budget, &self.v.crypto) {
                            Ok(block) => {
                                self.schedule(self.now + 1, i, Event::BodyAvailable { block })
                            }
                            Err((job, crate::availability::AcquisitionError::Incomplete)) => {
                                self.nodes[i].acquisitions.insert(bh, job);
                            }
                            Err((job, e)) if e.rejects_manifest() => self.schedule(
                                self.now + 1,
                                i,
                                Event::ManifestRejected {
                                    manifest: job.manifest().clone(),
                                },
                            ),
                            Err((_, e)) => panic!("reconstruction: {e:?}"),
                        }
                    }
                }
                Action::FetchPayload { source, peers } => {
                    if let Some(body) = self.local_body(i, source.height(), source.block_hash()) {
                        let job = BodyRestoration::new(
                            source,
                            body.header().clone(),
                            AvailabilityFrame::from_untrusted(
                                body.availability().as_slice().to_vec(),
                            )
                            .unwrap(),
                            PayloadBytes::from_untrusted(body.payload().as_slice().to_vec())
                                .unwrap(),
                        );
                        let block = job
                            .complete(&self.nodes[i].budget, &self.v.crypto)
                            .unwrap_or_else(|(_, e)| panic!("restoration: {e:?}"));
                        self.schedule(self.now + 1, i, Event::BodyAvailable { block });
                    } else {
                        let msg = WireMessage::PayloadRequest(crate::message::PayloadRequest {
                            instance: I,
                            height: source.height(),
                            block_hash: source.block_hash(),
                        });
                        for peer in &peers {
                            self.send(i, peer, &msg);
                        }
                    }
                }
                Action::ServePayload {
                    to,
                    height,
                    block_hash,
                } => {
                    if let Some(body) = self.local_body(i, height, block_hash) {
                        self.disseminate(i, &[to], &body);
                    }
                }
                Action::DisseminatePayload { peers, body } => self.disseminate(i, &peers, &body),
                Action::ServeBlocks {
                    to,
                    from_height,
                    max_count,
                    ..
                } => {
                    let blocks: Vec<SyncEntry> = self.nodes[i]
                        .store
                        .iter()
                        .filter(|(b, _)| b.header().height >= from_height)
                        .take(usize::from(max_count))
                        .map(|(b, q)| SyncEntry {
                            manifest: PayloadManifest {
                                header: b.header().clone(),
                                availability: b.availability().clone(),
                            },
                            commit_qc: q.clone(),
                        })
                        .collect();
                    // Possibly empty: "I hold nothing at from_height" (§3.5).
                    let msg = WireMessage::SyncResponse(SyncResponse {
                        instance: I,
                        blocks,
                    });
                    self.send(i, &to, &msg);
                }
                Action::ReportEvidence(_) => self.nodes[i].evidence += 1,
                Action::Halt(reason) => self.nodes[i].halted = Some(reason),
                Action::DiscardExecution { .. }
                | Action::DriveApplicationControl { .. }
                | Action::ReceiveApplicationControl { .. }
                | Action::PayloadRejected { .. }
                | Action::LocalFault(_) => {}
            }
        }
    }

    fn local_body(&self, i: usize, height: u64, bh: Hash32) -> Option<AvailableBody> {
        self.nodes[i]
            .bodies
            .get(&bh)
            .cloned()
            .or_else(|| {
                self.nodes[i]
                    .store
                    .iter()
                    .find(|(b, q)| q.block_hash == bh && b.header().height == height)
                    .map(|(b, _)| b.clone())
            })
            .filter(|b| b.header().height == height)
    }

    fn disseminate(&mut self, i: usize, peers: &[PublicKey], body: &AvailableBody) {
        let shape = self
            .config()
            .epoch
            .da_layout
            .shape(body.payload().as_slice().len() as u64)
            .unwrap();
        let encoded = iroha_primitives::erasure::rs16::compact::encode_funded(
            shape,
            body.payload().as_slice(),
            &self.nodes[i].budget,
        )
        .unwrap();
        let manifest = WireMessage::PayloadManifest(PayloadManifest {
            header: body.header().clone(),
            availability: body.availability().clone(),
        });
        for peer in peers {
            self.send(i, peer, &manifest);
        }
        for index in 0..shape.chunk_count() {
            let mut bytes = RowBytes::from_untrusted(
                encoded.codeword()[shape.chunk_range(index).unwrap()].to_vec(),
            )
            .unwrap();
            bytes.admit(&self.nodes[i].budget).unwrap();
            let chunk = WireMessage::PayloadChunk(PayloadChunk {
                instance: I,
                height: body.header().height,
                block_hash: body.hash(&self.v.crypto),
                index: u32::try_from(index).unwrap(),
                bytes,
            });
            for peer in peers {
                self.send(i, peer, &chunk);
            }
        }
    }

    /// Run until `until` (virtual ms).
    pub fn run_until(&mut self, until: Millis) {
        for _ in 0..2_000_000 {
            let next_event = self.queue.keys().next().map(|(t, _)| *t);
            let next_wake = self
                .nodes
                .iter()
                .enumerate()
                .filter_map(|(i, n)| n.core.as_ref().map(|c| (c.next_wakeup(), i)))
                .min();
            let t = match (next_event, next_wake) {
                (None, None) => break,
                (Some(e), None) => e,
                (None, Some((w, _))) => w,
                (Some(e), Some((w, _))) => e.min(w),
            };
            if t > until {
                break;
            }
            self.now = self.now.max(t);
            if let Some((w, i)) = next_wake
                && w <= next_event.unwrap_or(Millis::MAX)
            {
                let now = self.now;
                let actions = self.nodes[i]
                    .core
                    .as_mut()
                    .map(|c| c.handle(now, Event::Tick))
                    .unwrap_or_default();
                self.apply(i, actions);
                continue;
            }
            let Some(((_, seq), (to, event))) = self.queue.pop_first() else {
                break;
            };
            let injected = self.bypass.contains(&seq);
            if injected {
                self.bypass.retain(|s| *s != seq);
            } else if (self.hook)(self.now, to, &event) {
                self.held.push((to, event));
                continue;
            }
            let now = self.now;
            let Some(core) = self.nodes[to].core.as_mut() else {
                continue;
            };
            let actions = core.handle(now, event);
            self.apply(to, actions);
        }
        self.now = self.now.max(until);
    }

    /// Committed height of node `i` (its store tip).
    pub fn height_of(&self, i: usize) -> u64 {
        self.nodes[i]
            .store
            .last()
            .map_or(0, |(b, _)| b.header().height)
    }

    pub fn min_height(&self, nodes: &[usize]) -> u64 {
        nodes.iter().map(|i| self.height_of(*i)).min().unwrap_or(0)
    }
}

#[test]
fn cluster_commits_all_honest() {
    let mut c = Cluster::new(4);
    c.run_until(60_000);
    let min = c.min_height(&[0, 1, 2, 3]);
    eprintln!(
        "all honest: heights {:?}",
        (0..4).map(|i| c.height_of(i)).collect::<Vec<_>>()
    );
    assert!(
        min >= 10,
        "heights {:?}",
        (0..4).map(|i| c.height_of(i)).collect::<Vec<_>>()
    );
    assert!(
        c.nodes
            .iter()
            .all(|n| n.halted.is_none() && n.evidence == 0)
    );
}

#[test]
fn cluster_commits_with_one_silent_node() {
    for silent in 0..4 {
        let mut c = Cluster::new(4);
        c.filter = Box::new(move |from, to, _| from == silent || to == silent);
        c.run_until(120_000);
        let live: Vec<usize> = (0..4).filter(|i| *i != silent).collect();
        let min = c.min_height(&live);
        eprintln!(
            "silent {silent}: heights {:?}",
            (0..4).map(|i| c.height_of(i)).collect::<Vec<_>>()
        );
        assert!(
            min >= 5,
            "silent {silent}: heights {:?}",
            (0..4).map(|i| c.height_of(i)).collect::<Vec<_>>()
        );
    }
}

#[test]
fn cluster_single_validator_commits() {
    let mut c = Cluster::new(1);
    c.run_until(30_000);
    eprintln!("single: {}", c.height_of(0));
    assert!(c.height_of(0) >= 5, "height {}", c.height_of(0));
}

#[test]
fn cluster_seven_with_two_silent() {
    let mut c = Cluster::new(7);
    c.filter = Box::new(|from, to, _| from >= 5 || to >= 5);
    c.run_until(180_000);
    let min = c.min_height(&[0, 1, 2, 3, 4]);
    eprintln!(
        "7/2: heights {:?}",
        (0..7).map(|i| c.height_of(i)).collect::<Vec<_>>()
    );
    assert!(
        min >= 5,
        "heights {:?}",
        (0..7).map(|i| c.height_of(i)).collect::<Vec<_>>()
    );
}

#[test]
fn cluster_restart_every_node_keeps_committing() {
    let mut c = Cluster::new(4);
    c.run_until(20_000);
    let before = c.min_height(&[0, 1, 2, 3]);
    for i in 0..4 {
        c.crash(i);
        c.run_until(c.now + 700);
        c.start(i);
        c.run_until(c.now + 5_000);
    }
    c.run_until(c.now + 40_000);
    let after = c.min_height(&[0, 1, 2, 3]);
    eprintln!("restart: before {before} after {after}");
    assert!(after > before + 3, "before {before}, after {after}");
    assert!(c.nodes.iter().all(|n| n.halted.is_none()));
}

/// `det_l9` (ML9): n = 4, D silent. X alone forms TC(6) (it alone receives the view-6
/// timeouts), enters view 7, times out and restarts. The restored `high_tc` puts it back in
/// view 7 and its `Status` carries TC(6), so every live node reaches view 7 and commits.
#[test]
fn det_l9_restart_after_tc_entry() {
    use std::{cell::Cell, rc::Rc};
    let mut c = Cluster::new(4);
    let phase = Rc::new(Cell::new(0u8));
    let p = Rc::clone(&phase);
    c.filter = Box::new(move |from, to, msg| {
        if from == 3 || to == 3 {
            return true;
        }
        match p.get() {
            // No proposal reaches anyone: every view fails.
            0 => matches!(msg, WireMessage::Proposal(_)),
            // View 6: only Y and Z's timeouts reach X; nothing of X's leaves.
            1 => {
                matches!(msg, WireMessage::Proposal(_))
                    || from == 0
                    || matches!(msg, WireMessage::Timeout(t) if t.view >= 6 && to != 0)
            }
            _ => false,
        }
    });
    let view = |c: &Cluster, i: usize| c.nodes[i].core.as_ref().map_or(0, |core| core.view);
    while !(0..3).all(|i| view(&c, i) == 6) {
        assert!(c.now < 200_000, "views reach 6");
        c.run_until(c.now + 50);
    }
    let height = c.nodes[0].core.as_ref().unwrap().height;
    phase.set(1);
    while !c.nodes[0]
        .core
        .as_ref()
        .is_some_and(|core| core.view == 7 && core.timeout_view == Some(7))
    {
        assert!(c.now < 400_000, "X enters and times out view 7");
        c.run_until(c.now + 50);
    }
    assert_eq!((view(&c, 1), view(&c, 2)), (6, 6), "Y and Z stay in view 6");
    let before = c.min_height(&[0, 1, 2]);
    c.crash(0);
    c.run_until(c.now + 1_000);
    c.start(0);
    let x = c.nodes[0].core.as_ref().unwrap();
    assert_eq!((x.height, x.view), (height, 7));
    assert_eq!(
        x.high_tc.as_ref().map(|tc| tc.view),
        Some(6),
        "high_tc restored"
    );
    phase.set(2);
    c.run_until(c.now + 120_000);
    assert!(
        c.min_height(&[0, 1, 2]) > before,
        "all live nodes commit again"
    );
}

/// `det_l10` (ML10, F32): a `PrepareQC` is locked everywhere but no `CommitQC` forms; the whole
/// cluster restarts. Stored bodies and restored locks let it commit the locked block.
#[test]
fn det_l10_cluster_restart_lock_no_cqc() {
    use std::{cell::Cell, rc::Rc};
    let mut c = Cluster::new(4);
    c.run_until(5_000);
    let height = c.nodes[0].core.as_ref().unwrap().height;
    let block_commits = Rc::new(Cell::new(true));
    let b = Rc::clone(&block_commits);
    c.filter = Box::new(move |_, _, msg| {
        b.get() && matches!(msg, WireMessage::Vote(v) if v.kind == VoteKind::Commit)
    });
    let locked = |c: &Cluster| {
        c.nodes.iter().all(|n| {
            n.core
                .as_ref()
                .is_some_and(|core| core.height == height && core.high_pqc.is_some())
        })
    };
    while !locked(&c) {
        assert!(c.now < 60_000, "every node locks");
        c.run_until(c.now + 10);
    }
    let lock = c.nodes[0].core.as_ref().unwrap().high_pqc.clone().unwrap();
    assert!(!c.committed.contains_key(&height), "no CommitQC formed");
    for i in 0..4 {
        c.crash(i);
    }
    c.run_until(c.now + 2_000);
    block_commits.set(false);
    let mut restored = 0;
    for i in 0..4 {
        c.start(i);
        let core = c.nodes[i].core.as_ref().unwrap();
        // Every node that signed its Commit restores the lock (the lock is the record of the
        // Commit, written with every record).
        if core.high_pqc.as_ref() == Some(&lock) {
            restored += 1;
        }
    }
    assert!(
        restored >= c.v.committee.q(),
        "the Commit signers restore the lock"
    );
    c.run_until(c.now + 60_000);
    assert_eq!(
        c.committed.get(&height),
        Some(&lock.value()),
        "the locked block is committed"
    );
    assert!(c.min_height(&[0, 1, 2, 3]) > height);
}

impl Cluster {
    fn core(&self, i: usize) -> &Core {
        self.nodes[i].core.as_ref().expect("a running node")
    }

    /// Run until every node of `live` has demoted node `d` (its first leader turn failed).
    fn until_demoted(&mut self, live: &[usize], d: usize, limit: Millis) {
        let index = u32::try_from(d).unwrap();
        while !live
            .iter()
            .all(|i| self.core(*i).topo.demoted().contains(&index))
        {
            assert!(self.now < limit, "node {d} is demoted");
            self.run_until(self.now + 250);
        }
    }

    /// The topology of `height` with `demoted` (stable demotion, no other failure).
    fn topology_at(&self, height: u64, demoted: &[u32]) -> crate::topology::Topology {
        let perm = self.core(0).topo.permutation().to_vec();
        crate::topology::Topology::from_parts(perm, demoted, height).unwrap()
    }
}

/// `det_l19_late_entrant_repush` (`ML19a`, `ML19b`, `ML19c`; F34): n = 4, D crashed; C's
/// `BlockApplied(h − 1)` is delayed until 100 ms after proposal `(h + 1, 0)` reached it (C is
/// awaiting and drops it); execution takes `exec_budget`; C's last awaiting-cadence `Status`
/// reaches the leader A 10 ms before its `want_proposal` `Status` (inside A's per-peer
/// rate-limit window). With the n = 4 and the n = 22 default timings: C gets the proposal within
/// `2Δ` of entering `h + 1`, view 0 commits, and A is not in `skipped_leaders`.
#[test]
fn det_l19_late_entrant_repush() {
    for size in [4usize, 22] {
        late_entrant_repush(LocalParams::for_committee_size(size));
    }
}

#[allow(clippy::too_many_lines, clippy::many_single_char_names)] // one scripted scenario
fn late_entrant_repush(local: LocalParams) {
    use std::{cell::RefCell, rc::Rc};

    #[derive(Default)]
    struct Seen {
        /// Arrival times at C of proposals of `(T, 0)`.
        proposals: Vec<Millis>,
    }
    let d = 3usize;
    let params = ChainParams::default();
    let mut c = Cluster::with(4, local, params, false);
    c.exec_delay = crate::pacemaker::Pacemaker::new(&local, local.t_max).exec_budget(params.e_max);
    c.crash(d);
    let live = [0usize, 1, 2];
    c.until_demoted(&live, d, 300_000);
    let h0 = live.iter().map(|i| c.core(*i).height).min().unwrap();
    let target = h0 + 4;
    let topo = c.topology_at(target, &[3]);
    let a = usize::try_from(topo.leader(0)).unwrap();
    let cn = *live.iter().find(|i| **i != a).unwrap();
    let seen = Rc::new(RefCell::new(Seen::default()));
    let s = Rc::clone(&seen);
    c.hook = Box::new(move |now, to, event| {
        if to != cn {
            return false;
        }
        match event {
            // C's apply from T − 2 on is held (released in order by the test).
            Event::BlockApplied { height, .. } => *height + 2 >= target,
            Event::Message {
                msg: WireMessage::Proposal(p),
                ..
            } if p.proposal.height == target && p.proposal.view == 0 => {
                s.borrow_mut().proposals.push(now);
                false
            }
            _ => false,
        }
    });
    while seen.borrow().proposals.is_empty() {
        assert!(c.now < 600_000, "proposal ({target}, 0) reaches C");
        c.run_until(c.now + 1);
    }
    let reached = seen.borrow().proposals[0];
    {
        let core = c.core(cn);
        assert!(core.awaiting, "C awaits the configuration of {target}");
        assert_eq!(core.tip.height, target - 1);
    }
    // C's awaiting-cadence Status reaches A inside A's rate-limit window …
    let status = c.core(cn).status_message();
    assert!(!status.want_proposal, "no request while awaiting");
    let c_key = c.nodes[cn].key.clone();
    c.inject(
        reached + 100,
        a,
        Event::Message {
            from: c_key,
            msg: WireMessage::Status(Box::new(status)),
        },
    );
    // … and 100 ms after the proposal reached it, C's apply completes (in height order).
    let mut held: Vec<Event> = c
        .held
        .drain(..)
        .filter(|(to, _)| *to == cn)
        .map(|(_, e)| e)
        .collect();
    held.sort_by_key(|e| match e {
        Event::BlockApplied { height, .. } => *height,
        _ => 0,
    });
    c.hook = {
        let s = Rc::clone(&seen);
        Box::new(move |now, to, event| {
            if let Event::Message {
                msg: WireMessage::Proposal(p),
                ..
            } = event
                && to == cn
                && p.proposal.height == target
                && p.proposal.view == 0
            {
                s.borrow_mut().proposals.push(now);
            }
            false
        })
    };
    let entered = reached + 100;
    for (k, event) in held.into_iter().enumerate() {
        c.inject(entered + u64::try_from(k).unwrap(), cn, event);
    }
    c.run_until(entered + 2 * c.latency + 5);
    assert_eq!(c.core(cn).height, target, "C entered {target} late");
    let repushed = seen
        .borrow()
        .proposals
        .iter()
        .copied()
        .find(|t| *t > entered);
    assert!(
        repushed.is_some_and(|t| t <= entered + 1 + 2 * c.latency),
        "C gets the proposal within 2Δ of entering: {repushed:?} (entered {entered})"
    );
    c.run_until(c.now + 30_000);
    assert_eq!(
        c.commit_views.get(&target),
        Some(&0),
        "view 0 of {target} commits"
    );
    let block = c.blocks.get(&target).expect("committed");
    assert!(
        !block.header().skipped_leaders.contains(&c.nodes[a].key),
        "A is not skipped"
    );
}

/// Idle replicas retain their height through view changes, then commit real work.
#[test]
fn det_l21_idle_work_wakes_without_heartbeat() {
    for crashed in [false, true] {
        let mut c = Cluster::with(4, LocalParams::default(), ChainParams::default(), true);
        let live = if crashed {
            vec![0, 1, 2]
        } else {
            vec![0, 1, 2, 3]
        };
        if crashed {
            c.crash(3);
        }
        c.run_until(30_000);
        assert_eq!(c.min_height(&live), 0);
        assert!(
            c.committed.is_empty(),
            "idle view changes never create blocks"
        );
        c.idle = false;
        for i in &live {
            let req = match c.core(*i).build {
                super::super::Build::IdleWait { req, .. }
                | super::super::Build::Requested { req, .. } => Some(req),
                _ => None,
            };
            if let Some(req) = req {
                c.inject(c.now + 1, *i, Event::PayloadReady { req });
            }
        }
        c.run_until(c.now + 120_000);
        assert!(
            c.min_height(&live) >= 3,
            "pending work progresses after idle view changes"
        );
        assert!(
            c.blocks
                .values()
                .all(|block| !block.payload().as_slice().is_empty())
        );
    }
}

/// `det_l24_lost_proposal_copy` (ML24; F9): n = 4, `order_{h,0} = [A, C, B, D]` (A leads,
/// B = P, C in set A), D crashed, hint off; A's proposal copy to C is dropped once; C sends no
/// idle keepalive `Status` during view 0 → C receives A's and B's stage-2 Prepare broadcast,
/// asks A with `Status{want_proposal}`, gets an immediate reply and Prepares; view 0 commits.
/// The independent interval re-push may also run while availability rows are in flight.
#[test]
#[allow(clippy::many_single_char_names)] // replicas named as in the spec
fn det_l24_lost_proposal_copy() {
    use std::{cell::RefCell, rc::Rc};

    #[derive(Default)]
    struct Seen {
        dropped: bool,
        requests: usize,
        repushes: usize,
        request_received: Option<Millis>,
        proposal_received: Option<Millis>,
        c_prepared: bool,
    }
    let local = LocalParams {
        status_keepalive: 120_000,
        ..LocalParams::default()
    };
    let mut c = Cluster::with(4, local, ChainParams::default(), false);
    c.crash(3);
    let live = [0usize, 1, 2];
    c.until_demoted(&live, 3, 300_000);
    let h0 = live.iter().map(|i| c.core(*i).height).min().unwrap();
    let target = h0 + 2;
    let order = c.topology_at(target, &[3]).round(0).order().to_vec();
    let [a, cn, b, d] = order[..] else {
        panic!("n = 4");
    };
    let (a, cn, b) = (
        usize::try_from(a).unwrap(),
        usize::try_from(cn).unwrap(),
        usize::try_from(b).unwrap(),
    );
    assert_eq!(d, 3, "the crashed member is the demoted tail (set B)");
    let _ = b;
    let seen = Rc::new(RefCell::new(Seen::default()));
    let s = Rc::clone(&seen);
    c.filter = Box::new(move |from, to, msg| {
        let mut seen = s.borrow_mut();
        match msg {
            WireMessage::Proposal(p)
                if p.proposal.height == target && p.proposal.view == 0 && from == a && to == cn =>
            {
                if !seen.dropped {
                    seen.dropped = true;
                    return true;
                }
                seen.repushes += 1;
            }
            WireMessage::Status(st)
                if from == cn && to == a && st.want_proposal && st.height == target =>
            {
                seen.requests += 1;
            }
            WireMessage::Vote(v)
                if from == cn
                    && v.height == target
                    && v.view == 0
                    && v.kind == VoteKind::Prepare =>
            {
                seen.c_prepared = true;
            }
            _ => {}
        }
        false
    });
    let s = Rc::clone(&seen);
    let requester = c.nodes[cn].key.clone();
    c.hook = Box::new(move |now, to, event| {
        if let Event::Message { from, msg } = event {
            let mut seen = s.borrow_mut();
            match msg {
                WireMessage::Status(st)
                    if to == a && *from == requester && st.want_proposal && st.height == target =>
                {
                    seen.request_received.get_or_insert(now);
                }
                WireMessage::Proposal(p)
                    if to == cn && p.proposal.height == target && p.proposal.view == 0 =>
                {
                    seen.proposal_received.get_or_insert(now);
                }
                _ => {}
            }
        }
        false
    });
    c.run_until(c.now + 60_000);
    let seen = seen.borrow();
    assert!(seen.dropped, "A's copy to C was dropped");
    assert!(seen.requests >= 1, "C asked A for the proposal");
    assert!(
        (1..=2).contains(&seen.repushes),
        "at most one immediate and one independent interval re-push: {}",
        seen.repushes
    );
    let request_time = seen.request_received.expect("A received C's request");
    let received = seen.proposal_received.expect("C received the proposal");
    assert_eq!(received, request_time + c.latency, "A replies immediately");
    assert!(seen.c_prepared, "C Prepared at ({target}, 0)");
    assert_eq!(c.commit_views.get(&target), Some(&0), "view 0 commits");
}
