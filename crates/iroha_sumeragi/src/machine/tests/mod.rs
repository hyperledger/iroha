//! Deterministic tests of the state machine (spec §13.4): one core driven by scripted inputs,
//! with the test playing the other validators through harness-held keys, plus a tiny
//! multi-core loop (`cluster`) and a fuzz test.
#![allow(dead_code)] // shared harness helpers; not every helper is used by every test file

mod build_and_roles;
mod cluster;
mod control;
mod epochs;
mod fuzz;
mod handlers;
mod liveness;
mod regressions;
mod review;
mod revision4;
mod safety;

use std::collections::{BTreeMap, VecDeque};

use super::Core;
use crate::{
    api::{Action, CommittedTip, Event, ExecOutcome, HaltReason, Init, LocalFault, LocalParams},
    availability::{AvailableBody, PayloadAcquisition, PayloadAuthoring, PayloadBytes, RowBytes},
    crypto::{Crypto, Signer},
    message::{
        BlockHeader, Evidence, PayloadChunk, PayloadManifest, Proposal, ProposalMessage, Qc,
        TcEntry, TimeoutCert, TimeoutVote, Vote, VoteKind, WireMessage,
    },
    preimage,
    safety::{RecordState, SafetyRecord},
    testing::{FakeSigner, FakeValidators, SignLog, sha256},
    topology::{Round, Topology},
    types::{
        Bitmap, ChainParams, Committee, Hash32, HeightConfig, Millis, PublicKey, Signature,
        ValidatorIndex,
    },
};

/// Instance id of the tests.
pub(super) const I: Hash32 = Hash32([0x11; 32]);
/// Demotion window `W` of the tests (the §9.3 default).
pub(super) const W: u64 = 128;
/// Genesis block hash and result.
pub(super) const G_HASH: Hash32 = Hash32([0xaa; 32]);
pub(super) const G_RESULT: Hash32 = Hash32([0xbb; 32]);

/// The deterministic execution result of the tests: `R = H(parent_R ‖ payload)`.
pub(super) fn manifest(body: &AvailableBody) -> PayloadManifest {
    PayloadManifest {
        header: body.header().clone(),
        availability: body.availability().clone(),
    }
}

pub(super) fn result_of(block: &AvailableBody) -> Hash32 {
    let mut input = block.header().parent_result.0.to_vec();
    input.extend_from_slice(block.payload().as_slice());
    Hash32(sha256(&input))
}

/// A scripted driver around one core. Actions are absorbed like a driver would: records and
/// bodies become durable at once (unless held), `CommitBlock` is applied, local fetches are
/// served from the body store. Execution and payload building are answered by the test.
#[allow(clippy::struct_excessive_bools, reason = "independent test switches")]
pub(super) struct H {
    pub v: FakeValidators,
    pub log: SignLog,
    pub me: ValidatorIndex,
    pub core: Core,
    pub now: Millis,
    pub budget: iroha_allocation::AllocationBudget,
    pub remote_bodies: std::cell::RefCell<BTreeMap<Hash32, AvailableBody>>,
    pub withheld_rows: std::collections::BTreeSet<Hash32>,
    acquisitions: BTreeMap<Hash32, PayloadAcquisition>,
    pub local: LocalParams,
    pub params: ChainParams,
    /// The core's configured signers (default: the harness key of `me`).
    pub signers: Vec<FakeSigner>,
    /// Committee overrides by height (default: the harness committee).
    pub committees: BTreeMap<u64, Committee>,
    /// Durable block store: committed `(block, CommitQC)` in height order.
    pub store: Vec<(AvailableBody, Qc)>,
    /// Durable body store.
    pub bodies: BTreeMap<Hash32, AvailableBody>,
    /// Durable safety records per key.
    pub records: BTreeMap<PublicKey, Vec<u8>>,
    /// Outstanding `Execute` requests.
    pub pending_exec: Vec<(Hash32, u64, AvailableBody)>,
    /// The `certified` flag of every `Execute` since the core was created, by request id
    /// (§4.5 "Certified re-proposals").
    pub exec_certified: BTreeMap<u64, bool>,
    /// Actions of the most recent `fire`.
    pub out: Vec<Action>,
    /// Every action since the core was (re)started.
    pub all: Vec<Action>,
    pub auto_apply: bool,
    pub auto_fetch: bool,
    /// Answer `Execute` at once with `Valid(result_of(block))`.
    pub auto_exec: bool,
    pub auto_control: bool,
    /// Keys passed as retired (restored like the others, never signing; no signer).
    pub retired: Vec<PublicKey>,
    /// `Init.nonce` of the latest start.
    pub nonce: u64,
    /// Request id of the latest `BuildPayload`.
    pub last_build: Option<u64>,
    /// `Init.demotion_window` (default [`W`]).
    pub w: u64,
}

impl H {
    /// `n` validators; `pick` chooses the core's index from the topology of height 1.
    pub fn new(n: usize, pick: impl Fn(&Topology) -> ValidatorIndex) -> Self {
        Self::with(n, LocalParams::default(), ChainParams::default(), pick)
    }

    pub fn with(
        n: usize,
        local: LocalParams,
        params: ChainParams,
        pick: impl Fn(&Topology) -> ValidatorIndex,
    ) -> Self {
        let log = SignLog::new();
        let v = FakeValidators::new(n, 7, Some(log.clone()));
        let topo = Topology::compute(
            &v.crypto,
            &I,
            &crate::testing::TEST_EPOCH,
            &v.committee,
            1,
            0,
            W,
            &[],
        );
        let me = pick(&topo);
        let signers = vec![v.signer(me).clone()];
        let core = placeholder_core(&v, &local, &params, &signers);
        let mut h = Self {
            v,
            log,
            me,
            core,
            now: 0,
            budget: iroha_allocation::AllocationBudget::new(1 << 30),
            remote_bodies: std::cell::RefCell::new(BTreeMap::new()),
            withheld_rows: std::collections::BTreeSet::new(),
            acquisitions: BTreeMap::new(),
            local,
            params,
            signers,
            committees: BTreeMap::new(),
            store: Vec::new(),
            bodies: BTreeMap::new(),
            records: BTreeMap::new(),
            pending_exec: Vec::new(),
            exec_certified: BTreeMap::new(),
            out: Vec::new(),
            all: Vec::new(),
            auto_apply: true,
            auto_fetch: true,
            auto_exec: false,
            auto_control: true,
            retired: Vec::new(),
            nonce: 0,
            last_build: None,
            w: W,
        };
        h.install_keys();
        h.restart();
        h
    }

    /// The installation event of every configured key at genesis (§7.4 record provenance):
    /// the initial record `{I, K, height: g}`.
    pub fn install_keys(&mut self) {
        for signer in self.signers.clone() {
            let key = signer.public_key().clone();
            self.records
                .insert(key.clone(), initial_record(&self.v, &key));
        }
    }

    pub fn config(&self, height: u64) -> HeightConfig {
        let mut starts = vec![0];
        starts.extend(self.committees.keys().copied().filter(|h| *h != 0));
        let index = starts.iter().rposition(|start| *start <= height).unwrap();
        let last = starts.get(index + 1).map_or(u64::MAX, |start| start - 1);
        HeightConfig {
            epoch: Box::new(crate::testing::scheduled_epoch(
                index as u64,
                starts[index],
                last,
            )),
            committee: self
                .committees
                .range(..=height)
                .next_back()
                .map_or_else(|| self.v.committee.clone(), |(_, c)| c.clone()),
            params: self.params,
        }
    }

    /// The `Init` a restarting driver would build from the durable stores.
    pub fn init(&self, records: Vec<(PublicKey, RecordState, bool)>) -> Init {
        let tip = match self.store.last() {
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
        let active = self.config(t + 1);
        let mut configs = vec![
            (t + 1, crate::types::ConfigSlot::Ready(active.clone())),
            (
                t + 2,
                crate::testing::window_slot(&active, t + 2, self.config(t + 2)),
            ),
        ];
        if t > 0 {
            configs.push((t, crate::types::ConfigSlot::Ready(self.config(t))));
        }
        Init {
            instance: I,
            records,
            genesis_height: 0,
            demotion_window: self.w,
            nonce: self.nonce,
            tip,
            configs,
            recent_headers: self.store.iter().map(|(b, _)| b.header().clone()).collect(),
        }
    }

    /// (Re)start the core from the durable stores with the given record states of the
    /// configured signers (and `Absent`-or-durable states for the retired keys).
    pub fn start(&mut self, records: Vec<(PublicKey, RecordState)>) -> Vec<Action> {
        self.nonce = self.nonce.wrapping_add(0x9e37_79b9);
        let mut records: Vec<(PublicKey, RecordState, bool)> = records
            .into_iter()
            .map(|(key, state)| (key, state, false))
            .collect();
        for key in &self.retired {
            let state = self.records.get(key).map_or(RecordState::Absent, |bytes| {
                RecordState::Present(bytes.clone())
            });
            records.push((key.clone(), state, true));
        }
        let init = self.init(records);
        let signers: Vec<std::sync::Arc<dyn Signer>> = self
            .signers
            .iter()
            .map(|s| -> std::sync::Arc<dyn Signer> { std::sync::Arc::new(s.clone()) })
            .collect();
        let (core, actions) = Core::new(
            self.local,
            init,
            signers,
            Box::new(self.v.crypto.clone()),
            self.budget.clone(),
            self.now,
        )
        .expect("valid test configuration");
        self.core = core;
        self.pending_exec.clear();
        self.acquisitions.clear();
        self.all.clear();
        self.out.clear();
        self.absorb(actions);
        self.out.clone()
    }

    /// Crash and restart with the durable records (`Present`, or `Absent` if none exists).
    pub fn restart(&mut self) -> Vec<Action> {
        let states = self
            .signers
            .iter()
            .map(|s| {
                let key = s.public_key().clone();
                let state = self.records.get(&key).map_or(RecordState::Absent, |bytes| {
                    RecordState::Present(bytes.clone())
                });
                (key, state)
            })
            .collect();
        self.start(states)
    }

    /// Handle one event at the current time, absorbing the actions like a driver.
    pub fn fire(&mut self, mut event: Event) -> Vec<Action> {
        self.out.clear();
        if let Event::Message { msg, .. } = &mut event {
            let Ok(bytes) = msg.encode() else {
                return Vec::new();
            };
            let Ok(decoded) = WireMessage::decode(&bytes, 32 << 20) else {
                return Vec::new();
            };
            *msg = decoded;
            if msg.admit_owned_bytes(&self.budget).is_err() {
                return Vec::new();
            }
        }
        let actions = self.core.handle(self.now, event);
        self.absorb(actions);
        self.out.clone()
    }

    fn absorb(&mut self, actions: Vec<Action>) {
        let mut queue: VecDeque<Event> = VecDeque::new();
        let mut batch = actions;
        loop {
            for action in &batch {
                match action {
                    Action::PersistSafety(record) => {
                        let bytes = record.encode(&self.v.crypto).expect("encode record");
                        // MS33a (fake driver record store): one file per instance for all keys.
                        #[cfg(sumeragi_mutation = "MS33a")]
                        for file in self.records.values_mut() {
                            file.clone_from(&bytes);
                        }
                        self.records.insert(record.key.clone(), bytes);
                    }
                    Action::StoreBody { block } => {
                        self.bodies
                            .insert(block.hash(&self.v.crypto), block.clone());
                    }
                    Action::Execute {
                        block,
                        req,
                        certified,
                    } => {
                        let bh = block.hash(&self.v.crypto);
                        self.exec_certified.insert(*req, *certified);
                        if self.auto_exec {
                            queue.push_back(Event::Executed {
                                block_hash: bh,
                                req: *req,
                                outcome: ExecOutcome::Valid(result_of(block)),
                            });
                        } else {
                            self.pending_exec.push((bh, *req, block.clone()));
                        }
                    }
                    Action::BuildControlWitness { req, context } if self.auto_control => {
                        queue.push_back(Event::ControlWitnessBuilt {
                            req: *req,
                            context: *context,
                            witness: crate::types::ControlWitness::empty(),
                        });
                    }
                    Action::BuildPayload { req, .. } => self.last_build = Some(*req),
                    Action::CommitBlock { block, commit_qc } => {
                        self.store.push((block.clone(), commit_qc.clone()));
                        if self.auto_apply {
                            queue.push_back(self.applied_event(block));
                        }
                    }
                    Action::FetchPayload { source, .. } => {
                        if self.auto_fetch
                            && let Some(block) = self.bodies.get(&source.block_hash())
                        {
                            let frame = crate::availability::AvailabilityFrame::from_untrusted(
                                block.availability().as_slice().to_vec(),
                            )
                            .unwrap();
                            let payload =
                                PayloadBytes::from_untrusted(block.payload().as_slice().to_vec())
                                    .unwrap();
                            let job = crate::availability::BodyRestoration::new(
                                source.clone(),
                                block.header().clone(),
                                frame,
                                payload,
                            );
                            let block = job
                                .complete(&self.budget, &self.v.crypto)
                                .unwrap_or_else(|(_, e)| panic!("restore fixture: {e:?}"));
                            queue.push_back(Event::BodyAvailable { block });
                        }
                    }
                    Action::AuthorPayload {
                        req,
                        config,
                        header,
                        payload,
                    } => {
                        let signer = self.signer_of(config.committee.get(header.proposer).unwrap());
                        let body = PayloadAuthoring::new(header.clone(), payload.clone())
                            .complete(I, config, &self.budget, &self.v.crypto, &signer)
                            .unwrap_or_else(|(_, e)| panic!("author fixture: {e:?}"))
                            .body;
                        queue.push_back(Event::PayloadAuthored { req: *req, body });
                    }
                    Action::AcquirePayload { source, manifest } => {
                        if self.acquisitions.contains_key(&source.block_hash()) {
                            continue;
                        }
                        let mut job = PayloadAcquisition::new(source.clone(), manifest.clone());
                        if let Err(error) = job.prepare(&self.budget, &self.v.crypto) {
                            assert!(error.rejects_manifest());
                            queue.push_back(Event::ManifestRejected {
                                manifest: manifest.clone(),
                            });
                            continue;
                        }
                        let bh = source.block_hash();
                        self.acquisitions.entry(bh).or_insert(job);
                        if !self.withheld_rows.contains(&bh)
                            && let Some(body) = self.remote_bodies.borrow().get(&bh)
                        {
                            for chunk in self.chunks(body) {
                                queue.push_back(Event::Message {
                                    from: self.key_at(body.header().proposer),
                                    msg: WireMessage::PayloadChunk(chunk),
                                });
                            }
                        }
                    }
                    Action::ReceivePayloadChunk { chunk, .. } => {
                        let bh = chunk.block_hash;
                        if let Some(mut job) = self.acquisitions.remove(&bh) {
                            let _ = job.push(chunk.clone(), &self.budget, &self.v.crypto);
                            match job.complete(&self.budget, &self.v.crypto) {
                                Ok(block) => queue.push_back(Event::BodyAvailable { block }),
                                Err((job, crate::availability::AcquisitionError::Incomplete)) => {
                                    self.acquisitions.insert(bh, job);
                                }
                                Err((job, e)) if e.rejects_manifest() => {
                                    queue.push_back(Event::ManifestRejected {
                                        manifest: job.manifest().clone(),
                                    })
                                }
                                Err((_, e)) => panic!("fixture reconstruction: {e:?}"),
                            }
                        }
                    }
                    _ => {}
                }
            }
            self.out.extend(batch.iter().cloned());
            self.all.extend(batch);
            let Some(event) = queue.pop_front() else {
                return;
            };
            batch = self.core.handle(self.now, event);
        }
    }

    /// The `BlockApplied` a conforming driver reports for a committed `block` (O3).
    pub fn applied_event(&self, block: &AvailableBody) -> Event {
        let height = block.header().height;
        Event::BlockApplied {
            height,
            block_hash: block.hash(&self.v.crypto),
            header: Box::new(block.header().clone()),
            config: crate::testing::applied_config(
                height,
                &self.config(height),
                self.config(height + 1),
                self.config(height + 2),
            ),
        }
    }

    /// Apply the block store entry of `height` (when `auto_apply` is off).
    pub fn apply_height(&mut self, height: u64) -> Vec<Action> {
        let block = self
            .store
            .iter()
            .find(|(b, _)| b.header().height == height)
            .map(|(b, _)| b.clone())
            .expect("the block of the height is in the store");
        let event = self.applied_event(&block);
        self.fire(event)
    }

    /// Actual canonical rows of a fixture body; the original authorization table is retained.
    fn chunks(&self, body: &AvailableBody) -> Vec<PayloadChunk> {
        let shape = self
            .config(body.header().height)
            .epoch
            .da_layout
            .shape(body.payload().as_slice().len() as u64)
            .unwrap();
        let encoded = iroha_primitives::erasure::rs16::compact::encode_funded(
            shape,
            body.payload().as_slice(),
            &self.budget,
        )
        .unwrap();
        (0..shape.chunk_count())
            .map(|index| {
                let mut chunk = PayloadChunk {
                    instance: I,
                    height: body.header().height,
                    block_hash: self.bh(body),
                    index: u32::try_from(index).unwrap(),
                    bytes: RowBytes::from_untrusted(
                        encoded.codeword()[shape.chunk_range(index).unwrap()].to_vec(),
                    )
                    .unwrap(),
                };
                chunk.bytes.admit(&self.budget).unwrap();
                chunk
            })
            .collect()
    }

    /// Deliver actually received rows separately from the authenticated manifest.
    fn deliver_rows(&mut self, from: ValidatorIndex, body: &AvailableBody) -> Vec<Action> {
        self.withheld_rows.remove(&self.bh(body));
        let mut actions = Vec::new();
        for chunk in self.chunks(body) {
            actions.extend(self.deliver(from, WireMessage::PayloadChunk(chunk)));
        }
        actions
    }

    /// A message from member `from` of the current committee.
    pub fn deliver(&mut self, from: ValidatorIndex, msg: WireMessage) -> Vec<Action> {
        let from = self.key_at(from);
        self.fire(Event::Message { from, msg })
    }

    /// A message from the holder of `from`.
    pub fn deliver_key(&mut self, from: PublicKey, msg: WireMessage) -> Vec<Action> {
        self.fire(Event::Message { from, msg })
    }

    /// Advance the clock by `dt` and deliver a `Tick` if a deadline is due.
    pub fn tick(&mut self, dt: Millis) -> Vec<Action> {
        self.now += dt;
        self.fire(Event::Tick)
    }

    /// Deliver `Tick`s at every wakeup up to `until` (inclusive); returns all their actions.
    pub fn run_until(&mut self, until: Millis) -> Vec<Action> {
        let mut all = Vec::new();
        for _ in 0..10_000 {
            let wake = self.core.next_wakeup();
            if wake > until {
                break;
            }
            self.now = self.now.max(wake);
            all.extend(self.fire(Event::Tick));
        }
        self.now = self.now.max(until);
        all
    }

    fn payload(&self, payload: &[u8]) -> Option<PayloadBytes> {
        if payload.is_empty() {
            return None;
        }
        let mut bytes = PayloadBytes::from_untrusted(payload.to_vec()).unwrap();
        bytes.admit(&self.budget).unwrap();
        Some(bytes)
    }

    /// Answer the latest `BuildPayload` with `payload`.
    pub fn built(&mut self, payload: &[u8]) -> Vec<Action> {
        let req = self.last_build.expect("a BuildPayload was requested");
        self.fire(Event::PayloadBuilt {
            req,
            payload: self.payload(payload),
        })
    }

    /// `PayloadReady` for the latest `BuildPayload`.
    pub fn payload_ready(&mut self) -> Vec<Action> {
        let req = self.last_build.expect("a BuildPayload was requested");
        self.fire(Event::PayloadReady { req })
    }

    /// Answer every outstanding `Execute` with `Valid(result_of(block))`.
    pub fn exec_all(&mut self) -> Vec<Action> {
        let pending = std::mem::take(&mut self.pending_exec);
        let mut all = Vec::new();
        for (bh, req, block) in pending {
            all.extend(self.fire(Event::Executed {
                block_hash: bh,
                req,
                outcome: ExecOutcome::Valid(result_of(&block)),
            }));
        }
        all
    }

    /// Answer the outstanding `Execute` of `bh` with `outcome`.
    pub fn exec(&mut self, bh: Hash32, outcome: ExecOutcome) -> Vec<Action> {
        let position = self
            .pending_exec
            .iter()
            .position(|(b, _, _)| *b == bh)
            .expect("an outstanding Execute for the block");
        let (bh, req, _) = self.pending_exec.remove(position);
        self.fire(Event::Executed {
            block_hash: bh,
            req,
            outcome,
        })
    }

    // ---- topology and roles ------------------------------------------------------------

    pub fn height(&self) -> u64 {
        self.core.height
    }

    /// `C_h` of the current height.
    pub fn committee(&self) -> Committee {
        self.config(self.height()).committee
    }

    /// `C_h` of `height`.
    pub fn committee_at(&self, height: u64) -> Committee {
        self.config(height).committee
    }

    pub fn key_at(&self, index: ValidatorIndex) -> PublicKey {
        self.committee().get(index).cloned().expect("member index")
    }

    /// The harness signer holding `key`.
    pub fn signer_of(&self, key: &PublicKey) -> FakeSigner {
        self.v
            .signers()
            .iter()
            .chain(self.signers.iter())
            .find(|s| s.public_key() == key)
            .cloned()
            .expect("a harness key")
    }

    fn sign_as(&self, index: ValidatorIndex, msg: &[u8]) -> Signature {
        self.signer_of(&self.key_at(index)).sign(msg)
    }

    /// The core's index in the current committee.
    pub fn my_idx(&self) -> ValidatorIndex {
        self.committee()
            .index_of(self.signers[0].public_key())
            .expect("the core is a member")
    }

    pub fn round(&self, view: u64) -> Round {
        self.core.topo.round(view)
    }

    pub fn leader(&self, view: u64) -> ValidatorIndex {
        self.core.topo.leader(view)
    }

    pub fn proxy_tail(&self, view: u64) -> ValidatorIndex {
        self.round(view).proxy_tail()
    }

    /// `k` members other than the core's keys (and other than `except`), canonical order.
    pub fn others(&self, k: usize, except: &[ValidatorIndex]) -> Vec<ValidatorIndex> {
        let committee = self.committee();
        let mine: Vec<ValidatorIndex> = self
            .signers
            .iter()
            .filter_map(|s| committee.index_of(s.public_key()))
            .collect();
        (0..u32::try_from(committee.n()).unwrap())
            .filter(|i| !mine.contains(i) && !except.contains(i))
            .take(k)
            .collect()
    }

    pub fn q(&self) -> usize {
        self.committee().q()
    }

    pub fn f(&self) -> usize {
        self.committee().f()
    }

    // ---- message construction -----------------------------------------------------------

    /// A fresh block of the current height first proposed in `view` by `L(h, view)`.
    pub fn block(&self, view: u64, payload: &[u8]) -> AvailableBody {
        let topo = &self.core.topo;
        let header = BlockHeader {
            control_witness: crate::types::ControlWitness::empty(),
            epoch: self.config(self.height()).epoch.id,
            instance: I,
            height: self.height(),
            origin_view: view,
            parent_hash: self.core.tip.block_hash,
            parent_result: self.core.tip.result,
            payload_hash: preimage::payload_hash(&self.v.crypto, payload),
            availability_digest: crate::types::Hash32::ZERO,
            payload_len: u32::try_from(payload.len()).unwrap(),
            proposer: topo.leader(view),
            skipped_leaders: topo.skipped_leader_keys(&self.committee(), view),
        };
        self.author(header, payload)
    }

    /// Author exact fixture bytes with the current historical committee, using the actual worker.
    pub fn author(&self, header: BlockHeader, payload: &[u8]) -> AvailableBody {
        let config = self.config(header.height);
        // These are externally supplied fixture bodies, not actions by the local Core.
        // The actual AuthorPayload worker above retains the local signing log unchanged.
        let signer =
            FakeSigner::with_key(config.committee.get(header.proposer).unwrap().clone(), None);
        let body = crate::testing::author_body(
            header,
            payload,
            &config,
            &self.budget,
            &self.v.crypto,
            &signer,
        );
        self.remote_bodies
            .borrow_mut()
            .insert(body.hash(&self.v.crypto), body.clone());
        body
    }

    pub fn bh(&self, block: &AvailableBody) -> Hash32 {
        block.hash(&self.v.crypto)
    }

    /// The proposal of `block` in `(h, view)` signed by `L(h, view)` with the tip's `CommitQC`.
    pub fn proposal(
        &self,
        view: u64,
        block: &AvailableBody,
        justify: Option<TimeoutCert>,
    ) -> ProposalMessage {
        self.proposal_by(self.leader(view), view, block, justify)
    }

    pub fn proposal_by(
        &self,
        signer: ValidatorIndex,
        view: u64,
        block: &AvailableBody,
        justify: Option<TimeoutCert>,
    ) -> ProposalMessage {
        let parent_qc = self.core.tip.commit_qc.clone();
        let bh = self.bh(block);
        let ad = preimage::att_digest(&self.v.crypto, justify.as_ref(), parent_qc.as_ref());
        let msg = preimage::prop_preimage(
            &I,
            &self.config(self.height()).epoch.id,
            self.height(),
            view,
            &bh,
            &ad,
        );
        ProposalMessage {
            availability: block.availability().clone(),
            proposal: Proposal {
                instance: I,
                height: self.height(),
                view,
                header: block.header().clone(),
                justify,
                parent_qc,
                sig: self.sign_as(signer, &msg),
            },
        }
    }

    /// A certificate of a block/result pair by the supplied current-committee signers.
    /// Deliberately permits nonquorum signer counts for rejection tests.
    pub fn qc_value(
        &self,
        kind: VoteKind,
        view: u64,
        value: (Hash32, Hash32),
        signers: &[ValidatorIndex],
    ) -> Qc {
        let msg = preimage::vote_preimage(
            kind,
            &I,
            &self.config(self.height()).epoch.id,
            self.height(),
            view,
            &value.0,
            &value.1,
        );

        let mut sorted = signers.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let sigs: Vec<Signature> = sorted.iter().map(|i| self.sign_as(*i, &msg)).collect();
        Qc {
            epoch: self.config(self.height()).epoch.id,
            kind,
            instance: I,
            height: self.height(),
            view,
            block_hash: value.0,
            result: value.1,
            signers: Bitmap::from_indices(self.committee().n(), sorted.iter().copied()).unwrap(),
            agg_sig: self.v.crypto.aggregate(&sigs),
        }
    }

    /// A certificate of `block` and its execution result by the supplied signers.
    pub fn qc(
        &self,
        kind: VoteKind,
        view: u64,
        block: &AvailableBody,
        signers: &[ValidatorIndex],
    ) -> Qc {
        let value = (self.bh(block), result_of(block));
        self.qc_value(kind, view, value, signers)
    }

    /// A certificate by `q` members other than the core.
    pub fn qc_q(&self, kind: VoteKind, view: u64, block: &AvailableBody) -> Qc {
        let signers = self.others(self.q(), &[]);
        self.qc(kind, view, block, &signers)
    }

    /// A vote for a block hash and its execution result.
    pub fn vote_value(
        &self,
        kind: VoteKind,
        signer: ValidatorIndex,
        view: u64,
        value: (Hash32, Hash32),
    ) -> Vote {
        let msg = preimage::vote_preimage(
            kind,
            &I,
            &self.config(self.height()).epoch.id,
            self.height(),
            view,
            &value.0,
            &value.1,
        );

        Vote {
            epoch: self.config(self.height()).epoch.id,
            kind,
            instance: I,
            height: self.height(),
            view,
            block_hash: value.0,
            result: value.1,
            signer,
            sig: self.sign_as(signer, &msg),
        }
    }

    /// A vote for `block` (with its flag).
    pub fn vote(
        &self,
        kind: VoteKind,
        signer: ValidatorIndex,
        view: u64,
        block: &AvailableBody,
    ) -> Vote {
        let value = (self.bh(block), result_of(block));
        self.vote_value(kind, signer, view, value)
    }

    pub fn timeout(&self, signer: ValidatorIndex, view: u64, qc: Option<Qc>) -> TimeoutVote {
        let hq = qc.as_ref().map(|q| q.view);
        let msg = preimage::tmo_preimage(
            &I,
            &self.config(self.height()).epoch.id,
            self.height(),
            view,
            hq,
        );
        TimeoutVote {
            epoch: self.config(self.height()).epoch.id,
            instance: I,
            height: self.height(),
            view,
            high_pqc: qc,
            signer,
            sig: self.sign_as(signer, &msg),
        }
    }

    /// A TC from exactly `entries`; `high_pqc` = the `PrepareQC` of the maximal `hq`.
    pub fn tc(&self, view: u64, entries: &[(ValidatorIndex, Option<Qc>)]) -> TimeoutCert {
        let mut timeouts: Vec<TimeoutVote> = entries
            .iter()
            .map(|(signer, qc)| self.timeout(*signer, view, qc.clone()))
            .collect();
        timeouts.sort_by_key(|t| t.signer);
        let high_pqc = timeouts
            .iter()
            .filter(|t| t.high_pqc.is_some())
            .max_by(|a, b| a.hq().cmp(&b.hq()).then(b.signer.cmp(&a.signer)))
            .and_then(|t| t.high_pqc.clone());
        let sigs: Vec<Signature> = timeouts.iter().map(|t| t.sig).collect();
        TimeoutCert {
            epoch: self.config(self.height()).epoch.id,
            instance: I,
            height: self.height(),
            view,
            entries: timeouts
                .iter()
                .map(|t| TcEntry {
                    signer: t.signer,
                    hq: t.hq(),
                })
                .collect(),
            agg_sig: self.v.crypto.aggregate(&sigs),
            high_pqc,
        }
    }

    /// A TC for `view` by `q` members other than the core, carrying no lock.
    pub fn tc_q(&self, view: u64) -> TimeoutCert {
        let entries: Vec<_> = self
            .others(self.q(), &[])
            .into_iter()
            .map(|i| (i, None))
            .collect();
        self.tc(view, &entries)
    }

    /// Enter view `view` of the current height through a lock-free TC for `view − 1`.
    pub fn enter_view(&mut self, view: u64) {
        let tc = self.tc_q(view - 1);
        self.deliver(self.others(1, &[])[0], WireMessage::Tc(Box::new(tc)));
        assert_eq!(self.core.view, view);
    }

    /// Commit the current height with a fresh view-`view` block (the body comes from the
    /// local store) through a `CommitQC` of `q` other members. Returns the block.
    pub fn commit_with(&mut self, view: u64, payload: &[u8]) -> AvailableBody {
        let block = self.block(view, payload);
        self.bodies.insert(self.bh(&block), block.clone());
        let qc = self.qc_q(VoteKind::Commit, view, &block);
        let height = self.height();
        self.deliver(self.others(1, &[])[0], WireMessage::Qc(qc));
        assert_eq!(self.core.tip.height, height, "committed");
        block
    }

    /// Commit `k` heights at view 0.
    pub fn commit_heights(&mut self, k: u64) {
        for _ in 0..k {
            let payload = self.height().to_be_bytes();
            self.commit_with(0, &payload);
        }
    }

    /// A block of any height with an explicit parent and proposer.
    pub fn block_at(
        &self,
        height: u64,
        parent: (Hash32, Hash32),
        proposer: ValidatorIndex,
        payload: &[u8],
    ) -> AvailableBody {
        self.author(
            BlockHeader {
                control_witness: crate::types::ControlWitness::empty(),
                epoch: self.config(height).epoch.id,
                instance: I,
                height,
                origin_view: 0,
                parent_hash: parent.0,
                parent_result: parent.1,
                payload_hash: preimage::payload_hash(&self.v.crypto, payload),
                availability_digest: crate::types::Hash32::ZERO,
                payload_len: u32::try_from(payload.len()).unwrap(),
                proposer,
                skipped_leaders: Vec::new(),
            },
            payload,
        )
    }

    /// A certificate of any height signed by the holders of `keys`, with the bitmap of
    /// `committee` (keys outside it are signed but not representable and are skipped).
    pub fn qc_keys(
        &self,
        committee: &Committee,
        kind: VoteKind,
        height: u64,
        view: u64,
        value: (Hash32, Hash32),
        keys: &[PublicKey],
    ) -> Qc {
        let msg = preimage::vote_preimage(
            kind,
            &I,
            &self.config(height).epoch.id,
            height,
            view,
            &value.0,
            &value.1,
        );

        let sigs: Vec<Signature> = keys.iter().map(|k| self.signer_of(k).sign(&msg)).collect();
        let indices = keys.iter().filter_map(|k| committee.index_of(k));
        let signers = Bitmap::from_indices(committee.n(), indices).unwrap();
        Qc {
            epoch: self.config(height).epoch.id,
            kind,
            instance: I,
            height,
            view,
            block_hash: value.0,
            result: value.1,
            signers,
            agg_sig: self.v.crypto.aggregate(&sigs),
        }
    }

    /// A `CommitQC` for `block` (any height) by `q` members of its height's committee other
    /// than the core.
    pub fn cqc_for(&self, block: &AvailableBody, view: u64) -> Qc {
        let height = block.header().height;
        let committee = self.config(height).committee;
        let keys: Vec<PublicKey> = committee
            .members()
            .iter()
            .filter(|k| !self.signers.iter().any(|s| s.public_key() == *k))
            .take(committee.q())
            .cloned()
            .collect();
        let value = (self.bh(block), result_of(block));
        self.qc_keys(&committee, VoteKind::Commit, height, view, value, &keys)
    }

    /// Keys of a certificate's signers (canonical order) in the committee of its height.
    pub fn signer_keys_of(&self, qc: &Qc) -> Vec<PublicKey> {
        self.committee_at(qc.height)
            .keys_of(&qc.signers)
            .map(|keys| keys.into_iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Signatures of the core's key over preimages of `kind` at `(height, view)`.
    pub fn my_sigs(&self, kind: u8, height: u64, view: u64) -> Vec<Vec<u8>> {
        let mut prefix = preimage::TAG_SIG.to_vec();
        prefix.push(kind);
        prefix.extend_from_slice(I.as_bytes());
        let epoch = self.config(height).epoch.id;
        prefix.extend_from_slice(&epoch.epoch.to_be_bytes());
        prefix.extend_from_slice(epoch.context.as_bytes());
        prefix.extend_from_slice(&height.to_be_bytes());
        prefix.extend_from_slice(&view.to_be_bytes());
        let mut out: Vec<Vec<u8>> = self
            .signers
            .iter()
            .flat_map(|s| self.log.signatures_by(s.public_key()))
            .filter(|r| r.preimage.starts_with(&prefix))
            .map(|r| r.preimage)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// The latest durable record of the core's first key.
    pub fn durable(&self) -> Option<SafetyRecord> {
        let key = self.signers[0].public_key();
        self.records
            .get(key)
            .map(|bytes| SafetyRecord::decode(&self.v.crypto, bytes).expect("decodable"))
    }
}

/// The installation event's initial record `{I, K, height: g = 0, everything else None}`.
pub(super) fn initial_record(v: &FakeValidators, key: &PublicKey) -> Vec<u8> {
    SafetyRecord::fresh(I, crate::testing::TEST_EPOCH.id, key.clone(), 0, None)
        .encode(&v.crypto)
        .expect("encode the initial record")
}

/// A throwaway core replaced by `H::start` (the harness needs a value before starting).
fn placeholder_core(
    v: &FakeValidators,
    local: &LocalParams,
    params: &ChainParams,
    signers: &[FakeSigner],
) -> Core {
    let config = HeightConfig {
        epoch: Box::new(crate::testing::TEST_EPOCH),
        committee: v.committee.clone(),
        params: *params,
    };
    let init = Init {
        instance: I,
        records: signers
            .iter()
            .map(|s| {
                let key = s.public_key().clone();
                let state = RecordState::Present(initial_record(v, &key));
                (key, state, false)
            })
            .collect(),
        genesis_height: 0,
        demotion_window: W,
        nonce: 0,
        tip: CommittedTip {
            height: 0,
            block_hash: G_HASH,
            result: G_RESULT,
            header: None,
            commit_qc: None,
        },
        configs: vec![
            (1, crate::types::ConfigSlot::Ready(config.clone())),
            (2, crate::types::ConfigSlot::Ready(config)),
        ],
        recent_headers: Vec::new(),
    };
    let boxed: Vec<std::sync::Arc<dyn Signer>> = signers
        .iter()
        .map(|s| -> std::sync::Arc<dyn Signer> { std::sync::Arc::new(s.clone()) })
        .collect();
    Core::new(
        *local,
        init,
        boxed,
        Box::new(v.crypto.clone()),
        iroha_allocation::AllocationBudget::new(1 << 30),
        0,
    )
    .expect("valid test configuration")
    .0
}

// ---- action inspection ---------------------------------------------------------------------

/// Every sent or broadcast message with its recipients.
pub(super) fn sent(actions: &[Action]) -> Vec<(Vec<PublicKey>, WireMessage)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send { to, msg } => Some((vec![to.clone()], msg.clone())),
            Action::Broadcast { to, msg } => Some((to.clone(), msg.clone())),
            _ => None,
        })
        .collect()
}

pub(super) fn votes(actions: &[Action]) -> Vec<Vote> {
    sent(actions)
        .into_iter()
        .filter_map(|(_, m)| match m {
            WireMessage::Vote(v) => Some(v),
            _ => None,
        })
        .collect()
}

pub(super) fn votes_of(actions: &[Action], kind: VoteKind) -> Vec<Vote> {
    votes(actions)
        .into_iter()
        .filter(|v| v.kind == kind)
        .collect()
}

pub(super) fn timeouts(actions: &[Action]) -> Vec<TimeoutVote> {
    sent(actions)
        .into_iter()
        .filter_map(|(_, m)| match m {
            WireMessage::Timeout(t) => Some(*t),
            _ => None,
        })
        .collect()
}

pub(super) fn proposals(actions: &[Action]) -> Vec<Proposal> {
    sent(actions)
        .into_iter()
        .filter_map(|(_, m)| match m {
            WireMessage::Proposal(p) => Some(p.proposal),
            _ => None,
        })
        .collect()
}

pub(super) fn qcs(actions: &[Action]) -> Vec<Qc> {
    sent(actions)
        .into_iter()
        .filter_map(|(_, m)| match m {
            WireMessage::Qc(q) => Some(q),
            _ => None,
        })
        .collect()
}

pub(super) fn tcs(actions: &[Action]) -> Vec<TimeoutCert> {
    sent(actions)
        .into_iter()
        .filter_map(|(_, m)| match m {
            WireMessage::Tc(t) => Some(*t),
            WireMessage::Proposal(p) => p.proposal.justify,
            _ => None,
        })
        .collect()
}

pub(super) fn records(actions: &[Action]) -> Vec<SafetyRecord> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::PersistSafety(r) => Some((**r).clone()),
            _ => None,
        })
        .collect()
}

pub(super) fn evidence(actions: &[Action]) -> Vec<Evidence> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::ReportEvidence(e) => Some((**e).clone()),
            _ => None,
        })
        .collect()
}

pub(super) fn faults(actions: &[Action]) -> Vec<LocalFault> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::LocalFault(f) => Some(*f),
            _ => None,
        })
        .collect()
}

pub(super) fn halts(actions: &[Action]) -> Vec<HaltReason> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Halt(r) => Some(*r),
            _ => None,
        })
        .collect()
}

pub(super) fn executes(actions: &[Action]) -> Vec<(Hash32, u64)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Execute { block, req, .. } => Some((block.header().payload_hash, *req)),
            _ => None,
        })
        .collect()
}

pub(super) fn count<F: Fn(&Action) -> bool>(actions: &[Action], f: F) -> usize {
    actions.iter().filter(|a| f(a)).count()
}

/// Role pickers for `H::new` (height 1).
pub(super) mod pick {
    use crate::{topology::Topology, types::ValidatorIndex};

    pub fn leader(view: u64) -> impl Fn(&Topology) -> ValidatorIndex {
        move |t| t.leader(view)
    }

    pub fn proxy_tail(view: u64) -> impl Fn(&Topology) -> ValidatorIndex {
        move |t| t.round(view).proxy_tail()
    }

    /// A set-A member of `(1, view)` that is neither leader nor proxy tail.
    pub fn set_a(view: u64) -> impl Fn(&Topology) -> ValidatorIndex {
        move |t| {
            let r = t.round(view);
            r.set_a()[1..r.set_a().len() - 1][0]
        }
    }

    /// A set-A member of `(1, view)` that is neither leader nor proxy tail, and also not the
    /// leader of view `view + 1` (so a TC into that view does not make it propose).
    pub fn plain_set_a(view: u64) -> impl Fn(&Topology) -> ValidatorIndex {
        move |t| {
            let r = t.round(view);
            let next = t.leader(view + 1);
            *r.set_a()[1..r.set_a().len() - 1]
                .iter()
                .find(|m| **m != next)
                .expect("a plain set-A member")
        }
    }

    pub fn set_b(view: u64) -> impl Fn(&Topology) -> ValidatorIndex {
        move |t| t.round(view).set_b()[0]
    }

    /// Position `position` of `order_{height, view}` (no demotion before height 3).
    pub fn at(height: u64, view: u64, position: usize) -> impl Fn(&Topology) -> ValidatorIndex {
        move |t| {
            let topo = Topology::from_parts(t.permutation().to_vec(), &[], height).unwrap();
            topo.round(view).order()[position]
        }
    }
}
