//! The toy AMX application of F31 and its oracle O-AMX (spec §11, §13.2, §13.3).
//!
//! Instance [`GLOBAL`] is the global chain `G`; every other instance of the world is a
//! dataspace `D_i` with its own committee. They run the two-phase commit of §11 as an
//! application over the unmodified cores:
//!
//! - **Execution binds the records.** The simulator's executor computes
//!   `R_base = H(parent_R ‖ payload)` ([`super::driver::reference_exec`]). In an AMX world every
//!   block's execution also runs the application over the parent's application state and
//!   certifies `R = H(TAG ‖ R_base ‖ H(records))` ([`bind`]), where `records` are the block's
//!   AMX records: `Begin` and `Decision` on `G`, `Prepared` on a dataspace, and at the last
//!   height of an epoch the complete context of the next one (the handoff record, §11.7). The
//!   pair `(R_base, records)` is the result preimage a [`RecordProof`] discloses.
//! - **Inputs are transactions.** An AMX input ([`Input`]) is a workload-format transaction
//!   whose id names it in [`AmxWorld`]'s input registry; the registry stands in for the
//!   transaction body (proofs are not serialized). Inputs a state transition rejects (a second
//!   `Begin`, a second inclusion of `x`, a proof that does not verify) leave no record.
//! - **Light clients.** Every instance verifies another's records with a [`Tracker`] of that
//!   instance's committees (§11.7): the core's `Verifier::verify_commit_qc` under the committee
//!   of the certified height's epoch, which must be the tracked epoch `e` or `e − 1`. A handoff
//!   proof (the certified last block of `e`, whose records carry the context of `e + 1`)
//!   advances the tracker by exactly one epoch.
//! - **Relayers** run on chosen machines. They read their machine's committed blocks, build
//!   record proofs from the stored `CommitQC`s and submit them to the other instances until the
//!   effect is committed there (state, not custody: a relayer that is down or whose machine
//!   crashed loses its jobs and rebuilds them from the committed chain when it runs again).
//!   Relaying affects liveness only.
//! - **A client** begins transactions on `G` with short and long deadlines; some legs cannot be
//!   escrowed (a `No` vote).
//!
//! **O-AMX** walks every instance's committed reference chain (the first honest commit of each
//! height, [`super::oracle::Oracle::refs`]) and checks: at most one `Begin`, one `Decision` and,
//! per participant, one `Prepared` and one settlement per transaction; `G` records `Commit`
//! only at a height `≤ d` with a committed `Yes` from every participant, `Abort` before `d + 1`
//! only on a committed `No`, and decides every transaction by `d + 1`; a dataspace applies a
//! `Yes` escrow only on `G`'s `Commit` and releases it only on `G`'s `Abort` (an escrow leaves
//! only through a settlement with a verified decision proof); every dataspace ledger moves only
//! by its escrows and settlements; and every transaction `G` decided at least
//! [`AmxConfig::settle_window`] before the end is settled by every participant by the end of the
//! run. Non-blocking is O-LIVE: an instance keeps committing while another stalls
//! ([`super::scenario::Checks::stalled`] exempts only the stalled one).

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    rc::Rc,
};

use super::{
    crypto::SimCrypto,
    driver::{block_exec, decode_txs, encode_tx},
    world::{Inst, World},
};
use crate::{
    api::ExecOutcome,
    availability::AvailableBody,
    crypto::{Crypto, Verifier},
    message::{BlockHeader, Qc},
    preimage,
    testing::sha256,
    types::{Committee, EpochConfig, Hash32, Millis},
};

/// Index of the global instance `G`; every other instance is a dataspace.
pub const GLOBAL: usize = 0;
/// First transaction id of an AMX input (workload transactions count up from 1).
pub const INPUT_BASE: u64 = 1 << 60;
/// Largest distance `d − b` between a `Begin` at `b` and its deadline `d` (§11.6).
pub const MAX_WINDOW: u64 = 200;
/// Interval of the application's client, relayers and oracle.
pub const TICK: Millis = 100;
/// Padding of an input transaction.
const INPUT_PAD: u16 = 8;
const TAG_RESULT: &[u8] = b"sumeragi/sim/amx/result";
const TAG_RECORDS: &[u8] = b"sumeragi/sim/amx/records";
const TAG_TX: &[u8] = b"sumeragi/sim/amx/transaction";
const TAG_EFFECTS: &[u8] = b"sumeragi/sim/amx/effects";

fn put(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn index_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// One participant's leg of a toy AMX transaction: move `amount` from account `from` to account
/// `to` of dataspace `inst`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leg {
    /// The participant dataspace (an instance index other than [`GLOBAL`]).
    pub inst: usize,
    /// Debited account.
    pub from: u8,
    /// Credited account.
    pub to: u8,
    /// Amount.
    pub amount: u64,
}

/// A toy AMX transaction `X` (§11.2): one leg per participant in strictly increasing
/// participant order, the global deadline height `d` and a client nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmxTx {
    /// The legs.
    pub legs: Vec<Leg>,
    /// Global deadline height `d`.
    pub deadline: u64,
    /// Client nonce.
    pub nonce: u64,
}

impl AmxTx {
    /// `x = H(X)`.
    pub fn id(&self) -> Hash32 {
        let mut bytes = TAG_TX.to_vec();
        put(&mut bytes, index_u64(self.legs.len()));
        for leg in &self.legs {
            put(&mut bytes, index_u64(leg.inst));
            bytes.push(leg.from);
            bytes.push(leg.to);
            put(&mut bytes, leg.amount);
        }
        put(&mut bytes, self.deadline);
        put(&mut bytes, self.nonce);
        Hash32(sha256(&bytes))
    }

    /// The participant set, ascending.
    pub fn participants(&self) -> Vec<usize> {
        self.legs.iter().map(|leg| leg.inst).collect()
    }

    /// At least two legs, strictly increasing by participant, none of them `G`.
    pub fn well_formed(&self) -> bool {
        self.legs.len() >= 2
            && self.legs.windows(2).all(|pair| pair[0].inst < pair[1].inst)
            && self.legs.iter().all(|leg| leg.inst != GLOBAL)
    }

    /// The leg of `inst`.
    pub fn leg(&self, inst: usize) -> Option<&Leg> {
        self.legs.iter().find(|leg| leg.inst == inst)
    }
}

/// A participant's vote (§11.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vote {
    /// The participant escrowed its leg; the hash commits to the escrowed effects.
    Yes(Hash32),
    /// Nothing is escrowed.
    No,
}

/// `G`'s decision (§11.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    /// Every participant voted `Yes` by the deadline.
    Commit,
    /// A participant voted `No`, or the deadline passed first.
    Abort,
}

/// An AMX record of a block, bound into the block's `R` ([`bind`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// `Begin{x, participants, d}` (`G`, §11.2).
    Begin {
        /// Transaction id `x`.
        x: Hash32,
        /// Participants, ascending.
        participants: Vec<usize>,
        /// Global deadline height `d`.
        deadline: u64,
    },
    /// `Prepared{x, D_i, vote}` (a dataspace, §11.3).
    Prepared {
        /// Transaction id `x`.
        x: Hash32,
        /// The voting dataspace.
        participant: usize,
        /// Its vote.
        vote: Vote,
    },
    /// `Decision{x, outcome}` (`G`, §11.5).
    Decision {
        /// Transaction id `x`.
        x: Hash32,
        /// The decision.
        outcome: Outcome,
    },
    /// The complete context of the instance's next epoch, recorded by the last block of an
    /// epoch: what a handoff proof proves (§11.7).
    Epoch {
        /// The next epoch.
        next: EpochConfig,
        /// Its committee.
        committee: Committee,
    },
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Begin {
                x,
                participants,
                deadline,
            } => {
                out.push(1);
                out.extend_from_slice(&x.0);
                put(&mut out, index_u64(participants.len()));
                for participant in participants {
                    put(&mut out, index_u64(*participant));
                }
                put(&mut out, *deadline);
            }
            Self::Prepared {
                x,
                participant,
                vote,
            } => {
                out.push(2);
                out.extend_from_slice(&x.0);
                put(&mut out, index_u64(*participant));
                match vote {
                    Vote::Yes(effects) => {
                        out.push(1);
                        out.extend_from_slice(&effects.0);
                    }
                    Vote::No => out.push(0),
                }
            }
            Self::Decision { x, outcome } => {
                out.push(3);
                out.extend_from_slice(&x.0);
                out.push(u8::from(*outcome == Outcome::Commit));
            }
            Self::Epoch { next, committee } => {
                out.push(4);
                put(&mut out, next.id.epoch);
                out.extend_from_slice(&next.id.context.0);
                out.extend_from_slice(&next.authority_generation.0);
                put(&mut out, next.first_height);
                put(&mut out, next.last_height);
                out.extend_from_slice(&next.leader_seed.0);
                out.extend_from_slice(&preimage::committee_digest_preimage(committee));
            }
        }
        out
    }
}

/// `R = H(TAG ‖ R_base ‖ H(TAG_RECORDS ‖ (len ‖ record)*))`: the certified result of a block
/// whose plain execution commitment is `base` and whose application recorded `records`.
pub fn bind(base: &Hash32, records: &[Record]) -> Hash32 {
    let mut list = TAG_RECORDS.to_vec();
    for record in records {
        let bytes = record.encode();
        put(&mut list, index_u64(bytes.len()));
        list.extend_from_slice(&bytes);
    }
    let mut out = TAG_RESULT.to_vec();
    out.extend_from_slice(&base.0);
    out.extend_from_slice(&sha256(&list));
    Hash32(sha256(&out))
}

/// A proof that an instance recorded `records[index]` (§11.4, §11.6): the certified header, its
/// `CommitQC` and the result preimage `(R_base, records)` of the block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordProof {
    /// The certified header.
    pub header: BlockHeader,
    /// Its `CommitQC`.
    pub qc: Qc,
    /// `R_base` of the block.
    pub base: Hash32,
    /// Every record of the block, in execution order.
    pub records: Vec<Record>,
    /// Position of the proven record.
    pub index: usize,
}

impl RecordProof {
    /// The proven record.
    pub fn record(&self) -> Option<&Record> {
        self.records.get(self.index)
    }
}

/// The committee of one epoch of a tracked instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochContext {
    /// The epoch.
    pub epoch: EpochConfig,
    /// Its committee.
    pub committee: Committee,
}

impl EpochContext {
    /// The context of `inst`'s epoch that holds `height`.
    pub fn of(inst: &Inst, height: u64) -> Self {
        let config = inst.config(height);
        Self {
            epoch: *config.epoch,
            committee: config.committee,
        }
    }
}

/// Why a proof is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    /// The header names another instance.
    Instance,
    /// The certified height is not in a tracked epoch (`e − 1` or `e`).
    Epoch,
    /// The `CommitQC` does not certify the header under the epoch's committee.
    Certificate,
    /// The result preimage does not hash to the certified `R`.
    Result,
    /// The proven record is not in the preimage.
    Index,
    /// Not a handoff: not the last block of the tracked epoch, or no next-epoch context.
    Handoff,
}

/// A light client of another instance (§11.7): its latest verified epoch `e` and `e − 1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tracker {
    /// Instance id `I_J`.
    pub instance: Hash32,
    /// `C_{J,e}`.
    pub current: EpochContext,
    /// `C_{J,e−1}`, absent before the first handoff.
    pub previous: Option<EpochContext>,
}

impl Tracker {
    /// Track `instance` from an independently authenticated epoch context (its genesis).
    pub fn new(instance: Hash32, anchor: EpochContext) -> Self {
        Self {
            instance,
            current: anchor,
            previous: None,
        }
    }

    /// The latest tracked epoch `e`.
    pub fn epoch(&self) -> u64 {
        self.current.epoch.id.epoch
    }

    fn context(&self, header: &BlockHeader) -> Option<&EpochContext> {
        std::iter::once(&self.current)
            .chain(self.previous.as_ref())
            .find(|context| {
                context.epoch.id == header.epoch
                    // MX10: a committee certifies heights outside its epoch.
                    && (context.epoch.contains(header.height)
                        || cfg!(sumeragi_mutation = "MX10"))
            })
    }

    /// Verify a record proof; the certified height on success.
    ///
    /// # Errors
    /// The first failed check.
    pub fn verify(&self, crypto: &dyn Crypto, proof: &RecordProof) -> Result<u64, ProofError> {
        if proof.header.instance != self.instance {
            return Err(ProofError::Instance);
        }
        let context = self.context(&proof.header).ok_or(ProofError::Epoch)?;
        let verifier = Verifier::new(
            crypto,
            &self.instance,
            &context.epoch.id,
            &context.committee,
        );
        if !verifier.verify_commit_qc(&proof.qc, Some(&proof.header)) {
            return Err(ProofError::Certificate);
        }
        // MX12: the record list is not bound to the certified result.
        if proof.qc.result != bind(&proof.base, &proof.records) && !cfg!(sumeragi_mutation = "MX12")
        {
            return Err(ProofError::Result);
        }
        if proof.record().is_none() {
            return Err(ProofError::Index);
        }
        Ok(proof.header.height)
    }

    /// Apply a handoff proof: `Ok(true)` if the tracker advanced to `e + 1`, `Ok(false)` for a
    /// verified block of `e − 1` (a handoff into an epoch already held).
    ///
    /// # Errors
    /// The proof does not verify or is not the handoff of `e`.
    pub fn handoff(
        &mut self,
        crypto: &dyn Crypto,
        proof: &RecordProof,
    ) -> Result<bool, ProofError> {
        let height = self.verify(crypto, proof)?;
        if proof.header.epoch != self.current.epoch.id {
            return Ok(false);
        }
        let Some(Record::Epoch { next, committee }) = proof.record() else {
            return Err(ProofError::Handoff);
        };
        if height != self.current.epoch.last_height
            || next.first_height != height.saturating_add(1)
            || next.id.epoch != self.epoch().saturating_add(1)
        {
            return Err(ProofError::Handoff);
        }
        let next = EpochContext {
            epoch: *next,
            committee: committee.clone(),
        };
        let previous = std::mem::replace(&mut self.current, next);
        // MX11: the tracker keeps only `C_e`.
        self.previous = (!cfg!(sumeragi_mutation = "MX11")).then_some(previous);
        Ok(true)
    }
}

/// `G`'s entry of a begun transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalEntry {
    /// Participants, ascending.
    pub participants: Vec<usize>,
    /// Deadline `d`.
    pub deadline: u64,
    /// Participants whose verified `Yes` is recorded.
    pub yes: BTreeSet<usize>,
    /// The immutable decision.
    pub decided: Option<Outcome>,
}

/// `G`'s application state: a tracker per dataspace and every begun transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalState {
    /// Trackers of the dataspaces' instances.
    pub trackers: BTreeMap<usize, Tracker>,
    /// Begun transactions.
    pub txs: BTreeMap<Hash32, GlobalEntry>,
}

impl GlobalState {
    /// `Begin` (§11.2): a well-formed transaction with registered participants and
    /// `b < d ≤ b + MAX_WINDOW`; a second `Begin` for `x` is rejected.
    fn begin(&mut self, height: u64, tx: &AmxTx, records: &mut Vec<Record>) {
        let x = tx.id();
        if !tx.well_formed()
            || tx.deadline <= height
            || tx.deadline - height > MAX_WINDOW
            || tx
                .legs
                .iter()
                .any(|leg| !self.trackers.contains_key(&leg.inst))
        {
            return;
        }
        // MX4: a second `Begin` replaces the transaction's entry.
        if self.txs.contains_key(&x) && !cfg!(sumeragi_mutation = "MX4") {
            return;
        }
        let participants = tx.participants();
        self.txs.insert(
            x,
            GlobalEntry {
                participants: participants.clone(),
                deadline: tx.deadline,
                yes: BTreeSet::new(),
                decided: None,
            },
        );
        records.push(Record::Begin {
            x,
            participants,
            deadline: tx.deadline,
        });
    }

    /// A relayed `Prepared` proof (§11.4, §11.5): the first verified `No` decides `Abort`, the
    /// `Yes` that completes the votes at a height `≤ d` decides `Commit`; proofs for unknown or
    /// decided transactions and repeated votes are ignored.
    fn vote(
        &mut self,
        crypto: &dyn Crypto,
        height: u64,
        proof: &RecordProof,
        records: &mut Vec<Record>,
    ) {
        let Some(Record::Prepared {
            x,
            participant,
            vote,
        }) = proof.record()
        else {
            return;
        };
        let Some(entry) = self.txs.get_mut(x) else {
            return;
        };
        if entry.decided.is_some()
            || !entry.participants.contains(participant)
            || entry.yes.contains(participant)
        {
            return;
        }
        let Some(tracker) = self.trackers.get(participant) else {
            return;
        };
        // MX5: the vote is counted without verifying its proof.
        if tracker.verify(crypto, proof).is_err() && !cfg!(sumeragi_mutation = "MX5") {
            return;
        }
        let outcome = match vote {
            Vote::No => Outcome::Abort,
            Vote::Yes(_) => {
                entry.yes.insert(*participant);
                // MX1: one `Yes` suffices.
                let all =
                    entry.yes.len() == entry.participants.len() || cfg!(sumeragi_mutation = "MX1");
                // MX2: `Commit` after the deadline.
                let in_time = height <= entry.deadline || cfg!(sumeragi_mutation = "MX2");
                if !(all && in_time) {
                    return;
                }
                Outcome::Commit
            }
        };
        entry.decided = Some(outcome);
        records.push(Record::Decision { x: *x, outcome });
    }

    /// A relayed handoff of dataspace `inst`'s instance.
    fn handoff(&mut self, crypto: &dyn Crypto, inst: usize, proof: &RecordProof) {
        if let Some(tracker) = self.trackers.get_mut(&inst) {
            // A handoff that does not verify is a rejected transaction.
            let _ = tracker.handoff(crypto, proof);
        }
    }

    /// After the block's transactions: every undecided transaction whose deadline passed is
    /// aborted, so `G` decides by `d + 1` (§11.5).
    fn expire(&mut self, height: u64, records: &mut Vec<Record>) {
        // MX3: no deadline abort.
        if cfg!(sumeragi_mutation = "MX3") {
            return;
        }
        for (x, entry) in &mut self.txs {
            if entry.decided.is_none() && entry.deadline < height {
                entry.decided = Some(Outcome::Abort);
                records.push(Record::Decision {
                    x: *x,
                    outcome: Outcome::Abort,
                });
            }
        }
    }
}

/// A dataspace's entry of a prepared transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedEntry {
    /// Deadline `d`.
    pub deadline: u64,
    /// This dataspace's recorded vote.
    pub vote: Vote,
    /// The applied decision, once settled.
    pub settled: Option<Outcome>,
}

/// A dataspace's application state: its tracker of `G`, the prepared and held transactions,
/// and a toy ledger with escrows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataspaceState {
    /// This dataspace's instance index.
    pub me: usize,
    /// Tracker of `G`'s instance.
    pub global: Tracker,
    /// Highest verified `G` height.
    pub global_height: u64,
    /// `prepared_Di`; settled entries carry the decision.
    pub prepared: BTreeMap<Hash32, PreparedEntry>,
    /// Decisions of transactions not prepared here.
    pub held: BTreeMap<Hash32, Outcome>,
    /// Account balances.
    pub balances: BTreeMap<u8, u64>,
    /// `Yes` escrows by transaction.
    pub escrows: BTreeMap<Hash32, Leg>,
}

impl DataspaceState {
    /// The ledger's total: balances plus escrowed amounts.
    pub fn total(&self) -> u64 {
        self.balances.values().sum::<u64>()
            + self.escrows.values().map(|leg| leg.amount).sum::<u64>()
    }

    /// Whether `x` is settled here (a prepared entry with its decision, or a held decision).
    pub fn settled(&self, x: &Hash32) -> bool {
        self.prepared
            .get(x)
            .is_some_and(|entry| entry.settled.is_some())
            || self.held.contains_key(x)
    }

    /// Prepare (§11.3): the verified `Begin` of `tx` naming this dataspace, `x ∉ prepared`, and
    /// no verified `G` block beyond `d` (then `G` already decided `x`, without this vote only
    /// `Abort`). A held decision makes the vote `No`; otherwise the leg is escrowed (`Yes`) or
    /// cannot be (`No`).
    fn prepare(
        &mut self,
        crypto: &dyn Crypto,
        tx: &AmxTx,
        proof: &RecordProof,
        records: &mut Vec<Record>,
    ) {
        let x = tx.id();
        let Some(Record::Begin {
            x: begun,
            participants,
            deadline,
        }) = proof.record()
        else {
            return;
        };
        if *begun != x || *participants != tx.participants() || *deadline != tx.deadline {
            return;
        }
        let Some(leg) = tx.leg(self.me).copied() else {
            return;
        };
        let Ok(height) = self.global.verify(crypto, proof) else {
            return;
        };
        // MX6: a second inclusion of `x` is prepared again.
        if self.prepared.contains_key(&x) && !cfg!(sumeragi_mutation = "MX6") {
            return;
        }
        let global_height = self.global_height.max(height);
        if tx.deadline < global_height {
            return;
        }
        // MX7: a held decision is ignored.
        let held = if cfg!(sumeragi_mutation = "MX7") {
            None
        } else {
            self.held.remove(&x)
        };
        let vote = if held.is_some() {
            Vote::No
        } else {
            self.escrow(&x, leg)
        };
        self.prepared.insert(
            x,
            PreparedEntry {
                deadline: tx.deadline,
                vote,
                settled: held,
            },
        );
        self.observe(global_height);
        records.push(Record::Prepared {
            x,
            participant: self.me,
            vote,
        });
    }

    fn escrow(&mut self, x: &Hash32, leg: Leg) -> Vote {
        let balance = self.balances.entry(leg.from).or_default();
        if *balance < leg.amount || leg.from == leg.to {
            return Vote::No;
        }
        *balance -= leg.amount;
        self.escrows.insert(*x, leg);
        let mut effects = TAG_EFFECTS.to_vec();
        effects.extend_from_slice(&x.0);
        effects.push(leg.from);
        effects.push(leg.to);
        put(&mut effects, leg.amount);
        Vote::Yes(Hash32(sha256(&effects)))
    }

    /// Settle (§11.6) with a verified decision proof: a `Yes` escrow is applied on `Commit` and
    /// released on `Abort`, exactly once; a decision of a transaction not prepared here is held.
    fn settle(&mut self, crypto: &dyn Crypto, proof: &RecordProof) {
        let Some(Record::Decision { x, outcome }) = proof.record() else {
            return;
        };
        let Ok(height) = self.global.verify(crypto, proof) else {
            return;
        };
        match self.prepared.get_mut(x) {
            Some(entry) if entry.settled.is_none() => {
                entry.settled = Some(*outcome);
                if matches!(entry.vote, Vote::Yes(_))
                    && let Some(leg) = self.escrows.remove(x)
                {
                    // MX8: the escrow is applied whatever the decision.
                    let account = if *outcome == Outcome::Commit || cfg!(sumeragi_mutation = "MX8")
                    {
                        leg.to
                    } else {
                        leg.from
                    };
                    *self.balances.entry(account).or_default() += leg.amount;
                }
            }
            Some(_) => return,
            None => {
                self.held.entry(*x).or_insert(*outcome);
            }
        }
        self.observe(height);
    }

    /// A relayed handoff of `G`'s instance.
    fn handoff(&mut self, crypto: &dyn Crypto, proof: &RecordProof) {
        if self.global.handoff(crypto, proof) == Ok(true)
            && let Some(previous) = &self.global.previous
        {
            let last = previous.epoch.last_height;
            self.observe(last);
        }
    }

    /// Raise the verified `G` height. A `Yes` escrow is never released here: only a settlement
    /// with `G`'s `Abort` releases it (§11.6).
    fn observe(&mut self, height: u64) {
        self.global_height = self.global_height.max(height);
        // MX9: a local timeout releases the `Yes` escrows whose deadline passed.
        #[cfg(sumeragi_mutation = "MX9")]
        {
            let global_height = self.global_height;
            let expired: Vec<Hash32> = self
                .prepared
                .iter()
                .filter(|(_, entry)| entry.settled.is_none() && entry.deadline < global_height)
                .map(|(x, _)| *x)
                .collect();
            for x in expired {
                if let Some(leg) = self.escrows.remove(&x) {
                    *self.balances.entry(leg.from).or_default() += leg.amount;
                }
                if let Some(entry) = self.prepared.get_mut(&x) {
                    entry.settled = Some(Outcome::Abort);
                }
            }
        }
    }
}

/// The application state of one instance after a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppState {
    /// `G`.
    Global(Box<GlobalState>),
    /// A dataspace.
    Dataspace(Box<DataspaceState>),
}

impl AppState {
    /// `G`'s state.
    pub fn global(&self) -> Option<&GlobalState> {
        match self {
            Self::Global(state) => Some(state),
            Self::Dataspace(_) => None,
        }
    }

    /// A dataspace's state.
    pub fn dataspace(&self) -> Option<&DataspaceState> {
        match self {
            Self::Dataspace(state) => Some(state),
            Self::Global(_) => None,
        }
    }

    /// This instance's tracker of instance `inst`.
    pub fn tracker(&self, inst: usize) -> Option<&Tracker> {
        match self {
            Self::Global(state) => state.trackers.get(&inst),
            Self::Dataspace(state) => (inst == GLOBAL).then_some(&state.global),
        }
    }
}

/// An AMX input transaction, addressed to one instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// `Begin(X)` for `G` (a client's request).
    Begin(AmxTx),
    /// A relayed `Prepared` proof for `G`.
    Vote(Box<RecordProof>),
    /// A relayed handoff proof of dataspace `.0`'s instance for `G`'s tracker of it.
    Handoff(usize, Box<RecordProof>),
    /// `X` with `G`'s `Begin` proof, for a participant.
    Prepare(AmxTx, Box<RecordProof>),
    /// `G`'s decision proof, for a participant.
    Settle(Box<RecordProof>),
    /// A relayed handoff proof of `G`'s instance for a dataspace's tracker of `G`.
    GlobalHandoff(Box<RecordProof>),
}

/// The application's execution of one block: the post-state, `R_base` and the block's records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exec {
    /// The application state after the block.
    pub state: AppState,
    /// `R_base` of the block.
    pub base: Hash32,
    /// The block's records.
    pub records: Vec<Record>,
}

/// Settings of the toy AMX application (F31).
#[derive(Clone, Debug)]
pub struct AmxConfig {
    /// Machines that run a relayer.
    pub relayers: Vec<usize>,
    /// A machine that runs a forging relayer: it relays genuinely and also submits every vote
    /// and decision proof once more with the record rewritten (the vote or decision flipped),
    /// which no tracker may accept.
    pub forger: Option<usize>,
    /// Scripted relayer outages `(relayer index, from, until)`.
    pub relayer_down: Vec<(usize, Millis, Millis)>,
    /// Interval between submissions of a pending relay.
    pub retry: Millis,
    /// Largest delay of a prepare relay after its `Begin` commits (per transaction, from its
    /// id): a slow relayer, so that `G` sometimes decides before a participant prepares.
    pub prepare_delay: Millis,
    /// Largest delay of a settlement relay after its `Decision` commits (per transaction, from
    /// its id), so that a participant sometimes verifies `G` blocks above `d` while its `Yes`
    /// escrow still waits for the decision proof.
    pub settle_delay: Millis,
    /// Probability (ppm) that a submission to one replica is lost.
    pub submit_loss_ppm: u32,
    /// Interval between the client's transactions (uniform range).
    pub every: (Millis, Millis),
    /// The client's first and last transaction times.
    pub client: (Millis, Millis),
    /// Probability (ppm) of a short deadline.
    pub short_ppm: u32,
    /// Short deadline distance range (in `G` heights).
    pub short: (u64, u64),
    /// Long deadline distance range.
    pub long: (u64, u64),
    /// Accounts per dataspace.
    pub accounts: u8,
    /// Initial balance of every account.
    pub balance: u64,
    /// Largest leg amount (some legs cannot be escrowed: `No`).
    pub max_amount: u64,
    /// Every transaction `G` decided this long before the end is settled everywhere by the end.
    pub settle_window: Millis,
}

impl Default for AmxConfig {
    fn default() -> Self {
        Self {
            relayers: vec![0, 1],
            forger: None,
            relayer_down: Vec::new(),
            retry: 1_000,
            prepare_delay: 4_000,
            settle_delay: 6_000,
            submit_loss_ppm: 100_000,
            every: (800, 2_000),
            client: (2_000, 70_000),
            short_ppm: 300_000,
            short: (2, 6),
            long: (12, 40),
            accounts: 4,
            balance: 100,
            max_amount: 60,
            settle_window: 20_000,
        }
    }
}

/// What a pending relay delivers; the relay's key is `(target instance, JobKey)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum JobKey {
    /// `G`'s `Begin` of `x` to a participant (a prepare).
    Prepare(Hash32),
    /// Participant `.1`'s vote on `x` to `G`.
    Vote(Hash32, usize),
    /// `G`'s decision on `x` to a participant (a settlement).
    Settle(Hash32),
    /// Instance `.0`'s handoff into epoch `.1`.
    Handoff(usize, u64),
}

#[derive(Clone, Debug)]
struct Job {
    input: Input,
    next_at: Millis,
}

/// A relayer process on a machine: its scan position per instance and its pending relays by
/// `(target instance, what)`.
#[derive(Clone, Debug, Default)]
struct Relayer {
    machine: usize,
    forging: bool,
    incarnation: Option<u64>,
    scanned: BTreeMap<usize, usize>,
    jobs: BTreeMap<(usize, JobKey), Job>,
}

impl Relayer {
    fn reset(&mut self, incarnation: Option<u64>) {
        self.incarnation = incarnation;
        self.scanned.clear();
        self.jobs.clear();
    }

    /// Queue the relays a committed record of instance `inst` needs.
    fn learn(
        &mut self,
        inst: usize,
        instances: usize,
        proof: &RecordProof,
        txs: &BTreeMap<Hash32, AmxTx>,
        now: Millis,
        (prepare_delay, settle_delay): (Millis, Millis),
    ) {
        let boxed = || Box::new(proof.clone());
        let mut add = |target: usize, key: JobKey, input: Input, next_at: Millis| {
            self.jobs
                .entry((target, key))
                .or_insert(Job { input, next_at });
        };
        match (inst, proof.record()) {
            (GLOBAL, Some(Record::Begin { x, .. })) => {
                if let Some(tx) = txs.get(x) {
                    let delay = prepare_delay * u64::from(x.0[0]) / u64::from(u8::MAX);
                    for leg in &tx.legs {
                        add(
                            leg.inst,
                            JobKey::Prepare(*x),
                            Input::Prepare(tx.clone(), boxed()),
                            now + delay,
                        );
                    }
                }
            }
            (GLOBAL, Some(Record::Decision { x, .. })) => {
                if let Some(tx) = txs.get(x) {
                    let delay = settle_delay * u64::from(x.0[1]) / u64::from(u8::MAX);
                    for leg in &tx.legs {
                        add(
                            leg.inst,
                            JobKey::Settle(*x),
                            Input::Settle(boxed()),
                            now + delay,
                        );
                    }
                }
            }
            (GLOBAL, Some(Record::Epoch { next, .. })) => {
                for to in 1..instances {
                    add(
                        to,
                        JobKey::Handoff(GLOBAL, next.id.epoch),
                        Input::GlobalHandoff(boxed()),
                        now,
                    );
                }
            }
            (_, Some(Record::Prepared { x, participant, .. })) if *participant == inst => {
                add(GLOBAL, JobKey::Vote(*x, inst), Input::Vote(boxed()), now);
            }
            (_, Some(Record::Epoch { next, .. })) => {
                add(
                    GLOBAL,
                    JobKey::Handoff(inst, next.id.epoch),
                    Input::Handoff(inst, boxed()),
                    now,
                );
            }
            _ => {}
        }
    }
}

/// How a participant settled a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// Its `Yes` escrow was applied (`Commit`).
    Applied,
    /// Its `Yes` escrow was released (`Abort`).
    Released,
    /// It voted `No`: nothing was escrowed.
    Closed,
    /// It never prepared the transaction and holds the decision.
    Held,
}

/// What O-AMX has seen on the committed reference chains.
#[derive(Clone, Debug, Default)]
pub struct Observed {
    /// Per instance, the last processed reference height.
    pub processed: Vec<u64>,
    /// Begun transactions: participants and deadline.
    pub begun: BTreeMap<Hash32, (Vec<usize>, u64)>,
    /// `G`'s decisions: outcome, `G` height and the time of the first honest commit.
    pub decided: BTreeMap<Hash32, (Outcome, u64, Millis)>,
    /// Votes by `(dataspace, x)`.
    pub votes: BTreeMap<(usize, Hash32), Vote>,
    /// Settlements by `(dataspace, x)`.
    pub settled: BTreeMap<(usize, Hash32), (Outcome, Settlement)>,
    /// Epoch advances of every instance's trackers.
    pub handoffs: u64,
    commit_checks: Vec<Hash32>,
    abort_checks: Vec<Hash32>,
    settle_checks: Vec<(usize, Hash32, Outcome)>,
}

/// The toy AMX application of a world: the input registry, the execution memo, the client, the
/// relayers and the O-AMX observations.
#[derive(Debug)]
pub struct AmxWorld {
    /// Settings.
    pub config: AmxConfig,
    crypto: SimCrypto,
    inputs: BTreeMap<u64, (usize, Input)>,
    next_input: u64,
    /// Transactions by id (the client's registry; a relayer reads `X` from `G`'s payload).
    pub txs: BTreeMap<Hash32, AmxTx>,
    memo: RefCell<BTreeMap<(usize, Hash32), Rc<Exec>>>,
    next_client: Millis,
    nonce: u64,
    relayers: Vec<Relayer>,
    /// O-AMX observations.
    pub seen: Observed,
}

impl AmxWorld {
    /// The application of `instances` (instance [`GLOBAL`] is `G`), anchored at their genesis
    /// contexts.
    pub fn new(config: AmxConfig, instances: &[Inst]) -> Self {
        let mut memo = BTreeMap::new();
        for (index, inst) in instances.iter().enumerate() {
            let state = if index == GLOBAL {
                AppState::Global(Box::new(GlobalState {
                    trackers: instances
                        .iter()
                        .enumerate()
                        .skip(1)
                        .map(|(ds, other)| (ds, Tracker::new(other.id, EpochContext::of(other, 0))))
                        .collect(),
                    txs: BTreeMap::new(),
                }))
            } else {
                AppState::Dataspace(Box::new(DataspaceState {
                    me: index,
                    global: Tracker::new(
                        instances[GLOBAL].id,
                        EpochContext::of(&instances[GLOBAL], 0),
                    ),
                    global_height: 0,
                    prepared: BTreeMap::new(),
                    held: BTreeMap::new(),
                    balances: (1..=config.accounts)
                        .map(|account| (account, config.balance))
                        .collect(),
                    escrows: BTreeMap::new(),
                }))
            };
            memo.insert(
                (index, inst.genesis_result),
                Rc::new(Exec {
                    state,
                    base: inst.genesis_result,
                    records: Vec::new(),
                }),
            );
        }
        let relayers = config
            .relayers
            .iter()
            .map(|machine| (*machine, false))
            .chain(config.forger.map(|machine| (machine, true)))
            .map(|(machine, forging)| Relayer {
                machine,
                forging,
                ..Relayer::default()
            })
            .collect();
        Self {
            next_client: config.client.0,
            config,
            crypto: SimCrypto::new(),
            inputs: BTreeMap::new(),
            next_input: INPUT_BASE,
            txs: BTreeMap::new(),
            memo: RefCell::new(memo),
            nonce: 0,
            relayers,
            seen: Observed {
                processed: vec![0; instances.len()],
                ..Observed::default()
            },
        }
    }

    /// The application's execution of instance `inst` that certified `result`.
    pub fn exec_of(&self, inst: usize, result: &Hash32) -> Option<Rc<Exec>> {
        self.memo.borrow().get(&(inst, *result)).cloned()
    }

    /// Register an input for instance `target`; its transaction id.
    fn register(&mut self, target: usize, input: Input) -> u64 {
        let id = self.next_input;
        self.next_input += 1;
        self.inputs.insert(id, (target, input));
        id
    }

    /// Run the application over `block` of instance `inst` on the post-state certified by
    /// `parent`: `base` is the plain execution outcome, the result binds the block's records.
    pub fn execute(
        &self,
        inst_config: &Inst,
        inst: usize,
        parent: &Hash32,
        block: &AvailableBody,
        base: ExecOutcome,
    ) -> ExecOutcome {
        let ExecOutcome::Valid(base) = base else {
            return base;
        };
        let Some(parent) = self.exec_of(inst, parent) else {
            return ExecOutcome::Failed("AMX application: unknown parent post-state".to_owned());
        };
        let (state, records) = self.step(
            inst_config,
            inst,
            &parent.state,
            block.payload().as_slice(),
            block.header().height,
        );
        let result = bind(&base, &records);
        self.memo
            .borrow_mut()
            .entry((inst, result))
            .or_insert_with(|| {
                Rc::new(Exec {
                    state,
                    base,
                    records,
                })
            });
        ExecOutcome::Valid(result)
    }

    /// The application's state transition of one block: the block's inputs in payload order,
    /// `G`'s deadline step, and the next-epoch record at the last height of an epoch.
    fn step(
        &self,
        inst_config: &Inst,
        inst: usize,
        state: &AppState,
        payload: &[u8],
        height: u64,
    ) -> (AppState, Vec<Record>) {
        let crypto = &self.crypto;
        let mut state = state.clone();
        let mut records = Vec::new();
        for (id, _) in decode_txs(payload) {
            let Some((target, input)) = self.inputs.get(&id) else {
                continue;
            };
            if *target != inst {
                continue;
            }
            match (&mut state, input) {
                (AppState::Global(global), Input::Begin(tx)) => {
                    global.begin(height, tx, &mut records);
                }
                (AppState::Global(global), Input::Vote(proof)) => {
                    global.vote(crypto, height, proof, &mut records);
                }
                (AppState::Global(global), Input::Handoff(ds, proof)) => {
                    global.handoff(crypto, *ds, proof);
                }
                (AppState::Dataspace(ds), Input::Prepare(tx, proof)) => {
                    ds.prepare(crypto, tx, proof, &mut records);
                }
                (AppState::Dataspace(ds), Input::Settle(proof)) => ds.settle(crypto, proof),
                (AppState::Dataspace(ds), Input::GlobalHandoff(proof)) => {
                    ds.handoff(crypto, proof);
                }
                _ => {}
            }
        }
        if let AppState::Global(global) = &mut state {
            global.expire(height, &mut records);
        }
        let config = inst_config.config(height);
        if height == config.epoch.last_height {
            let next = EpochContext::of(inst_config, height.saturating_add(1));
            records.push(Record::Epoch {
                next: next.epoch,
                committee: next.committee,
            });
        }
        (state, records)
    }

    /// Whether the effect of a relay is committed in `state` of its target.
    fn done(&self, key: JobKey, state: &AppState) -> bool {
        match key {
            JobKey::Prepare(x) => state.dataspace().is_some_and(|ds| {
                ds.prepared.contains_key(&x)
                    || ds.held.contains_key(&x)
                    || self
                        .txs
                        .get(&x)
                        .is_none_or(|tx| tx.deadline < ds.global_height)
            }),
            JobKey::Vote(x, participant) => state.global().is_some_and(|global| {
                global
                    .txs
                    .get(&x)
                    .is_none_or(|entry| entry.decided.is_some() || entry.yes.contains(&participant))
            }),
            JobKey::Settle(x) => state.dataspace().is_some_and(|ds| ds.settled(&x)),
            JobKey::Handoff(from, epoch) => state
                .tracker(from)
                .is_some_and(|tracker| tracker.epoch() >= epoch),
        }
    }
}

impl World {
    /// The execution of `block` of instance `inst` on the post-state certified by `parent`: the
    /// simulator's `block_exec` and, in an AMX world, the application's records bound into `R`.
    pub fn app_exec(&self, inst: usize, parent: &Hash32, block: &AvailableBody) -> ExecOutcome {
        let config = &self.instances[inst];
        let base = block_exec(parent, block, &config.config(block.header().height).epoch);
        match &self.amx {
            Some(amx) => amx.execute(config, inst, parent, block, base),
            None => base,
        }
    }

    /// One AMX tick: the client, the relayers and O-AMX.
    pub fn amx_tick(&mut self) {
        if self.amx.is_none() {
            return;
        }
        self.amx_client();
        self.amx_relay();
        self.amx_observe();
    }

    /// O-AMX at the end of a run: every transaction `G` decided at least the settle window
    /// before the end is settled by every participant.
    pub fn amx_finish(&mut self) {
        if self.amx.is_none() || self.failure.is_some() {
            return;
        }
        self.amx_observe();
        let Some(amx) = &self.amx else {
            return;
        };
        let horizon = self.duration.saturating_sub(amx.config.settle_window);
        let mut failure = None;
        for (x, (outcome, height, at)) in &amx.seen.decided {
            if *at > horizon {
                continue;
            }
            let Some((participants, _)) = amx.seen.begun.get(x) else {
                continue;
            };
            for participant in participants {
                let tip = self.oracle.refs[*participant]
                    .last_key_value()
                    .map_or(self.instances[*participant].genesis_result, |(_, block)| {
                        block.result
                    });
                let settled = amx
                    .exec_of(*participant, &tip)
                    .and_then(|exec| {
                        exec.state
                            .dataspace()
                            .map(|ds| ds.settled(x) && !ds.escrows.contains_key(x))
                    })
                    .unwrap_or(false);
                if !settled && failure.is_none() {
                    failure = Some(format!(
                        "O-AMX: G decided {outcome:?} for {} at height {height} (t={at}), but \
                         dataspace {participant} has not settled it by the end",
                        short(x)
                    ));
                }
            }
        }
        if let Some(failure) = failure {
            self.fail(failure);
        }
    }

    /// Submit input `id` to every running replica of instance `target` (each submission may be
    /// lost).
    fn amx_submit(&mut self, target: usize, id: u64) {
        let loss = self
            .amx
            .as_ref()
            .map_or(0, |amx| amx.config.submit_loss_ppm);
        let tx = encode_tx(id, false, INPUT_PAD);
        for r in 0..self.replicas.len() {
            let machine = self.replicas[r].machine;
            if self.replicas[r].inst == target
                && self.machines[machine].up
                && !self.rng.chance(loss)
            {
                self.offer_tx(r, id, tx.clone());
            }
        }
    }

    /// The client: a new transaction on `G` with a short or long deadline.
    fn amx_client(&mut self) {
        let now = self.now;
        let dataspaces = self.instances.len().saturating_sub(1);
        let g_height = self.oracle.refs[GLOBAL]
            .last_key_value()
            .map_or(0, |(height, _)| *height);
        let Some(amx) = self.amx.as_mut() else {
            return;
        };
        if dataspaces < 2 || now < amx.next_client || now > amx.config.client.1 {
            return;
        }
        let config = &amx.config;
        let rng = &mut self.rng;
        let mut all: Vec<usize> = (1..=dataspaces).collect();
        rng.shuffle(&mut all);
        let count = 2 + rng.index(dataspaces - 1);
        let mut participants = all[..count].to_vec();
        participants.sort_unstable();
        let accounts = u64::from(config.accounts.max(2));
        let legs = participants
            .into_iter()
            .map(|inst| {
                let from = rng.range(1, accounts);
                let to = 1 + (from + rng.range(0, accounts - 2)) % accounts;
                Leg {
                    inst,
                    from: u8::try_from(from).unwrap_or(1),
                    to: u8::try_from(to).unwrap_or(1),
                    amount: rng.range(1, config.max_amount),
                }
            })
            .collect();
        let (lo, hi) = if rng.chance(config.short_ppm) {
            config.short
        } else {
            config.long
        };
        let deadline = g_height + rng.range(lo, hi);
        amx.nonce += 1;
        let tx = AmxTx {
            legs,
            deadline,
            nonce: amx.nonce,
        };
        amx.next_client = now + rng.range(config.every.0, config.every.1);
        amx.txs.insert(tx.id(), tx.clone());
        let id = amx.register(GLOBAL, Input::Begin(tx));
        self.amx_submit(GLOBAL, id);
    }

    /// The relayers: scan their machine's committed blocks, queue the relays their records need
    /// and submit every relay whose effect is not yet committed at the target (as the relayer's
    /// own replica of the target sees it).
    fn amx_relay(&mut self) {
        let now = self.now;
        let instances = self.instances.len();
        let Some(amx) = self.amx.as_mut() else {
            return;
        };
        let mut submissions = Vec::new();
        let mut failure = None;
        for index in 0..amx.relayers.len() {
            let machine = &self.machines[amx.relayers[index].machine];
            let outage = amx
                .config
                .relayer_down
                .iter()
                .any(|(relayer, from, until)| *relayer == index && (*from..*until).contains(&now));
            if !machine.up || outage {
                amx.relayers[index].reset(None);
                continue;
            }
            if amx.relayers[index].incarnation != Some(machine.epoch) {
                amx.relayers[index].reset(Some(machine.epoch));
            }
            for inst in 0..instances {
                let Some(r) = machine.replicas.get(inst).copied().flatten() else {
                    continue;
                };
                let store = &self.replicas[r].store;
                let from = amx.relayers[index].scanned.get(&inst).copied().unwrap_or(0);
                for (block, qc) in store.iter().skip(from) {
                    let Some(exec) = amx.exec_of(inst, &qc.result) else {
                        failure.get_or_insert_with(|| {
                            format!(
                                "O-AMX: instance {inst} committed height {} without an \
                                 application execution",
                                block.header().height
                            )
                        });
                        continue;
                    };
                    for position in 0..exec.records.len() {
                        let proof = RecordProof {
                            header: block.header().clone(),
                            qc: qc.clone(),
                            base: exec.base,
                            records: exec.records.clone(),
                            index: position,
                        };
                        if amx.relayers[index].forging {
                            for (target, input) in forged(inst, &proof, &amx.txs) {
                                submissions.push((target, amx.register(target, input)));
                            }
                        }
                        amx.relayers[index].learn(
                            inst,
                            instances,
                            &proof,
                            &amx.txs,
                            now,
                            (amx.config.prepare_delay, amx.config.settle_delay),
                        );
                    }
                }
                amx.relayers[index].scanned.insert(inst, store.len());
            }
            let keys: Vec<(usize, JobKey)> = amx.relayers[index].jobs.keys().copied().collect();
            for (target, key) in keys {
                let state = machine
                    .replicas
                    .get(target)
                    .copied()
                    .flatten()
                    .and_then(|r| amx.exec_of(target, &self.replicas[r].applied.2));
                if state.is_some_and(|exec| amx.done(key, &exec.state)) {
                    amx.relayers[index].jobs.remove(&(target, key));
                    continue;
                }
                let retry = amx.config.retry;
                let Some(job) = amx.relayers[index].jobs.get_mut(&(target, key)) else {
                    continue;
                };
                if job.next_at > now {
                    continue;
                }
                job.next_at = now + retry;
                let input = job.input.clone();
                submissions.push((target, amx.register(target, input)));
            }
        }
        for (target, id) in submissions {
            self.amx_submit(target, id);
        }
        if let Some(failure) = failure {
            self.fail(failure);
        }
    }

    /// O-AMX over the newly committed reference heights of every instance.
    fn amx_observe(&mut self) {
        let Some(amx) = self.amx.as_mut() else {
            return;
        };
        let instances = self.instances.len();
        let mut failure: Option<String> = None;
        // Dataspaces first, then `G`; the cross-instance checks run after both.
        for inst in (1..instances).chain(std::iter::once(GLOBAL)) {
            loop {
                let height = amx.seen.processed[inst] + 1;
                let Some(block) = self.oracle.refs[inst].get(&height) else {
                    break;
                };
                let parent = if height == 1 {
                    self.instances[inst].genesis_result
                } else {
                    self.oracle.refs[inst]
                        .get(&(height - 1))
                        .map_or(Hash32::ZERO, |parent| parent.result)
                };
                let (Some(before), Some(after)) =
                    (amx.exec_of(inst, &parent), amx.exec_of(inst, &block.result))
                else {
                    failure.get_or_insert_with(|| {
                        format!("O-AMX: instance {inst} height {height} has no application state")
                    });
                    break;
                };
                amx.seen.processed[inst] = height;
                let at = block.at;
                if let Err(violation) =
                    observe_block(&mut amx.seen, &amx.txs, inst, (height, at), &before, &after)
                {
                    failure.get_or_insert(violation);
                }
            }
        }
        if let Err(violation) = check_cross(&mut amx.seen) {
            failure.get_or_insert(violation);
        }
        if let Some(failure) = failure {
            self.fail(failure);
        }
    }
}

/// The forging relayer's inputs for a genuine proof: the same certified block with its vote or
/// decision flipped, to `G` or to every participant.
fn forged(inst: usize, proof: &RecordProof, txs: &BTreeMap<Hash32, AmxTx>) -> Vec<(usize, Input)> {
    let mut forgery = proof.clone();
    let Some(record) = forgery.records.get_mut(forgery.index) else {
        return Vec::new();
    };
    match record {
        Record::Prepared { vote, .. } => {
            *vote = match vote {
                Vote::Yes(_) => Vote::No,
                Vote::No => Vote::Yes(Hash32([0xFF; 32])),
            };
            vec![(GLOBAL, Input::Vote(Box::new(forgery)))]
        }
        Record::Decision { x, outcome } if inst == GLOBAL => {
            *outcome = match outcome {
                Outcome::Commit => Outcome::Abort,
                Outcome::Abort => Outcome::Commit,
            };
            let participants = txs.get(x).map(AmxTx::participants).unwrap_or_default();
            participants
                .into_iter()
                .map(|participant| (participant, Input::Settle(Box::new(forgery.clone()))))
                .collect()
        }
        _ => Vec::new(),
    }
}

/// The first four bytes of `x` in hex, for reports.
fn short(x: &Hash32) -> String {
    x.0[..4].iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// O-AMX on the committed reference block of instance `inst` at `height`, first committed at
/// `at`.
fn observe_block(
    seen: &mut Observed,
    txs: &BTreeMap<Hash32, AmxTx>,
    inst: usize,
    (height, at): (u64, Millis),
    before: &Exec,
    after: &Exec,
) -> Result<(), String> {
    for record in &after.records {
        match record {
            Record::Begin {
                x,
                participants,
                deadline,
            } => {
                if seen
                    .begun
                    .insert(*x, (participants.clone(), *deadline))
                    .is_some()
                {
                    return Err(format!("O-AMX: G recorded a second Begin for {}", short(x)));
                }
            }
            Record::Decision { x, outcome } => {
                let Some((_, deadline)) = seen.begun.get(x) else {
                    return Err(format!("O-AMX: G decided {} without a Begin", short(x)));
                };
                if *outcome == Outcome::Commit {
                    if height > *deadline {
                        return Err(format!(
                            "O-AMX: G committed {} at height {height} after its deadline {deadline}",
                            short(x)
                        ));
                    }
                    seen.commit_checks.push(*x);
                } else if height <= *deadline {
                    seen.abort_checks.push(*x);
                }
                if seen.decided.insert(*x, (*outcome, height, at)).is_some() {
                    return Err(format!("O-AMX: G decided {} twice", short(x)));
                }
            }
            Record::Prepared {
                x,
                participant,
                vote,
            } => {
                if *participant != inst || seen.votes.insert((inst, *x), *vote).is_some() {
                    return Err(format!(
                        "O-AMX: dataspace {inst} recorded a second Prepared for {}",
                        short(x)
                    ));
                }
            }
            Record::Epoch { .. } => {}
        }
    }
    for tracked in 0..seen.processed.len() {
        if let (Some(old), Some(new)) =
            (before.state.tracker(tracked), after.state.tracker(tracked))
        {
            seen.handoffs += new.epoch().saturating_sub(old.epoch());
        }
    }
    match (&before.state, &after.state) {
        (AppState::Global(_), AppState::Global(global)) => {
            // `G` decides every transaction by `d + 1`.
            if let Some((x, _)) = global
                .txs
                .iter()
                .find(|(_, entry)| entry.decided.is_none() && entry.deadline < height)
            {
                return Err(format!(
                    "O-AMX: {} is undecided at G height {height}, after its deadline",
                    short(x)
                ));
            }
            Ok(())
        }
        (AppState::Dataspace(old), AppState::Dataspace(new)) => {
            observe_dataspace(seen, txs, inst, old, new)
        }
        _ => Err(format!(
            "O-AMX: instance {inst} changed its application role"
        )),
    }
}

/// O-AMX on the state change of one dataspace block: settlements, escrows and the ledger.
fn observe_dataspace(
    seen: &mut Observed,
    txs: &BTreeMap<Hash32, AmxTx>,
    inst: usize,
    old: &DataspaceState,
    new: &DataspaceState,
) -> Result<(), String> {
    for (x, entry) in &new.prepared {
        let was = old.prepared.get(x).and_then(|entry| entry.settled);
        let Some(outcome) = entry.settled else {
            continue;
        };
        if was.is_some() {
            continue;
        }
        let kind = match (entry.vote, outcome) {
            (Vote::Yes(_), Outcome::Commit) => Settlement::Applied,
            (Vote::Yes(_), Outcome::Abort) => Settlement::Released,
            (Vote::No, _) => Settlement::Closed,
        };
        // A decision may arrive before Begin. Preparing it later moves the
        // already held decision into a No record without another monetary effect.
        // Only this exact, unchanged Held -> Closed refinement is idempotent.
        let completes_held = kind == Settlement::Closed
            && !old.prepared.contains_key(x)
            && old.held.get(x) == Some(&outcome)
            && !new.held.contains_key(x)
            && seen.settled.get(&(inst, *x)) == Some(&(outcome, Settlement::Held));
        if seen.settled.contains_key(&(inst, *x)) && !completes_held {
            return Err(format!(
                "O-AMX: dataspace {inst} settled {} twice",
                short(x)
            ));
        }
        seen.settled.insert((inst, *x), (outcome, kind));
        seen.settle_checks.push((inst, *x, outcome));
    }
    for (x, outcome) in &new.held {
        if !old.held.contains_key(x) && !new.prepared.contains_key(x) {
            if seen
                .settled
                .insert((inst, *x), (*outcome, Settlement::Held))
                .is_some()
            {
                return Err(format!(
                    "O-AMX: dataspace {inst} settled {} twice",
                    short(x)
                ));
            }
            seen.settle_checks.push((inst, *x, *outcome));
        }
    }
    // An escrow leaves only through a settlement with `G`'s decision.
    for x in old.escrows.keys() {
        let settled_now = new
            .prepared
            .get(x)
            .is_some_and(|entry| entry.settled.is_some())
            && old
                .prepared
                .get(x)
                .is_some_and(|entry| entry.settled.is_none());
        if !new.escrows.contains_key(x) && !settled_now {
            return Err(format!(
                "O-AMX: dataspace {inst} released the escrow of {} without a decision",
                short(x)
            ));
        }
    }
    for (x, leg) in &new.escrows {
        let held = new
            .prepared
            .get(x)
            .is_some_and(|entry| matches!(entry.vote, Vote::Yes(_)) && entry.settled.is_none());
        if !held || leg.inst != inst {
            return Err(format!(
                "O-AMX: dataspace {inst} holds an escrow of {} without an unsettled Yes",
                short(x)
            ));
        }
    }
    if new.total() != old.total() {
        return Err(format!(
            "O-AMX: dataspace {inst}'s ledger total changed from {} to {}",
            old.total(),
            new.total()
        ));
    }
    check_ledger(txs, inst, old, new)
}

/// Replay a dataspace block's ledger: a new `Yes` debits its leg's source, a settled `Yes`
/// credits the leg's destination on `Commit` and its source on `Abort`, and nothing else moves
/// (signed deltas: within a block a settlement may fund a later escrow).
fn check_ledger(
    txs: &BTreeMap<Hash32, AmxTx>,
    inst: usize,
    old: &DataspaceState,
    new: &DataspaceState,
) -> Result<(), String> {
    let mut delta = BTreeMap::<u8, i128>::new();
    for (x, entry) in &new.prepared {
        let Vote::Yes(_) = entry.vote else {
            continue;
        };
        let Some(leg) = txs.get(x).and_then(|tx| tx.leg(inst)) else {
            return Err(format!(
                "O-AMX: dataspace {inst} voted Yes on unknown {}",
                short(x)
            ));
        };
        let previous = old.prepared.get(x);
        if previous.is_none() {
            *delta.entry(leg.from).or_default() -= i128::from(leg.amount);
        }
        if let Some(outcome) = entry.settled
            && previous.is_none_or(|entry| entry.settled.is_none())
        {
            let account = if outcome == Outcome::Commit {
                leg.to
            } else {
                leg.from
            };
            *delta.entry(account).or_default() += i128::from(leg.amount);
        }
    }
    let accounts: BTreeSet<u8> = old
        .balances
        .keys()
        .chain(new.balances.keys())
        .chain(delta.keys())
        .copied()
        .collect();
    if let Some(account) = accounts.into_iter().find(|account| {
        let before = old.balances.get(account).copied().unwrap_or(0);
        let after = new.balances.get(account).copied().unwrap_or(0);
        i128::from(before) + delta.get(account).copied().unwrap_or(0) != i128::from(after)
    }) {
        return Err(format!(
            "O-AMX: dataspace {inst}'s account {account} moved from {:?} to {:?}, which its \
             escrows and settlements do not explain",
            old.balances.get(&account),
            new.balances.get(&account)
        ));
    }
    Ok(())
}

/// The cross-instance checks: every `Commit` has a committed `Yes` from each participant, every
/// settlement applies `G`'s decision.
fn check_cross(seen: &mut Observed) -> Result<(), String> {
    for x in std::mem::take(&mut seen.commit_checks) {
        let Some((participants, _)) = seen.begun.get(&x) else {
            return Err(format!("O-AMX: G committed {} without a Begin", short(&x)));
        };
        if let Some(participant) = participants
            .iter()
            .find(|participant| !matches!(seen.votes.get(&(**participant, x)), Some(Vote::Yes(_))))
        {
            return Err(format!(
                "O-AMX: G committed {} without a committed Yes from dataspace {participant}",
                short(&x)
            ));
        }
    }
    for x in std::mem::take(&mut seen.abort_checks) {
        let Some((participants, _)) = seen.begun.get(&x) else {
            return Err(format!("O-AMX: G aborted {} without a Begin", short(&x)));
        };
        if !participants
            .iter()
            .any(|participant| seen.votes.get(&(*participant, x)) == Some(&Vote::No))
        {
            return Err(format!(
                "O-AMX: G aborted {} before its deadline without a committed No",
                short(&x)
            ));
        }
    }
    for (inst, x, outcome) in std::mem::take(&mut seen.settle_checks) {
        match seen.decided.get(&x) {
            Some((decided, _, _)) if *decided == outcome => {}
            other => {
                return Err(format!(
                    "O-AMX: dataspace {inst} settled {} as {outcome:?}, G decided {:?}",
                    short(&x),
                    other.map(|(decided, _, _)| decided)
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
