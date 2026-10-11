//! Named deterministic tests of the toy AMX application's rules (spec §11, §13.4 `MX*`): each
//! drives the global or a dataspace state transition, or a tracker, over genuine fake
//! certificates of synthetic blocks, and is the only guard between its mutation and the failure.

use super::*;
use crate::{
    crypto::Signer,
    message::VoteKind,
    testing::{FakeValidators, scheduled_epoch},
    types::{Bitmap, ControlWitness, ValidatorIndex},
};

/// A synthetic instance: its id and, per epoch, the epoch and a harness-held committee.
struct Chain {
    instance: Hash32,
    epochs: Vec<(EpochConfig, FakeValidators)>,
}

/// An instance with one committee of four fake keys per epoch `(first, last)`.
fn chain(tag: u8, epochs: &[(u64, u64)]) -> Chain {
    Chain {
        instance: Hash32([tag; 32]),
        epochs: epochs
            .iter()
            .enumerate()
            .map(|(index, (first, last))| {
                let index = index_u64(index);
                (
                    scheduled_epoch(index, *first, *last),
                    FakeValidators::new(4, u64::from(tag) * 100 + index, None),
                )
            })
            .collect(),
    }
}

/// An instance with one long epoch.
fn single(tag: u8) -> Chain {
    chain(tag, &[(0, 1_000)])
}

impl Chain {
    fn context(&self, epoch: usize) -> EpochContext {
        EpochContext {
            epoch: self.epochs[epoch].0,
            committee: self.epochs[epoch].1.committee.clone(),
        }
    }

    fn tracker(&self) -> Tracker {
        Tracker::new(self.instance, self.context(0))
    }

    /// A block of epoch `epoch` at `height` recording `records`, certified by a quorum of that
    /// epoch's committee; the proof proves `records[index]`.
    fn certify(
        &self,
        epoch: usize,
        height: u64,
        records: Vec<Record>,
        index: usize,
    ) -> RecordProof {
        self.certify_by(epoch, epoch, height, records, index, 3)
    }

    /// As [`Chain::certify`], but the header claims epoch `epoch` while `signers` members of
    /// epoch `signing`'s committee sign.
    fn certify_by(
        &self,
        epoch: usize,
        signing: usize,
        height: u64,
        records: Vec<Record>,
        index: usize,
        signers: ValidatorIndex,
    ) -> RecordProof {
        let config = self.epochs[epoch].0;
        let validators = &self.epochs[signing].1;
        let base = Hash32(sha256(&height.to_be_bytes()));
        let result = bind(&base, &records);
        let header = BlockHeader {
            instance: self.instance,
            epoch: config.id,
            height,
            origin_view: 0,
            parent_hash: Hash32([1; 32]),
            parent_result: Hash32([2; 32]),
            payload_hash: Hash32([3; 32]),
            availability_digest: Hash32([4; 32]),
            payload_len: 0,
            proposer: 0,
            skipped_leaders: Vec::new(),
            control_witness: ControlWitness::empty(),
        };
        let block_hash = header.hash(&validators.crypto);
        let preimage = preimage::vote_preimage(
            VoteKind::Commit,
            &self.instance,
            &config.id,
            height,
            0,
            &block_hash,
            &result,
        );
        let indices: Vec<ValidatorIndex> = (0..signers).collect();
        let signatures: Vec<_> = indices
            .iter()
            .map(|index| validators.signer(*index).sign(&preimage))
            .collect();
        let qc = Qc {
            kind: VoteKind::Commit,
            instance: self.instance,
            epoch: config.id,
            height,
            view: 0,
            block_hash,
            result,
            signers: Bitmap::from_indices(validators.committee.n(), indices.iter().copied())
                .expect("signer bitmap"),
            agg_sig: validators.crypto.aggregate(&signatures),
        };
        RecordProof {
            header,
            qc,
            base,
            records,
            index,
        }
    }

    /// The handoff proof of epoch `epoch`: its last block, recording the next epoch's context.
    fn handoff(&self, epoch: usize) -> RecordProof {
        let next = self.context(epoch + 1);
        self.certify(
            epoch,
            self.epochs[epoch].0.last_height,
            vec![Record::Epoch {
                next: next.epoch,
                committee: next.committee,
            }],
            0,
        )
    }
}

const D1: usize = 1;
const D2: usize = 2;
const D3: usize = 3;

fn crypto() -> SimCrypto {
    SimCrypto::new()
}

/// Dataspaces 1..=3 and `G`'s state tracking them.
fn global() -> (Vec<Chain>, GlobalState) {
    let dataspaces = vec![single(11), single(12), single(13)];
    let state = GlobalState {
        trackers: dataspaces
            .iter()
            .enumerate()
            .map(|(index, chain)| (index + 1, chain.tracker()))
            .collect(),
        txs: BTreeMap::new(),
    };
    (dataspaces, state)
}

fn tx(participants: &[usize], deadline: u64, nonce: u64) -> AmxTx {
    AmxTx {
        legs: participants
            .iter()
            .map(|inst| Leg {
                inst: *inst,
                from: 1,
                to: 2,
                amount: 10,
            })
            .collect(),
        deadline,
        nonce,
    }
}

/// Dataspace `participant`'s certified vote on `x`.
fn vote(dataspaces: &[Chain], participant: usize, x: Hash32, vote: Vote) -> RecordProof {
    dataspaces[participant - 1].certify(
        0,
        7,
        vec![Record::Prepared {
            x,
            participant,
            vote,
        }],
        0,
    )
}

fn begun(state: &mut GlobalState, height: u64, tx: &AmxTx) {
    let mut records = Vec::new();
    state.begin(height, tx, &mut records);
    assert_eq!(records.len(), 1, "a Begin record");
}

#[test]
fn det_amx_commit_needs_every_yes() {
    let (dataspaces, mut state) = global();
    let t = tx(&[D1, D2, D3], 50, 1);
    let x = t.id();
    begun(&mut state, 10, &t);
    let mut records = Vec::new();
    for (height, participant) in [(11, D1), (12, D2)] {
        state.vote(
            &crypto(),
            height,
            &vote(&dataspaces, participant, x, Vote::Yes(Hash32([4; 32]))),
            &mut records,
        );
        assert!(
            records.is_empty(),
            "no decision before every participant voted Yes"
        );
    }
    state.vote(
        &crypto(),
        13,
        &vote(&dataspaces, D3, x, Vote::Yes(Hash32([4; 32]))),
        &mut records,
    );
    assert_eq!(
        records,
        vec![Record::Decision {
            x,
            outcome: Outcome::Commit
        }]
    );
}

#[test]
fn det_amx_no_commit_after_deadline() {
    let (dataspaces, mut state) = global();
    let t = tx(&[D1, D2], 20, 2);
    let x = t.id();
    begun(&mut state, 10, &t);
    let mut records = Vec::new();
    state.vote(
        &crypto(),
        15,
        &vote(&dataspaces, D1, x, Vote::Yes(Hash32([4; 32]))),
        &mut records,
    );
    // The completing Yes is relayed in the first block after the deadline.
    state.vote(
        &crypto(),
        21,
        &vote(&dataspaces, D2, x, Vote::Yes(Hash32([4; 32]))),
        &mut records,
    );
    assert!(records.is_empty(), "no Commit at a height above d");
    state.expire(21, &mut records);
    assert_eq!(
        records,
        vec![Record::Decision {
            x,
            outcome: Outcome::Abort
        }]
    );
}

#[test]
fn det_amx_deadline_aborts_at_d_plus_1() {
    let (_, mut state) = global();
    let t = tx(&[D1, D2], 20, 3);
    let x = t.id();
    begun(&mut state, 10, &t);
    let mut records = Vec::new();
    state.expire(20, &mut records);
    assert!(records.is_empty(), "undecided until d");
    state.expire(21, &mut records);
    assert_eq!(
        records,
        vec![Record::Decision {
            x,
            outcome: Outcome::Abort
        }],
        "G decides by d + 1 without any proof"
    );
    assert_eq!(state.txs[&x].decided, Some(Outcome::Abort));
    // One immutable decision: nothing later changes it.
    records.clear();
    state.expire(22, &mut records);
    assert!(records.is_empty());
}

#[test]
fn det_amx_second_begin_rejected() {
    let (dataspaces, mut state) = global();
    let t = tx(&[D1, D2], 40, 4);
    let x = t.id();
    begun(&mut state, 10, &t);
    let mut records = Vec::new();
    state.vote(
        &crypto(),
        11,
        &vote(&dataspaces, D1, x, Vote::Yes(Hash32([4; 32]))),
        &mut records,
    );
    state.begin(12, &t, &mut records);
    assert!(records.is_empty(), "a second Begin for x records nothing");
    assert!(state.txs[&x].yes.contains(&D1), "the recorded vote stays");
    // Begins outside the window or naming an unregistered participant are rejected too.
    for bad in [
        tx(&[D1, D2], 12, 5),
        tx(&[D1, D2], 13 + MAX_WINDOW, 6),
        tx(&[D1, 9], 40, 7),
    ] {
        state.begin(12, &bad, &mut records);
    }
    assert!(records.is_empty());
}

#[test]
fn det_amx_forged_vote_rejected() {
    let (dataspaces, mut state) = global();
    let t = tx(&[D1, D2], 40, 8);
    let x = t.id();
    begun(&mut state, 10, &t);
    let mut records = Vec::new();
    // D1's No, but certified by D2's committee, or by fewer than a quorum of D1's.
    let foreign = dataspaces[D2 - 1].certify(
        0,
        7,
        vec![Record::Prepared {
            x,
            participant: D1,
            vote: Vote::No,
        }],
        0,
    );
    let mut stolen = foreign.clone();
    stolen.header.instance = dataspaces[D1 - 1].instance;
    let short = dataspaces[D1 - 1].certify_by(
        0,
        0,
        7,
        vec![Record::Prepared {
            x,
            participant: D1,
            vote: Vote::No,
        }],
        0,
        2,
    );
    for proof in [&foreign, &stolen, &short] {
        state.vote(&crypto(), 11, proof, &mut records);
    }
    assert!(
        records.is_empty(),
        "a vote counts only with a verified proof"
    );
    assert_eq!(state.txs[&x].decided, None);
}

#[test]
fn det_amx_record_bound_to_result() {
    let (dataspaces, mut state) = global();
    let t = tx(&[D1, D2], 40, 9);
    let x = t.id();
    begun(&mut state, 10, &t);
    let mut records = Vec::new();
    // A genuine Yes whose disclosed record list was rewritten to a No.
    let mut rewritten = vote(&dataspaces, D1, x, Vote::Yes(Hash32([4; 32])));
    rewritten.records[0] = Record::Prepared {
        x,
        participant: D1,
        vote: Vote::No,
    };
    assert_eq!(
        state.trackers[&D1].verify(&crypto(), &rewritten),
        Err(ProofError::Result)
    );
    state.vote(&crypto(), 11, &rewritten, &mut records);
    assert!(records.is_empty(), "the rewritten record is not certified");
    // An index outside the disclosed records proves nothing.
    let mut outside = vote(&dataspaces, D1, x, Vote::No);
    outside.index = 1;
    assert_eq!(
        state.trackers[&D1].verify(&crypto(), &outside),
        Err(ProofError::Index)
    );
}

/// A dataspace (instance `D1`) tracking `global`, with accounts 1 and 2 holding 100 each.
fn dataspace(global: &Chain) -> DataspaceState {
    DataspaceState {
        me: D1,
        global: global.tracker(),
        global_height: 0,
        prepared: BTreeMap::new(),
        held: BTreeMap::new(),
        balances: [(1, 100), (2, 100)].into_iter().collect(),
        escrows: BTreeMap::new(),
    }
}

fn begin_proof(global: &Chain, t: &AmxTx, height: u64) -> RecordProof {
    global.certify(
        0,
        height,
        vec![Record::Begin {
            x: t.id(),
            participants: t.participants(),
            deadline: t.deadline,
        }],
        0,
    )
}

fn decision_proof(global: &Chain, x: Hash32, outcome: Outcome, height: u64) -> RecordProof {
    global.certify(0, height, vec![Record::Decision { x, outcome }], 0)
}

fn prepare(state: &mut DataspaceState, global: &Chain, t: &AmxTx) -> Vec<Record> {
    let mut records = Vec::new();
    state.prepare(&crypto(), t, &begin_proof(global, t, 5), &mut records);
    records
}

#[test]
fn det_amx_prepare_once() {
    let g = single(1);
    let mut state = dataspace(&g);
    let t = tx(&[D1, D2], 40, 10);
    let records = prepare(&mut state, &g, &t);
    assert!(matches!(
        records.as_slice(),
        [Record::Prepared {
            vote: Vote::Yes(_),
            ..
        }]
    ));
    assert_eq!(state.balances[&1], 90);
    assert!(
        prepare(&mut state, &g, &t).is_empty(),
        "a second inclusion of x is rejected"
    );
    assert_eq!(state.balances[&1], 90, "escrowed once");
    assert_eq!(state.total(), 200);
    // A Begin certified by another instance, or of another transaction, prepares nothing.
    let other = tx(&[D1, D2], 40, 11);
    let mut records = Vec::new();
    state.prepare(
        &crypto(),
        &other,
        &begin_proof(&single(2), &other, 5),
        &mut records,
    );
    state.prepare(&crypto(), &other, &begin_proof(&g, &t, 5), &mut records);
    assert!(records.is_empty());
}

#[test]
fn det_amx_held_decision_votes_no() {
    let g = single(1);
    let mut state = dataspace(&g);
    let t = tx(&[D1, D2], 40, 12);
    let x = t.id();
    // G aborted x (another participant's No) before this dataspace prepared it.
    state.settle(&crypto(), &decision_proof(&g, x, Outcome::Abort, 12));
    assert_eq!(state.held.get(&x), Some(&Outcome::Abort));
    let records = prepare(&mut state, &g, &t);
    assert_eq!(
        records,
        vec![Record::Prepared {
            x,
            participant: D1,
            vote: Vote::No
        }]
    );
    assert!(state.escrows.is_empty(), "nothing escrowed");
    assert_eq!(state.balances[&1], 100);
    assert_eq!(state.prepared[&x].settled, Some(Outcome::Abort));
    assert!(state.held.is_empty());
}

#[test]
fn det_amx_oracle_held_decision_then_no_is_one_settlement() {
    let g = single(1);
    let initial = dataspace(&g);
    let t = tx(&[D1, D2], 40, 12);
    let x = t.id();
    let txs = [(x, t.clone())].into_iter().collect();
    let mut seen = Observed::default();
    let mut held = initial.clone();
    held.settle(&crypto(), &decision_proof(&g, x, Outcome::Abort, 12));
    observe_dataspace(&mut seen, &txs, D1, &initial, &held).unwrap();
    assert_eq!(seen.settled[&(D1, x)], (Outcome::Abort, Settlement::Held));
    let mut prepared = held.clone();
    prepare(&mut prepared, &g, &t);
    observe_dataspace(&mut seen, &txs, D1, &held, &prepared).unwrap();
    assert_eq!(seen.settled.len(), 1);
    assert_eq!(seen.settled[&(D1, x)], (Outcome::Abort, Settlement::Closed));
    assert_eq!(prepared.balances, initial.balances);
    assert!(prepared.escrows.is_empty());
    observe_dataspace(&mut seen, &txs, D1, &prepared, &prepared).unwrap();

    // Recreating a settlement without its original held decision is still a
    // duplicate; changing the held decision is also rejected independently.
    assert!(observe_dataspace(&mut seen.clone(), &txs, D1, &initial, &prepared).is_err());
    let mut wrong_held = held.clone();
    wrong_held.held.insert(x, Outcome::Commit);
    assert!(observe_dataspace(&mut seen, &txs, D1, &wrong_held, &prepared).is_err());
}

#[test]
fn det_amx_settle_follows_decision() {
    let g = single(1);
    let mut state = dataspace(&g);
    let committed = tx(&[D1, D2], 40, 13);
    let aborted = tx(&[D1, D2], 40, 14);
    prepare(&mut state, &g, &committed);
    prepare(&mut state, &g, &aborted);
    assert_eq!((state.balances[&1], state.balances[&2]), (80, 100));
    state.settle(
        &crypto(),
        &decision_proof(&g, committed.id(), Outcome::Commit, 20),
    );
    state.settle(
        &crypto(),
        &decision_proof(&g, aborted.id(), Outcome::Abort, 21),
    );
    assert_eq!(
        (state.balances[&1], state.balances[&2]),
        (90, 110),
        "Commit applies the leg, Abort restores it"
    );
    assert!(state.escrows.is_empty());
    // Exactly once: a replayed decision changes nothing.
    state.settle(
        &crypto(),
        &decision_proof(&g, committed.id(), Outcome::Commit, 22),
    );
    assert_eq!((state.balances[&1], state.balances[&2]), (90, 110));
    assert_eq!(state.total(), 200);
}

#[test]
fn det_amx_no_release_without_abort_proof() {
    let g = single(1);
    let mut state = dataspace(&g);
    let t = tx(&[D1, D2], 20, 15);
    let x = t.id();
    prepare(&mut state, &g, &t);
    assert_eq!(state.balances[&1], 90);
    // The dataspace verifies a global block far beyond d (another transaction's decision):
    // its Yes escrow stays, as does a forged Abort of x.
    state.settle(
        &crypto(),
        &decision_proof(&g, Hash32([9; 32]), Outcome::Abort, 30),
    );
    state.settle(
        &crypto(),
        &decision_proof(&single(2), x, Outcome::Abort, 31),
    );
    assert_eq!(state.global_height, 30);
    assert_eq!(state.balances[&1], 90, "no release without G's Abort");
    assert!(state.escrows.contains_key(&x));
    assert_eq!(state.prepared[&x].settled, None);
    state.settle(&crypto(), &decision_proof(&g, x, Outcome::Abort, 32));
    assert_eq!(state.balances[&1], 100);
    assert!(state.escrows.is_empty());
    // After the verified global height passed d no Prepare of a transaction follows.
    let late = tx(&[D1, D2], 25, 16);
    assert!(prepare(&mut state, &g, &late).is_empty());
}

/// A chain with three epochs and a new committee in each.
fn epochs() -> Chain {
    chain(5, &[(0, 9), (10, 19), (20, 1_000)])
}

#[test]
fn det_amx_tracker_epoch_window() {
    let chain = epochs();
    let mut tracker = chain.tracker();
    let crypto = crypto();
    let record = || {
        vec![Record::Decision {
            x: Hash32([6; 32]),
            outcome: Outcome::Abort,
        }]
    };
    tracker
        .verify(&crypto, &chain.certify(0, 5, record(), 0))
        .expect("epoch 0 verifies");
    // Epoch 0's committee certifies no height of a later epoch, under either epoch's id.
    assert_eq!(
        tracker.verify(&crypto, &chain.certify_by(0, 0, 12, record(), 0, 3)),
        Err(ProofError::Epoch)
    );
    assert_eq!(
        tracker.verify(&crypto, &chain.certify(1, 12, record(), 0)),
        Err(ProofError::Epoch),
        "epoch 1 waits for its handoff"
    );
    assert_eq!(tracker.handoff(&crypto, &chain.handoff(0)), Ok(true));
    assert_eq!(tracker.epoch(), 1);
    tracker
        .verify(&crypto, &chain.certify(1, 12, record(), 0))
        .expect("epoch 1 verifies after its handoff");
    assert_eq!(
        tracker.verify(&crypto, &chain.certify_by(1, 0, 12, record(), 0, 3)),
        Err(ProofError::Certificate),
        "a removed committee cannot certify epoch 1"
    );
    assert_eq!(
        tracker.verify(&crypto, &chain.certify(2, 25, record(), 0)),
        Err(ProofError::Epoch)
    );
}

#[test]
fn det_amx_handoff_keeps_previous_epoch() {
    let chain = epochs();
    let mut tracker = chain.tracker();
    let crypto = crypto();
    let late = chain.certify(
        0,
        8,
        vec![Record::Decision {
            x: Hash32([6; 32]),
            outcome: Outcome::Commit,
        }],
        0,
    );
    // A handoff must follow the sequence: epoch 1's handoff before epoch 0's is not verifiable,
    // and a non-final block of epoch 0 hands nothing off.
    assert_eq!(
        tracker.handoff(&crypto, &chain.handoff(1)),
        Err(ProofError::Epoch)
    );
    let next = chain.context(1);
    let early = chain.certify(
        0,
        8,
        vec![Record::Epoch {
            next: next.epoch,
            committee: next.committee,
        }],
        0,
    );
    assert_eq!(tracker.handoff(&crypto, &early), Err(ProofError::Handoff));
    assert_eq!(tracker.handoff(&crypto, &chain.handoff(0)), Ok(true));
    // `C_{e−1}` is kept: a record of epoch 0 relayed after the handoff still verifies.
    assert_eq!(tracker.verify(&crypto, &late), Ok(8));
    assert_eq!(
        tracker.handoff(&crypto, &chain.handoff(0)),
        Ok(false),
        "a replayed handoff is stale"
    );
    assert_eq!(tracker.handoff(&crypto, &chain.handoff(1)), Ok(true));
    assert_eq!(tracker.epoch(), 2);
    assert_eq!(
        tracker.verify(&crypto, &late),
        Err(ProofError::Epoch),
        "epoch 0 left the window"
    );
}

#[test]
fn amx_result_binds_every_record_in_order() {
    let base = Hash32([1; 32]);
    let a = Record::Decision {
        x: Hash32([2; 32]),
        outcome: Outcome::Commit,
    };
    let b = Record::Prepared {
        x: Hash32([2; 32]),
        participant: 1,
        vote: Vote::Yes(Hash32([3; 32])),
    };
    let both = bind(&base, &[a.clone(), b.clone()]);
    assert_ne!(both, bind(&base, &[b.clone(), a.clone()]));
    assert_ne!(both, bind(&base, std::slice::from_ref(&a)));
    assert_ne!(both, bind(&Hash32([9; 32]), &[a.clone(), b]));
    assert_ne!(
        bind(&base, &[]),
        base,
        "the result always binds the record list"
    );
    let t = tx(&[D1, D2], 30, 1);
    let mut changed = t.clone();
    changed.legs[1].amount += 1;
    assert_ne!(t.id(), changed.id());
    assert!(t.well_formed());
    assert!(!tx(&[D1], 30, 1).well_formed());
    assert!(!tx(&[D2, D1], 30, 1).well_formed());
    assert!(!tx(&[GLOBAL, D1], 30, 1).well_formed());
}
