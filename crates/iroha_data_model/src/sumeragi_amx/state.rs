//! The global chain's AMX World state and its deterministic transitions (§11.2, §11.4, §11.5,
//! §11.7).
//!
//! Every transition is a pure function of the committed state, the executing height and its
//! input, so every honest validator records the same writes. The executor (in the node) calls
//! them from the AMX instructions and, after every block's transactions, [`SumeragiAmxState::expire`];
//! returned or visited records are the World writes of the block.

use iroha_model_base::topology::DataSpaceId;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    AmxBeginV1, AmxDecisionV1, AmxError, AmxForeignInstanceV1, AmxHandoffOutcome,
    AmxHandoffProofV1, AmxOutcomeV1, AmxRecordProofV1, AmxRecordV1, AmxTransactionV1, AmxVoteV1,
    MAX_AMX_DATASPACES, MAX_AMX_DEADLINE_WINDOW, MAX_AMX_PENDING,
};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};

/// A participant dataspace registered with the global chain and its foreign-committee tracker.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxDataspaceV1")]
pub struct AmxDataspaceV1 {
    /// The dataspace.
    pub dataspace: DataSpaceId,
    /// The committees of its consensus instance, as far as handoffs were relayed.
    pub tracker: AmxForeignInstanceV1,
}

/// A verified `Yes` vote.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxYesV1")]
pub struct AmxYesV1 {
    /// The voting participant.
    pub participant: DataSpaceId,
    /// Hash of its escrowed effects.
    pub effects_hash: [u8; 32],
}

/// The decision of a transaction and the height of the block that recorded it.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxDecidedV1")]
pub struct AmxDecidedV1 {
    /// The decision.
    pub outcome: AmxOutcomeV1,
    /// Height of the block that recorded it.
    pub height: u64,
}

/// A transaction the global chain knows: from its `Begin` until the first block after its
/// deadline, which decides it if nothing did before and then drops it.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxGlobalEntryV1")]
pub struct AmxGlobalEntryV1 {
    /// The recorded `Begin`.
    pub begin: AmxBeginV1,
    /// Height of the block that recorded it (`b < d`).
    pub begun_at: u64,
    /// Verified `Yes` votes, ascending by participant.
    pub yes: Vec<AmxYesV1>,
    /// The immutable decision, once recorded.
    #[norito(required)]
    pub decided: Option<AmxDecidedV1>,
}

/// What relaying a `Prepared` proof did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmxRelayOutcome {
    /// The transaction is unknown (never begun or past its deadline), already decided, or the
    /// participant's vote is already recorded: later proofs are ignored (§11.5).
    Ignored,
    /// A `Yes` was recorded; the transaction still waits for other votes.
    Voted,
    /// The vote decided the transaction; the decision is a record of this block.
    Decided(AmxDecisionV1),
}

/// The global chain's AMX World state: registered participant dataspaces, ascending, and the
/// transactions whose deadline has not passed, ascending by id.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::SumeragiAmxState")]
pub struct SumeragiAmxState {
    /// Registered participant dataspaces, strictly ascending.
    pub dataspaces: Vec<AmxDataspaceV1>,
    /// Known transactions, strictly ascending by id.
    pub transactions: Vec<AmxGlobalEntryV1>,
}

fn rejected(reason: &'static str) -> AmxError {
    AmxError::State(reason)
}

impl SumeragiAmxState {
    /// The registration of `dataspace`.
    #[must_use]
    pub fn dataspace(&self, dataspace: DataSpaceId) -> Option<&AmxDataspaceV1> {
        self.dataspaces
            .binary_search_by_key(&dataspace, |entry| entry.dataspace)
            .ok()
            .map(|index| &self.dataspaces[index])
    }

    /// The known transaction `tx`.
    #[must_use]
    pub fn transaction(&self, tx: &[u8; 32]) -> Option<&AmxGlobalEntryV1> {
        self.transactions
            .binary_search_by(|entry| entry.begin.tx.cmp(tx))
            .ok()
            .map(|index| &self.transactions[index])
    }

    /// Check the stored invariants (a restored snapshot must satisfy them).
    ///
    /// # Errors
    /// The first violated invariant.
    pub fn validate(&self) -> Result<(), AmxError> {
        if self.dataspaces.len() > MAX_AMX_DATASPACES || self.transactions.len() > MAX_AMX_PENDING {
            return Err(rejected("state exceeds its bounds"));
        }
        if self
            .dataspaces
            .windows(2)
            .any(|pair| pair[0].dataspace >= pair[1].dataspace)
            || self
                .transactions
                .windows(2)
                .any(|pair| pair[0].begin.tx >= pair[1].begin.tx)
        {
            return Err(rejected("state entries are not strictly ascending"));
        }
        for entry in &self.dataspaces {
            entry.tracker.validate()?;
        }
        for entry in &self.transactions {
            entry.begin.validate()?;
            if entry.begun_at >= entry.begin.deadline
                || entry.begin.deadline - entry.begun_at > MAX_AMX_DEADLINE_WINDOW
                || entry
                    .begin
                    .participants
                    .iter()
                    .any(|participant| self.dataspace(*participant).is_none())
                || entry
                    .yes
                    .windows(2)
                    .any(|pair| pair[0].participant >= pair[1].participant)
                || entry
                    .yes
                    .iter()
                    .any(|yes| !entry.begin.has_participant(yes.participant))
                || entry.decided.is_some_and(|decided| {
                    decided.height < entry.begun_at
                        || (decided.outcome == AmxOutcomeV1::Commit
                            && (entry.yes.len() != entry.begin.participants.len()
                                || decided.height > entry.begin.deadline))
                })
            {
                return Err(rejected("transaction entry breaks its invariants"));
            }
        }
        Ok(())
    }

    /// Register a participant dataspace with its tracker, anchored at an independently
    /// authenticated epoch context.
    ///
    /// # Errors
    /// The dataspace is already registered or the registry is full.
    pub fn register_dataspace(
        &mut self,
        dataspace: DataSpaceId,
        tracker: AmxForeignInstanceV1,
    ) -> Result<(), AmxError> {
        tracker.validate()?;
        let Err(index) = self
            .dataspaces
            .binary_search_by_key(&dataspace, |entry| entry.dataspace)
        else {
            return Err(rejected("the dataspace is already registered"));
        };
        if self.dataspaces.len() >= MAX_AMX_DATASPACES {
            return Err(rejected("the dataspace registry is full"));
        }
        self.dataspaces
            .insert(index, AmxDataspaceV1 { dataspace, tracker });
        Ok(())
    }

    /// Record `Begin{x, participants, d}` of `transaction` at height `height` (§11.2).
    ///
    /// # Errors
    /// A malformed transaction, an unregistered participant, a deadline not in
    /// `(height, height + MAX_AMX_DEADLINE_WINDOW]`, a transaction the state already knows (a
    /// second `Begin` for `x`), or a full state.
    pub fn begin(
        &mut self,
        height: u64,
        transaction: &AmxTransactionV1,
    ) -> Result<AmxRecordV1, AmxError> {
        let begin = transaction.begin()?;
        if begin.deadline <= height || begin.deadline - height > MAX_AMX_DEADLINE_WINDOW {
            return Err(rejected("the deadline is not within the admitted window"));
        }
        if begin
            .participants
            .iter()
            .any(|participant| self.dataspace(*participant).is_none())
        {
            return Err(rejected("a participant dataspace is not registered"));
        }
        let Err(index) = self
            .transactions
            .binary_search_by(|entry| entry.begin.tx.cmp(&begin.tx))
        else {
            return Err(rejected("the transaction was already begun"));
        };
        if self.transactions.len() >= MAX_AMX_PENDING {
            return Err(rejected("too many pending transactions"));
        }
        self.transactions.insert(
            index,
            AmxGlobalEntryV1 {
                begin: begin.clone(),
                begun_at: height,
                yes: Vec::new(),
                decided: None,
            },
        );
        Ok(AmxRecordV1::Begin(begin))
    }

    /// Relay a participant's `Prepared` proof at height `height` (§11.4, §11.5): verified with
    /// the participant's tracker, a `No` decides `Abort`; the `Yes` that completes the vote at a
    /// height `≤ d` decides `Commit`. Proofs for unknown or decided transactions and repeated
    /// votes are ignored.
    ///
    /// # Errors
    /// The proof carries no `Prepared` record, its voter is not a participant, or it does not
    /// verify.
    pub fn relay_prepared(
        &mut self,
        height: u64,
        proof: &AmxRecordProofV1,
    ) -> Result<AmxRelayOutcome, AmxError> {
        let AmxRecordV1::Prepared(prepared) = &proof.record else {
            return Err(AmxError::Record("a relayed vote must be a Prepared record"));
        };
        let Ok(index) = self
            .transactions
            .binary_search_by(|entry| entry.begin.tx.cmp(&prepared.tx))
        else {
            return Ok(AmxRelayOutcome::Ignored);
        };
        let entry = &self.transactions[index];
        if entry.decided.is_some() {
            return Ok(AmxRelayOutcome::Ignored);
        }
        if !entry.begin.has_participant(prepared.participant) {
            return Err(rejected("the voter is not a participant"));
        }
        let Err(slot) = entry
            .yes
            .binary_search_by_key(&prepared.participant, |yes| yes.participant)
        else {
            return Ok(AmxRelayOutcome::Ignored);
        };
        self.dataspace(prepared.participant)
            .ok_or_else(|| rejected("the voter is not registered"))?
            .tracker
            .verify_record(proof)?;
        let entry = &mut self.transactions[index];
        let outcome = match prepared.vote {
            AmxVoteV1::No => AmxOutcomeV1::Abort,
            AmxVoteV1::Yes(effects_hash) => {
                entry.yes.insert(
                    slot,
                    AmxYesV1 {
                        participant: prepared.participant,
                        effects_hash,
                    },
                );
                if entry.yes.len() < entry.begin.participants.len() || height > entry.begin.deadline
                {
                    return Ok(AmxRelayOutcome::Voted);
                }
                AmxOutcomeV1::Commit
            }
        };
        entry.decided = Some(AmxDecidedV1 { outcome, height });
        Ok(AmxRelayOutcome::Decided(AmxDecisionV1 {
            tx: entry.begin.tx,
            outcome,
        }))
    }

    /// Relay a handoff proof of `dataspace`'s instance (§11.7).
    ///
    /// # Errors
    /// The dataspace is not registered or the proof does not verify.
    pub fn relay_handoff(
        &mut self,
        dataspace: DataSpaceId,
        proof: &AmxHandoffProofV1,
    ) -> Result<AmxHandoffOutcome, AmxError> {
        let index = self
            .dataspaces
            .binary_search_by_key(&dataspace, |entry| entry.dataspace)
            .map_err(|_| rejected("the dataspace is not registered"))?;
        self.dataspaces[index].tracker.apply_handoff(proof)
    }

    /// The deadline step of the block at `height`, after its transactions (§11.5): every known
    /// transaction whose deadline passed and that has no decision emits its Abort record,
    /// then every transaction whose deadline passed is dropped. A `Begin` must precede its
    /// deadline, so a dropped id is never begun again. No temporary decision vector is built.
    ///
    /// All records must be accepted before this state changes. On refusal the callback may
    /// already have observed an earlier record; it must discard that provisional output or
    /// accept the same keyed record again when retrying this unchanged source.
    ///
    /// # Errors
    /// Returns the callback's original error without pruning or changing any pending entry.
    pub fn expire<E>(
        &mut self,
        height: u64,
        mut record: impl FnMut(AmxDecisionV1) -> Result<(), E>,
    ) -> Result<usize, E> {
        let mut decisions = 0;
        for entry in &mut self.transactions {
            if entry.begin.deadline < height && entry.decided.is_none() {
                #[cfg(all(test, sumeragi_model_mutation = "DM8"))]
                {
                    entry.decided = Some(AmxDecidedV1 {
                        outcome: AmxOutcomeV1::Abort,
                        height,
                    });
                }
                record(AmxDecisionV1 {
                    tx: entry.begin.tx,
                    outcome: AmxOutcomeV1::Abort,
                })?;
                decisions += 1;
            }
        }
        self.transactions
            .retain(|entry| entry.begin.deadline >= height);
        Ok(decisions)
    }
}
