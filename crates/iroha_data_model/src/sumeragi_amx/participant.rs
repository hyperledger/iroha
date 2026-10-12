//! The participant (dataspace) side of AMX (§11.3, §11.6, §11.7): the dataspace's AMX World
//! state and its deterministic transitions over an explicit escrow interface ([`AmxEscrow`]),
//! which the dataspace's executor implements over its own World.
//!
//! **Prepare.** A participant includes `X` with a proof of the global chain's `Begin`. Execution
//! verifies the proof with the participant's tracker of the global instance, rejects a second
//! inclusion of `x`, and either escrows the state its leg touches (`Yes` with the effects hash) or
//! records `No`. It records `No` and escrows nothing when it already holds the global decision
//! for `x`. A `Prepare` after the deadline is rejected once the participant has verified a global
//! block beyond it: the global chain has then decided `x`, and without this vote only `Abort`.
//!
//! **Settle.** A later block includes the decision proof; execution applies (`Commit`) or releases
//! (`Abort`) a `Yes` escrow exactly once. **This is the only way a `Yes` escrow is released**: no
//! local timeout and no operator action. A decision for a transaction the participant has not
//! prepared is held, so a later `Prepare` of it records `No`.
//!
//! **Bounds.** Entries leave the state once the participant has verified a global block beyond
//! the transaction's deadline (prepared entries, except an unsettled `Yes` escrow, which only its
//! decision proof closes) or beyond the decision's height plus [`MAX_AMX_DEADLINE_WINDOW`] (held
//! decisions): no valid `Prepare` of such a transaction can follow, because the global chain
//! decided it by `d + 1` and `d` is at most the window after its `Begin`. A decision proof of a
//! dropped entry is then only held.

use iroha_model_base::topology::DataSpaceId;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    AmxDecisionV1, AmxError, AmxForeignInstanceV1, AmxHandoffOutcome, AmxHandoffProofV1, AmxLegV1,
    AmxOutcomeV1, AmxPreparedV1, AmxRecordProofV1, AmxRecordV1, AmxTransactionV1, AmxVoteV1,
    MAX_AMX_DEADLINE_WINDOW, MAX_AMX_PENDING,
};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};

/// The dataspace executor's side of AMX: escrow, apply and release a leg's effects.
///
/// Implementations are deterministic functions of the dataspace's committed state and must be
/// atomic per call: every error leaves its ledger and original retained owners unchanged.
/// Local resource refusal is an error, never a protocol `No` vote or successful settlement.
pub trait AmxEscrow {
    /// The host's typed failure, retaining resource refusal separately from invalid input.
    type Error;

    /// Escrow (lock) the state `leg` of transaction `tx` touches and return the hash of the
    /// escrowed effects, or `None` if the leg cannot be escrowed (the vote is `No`).
    ///
    /// # Errors
    /// A local host failure leaves the ledger unchanged and must not become a `No` vote.
    fn escrow(&mut self, tx: &[u8; 32], leg: &AmxLegV1) -> Result<Option<[u8; 32]>, Self::Error>;
    /// Apply the escrowed effects of `tx`: the global chain committed it.
    ///
    /// # Errors
    /// A local host failure preserves the original escrow for the same decision to retry.
    fn apply(&mut self, tx: &[u8; 32]) -> Result<(), Self::Error>;
    /// Release the escrow of `tx`, restoring the touched state: the global chain aborted it.
    ///
    /// # Errors
    /// A local host failure preserves the original escrow for the same decision to retry.
    fn release(&mut self, tx: &[u8; 32]) -> Result<(), Self::Error>;
}

/// A rejected AMX proof/transition or an unchanged escrow operation to retry at the host.
/// This runtime error is not a wire value and does not change the AMX record layout.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AmxParticipantError<E> {
    /// The protocol input or participant state rejected the requested transition.
    #[error(transparent)]
    Protocol(AmxError),
    /// A local proof decoder refused before changing escrow or participant state.
    #[error("local AMX participant decoder resource refusal: {0}")]
    Resource(norito::core::DecodeResourceError),
    /// The host refused without changing escrow or participant state.
    #[error("AMX escrow operation failed: {0}")]
    Escrow(E),
}

impl<E> From<AmxError> for AmxParticipantError<E> {
    fn from(error: AmxError) -> Self {
        match error {
            AmxError::Resource(resource) => Self::Resource(resource),
            other => Self::Protocol(other),
        }
    }
}

/// A prepared transaction: its deadline, this participant's vote and, once settled, the global
/// decision.
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
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxPreparedEntryV1")]
pub struct AmxPreparedEntryV1 {
    /// Transaction id `x`.
    #[norito(
        with = "crate::json_helpers::fixed_bytes_hex",
        bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
    )]
    pub tx: [u8; 32],
    /// Global deadline height `d`.
    pub deadline: u64,
    /// This participant's recorded vote.
    pub vote: AmxVoteV1,
    /// The applied global decision, once settled.
    #[norito(required)]
    pub settled: Option<AmxOutcomeV1>,
}

/// A global decision held for a transaction this participant has not prepared.
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
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxHeldDecisionV1")]
pub struct AmxHeldDecisionV1 {
    /// The decision.
    pub decision: AmxDecisionV1,
    /// Global height of the block that recorded it.
    pub height: u64,
}

/// What settling a decision did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmxSettleOutcome {
    /// The `Yes` escrow was applied.
    Applied,
    /// The `Yes` escrow was released.
    Released,
    /// The participant voted `No`: nothing was escrowed.
    Closed,
    /// The transaction is not prepared here: the decision is held for a later `Prepare`.
    Held,
}

/// A participant dataspace's AMX World state.
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
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxParticipantStateV1")]
pub struct AmxParticipantStateV1 {
    /// This dataspace.
    pub dataspace: DataSpaceId,
    /// The tracked committees of the global chain's instance.
    pub global: AmxForeignInstanceV1,
    /// Highest global height of a verified global block.
    pub global_height: u64,
    /// Prepared transactions (`prepared_Di`, settled ones carry their decision), ascending.
    pub prepared: Vec<AmxPreparedEntryV1>,
    /// Decisions held for transactions not prepared here, ascending by transaction.
    pub held: Vec<AmxHeldDecisionV1>,
}

fn rejected(reason: &'static str) -> AmxError {
    AmxError::State(reason)
}

impl AmxParticipantStateV1 {
    /// A participant with no AMX history, tracking the global chain from `global`.
    #[must_use]
    pub fn new(dataspace: DataSpaceId, global: AmxForeignInstanceV1) -> Self {
        Self {
            dataspace,
            global,
            global_height: 0,
            prepared: Vec::new(),
            held: Vec::new(),
        }
    }

    /// The prepared entry of `tx`.
    #[must_use]
    pub fn entry(&self, tx: &[u8; 32]) -> Option<&AmxPreparedEntryV1> {
        self.prepared
            .binary_search_by(|entry| entry.tx.cmp(tx))
            .ok()
            .map(|index| &self.prepared[index])
    }

    /// Check the stored invariants.
    ///
    /// # Errors
    /// The first violated invariant.
    pub fn validate(&self) -> Result<(), AmxError> {
        self.global.validate()?;
        if self.prepared.len() > MAX_AMX_PENDING || self.held.len() > MAX_AMX_PENDING {
            return Err(rejected("participant state exceeds its bounds"));
        }
        if self
            .prepared
            .windows(2)
            .any(|pair| pair[0].tx >= pair[1].tx)
            || self
                .held
                .windows(2)
                .any(|pair| pair[0].decision.tx >= pair[1].decision.tx)
            || self
                .held
                .iter()
                .any(|held| self.entry(&held.decision.tx).is_some())
        {
            return Err(rejected("participant entries are not strictly ascending"));
        }
        Ok(())
    }

    /// Prepare `transaction` with the proof of its `Begin` (§11.3); the returned `Prepared`
    /// record is a World write of the executing block.
    ///
    /// # Errors
    /// The proof is not a verified `Begin` of this transaction naming this participant, the
    /// transaction was already prepared (a second inclusion), its deadline is behind a verified
    /// global block, the state is full, or the host refused escrow without changing state.
    pub fn prepare<E: AmxEscrow>(
        &mut self,
        escrow: &mut E,
        transaction: &AmxTransactionV1,
        begin: &AmxRecordProofV1,
    ) -> Result<AmxRecordV1, AmxParticipantError<E::Error>> {
        let AmxRecordV1::Begin(record) = &begin.record else {
            return Err(AmxError::Record("a Prepare needs a Begin proof").into());
        };
        if !record.matches(transaction) {
            return Err(AmxError::Record("the Begin is not this transaction's").into());
        }
        let leg = transaction
            .leg(self.dataspace)
            .ok_or_else(|| rejected("this dataspace is not a participant"))?;
        let verified = self.global.verify_record(
            begin,
            crate::sumeragi_finality::CertifiedResultScope::TairaGlobal,
        )?;
        let Err(index) = self
            .prepared
            .binary_search_by(|entry| entry.tx.cmp(&record.tx))
        else {
            return Err(rejected("the transaction was already prepared").into());
        };
        let global_height = self.global_height.max(verified.height);
        if record.deadline < global_height {
            return Err(rejected("the transaction is past its deadline").into());
        }
        if self.prepared.len() >= MAX_AMX_PENDING {
            return Err(rejected("too many prepared transactions").into());
        }
        let held = self
            .held
            .binary_search_by(|held| held.decision.tx.cmp(&record.tx))
            .ok();
        let vote = if held.is_some() {
            AmxVoteV1::No
        } else {
            escrow
                .escrow(&record.tx, leg)
                .map_err(AmxParticipantError::Escrow)?
                .map_or(AmxVoteV1::No, AmxVoteV1::Yes)
        };
        let held = held.map(|slot| self.held.remove(slot));
        // TODO(S6): native participant installation must prepay this bounded state's graph
        // before calling the escrow host; ordinary Vec allocation is not original-pool custody.
        self.prepared.insert(
            index,
            AmxPreparedEntryV1 {
                tx: record.tx,
                deadline: record.deadline,
                vote,
                settled: held.map(|held| held.decision.outcome),
            },
        );
        self.observe(global_height);
        Ok(AmxRecordV1::Prepared(AmxPreparedV1 {
            tx: record.tx,
            participant: self.dataspace,
            vote,
        }))
    }

    /// Settle with the proof of the global decision (§11.6): a `Yes` escrow is applied on
    /// `Commit` and released on `Abort`, exactly once.
    ///
    /// # Errors
    /// The proof is not a verified `Decision`, the transaction is already settled or its
    /// decision already held, the held decisions are full, or the host refused settlement.
    /// A host error keeps the original prepared entry and verified-height cursor unchanged.
    pub fn settle<E: AmxEscrow>(
        &mut self,
        escrow: &mut E,
        decision: &AmxRecordProofV1,
    ) -> Result<AmxSettleOutcome, AmxParticipantError<E::Error>> {
        let AmxRecordV1::Decision(record) = &decision.record else {
            return Err(AmxError::Record("a settlement needs a Decision proof").into());
        };
        let verified = self.global.verify_record(
            decision,
            crate::sumeragi_finality::CertifiedResultScope::TairaGlobal,
        )?;
        let outcome = match self
            .prepared
            .binary_search_by(|entry| entry.tx.cmp(&record.tx))
        {
            Ok(index) => self.settle_prepared(escrow, index, record)?,
            Err(_) => self.hold(*record, verified.height)?,
        };
        self.observe(verified.height);
        Ok(outcome)
    }

    /// Settle the prepared entry at `index` with `decision`: apply or release a `Yes` escrow.
    fn settle_prepared<E: AmxEscrow>(
        &mut self,
        escrow: &mut E,
        index: usize,
        decision: &AmxDecisionV1,
    ) -> Result<AmxSettleOutcome, AmxParticipantError<E::Error>> {
        let entry = &mut self.prepared[index];
        if entry.settled.is_some() {
            return Err(rejected("the transaction was already settled").into());
        }
        let outcome = match (entry.vote, decision.outcome) {
            (AmxVoteV1::Yes(_), AmxOutcomeV1::Commit) => {
                escrow
                    .apply(&decision.tx)
                    .map_err(AmxParticipantError::Escrow)?;
                AmxSettleOutcome::Applied
            }
            (AmxVoteV1::Yes(_), AmxOutcomeV1::Abort) => {
                escrow
                    .release(&decision.tx)
                    .map_err(AmxParticipantError::Escrow)?;
                AmxSettleOutcome::Released
            }
            (AmxVoteV1::No, _) => AmxSettleOutcome::Closed,
        };
        entry.settled = Some(decision.outcome);
        Ok(outcome)
    }

    /// Hold the decision of a transaction not prepared here, recorded at global `height`.
    fn hold(&mut self, decision: AmxDecisionV1, height: u64) -> Result<AmxSettleOutcome, AmxError> {
        let Err(slot) = self
            .held
            .binary_search_by(|held| held.decision.tx.cmp(&decision.tx))
        else {
            return Err(rejected("the decision is already held"));
        };
        if self.held.len() >= MAX_AMX_PENDING {
            return Err(rejected("too many held decisions"));
        }
        self.held
            .insert(slot, AmxHeldDecisionV1 { decision, height });
        Ok(AmxSettleOutcome::Held)
    }

    /// Apply a handoff proof of the global chain's instance (§11.7).
    ///
    /// # Errors
    /// The proof does not verify.
    pub fn handoff(&mut self, proof: &AmxHandoffProofV1) -> Result<AmxHandoffOutcome, AmxError> {
        let outcome = self.global.apply_handoff(
            proof,
            crate::sumeragi_finality::CertifiedResultScope::TairaGlobal,
        )?;
        if let Some(previous) = &self.global.previous {
            self.observe(previous.authorization.last_height);
        }
        Ok(outcome)
    }

    /// Raise the verified global height and drop the entries no valid `Prepare` can follow.
    fn observe(&mut self, height: u64) {
        self.global_height = self.global_height.max(height);
        let global_height = self.global_height;
        self.prepared.retain(|entry| {
            entry.deadline >= global_height
                || (entry.settled.is_none() && matches!(entry.vote, AmxVoteV1::Yes(_)))
        });
        self.held
            .retain(|held| held.height.saturating_add(MAX_AMX_DEADLINE_WINDOW) >= global_height);
    }
}
