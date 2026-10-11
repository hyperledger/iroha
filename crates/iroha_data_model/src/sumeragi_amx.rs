//! Atomic cross-dataspace transactions (AMX) by two-phase commit through the global chain
//! (`specs/sumeragi.md` §11).
//!
//! An AMX transaction `X` ([`AmxTransactionV1`]) names its participant dataspaces, one opaque
//! leg per participant and a global deadline height `d`; its id is `x = H(X)`
//! ([`AmxTransactionV1::id`]). The global chain `G` records [`AmxBeginV1`] and, by `d + 1`, one
//! immutable [`AmxDecisionV1`]; each participant records one [`AmxPreparedV1`] vote.
//!
//! **Records are World writes.** The executor that creates a record writes it into the block's
//! execution witness under [`amx_record_witness_key`] with the canonical record as value, so the
//! ordinary-write root of the block's certified result `R` commits the record without any change
//! to `R`'s layout. A record proof ([`AmxRecordProofV1`]) is the certified block (core header,
//! `CommitQC`, result preimage, [`AmxCertifiedBlockV1`]) plus the sparse-Merkle path of the write
//! ([`AmxWriteProofV1`]). Another instance verifies it with its [`AmxForeignInstanceV1`] tracker,
//! which follows the foreign instance's committees epoch by epoch through handoff proofs
//! ([`AmxHandoffProofV1`], §11.7).
//!
//! **State.** [`SumeragiAmxState`] is the global chain's AMX World state: the registered
//! participant dataspaces with their foreign-committee trackers and the transactions whose
//! deadline has not passed. It is bounded ([`MAX_AMX_DATASPACES`], [`MAX_AMX_PENDING`]): every
//! transaction is decided by `d + 1` and dropped from the state in the first block after `d`,
//! which cannot readmit it because a `Begin` must precede its deadline.
//!
//! Nothing in this module grants authority by decoding: a record is trusted only after a tracker
//! verified its proof against an independently registered trust anchor.

mod allocation;
pub use allocation::{AllocatedAmxRecordProofV1, AmxProofAllocationErrorV1};
mod participant;
mod proof;
mod state;
mod tracker;

use iroha_crypto::Hash;
use iroha_model_base::topology::DataSpaceId;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

pub use participant::{
    AmxEscrow, AmxHeldDecisionV1, AmxParticipantError, AmxParticipantStateV1, AmxPreparedEntryV1,
    AmxSettleOutcome,
};
pub use proof::{
    AmxCertifiedBlockV1, AmxHandoffProofV1, AmxRecordProofV1, AmxWriteProofV1,
    MAX_AMX_HEADER_BYTES, MAX_AMX_QC_BYTES, write_set_root,
};
pub use state::{
    AmxDataspaceV1, AmxDecidedV1, AmxGlobalEntryV1, AmxRelayOutcome, AmxYesV1, SumeragiAmxState,
};
pub use tracker::{AmxForeignInstanceV1, AmxHandoffOutcome, AmxVerifiedBlock};

use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, execution_witness::ExecutionWitnessKeyTagV1,
};

/// Domain tag of an AMX transaction id `x = H(AMX_TRANSACTION_DOMAIN ‖ norito(X))`.
pub const AMX_TRANSACTION_DOMAIN: &[u8] = b"iroha/sumeragi/amx/transaction/v1";
/// Fewest participants of an AMX transaction: it spans at least two dataspaces.
pub const MIN_AMX_PARTICIPANTS: usize = 2;
/// Most participants of an AMX transaction.
pub const MAX_AMX_PARTICIPANTS: usize = 16;
/// Largest opaque leg payload in bytes.
pub const MAX_AMX_LEG_BYTES: usize = 64 * 1024;
/// Largest distance `d − b` between the `Begin` height `b` and the deadline `d`: escrow is
/// bounded in global heights (§11.6).
pub const MAX_AMX_DEADLINE_WINDOW: u64 = 7_200;
/// Most transactions the global chain tracks before their deadlines pass.
pub const MAX_AMX_PENDING: usize = 4_096;
/// Most participant dataspaces the global chain registers.
pub const MAX_AMX_DATASPACES: usize = 256;
/// Length of an AMX record's witness key: tag, kind and transaction id.
pub const AMX_RECORD_WITNESS_KEY_BYTES: usize = 34;

/// An invalid AMX input/transition or a local decoder resource refusal.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AmxError {
    /// The transaction `X` is malformed.
    #[error("malformed AMX transaction: {0}")]
    Transaction(&'static str),
    /// A record is malformed.
    #[error("malformed AMX record: {0}")]
    Record(&'static str),
    /// A proof does not verify.
    #[error("invalid AMX proof: {0}")]
    Proof(String),
    /// A certified block belongs to an epoch the tracker does not hold (a handoff is missing).
    #[error("certified epoch {epoch} is not tracked (tracked epochs end at {tracked})")]
    EpochNotTracked {
        /// Epoch of the certified block.
        epoch: u64,
        /// Latest tracked epoch `e`.
        tracked: u64,
    },
    /// A trust anchor or tracked epoch context is invalid.
    #[error("invalid AMX trust anchor: {0}")]
    Anchor(String),
    /// The global chain's AMX state rejects the transition.
    #[error("AMX state rejects the transition: {0}")]
    State(&'static str),
    /// A Norito encoding or decoding failure.
    #[error("AMX encoding: {0}")]
    Encoding(String),
    /// The original codec scope or allocator refused; no protocol verdict was produced.
    #[error("local AMX codec resource refusal: {0}")]
    Resource(norito::core::DecodeResourceError),
}

fn proof_codec_error(error: &norito::Error, part: &str, outer_scope: bool) -> AmxError {
    if (outer_scope || matches!(error, norito::Error::AllocationFailed { .. }))
        && let Some(resource) = error.decode_resource_error()
    {
        return AmxError::Resource(resource);
    }
    AmxError::Proof(format!("{part}: {error}"))
}

fn commitment_error(error: &crate::sumeragi_finality::CommitmentError) -> AmxError {
    match error {
        crate::sumeragi_finality::CommitmentError::Resource(resource) => {
            AmxError::Resource(*resource)
        }
        other => AmxError::Proof(format!("result preimage: {other}")),
    }
}

fn encoding(error: impl std::borrow::Borrow<norito::Error>) -> AmxError {
    let error = error.borrow();
    if !cfg!(all(test, sumeragi_model_mutation = "DM9"))
        && matches!(error, norito::Error::AllocationFailed { .. })
        && let Some(resource) = error.decode_resource_error()
    {
        return AmxError::Resource(resource);
    }
    AmxError::Encoding(error.to_string())
}

/// One participant's part of an AMX transaction: the dataspace and its opaque effects, which
/// only that dataspace's executor interprets.
#[derive(
    Clone,
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
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxLegV1")]
pub struct AmxLegV1 {
    /// The participant dataspace.
    pub dataspace: DataSpaceId,
    /// Dataspace-local effects (at most [`MAX_AMX_LEG_BYTES`]).
    #[norito(
        with = "crate::json_helpers::base64_vec",
        bounded_with = "crate::json_helpers::base64_vec::serialize_bounded"
    )]
    pub payload: Vec<u8>,
}

/// An AMX transaction `X` (§11.2): legs in strictly increasing dataspace order, the global
/// deadline height `d` and a client nonce that makes `x` unique.
#[derive(
    Clone,
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
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxTransactionV1")]
pub struct AmxTransactionV1 {
    /// One leg per participant, strictly increasing by dataspace.
    pub legs: Vec<AmxLegV1>,
    /// Global deadline height `d`.
    pub deadline: u64,
    /// Client nonce.
    #[norito(
        with = "crate::json_helpers::fixed_bytes_hex",
        bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
    )]
    pub nonce: [u8; 32],
}

impl AmxTransactionV1 {
    /// Check the leg count, order and sizes and the deadline.
    ///
    /// # Errors
    /// The first violated rule.
    pub fn validate(&self) -> Result<(), AmxError> {
        if !(MIN_AMX_PARTICIPANTS..=MAX_AMX_PARTICIPANTS).contains(&self.legs.len()) {
            return Err(AmxError::Transaction("participant count out of range"));
        }
        if self
            .legs
            .windows(2)
            .any(|pair| pair[0].dataspace >= pair[1].dataspace)
        {
            return Err(AmxError::Transaction(
                "legs are not in strictly increasing dataspace order",
            ));
        }
        if self
            .legs
            .iter()
            .any(|leg| leg.payload.len() > MAX_AMX_LEG_BYTES)
        {
            return Err(AmxError::Transaction("leg payload exceeds its bound"));
        }
        if self.deadline == 0 {
            return Err(AmxError::Transaction("deadline must be a positive height"));
        }
        Ok(())
    }

    /// `x = H(AMX_TRANSACTION_DOMAIN ‖ norito(X))` of a valid transaction.
    ///
    /// # Errors
    /// The transaction is malformed or does not encode.
    pub fn id(&self) -> Result<[u8; 32], AmxError> {
        self.validate()?;
        // DM5 restores only the retired canonical-frame scratch in this public API.
        #[cfg(all(test, sumeragi_model_mutation = "DM5"))]
        {
            let bytes = norito::encode_canonical(self).map_err(encoding)?;
            return Ok(Hash::new_from_chunks(&[AMX_TRANSACTION_DOMAIN, &bytes]).into());
        }
        #[cfg(not(all(test, sumeragi_model_mutation = "DM5")))]
        streamed_transaction_id(self).map_err(|error| {
            error
                .decode_resource_error()
                .map_or_else(|| encoding(&error), AmxError::Resource)
        })
    }

    /// The participant set, ascending.
    #[must_use]
    pub fn participants(&self) -> Vec<DataSpaceId> {
        self.legs.iter().map(|leg| leg.dataspace).collect()
    }

    /// The leg of `dataspace`.
    #[must_use]
    pub fn leg(&self, dataspace: DataSpaceId) -> Option<&AmxLegV1> {
        self.legs
            .binary_search_by_key(&dataspace, |leg| leg.dataspace)
            .ok()
            .map(|index| &self.legs[index])
    }

    /// The `Begin` record of a valid transaction.
    ///
    /// # Errors
    /// The transaction is malformed.
    pub fn begin(&self) -> Result<AmxBeginV1, AmxError> {
        Ok(AmxBeginV1 {
            tx: self.id()?,
            participants: self.participants(),
            deadline: self.deadline,
        })
    }
}

/// `Begin{x, participants, d}` (§11.2), recorded by the global chain.
#[derive(
    Clone,
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
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxBeginV1")]
pub struct AmxBeginV1 {
    /// Transaction id `x`.
    #[norito(
        with = "crate::json_helpers::fixed_bytes_hex",
        bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
    )]
    pub tx: [u8; 32],
    /// Participants, strictly ascending.
    pub participants: Vec<DataSpaceId>,
    /// Global deadline height `d`.
    pub deadline: u64,
}

impl AmxBeginV1 {
    /// Check the participant set and the deadline.
    ///
    /// # Errors
    /// The first violated rule.
    pub fn validate(&self) -> Result<(), AmxError> {
        if !(MIN_AMX_PARTICIPANTS..=MAX_AMX_PARTICIPANTS).contains(&self.participants.len())
            || self.participants.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(AmxError::Record(
                "participants are not a strictly increasing set of valid size",
            ));
        }
        if self.deadline == 0 {
            return Err(AmxError::Record("deadline must be a positive height"));
        }
        Ok(())
    }

    /// Whether `dataspace` takes part.
    #[must_use]
    pub fn has_participant(&self, dataspace: DataSpaceId) -> bool {
        self.participants.binary_search(&dataspace).is_ok()
    }

    /// Whether this record is the `Begin` of `transaction` (same id, participants and deadline).
    #[must_use]
    pub fn matches(&self, transaction: &AmxTransactionV1) -> bool {
        // DM6 reconstructs only the retired Begin owner instead of comparing borrowed fields.
        #[cfg(all(test, sumeragi_model_mutation = "DM6"))]
        {
            return transaction.begin().is_ok_and(|begin| &begin == self);
        }
        #[cfg(not(all(test, sumeragi_model_mutation = "DM6")))]
        {
            self.deadline == transaction.deadline
                && self
                    .participants
                    .iter()
                    .copied()
                    .eq(transaction.legs.iter().map(|leg| leg.dataspace))
                && transaction.id().is_ok_and(|tx| tx == self.tx)
        }
    }
}

// Hash only this closed canonical schema. Validation belongs to the caller; this helper
// preserves the actual codec or I/O cause without an encoded frame or diagnostic allocation.
pub(crate) fn streamed_transaction_id(
    transaction: &AmxTransactionV1,
) -> Result<[u8; 32], norito::Error> {
    // Exact existing domain and canonical frame, streamed into the fixed hash owner. Preserve
    // original codec failures; no Vec, encoded-error String or substituted source identity.
    // This concrete nongeneric schema has a borrowed static frame name. Its derived struct
    // serializer calls write_len_prefixed; Vec<AmxLegV1> streams counted elements and each
    // Vec<u8> payload streams its borrowed slice. Canonical COMPACT_LEN has no offset table.
    // Both frame passes and the Blake2b writer use fixed stack state; no serializer scratch
    // layout is omitted from admission. This conclusion is specific to these exact fields.
    let mut codec = None;
    let hash = Hash::new_from_writer(|writer| {
        writer.write_all(AMX_TRANSACTION_DOMAIN)?;
        norito::core::write_canonical_to_writer(transaction, writer).map_err(|cause| {
            codec = Some(cause);
            // The original codec error is retained above. Use the inline ErrorKind bridge,
            // without allocating an error string or boxed dynamic error while refusing.
            std::io::Error::from(std::io::ErrorKind::Other)
        })
    });
    if let Some(cause) = codec {
        return Err(cause);
    }
    Ok(hash.map_err(norito::Error::Io)?.into())
}

/// A participant's vote (§11.3).
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
#[norito(tag = "vote", content = "effects_hash")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxVoteV1")]
pub enum AmxVoteV1 {
    /// The participant escrowed the touched state; the hash commits to the escrowed effects.
    #[codec(index = 0)]
    Yes([u8; 32]),
    /// The participant escrowed nothing: `X` cannot commit.
    #[codec(index = 1)]
    No,
}

/// `Prepared{x, Di, Yes(effects_hash) | No}` (§11.3), recorded by participant `Di`.
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
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxPreparedV1")]
pub struct AmxPreparedV1 {
    /// Transaction id `x`.
    #[norito(
        with = "crate::json_helpers::fixed_bytes_hex",
        bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
    )]
    pub tx: [u8; 32],
    /// The voting participant `Di`.
    pub participant: DataSpaceId,
    /// Its vote.
    pub vote: AmxVoteV1,
}

/// The global chain's decision (§11.5).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[norito(tag = "outcome", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxOutcomeV1")]
pub enum AmxOutcomeV1 {
    /// Every participant voted `Yes` by the deadline: apply the escrows.
    #[codec(index = 0)]
    Commit,
    /// A participant voted `No`, or the deadline passed: release the escrows.
    #[codec(index = 1)]
    Abort,
}

/// `Decision{x, Commit | Abort}` (§11.5), recorded once by the global chain.
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
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxDecisionV1")]
pub struct AmxDecisionV1 {
    /// Transaction id `x`.
    #[norito(
        with = "crate::json_helpers::fixed_bytes_hex",
        bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
    )]
    pub tx: [u8; 32],
    /// The decision.
    pub outcome: AmxOutcomeV1,
}

/// Kind of an AMX record: the second byte of its witness key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AmxRecordKind {
    /// [`AmxBeginV1`], written by the global chain.
    Begin = 1,
    /// [`AmxPreparedV1`], written by a participant.
    Prepared = 2,
    /// [`AmxDecisionV1`], written by the global chain.
    Decision = 3,
}

/// Any AMX record, as written into the execution witness.
#[derive(
    Clone,
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
#[norito(tag = "kind", content = "record")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxRecordV1")]
pub enum AmxRecordV1 {
    /// `Begin` (global chain).
    #[codec(index = 0)]
    Begin(AmxBeginV1),
    /// `Prepared` (participant).
    #[codec(index = 1)]
    Prepared(AmxPreparedV1),
    /// `Decision` (global chain).
    #[codec(index = 2)]
    Decision(AmxDecisionV1),
}

impl AmxRecordV1 {
    /// The record's kind.
    #[must_use]
    pub const fn kind(&self) -> AmxRecordKind {
        match self {
            Self::Begin(_) => AmxRecordKind::Begin,
            Self::Prepared(_) => AmxRecordKind::Prepared,
            Self::Decision(_) => AmxRecordKind::Decision,
        }
    }

    /// The transaction id `x` the record is about.
    #[must_use]
    pub const fn tx(&self) -> [u8; 32] {
        match self {
            Self::Begin(record) => record.tx,
            Self::Prepared(record) => record.tx,
            Self::Decision(record) => record.tx,
        }
    }

    /// Check the record's own structure.
    ///
    /// # Errors
    /// A malformed `Begin`.
    pub fn validate(&self) -> Result<(), AmxError> {
        match self {
            Self::Begin(begin) => begin.validate(),
            Self::Prepared(_) | Self::Decision(_) => Ok(()),
        }
    }

    /// The execution-witness key of this record.
    #[must_use]
    pub fn witness_key(&self) -> [u8; AMX_RECORD_WITNESS_KEY_BYTES] {
        amx_record_witness_key(self.kind(), self.tx())
    }

    /// The execution-witness value of this record: its canonical Norito frame.
    ///
    /// # Errors
    /// A Norito encoding failure.
    pub fn witness_value(&self) -> Result<Vec<u8>, AmxError> {
        norito::encode_canonical(self).map_err(encoding)
    }

    /// Decode a witness value, checking that it is canonical and belongs under `key`.
    ///
    /// # Errors
    /// The value is not one canonical, valid record of the key's kind and transaction.
    pub fn from_witness(key: &[u8], value: &[u8]) -> Result<Self, AmxError> {
        let outer_scope = norito::core::decode_limits_active();
        let record: Self = norito::decode_canonical(value).map_err(|error| {
            if (outer_scope || matches!(error, norito::Error::AllocationFailed { .. }))
                && let Some(resource) = error.decode_resource_error()
            {
                return AmxError::Resource(resource);
            }
            encoding(&error)
        })?;
        record.validate()?;
        if record.witness_key().as_slice() != key {
            return Err(AmxError::Record("witness key differs from the record"));
        }
        if record.witness_value()? != value {
            return Err(AmxError::Record("witness value is not canonical"));
        }
        Ok(record)
    }
}

/// The execution-witness key of an AMX record: the reserved tag
/// [`ExecutionWitnessKeyTagV1::AmxRecord`], the record kind and the transaction id. One key
/// holds one record: each kind is written at most once per transaction and instance.
#[must_use]
pub const fn amx_record_witness_key(
    kind: AmxRecordKind,
    tx: [u8; 32],
) -> [u8; AMX_RECORD_WITNESS_KEY_BYTES] {
    let mut key = [0; AMX_RECORD_WITNESS_KEY_BYTES];
    key[0] = ExecutionWitnessKeyTagV1::AmxRecord as u8;
    key[1] = kind as u8;
    let mut index = 0;
    while index < tx.len() {
        key[index + 2] = tx[index];
        index += 1;
    }
    key
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::allocated_amx_instruction_fixture;

mod native;
pub use native::{
    AllocatedAmxTransferLegV1, AmxLegDecodeErrorV1, AmxTransferEscrowV1, AmxTransferLegV1,
    CompletedAmxTransferLegDecodeV1, NativeAmxParticipantStateV1, PendingAmxTransferLegDecodeV1,
    native_transfer_effects_hash,
};
