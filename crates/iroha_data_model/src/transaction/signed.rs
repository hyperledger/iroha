//! Transaction structures and related implementations.
pub use self::model::*;
mod ivm_proved_intent;
mod ordered_intent;
/// Exact original-pool allocation custody for closed native pin/outbox transaction graphs.
pub mod pin_allocation;
mod wire_v1;
mod wire_v1_api;
use super::{
    error,
    executable::{Executable, ExecutableBatchItem, IvmBytecode},
};
use crate::{
    NetworkId,
    account::{AccountController, AccountId, MultisigPolicy},
    asset::AssetDefinitionId,
    block::consensus::NexusFeeReceipt,
    events::data::prelude::AssetBatchTransferOutcome,
    isi::{CustomInstruction, ExecuteTrigger, InstructionBox, privacy::SubmitPrivacyProofV1},
    nexus::FeeSponsorProgramId,
    privacy::{
        PrivacyStatementDigestV1, PrivacyStatementV1, PrivacyTransactionIntentDigestV1,
        PrivacyVegaDeviceAuthenticationDigestV1,
    },
    trigger::DataTriggerSequence,
};
#[cfg(feature = "fault_injection")]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use derive_more::{Deref, Display, From, TryInto};
use iroha_crypto::{Algorithm, Hash, HashOf, PublicKey, Signature, SignatureOf};
use iroha_data_model_derive::model;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::numeric::Quantity;
use iroha_primitives::{const_vec::ConstVec, json::Json, time::TimeSource};
use iroha_schema::IntoSchema;
pub use ivm_proved_intent::{
    IVM_PROVED_TRANSACTION_INTENT_DIGEST_DOMAIN_V1, IvmProvedTransactionIntentDigestV1,
    IvmProvedTransactionIntentErrorV1,
};
use norito::{
    codec::{Decode, Encode},
    core::DecodeFromSlice,
};
pub use ordered_intent::ORDERED_INTENT_DIGEST_DOMAIN_V1;
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    iter::IntoIterator,
    num::{NonZeroU32, NonZeroU64},
    str::FromStr,
    string::String,
    sync::LazyLock,
    time::Duration,
    vec::Vec,
};
use thiserror::Error;
pub use wire_v1::{
    SIGNED_TRANSACTION_FRAME_OVERHEAD_BYTES_V1, SIGNED_TRANSACTION_FRAME_PADDING_BYTES_V1,
    SIGNED_TRANSACTION_WIRE_PREFIX_BYTES_V1, WireV1Plan,
};
/// Default signature-bound lifetime assigned by [`TransactionBuilder`].
///
/// Networks govern the admission ceiling through
/// [`crate::parameter::TransactionParameters::max_time_to_live_ms`]. This
/// default matches the default client transaction lifetime.
pub const DEFAULT_TRANSACTION_TIME_TO_LIVE: Duration = Duration::from_secs(100);
fn verify_typed_signature_for_signer<T: Encode>(
    signature: &SignatureOf<T>,
    signer: &PublicKey,
    payload: &T,
) -> Result<(), iroha_crypto::Error> {
    // The shared admission relation borrows the existing signature. Parsing into an
    // owned Signature here would reserve and copy bytes only to discard them before
    // verification, turning a local decoder refusal into a bad-signature verdict.
    iroha_crypto::verify_signature_for_admission(
        signature,
        signer,
        iroha_crypto::HashOf::new(payload).as_ref(),
    )
}
#[model]
mod model {
    use super::*;
    use crate::account::AccountId;
    use iroha_primitives::const_vec::ConstVec;
    /// Fee system whose charge is bounded by a signed transaction limit.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::FeeChargeKind")]
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(
        tag = "kind",
        content = "value",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    pub enum FeeChargeKind {
        /// Nexus admission and execution fee.
        Nexus,
        /// Pipeline gas charged for contract or IVM execution.
        PipelineGas,
    }
    /// Signature-bound upper bound for one fee component and asset.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::FeeChargeLimit")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct FeeChargeLimit {
        /// Fee component constrained by this limit.
        pub kind: FeeChargeKind,
        /// Exact canonical asset definition in which the component may be charged.
        pub asset_definition_id: AssetDefinitionId,
        /// Maximum amount the signer authorizes for this component.
        pub max_amount: Quantity,
    }
    /// Signature-bound limits for authority-paid fees.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::AuthorityFeePayment")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct AuthorityFeePayment {
        /// Canonically ordered per-component charge limits.
        pub charge_limits: Vec<FeeChargeLimit>,
        /// Maximum executable gas; required for contract and IVM transactions.
        #[norito(required)]
        pub gas_limit: Option<NonZeroU64>,
    }
    /// Signature-bound limits and exact revision for sponsor-program fees.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::SponsorFeePayment")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct SponsorFeePayment {
        /// Exact sponsor program selected before signing.
        pub program_id: FeeSponsorProgramId,
        /// Exact immutable program revision accepted by the signer.
        pub program_revision: u64,
        /// Canonically ordered per-component charge limits.
        pub charge_limits: Vec<FeeChargeLimit>,
        /// Maximum executable gas; required for contract and IVM transactions.
        #[norito(required)]
        pub gas_limit: Option<NonZeroU64>,
    }
    /// Required signature-bound choice of fee funding source and limits.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::FeePaymentIntent")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(
        tag = "payer",
        content = "value",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    pub enum FeePaymentIntent {
        /// Charge the transaction authority directly.
        Authority(AuthorityFeePayment),
        /// Charge one exact revision of an on-chain sponsor program.
        Sponsor(SponsorFeePayment),
    }
    /// Closed security domain signed into every transaction payload.
    ///
    /// Ordinary transactions bind the exact genesis-header-derived network
    /// identity. The marker variant exists solely because a genesis block
    /// cannot contain its own header hash without a self-reference.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(
        tag = "kind",
        content = "value",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::TransactionDomain")]
    pub enum TransactionDomain {
        /// Exact deployment identity for every non-genesis transaction.
        Network(NetworkId),
        /// Genesis-only marker used to avoid a genesis-hash self-reference.
        Genesis,
    }
    /// Canonical unsigned transaction draft used by quote, signing, and verification APIs.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::TransactionPayload")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct TransactionPayload {
        /// Exact signed security domain for replay protection.
        pub domain: TransactionDomain,
        /// Account ID of transaction creator. Signing rejects a key mismatch;
        /// it never rewrites this signature-bound field.
        pub authority: AccountId,
        /// Creation timestamp (unix time in milliseconds).
        pub creation_time_ms: u64,
        /// ISI or IVM smart contract bytecode.
        pub instructions: Executable,
        /// Required signature-bound lifetime. `None` exists only so malformed
        /// wire input can be decoded and rejected deterministically.
        pub time_to_live_ms: Option<NonZeroU64>,
        /// Random value to make different hashes for transactions which occur repeatedly and simultaneously.
        pub nonce: Option<NonZeroU32>,
        /// Explicit fee payer, assets, limits, and executable gas bound.
        pub fee_payment: FeePaymentIntent,
        /// Store for additional information.
        pub metadata: Metadata,
        /// Ordered intent descriptor and signed inline attachment occurrences.
        ///
        /// The transaction signature covers every occurrence byte. Relays
        /// cannot add, remove, reorder or replace an action or an occurrence
        /// without invalidating every authorization signature and changing
        /// the transaction identifier. A proof binds the normalized ordered
        /// intent, which excludes generated proof bytes, lengths and hashes.
        #[norito(required)]
        pub attachments: Option<crate::transaction::signed_attachments::SignedAttachmentsV1>,
    }
    /// Signature of a transaction, encoded in its declared tuple-field frame.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::TransactionSignature")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(decode_from_slice)]
    pub struct TransactionSignature(pub SignatureOf<TransactionPayload>);
    /// A single signature produced by a multisig member.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::MultisigSignature")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct MultisigSignature {
        /// Signer public key.
        pub signer: iroha_crypto::PublicKey,
        /// Signature over the transaction payload produced by `signer`.
        pub signature: SignatureOf<TransactionPayload>,
    }
    impl MultisigSignature {
        /// Construct a new multisig signature entry.
        pub fn new(
            signer: iroha_crypto::PublicKey,
            signature: SignatureOf<TransactionPayload>,
        ) -> Self {
            Self { signer, signature }
        }
    }
    /// Collection of multisig signatures attached to a transaction.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::MultisigSignatures")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct MultisigSignatures {
        /// Signature entries provided by multisig members.
        pub signatures: Vec<MultisigSignature>,
    }
    impl MultisigSignatures {
        /// Construct a bundle in canonical signer order.
        pub fn new(mut signatures: Vec<MultisigSignature>) -> Self {
            signatures.sort_by(|left, right| left.signer.cmp(&right.signer));
            Self { signatures }
        }
        /// Validate the unique canonical signer ordering required on the wire.
        ///
        /// # Errors
        ///
        /// Returns an error when a signer occurs more than once or entries are
        /// not strictly ordered by public key.
        pub fn validate_canonical(&self) -> Result<(), TransactionSignatureError> {
            if self
                .signatures
                .windows(2)
                .any(|pair| pair[0].signer >= pair[1].signer)
            {
                return Err(TransactionSignatureError::NonCanonicalMultisigSignatures);
            }
            Ok(())
        }
    }
    /// Payload signed when committing to a sealed transaction.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_data_model::transaction::signed::model::SealedTransactionCommitmentPayload"
    )]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    pub struct SealedTransactionCommitmentPayload {
        /// Exact deployment identity of the blockchain.
        pub network_id: NetworkId,
        /// Account authorized to later reveal the transaction.
        pub authority: AccountId,
        /// Commitment to the canonical signed transaction bytes and salt.
        pub commitment: Hash,
        /// First block height where the reveal may execute.
        pub reveal_after_height: u64,
        /// Last block height where the reveal may execute.
        pub reveal_deadline_height: u64,
        /// Optional nonce to let an authority submit multiple indistinguishable commitments.
        pub nonce: Option<NonZeroU64>,
    }
    /// Signed sealed-transaction commitment.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_data_model::transaction::signed::model::SignedSealedTransactionCommitment"
    )]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    pub struct SignedSealedTransactionCommitment {
        /// Signature over [`Self::payload`].
        pub(super) signature: SignatureOf<SealedTransactionCommitmentPayload>,
        /// Commitment payload.
        pub(super) payload: SealedTransactionCommitmentPayload,
    }
    /// Reveal data for a previously committed sealed transaction.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::SealedTransactionReveal")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    pub struct SealedTransactionReveal {
        /// Commitment hash being opened.
        pub commitment: Hash,
        /// Canonical signed transaction hidden by the commitment.
        pub signed_transaction: SignedTransaction,
        /// Salt used when computing the commitment.
        pub salt: [u8; 32],
    }
    /// Transaction containing a signed intent and its authorization proof.
    ///
    /// `Iroha` and its clients use [`Self`] to send transactions over the network. After a
    /// transaction is signed and before it can be processed any further, the transaction must be
    /// accepted by an `Iroha` peer. The peer verifies the signature and checks the limits.
    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Display,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    #[display("{}", self.hash())]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::SignedTransaction")]
    pub struct SignedTransaction {
        /// Signature of [`Self::payload`].
        pub(super) signature: TransactionSignature,
        /// Payload of the transaction.
        pub(super) payload: TransactionPayload,
        /// Optional bundle of multisig signatures when the authority uses a multisig controller.
        pub(super) multisig_signatures: Option<MultisigSignatures>,
        /// Memoized canonical identity of [`Self::payload`]; never encoded or compared.
        #[norito(skip)]
        #[codec(skip)]
        pub(super) entrypoint_hash: EntrypointHashMemo,
    }
    /// Structure that represents the initial state of a transaction before the transaction receives any signatures.
    #[derive(Debug, Clone)]
    #[must_use]
    pub struct TransactionBuilder {
        /// [`Transaction`] payload.
        pub(super) payload: TransactionPayload,
        /// Optional multisig signature bundle to include upon signing.
        pub(super) multisig_signatures: Option<MultisigSignatures>,
        /// Whether this builder came from the explicit genesis-only constructor.
        pub(super) construction: TransactionConstruction,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TransactionConstruction {
        Ordinary,
        Genesis,
    }
    impl TransactionBuilder {
        /// Validate the builder's construction-domain invariant before signing or export.
        pub(super) fn validate_payload_state(
            &self,
        ) -> Result<(), super::TransactionSignatureError> {
            super::TransactionBuilder::validate_payload(&self.payload, self.construction)
        }
    }
    /// Initial execution step of a transaction, which may invoke data triggers.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Display,
        Decode,
        Encode,
        From,
        TryInto,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::TransactionEntrypoint")]
    pub enum TransactionEntrypoint {
        /// User request that initiates a transaction.
        External(SignedTransaction),
        /// Commitment to a sealed transaction, executed after reveal.
        SealedCommitment(SignedSealedTransactionCommitment),
        /// Reveal of a previously committed sealed transaction.
        SealedReveal(SealedTransactionReveal),
    }
    /// The outcome of processing a transaction:
    /// either a sequence of data triggers, or a rejection reason.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::TransactionResult")]
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
    pub struct TransactionResult(
        pub TransactionResultInner,
        /// Durable per-leg receipts emitted by an independently settled native transfer batch.
        pub Vec<AssetBatchTransferOutcome>,
        /// Exact actual Nexus charge; explicitly absent when no charge committed.
        /// The binary tuple frame and manual JSON key are mandatory, including `None`.
        pub Option<NexusFeeReceipt>,
        /// Actual native contract emissions in execution order, required even when empty.
        pub crate::smart_contract::event::ContractEmissionsV1,
    );
    /// The outcome of processing a transaction:
    /// either a sequence of data triggers, or a rejection reason.
    pub type TransactionResultInner =
        Result<DataTriggerSequence, error::TransactionRejectionReason>;
    /// Single execution step in a transaction, comprising ordered instructions.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::ExecutionStep")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Display,
        Decode,
        Encode,
        From,
        Deref,
        IntoSchema,
    )]
    #[display("ExecutionStep")]
    pub struct ExecutionStep(pub ConstVec<InstructionBox>);
}
// Keep explicit slice decoders for hot ingress paths.
fn read_aos_field<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    flags: u8,
) -> Result<&'a [u8], norito::core::Error> {
    let remaining = bytes
        .get(*offset..)
        .ok_or(norito::core::Error::LengthMismatch)?;
    let (field_len, hdr) = norito::core::read_len_from_slice_with_flags(remaining, flags)?;
    let field_start = (*offset)
        .checked_add(hdr)
        .ok_or(norito::core::Error::LengthMismatch)?;
    let field_end = field_start
        .checked_add(field_len)
        .ok_or(norito::core::Error::LengthMismatch)?;
    let field = bytes
        .get(field_start..field_end)
        .ok_or(norito::core::Error::LengthMismatch)?;
    *offset = field_end;
    Ok(field)
}
fn decode_slice_field<T>(field: &[u8], flags: u8) -> Result<T, norito::core::Error>
where
    T: for<'de> norito::core::NoritoDeserialize<'de> + for<'de> norito::core::DecodeFromSlice<'de>,
{
    let _guard = norito::core::DecodeFlagsGuard::enter(flags);
    let (value, used) = norito::core::decode_field_canonical_from_slice::<T>(field)?;
    if used != field.len() {
        return Err(norito::core::Error::LengthMismatch);
    }
    Ok(value)
}
fn decode_canonical_field<T>(field: &[u8], flags: u8) -> Result<T, norito::core::Error>
where
    T: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    let _guard = norito::core::DecodeFlagsGuard::enter(flags);
    let (value, used) = norito::core::decode_field_canonical::<T>(field)?;
    if used != field.len() {
        return Err(norito::core::Error::LengthMismatch);
    }
    Ok(value)
}
fn decode_codec_field<T>(field: &[u8]) -> Result<T, norito::core::Error>
where
    T: norito::codec::Decode,
{
    let mut cursor = std::io::Cursor::new(field);
    <T as norito::codec::Decode>::decode(&mut cursor)
}
// The payload has one decoder. Archive-based decoding delegates to the slice
// decoder below, so the binding of the attachment descriptor to the rest of the
// payload is checked whichever way a transaction is decoded.
impl<'de> norito::DeserializePayload<'de> for model::TransactionPayload {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("TransactionPayload deserialization requires a canonical valid archive")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = norito::core::payload_slice_from_ptr(ptr)?;
        let (value, used) = <Self as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        if used != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        Ok(value)
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for model::TransactionPayload {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let domain = decode_canonical_field::<TransactionDomain>(
            read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let authority =
            decode_slice_field::<AccountId>(read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let creation_time_ms =
            decode_slice_field::<u64>(read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let instructions =
            decode_slice_field::<Executable>(read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let time_to_live_ms = decode_slice_field::<Option<NonZeroU64>>(
            read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let nonce = decode_slice_field::<Option<NonZeroU32>>(
            read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let fee_payment = decode_canonical_field::<FeePaymentIntent>(
            read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let metadata =
            decode_canonical_field::<Metadata>(read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let attachments = decode_slice_field::<
            Option<crate::transaction::signed_attachments::SignedAttachmentsV1>,
        >(read_aos_field(bytes, &mut offset, flags)?, flags)?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        let payload = Self {
            domain,
            authority,
            creation_time_ms,
            instructions,
            time_to_live_ms,
            nonce,
            fee_payment,
            metadata,
            attachments,
        };
        // The attachment decoder has checked everything that is independent of
        // the rest of the payload. The descriptor is bound to this payload here,
        // so a stale, foreign or mis-targeted declaration never decodes.
        payload
            .validate_signed_attachments_v1()
            .map_err(|error| norito::core::Error::Message(error.to_string()))?;
        Ok((payload, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for model::SignedTransaction {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let signature =
            decode_codec_field::<TransactionSignature>(read_aos_field(bytes, &mut offset, flags)?)?;
        let payload = decode_slice_field::<TransactionPayload>(
            read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let multisig_signatures = decode_slice_field::<Option<MultisigSignatures>>(
            read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                signature,
                payload,
                multisig_signatures,
                entrypoint_hash: EntrypointHashMemo::default(),
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for model::TransactionEntrypoint {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let _guard = norito::core::PayloadCtxGuard::enter(bytes);
        let mut cursor = std::io::Cursor::new(bytes);
        let decoded: Self = <Self as norito::codec::Decode>::decode(&mut cursor)?;
        let used =
            usize::try_from(cursor.position()).map_err(|_| norito::core::Error::LengthMismatch)?;
        Ok((decoded, used))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for model::ExecutionStep {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let (field_len, field_hdr) = norito::core::read_len_from_slice_with_flags(bytes, flags)?;
        let field_start = field_hdr;
        let field_end = field_start
            .checked_add(field_len)
            .ok_or(norito::core::Error::LengthMismatch)?;
        if field_end != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        let field = bytes
            .get(field_start..field_end)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let (instructions, used) =
            <ConstVec<InstructionBox> as norito::core::DecodeFromSlice>::decode_from_slice(field)?;
        if used != field.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, field_end);
        Ok((Self(instructions), field_end))
    }
}
/// Error returned when verifying a transaction signature.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransactionSignatureError {
    /// Multisig authorities are not supported for transaction signing yet.
    #[error("{MULTISIG_SIGNING_UNSUPPORTED_REASON}")]
    UnsupportedMultisigAuthority,
    /// Signature algorithm is not allowed by configuration.
    #[error("signature algorithm {0} is not permitted by configuration")]
    AlgorithmNotPermitted(Algorithm),
    /// The supplied private key does not control the exact payload authority.
    #[error("transaction authority does not match the supplied signing key")]
    AuthorityKeyMismatch,
    /// Signature verification failed for the provided payload and signatory.
    #[error("{0}")]
    CryptoError(String),
    /// The transaction does not contain any signatures.
    #[error("transaction carries no signatures")]
    NoSignatures,
    /// Multisig signature bundle is missing.
    #[error("missing multisig signatures for multisig authority")]
    MissingMultisigSignatures,
    /// A single-controller transaction carried an unrelated multisig proof.
    #[error("single-controller transaction must not carry multisig signatures")]
    UnexpectedMultisigSignatures,
    /// Transaction contains a signature from a non-member.
    #[error("multisig signature from unknown member")]
    UnknownMultisigSigner,
    /// Multisig signatures are duplicated or not ordered by signer.
    #[error("multisig signatures are not in canonical distinct signer order")]
    NonCanonicalMultisigSignatures,
    /// The signature-bound fee payment intent is malformed or ambiguous.
    #[error("invalid fee payment intent: {0}")]
    InvalidFeePaymentIntent(String),
    /// A signable transaction payload omitted its signature-bound lifetime.
    #[error("transaction time_to_live_ms is required")]
    MissingTimeToLive,
    /// An ordinary transaction draft used the genesis-only security domain.
    #[error("genesis transaction domain is restricted to explicit genesis construction")]
    GenesisDomainNotAllowed,
    /// A genesis-only builder carried an ordinary network security domain.
    #[error("explicit genesis construction requires the genesis transaction domain")]
    GenesisDomainRequired,
    /// Collected multisig signatures do not satisfy the policy threshold.
    #[error("insufficient multisig weight: collected {collected}, required {required}")]
    InsufficientMultisigWeight {
        #[doc = "Total weight contributed by provided signatures."]
        collected: u32,
        #[doc = "Threshold required by the multisig policy."]
        required: u16,
    },
}
static EXPIRES_AT_HEIGHT_NAME: LazyLock<Name> = LazyLock::new(|| {
    Name::from_str("expires_at_height").expect("expires_at_height is a valid metadata key")
});
/// Stable reason string for rejecting multisig controllers in tx signing paths.
pub const MULTISIG_SIGNING_UNSUPPORTED_REASON: &str =
    "multisig authority requires bundled signatures for verification";
/// Domain separation tag for sealed transaction commitment hashing.
pub const SEALED_TRANSACTION_COMMITMENT_DOMAIN: &[u8] = b"iroha.sealed_tx.v1";
/// Structural error in a signature-bound fee payment intent.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FeePaymentIntentError {
    /// Sponsor revisions start at one; zero cannot identify an active revision.
    #[error("sponsor program revision must be non-zero")]
    ZeroProgramRevision,
    /// Charge limits must be ordered by fee component.
    #[error("charge limits are not in canonical fee-component order")]
    NonCanonicalChargeLimitOrder,
    /// A fee component may select exactly one asset and maximum amount.
    #[error("duplicate charge limit for component {0:?}")]
    DuplicateChargeKind(FeeChargeKind),
    /// A signed maximum must authorize a positive amount.
    #[error("charge limit for component {kind:?} and asset {asset_definition_id} is zero")]
    ZeroChargeLimit {
        /// Component carrying the zero limit.
        kind: FeeChargeKind,
        /// Asset selected by the invalid limit.
        asset_definition_id: AssetDefinitionId,
    },
    /// Retired metadata keys must never coexist with the typed fee surface.
    #[error("legacy transaction metadata key `{0}` is not supported")]
    LegacyMetadataKey(String),
}
impl FeeChargeLimit {
    /// Construct a signature-bound limit for one exact fee component and asset.
    #[must_use]
    pub const fn new(
        kind: FeeChargeKind,
        asset_definition_id: AssetDefinitionId,
        max_amount: Quantity,
    ) -> Self {
        Self {
            kind,
            asset_definition_id,
            max_amount,
        }
    }
    /// Return the fee component constrained by this limit.
    #[must_use]
    pub const fn kind(&self) -> FeeChargeKind {
        self.kind
    }
    /// Return the exact asset definition selected for this component.
    #[must_use]
    pub const fn asset_definition_id(&self) -> &AssetDefinitionId {
        &self.asset_definition_id
    }
    /// Return the maximum amount authorized for this component.
    #[must_use]
    pub const fn max_amount(&self) -> &Quantity {
        &self.max_amount
    }
}
impl FeePaymentIntent {
    /// Construct an authority-paid intent.
    #[must_use]
    pub const fn authority(
        charge_limits: Vec<FeeChargeLimit>,
        gas_limit: Option<NonZeroU64>,
    ) -> Self {
        Self::Authority(AuthorityFeePayment {
            charge_limits,
            gas_limit,
        })
    }
    /// Construct an exact sponsor-program intent.
    #[must_use]
    pub const fn sponsor(
        program_id: FeeSponsorProgramId,
        program_revision: u64,
        charge_limits: Vec<FeeChargeLimit>,
        gas_limit: Option<NonZeroU64>,
    ) -> Self {
        Self::Sponsor(SponsorFeePayment {
            program_id,
            program_revision,
            charge_limits,
            gas_limit,
        })
    }
    /// Return the canonical per-component charge limits.
    #[must_use]
    pub fn charge_limits(&self) -> &[FeeChargeLimit] {
        match self {
            Self::Authority(payment) => &payment.charge_limits,
            Self::Sponsor(payment) => &payment.charge_limits,
        }
    }
    /// Return the signed executable gas limit, when applicable.
    #[must_use]
    pub const fn gas_limit(&self) -> Option<NonZeroU64> {
        match self {
            Self::Authority(payment) => payment.gas_limit,
            Self::Sponsor(payment) => payment.gas_limit,
        }
    }
    /// Return the exact sponsor program and revision, if sponsorship was selected.
    #[must_use]
    pub const fn sponsor_program(&self) -> Option<(&FeeSponsorProgramId, u64)> {
        match self {
            Self::Authority(_) => None,
            Self::Sponsor(payment) => Some((&payment.program_id, payment.program_revision)),
        }
    }
    /// Return whether two intents select the same payer and executable gas bound.
    ///
    /// Quote-to-sign clients use this before replacing the draft's charge
    /// maxima, preventing a quote from substituting an authority/program,
    /// immutable program revision, or gas authorization.
    #[must_use]
    pub fn has_same_payer_and_gas_bound(&self, other: &Self) -> bool {
        let same_payer = match (self.sponsor_program(), other.sponsor_program()) {
            (None, None) => true,
            (Some(left), Some(right)) => left == right,
            _ => false,
        };
        same_payer && self.gas_limit() == other.gas_limit()
    }
    /// Validate canonical ordering, uniqueness, revision, and positive maxima.
    ///
    /// Empty limits are structurally valid because fee-free networks have no
    /// applicable components. Admission rejects missing limits whenever a fee
    /// component is enabled by the authoritative schedule.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero sponsor revision, a zero charge maximum,
    /// or charge limits that are duplicated or not in canonical order.
    pub fn validate(&self) -> Result<(), FeePaymentIntentError> {
        if matches!(
            self,
            Self::Sponsor(SponsorFeePayment {
                program_revision: 0,
                ..
            })
        ) {
            return Err(FeePaymentIntentError::ZeroProgramRevision);
        }
        let mut previous = None;
        for limit in self.charge_limits() {
            if limit.max_amount.is_zero() {
                return Err(FeePaymentIntentError::ZeroChargeLimit {
                    kind: limit.kind,
                    asset_definition_id: limit.asset_definition_id.clone(),
                });
            }
            if let Some(previous) = previous {
                if limit.kind == previous {
                    return Err(FeePaymentIntentError::DuplicateChargeKind(limit.kind));
                }
                if limit.kind < previous {
                    return Err(FeePaymentIntentError::NonCanonicalChargeLimitOrder);
                }
            }
            previous = Some(limit.kind);
        }
        Ok(())
    }
    fn validate_metadata(metadata: &Metadata) -> Result<(), FeePaymentIntentError> {
        for key in ["fee_sponsor", "gas_limit", "gas_asset_id"] {
            if metadata.get(key).is_some() {
                return Err(FeePaymentIntentError::LegacyMetadataKey(key.to_owned()));
            }
        }
        Ok(())
    }
}
static TX_SEQUENCE_NAME: LazyLock<Name> =
    LazyLock::new(|| Name::from_str("tx_sequence").expect("tx_sequence is a valid metadata key"));
/// Domain separator for the canonical first-release privacy transaction intent.
pub const PRIVACY_TRANSACTION_INTENT_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.privacy.transaction-intent-digest.v1";
/// Dynamic executable path excluded from the V1 privacy intent projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyTransactionIntentUnsupportedPathV1 {
    /// A deployed contract call can enqueue instructions not present in the signed payload.
    ContractCall,
    /// Raw IVM bytecode can enqueue instructions not present in the signed payload.
    Ivm,
    /// A proved IVM overlay is not a direct signed native-instruction list.
    IvmProved,
    /// A mixed batch contains a deployed contract call.
    BatchContractCall,
    /// A custom instruction is interpreted by an executor rather than this closed projection.
    CustomInstruction,
    /// A by-call trigger can execute instructions outside the signed payload.
    ExecuteTrigger,
}
/// Failure to derive or validate a canonical V1 privacy transaction intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PrivacyTransactionIntentErrorV1 {
    /// The payload has no direct typed privacy proof submission.
    #[error("privacy transaction intent requires exactly one direct SubmitPrivacyProofV1")]
    MissingSubmission,
    /// More than one direct typed privacy proof submission is present.
    #[error("privacy transaction intent contains {count} direct privacy submissions")]
    MultipleSubmissions {
        /// Observed direct submission count.
        count: u64,
    },
    /// The payload uses a dynamic path excluded from the V1 projection.
    #[error("privacy transaction intent contains an unsupported dynamic path")]
    UnsupportedPath {
        /// Exact excluded path.
        path: PrivacyTransactionIntentUnsupportedPathV1,
    },
    /// Canonical encoding of the normalized unsigned payload failed.
    #[error("canonical privacy transaction-intent payload encoding failed")]
    PayloadEncodingFailure,
    /// Canonical encoding of the complete statement failed.
    #[error("canonical privacy statement encoding failed during transaction-intent validation")]
    StatementEncodingFailure,
    /// A platform payload length cannot be represented by the fixed u64 frame.
    #[error("privacy transaction-intent payload length overflow")]
    PayloadLengthOverflow,
    /// The statement targets a different network, or the payload is genesis-only.
    #[error("privacy statement network does not match the transaction network domain")]
    NetworkDomainMismatch,
    /// The stored intent digest is zero.
    #[error("privacy statement transaction-intent digest must not be zero")]
    ZeroIntentDigest,
    /// The stored intent digest is stale or belongs to a different payload.
    #[error("privacy statement transaction-intent digest differs from the canonical payload")]
    IntentDigestMismatch {
        /// Digest recomputed from the canonical normalized payload.
        expected: PrivacyTransactionIntentDigestV1,
        /// Digest carried by the signed statement.
        actual: PrivacyTransactionIntentDigestV1,
    },
    /// The stored statement digest is zero.
    #[error("privacy envelope statement digest must not be zero")]
    ZeroStatementDigest,
    /// The stored statement digest does not commit to the final statement.
    #[error("privacy envelope statement digest differs from the canonical statement")]
    StatementDigestMismatch {
        /// Digest recomputed from the final statement.
        expected: PrivacyStatementDigestV1,
        /// Digest carried by the signed envelope.
        actual: PrivacyStatementDigestV1,
    },
}
#[derive(Default)]
struct PrivacyTransactionIntentScan<'a> {
    first_submission: Option<&'a SubmitPrivacyProofV1>,
    direct_submission_count: u64,
    unsupported_path: Option<PrivacyTransactionIntentUnsupportedPathV1>,
    privacy_in_unsupported_path: bool,
}
impl<'a> PrivacyTransactionIntentScan<'a> {
    fn inspect_direct_instruction(&mut self, instruction: &'a InstructionBox) {
        if let Some(submission) = instruction.as_any().downcast_ref::<SubmitPrivacyProofV1>() {
            self.direct_submission_count = self.direct_submission_count.saturating_add(1);
            self.first_submission.get_or_insert(submission);
            return;
        }
        if instruction
            .as_any()
            .downcast_ref::<CustomInstruction>()
            .is_some()
        {
            self.unsupported_path
                .get_or_insert(PrivacyTransactionIntentUnsupportedPathV1::CustomInstruction);
        } else if instruction
            .as_any()
            .downcast_ref::<ExecuteTrigger>()
            .is_some()
        {
            self.unsupported_path
                .get_or_insert(PrivacyTransactionIntentUnsupportedPathV1::ExecuteTrigger);
        }
    }
    fn inspect_proved_overlay_instruction(&mut self, instruction: &InstructionBox) {
        if instruction
            .as_any()
            .downcast_ref::<SubmitPrivacyProofV1>()
            .is_some()
        {
            self.privacy_in_unsupported_path = true;
        }
    }
}
fn scan_privacy_transaction_intent_v1(executable: &Executable) -> PrivacyTransactionIntentScan<'_> {
    let mut scan = PrivacyTransactionIntentScan::default();
    match executable {
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                scan.inspect_direct_instruction(instruction);
            }
        }
        Executable::Batch(items) => {
            for item in items {
                match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        scan.inspect_direct_instruction(instruction);
                    }
                    ExecutableBatchItem::ContractCall(_) => {
                        scan.unsupported_path.get_or_insert(
                            PrivacyTransactionIntentUnsupportedPathV1::BatchContractCall,
                        );
                    }
                }
            }
        }
        Executable::ContractCall(_) => {
            scan.unsupported_path
                .replace(PrivacyTransactionIntentUnsupportedPathV1::ContractCall);
        }
        Executable::Ivm(_) => {
            scan.unsupported_path
                .replace(PrivacyTransactionIntentUnsupportedPathV1::Ivm);
        }
        Executable::IvmProved(proved) => {
            scan.unsupported_path
                .replace(PrivacyTransactionIntentUnsupportedPathV1::IvmProved);
            for instruction in &proved.overlay {
                scan.inspect_proved_overlay_instruction(instruction);
            }
        }
    }
    scan
}
fn validate_exact_direct_privacy_submission_v1<'a>(
    scan: &PrivacyTransactionIntentScan<'a>,
) -> Result<&'a SubmitPrivacyProofV1, PrivacyTransactionIntentErrorV1> {
    if scan.direct_submission_count == 0 {
        if let Some(path) = scan.unsupported_path {
            return Err(PrivacyTransactionIntentErrorV1::UnsupportedPath { path });
        }
        return Err(PrivacyTransactionIntentErrorV1::MissingSubmission);
    }
    if scan.direct_submission_count != 1 {
        return Err(PrivacyTransactionIntentErrorV1::MultipleSubmissions {
            count: scan.direct_submission_count,
        });
    }
    if let Some(path) = scan.unsupported_path {
        return Err(PrivacyTransactionIntentErrorV1::UnsupportedPath { path });
    }
    Ok(scan
        .first_submission
        .expect("a non-zero direct submission count stores its first submission"))
}
impl SubmitPrivacyProofV1 {
    /// Canonical normalized instruction bytes used only inside an ordered-intent preimage.
    ///
    /// The projection clears generated proof/digest fields and is not an admissible instruction.
    /// It grants no construction, proof-verification, or governed-artifact authority.
    ///
    /// # Errors
    /// Returns an error when canonical Norito encoding fails.
    pub fn ordered_intent_projection_bytes_v1(&self) -> Result<Vec<u8>, norito::Error> {
        norito::encode_canonical(&normalized_privacy_submission_for_intent_v1(self))
    }
}

fn normalize_privacy_submission_for_intent_v1(submission: &SubmitPrivacyProofV1) -> InstructionBox {
    normalized_privacy_submission_for_intent_v1(submission).into()
}

fn normalized_privacy_submission_for_intent_v1(
    submission: &SubmitPrivacyProofV1,
) -> SubmitPrivacyProofV1 {
    let mut normalized = submission.clone();
    normalized.envelope.proof.bytes_mut().bytes.clear();
    normalized
        .envelope
        .statement
        .context_mut()
        .transaction_intent_digest = PrivacyTransactionIntentDigestV1::new([0; 32]);
    if let PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) =
        &mut normalized.envelope.statement
    {
        statement.replay_nullifier = crate::privacy::PrivacyZkAceReplayNullifierV1::default();
    }
    if let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) =
        &mut normalized.envelope.statement
    {
        statement.device_authentication_digest =
            PrivacyVegaDeviceAuthenticationDigestV1::new([0; 32]);
    }
    if let PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) =
        &mut normalized.envelope.statement
    {
        statement.action_digest = crate::privacy::PrivacyActionDigestV1::new([0; 32]);
    }
    normalized.envelope.statement_digest = PrivacyStatementDigestV1::new([0; 32]);
    normalized
}
fn normalize_privacy_executable_for_intent_v1(
    executable: &Executable,
) -> Result<Executable, PrivacyTransactionIntentErrorV1> {
    let scan = scan_privacy_transaction_intent_v1(executable);
    let _target = validate_exact_direct_privacy_submission_v1(&scan)?;
    match executable {
        Executable::Instructions(instructions) => {
            let normalized = instructions
                .iter()
                .map(|instruction| {
                    instruction
                        .as_any()
                        .downcast_ref::<SubmitPrivacyProofV1>()
                        .map_or_else(
                            || instruction.clone(),
                            normalize_privacy_submission_for_intent_v1,
                        )
                })
                .collect::<Vec<_>>();
            Ok(Executable::Instructions(normalized.into()))
        }
        Executable::Batch(items) => {
            let normalized = items
                .iter()
                .map(|item| match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        ExecutableBatchItem::Instruction(
                            instruction
                                .as_any()
                                .downcast_ref::<SubmitPrivacyProofV1>()
                                .map_or_else(
                                    || instruction.clone(),
                                    normalize_privacy_submission_for_intent_v1,
                                ),
                        )
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        ExecutableBatchItem::ContractCall(call.clone())
                    }
                })
                .collect::<Vec<_>>();
            Ok(Executable::Batch(normalized.into()))
        }
        Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => {
            unreachable!("exact direct privacy submission validation excludes opaque executables")
        }
    }
}
#[cfg(feature = "fault_injection")]
static FAULT_INJECTION_METADATA_NAME: LazyLock<Name> = LazyLock::new(|| {
    Name::from_str("fault_injection_overlay")
        .expect("fault_injection_overlay is a valid metadata key")
});
impl TransactionPayload {
    /// Validate the complete signature-bound fee intent.
    ///
    /// This combines the typed fee-intent invariants with rejection of retired
    /// metadata keys so every admission path can apply one canonical check.
    ///
    /// # Errors
    ///
    /// Returns an error when the typed intent is non-canonical or legacy fee metadata is present.
    pub fn validate_fee_payment_intent(&self) -> Result<(), FeePaymentIntentError> {
        self.fee_payment
            .validate()
            .and_then(|()| FeePaymentIntent::validate_metadata(&self.metadata))
    }
    /// Return the exact signature-bound fee payment intent.
    #[must_use]
    pub const fn fee_payment_intent(&self) -> &FeePaymentIntent {
        &self.fee_payment
    }
    /// Return the canonical privacy transaction-intent projection bytes.
    ///
    /// This is the exact unsigned-payload preimage consumed by
    /// [`Self::privacy_transaction_intent_digest_v1`]. Exposing the projection
    /// removes independent SDK approximations: callers can decode and
    /// byte-identically reproduce the Rust-owned normalization before signing.
    ///
    /// # Errors
    ///
    /// Returns a closed error for zero or multiple submissions, dynamic/opaque
    /// execution paths, or canonical encoding failure.
    pub fn privacy_transaction_intent_projection_bytes_v1(
        &self,
    ) -> Result<Vec<u8>, PrivacyTransactionIntentErrorV1> {
        let mut normalized = self.clone();
        normalized.instructions =
            normalize_privacy_executable_for_intent_v1(&normalized.instructions)?;
        norito::encode_canonical(&normalized)
            .map_err(|_| PrivacyTransactionIntentErrorV1::PayloadEncodingFailure)
    }
    /// Derive the canonical privacy transaction-intent digest from this unsigned payload.
    ///
    /// V1 accepts exactly one direct typed [`SubmitPrivacyProofV1`] in either
    /// [`Executable::Instructions`] or the native-instruction members of
    /// [`Executable::Batch`]. The canonical projection clones the complete
    /// unsigned payload and changes exactly three universally derived values:
    ///
    /// - the typed proof byte vector becomes empty;
    /// - `statement.context.transaction_intent_digest` becomes 32 zero bytes;
    /// - `envelope.statement_digest` becomes 32 zero bytes.
    ///
    /// For ZK-ACE, the replay nullifier also becomes 48 zero bytes because it is derived from the
    /// resulting intent-bound authorization projection. For Vega, the device-authentication digest
    /// also becomes 32 zero bytes because `H_dev` binds the resulting transaction-intent digest.
    /// For the native IVM private-note protocol, the self-authenticating action digest likewise
    /// becomes 32 zero bytes because its canonical preimage includes the resulting
    /// transaction-intent digest.
    ///
    /// Zeroing these derived fields removes their otherwise unavoidable
    /// self-reference. Every independent payload field, statement field,
    /// instruction tag, and instruction ordinal remains in the Norito preimage.
    ///
    /// # Errors
    ///
    /// Returns a closed error for zero or multiple submissions, dynamic/opaque
    /// execution paths, or canonical encoding failure.
    pub fn privacy_transaction_intent_digest_v1(
        &self,
    ) -> Result<PrivacyTransactionIntentDigestV1, PrivacyTransactionIntentErrorV1> {
        let encoded = self.privacy_transaction_intent_projection_bytes_v1()?;
        let encoded_len = u64::try_from(encoded.len())
            .map_err(|_| PrivacyTransactionIntentErrorV1::PayloadLengthOverflow)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(PRIVACY_TRANSACTION_INTENT_DIGEST_DOMAIN_V1);
        hasher.update(&encoded_len.to_le_bytes());
        hasher.update(&encoded);
        Ok(PrivacyTransactionIntentDigestV1::new(
            *hasher.finalize().as_bytes(),
        ))
    }
    /// Validate the final stored intent and statement digests.
    ///
    /// This is the admission-side companion to [`Self::privacy_transaction_intent_digest_v1`]. It
    /// recomputes both derived values from the exact signed payload and rejects zero, stale, or
    /// foreign values before any executor effect.
    ///
    /// # Errors
    ///
    /// Returns a canonical projection error, network-domain mismatch, or an exact
    /// derived-field mismatch.
    pub fn validate_privacy_transaction_intent_binding_v1(
        &self,
    ) -> Result<PrivacyTransactionIntentDigestV1, PrivacyTransactionIntentErrorV1> {
        let scan = scan_privacy_transaction_intent_v1(&self.instructions);
        let submission = validate_exact_direct_privacy_submission_v1(&scan)?;
        if self.domain
            != TransactionDomain::Network(submission.envelope.statement.context().network_id)
        {
            return Err(PrivacyTransactionIntentErrorV1::NetworkDomainMismatch);
        }
        let expected_intent = self.privacy_transaction_intent_digest_v1()?;
        let actual_intent = submission
            .envelope
            .statement
            .context()
            .transaction_intent_digest;
        if actual_intent.is_zero() {
            return Err(PrivacyTransactionIntentErrorV1::ZeroIntentDigest);
        }
        if actual_intent != expected_intent {
            return Err(PrivacyTransactionIntentErrorV1::IntentDigestMismatch {
                expected: expected_intent,
                actual: actual_intent,
            });
        }
        let expected_statement = submission
            .envelope
            .statement
            .digest()
            .map_err(|_| PrivacyTransactionIntentErrorV1::StatementEncodingFailure)?;
        let actual_statement = submission.envelope.statement_digest;
        if actual_statement.is_zero() {
            return Err(PrivacyTransactionIntentErrorV1::ZeroStatementDigest);
        }
        if actual_statement != expected_statement {
            return Err(PrivacyTransactionIntentErrorV1::StatementDigestMismatch {
                expected: expected_statement,
                actual: actual_statement,
            });
        }
        Ok(expected_intent)
    }
    /// Validate and borrow an optional direct privacy submission for runtime admission.
    ///
    /// Ordinary non-privacy transactions return `Ok(None)`. A typed submission hidden in a proved
    /// overlay fails closed. When one direct submission exists, every V1 projection and
    /// derived-field rule is enforced.
    ///
    /// # Errors
    ///
    /// Returns a closed projection or binding error for any privacy-bearing
    /// payload that is not exactly one auditable direct submission.
    pub fn privacy_transaction_intent_binding_if_present_v1(
        &self,
    ) -> Result<
        Option<(PrivacyTransactionIntentDigestV1, &SubmitPrivacyProofV1)>,
        PrivacyTransactionIntentErrorV1,
    > {
        let scan = scan_privacy_transaction_intent_v1(&self.instructions);
        if scan.direct_submission_count == 0 {
            if scan.privacy_in_unsupported_path {
                return Err(PrivacyTransactionIntentErrorV1::UnsupportedPath {
                    path: scan
                        .unsupported_path
                        .expect("privacy observed in an unsupported path records that path"),
                });
            }
            return Ok(None);
        }
        let submission = validate_exact_direct_privacy_submission_v1(&scan)?;
        let digest = self.validate_privacy_transaction_intent_binding_v1()?;
        Ok(Some((digest, submission)))
    }
    /// Return transaction instructions.
    #[inline]
    pub fn instructions(&self) -> &Executable {
        &self.instructions
    }
    /// Return transaction authority.
    #[inline]
    pub fn authority(&self) -> &AccountId {
        &self.authority
    }
    /// Return the required signature-bound transaction lifetime.
    ///
    /// `None` identifies malformed decoded input; safe builders always assign
    /// a non-zero value and transaction admission rejects `None`.
    #[inline]
    pub fn time_to_live(&self) -> Option<Duration> {
        self.time_to_live_ms
            .map(|ttl| Duration::from_millis(ttl.into()))
    }
    /// Return the exact signed transaction security domain.
    #[inline]
    pub const fn domain(&self) -> &TransactionDomain {
        &self.domain
    }
    /// Return the exact network identity for an ordinary transaction.
    ///
    /// Genesis payloads return `None` because their explicit marker avoids a
    /// self-reference to the genesis header hash.
    #[inline]
    pub const fn network_id(&self) -> Option<&NetworkId> {
        match &self.domain {
            TransactionDomain::Network(network_id) => Some(network_id),
            TransactionDomain::Genesis => None,
        }
    }
}
/// Memoized canonical identity of one signed payload.
///
/// The identity is a pure function of the payload, so a transaction computes
/// it at most once however many pipeline stages ask for it. The memo carries no
/// information of its own: it is excluded from the codec, JSON and schema, it
/// compares equal to every other memo, a clone keeps the computed value (the
/// payload is cloned too), and every method that replaces payload content
/// resets it. Code in this module that writes `payload` fields directly must
/// reset it as well (tests go through `payload_mut`).
#[derive(Default)]
struct EntrypointHashMemo(std::sync::OnceLock<HashOf<TransactionEntrypoint>>);
impl EntrypointHashMemo {
    fn get_or_try_compute(
        &self,
        compute: impl FnOnce() -> Result<HashOf<TransactionEntrypoint>, norito::Error>,
    ) -> Result<HashOf<TransactionEntrypoint>, norito::Error> {
        if let Some(hash) = self.0.get() {
            return Ok(*hash);
        }
        let hash = compute()?;
        Ok(*self.0.get_or_init(|| hash))
    }
}
impl Clone for EntrypointHashMemo {
    fn clone(&self) -> Self {
        let memo = Self::default();
        if let Some(hash) = self.0.get() {
            let _ = memo.0.set(*hash);
        }
        memo
    }
}
impl PartialEq for EntrypointHashMemo {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for EntrypointHashMemo {}
impl PartialOrd for EntrypointHashMemo {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for EntrypointHashMemo {
    fn cmp(&self, _: &Self) -> core::cmp::Ordering {
        core::cmp::Ordering::Equal
    }
}
#[allow(
    clippy::missing_fields_in_debug,
    reason = "the identity memo is a cache of `payload`, not data; output matches the former derive"
)]
impl core::fmt::Debug for SignedTransaction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedTransaction")
            .field("signature", &self.signature)
            .field("payload", &self.payload)
            .field("multisig_signatures", &self.multisig_signatures)
            .finish()
    }
}
impl SignedTransaction {
    /// Derive the privacy intent from the canonical signed payload.
    ///
    /// Authorization signatures are excluded from the intent preimage, while
    /// execution-affecting proof attachments are included.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyTransactionIntentErrorV1`] if instruction inspection
    /// or canonical intent encoding fails.
    pub fn privacy_transaction_intent_digest_v1(
        &self,
    ) -> Result<PrivacyTransactionIntentDigestV1, PrivacyTransactionIntentErrorV1> {
        self.payload.privacy_transaction_intent_digest_v1()
    }
    /// Validate and borrow the optional direct privacy submission in this signed transaction.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyTransactionIntentErrorV1`] if the transaction contains an invalid
    /// privacy-instruction combination or its canonical intent cannot be derived.
    pub fn privacy_transaction_intent_binding_if_present_v1(
        &self,
    ) -> Result<
        Option<(PrivacyTransactionIntentDigestV1, &SubmitPrivacyProofV1)>,
        PrivacyTransactionIntentErrorV1,
    > {
        self.payload
            .privacy_transaction_intent_binding_if_present_v1()
    }
    /// Transaction payload. Used for tests
    pub fn payload(&self) -> &TransactionPayload {
        &self.payload
    }
    /// Return transaction instructions
    #[inline]
    pub fn instructions(&self) -> &Executable {
        self.payload.instructions()
    }
    /// Return transaction authority
    #[inline]
    pub fn authority(&self) -> &AccountId {
        self.payload.authority()
    }
    /// Return transaction metadata.
    #[inline]
    pub fn metadata(&self) -> &Metadata {
        &self.payload.metadata
    }
    /// Return the exact signature-bound fee payment intent.
    #[inline]
    pub fn fee_payment_intent(&self) -> &FeePaymentIntent {
        &self.payload.fee_payment
    }
    /// Multisig signature bundle attached to this transaction, if any.
    #[inline]
    pub fn multisig_signatures(&self) -> Option<&MultisigSignatures> {
        self.multisig_signatures.as_ref()
    }
    /// Creation timestamp as [`core::time::Duration`]
    #[inline]
    pub fn creation_time(&self) -> Duration {
        Duration::from_millis(self.payload.creation_time_ms)
    }
    /// Replace the transaction authority without re-signing the payload.
    ///
    /// Useful for tests that need to simulate malformed or unsupported
    /// authorities without going through the builder.
    #[inline]
    #[must_use]
    pub fn with_authority(mut self, authority: AccountId) -> Self {
        self.payload.authority = authority;
        self.entrypoint_hash = EntrypointHashMemo::default();
        self
    }
    /// Mutable payload for tests that tamper with a signed transaction.
    ///
    /// Direct field writes would leave the memoized identity stale; this resets it.
    #[cfg(test)]
    fn payload_mut(&mut self) -> &mut TransactionPayload {
        self.entrypoint_hash = EntrypointHashMemo::default();
        &mut self.payload
    }
    /// Return the required signature-bound transaction lifetime.
    ///
    /// `None` identifies malformed decoded input.
    #[inline]
    pub fn time_to_live(&self) -> Option<Duration> {
        self.payload.time_to_live()
    }
    /// Transaction nonce
    #[inline]
    pub fn nonce(&self) -> Option<NonZeroU32> {
        self.payload.nonce
    }
    /// Exact signed transaction security domain.
    #[inline]
    pub const fn domain(&self) -> &TransactionDomain {
        self.payload.domain()
    }
    /// Exact network identity for an ordinary transaction.
    #[inline]
    pub const fn network_id(&self) -> Option<&NetworkId> {
        self.payload.network_id()
    }
    /// Return the transaction signature
    #[inline]
    pub fn signature(&self) -> &TransactionSignature {
        &self.signature
    }
    /// Attach a multisig signature bundle, replacing any existing entry.
    #[inline]
    pub fn set_multisig_signatures(&mut self, signatures: MultisigSignatures) {
        self.multisig_signatures = Some(signatures);
    }
    /// Replace the transaction signature.
    #[cfg(feature = "transparent_api")]
    #[inline]
    pub fn set_signature(&mut self, signature: TransactionSignature) {
        self.signature = signature;
    }
    /// Number of signatures bundled with this transaction.
    ///
    /// Current transactions carry exactly one signature for single-key authorities. Multisig
    /// authorities count the raw signature entries in the multisig bundle (including duplicates) so
    /// admission can enforce bundle size limits.
    #[inline]
    pub fn signature_count(&self) -> usize {
        match self.payload.authority.controller() {
            AccountController::Single(_) => 1,
            AccountController::Multisig(_) => self
                .multisig_signatures
                .as_ref()
                .map_or(0, |bundle| bundle.signatures.len()),
        }
    }
    /// Ordered intent descriptor and attachment occurrences of the signed payload.
    #[inline]
    pub fn attachments(
        &self,
    ) -> Option<&crate::transaction::signed_attachments::SignedAttachmentsV1> {
        self.payload.attachments.as_ref()
    }
    /// Height-based TTL advertised via transaction metadata.
    ///
    /// Returns `Ok(None)` when the metadata key is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored metadata value cannot be decoded as `u64`.
    pub fn expires_at_height(&self) -> Result<Option<u64>, norito::Error> {
        self.metadata()
            .get(&*EXPIRES_AT_HEIGHT_NAME)
            .map(Json::try_into_any_norito::<u64>)
            .transpose()
    }
    /// Per-authority transaction sequence advertised via metadata.
    ///
    /// Returns `Ok(None)` when the metadata key is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored metadata value cannot be decoded as `u64`.
    pub fn tx_sequence(&self) -> Result<Option<u64>, norito::Error> {
        self.metadata()
            .get(&*TX_SEQUENCE_NAME)
            .map(Json::try_into_any_norito::<u64>)
            .transpose()
    }
    /// Canonical identifier for this external transaction.
    ///
    /// The identifier commits to the exact signed intent and excludes the
    /// authorization proof. Adding or replacing a signature therefore cannot
    /// create a second identity for the same authorized action.
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        let entry_hash = self.hash_as_entrypoint();
        HashOf::from_untyped_unchecked(Hash::from(entry_hash))
    }
    /// Hash for this external transaction as `TransactionEntrypoint`.
    ///
    /// This matches the canonical transaction hash returned by [`Self::hash`].
    #[inline]
    pub fn hash_as_entrypoint(&self) -> HashOf<TransactionEntrypoint> {
        self.try_hash_as_entrypoint()
            .expect("external transaction hash encoding should not fail")
    }
    /// Hash the original external intent without erasing a serializer or allocation refusal.
    ///
    /// Uses the same borrowed payload projection and fixed V1 hash domain as [`Self::hash`].
    ///
    /// # Errors
    /// Returns the original codec failure without producing a partial transaction identity.
    pub fn try_hash_as_entrypoint(&self) -> Result<HashOf<TransactionEntrypoint>, norito::Error> {
        self.entrypoint_hash.get_or_try_compute(|| {
            let entry_hash = HashOf::try_new(&ExternalEntrypointRef(self.payload()))?;
            Ok(HashOf::from_untyped_unchecked(Hash::from(entry_hash)))
        })
    }
    /// Injects a set of fictitious instructions into the transaction payload for testing.
    ///
    /// Only available when the `fault_injection` feature is enabled.
    #[cfg(feature = "fault_injection")]
    pub fn inject_instructions(
        &mut self,
        extra_instructions: impl IntoIterator<Item = impl Into<InstructionBox>>,
    ) {
        let additions: Vec<InstructionBox> =
            extra_instructions.into_iter().map(Into::into).collect();
        if additions.is_empty() {
            return;
        }
        match &mut self.payload.instructions {
            Executable::Instructions(instructions) => {
                let mut modified = instructions.clone().into_vec();
                modified.extend(additions);
                *instructions = modified.into();
            }
            Executable::Batch(items) => {
                let mut modified = items.clone().into_vec();
                modified.extend(
                    additions
                        .into_iter()
                        .map(crate::transaction::ExecutableBatchItem::Instruction),
                );
                *items = modified.into();
            }
            Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => {
                Self::apply_fault_injection_overlay(&mut self.payload.metadata, additions);
            }
        }
        self.entrypoint_hash = EntrypointHashMemo::default();
    }
    #[cfg(feature = "fault_injection")]
    pub(crate) fn fault_injection_overlay(metadata: &Metadata) -> Option<Vec<String>> {
        metadata
            .get(&*FAULT_INJECTION_METADATA_NAME)
            .cloned()
            .and_then(|value| value.try_into_any_norito::<Vec<String>>().ok())
    }
    #[cfg(feature = "fault_injection")]
    pub(crate) fn apply_fault_injection_overlay(
        metadata: &mut Metadata,
        additions: Vec<InstructionBox>,
    ) {
        let mut combined = Self::fault_injection_overlay(metadata).unwrap_or_default();
        combined.extend(additions.into_iter().map(|instruction| {
            let bytes = norito::encode_canonical(&instruction)
                .expect("fault injection overlay instruction canonical encode");
            BASE64_STANDARD.encode(bytes)
        }));
        metadata.insert(FAULT_INJECTION_METADATA_NAME.clone(), Json::new(combined));
    }
    /// Verify transaction signature.
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails.
    #[inline]
    pub fn verify_signature(&self) -> Result<(), TransactionSignatureError> {
        self.payload
            .validate_fee_payment_intent()
            .map_err(|err| TransactionSignatureError::InvalidFeePaymentIntent(err.to_string()))?;
        let TransactionSignature(signature) = &self.signature;
        match self.payload.authority.controller() {
            AccountController::Single(signatory) => {
                if self.multisig_signatures.is_some() {
                    return Err(TransactionSignatureError::UnexpectedMultisigSignatures);
                }
                verify_typed_signature_for_signer(signature, signatory, &self.payload)
                    .map_err(|err| TransactionSignatureError::CryptoError(err.to_string()))
            }
            AccountController::Multisig(policy) => self.verify_multisig_signatures(policy),
        }
    }
}
impl SealedTransactionCommitmentPayload {
    /// Construct a sealed transaction commitment payload.
    #[must_use]
    pub fn new(
        network_id: NetworkId,
        authority: AccountId,
        commitment: Hash,
        reveal_after_height: u64,
        reveal_deadline_height: u64,
        nonce: Option<NonZeroU64>,
    ) -> Self {
        Self {
            network_id,
            authority,
            commitment,
            reveal_after_height,
            reveal_deadline_height,
            nonce,
        }
    }
}
impl SignedSealedTransactionCommitment {
    /// Try to sign a sealed transaction commitment payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured signature backend cannot sign the
    /// commitment payload with the supplied private key.
    pub fn try_sign(
        payload: SealedTransactionCommitmentPayload,
        private_key: &iroha_crypto::PrivateKey,
    ) -> Result<Self, iroha_crypto::Error> {
        Ok(Self {
            signature: SignatureOf::try_new(private_key, &payload)?,
            payload,
        })
    }
    /// Sign a sealed transaction commitment payload.
    #[must_use]
    pub fn sign(
        payload: SealedTransactionCommitmentPayload,
        private_key: &iroha_crypto::PrivateKey,
    ) -> Self {
        Self::try_sign(payload, private_key)
            .expect("signing should succeed for a valid key pair and sealed commitment payload")
    }
    /// Commitment payload.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &SealedTransactionCommitmentPayload {
        &self.payload
    }
    /// Account authorized to reveal the transaction.
    #[inline]
    #[must_use]
    pub fn authority(&self) -> &AccountId {
        &self.payload.authority
    }
    /// Commitment hash.
    #[inline]
    #[must_use]
    pub fn commitment(&self) -> &Hash {
        &self.payload.commitment
    }
    /// Signature over the commitment payload.
    #[inline]
    #[must_use]
    pub fn signature(&self) -> &SignatureOf<SealedTransactionCommitmentPayload> {
        &self.signature
    }
    /// Verify the commitment signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the authority is multisig or signature verification fails.
    #[inline]
    pub fn verify_signature(&self) -> Result<(), TransactionSignatureError> {
        match self.payload.authority.controller() {
            AccountController::Single(signatory) => {
                verify_typed_signature_for_signer(&self.signature, signatory, &self.payload)
                    .map_err(|err| TransactionSignatureError::CryptoError(err.to_string()))
            }
            AccountController::Multisig(_) => {
                Err(TransactionSignatureError::UnsupportedMultisigAuthority)
            }
        }
    }
}
impl core::fmt::Display for SignedSealedTransactionCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.commitment().fmt(f)
    }
}
impl SealedTransactionReveal {
    /// Construct a sealed transaction reveal.
    #[must_use]
    pub fn new(commitment: Hash, signed_transaction: SignedTransaction, salt: [u8; 32]) -> Self {
        Self {
            commitment,
            signed_transaction,
            salt,
        }
    }
    /// Revealed signed transaction.
    #[inline]
    #[must_use]
    pub fn signed_transaction(&self) -> &SignedTransaction {
        &self.signed_transaction
    }
    /// Recompute the expected commitment using the stored commitment deadline.
    #[must_use]
    pub fn expected_commitment_with_deadline(&self, reveal_deadline_height: u64) -> Hash {
        let network_id = self
            .signed_transaction
            .network_id()
            .expect("sealed transactions cannot use the genesis-only transaction domain");
        compute_sealed_transaction_commitment(
            network_id,
            &self.signed_transaction,
            self.salt,
            reveal_deadline_height,
        )
    }
}
impl core::fmt::Display for SealedTransactionReveal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.commitment.fmt(f)
    }
}
/// Compute the canonical sealed transaction commitment.
///
/// The input is domain-separated and includes the exact network id, the hash of canonical Norito
/// signed-transaction bytes, the salt, and the reveal deadline height.
#[must_use]
pub fn compute_sealed_transaction_commitment(
    network_id: &NetworkId,
    signed_transaction: &SignedTransaction,
    salt: [u8; 32],
    reveal_deadline_height: u64,
) -> Hash {
    let tx_bytes = norito::encode_canonical(signed_transaction)
        .expect("signed transaction must canonically encode to Norito");
    let tx_hash = Hash::new(tx_bytes);
    let network_bytes =
        norito::encode_canonical(network_id).expect("network id must canonically encode to Norito");
    let mut bytes = Vec::with_capacity(
        SEALED_TRANSACTION_COMMITMENT_DOMAIN.len()
            + network_bytes.len()
            + Hash::LENGTH
            + salt.len()
            + core::mem::size_of::<u64>(),
    );
    bytes.extend_from_slice(SEALED_TRANSACTION_COMMITMENT_DOMAIN);
    bytes.extend_from_slice(&network_bytes);
    bytes.extend_from_slice(tx_hash.as_ref());
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&reveal_deadline_height.to_le_bytes());
    Hash::new(bytes)
}
impl SignedTransaction {
    fn verify_multisig_signatures(
        &self,
        policy: &MultisigPolicy,
    ) -> Result<(), TransactionSignatureError> {
        let Some(bundle) = self.multisig_signatures.as_ref() else {
            return Err(TransactionSignatureError::MissingMultisigSignatures);
        };
        if bundle.signatures.is_empty() {
            return Err(TransactionSignatureError::NoSignatures);
        }
        bundle.validate_canonical()?;
        let TransactionSignature(primary_signature) = &self.signature;
        if &bundle.signatures[0].signature != primary_signature {
            return Err(TransactionSignatureError::NonCanonicalMultisigSignatures);
        }
        let mut weights = BTreeMap::new();
        for member in policy.members() {
            weights.insert(member.public_key().clone(), member.weight());
        }
        let mut collected: u32 = 0;
        for entry in &bundle.signatures {
            let Some(weight) = weights.get(&entry.signer) else {
                return Err(TransactionSignatureError::UnknownMultisigSigner);
            };
            verify_typed_signature_for_signer(&entry.signature, &entry.signer, &self.payload)
                .map_err(|err| TransactionSignatureError::CryptoError(err.to_string()))?;
            collected = collected.saturating_add(u32::from(*weight));
        }
        if collected < u32::from(policy.threshold()) {
            return Err(TransactionSignatureError::InsufficientMultisigWeight {
                collected,
                required: policy.threshold(),
            });
        }
        Ok(())
    }
}
impl iroha_version::Version for SignedTransaction {
    fn version(&self) -> u8 {
        1
    }
    fn supported_versions() -> core::ops::Range<u8> {
        1..2
    }
}
impl SignedTransaction {
    /// Encode the complete canonical fixed-V1 transaction wire.
    ///
    /// These are the exact bytes emitted by [`iroha_version::codec::EncodeVersioned`], including
    /// the primary signature and every multisignature authorization proof. They are therefore
    /// suitable for exact replay and commitment checks where the payload-only transaction hash is
    /// insufficient.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be serialized with the canonical V1 Norito
    /// layout.
    pub fn encode_wire_v1(&self) -> Result<Vec<u8>, norito::core::Error> {
        self.wire_plan_v1()?.into_vec()
    }
}
impl iroha_version::codec::EncodeVersioned for SignedTransaction {
    fn encode_versioned(&self) -> Vec<u8> {
        self.encode_wire_v1()
            .expect("versioned transaction encoding should not fail")
    }
}
impl iroha_version::codec::DecodeVersioned for SignedTransaction {
    fn decode_all_versioned(input: &[u8]) -> iroha_version::error::Result<Self> {
        let transaction: Self = iroha_version::codec::decode_exact_versioned(input)?;
        // Observe the actual checked writer while its original enclosing allowance
        // is live; returned numeric fields cannot recover this provenance later.
        let canonical = norito::core::classify_decode_attempt(|| transaction.encode_wire_v1())
            .map_err(iroha_version::error::Error::from)?;
        if canonical.as_slice() != input {
            return Err(iroha_version::error::Error::from(
                norito::core::Error::NonCanonicalEncoding,
            ));
        }
        Ok(transaction)
    }
}
impl iroha_version::Version for TransactionEntrypoint {
    fn version(&self) -> u8 {
        1
    }
    fn supported_versions() -> core::ops::Range<u8> {
        1..2
    }
}
impl TransactionEntrypoint {
    /// Encode the complete canonical fixed-V1 transaction-entrypoint wire.
    ///
    /// These are the exact bytes emitted by [`iroha_version::codec::EncodeVersioned`]. In
    /// particular, an external entrypoint retains its complete [`SignedTransaction`], including
    /// every authorization proof, so callers can compare an observed committed entrypoint with the
    /// exact transaction they submitted.
    ///
    /// # Errors
    ///
    /// Returns an error if the entrypoint cannot be serialized with the canonical V1 Norito layout.
    pub fn encode_wire_v1(&self) -> Result<Vec<u8>, norito::core::Error> {
        self.wire_plan_v1()?.into_vec()
    }
}
impl iroha_version::codec::EncodeVersioned for TransactionEntrypoint {
    fn encode_versioned(&self) -> Vec<u8> {
        self.encode_wire_v1()
            .expect("versioned transaction entrypoint encoding should not fail")
    }
}
impl iroha_version::codec::DecodeVersioned for TransactionEntrypoint {
    fn decode_all_versioned(input: &[u8]) -> iroha_version::error::Result<Self> {
        let entrypoint: Self = iroha_version::codec::decode_exact_versioned(input)?;
        // Observe the actual checked writer while its original enclosing allowance
        // is live; returned numeric fields cannot recover this provenance later.
        let canonical = norito::core::classify_decode_attempt(|| entrypoint.encode_wire_v1())
            .map_err(iroha_version::error::Error::from)?;
        if canonical.as_slice() != input {
            return Err(iroha_version::error::Error::from(
                norito::core::Error::NonCanonicalEncoding,
            ));
        }
        Ok(entrypoint)
    }
}
#[cfg(feature = "transparent_api")]
impl From<SignedTransaction> for (AccountId, Executable) {
    fn from(source: SignedTransaction) -> Self {
        (source.payload.authority, source.payload.instructions)
    }
}
impl TransactionSignature {
    /// Signature itself
    pub fn payload(&self) -> &Signature {
        &self.0
    }
}
impl MultisigSignatures {
    /// Produce a multisig signature bundle by signing the given payload with each private key.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionSignatureError::NoSignatures`] if no signers are provided.
    #[allow(single_use_lifetimes)]
    pub fn from_signers<'a>(
        payload: &TransactionPayload,
        signers: impl IntoIterator<Item = &'a iroha_crypto::PrivateKey>,
    ) -> Result<Self, TransactionSignatureError> {
        let signatures: Vec<MultisigSignature> = signers
            .into_iter()
            .map(|private_key| {
                let signer = PublicKey::from(private_key.clone());
                let signature = SignatureOf::try_new(private_key, payload)
                    .map_err(|err| TransactionSignatureError::CryptoError(err.to_string()))?;
                Ok(MultisigSignature::new(signer, signature))
            })
            .collect::<Result<_, _>>()?;
        if signatures.is_empty() {
            return Err(TransactionSignatureError::NoSignatures);
        }
        Ok(Self::new(signatures))
    }
}

impl norito::json::FastJsonWrite for TransactionEntrypoint {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        match self {
            TransactionEntrypoint::External(tx) => {
                norito::json::write_json_string("External", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(tx, out);
            }
            TransactionEntrypoint::SealedCommitment(commitment) => {
                norito::json::write_json_string("SealedCommitment", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(commitment, out);
            }
            TransactionEntrypoint::SealedReveal(reveal) => {
                norito::json::write_json_string("SealedReveal", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(reveal, out);
            }
        }
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            match self {
                TransactionEntrypoint::External(tx) => {
                    out.push_str("\"External\":")?;
                    norito::json::JsonSerialize::json_serialize_to(tx, out)?;
                }
                TransactionEntrypoint::SealedCommitment(commitment) => {
                    out.push_str("\"SealedCommitment\":")?;
                    norito::json::JsonSerialize::json_serialize_to(commitment, out)?;
                }
                TransactionEntrypoint::SealedReveal(reveal) => {
                    out.push_str("\"SealedReveal\":")?;
                    norito::json::JsonSerialize::json_serialize_to(reveal, out)?;
                }
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl norito::json::JsonDeserialize for TransactionEntrypoint {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        parser.skip_ws();
        parser.consume_char(b'{')?;
        let key = parser.parse_key()?;
        let value = match key.as_str() {
            "External" => {
                let tx = SignedTransaction::json_deserialize(parser)?;
                TransactionEntrypoint::External(tx)
            }
            "SealedCommitment" => {
                let commitment = SignedSealedTransactionCommitment::json_deserialize(parser)?;
                TransactionEntrypoint::SealedCommitment(commitment)
            }
            "SealedReveal" => {
                let reveal = SealedTransactionReveal::json_deserialize(parser)?;
                TransactionEntrypoint::SealedReveal(reveal)
            }
            other => {
                return Err(norito::json::Error::UnknownField {
                    field: other.to_owned(),
                });
            }
        };
        parser.skip_ws();
        parser.consume_char(b'}')?;
        Ok(value)
    }
}

impl norito::json::JsonSerialize for TransactionResult {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        match &self.0 {
            Ok(sequence) => {
                norito::json::write_json_string("Ok", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(sequence, out);
            }
            Err(reason) => {
                norito::json::write_json_string("Err", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(reason, out);
            }
        }
        out.push(',');
        norito::json::write_json_string("batch_transfer_outcomes", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.1, out);
        out.push(',');
        norito::json::write_json_string("nexus_fee_receipt", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.2, out);
        out.push_str(",\"contract_events\":");
        norito::json::JsonSerialize::json_serialize(&self.3, out);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            match &self.0 {
                Ok(sequence) => {
                    out.push_str("\"Ok\":")?;
                    norito::json::JsonSerialize::json_serialize_to(sequence, out)?;
                }
                Err(reason) => {
                    out.push_str("\"Err\":")?;
                    norito::json::JsonSerialize::json_serialize_to(reason, out)?;
                }
            }
            out.push_str(",\"batch_transfer_outcomes\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.1, out)?;
            out.push_str(",\"nexus_fee_receipt\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.2, out)?;
            out.push_str(",\"contract_events\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.3, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl norito::json::JsonDeserialize for TransactionResult {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        parser.skip_ws();
        parser.consume_char(b'{')?;
        let mut inner = None;
        let mut batch_transfer_outcomes = None;
        let mut nexus_fee_receipt = None;
        let mut contract_events = None;
        loop {
            parser.skip_ws();
            if parser.try_consume_char(b'}')? {
                break;
            }
            let key = parser.parse_key()?;
            match key.as_str() {
                "Ok" => {
                    if inner.is_some() {
                        return Err(norito::json::Error::duplicate_field("Ok"));
                    }
                    inner = Some(TransactionResultInner::Ok(
                        DataTriggerSequence::json_deserialize(parser)?,
                    ));
                }
                "Err" => {
                    if inner.is_some() {
                        return Err(norito::json::Error::duplicate_field("Err"));
                    }
                    inner = Some(TransactionResultInner::Err(
                        error::TransactionRejectionReason::json_deserialize(parser)?,
                    ));
                }
                "batch_transfer_outcomes" => {
                    if batch_transfer_outcomes.is_some() {
                        return Err(norito::json::Error::duplicate_field(
                            "batch_transfer_outcomes",
                        ));
                    }
                    batch_transfer_outcomes =
                        Some(Vec::<AssetBatchTransferOutcome>::json_deserialize(parser)?);
                }
                "contract_events" => {
                    if contract_events.is_some() {
                        return Err(norito::json::Error::duplicate_field("contract_events"));
                    }
                    contract_events = Some(
                        crate::smart_contract::event::ContractEmissionsV1::json_deserialize(
                            parser,
                        )?,
                    );
                }
                "nexus_fee_receipt" => {
                    if nexus_fee_receipt.is_some() {
                        return Err(norito::json::Error::duplicate_field("nexus_fee_receipt"));
                    }
                    nexus_fee_receipt = Some(Option::<NexusFeeReceipt>::json_deserialize(parser)?);
                }
                other => return Err(norito::json::Error::unknown_field(other.to_owned())),
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.consume_char(b'}')?;
            break;
        }
        Ok(TransactionResult(
            inner.ok_or_else(|| norito::json::Error::missing_field("Ok or Err"))?,
            batch_transfer_outcomes.unwrap_or_default(),
            nexus_fee_receipt
                .ok_or_else(|| norito::json::Error::missing_field("nexus_fee_receipt"))?,
            contract_events.ok_or_else(|| norito::json::Error::missing_field("contract_events"))?,
        ))
    }
}

impl norito::json::FastJsonWrite for ExecutionStep {
    fn write_json(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(&self.0, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::JsonSerialize::json_serialize_to(&self.0, out)
    }
}

impl norito::json::JsonDeserialize for ExecutionStep {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        ConstVec::<InstructionBox>::json_deserialize(parser).map(ExecutionStep)
    }
}
struct ExternalEntrypointRef<'a>(&'a TransactionPayload);

impl norito::core::SerializePayload for ExternalEntrypointRef<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::SerializePayload::serialize(&0_u32, writer)?;
        norito::core::write_len_prefixed(writer, self.0)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0
            .encoded_len_hint()
            .map(|len| 4_usize.saturating_add(8).saturating_add(len))
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        let len = self.0.encoded_len_exact()?;
        Some(
            4_usize
                .saturating_add(norito::core::len_prefix_len(len))
                .saturating_add(len),
        )
    }
}
impl TransactionBuilder {
    fn new_with_time(
        domain: TransactionDomain,
        authority: AccountId,
        creation_time_ms: u64,
        fee_payment: FeePaymentIntent,
    ) -> Self {
        let construction = match domain {
            TransactionDomain::Network(_) => TransactionConstruction::Ordinary,
            TransactionDomain::Genesis => TransactionConstruction::Genesis,
        };
        Self {
            payload: TransactionPayload {
                domain,
                authority,
                creation_time_ms,
                nonce: None,
                time_to_live_ms: Some(
                    NonZeroU64::new(
                        u64::try_from(DEFAULT_TRANSACTION_TIME_TO_LIVE.as_millis())
                            .expect("default transaction TTL fits in u64 milliseconds"),
                    )
                    .expect("default transaction TTL is non-zero"),
                ),
                instructions: Vec::<InstructionBox>::new().into(),
                fee_payment,
                metadata: Metadata::default(),
                attachments: None,
            },
            multisig_signatures: None,
            construction,
        }
    }
    /// Construct [`Self`], using the time from [`TimeSource`]
    // we don't want to expose this to non-tests
    #[inline]
    pub fn new_with_time_source(
        network_id: NetworkId,
        authority: AccountId,
        time_source: &TimeSource,
        fee_payment: FeePaymentIntent,
    ) -> Self {
        let creation_time_ms = time_source
            .get_unix_time()
            .as_millis()
            .try_into()
            .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX");
        Self::new_with_time(
            TransactionDomain::Network(network_id),
            authority,
            creation_time_ms,
            fee_payment,
        )
    }
    /// Construct [`Self`] with the exact signature-bound fee payment intent.
    #[inline]
    pub fn new(network_id: NetworkId, authority: AccountId, fee_payment: FeePaymentIntent) -> Self {
        Self::new_with_time_source(
            network_id,
            authority,
            &TimeSource::new_system(),
            fee_payment,
        )
    }
    /// Construct a transaction carrying the explicit genesis-only domain.
    ///
    /// Runtime admission rejects this domain. Genesis construction and
    /// validation are the only callers that may use it.
    #[inline]
    pub fn new_genesis(authority: AccountId, fee_payment: FeePaymentIntent) -> Self {
        Self::new_genesis_with_time_source(authority, &TimeSource::new_system(), fee_payment)
    }
    /// Construct a genesis-domain transaction using an explicit time source.
    #[inline]
    pub fn new_genesis_with_time_source(
        authority: AccountId,
        time_source: &TimeSource,
        fee_payment: FeePaymentIntent,
    ) -> Self {
        let creation_time_ms = time_source
            .get_unix_time()
            .as_millis()
            .try_into()
            .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX");
        Self::new_with_time(
            TransactionDomain::Genesis,
            authority,
            creation_time_ms,
            fee_payment,
        )
    }
}
include!("signed/builder_construction.rs");
impl TransactionBuilder {
    /// Borrow the exact unsigned payload currently held by this builder.
    #[must_use]
    pub const fn payload(&self) -> &TransactionPayload {
        &self.payload
    }
    /// Set instructions for this transaction
    pub fn with_instructions<I>(mut self, instructions: impl IntoIterator<Item = I>) -> Self
    where
        I: Into<InstructionBox>,
    {
        self.payload.instructions = instructions
            .into_iter()
            .map(Into::into)
            .collect::<Vec<InstructionBox>>()
            .into();
        self.rebind_attachments();
        self
    }
    /// Add IVM bytecode to this transaction
    pub fn with_bytecode(mut self, bytecode: IvmBytecode) -> Self {
        self.payload.instructions = bytecode.into();
        self.rebind_attachments();
        self
    }
    /// Set executable for this transaction
    pub fn with_executable(mut self, executable: Executable) -> Self {
        self.payload.instructions = executable;
        self.rebind_attachments();
        self
    }
    /// Set an ordered, atomic mix of instructions and deployed-contract calls.
    ///
    /// An empty iterator can be represented for decoding symmetry but is
    /// rejected by transaction admission.
    pub fn with_executable_batch<I>(mut self, items: impl IntoIterator<Item = I>) -> Self
    where
        I: Into<crate::transaction::ExecutableBatchItem>,
    {
        self.payload.instructions = Executable::Batch(
            items
                .into_iter()
                .map(Into::into)
                .collect::<Vec<crate::transaction::ExecutableBatchItem>>()
                .into(),
        );
        self.rebind_attachments();
        self
    }
    /// Adds metadata to this transaction
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.payload.metadata = metadata;
        self.rebind_attachments();
        self
    }
    /// Set the required signature-bound fee payer and charge limits.
    pub fn with_fee_payment_intent(mut self, intent: FeePaymentIntent) -> Self {
        self.payload.fee_payment = intent;
        self.rebind_attachments();
        self
    }
    /// Attach multisig signatures for a multisig authority.
    pub fn with_multisig_signatures(mut self, signatures: MultisigSignatures) -> Self {
        self.multisig_signatures = Some(signatures);
        self
    }
    /// Set nonce for this transaction
    pub fn set_nonce(&mut self, nonce: NonZeroU32) -> &mut Self {
        self.payload.nonce = Some(nonce);
        self.rebind_attachments();
        self
    }
    /// Set time-to-live for this transaction
    ///
    /// A zero duration leaves the builder with an invalid missing lifetime; fallible
    /// payload/signing workflows then return [`TransactionSignatureError::MissingTimeToLive`].
    pub fn set_ttl(&mut self, time_to_live: Duration) -> &mut Self {
        let ttl: u64 = time_to_live
            .as_millis()
            .try_into()
            .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX");
        self.payload.time_to_live_ms = NonZeroU64::new(ttl);
        self.rebind_attachments();
        self
    }
    /// Set creation time of transaction
    pub fn set_creation_time(&mut self, value: Duration) -> &mut Self {
        self.payload.creation_time_ms = u64::try_from(value.as_millis())
            .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX");
        self.rebind_attachments();
        self
    }
    /// Encode the transaction payload to canonical Norito bytes.
    ///
    /// This is the byte sequence external signers should receive before
    /// applying Iroha's typed transaction prehash.
    #[must_use]
    pub fn encode_payload(&self) -> Vec<u8> {
        norito::codec::encode_adaptive(&self.payload)
    }
    /// Return the canonical prehash signed by transaction signatures.
    #[must_use]
    pub fn payload_hash(&self) -> Hash {
        Hash::from(HashOf::new(&self.payload))
    }
    /// Return the canonical prehash signed by transaction signatures as raw bytes.
    #[must_use]
    pub fn payload_hash_bytes(&self) -> [u8; Hash::LENGTH] {
        *HashOf::new(&self.payload).as_ref()
    }
    /// Canonical external transaction identifier for this exact unsigned intent.
    ///
    /// This matches [`SignedTransaction::hash_as_entrypoint`] after signing.
    /// Authorization proofs are excluded from transaction identity, so callers
    /// can reconcile a prepared input before receiving a signature. This is
    /// distinct from [`Self::payload_hash`], the prehash signed by the authority.
    #[must_use]
    pub fn hash_as_entrypoint(&self) -> HashOf<TransactionEntrypoint> {
        let entry_hash = HashOf::new(&ExternalEntrypointRef(&self.payload));
        HashOf::from_untyped_unchecked(Hash::from(entry_hash))
    }
    /// Build a signed transaction from a signature produced by an external signer.
    ///
    /// The signature is not trusted blindly by this constructor. Callers that
    /// receive signatures over the wire should verify the returned transaction
    /// with [`SignedTransaction::verify_signature`] before submitting it.
    #[must_use]
    pub fn build_with_signature(self, signature: Signature) -> SignedTransaction {
        SignedTransaction {
            signature: TransactionSignature(SignatureOf::from_signature(signature)),
            payload: self.payload,
            multisig_signatures: self.multisig_signatures,
            entrypoint_hash: EntrypointHashMemo::default(),
        }
    }
    /// Try to sign transaction with provided key pair.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied key does not control the exact
    /// signature-bound authority or the signature backend cannot sign.
    pub fn try_sign(
        self,
        private_key: &iroha_crypto::PrivateKey,
    ) -> Result<SignedTransaction, TransactionSignatureError> {
        use iroha_crypto::PublicKey;
        self.validate_payload_state()?;
        let payload = self.payload;
        let expected = payload
            .authority
            .try_signatory()
            .ok_or(TransactionSignatureError::UnsupportedMultisigAuthority)?;
        let derived = PublicKey::from(private_key.clone());
        if expected != &derived {
            return Err(TransactionSignatureError::AuthorityKeyMismatch);
        }
        let signature = TransactionSignature(
            SignatureOf::try_new(private_key, &payload)
                .map_err(|err| TransactionSignatureError::CryptoError(err.to_string()))?,
        );
        Ok(SignedTransaction {
            signature,
            payload,
            multisig_signatures: self.multisig_signatures,
            entrypoint_hash: EntrypointHashMemo::default(),
        })
    }
    /// Sign transaction with provided key pair.
    #[must_use]
    pub fn sign(self, private_key: &iroha_crypto::PrivateKey) -> SignedTransaction {
        self.try_sign(private_key)
            .expect("signing should succeed for a valid private key and transaction payload")
    }
    /// Try to sign a transaction whose authority uses a multisig controller.
    ///
    /// The provided signer keys are used to produce a canonical multisig
    /// signature bundle. Duplicate signers are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if no signer keys are provided or a signature backend
    /// fails while signing one of the multisig entries.
    #[allow(single_use_lifetimes)]
    pub fn try_sign_multisig<'a>(
        self,
        signers: impl IntoIterator<Item = &'a iroha_crypto::PrivateKey>,
    ) -> Result<SignedTransaction, TransactionSignatureError> {
        self.validate_payload_state()?;
        let payload = self.payload;
        let mut bundle = self
            .multisig_signatures
            .unwrap_or_else(|| MultisigSignatures::new(Vec::new()));
        let produced = MultisigSignatures::from_signers(&payload, signers)?;
        bundle.signatures.extend(produced.signatures);
        bundle = MultisigSignatures::new(bundle.signatures);
        bundle.validate_canonical()?;
        let primary_signature = bundle
            .signatures
            .first()
            .expect("multisig signing requires at least one signer")
            .signature
            .clone();
        Ok(SignedTransaction {
            signature: TransactionSignature(primary_signature),
            payload,
            multisig_signatures: Some(bundle),
            entrypoint_hash: EntrypointHashMemo::default(),
        })
    }
    /// Sign a transaction whose authority uses a multisig controller.
    ///
    /// The provided signer keys are used to produce a canonical multisig
    /// signature bundle. Duplicate signers are rejected.
    ///
    /// # Panics
    ///
    /// Panics if no signer keys are provided or a signature backend fails while
    /// signing one of the multisig entries.
    #[must_use]
    #[allow(single_use_lifetimes)]
    pub fn sign_multisig<'a>(
        self,
        signers: impl IntoIterator<Item = &'a iroha_crypto::PrivateKey>,
    ) -> SignedTransaction {
        self.try_sign_multisig(signers)
            .expect("multisig signing requires at least one valid signer")
    }
}
#[cfg(test)]
fn test_network_id(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([seed; Hash::LENGTH]),
    ))
}
#[cfg(test)]
#[path = "signed/authorization_tests.rs"]
mod authorization_tests;
#[cfg(all(test, feature = "fault_injection"))]
#[path = "signed/fault_injection_tests.rs"]
mod fault_injection_tests;
#[cfg(test)]
#[path = "signed/signature_codec_tests.rs"]
mod signature_codec_tests;
#[cfg(test)]
#[path = "signed_model_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "signed/ttl_tests.rs"]
mod ttl_tests;
#[cfg(test)]
#[path = "signed/wire_v1_test_support.rs"]
mod wire_v1_test_support;
include!("signed/attachments_tests.rs");
impl TransactionEntrypoint {
    /// Account authorized to initiate this transaction when one exists.
    #[inline]
    pub fn authority_opt(&self) -> Option<&AccountId> {
        match self {
            TransactionEntrypoint::External(entrypoint) => Some(entrypoint.authority()),
            TransactionEntrypoint::SealedCommitment(entrypoint) => Some(entrypoint.authority()),
            TransactionEntrypoint::SealedReveal(entrypoint) => {
                Some(entrypoint.signed_transaction().authority())
            }
        }
    }
    /// Account authorized to initiate this transaction.
    ///
    #[inline]
    pub fn authority(&self) -> &AccountId {
        match self {
            TransactionEntrypoint::External(entrypoint) => entrypoint.authority(),
            TransactionEntrypoint::SealedCommitment(entrypoint) => entrypoint.authority(),
            TransactionEntrypoint::SealedReveal(entrypoint) => {
                entrypoint.signed_transaction().authority()
            }
        }
    }
    /// Creation timestamp in milliseconds when the entrypoint carries one.
    #[inline]
    pub fn creation_time_ms(&self) -> Option<u64> {
        match self {
            TransactionEntrypoint::External(entrypoint) => {
                u64::try_from(entrypoint.creation_time().as_millis()).ok()
            }
            TransactionEntrypoint::SealedReveal(entrypoint) => {
                u64::try_from(entrypoint.signed_transaction().creation_time().as_millis()).ok()
            }
            TransactionEntrypoint::SealedCommitment(_) => None,
        }
    }
    /// Metadata attached to the entrypoint when one exists.
    #[inline]
    pub fn metadata(&self) -> Option<&Metadata> {
        match self {
            TransactionEntrypoint::External(entrypoint) => Some(entrypoint.metadata()),
            TransactionEntrypoint::SealedReveal(entrypoint) => {
                Some(entrypoint.signed_transaction().metadata())
            }
            TransactionEntrypoint::SealedCommitment(_) => None,
        }
    }
    /// Hash for this transaction entrypoint.
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        match self {
            Self::External(transaction) => transaction.hash_as_entrypoint(),
            Self::SealedCommitment(_) | Self::SealedReveal(_) => HashOf::new(self),
        }
    }
    /// Actual network execution-call hash, distinct from a sealed reveal outer identity.
    ///
    /// Result leaves and block entrypoint Merkle trees always use [`Self::hash`]. A sealed reveal,
    /// however, executes its inner signed transaction, whose call hash keys execution-scoped
    /// evidence such as native batch receipts and FASTPQ transcripts. Other network entrypoints
    /// use their canonical outer hash. Internal invocation identities belong to typed outputs.
    #[inline]
    pub fn execution_call_hash(&self) -> HashOf<Self> {
        match self {
            Self::SealedReveal(reveal) => reveal.signed_transaction().hash_as_entrypoint(),
            _ => self.hash(),
        }
    }
}
impl TransactionResult {
    /// Construct a transaction result without independent-batch receipts.
    #[inline]
    #[must_use]
    pub fn new(inner: TransactionResultInner) -> Self {
        Self(
            inner,
            Vec::new(),
            None,
            crate::smart_contract::event::ContractEmissionsV1::default(),
        )
    }
    /// Durable per-leg receipts emitted by an independently settled native transfer batch.
    #[inline]
    #[must_use]
    pub fn batch_transfer_outcomes(&self) -> &[AssetBatchTransferOutcome] {
        &self.1
    }
    /// Replace the durable per-leg receipts committed by this transaction-result leaf.
    #[inline]
    pub fn set_batch_transfer_outcomes(&mut self, outcomes: Vec<AssetBatchTransferOutcome>) {
        self.1 = outcomes;
    }
    /// Exact actual Nexus settlement committed by this result leaf.
    #[inline]
    #[must_use]
    pub fn nexus_fee_receipt(&self) -> Option<&NexusFeeReceipt> {
        self.2.as_ref()
    }
    /// Set the execution owner's actual charge before result sizing and hashing.
    #[inline]
    pub fn set_nexus_fee_receipt(&mut self, receipt: Option<NexusFeeReceipt>) {
        self.2 = receipt;
    }
    /// Actual committed native contract emissions in execution order.
    #[inline]
    #[must_use]
    pub fn contract_events(&self) -> &crate::smart_contract::event::ContractEmissionsV1 {
        &self.3
    }
    /// Install the execution owner's immutable event collection before sizing and hashing.
    #[inline]
    pub fn set_contract_events(
        &mut self,
        events: crate::smart_contract::event::ContractEmissionsV1,
    ) {
        self.3 = events;
    }
    /// Hash for this transaction result.
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(self)
    }
    /// Hash for this transaction result computed from its inner representation.
    #[inline]
    pub fn hash_from_inner(inner: &TransactionResultInner) -> HashOf<Self> {
        HashOf::new(&TransactionResult::new(inner.clone()))
    }
}
impl From<TransactionResultInner> for TransactionResult {
    #[inline]
    fn from(inner: TransactionResultInner) -> Self {
        Self::new(inner)
    }
}
impl core::ops::Deref for TransactionResult {
    type Target = TransactionResultInner;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::fmt::Display for TransactionResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TransactionResult")
    }
}
include!("signed_norito_rpc_fixture_tests.rs");

#[cfg(test)]
mod checked_container_cleanup_tests {
    //! Original owning writer refusal and nested-depth controls.
    use super::*;
    use crate::checked_container_refusal_controls::{account, audit, definition};

    #[test]
    fn original_entrypoint_checked_container_retains_every_legal_variant_and_depth() {
        let key = iroha_crypto::KeyPair::from_seed(vec![61; 32], iroha_crypto::Algorithm::Ed25519);
        let authority = crate::account::AccountId::new(key.public_key().clone());
        let network =
            crate::NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"original network"),
            ));
        let fees = FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                definition(),
                7_u32.into(),
            )],
            None,
        );
        let tx = TransactionBuilder::new(network, authority.clone(), fees)
            .with_instructions([crate::isi::Log::new(crate::Level::INFO, "original".into())])
            .sign(key.private_key());
        audit(&TransactionEntrypoint::External(tx));
        let commitment = SealedTransactionCommitmentPayload::new(
            network,
            authority,
            iroha_crypto::Hash::new(b"sealed original"),
            3,
            7,
            None,
        );
        audit(&TransactionEntrypoint::SealedCommitment(
            SignedSealedTransactionCommitment::sign(commitment, key.private_key()),
        ));
        let fees = FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                definition(),
                7_u32.into(),
            )],
            None,
        );
        let reveal_tx = TransactionBuilder::new(network, account(61), fees)
            .with_instructions([crate::isi::Log::new(crate::Level::INFO, "reveal".into())])
            .sign(key.private_key());
        audit(&TransactionEntrypoint::SealedReveal(
            SealedTransactionReveal::new(
                iroha_crypto::Hash::new(b"original reveal"),
                reveal_tx,
                [7; 32],
            ),
        ));
    }

    #[test]
    fn original_transaction_result_checked_container_retains_success_rejection_and_depth() {
        audit(&TransactionResult::new(Ok(Vec::default())));
        let rejection = crate::transaction::error::TransactionRejectionReason::LimitCheck(
            crate::transaction::error::TransactionLimitError {
                reason: "original rejection".into(),
            },
        );
        audit(&TransactionResult::new(Err(rejection)));
    }
}
