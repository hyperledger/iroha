//! Nominal complete-entry quantity effects before execution authentication or proof admission.
//!
//! These DTOs preserve exact operation, scoped balance, lifecycle and authorization
//! claims. Decoding or hashing them grants no authority. A verifier must obtain
//! independent expected commitments from authenticated execution; ordinary
//! artifacts transport this statement, while AXT retains its transfer statement.

use super::{
    FastpqPublicInputs, FastpqSourceExecutionEntryV1, FastpqSourceStatementContextV1,
    FastpqStateTransition,
};
use crate::{
    account::AccountId,
    asset::{AssetBalanceScope, AssetDefinitionId},
    nexus::AxtAssetIncarnationV1,
};
use iroha_crypto::Hash;
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;

mod admitted;
mod commitment;
pub use admitted::{
    AllocatedFastpqEffectsV1, FastpqEffectsDecodeError, PendingFastpqEffectsDecodeV1,
    decode_fastpq_source_entry_payload_v1, decode_fastpq_source_leaf_payload_v1,
    decode_fastpq_source_manifest_frame_v1, decode_fastpq_source_manifest_payload_v1,
};
pub use commitment::*;

/// Exact definition and externally authenticated registration/lifecycle identity.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqExecutionAssetV1")]
#[norito(decode_fields)]
pub struct FastpqExecutionAssetV1 {
    /// Canonical definition identity.
    pub definition: AssetDefinitionId,
    /// Exact existing registry incarnation supplied by authenticated execution, never inferred.
    pub incarnation: AxtAssetIncarnationV1,
}

/// Exact account balance bucket, without alias or display-address interpretation.
#[derive(
    Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqExecutionBalanceV1")]
#[norito(decode_fields)]
pub struct FastpqExecutionBalanceV1 {
    /// Definition and exact lifecycle.
    pub asset: FastpqExecutionAssetV1,
    /// Full canonical controller.
    pub account: AccountId,
    /// Exact resolved storage scope, including explicit global scope.
    pub scope: AssetBalanceScope,
}

/// Domain-separated balance, total-supply or lifecycle key for the effect relation.
#[derive(
    Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqExecutionQuantityKeyV1")]
pub enum FastpqExecutionQuantityKeyV1 {
    /// A single exact account balance bucket.
    #[codec(index = 0)]
    Balance(FastpqExecutionBalanceV1),
    /// Definition-wide circulating supply for one exact lifecycle.
    #[codec(index = 1)]
    Supply(FastpqExecutionAssetV1),
    /// Presence of the exact definition/incarnation: one while live, zero after retirement.
    /// This key never aliases a zero circulating-supply quantity.
    #[codec(index = 2)]
    Lifecycle(FastpqExecutionAssetV1),
}

/// Original exact quantity facts for a transfer; self-transfer legs remain sequential.
#[derive(
    Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqExecutionTransferV1")]
#[norito(decode_fields)]
pub struct FastpqExecutionTransferV1 {
    /// Exact sender bucket.
    pub source: FastpqExecutionBalanceV1,
    /// Exact receiver bucket.
    pub destination: FastpqExecutionBalanceV1,
    /// Unnormalized exact amount.
    pub amount: Quantity,
    /// Sender before debit.
    pub source_before: Quantity,
    /// Sender after debit, including the intermediate self-transfer value.
    pub source_after: Quantity,
    /// Receiver before credit, after debit for a self-transfer.
    pub destination_before: Quantity,
    /// Receiver after credit.
    pub destination_after: Quantity,
}

/// Original balance and supply facts for one explicitly authorized mint or burn.
#[derive(
    Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqExecutionSupplyChangeV1")]
#[norito(decode_fields)]
pub struct FastpqExecutionSupplyChangeV1 {
    /// Exact affected balance; its asset also identifies the supply key.
    pub balance: FastpqExecutionBalanceV1,
    /// Original amount, without truncation or narrow integer conversion.
    pub amount: Quantity,
    /// Balance before the operation.
    pub balance_before: Quantity,
    /// Balance after the operation.
    pub balance_after: Quantity,
    /// Circulating supply before the operation.
    pub supply_before: Quantity,
    /// Circulating supply after the operation.
    pub supply_after: Quantity,
}

/// Typed arithmetic relation; no opaque gap or arbitrary-write variant exists.
#[derive(
    Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqExecutionEffectKindV1")]
pub enum FastpqExecutionEffectKindV1 {
    /// Source subtraction followed by destination addition.
    #[codec(index = 0)]
    Transfer(FastpqExecutionTransferV1),
    /// Balance and supply increase by the same amount.
    #[codec(index = 1)]
    Mint(FastpqExecutionSupplyChangeV1),
    /// Balance and supply decrease by the same amount.
    #[codec(index = 2)]
    Burn(FastpqExecutionSupplyChangeV1),
    /// Retire this exact live incarnation after its circulating supply reaches zero.
    /// The closed relation requires zero supply and changes lifecycle presence from one
    /// to zero. It cannot register, resurrect or substitute a different incarnation.
    #[codec(index = 3)]
    Retire(FastpqExecutionAssetV1),
}

/// One original committed effect in complete execution order.
#[derive(
    Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqExecutionEffectV1")]
#[norito(decode_fields)]
pub struct FastpqExecutionEffectV1 {
    /// Zero-based contiguous committed-effect ordinal within the logical entry.
    pub ordinal: u32,
    /// Actual authority-set commitment; its bytes alone establish no authorization.
    pub authority_digest: Hash,
    /// Execution-owned authorization/purpose context committed by the source owner.
    pub authorization_context: Hash,
    /// Exact original typed operation and quantities.
    pub kind: FastpqExecutionEffectKindV1,
}

/// Complete logical execution source, including route/incarnation and original identity.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    norito::Encode,
    norito::Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqExecutionEffectContextV1")]
#[norito(decode_fields)]
pub struct FastpqExecutionEffectContextV1 {
    /// Source network and height.
    pub source: FastpqSourceStatementContextV1,
    /// Exact entry identity, execution kind and route.
    pub entry: FastpqSourceExecutionEntryV1,
}

/// Complete ordered effect tape, including zero-effect entries.
#[derive(
    Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqExecutionEffectsV1")]
#[norito(decode_fields)]
pub struct FastpqExecutionEffectsV1 {
    /// Exact source owner context.
    pub context: FastpqExecutionEffectContextV1,
    /// Every original effect once, in committed execution order.
    pub effects: Vec<FastpqExecutionEffectV1>,
}

/// Candidate ordinary execution statement; not an accepted artifact or policy selection.
#[derive(
    Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqExecutionEffectStatementV1")]
pub struct FastpqExecutionEffectStatementV1 {
    /// Complete advertised public inputs, compared with independent expectations.
    pub public_inputs: FastpqPublicInputs,
    /// Canonical complete operation-tagged row ordering commitment.
    pub ordering_hash: [u8; 32],
    /// Complete key/operation-sorted transition table, retaining duplicate rows.
    pub transitions: Vec<FastpqStateTransition>,
    /// Complete original source-owned effect tape.
    pub effects: FastpqExecutionEffectsV1,
}

/// Canonically encode a complete tagged balance/supply key.
/// # Errors
/// Returns the canonical Norito encoding error without inventing a replacement key.
pub fn execution_quantity_key_v1(
    key: &FastpqExecutionQuantityKeyV1,
) -> Result<Vec<u8>, norito::Error> {
    let frame = norito::encode_canonical(key)?;
    let mut key = b"iroha:fastpq:execution-quantity-key:v1\0".to_vec();
    key.extend_from_slice(&frame);
    Ok(key)
}

/// Commitment to complete original facts, not an authorization certificate.
/// # Errors
/// Returns the canonical encoding error, ordinal mismatch or count overflow without
/// returning a partial or differently ordered commitment.
pub fn execution_effects_digest_v1(
    effects: &FastpqExecutionEffectsV1,
) -> Result<Hash, norito::Error> {
    let mut journal = FastpqExecutionEffectCommitmentV1::new(effects.context);
    for effect in &effects.effects {
        journal.append(FastpqExecutionEffectRefV1::from(effect))?;
    }
    journal.digest()
}

/// Commitment to the complete candidate statement under its distinct semantics domain.
/// # Errors
/// Returns the canonical encoding error without hashing a prefix or projection.
pub fn execution_effect_statement_digest_v1(
    statement: &FastpqExecutionEffectStatementV1,
) -> Result<Hash, norito::Error> {
    canonical_effect_digest(b"fastpq:execution-effects:v1:statement|", statement)
}

/// Stream the exact canonical frame after its original semantics domain.
/// No output-sized frame is retained. Serializer-internal scratch remains the
/// serializer's responsibility. Preserve the original codec error and discard
/// every partial hash, including second-pass framing/checksum failures.
fn canonical_effect_digest<T: norito::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<Hash, norito::Error> {
    let mut encoding_error = None;
    let digest = Hash::new_from_writer(|writer| {
        writer.write_all(domain)?;
        norito::core::write_canonical_to_writer(value, writer).map_err(|error| {
            encoding_error = Some(error);
            std::io::Error::other("complete effect canonical encoding failed")
        })
    });
    encoding_error.map_or_else(|| digest.map_err(norito::Error::Io), Err)
}

#[cfg(test)]
mod tests;
