//! Atomic cross-transaction (AXT) envelope and fragment types for Nexus lanes.
//!
//! These structures mirror the IVM syscall surface while providing Norito-compatible
//! schemas for WSV/block persistence and gossip replication.

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use crate::{
    NetworkId, asset::id::AssetDefinitionId, block::BlockHeader, nexus::UniversalAccountId,
    transaction::signed::TransactionEntrypoint,
};
use iroha_crypto::{Hash, HashOf, PrivateKey, PublicKey, Signature};
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::numeric::{NumericOperationError, Quantity};
use iroha_schema::IntoSchema;
use iroha_zkp_poseidon::poseidon::hash_bytes as poseidon_hash_bytes;
use norito::codec::{Decode, Encode, encode_adaptive};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
/// Maximum number of proof-bound remote-spend statements in one V1 FASTPQ binding.
///
/// This matches the consensus ceiling for authenticated AXT handles in one
/// block, so one proof can legitimately cover every same-dataspace handle
/// without permitting an unbounded outer proof envelope.
pub const MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1: usize = 65_536;
/// Maximum encoded [`AxtProofEnvelope`] payload accepted from one [`ProofBlob`].
///
/// The inner FASTPQ batch/proof payload has its own one MiB verifier limit. This
/// outer ceiling leaves one additional MiB for the envelope and binding while
/// keeping every proof-envelope decode bounded at the shared data-model layer.
pub const MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
/// Domain separator for one finalized source-state anchor digest.
pub const AXT_FINALIZED_SPEND_ANCHOR_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:axt:finalized-spend-anchor:digest:v1\0";
/// Domain separator for the exact proof carried by one anchored spend.
pub const AXT_ANCHORED_SPEND_PROOF_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:axt:anchored-spend:proof:digest:v1\0";
/// Domain separator for the exact reusable handle carried by one anchored spend.
pub const AXT_ANCHORED_SPEND_HANDLE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:axt:anchored-spend:handle:digest:v1\0";
/// Domain separator for a fresh issuer signature over one exact anchored spend.
pub const AXT_ANCHORED_SPEND_ISSUER_SIGNATURE_DOMAIN_V1: &[u8] =
    b"iroha:axt:anchored-spend:issuer-signature:v1\0";
/// Domain separator for one claimed successful source execution receipt.
pub const AXT_SOURCE_SUCCESS_RECEIPT_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:axt:source-success-receipt:digest:v1\0";
/// Domain separator for the complete public facts of one ordered transfer.
pub const AXT_SOURCE_TRANSFER_DIGEST_DOMAIN_V1: &[u8] = b"iroha:axt:source-transfer:digest:v1\0";
/// Domain separator for one source receipt and exact ordered transfer occurrence.
pub const AXT_SOURCE_TRANSFER_OCCURRENCE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:axt:source-transfer-occurrence:digest:v1\0";

/// Domain separator for the exact ordered transaction wires in a finalized AXT anchor.
pub const AXT_ORDERED_TRANSACTION_SET_DOMAIN_V1: &[u8] =
    b"iroha:axt:ordered-transaction-wire-set:v1\0";
/// Maximum transaction count in one finalized AXT anchor witness.
///
/// This bounded AXT verification surface admits up to the per-block AXT handle
/// ceiling. This witness-admission limit does not restrict canonical block hashing.
pub const MAX_AXT_FINALIZED_TRANSACTIONS_V1: usize = 65_536;
/// Maximum cumulative canonical transaction-wire bytes in one finalized AXT witness.
///
/// The consensus executed-block hard ceiling also bounds its transaction wires.
pub const MAX_AXT_FINALIZED_TRANSACTION_WIRE_BYTES_V1: u64 =
    crate::block::consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES;
// Every supported target must represent the same consensus-implied count cap.
const _: () = assert!(MAX_AXT_FINALIZED_TRANSACTION_WIRE_BYTES_V1 <= usize::MAX as u64);

/// Failure to commit a bounded ordered transaction-wire set.
#[derive(Debug, Error)]
pub enum AxtOrderedTransactionSetErrorV1 {
    /// The supplied transaction count exceeds the anchored-spend verification ceiling.
    #[error("AXT ordered transaction count exceeds {maximum}")]
    Count {
        /// Maximum admitted transaction count.
        maximum: usize,
    },
    /// The cumulative exact wire length exceeds the consensus block ceiling.
    #[error("AXT ordered transaction wires exceed {maximum} bytes")]
    WireBytes {
        /// Maximum admitted cumulative wire bytes.
        maximum: u64,
    },
    /// A canonical transaction wire could not be encoded.
    #[error("AXT ordered transaction wire encoding failed: {0}")]
    Encoding(String),
}

/// Commit exact transaction-entrypoint wires in their supplied finalized order.
///
/// The BLAKE2b-256 `Hash` preimage is the domain above, a little-endian `u64`
/// count, then for each transaction its little-endian `u64` wire length and its
/// complete [`TransactionEntrypoint::encode_wire_v1`] bytes. Signatures and all
/// authorization proofs are retained. Entries are never sorted or deduplicated.
/// This is a ledger commitment, distinct from six-lane native-STARK hashes.
///
/// A bounded counting pass checks the cumulative consensus wire budget before a
/// second pass streams the exact bytes into the hasher. The cloneable iterator
/// retains borrowed entries; only bounded per-entry lengths are stored. The
/// smaller AXT witness-count admission limit is enforced by the proof verifier,
/// so this canonical commitment does not impose that limit on ordinary blocks.
///
/// # Errors
/// Rejects excessive count or cumulative wire bytes and serialization errors.
pub fn axt_ordered_transaction_set_digest_v1<I>(
    transactions: I,
) -> Result<Hash, AxtOrderedTransactionSetErrorV1>
where
    I: IntoIterator,
    I::Item: std::borrow::Borrow<TransactionEntrypoint>,
    I::IntoIter: Clone,
{
    // Every complete versioned wire contains at least its one-byte version.
    // This count bound is therefore implied by the consensus wire ceiling.
    let max_count = usize::try_from(MAX_AXT_FINALIZED_TRANSACTION_WIRE_BYTES_V1).map_err(|_| {
        AxtOrderedTransactionSetErrorV1::Encoding(
            "AXT consensus wire ceiling exceeds the target address space".to_owned(),
        )
    })?;
    axt_ordered_transaction_set_digest_with_limits(
        transactions,
        max_count,
        MAX_AXT_FINALIZED_TRANSACTION_WIRE_BYTES_V1,
    )
}

fn axt_ordered_transaction_set_digest_with_limits<I>(
    transactions: I,
    max_count: usize,
    max_wire_bytes: u64,
) -> Result<Hash, AxtOrderedTransactionSetErrorV1>
where
    I: IntoIterator,
    I::Item: std::borrow::Borrow<TransactionEntrypoint>,
    I::IntoIter: Clone,
{
    use std::io::Write as _;

    let iter = transactions.into_iter();
    if iter.size_hint().0 > max_count {
        return Err(AxtOrderedTransactionSetErrorV1::Count { maximum: max_count });
    }
    let mut counter = AxtWireBudgetWriter {
        written: 0,
        maximum: max_wire_bytes,
        rejected: false,
    };
    let mut lengths = Vec::new();
    for transaction in iter.clone() {
        if lengths.len() == max_count {
            return Err(AxtOrderedTransactionSetErrorV1::Count { maximum: max_count });
        }
        let transaction: &TransactionEntrypoint = std::borrow::Borrow::borrow(&transaction);
        let start = counter.written;
        let encoding_result = counter
            .write_all(&[1])
            .map_err(norito::core::Error::from)
            .and_then(|()| {
                norito::codec::encode_adaptive_into(transaction, &mut counter).map(|_| ())
            });
        if counter.rejected {
            return Err(AxtOrderedTransactionSetErrorV1::WireBytes {
                maximum: max_wire_bytes,
            });
        }
        encoding_result
            .map_err(|error| AxtOrderedTransactionSetErrorV1::Encoding(error.to_string()))?;
        lengths.push(counter.written - start);
    }
    Hash::new_from_writer(|mut writer| {
        writer.write_all(AXT_ORDERED_TRANSACTION_SET_DOMAIN_V1)?;
        writer.write_all(&(lengths.len() as u64).to_le_bytes())?;
        let mut remaining = iter;
        for length in lengths {
            let transaction = remaining.next().ok_or_else(|| {
                std::io::Error::other("canonical AXT entry count shortened between passes")
            })?;
            let transaction: &TransactionEntrypoint = std::borrow::Borrow::borrow(&transaction);
            writer.write_all(&length.to_le_bytes())?;
            writer.write_all(&[1])?;
            let written = norito::codec::encode_adaptive_into(transaction, &mut writer)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if written as u64 != length - 1 {
                return Err(std::io::Error::other(
                    "canonical AXT wire length changed between passes",
                ));
            }
        }
        if remaining.next().is_some() {
            return Err(std::io::Error::other(
                "canonical AXT entry count grew between passes",
            ));
        }
        Ok(())
    })
    .map_err(|error| AxtOrderedTransactionSetErrorV1::Encoding(error.to_string()))
}

struct AxtWireBudgetWriter {
    written: u64,
    maximum: u64,
    rejected: bool,
}

impl std::io::Write for AxtWireBudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(total) = self
            .written
            .checked_add(bytes.len() as u64)
            .filter(|total| *total <= self.maximum)
        else {
            self.rejected = true;
            return Err(std::io::Error::other("AXT canonical wire budget exceeded"));
        };
        self.written = total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn axt_logical_hash_is_zero(bytes: &[u8; Hash::LENGTH]) -> bool {
    bytes[..Hash::LENGTH - 1].iter().all(|byte| *byte == 0) && bytes[Hash::LENGTH - 1] & !1 == 0
}

fn axt_framed_digest_v1<T: Encode>(domain: &[u8], value: &T) -> [u8; Hash::LENGTH] {
    let encoded = encode_adaptive(value);
    let mut preimage = Vec::with_capacity(
        domain
            .len()
            .saturating_add(std::mem::size_of::<u64>())
            .saturating_add(encoded.len()),
    );
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(
        &u64::try_from(encoded.len())
            .expect("Norito output length fits u64 on supported targets")
            .to_le_bytes(),
    );
    preimage.extend_from_slice(&encoded);
    Hash::new(preimage).into()
}
/// Canonical 32-byte binding derived from an AXT descriptor.
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
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtBinding")]
pub struct AxtBinding([u8; 32]);
impl AxtBinding {
    /// Construct a binding from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Borrow the binding bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Consume the binding and return the inner array.
    #[must_use]
    pub const fn into_array(self) -> [u8; 32] {
        self.0
    }
}
/// Canonical descriptor for an AXT envelope.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtDescriptor")]
pub struct AxtDescriptor {
    /// List of dataspace identifiers touched by the transaction.
    pub dsids: Vec<DataSpaceId>,
    /// Fine-grained access declarations for each dataspace.
    pub touches: Vec<AxtTouchSpec>,
}
/// Declared access set for a dataspace touched by an AXT envelope.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtTouchSpec")]
pub struct AxtTouchSpec {
    /// Dataspace identifier.
    pub dsid: DataSpaceId,
    /// Logical read-set expressed as application key prefixes.
    pub read: Vec<String>,
    /// Logical write-set expressed as application key prefixes.
    pub write: Vec<String>,
}
/// Runtime manifest supplied via `AXT_TOUCH`.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::TouchManifest")]
pub struct TouchManifest {
    /// Keys read within the dataspace during execution.
    pub read: Vec<String>,
    /// Keys written within the dataspace during execution.
    pub write: Vec<String>,
}
impl TouchManifest {
    /// Construct a canonical touch manifest from read/write key prefixes.
    ///
    /// Paths are trimmed, empty paths are discarded, and the remaining paths
    /// are sorted and deduplicated.
    #[must_use]
    pub fn from_read_write<R, W>(read: R, write: W) -> Self
    where
        R: IntoIterator,
        R::Item: Into<String>,
        W: IntoIterator,
        W::Item: Into<String>,
    {
        fn collect_sorted<I>(iter: I) -> Vec<String>
        where
            I: IntoIterator,
            I::Item: Into<String>,
        {
            let mut values: Vec<String> = iter
                .into_iter()
                .map(Into::into)
                .map(|path: String| path.trim().to_owned())
                .filter(|path| !path.is_empty())
                .collect();
            values.sort();
            values.dedup();
            values
        }
        Self {
            read: collect_sorted(read),
            write: collect_sorted(write),
        }
    }
}
/// Compute the canonical descriptor binding used by asset handles and manifests.
///
/// The descriptor's bare Norito payload is prefixed with a domain separator and
/// hashed using original BN254 Poseidon (rate 2, capacity 1) to produce a 32-byte digest. Byte
/// packing appends `0x01` and zero-pads to an eight-byte boundary before the
/// sponge's field-level +1 padding. The header-framed encoding is intentionally
/// excluded so the binding stays stable across feature-sensitive schema hashes.
///
/// # Errors
/// Returns an error if the descriptor cannot be encoded using Norito.
pub fn compute_descriptor_binding(descriptor: &AxtDescriptor) -> Result<[u8; 32], norito::Error> {
    let mut buf = b"iroha:axt:desc:v1\0".to_vec();
    let encoded = encode_adaptive(descriptor);
    buf.extend_from_slice(&encoded);
    Ok(poseidon_hash_bytes(&buf))
}
impl AxtDescriptor {
    /// Deterministically compute the binding hash for this descriptor.
    ///
    /// # Errors
    /// Returns an error if the descriptor cannot be encoded.
    pub fn binding(&self) -> Result<AxtBinding, norito::Error> {
        compute_descriptor_binding(self).map(AxtBinding::new)
    }
    /// Build a descriptor with sorted dataspace/touch entries.
    #[must_use]
    pub fn builder() -> AxtDescriptorBuilder {
        AxtDescriptorBuilder::default()
    }
}
/// Deterministic builder for [`AxtDescriptor`].
#[derive(Debug, Default, Clone)]
pub struct AxtDescriptorBuilder {
    dsids: BTreeSet<DataSpaceId>,
    touches: BTreeMap<DataSpaceId, AxtTouchSpec>,
}
impl AxtDescriptorBuilder {
    /// Start an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a dataspace to the descriptor.
    #[must_use]
    pub fn dataspace(mut self, dsid: DataSpaceId) -> Self {
        self.dsids.insert(dsid);
        self
    }
    /// Add or replace a touch declaration for a dataspace.
    #[must_use]
    pub fn touch<R, W>(mut self, dsid: DataSpaceId, read: R, write: W) -> Self
    where
        R: IntoIterator,
        R::Item: Into<String>,
        W: IntoIterator,
        W::Item: Into<String>,
    {
        let manifest = TouchManifest::from_read_write(read, write);
        let touch = AxtTouchSpec {
            dsid,
            read: manifest.read,
            write: manifest.write,
        };
        self.dsids.insert(dsid);
        self.touches.insert(dsid, touch);
        self
    }
    /// Build the descriptor, rejecting undeclared/duplicate dataspace or touch entries.
    ///
    /// # Errors
    /// Returns [`AxtValidationError`] if the descriptor is invalid.
    pub fn build(self) -> Result<AxtDescriptor, AxtValidationError> {
        let dsids: Vec<DataSpaceId> = self.dsids.into_iter().collect();
        let touches: Vec<AxtTouchSpec> = self.touches.into_values().collect();
        let descriptor = AxtDescriptor { dsids, touches };
        validate_descriptor(&descriptor)?;
        Ok(descriptor)
    }
}
/// Touch fragment emitted for a particular dataspace.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtTouchFragment")]
pub struct AxtTouchFragment {
    /// Dataspace identifier.
    pub dsid: DataSpaceId,
    /// Manifest captured during execution.
    pub manifest: TouchManifest,
}
/// Wrapper around proof artifacts provided by dataspace verifiers.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::ProofBlob")]
pub struct ProofBlob {
    /// Norito-encoded AXT proof envelope bytes, bounded by
    /// [`MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES`] at every proof-aware ingress.
    pub payload: Vec<u8>,
    /// Outer mirror of the proof-bound expiry slot.
    ///
    /// `None` is an authenticated no-expiry sentinel, not an omitted
    /// verification field. Consensus consumers must exact-compare this value
    /// with the proof metadata.
    #[norito(required)]
    pub expiry_slot: Option<u64>,
}
/// Check whether the decoded proof envelope has the expected structural shape.
///
/// This helper enforces the shared payload ceiling, performs canonical decoding,
/// and compares untrusted outer fields; it does **not** verify the `FastPQ`
/// proof or cryptographically authenticate the dataspace, manifest root,
/// expiry, DA commitment, or binding. Consensus and host admission must use the
/// `fastpq_prover` verifier instead.
#[must_use]
pub fn proof_envelope_shape_matches_manifest(
    proof: &ProofBlob,
    dsid: DataSpaceId,
    manifest_root: [u8; 32],
) -> bool {
    if proof.payload.len() > MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES
        || manifest_root.iter().all(|byte| *byte == 0)
    {
        return false;
    }
    let Ok(envelope) = norito::decode_canonical::<AxtProofEnvelope>(&proof.payload) else {
        return false;
    };
    let Some(binding) = envelope.fastpq_binding.as_ref() else {
        return false;
    };
    envelope.dsid == dsid
        && envelope.manifest_root == manifest_root
        && envelope.manifest_root.iter().any(|byte| *byte != 0)
        && !envelope.proof.is_empty()
        && binding.source_dsid == dsid.as_u64()
        && binding.verifier_id == "fastpq"
        && binding.verifier_version == "v1"
        && fastpq_binding_shape_is_concrete(binding)
}
fn fastpq_binding_shape_is_concrete(binding: &AxtFastpqBinding) -> bool {
    binding_string_is_present(&binding.parameter)
        && binding_string_is_present(&binding.source_dataspace)
        && binding_string_is_present(&binding.source_receipt_id)
        && binding_hex_digest_is_present(&binding.source_tx_commitment)
        && fastpq_claim_type_is_supported(&binding.claim_type)
        && binding_hex_digest_is_present(&binding.claim_digest)
        && binding_hex_digest_is_present(&binding.witness_commitment)
        && binding_hex_digest_is_present(&binding.policy_commitment)
        && binding_string_is_present(&binding.verified_effect_type)
        && !binding.target_dsids.is_empty()
        && binding
            .target_dsids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        && binding.remote_spend_intent_commitments.len() <= MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1
        && binding
            .remote_spend_intent_commitments
            .windows(2)
            .all(|pair| pair[0] < pair[1])
}
fn binding_string_is_present(value: &str) -> bool {
    !value.trim().is_empty()
}
fn binding_hex_digest_is_present(value: &str) -> bool {
    let value = value.trim();
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn fastpq_claim_type_is_supported(value: &str) -> bool {
    let value = value.trim();
    value.eq_ignore_ascii_case("authorization")
        || value.eq_ignore_ascii_case("compliance")
        || value.eq_ignore_ascii_case("tx_predicate")
        || value.eq_ignore_ascii_case("value_conservation")
}
/// Norito envelope used to bind dataspace proofs to manifest roots and DA state.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(decode_from_slice)]
#[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtProofEnvelope")]
pub struct AxtProofEnvelope {
    /// Dataspace the proof is intended for.
    pub dsid: DataSpaceId,
    /// Manifest root the proof commits to.
    pub manifest_root: [u8; 32],
    /// Optional DA commitment the proof is bound to.
    #[norito(required)]
    pub da_commitment: Option<[u8; 32]>,
    /// Backend-specific proof payload.
    pub proof: Vec<u8>,
    /// Structured FASTPQ binding used to reconstruct the verified batch.
    #[norito(required)]
    pub fastpq_binding: Option<AxtFastpqBinding>,
    /// Optional non-zero *public* scalar committed by the versioned FASTPQ proof statement.
    ///
    /// This is deliberately a fixed-width proof field, not a business-facing
    /// monetary quantity. Callers must convert a clear [`Quantity`] exactly at
    /// scale zero and reject values outside the `u128` statement domain. When
    /// present, the value must exactly match the proof-bound AXT batch metadata.
    #[norito(required)]
    pub committed_amount: Option<u128>,
    /// Optional commitment for hidden-amount intents. An anchored V1 hidden
    /// spend must not also carry a public `committed_amount` scalar.
    #[norito(required)]
    pub amount_commitment: Option<[u8; 32]>,
}
/// Structured FASTPQ receipt/effect binding embedded in AXT proof envelopes.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtFastpqBinding")]
pub struct AxtFastpqBinding {
    /// Canonical FASTPQ parameter set.
    pub parameter: String,
    /// Source dataspace identifier.
    pub source_dsid: u64,
    /// Source dataspace alias.
    pub source_dataspace: String,
    /// Canonical receipt identifier bound to the proof.
    pub source_receipt_id: String,
    /// Canonical source transaction commitment.
    pub source_tx_commitment: String,
    /// Claim family proven by FASTPQ.
    pub claim_type: String,
    /// Canonical claim digest.
    pub claim_digest: String,
    /// Canonical witness commitment.
    pub witness_commitment: String,
    /// Canonical policy commitment.
    pub policy_commitment: String,
    /// Business effect type verified by the proof.
    pub verified_effect_type: String,
    /// Optional corridor label used by maintained flows.
    pub corridor: String,
    /// Verifier identifier.
    pub verifier_id: String,
    /// Verifier version.
    pub verifier_version: String,
    /// Non-empty, strictly increasing target dataspace ids committed by the proof.
    pub target_dsids: Vec<u64>,
    /// Business-effect bindings that maintained contracts compare on-ledger.
    #[norito(required)]
    pub effect_binding: Option<AxtEffectBinding>,
    /// Canonical sorted commitments linking this proof's exact transfer
    /// statements to independently authenticated [`RemoteSpendIntent`] handles.
    ///
    /// Proofs without anchored remote spends leave this empty. Spend-bound
    /// proofs must include every exact replay identity,
    /// descriptor, asset, dataspace, operation, accounts, and effective amount
    /// tuple that may use the proof. The proof does not itself grant authority.
    /// Duplicates, non-canonical ordering, and sets larger than
    /// [`MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1`] are rejected.
    pub remote_spend_intent_commitments: Vec<[u8; 32]>,
}
/// Business-effect bindings committed by a FASTPQ proof envelope.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtEffectBinding")]
pub struct AxtEffectBinding {
    /// Destination dataspace/domain label when applicable.
    #[norito(required)]
    pub destination_domain: Option<String>,
    /// Destination account id in canonical encoded form.
    #[norito(required)]
    pub destination_account_id: Option<String>,
    /// Vault account id in canonical encoded form.
    #[norito(required)]
    pub vault_account_id: Option<String>,
    /// Issuance account id in canonical encoded form.
    #[norito(required)]
    pub issuance_account_id: Option<String>,
    /// Source asset definition id in canonical literal form.
    #[norito(required)]
    pub source_asset_definition_id: Option<String>,
    /// Destination asset definition id in canonical literal form.
    #[norito(required)]
    pub destination_asset_definition_id: Option<String>,
    /// Source scalar in the versioned FASTPQ circuit statement, when present.
    ///
    /// This is not a ledger amount; business quantities must be converted
    /// exactly before constructing the proof witness.
    #[norito(required)]
    pub source_amount_i64: Option<i64>,
    /// Destination scalar in the versioned FASTPQ circuit statement, when present.
    ///
    /// This is not a ledger amount; business quantities must be converted
    /// exactly before constructing the proof witness.
    #[norito(required)]
    pub destination_amount_i64: Option<i64>,
}
/// Proof fragment associated with a dataspace.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtProofFragment")]
pub struct AxtProofFragment {
    /// Dataspace identifier.
    pub dsid: DataSpaceId,
    /// Proof payload provided by the dataspace.
    pub proof: ProofBlob,
}
/// Dataspace composability group binding advertised by the capability.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::GroupBinding")]
pub struct GroupBinding {
    /// Domain or composability group identifier.
    pub composability_group_id: Vec<u8>,
    /// Epoch identifier linked to the handle.
    pub epoch_id: u64,
}
/// Handle budget parameters.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::HandleBudget")]
pub struct HandleBudget {
    /// Remaining allowance for the capability.
    pub remaining: Quantity,
    /// Optional per-use cap.
    #[norito(required)]
    pub per_use: Option<Quantity>,
}
/// Capability subject metadata.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::HandleSubject")]
pub struct HandleSubject {
    /// Canonical I105 account identifier of the spender.
    pub account: String,
    /// Optional originating dataspace for cross-dataspace handles.
    #[norito(required)]
    pub origin_dsid: Option<DataSpaceId>,
}
/// Domain separator for V1 issuer signatures over asset handles.
pub const AXT_HANDLE_ISSUER_SIGNATURE_DOMAIN_V1: &[u8] = b"iroha:axt:asset-handle-issuer:v1\0";
/// Domain separator for V1 asset-definition incarnation commitments.
pub const AXT_ASSET_INCARNATION_DOMAIN_V1: &[u8] = b"iroha:axt:asset-incarnation:v1\0";
/// Exact non-zero lifecycle incarnation of one registered asset definition.
///
/// Core derives this value from the network, canonical asset identifier,
/// registration header, deterministic execution identity, and lifecycle
/// ordinal. An absent-to-present registration (including
/// re-registration) creates a distinct authority context without revoking
/// handles for unrelated assets. Ordinary updates to a registered definition
/// do not rotate this token.
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
#[repr(transparent)]
#[schema(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtAssetIncarnationV1")]
pub struct AxtAssetIncarnationV1(Hash);
/// Failure returned while validating raw V1 asset-incarnation bytes.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AxtAssetIncarnationValidationError {
    /// The all-zero token is reserved for absence.
    #[error("AXT asset-definition incarnation is zero")]
    Zero,
    /// Raw bytes do not satisfy the canonical Iroha hash marker invariant.
    #[error("AXT asset-definition incarnation has an invalid hash marker")]
    InvalidHashMarker,
}
impl AxtAssetIncarnationV1 {
    /// Derive the exact V1 incarnation installed by an asset registry event.
    ///
    /// `registration_header_hash` is `StateTransaction::_curr_block.hash()` at
    /// the absent-to-present registration boundary. `execution_identity` and
    /// `lifecycle_ordinal` identify the exact deterministic registration event
    /// when multiple autonomous executions share that header context.
    #[must_use]
    pub fn derive(
        network_id: &NetworkId,
        asset_definition_id: &AssetDefinitionId,
        registration_header_hash: &HashOf<BlockHeader>,
        execution_identity: &Hash,
        lifecycle_ordinal: u64,
    ) -> Self {
        let asset_bytes = asset_definition_id.aid_bytes();
        let ordinal_bytes = lifecycle_ordinal.to_be_bytes();
        Self(Hash::new_from_chunks(&[
            AXT_ASSET_INCARNATION_DOMAIN_V1,
            network_id.as_bytes(),
            &asset_bytes,
            registration_header_hash.as_ref(),
            execution_identity.as_ref(),
            &ordinal_bytes,
        ]))
    }

    /// Validate and wrap canonical raw incarnation bytes.
    ///
    /// # Errors
    ///
    /// Rejects the absence sentinel and bytes that do not carry the canonical
    /// Iroha hash marker.
    pub fn try_from_bytes(
        bytes: [u8; Hash::LENGTH],
    ) -> Result<Self, AxtAssetIncarnationValidationError> {
        let logical_payload_is_zero = bytes[..Hash::LENGTH - 1].iter().all(|byte| *byte == 0)
            && bytes[Hash::LENGTH - 1] & !1 == 0;
        if logical_payload_is_zero {
            return Err(AxtAssetIncarnationValidationError::Zero);
        }
        let hash = Hash::prehashed(bytes);
        if hash.as_ref() != &bytes {
            return Err(AxtAssetIncarnationValidationError::InvalidHashMarker);
        }
        Ok(Self(hash))
    }

    /// Validate this token's non-zero canonical hash invariant.
    ///
    /// # Errors
    ///
    /// Returns the corresponding validation error for corrupt in-memory or
    /// decoded state.
    pub fn validate(&self) -> Result<(), AxtAssetIncarnationValidationError> {
        Self::try_from_bytes(*self.as_bytes()).map(|_| ())
    }

    /// Borrow the canonical 32-byte incarnation token.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Hash::LENGTH] {
        self.0.as_ref()
    }

    /// Recover the typed hash backing this token.
    #[must_use]
    pub const fn into_hash(self) -> Hash {
        self.0
    }
}
/// Exact finalized source-state anchor authorized by one V1 AXT spend.
///
/// Every digest is reconstructed from committed consensus state. Submitted
/// spend bytes select an already-finalized record; they never define or extend
/// the authoritative anchor.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtFinalizedSpendAnchorV1")]
pub struct AxtFinalizedSpendAnchorV1 {
    /// Exact genesis-derived network identity.
    pub network_id: NetworkId,
    /// Exact genesis hash; validation requires byte equality with `network_id`.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub genesis_hash: [u8; Hash::LENGTH],
    /// Source dataspace whose finalized state authorizes the spend.
    pub dataspace_id: DataSpaceId,
    /// Source execution lane.
    pub lane_id: LaneId,
    /// Exact active lane incarnation at `finalized_height`.
    pub lane_incarnation: Hash,
    /// Positive finalized global/catalog height.
    pub finalized_height: u64,
    /// Hash of the exact canonical finalized block header.
    pub block_header_hash: HashOf<BlockHeader>,
    /// Digest of the exact commit quorum certificate.
    pub quorum_certificate_digest: Hash,
    /// Digest of the exact ordered `3f + 1` committee and key lineages.
    pub committee_digest: Hash,
    /// State root before the anchored transaction set executed.
    pub pre_state_root: Hash,
    /// State root after the anchored transaction set executed.
    pub post_state_root: Hash,
    /// Digest of the exact ordered canonical transaction-wire set, computed by
    /// [`axt_ordered_transaction_set_digest_v1`].
    pub transaction_set_digest: Hash,
    /// Digest of the exact signed RS16 data-availability manifest.
    pub da_manifest_digest: Hash,
}

impl AxtFinalizedSpendAnchorV1 {
    /// Validate the closed non-zero source-state anchor shape.
    ///
    /// # Errors
    ///
    /// Rejects a network/genesis mismatch, height zero, or any absent
    /// consensus, state, transaction-set, or data-availability binding.
    pub fn validate(&self) -> Result<(), AxtFinalizedSpendAnchorValidationErrorV1> {
        if self.network_id.as_bytes() != &self.genesis_hash {
            return Err(AxtFinalizedSpendAnchorValidationErrorV1::NetworkGenesis);
        }
        if self.finalized_height == 0 {
            return Err(AxtFinalizedSpendAnchorValidationErrorV1::ZeroHeight);
        }
        let bindings = [
            (
                AxtFinalizedSpendAnchorFieldV1::LaneIncarnation,
                self.lane_incarnation.as_ref(),
            ),
            (
                AxtFinalizedSpendAnchorFieldV1::BlockHeader,
                self.block_header_hash.as_ref(),
            ),
            (
                AxtFinalizedSpendAnchorFieldV1::QuorumCertificate,
                self.quorum_certificate_digest.as_ref(),
            ),
            (
                AxtFinalizedSpendAnchorFieldV1::Committee,
                self.committee_digest.as_ref(),
            ),
            (
                AxtFinalizedSpendAnchorFieldV1::PreStateRoot,
                self.pre_state_root.as_ref(),
            ),
            (
                AxtFinalizedSpendAnchorFieldV1::PostStateRoot,
                self.post_state_root.as_ref(),
            ),
            (
                AxtFinalizedSpendAnchorFieldV1::TransactionSet,
                self.transaction_set_digest.as_ref(),
            ),
            (
                AxtFinalizedSpendAnchorFieldV1::DaManifest,
                self.da_manifest_digest.as_ref(),
            ),
        ];
        for (field, bytes) in bindings {
            if axt_logical_hash_is_zero(bytes) {
                return Err(AxtFinalizedSpendAnchorValidationErrorV1::ZeroBinding { field });
            }
        }
        Ok(())
    }

    /// Compute the canonical content identity of this complete anchor.
    #[must_use]
    pub fn digest_v1(&self) -> [u8; Hash::LENGTH] {
        axt_framed_digest_v1(AXT_FINALIZED_SPEND_ANCHOR_DIGEST_DOMAIN_V1, self)
    }
}

/// Finalized anchor field selected by deterministic validation diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AxtFinalizedSpendAnchorFieldV1 {
    /// Active lane incarnation commitment.
    LaneIncarnation,
    /// Canonical finalized block header.
    BlockHeader,
    /// Commit quorum certificate.
    QuorumCertificate,
    /// Exact validator committee.
    Committee,
    /// Pre-execution state root.
    PreStateRoot,
    /// Post-execution state root.
    PostStateRoot,
    /// Exact ordered transaction set.
    TransactionSet,
    /// Signed RS16 data-availability manifest.
    DaManifest,
}

/// Structural validation failure for [`AxtFinalizedSpendAnchorV1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AxtFinalizedSpendAnchorValidationErrorV1 {
    /// The explicit genesis hash differs from the genesis-derived network id.
    #[error("AXT finalized anchor network and genesis hash differ")]
    NetworkGenesis,
    /// Height zero cannot identify a finalized source block.
    #[error("AXT finalized anchor height must be non-zero")]
    ZeroHeight,
    /// One required finalized-state binding is the logical zero sentinel.
    #[error("AXT finalized anchor has zero {field:?} binding")]
    ZeroBinding {
        /// Missing binding.
        field: AxtFinalizedSpendAnchorFieldV1,
    },
}
/// Immutable admission context for one V1 AXT issuer signature.
///
/// None of these values is selected by the submitted handle. Validators
/// reconstruct the context from the exact network, committed issuer policy,
/// and currently executing IVM image before checking the signature.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtHandleIssuerContextV1")]
pub struct AxtHandleIssuerContextV1 {
    /// Exact genesis-derived network identity.
    pub network_id: NetworkId,
    /// Dataspace whose committed policy authorizes the handle.
    pub asset_dsid: DataSpaceId,
    /// Exact registered incarnation of the asset definition authorized by the handle.
    pub asset_definition_incarnation: AxtAssetIncarnationV1,
    /// Committed UAID authorized to issue handles for the dataspace.
    pub issuer: UniversalAccountId,
    /// Exact committed issuer/permission-manifest root.
    pub issuer_manifest_root: [u8; 32],
    /// Hash of the exact IVM program image allowed to exercise the handle.
    pub code_root: [u8; 32],
    /// Pointer/syscall ABI version whose semantics are authorized.
    pub abi_version: u16,
    /// Canonical hash of the authorized ABI surface.
    pub abi_hash: [u8; 32],
}
impl AxtHandleIssuerContextV1 {
    /// Validate the exact asset-registration incarnation in this context.
    ///
    /// # Errors
    ///
    /// Rejects the absence sentinel or a non-canonical hash marker.
    pub fn validate(&self) -> Result<(), AxtAssetIncarnationValidationError> {
        self.asset_definition_incarnation.validate()
    }
}
impl Default for AxtHandleIssuerContextV1 {
    /// Return a syntactic fixture context that cannot match committed policy.
    ///
    /// This exists for context-free codec/shape fixtures. Issuers must replace
    /// every field with exact committed values before signing; admission always
    /// reconstructs and compares the complete context.
    fn default() -> Self {
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xF1; 32])),
        );
        let asset_definition_id = AssetDefinitionId::from_uuid_bytes([
            0xF0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xF2,
        ])
        .expect("fixed fixture asset identifier is canonical UUIDv4");
        let registration_header_hash =
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xF4; 32]));
        let execution_identity = Hash::new(b"axt-default-asset-registration-execution");
        Self {
            network_id,
            asset_dsid: DataSpaceId::UNIVERSAL,
            asset_definition_incarnation: AxtAssetIncarnationV1::derive(
                &network_id,
                &asset_definition_id,
                &registration_header_hash,
                &execution_identity,
                0,
            ),
            issuer: UniversalAccountId::from_hash(Hash::prehashed([0xF3; 32])),
            issuer_manifest_root: [0xF5; 32],
            code_root: [0xF7; 32],
            abi_version: 1,
            abi_hash: [0xF9; 32],
        }
    }
}
/// Canonical V1 statement authenticated by an AXT capability issuer.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AssetHandleIssuerPayloadV1")]
pub struct AssetHandleIssuerPayloadV1 {
    /// Immutable admission context reconstructed by the validating host.
    pub context: AxtHandleIssuerContextV1,
    /// Exact asset definition this capability authorizes.
    pub asset_definition_id: AssetDefinitionId,
    /// Declared operations permitted by the capability.
    pub scope: Vec<String>,
    /// Capability subject.
    pub subject: HandleSubject,
    /// Capability budget.
    pub budget: HandleBudget,
    /// Exact active policy era.
    pub active_handle_era: u64,
    /// Exact next per-dataspace capability counter.
    pub next_handle_counter: u64,
    /// Composability group and epoch.
    pub group_binding: GroupBinding,
    /// Authorized execution lane.
    pub target_lane: LaneId,
    /// Descriptor/AXT execution context.
    pub axt_binding: AxtBinding,
    /// Exact active manifest root.
    pub manifest_view_root: [u8; 32],
    /// Capability expiry slot.
    pub expiry_slot: u64,
    /// Requested clock-skew allowance, if any.
    #[norito(required)]
    pub max_clock_skew_ms: Option<u32>,
}
/// Unsigned AXT capability claims prepared by an issuer.
///
/// This type cannot enter an AXT envelope. Signing consumes it and returns the
/// admission-ready [`AssetHandle`] whose signature is mandatory on the wire.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AssetHandleDraft")]
pub struct AssetHandleDraft {
    /// Exact asset definition authorized by the capability.
    pub asset_definition_id: AssetDefinitionId,
    /// Declared permissions (example values such as "transfer").
    pub scope: Vec<String>,
    /// Subject bound to the capability.
    pub subject: HandleSubject,
    /// Budget parameters controlling single-/multi-use semantics.
    pub budget: HandleBudget,
    /// Exact active policy era selected for this draft.
    pub handle_era: u64,
    /// Exact next per-dataspace counter selected for this draft.
    pub sub_nonce: u64,
    /// Dataspace composability group binding.
    pub group_binding: GroupBinding,
    /// Lane the handle is authorised to execute on.
    pub target_lane: LaneId,
    /// Poseidon-style binding of this handle to a descriptor.
    pub axt_binding: AxtBinding,
    /// Dataspace manifest root observed by the issuer at handle time.
    pub manifest_view_root: [u8; 32],
    /// Expiry slot for freshness enforcement.
    pub expiry_slot: u64,
    /// Optional wall-clock skew allowance enforced by the host.
    #[norito(required)]
    pub max_clock_skew_ms: Option<u32>,
}
impl AssetHandleDraft {
    /// Build the exact statement authenticated by the dataspace issuer.
    #[must_use]
    pub fn issuer_payload_v1(
        &self,
        context: AxtHandleIssuerContextV1,
    ) -> AssetHandleIssuerPayloadV1 {
        AssetHandleIssuerPayloadV1 {
            context,
            asset_definition_id: self.asset_definition_id.clone(),
            scope: self.scope.clone(),
            subject: self.subject.clone(),
            budget: self.budget.clone(),
            active_handle_era: self.handle_era,
            next_handle_counter: self.sub_nonce,
            group_binding: self.group_binding.clone(),
            target_lane: self.target_lane,
            axt_binding: self.axt_binding,
            manifest_view_root: self.manifest_view_root,
            expiry_slot: self.expiry_slot,
            max_clock_skew_ms: self.max_clock_skew_ms,
        }
    }
    /// Encode the domain-separated canonical V1 issuer-signature preimage.
    #[must_use]
    pub fn issuer_signature_preimage_v1(&self, context: AxtHandleIssuerContextV1) -> Vec<u8> {
        let payload = self.issuer_payload_v1(context);
        let encoded = encode_adaptive(&payload);
        let mut preimage = Vec::with_capacity(
            AXT_HANDLE_ISSUER_SIGNATURE_DOMAIN_V1
                .len()
                .saturating_add(encoded.len()),
        );
        preimage.extend_from_slice(AXT_HANDLE_ISSUER_SIGNATURE_DOMAIN_V1);
        preimage.extend_from_slice(&encoded);
        preimage
    }
    /// Authenticate this handle with the committed dataspace issuer's key.
    ///
    /// # Errors
    ///
    /// Returns a cryptographic signing error when the private key is invalid.
    pub fn sign_by_issuer_v1(
        self,
        context: AxtHandleIssuerContextV1,
        private_key: &PrivateKey,
    ) -> Result<AssetHandle, iroha_crypto::Error> {
        let preimage = self.issuer_signature_preimage_v1(context);
        let issuer_signature = Signature::try_new(private_key, &preimage)?;
        Ok(AssetHandle::from_signed_draft(
            self,
            context,
            issuer_signature,
        ))
    }
}
/// Admission-ready AXT capability with a mandatory issuer signature.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AssetHandle")]
pub struct AssetHandle {
    /// Exact asset definition authorized by the issuer signature.
    pub asset_definition_id: AssetDefinitionId,
    /// Declared permissions (example values such as "transfer").
    pub scope: Vec<String>,
    /// Subject bound to the capability.
    pub subject: HandleSubject,
    /// Budget parameters controlling single-/multi-use semantics.
    pub budget: HandleBudget,
    /// Exact active era selected by committed issuer policy.
    pub handle_era: u64,
    /// Exact next per-dataspace counter selected by committed issuer policy.
    pub sub_nonce: u64,
    /// Dataspace composability group binding.
    pub group_binding: GroupBinding,
    /// Lane the handle is authorized to execute on.
    pub target_lane: LaneId,
    /// Poseidon-style binding of this handle to a descriptor.
    pub axt_binding: AxtBinding,
    /// Exact committed manifest root observed by the issuer.
    pub manifest_view_root: [u8; 32],
    /// Expiry slot for freshness enforcement.
    pub expiry_slot: u64,
    /// Optional wall-clock skew allowance enforced by the host.
    #[norito(required)]
    pub max_clock_skew_ms: Option<u32>,
    /// Immutable network, issuer, code, and ABI context authenticated by the signature.
    pub issuer_context: AxtHandleIssuerContextV1,
    /// Issuer signature over the canonical V1 handle statement.
    pub issuer_signature: Signature,
}
impl AssetHandle {
    fn from_signed_draft(
        draft: AssetHandleDraft,
        issuer_context: AxtHandleIssuerContextV1,
        issuer_signature: Signature,
    ) -> Self {
        Self {
            asset_definition_id: draft.asset_definition_id,
            scope: draft.scope,
            subject: draft.subject,
            budget: draft.budget,
            handle_era: draft.handle_era,
            sub_nonce: draft.sub_nonce,
            group_binding: draft.group_binding,
            target_lane: draft.target_lane,
            axt_binding: draft.axt_binding,
            manifest_view_root: draft.manifest_view_root,
            expiry_slot: draft.expiry_slot,
            max_clock_skew_ms: draft.max_clock_skew_ms,
            issuer_context,
            issuer_signature,
        }
    }
    /// Recover the unsigned claims for canonical signature verification.
    #[must_use]
    pub fn draft(&self) -> AssetHandleDraft {
        AssetHandleDraft {
            asset_definition_id: self.asset_definition_id.clone(),
            scope: self.scope.clone(),
            subject: self.subject.clone(),
            budget: self.budget.clone(),
            handle_era: self.handle_era,
            sub_nonce: self.sub_nonce,
            group_binding: self.group_binding.clone(),
            target_lane: self.target_lane,
            axt_binding: self.axt_binding,
            manifest_view_root: self.manifest_view_root,
            expiry_slot: self.expiry_slot,
            max_clock_skew_ms: self.max_clock_skew_ms,
        }
    }
    /// Verify this handle against the issuer key resolved from committed policy.
    ///
    /// # Errors
    ///
    /// Returns [`iroha_crypto::Error::BadSignature`] when the carried context
    /// differs from the authoritative context or the signature is invalid.
    pub fn verify_issuer_signature_v1(
        &self,
        context: AxtHandleIssuerContextV1,
        issuer: &PublicKey,
    ) -> Result<(), iroha_crypto::Error> {
        if self.issuer_context.validate().is_err()
            || context.validate().is_err()
            || self.issuer_context != context
        {
            return Err(iroha_crypto::Error::BadSignature);
        }
        self.issuer_signature.verify(
            issuer,
            &self
                .draft()
                .issuer_signature_preimage_v1(self.issuer_context),
        )
    }
}
/// Canonical issuer-signed handle family used for cumulative budget accounting.
///
/// The key contains every field in [`AssetHandleIssuerPayloadV1`] except
/// `next_handle_counter`. Sequential sub-nonces therefore spend one shared
/// allowance, while a different signed capability statement remains a distinct
/// family. The signature bytes are deliberately absent because they authenticate
/// the statement but are not part of its identity.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtHandleBudgetKey")]
pub struct AxtHandleBudgetKey {
    issuer_context: AxtHandleIssuerContextV1,
    asset_definition_id: AssetDefinitionId,
    scope: Vec<String>,
    subject: HandleSubject,
    budget: HandleBudget,
    active_handle_era: u64,
    group_binding: GroupBinding,
    target_lane: LaneId,
    axt_binding: AxtBinding,
    manifest_view_root: [u8; 32],
    expiry_slot: u64,
    #[norito(required)]
    max_clock_skew_ms: Option<u32>,
}
impl AxtHandleBudgetKey {
    /// Derive a family key from the exact V1 statement authenticated by an issuer.
    #[must_use]
    pub fn from_issuer_payload_v1(payload: &AssetHandleIssuerPayloadV1) -> Self {
        Self {
            issuer_context: payload.context,
            asset_definition_id: payload.asset_definition_id.clone(),
            scope: payload.scope.clone(),
            subject: payload.subject.clone(),
            budget: payload.budget.clone(),
            active_handle_era: payload.active_handle_era,
            group_binding: payload.group_binding.clone(),
            target_lane: payload.target_lane,
            axt_binding: payload.axt_binding,
            manifest_view_root: payload.manifest_view_root,
            expiry_slot: payload.expiry_slot,
            max_clock_skew_ms: payload.max_clock_skew_ms,
        }
    }

    /// Derive the canonical family key for an admitted signed handle.
    #[must_use]
    pub fn from_handle(handle: &AssetHandle) -> Self {
        Self::from_issuer_payload_v1(&handle.draft().issuer_payload_v1(handle.issuer_context))
    }

    /// Return the authenticated dataspace that issued this handle family.
    #[must_use]
    pub const fn asset_dsid(&self) -> DataSpaceId {
        self.issuer_context.asset_dsid
    }

    /// Return the permanent authorization generation signed into this family.
    #[must_use]
    pub const fn authorization_generation(&self) -> u64 {
        self.active_handle_era
    }

    /// Return the asset-registration incarnation authenticated by this family.
    #[must_use]
    pub const fn asset_definition_incarnation(&self) -> AxtAssetIncarnationV1 {
        self.issuer_context.asset_definition_incarnation
    }

    /// Validate structural invariants carried by this family key.
    ///
    /// # Errors
    ///
    /// Rejects an absent or non-canonical asset-registration incarnation.
    pub fn validate(&self) -> Result<(), AxtAssetIncarnationValidationError> {
        self.issuer_context.validate()
    }

    /// Return the issuer-authorized execution lane for this handle family.
    #[must_use]
    pub const fn target_lane(&self) -> LaneId {
        self.target_lane
    }

    /// Return a conservative count of heap bytes owned by this family key.
    ///
    /// This excludes the inline size of [`Self`] so callers can combine it
    /// with their own container accounting without double-counting. Capacity,
    /// rather than length, is used for owned collections because the WSV hot
    /// tier budgets resident allocation.
    #[must_use]
    pub fn allocated_heap_bytes(&self) -> usize {
        fn quantity_heap_bytes(quantity: &Quantity) -> usize {
            quantity.mantissa().bit_len().saturating_add(7) / 8
        }

        let mut total = self
            .scope
            .capacity()
            .saturating_mul(core::mem::size_of::<String>());
        for item in &self.scope {
            total = total.saturating_add(item.capacity());
        }
        total = total.saturating_add(self.subject.account.capacity());
        total = total.saturating_add(self.group_binding.composability_group_id.capacity());
        total = total.saturating_add(quantity_heap_bytes(&self.budget.remaining));
        if let Some(per_use) = &self.budget.per_use {
            total = total.saturating_add(quantity_heap_bytes(per_use));
        }
        total
    }
}
/// Consensus-persisted cumulative consumption for one handle budget family.
///
/// `retain_until_slot` is monotonic audit metadata. V1 deliberately exposes no
/// pruning predicate: slot-configuration changes could otherwise make a removed
/// family usable again and reset its budget.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtHandleBudgetRecord")]
pub struct AxtHandleBudgetRecord {
    consumed: Quantity,
    retain_until_slot: u64,
}
/// Failure returned while consuming a persisted handle-family budget.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AxtHandleBudgetConsumeError {
    /// The signed family carries an absent or malformed asset incarnation.
    #[error("handle budget family has invalid asset incarnation: {0}")]
    InvalidAssetIncarnation(#[from] AxtAssetIncarnationValidationError),
    /// A handle use must consume a non-zero amount.
    #[error("handle budget consumption amount is zero")]
    ZeroAmount,
    /// Exact decimal accumulation exceeded the canonical quantity domain.
    #[error("handle budget arithmetic failed: {0}")]
    Arithmetic(#[from] NumericOperationError),
    /// Cumulative consumption exceeded the issuer-signed remaining allowance.
    #[error("handle budget cumulative consumption exceeds remaining allowance")]
    RemainingExceeded,
    /// One spend exceeded the issuer-signed per-use allowance.
    #[error("handle budget spend exceeds per-use allowance")]
    PerUseExceeded,
}
impl AxtHandleBudgetRecord {
    /// Construct an empty cumulative record.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            consumed: Quantity::zero(),
            retain_until_slot: 0,
        }
    }

    /// Return the amount consumed by this family across committed blocks.
    #[must_use]
    pub const fn consumed(&self) -> &Quantity {
        &self.consumed
    }

    /// Return the greatest consensus retention deadline observed for the family.
    #[must_use]
    pub const fn retain_until_slot(&self) -> u64 {
        self.retain_until_slot
    }

    /// Validate a decoded persisted record against its authenticated family key.
    ///
    /// An empty record is only a transient accumulator created by [`Self::empty`]
    /// and must never appear in committed state. `retain_until_slot` is audit
    /// metadata and may be zero for a capability accepted at the genesis slot;
    /// V1 therefore imposes no independent validity rule on it.
    ///
    /// # Errors
    ///
    /// Returns [`AxtHandleBudgetConsumeError::ZeroAmount`] for an empty persisted
    /// record, or the corresponding limit error when cumulative consumption
    /// exceeds the issuer-signed `remaining` allowance. A cumulative record
    /// cannot recover individual per-use amounts; admission checks those when
    /// each spend is consumed.
    pub fn validate_for_key(
        &self,
        key: &AxtHandleBudgetKey,
    ) -> Result<(), AxtHandleBudgetConsumeError> {
        Self::validate_consumed_for_key(&self.consumed, key)
    }

    /// Add one non-zero use while enforcing the issuer-signed aggregate limits.
    ///
    /// The record is unchanged on error. A successful update monotonically
    /// retains the greatest supplied audit deadline.
    ///
    /// # Errors
    ///
    /// Returns [`AxtHandleBudgetConsumeError`] for a zero amount, exact-decimal
    /// overflow, or an issuer-signed `remaining`/`per_use` limit violation.
    pub fn try_consume(
        &mut self,
        key: &AxtHandleBudgetKey,
        amount: &Quantity,
        retain_until_slot: u64,
    ) -> Result<(), AxtHandleBudgetConsumeError> {
        if amount.is_zero() {
            return Err(AxtHandleBudgetConsumeError::ZeroAmount);
        }
        key.validate()?;
        if key
            .budget
            .per_use
            .as_ref()
            .is_some_and(|limit| amount > limit)
        {
            return Err(AxtHandleBudgetConsumeError::PerUseExceeded);
        }
        let consumed = self.consumed.checked_add(amount)?;
        Self::validate_consumed_for_key(&consumed, key)?;
        self.consumed = consumed;
        self.retain_until_slot = self.retain_until_slot.max(retain_until_slot);
        Ok(())
    }

    fn validate_consumed_for_key(
        consumed: &Quantity,
        key: &AxtHandleBudgetKey,
    ) -> Result<(), AxtHandleBudgetConsumeError> {
        key.validate()?;
        if consumed.is_zero() {
            return Err(AxtHandleBudgetConsumeError::ZeroAmount);
        }
        if consumed > &key.budget.remaining {
            return Err(AxtHandleBudgetConsumeError::RemainingExceeded);
        }
        Ok(())
    }
}
/// Permanent per-dataspace ratchet for AXT authorization generations and sub-nonces.
///
/// The record is consensus state independent of manifest, era, lane, and slot
/// configuration. Once created it must never be removed or reset: policy
/// snapshots project both fields so a previously issued handle can never become
/// current again after an authorization-identity cycle or node restart.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtHandleCounterRecord")]
pub struct AxtHandleCounterRecord {
    next: u64,
    authorization_generation: u64,
}
/// Failure returned while validating or advancing an AXT handle counter ratchet.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AxtHandleCounterError {
    /// A persisted ratchet may never contain the reserved zero value.
    #[error("AXT handle counter ratchet contains reserved zero value")]
    ZeroNextCounter,
    /// A persisted ratchet may never contain the inactive generation sentinel.
    #[error("AXT authorization generation contains reserved zero value")]
    ZeroAuthorizationGeneration,
    /// The presented sub-nonce is not the exact permanent next value.
    #[error("handle sub-nonce mismatch: expected {expected}, found {actual}")]
    SubNonceMismatch {
        /// Exact next admissible sub-nonce.
        expected: u64,
        /// Caller-presented sub-nonce.
        actual: u64,
    },
    /// The presented handle era is not the exact permanent authorization generation.
    #[error("handle authorization generation mismatch: expected {expected}, found {actual}")]
    AuthorizationGenerationMismatch {
        /// Exact generation projected into the active policy.
        expected: u64,
        /// Caller-presented handle era.
        actual: u64,
    },
    /// The permanent counter cannot advance without wrapping.
    #[error("AXT handle counter ratchet is exhausted")]
    CounterExhausted,
    /// The permanent authorization generation cannot advance without wrapping.
    #[error("AXT authorization generation is exhausted")]
    AuthorizationGenerationExhausted,
}
impl AxtHandleCounterRecord {
    /// Construct the first permanent record for a dataspace.
    ///
    /// `authorization_generation` is derived from the first active manifest's
    /// activation era. Zero is the absent/inactive policy sentinel, so an
    /// active record normalizes it to one.
    #[must_use]
    pub const fn initial(authorization_generation: u64) -> Self {
        Self {
            next: 1,
            authorization_generation: if authorization_generation == 0 {
                1
            } else {
                authorization_generation
            },
        }
    }

    /// Construct a validated record from authoritative persisted/setup state.
    ///
    /// Live handle consumption must use [`Self::try_advance`]; this constructor
    /// exists for bounded snapshot decoding and explicit policy installation.
    ///
    /// # Errors
    ///
    /// Returns the corresponding zero-value error for a reserved next counter
    /// or inactive authorization generation.
    pub const fn try_from_parts(
        next: u64,
        authorization_generation: u64,
    ) -> Result<Self, AxtHandleCounterError> {
        if next == 0 {
            return Err(AxtHandleCounterError::ZeroNextCounter);
        }
        if authorization_generation == 0 {
            return Err(AxtHandleCounterError::ZeroAuthorizationGeneration);
        }
        Ok(Self {
            next,
            authorization_generation,
        })
    }

    /// Return the exact next admissible handle sub-nonce.
    #[must_use]
    pub const fn next(&self) -> u64 {
        self.next
    }

    /// Return the permanent generation projected as `active_handle_era`.
    #[must_use]
    pub const fn authorization_generation(&self) -> u64 {
        self.authorization_generation
    }

    /// Validate a decoded persisted counter record.
    ///
    /// # Errors
    ///
    /// Returns the corresponding zero-value error when snapshot data contains
    /// a reserved counter or inactive generation sentinel.
    pub const fn validate(&self) -> Result<(), AxtHandleCounterError> {
        if self.next == 0 {
            return Err(AxtHandleCounterError::ZeroNextCounter);
        }
        if self.authorization_generation == 0 {
            return Err(AxtHandleCounterError::ZeroAuthorizationGeneration);
        }
        Ok(())
    }

    /// Consume a handle at the exact generation and next sub-nonce.
    ///
    /// The record is unchanged on error.
    ///
    /// # Errors
    ///
    /// Returns [`AxtHandleCounterError`] when the persisted value is invalid,
    /// the presented generation/sub-nonce is stale or caller-selected future
    /// state, or the counter is exhausted.
    pub fn try_advance(
        &mut self,
        presented_generation: u64,
        presented_sub_nonce: u64,
    ) -> Result<(), AxtHandleCounterError> {
        self.validate()?;
        if presented_generation != self.authorization_generation {
            return Err(AxtHandleCounterError::AuthorizationGenerationMismatch {
                expected: self.authorization_generation,
                actual: presented_generation,
            });
        }
        if presented_sub_nonce != self.next {
            return Err(AxtHandleCounterError::SubNonceMismatch {
                expected: self.next,
                actual: presented_sub_nonce,
            });
        }
        let advanced = self
            .next
            .checked_add(1)
            .ok_or(AxtHandleCounterError::CounterExhausted)?;
        self.next = advanced;
        Ok(())
    }

    /// Revoke the current generation and next sub-nonce during a policy transition.
    ///
    /// The next generation is `max(current + 1, minimum_generation)`, where the
    /// minimum is the newly derived manifest activation era (or zero on
    /// removal). The record is unchanged on error.
    ///
    /// # Errors
    ///
    /// Returns [`AxtHandleCounterError`] for invalid persisted state or when
    /// either permanent dimension cannot advance without wrapping.
    pub fn try_revoke_for_policy_transition(
        &mut self,
        minimum_generation: u64,
    ) -> Result<(), AxtHandleCounterError> {
        self.validate()?;
        let advanced_next = self
            .next
            .checked_add(1)
            .ok_or(AxtHandleCounterError::CounterExhausted)?;
        let advanced_generation = self
            .authorization_generation
            .checked_add(1)
            .ok_or(AxtHandleCounterError::AuthorizationGenerationExhausted)?
            .max(minimum_generation);
        self.next = advanced_next;
        self.authorization_generation = advanced_generation;
        Ok(())
    }
}
/// Error returned when a handle does not represent the one allowed ratchet step.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AxtHandleSequenceError {
    /// The handle does not use the exact active manifest era.
    #[error("handle era mismatch: expected {expected}, found {actual}")]
    EraMismatch {
        /// Active manifest era.
        expected: u64,
        /// Caller-supplied era.
        actual: u64,
    },
    /// The handle does not use the exact next counter.
    #[error("handle sub-nonce mismatch: expected {expected}, found {actual}")]
    SubNonceMismatch {
        /// Next admissible counter.
        expected: u64,
        /// Caller-supplied counter.
        actual: u64,
    },
    /// The counter cannot advance without wrapping.
    #[error("handle sub-nonce counter is exhausted")]
    CounterExhausted,
}
/// Validate one exact era/counter transition and return the next counter.
///
/// This deliberately rejects both stale values and caller-selected future values. The active
/// manifest controls the era; accepted handles advance only the per-dataspace counter by one.
///
/// # Errors
///
/// Returns [`AxtHandleSequenceError::EraMismatch`] or
/// [`AxtHandleSequenceError::SubNonceMismatch`] when the handle does not match the active policy,
/// and [`AxtHandleSequenceError::CounterExhausted`] when the accepted counter cannot advance.
pub fn next_axt_handle_sub_nonce(
    policy: &AxtPolicyEntry,
    handle: &AssetHandle,
) -> Result<u64, AxtHandleSequenceError> {
    if handle.handle_era != policy.active_handle_era {
        return Err(AxtHandleSequenceError::EraMismatch {
            expected: policy.active_handle_era,
            actual: handle.handle_era,
        });
    }
    if handle.sub_nonce != policy.next_handle_counter {
        return Err(AxtHandleSequenceError::SubNonceMismatch {
            expected: policy.next_handle_counter,
            actual: handle.sub_nonce,
        });
    }
    handle
        .sub_nonce
        .checked_add(1)
        .ok_or(AxtHandleSequenceError::CounterExhausted)
}
/// Simplified representation of spend operations.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::SpendOp")]
pub struct SpendOp {
    /// Exact asset definition authorized by the handle and proven by FASTPQ.
    pub asset_definition_id: AssetDefinitionId,
    /// Operation kind (e.g., "transfer").
    pub kind: String,
    /// Origin account id in canonical I105 form.
    pub from: String,
    /// Destination account id in canonical I105 form.
    pub to: String,
    /// Cleartext amount, or `None` when the proof carries a hidden amount.
    #[norito(required)]
    pub amount: Option<Quantity>,
}
/// Intent bound to an anchored remote spend in its target dataspace.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::RemoteSpendIntent")]
pub struct RemoteSpendIntent {
    /// Target asset dataspace identifier.
    pub asset_dsid: DataSpaceId,
    /// Operation payload.
    pub op: SpendOp,
}
/// Fresh, issuer-selected nonce for exactly one anchored AXT spend.
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
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtSpendNonceV1")]
pub struct AxtSpendNonceV1([u8; 32]);

impl AxtSpendNonceV1 {
    /// Validate and wrap a non-zero nonce.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero absence sentinel.
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, AxtSpendNonceValidationErrorV1> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(AxtSpendNonceValidationErrorV1::Zero);
        }
        Ok(Self(bytes))
    }

    /// Borrow the exact nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Validate a decoded nonce.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero absence sentinel.
    pub fn validate(&self) -> Result<(), AxtSpendNonceValidationErrorV1> {
        Self::try_new(self.0).map(|_| ())
    }
}

/// Validation failure for [`AxtSpendNonceV1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AxtSpendNonceValidationErrorV1 {
    /// The nonce is the reserved zero sentinel.
    #[error("AXT anchored-spend nonce must be non-zero")]
    Zero,
}

/// Unsigned exact spend facts that an issuer authorizes for one finalized anchor.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtAnchoredSpendDraftV1")]
pub struct AxtAnchoredSpendDraftV1 {
    /// Reusable issuer-authenticated capability consumed by this spend.
    pub handle: AssetHandle,
    /// Exact destination-side operation.
    pub intent: RemoteSpendIntent,
    /// Exact proof whose canonical bytes are authenticated by the spend signature.
    #[norito(required)]
    pub proof: Option<ProofBlob>,
    /// Exact clear intent amount mirror, or `None` for a proof-hidden amount.
    #[norito(required)]
    pub amount: Option<Quantity>,
    /// Exact hidden-amount commitment mirror, when applicable.
    #[norito(required)]
    pub amount_commitment: Option<[u8; 32]>,
    /// Claimed successful source execution, resolved from finalized State at admission.
    pub source_receipt: AxtSourceSuccessReceiptV1,
    /// Exact ordered source transfer whose proof-bound claim consumes this handle.
    pub source_occurrence: AxtSourceTransferOccurrenceV1,
}

/// Canonical payload covered by the fresh issuer signature on one AXT spend.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtAnchoredSpendIssuerPayloadV1")]
pub struct AxtAnchoredSpendIssuerPayloadV1 {
    /// Exact replay identity of the reusable handle.
    pub handle_replay_key: AxtHandleReplayKey,
    /// Digest of the complete canonical signed handle.
    pub handle_digest: [u8; 32],
    /// Exact destination-side operation.
    pub intent: RemoteSpendIntent,
    /// Digest of the complete canonical proof blob, including its expiry mirror.
    pub proof_digest: [u8; 32],
    /// Clear amount mirror, or `None` for a proof-hidden amount.
    #[norito(required)]
    pub amount: Option<Quantity>,
    /// Hidden-amount commitment mirror, when applicable.
    #[norito(required)]
    pub amount_commitment: Option<[u8; 32]>,
    /// Digest of the exact claimed successful source execution receipt.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub source_success_receipt_digest: [u8; 32],
    /// Exact ordered source transfer occurrence authorized by this signature.
    pub source_occurrence: AxtSourceTransferOccurrenceV1,
    /// Exact authoritative finalized source-state anchor.
    pub anchor: AxtFinalizedSpendAnchorV1,
    /// Exact positive expiry authenticated for this spend.
    pub expiry_slot: u64,
    /// Fresh nonce whose durable replay key may be consumed only once.
    pub nonce: AxtSpendNonceV1,
}

/// Fresh issuer authorization attached to one exact anchored AXT spend.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtAnchoredSpendIssuerAuthorizationV1")]
pub struct AxtAnchoredSpendIssuerAuthorizationV1 {
    /// Exact authoritative finalized source-state anchor.
    pub anchor: AxtFinalizedSpendAnchorV1,
    /// Exact positive expiry authenticated for this spend.
    pub expiry_slot: u64,
    /// Fresh issuer nonce.
    pub nonce: AxtSpendNonceV1,
    /// Issuer signature over [`AxtAnchoredSpendIssuerPayloadV1`].
    pub issuer_signature: Signature,
}

/// Issuer-signed AXT spend carrying a claimed source receipt and exact occurrence.
// TODO: route block admission, CoreHost, and the IVM syscall through one verified
// finalized-State resolver. Constructing this value grants no authorization.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtAnchoredSpendV1")]
pub struct AxtAnchoredSpendV1 {
    /// Exact spend facts authenticated by the issuer.
    pub draft: AxtAnchoredSpendDraftV1,
    /// Fresh finalized-anchor authorization.
    pub authorization: AxtAnchoredSpendIssuerAuthorizationV1,
}

/// Durable identity of one fresh issuer spend authorization.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtAnchoredSpendReplayKeyV1")]
pub struct AxtAnchoredSpendReplayKeyV1 {
    /// Complete committed issuer context, including network and asset incarnation.
    pub issuer_context: AxtHandleIssuerContextV1,
    /// Fresh nonce consumed by this exact spend.
    pub nonce: AxtSpendNonceV1,
}

impl AxtAnchoredSpendReplayKeyV1 {
    /// Validate the durable issuer nonce identity after decoding persisted state.
    ///
    /// # Errors
    ///
    /// Rejects an invalid asset incarnation or a zero nonce. Admission must also
    /// compare the complete issuer context with current authoritative State.
    pub fn validate(&self) -> Result<(), AxtAnchoredSpendReplayKeyValidationErrorV1> {
        self.issuer_context
            .validate()
            .map_err(AxtAnchoredSpendReplayKeyValidationErrorV1::IssuerContext)?;
        self.nonce
            .validate()
            .map_err(AxtAnchoredSpendReplayKeyValidationErrorV1::Nonce)
    }
}

/// Permanent identity of one physical transfer in a finalized source execution.
///
/// The key deliberately excludes issuer nonce, handle, proof, transfer digest, and
/// receipt claims. Changing any of those cannot make the same ordered source
/// transfer available a second time. State must authenticate the anchor and
/// source execution before consuming this key.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtSourceTransferReplayKeyV1")]
pub struct AxtSourceTransferReplayKeyV1 {
    /// Genesis-derived source network.
    pub network_id: NetworkId,
    /// Source dataspace within the finalized block.
    pub dataspace_id: DataSpaceId,
    /// Source execution lane within the finalized block.
    pub lane_id: LaneId,
    /// Exact canonical finalized source block header.
    pub block_header_hash: HashOf<BlockHeader>,
    /// Position of the successful source transaction in the block.
    pub source_tx_index: u32,
    /// Position of the ordered transfer transcript in that execution.
    pub transcript_index: u32,
    /// Position of the transfer within that transcript.
    pub delta_index: u32,
}

impl AxtSourceTransferReplayKeyV1 {
    /// Extract the physical coordinate claimed by a structurally valid spend.
    ///
    /// # Errors
    /// Rejects malformed public bindings. This does not authenticate the
    /// finalized source anchor, receipt, or transfer occurrence.
    pub fn from_spend_v1(
        spend: &AxtAnchoredSpendV1,
    ) -> Result<Self, AxtAnchoredSpendValidationErrorV1> {
        spend.issuer_payload_v1()?;
        let anchor = &spend.authorization.anchor;
        let occurrence = &spend.draft.source_occurrence;
        Ok(Self {
            network_id: anchor.network_id,
            dataspace_id: anchor.dataspace_id,
            lane_id: anchor.lane_id,
            block_header_hash: anchor.block_header_hash,
            source_tx_index: occurrence.source_tx_index,
            transcript_index: occurrence.transcript_index,
            delta_index: occurrence.delta_index,
        })
    }

    /// Validate the persistent physical coordinate after snapshot decoding.
    ///
    /// # Errors
    /// Rejects missing source identity or an out-of-range source coordinate.
    pub fn validate(&self) -> Result<(), AxtSourceTransferReplayKeyValidationErrorV1> {
        if axt_logical_hash_is_zero(self.network_id.as_bytes()) {
            return Err(AxtSourceTransferReplayKeyValidationErrorV1::Network);
        }
        if axt_logical_hash_is_zero(self.block_header_hash.as_ref()) {
            return Err(AxtSourceTransferReplayKeyValidationErrorV1::BlockHeader);
        }
        if self.source_tx_index as usize >= MAX_AXT_FINALIZED_TRANSACTIONS_V1 {
            return Err(AxtSourceTransferReplayKeyValidationErrorV1::TransactionIndex);
        }
        if self.transcript_index as usize >= MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1 {
            return Err(AxtSourceTransferReplayKeyValidationErrorV1::TranscriptIndex);
        }
        if self.delta_index as usize >= MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1 {
            return Err(AxtSourceTransferReplayKeyValidationErrorV1::DeltaIndex);
        }
        Ok(())
    }
}

/// Invalid permanent physical-transfer replay identity.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AxtSourceTransferReplayKeyValidationErrorV1 {
    /// Source network identity is absent.
    #[error("AXT source transfer replay key has no network identity")]
    Network,
    /// Finalized source block identity is absent.
    #[error("AXT source transfer replay key has no finalized block header")]
    BlockHeader,
    /// Transaction position exceeds the bounded canonical source block.
    #[error("AXT source transfer replay key transaction index is out of range")]
    TransactionIndex,
    /// Transcript position exceeds the maximum proof-bound transfer count.
    #[error("AXT source transfer replay key transcript index is out of range")]
    TranscriptIndex,
    /// Delta position exceeds the maximum proof-bound transfer count.
    #[error("AXT source transfer replay key delta index is out of range")]
    DeltaIndex,
}

/// Permanent witness that one source transfer consumed one issuer nonce.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtSourceTransferReplayRecordV1")]
pub struct AxtSourceTransferReplayRecordV1 {
    /// Fresh issuer authorization consumed by this physical transfer.
    pub issuer_nonce: AxtAnchoredSpendReplayKeyV1,
    /// Exact consensus slot in which the spend was applied.
    pub consumed_slot: u64,
}

/// Invalid durable issuer nonce identity for an anchored AXT spend.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AxtAnchoredSpendReplayKeyValidationErrorV1 {
    /// The issuer context does not identify a registered asset incarnation.
    #[error("AXT spend replay key has an invalid issuer context: {0}")]
    IssuerContext(AxtAssetIncarnationValidationError),
    /// A zero nonce cannot authenticate a spend.
    #[error("AXT spend replay key has an invalid nonce: {0}")]
    Nonce(AxtSpendNonceValidationErrorV1),
}

impl AxtAnchoredSpendDraftV1 {
    fn validate_binding_v1(
        &self,
        anchor: &AxtFinalizedSpendAnchorV1,
        expiry_slot: u64,
        nonce: AxtSpendNonceV1,
    ) -> Result<AxtAnchoredSpendIssuerPayloadV1, AxtAnchoredSpendValidationErrorV1> {
        anchor
            .validate()
            .map_err(AxtAnchoredSpendValidationErrorV1::Anchor)?;
        nonce
            .validate()
            .map_err(AxtAnchoredSpendValidationErrorV1::Nonce)?;
        if expiry_slot == 0
            || self.handle.expiry_slot != expiry_slot
            || self.proof.as_ref().and_then(|proof| proof.expiry_slot) != Some(expiry_slot)
        {
            return Err(AxtAnchoredSpendValidationErrorV1::Expiry);
        }
        if self.handle.issuer_context.network_id != anchor.network_id {
            return Err(AxtAnchoredSpendValidationErrorV1::Network);
        }
        if self.handle.issuer_context.asset_dsid != anchor.dataspace_id
            || self.intent.asset_dsid != anchor.dataspace_id
        {
            return Err(AxtAnchoredSpendValidationErrorV1::Dataspace);
        }
        if self.handle.target_lane != anchor.lane_id {
            return Err(AxtAnchoredSpendValidationErrorV1::Lane);
        }
        if self.handle.asset_definition_id != self.intent.op.asset_definition_id {
            return Err(AxtAnchoredSpendValidationErrorV1::AssetDefinition);
        }
        if !self.handle.scope.iter().any(|scope| scope == "transfer") {
            return Err(AxtAnchoredSpendValidationErrorV1::Scope);
        }
        if self.handle.subject.account != self.intent.op.from {
            return Err(AxtAnchoredSpendValidationErrorV1::Subject);
        }
        if self
            .handle
            .subject
            .origin_dsid
            .is_some_and(|origin| origin != anchor.dataspace_id)
        {
            return Err(AxtAnchoredSpendValidationErrorV1::OriginDataspace);
        }
        if self.amount.as_ref() != self.intent.op.amount.as_ref() {
            return Err(AxtAnchoredSpendValidationErrorV1::AmountMirror);
        }
        let proof = self
            .proof
            .as_ref()
            .ok_or(AxtAnchoredSpendValidationErrorV1::Proof)?;
        if !proof_envelope_shape_matches_manifest(
            proof,
            anchor.dataspace_id,
            self.handle.manifest_view_root,
        ) {
            return Err(AxtAnchoredSpendValidationErrorV1::Proof);
        }
        let envelope = norito::decode_canonical::<AxtProofEnvelope>(&proof.payload)
            .map_err(|_| AxtAnchoredSpendValidationErrorV1::Proof)?;
        if envelope.da_commitment != Some(anchor.da_manifest_digest.into()) {
            return Err(AxtAnchoredSpendValidationErrorV1::DaManifest);
        }
        if envelope.amount_commitment != self.amount_commitment {
            return Err(AxtAnchoredSpendValidationErrorV1::AmountCommitmentMirror);
        }
        if let Some(clear_amount) = self.intent.op.amount.as_ref() {
            if self.amount_commitment.is_some() || envelope.amount_commitment.is_some() {
                return Err(AxtAnchoredSpendValidationErrorV1::AmountCommitment);
            }
            if self.amount.as_ref() != Some(clear_amount) {
                return Err(AxtAnchoredSpendValidationErrorV1::Amount);
            }
            if envelope.committed_amount.is_none_or(|amount| amount == 0)
                || clear_amount.scale() != 0
                || clear_amount.as_numeric().try_mantissa_u128() != envelope.committed_amount
            {
                return Err(AxtAnchoredSpendValidationErrorV1::Amount);
            }
        } else {
            if self.amount.is_some() || envelope.committed_amount.is_some() {
                return Err(AxtAnchoredSpendValidationErrorV1::Amount);
            }
            if self.amount_commitment.is_none_or(|bytes| bytes == [0; 32]) {
                return Err(AxtAnchoredSpendValidationErrorV1::AmountCommitment);
            }
        }
        self.source_occurrence
            .validate()
            .map_err(AxtAnchoredSpendValidationErrorV1::SourceOccurrence)?;
        if self.source_receipt.finalized_anchor_digest != anchor.digest_v1()
            || self
                .source_receipt
                .source_tx_commitment
                .iter()
                .all(|byte| *byte == 0)
            || self
                .source_receipt
                .post_transaction_state_root
                .iter()
                .all(|byte| *byte == 0)
            || self
                .source_receipt
                .effect_set_digest
                .iter()
                .all(|byte| *byte == 0)
            || usize::try_from(self.source_receipt.source_tx_index)
                .map_or(true, |index| index >= MAX_AXT_FINALIZED_TRANSACTIONS_V1)
            || self.source_receipt.source_tx_commitment
                != self.source_occurrence.source_tx_commitment
            || self.source_receipt.source_tx_index != self.source_occurrence.source_tx_index
            || self.source_receipt.digest_v1()
                != self.source_occurrence.source_success_receipt_digest
        {
            return Err(AxtAnchoredSpendValidationErrorV1::SourceReceipt);
        }
        let binding = envelope
            .fastpq_binding
            .as_ref()
            .ok_or(AxtAnchoredSpendValidationErrorV1::Proof)?;
        if self.intent.op.kind != "transfer"
            || !matches!(
                binding.claim_type.as_str(),
                "tx_predicate" | "value_conservation"
            )
            || !binding
                .source_tx_commitment
                .eq_ignore_ascii_case(&hex::encode(self.source_occurrence.source_tx_commitment))
            || binding
                .remote_spend_intent_commitments
                .binary_search(&self.source_occurrence.remote_spend_claim_commitment)
                .is_err()
        {
            return Err(AxtAnchoredSpendValidationErrorV1::SourceClaim);
        }
        if let Some(amount) = self.intent.op.amount.as_ref() {
            let expected_claim = compute_remote_spend_intent_commitment_v1(
                AxtHandleReplayKey::from_handle(anchor.dataspace_id, &self.handle),
                &self.intent.op.asset_definition_id,
                &self.intent.op.kind,
                &self.intent.op.from,
                &self.intent.op.to,
                amount,
            );
            if expected_claim != self.source_occurrence.remote_spend_claim_commitment {
                return Err(AxtAnchoredSpendValidationErrorV1::SourceClaim);
            }
        }
        // These fields are issuer-bound claims. Only the finalized State owner
        // and FASTPQ verifier can authenticate source success and occurrence.
        Ok(AxtAnchoredSpendIssuerPayloadV1 {
            handle_replay_key: AxtHandleReplayKey::from_handle(anchor.dataspace_id, &self.handle),
            handle_digest: axt_framed_digest_v1(
                AXT_ANCHORED_SPEND_HANDLE_DIGEST_DOMAIN_V1,
                &self.handle,
            ),
            intent: self.intent.clone(),
            proof_digest: axt_framed_digest_v1(AXT_ANCHORED_SPEND_PROOF_DIGEST_DOMAIN_V1, proof),
            amount: self.amount.clone(),
            amount_commitment: self.amount_commitment,
            source_success_receipt_digest: self.source_receipt.digest_v1(),
            source_occurrence: self.source_occurrence,
            anchor: *anchor,
            expiry_slot,
            nonce,
        })
    }

    /// Sign this exact spend with the committed issuer key.
    ///
    /// # Errors
    ///
    /// Rejects incomplete or inconsistent spend bindings and cryptographic
    /// signing failure.
    pub fn sign_by_issuer_v1(
        self,
        anchor: AxtFinalizedSpendAnchorV1,
        expiry_slot: u64,
        nonce: AxtSpendNonceV1,
        issuer: &PrivateKey,
    ) -> Result<AxtAnchoredSpendV1, AxtAnchoredSpendValidationErrorV1> {
        let payload = self.validate_binding_v1(&anchor, expiry_slot, nonce)?;
        let preimage = anchored_spend_signature_preimage_v1(&payload);
        let issuer_signature = Signature::try_new(issuer, &preimage)
            .map_err(|_| AxtAnchoredSpendValidationErrorV1::Cryptography)?;
        Ok(AxtAnchoredSpendV1 {
            draft: self,
            authorization: AxtAnchoredSpendIssuerAuthorizationV1 {
                anchor,
                expiry_slot,
                nonce,
                issuer_signature,
            },
        })
    }
}

impl AxtAnchoredSpendV1 {
    /// Reconstruct the canonical issuer-signed payload from the carried fields.
    ///
    /// # Errors
    ///
    /// Rejects any inconsistent anchor, proof, handle, amount, expiry, or nonce.
    pub fn issuer_payload_v1(
        &self,
    ) -> Result<AxtAnchoredSpendIssuerPayloadV1, AxtAnchoredSpendValidationErrorV1> {
        self.draft.validate_binding_v1(
            &self.authorization.anchor,
            self.authorization.expiry_slot,
            self.authorization.nonce,
        )
    }

    /// Verify both the reusable handle signature and fresh spend signature.
    ///
    /// # Errors
    ///
    /// Rejects a mismatch with authoritative WSV context or anchor, malformed
    /// spend bindings, or either invalid issuer signature.
    pub fn verify_issuer_signatures_v1(
        &self,
        authoritative_context: AxtHandleIssuerContextV1,
        authoritative_anchor: AxtFinalizedSpendAnchorV1,
        issuer: &PublicKey,
    ) -> Result<(), AxtAnchoredSpendValidationErrorV1> {
        if self.authorization.anchor != authoritative_anchor {
            return Err(AxtAnchoredSpendValidationErrorV1::AnchorMismatch);
        }
        self.draft
            .handle
            .verify_issuer_signature_v1(authoritative_context, issuer)
            .map_err(|_| AxtAnchoredSpendValidationErrorV1::HandleSignature)?;
        let payload = self.issuer_payload_v1()?;
        self.authorization
            .issuer_signature
            .verify(issuer, &anchored_spend_signature_preimage_v1(&payload))
            .map_err(|_| AxtAnchoredSpendValidationErrorV1::SpendSignature)
    }

    /// Return the durable once-only issuer nonce identity.
    #[must_use]
    pub const fn replay_key_v1(&self) -> AxtAnchoredSpendReplayKeyV1 {
        AxtAnchoredSpendReplayKeyV1 {
            issuer_context: self.draft.handle.issuer_context,
            nonce: self.authorization.nonce,
        }
    }
}

fn anchored_spend_signature_preimage_v1(payload: &AxtAnchoredSpendIssuerPayloadV1) -> Vec<u8> {
    let encoded = encode_adaptive(payload);
    let mut preimage = Vec::with_capacity(
        AXT_ANCHORED_SPEND_ISSUER_SIGNATURE_DOMAIN_V1
            .len()
            .saturating_add(encoded.len()),
    );
    preimage.extend_from_slice(AXT_ANCHORED_SPEND_ISSUER_SIGNATURE_DOMAIN_V1);
    preimage.extend_from_slice(&encoded);
    preimage
}

/// Validation failure for a finalized, issuer-signed AXT spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AxtAnchoredSpendValidationErrorV1 {
    /// Finalized source-state anchor is structurally invalid.
    #[error("AXT anchored spend has an invalid finalized anchor: {0}")]
    Anchor(AxtFinalizedSpendAnchorValidationErrorV1),
    /// Submitted anchor differs from the exact WSV-resolved record.
    #[error("AXT anchored spend does not match the authoritative finalized anchor")]
    AnchorMismatch,
    /// Fresh nonce is invalid.
    #[error("AXT anchored spend has an invalid nonce: {0}")]
    Nonce(AxtSpendNonceValidationErrorV1),
    /// Expiry is absent or differs across the handle, proof, and spend authorization.
    #[error("AXT anchored spend expiry binding is invalid")]
    Expiry,
    /// Anchor and issuer context target different networks.
    #[error("AXT anchored spend network binding is invalid")]
    Network,
    /// Anchor, handle, and intent target different dataspaces.
    #[error("AXT anchored spend dataspace binding is invalid")]
    Dataspace,
    /// Anchor and handle target different lanes.
    #[error("AXT anchored spend lane binding is invalid")]
    Lane,
    /// Handle and intent target different asset definitions.
    #[error("AXT anchored spend asset-definition binding is invalid")]
    AssetDefinition,
    /// Issuer-signed capability does not authorize a transfer.
    #[error("AXT anchored spend handle does not authorize transfers")]
    Scope,
    /// Issuer-signed capability subject differs from the transfer source.
    #[error("AXT anchored spend transfer source differs from the handle subject")]
    Subject,
    /// Explicit issuer-signed source dataspace differs from the finalized anchor.
    #[error("AXT anchored spend origin dataspace differs from the finalized anchor")]
    OriginDataspace,
    /// Clear amount does not match the intent, or a hidden amount was revealed.
    #[error("AXT anchored spend amount mirror is invalid")]
    AmountMirror,
    /// The issuer-signed amount commitment differs from the proof envelope.
    #[error("AXT anchored spend amount commitment differs from the proof envelope")]
    AmountCommitmentMirror,
    /// Proof is absent, oversized, malformed, or bound to another policy manifest.
    #[error("AXT anchored spend proof binding is invalid")]
    Proof,
    /// Proof and finalized anchor bind different DA manifests.
    #[error("AXT anchored spend DA-manifest binding is invalid")]
    DaManifest,
    /// Clear/hidden amount modes or exact proof scalar and intent mirrors disagree.
    #[error("AXT anchored spend amount binding is invalid")]
    Amount,
    /// Hidden commitment is missing or differs between spend and proof envelope.
    #[error("AXT anchored spend amount commitment binding is invalid")]
    AmountCommitment,
    /// Claimed source success receipt does not match this anchor and occurrence.
    #[error("AXT anchored spend source success receipt binding is invalid")]
    SourceReceipt,
    /// Claimed ordered source transfer occurrence is structurally invalid.
    #[error("AXT anchored spend source transfer occurrence is invalid: {0}")]
    SourceOccurrence(AxtSourceTransferOccurrenceErrorV1),
    /// The proof does not commit this exact source execution and remote spend claim.
    #[error("AXT anchored spend source transfer claim binding is invalid")]
    SourceClaim,
    /// Reusable handle signature is invalid for authoritative WSV context.
    #[error("AXT anchored spend handle signature is invalid")]
    HandleSignature,
    /// Fresh issuer signature is invalid for the exact spend payload.
    #[error("AXT anchored spend issuer signature is invalid")]
    SpendSignature,
    /// Issuer signing failed.
    #[error("AXT anchored spend signing failed")]
    Cryptography,
}
/// Claimed source receipt preimage for one successful finalized execution.
///
/// The success domain is intentional, but constructing this value does not
/// authenticate execution. The finalized State owner must resolve and compare
/// the exact receipt before the digest can authorize a remote spend.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtSourceSuccessReceiptV1")]
pub struct AxtSourceSuccessReceiptV1 {
    /// Digest of the exact authoritative finalized anchor.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub finalized_anchor_digest: [u8; 32],
    /// Exact source execution-call commitment, distinct from transaction inclusion.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub source_tx_commitment: [u8; 32],
    /// Zero-based position in the anchor's ordered canonical transaction wires.
    pub source_tx_index: u32,
    /// State root immediately after this transaction executed successfully.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub post_transaction_state_root: [u8; 32],
    /// Digest of the complete ordered effects emitted by this execution.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub effect_set_digest: [u8; 32],
}

impl AxtSourceSuccessReceiptV1 {
    /// Commit the complete claimed successful-execution receipt preimage.
    #[must_use]
    pub fn digest_v1(&self) -> [u8; 32] {
        axt_framed_digest_v1(AXT_SOURCE_SUCCESS_RECEIPT_DIGEST_DOMAIN_V1, self)
    }
}

/// Claimed exact transfer occurrence within one successful source execution.
///
/// The receipt and transfer digests must be resolved against authoritative
/// finalized state before admission. The FASTPQ verifier separately binds
/// this public coordinate to its ordered transfer transcript and proof trace.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtSourceTransferOccurrenceV1")]
pub struct AxtSourceTransferOccurrenceV1 {
    /// Exact source execution-call commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub source_tx_commitment: [u8; 32],
    /// Digest of the claimed successful-execution receipt.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub source_success_receipt_digest: [u8; 32],
    /// Zero-based position of the source execution in finalized transaction wires.
    pub source_tx_index: u32,
    /// Zero-based position of the ordered transfer transcript.
    pub transcript_index: u32,
    /// Zero-based position of the transfer within that transcript.
    pub delta_index: u32,
    /// Zero-based transfer-pair ordinal across all ordered transcripts.
    pub pair_ordinal: u32,
    /// Digest of complete public transfer facts, including before/after balances.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub transfer_digest: [u8; 32],
    /// Exact authenticated handle/intent claim commitment using this occurrence.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub remote_spend_claim_commitment: [u8; 32],
}

impl AxtSourceTransferOccurrenceV1 {
    /// Check required digests and bounded finalized/proof coordinates.
    ///
    /// # Errors
    /// Returns the first missing digest or out-of-range coordinate. This structural check does not
    /// authenticate a finalized receipt or authorize a spend.
    pub fn validate(&self) -> Result<(), AxtSourceTransferOccurrenceErrorV1> {
        for (field, digest) in [
            (
                AxtSourceTransferOccurrenceFieldV1::SourceExecution,
                &self.source_tx_commitment,
            ),
            (
                AxtSourceTransferOccurrenceFieldV1::SuccessReceipt,
                &self.source_success_receipt_digest,
            ),
            (
                AxtSourceTransferOccurrenceFieldV1::Transfer,
                &self.transfer_digest,
            ),
            (
                AxtSourceTransferOccurrenceFieldV1::RemoteClaim,
                &self.remote_spend_claim_commitment,
            ),
        ] {
            if digest.iter().all(|byte| *byte == 0) {
                return Err(AxtSourceTransferOccurrenceErrorV1::MissingDigest(field));
            }
        }
        for (field, index, maximum) in [
            (
                AxtSourceTransferCoordinateFieldV1::SourceTransaction,
                self.source_tx_index,
                MAX_AXT_FINALIZED_TRANSACTIONS_V1,
            ),
            (
                AxtSourceTransferCoordinateFieldV1::Transcript,
                self.transcript_index,
                MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1,
            ),
            (
                AxtSourceTransferCoordinateFieldV1::Delta,
                self.delta_index,
                MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1,
            ),
            (
                AxtSourceTransferCoordinateFieldV1::PairOrdinal,
                self.pair_ordinal,
                MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1,
            ),
        ] {
            if index as usize >= maximum {
                return Err(AxtSourceTransferOccurrenceErrorV1::CoordinateOutOfRange(
                    field,
                ));
            }
        }
        Ok(())
    }

    /// Commit the receipt, exact ordered coordinate, transfer, and handle claim.
    #[must_use]
    pub fn digest_v1(&self) -> [u8; 32] {
        axt_framed_digest_v1(AXT_SOURCE_TRANSFER_OCCURRENCE_DIGEST_DOMAIN_V1, self)
    }
}

/// One required digest in a source transfer occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AxtSourceTransferOccurrenceFieldV1 {
    /// Exact source execution-call commitment.
    SourceExecution,
    /// Successful-execution receipt digest.
    SuccessReceipt,
    /// Complete public transfer fact digest.
    Transfer,
    /// Handle/intent claim commitment.
    RemoteClaim,
}

/// One bounded coordinate in a claimed source transfer occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AxtSourceTransferCoordinateFieldV1 {
    /// Position in canonical finalized source transaction wires.
    SourceTransaction,
    /// Position in ordered transfer transcripts for that execution.
    Transcript,
    /// Position within the selected transfer transcript.
    Delta,
    /// Position among all transfer pairs in transcript order.
    PairOrdinal,
}

/// Structural error for a claimed source transfer occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AxtSourceTransferOccurrenceErrorV1 {
    /// A required digest is the all-zero absence sentinel.
    #[error("AXT source transfer occurrence has an absent {0:?} digest")]
    MissingDigest(AxtSourceTransferOccurrenceFieldV1),
    /// One claimed coordinate exceeds its V1 finalized-block or proof ceiling.
    #[error("AXT source transfer occurrence has an out-of-range {0:?} coordinate")]
    CoordinateOutOfRange(AxtSourceTransferCoordinateFieldV1),
}

/// Commit the complete public facts of one ordered transfer delta.
///
/// The digest omits private sparse-Merkle witness paths. Its caller must use
/// the exact delta at the claimed transcript/delta coordinate.
#[must_use]
pub fn axt_source_transfer_digest_v1(
    delta: &crate::fastpq::FastpqPublicTransferDeltaV1,
) -> [u8; 32] {
    axt_framed_digest_v1(AXT_SOURCE_TRANSFER_DIGEST_DOMAIN_V1, delta)
}

/// Canonical claim binding one proof-resolved remote spend to one authenticated handle use.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtRemoteSpendClaimV1")]
pub struct AxtRemoteSpendClaimV1 {
    /// Exact authenticated handle use that is allowed to consume this claim.
    ///
    /// Including the replay identity prevents a proof for one handle from
    /// authorizing a different handle with otherwise identical transfer data.
    pub handle_replay_key: AxtHandleReplayKey,
    /// Exact asset definition transferred by the proof transcript.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact operation kind. V1 FASTPQ transcript linkage accepts only `transfer`.
    pub kind: String,
    /// Canonical I105 source account.
    pub from: String,
    /// Canonical I105 destination account.
    pub to: String,
    /// Effective clear or proof-resolved amount.
    pub effective_amount: Quantity,
}
impl AxtRemoteSpendClaimV1 {
    /// Construct the canonical preimage committed for one remote spend.
    #[must_use]
    pub fn new(
        handle_replay_key: AxtHandleReplayKey,
        asset_definition_id: AssetDefinitionId,
        kind: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        effective_amount: Quantity,
    ) -> Self {
        Self {
            handle_replay_key,
            asset_definition_id,
            kind: kind.into(),
            from: from.into(),
            to: to.into(),
            effective_amount,
        }
    }
}
/// Compute the canonical V1 commitment that binds a FASTPQ proof to one remote spend.
///
/// The commitment covers the exact authenticated handle replay identity, asset
/// definition, operation kind, canonical accounts, and effective amount. The
/// handle identity includes its descriptor binding, asset dataspace, exact
/// asset-definition incarnation, era, sub-nonce, and target lane, so a proof
/// cannot be replayed for another handle or a later registration of the asset.
/// The domain separator and canonical framed Norito statement encoding make
/// the commitment deterministic and distinct from other AXT and FASTPQ digests.
#[must_use]
pub fn compute_remote_spend_intent_commitment_v1(
    handle_replay_key: AxtHandleReplayKey,
    asset_definition_id: &AssetDefinitionId,
    kind: &str,
    from: &str,
    to: &str,
    effective_amount: &Quantity,
) -> [u8; 32] {
    let statement = AxtRemoteSpendClaimV1::new(
        handle_replay_key,
        asset_definition_id.clone(),
        kind,
        from,
        to,
        effective_amount.clone(),
    );
    compute_remote_spend_claim_commitment_v1(&statement)
}
/// Compute the canonical V1 commitment for an already materialized remote-spend claim.
#[must_use]
pub fn compute_remote_spend_claim_commitment_v1(statement: &AxtRemoteSpendClaimV1) -> [u8; 32] {
    let mut payload = b"iroha:axt:remote-spend-intent:v1\0".to_vec();
    payload.extend_from_slice(
        &norito::encode_canonical(statement)
            .expect("fixed remote-spend commitment statement must encode canonically"),
    );
    Hash::new(payload).into()
}
/// Canonical fingerprint for a handle usage recorded in the replay ledger.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtHandleReplayKey")]
pub struct AxtHandleReplayKey {
    /// Dataspace whose committed policy issued the handle.
    pub asset_dsid: DataSpaceId,
    /// Exact registered incarnation of the asset definition authorized by the handle.
    pub asset_definition_incarnation: AxtAssetIncarnationV1,
    /// Descriptor binding that minted the handle.
    pub binding: AxtBinding,
    /// Handle era.
    pub handle_era: u64,
    /// Handle sub-nonce.
    pub sub_nonce: u64,
    /// Target lane for the handle.
    pub target_lane: LaneId,
}
impl AxtHandleReplayKey {
    /// Create a replay key from explicit parts.
    #[must_use]
    pub fn from_parts(
        asset_dsid: DataSpaceId,
        asset_definition_incarnation: AxtAssetIncarnationV1,
        binding: [u8; 32],
        handle_era: u64,
        sub_nonce: u64,
        target_lane: LaneId,
    ) -> Self {
        Self {
            asset_dsid,
            asset_definition_incarnation,
            binding: AxtBinding::new(binding),
            handle_era,
            sub_nonce,
            target_lane,
        }
    }
    /// Create a replay key from an [`AssetHandle`] and its authenticated policy dataspace.
    #[must_use]
    pub fn from_handle(asset_dsid: DataSpaceId, handle: &AssetHandle) -> Self {
        Self::from_parts(
            asset_dsid,
            handle.issuer_context.asset_definition_incarnation,
            handle.axt_binding.into_array(),
            handle.handle_era,
            handle.sub_nonce,
            handle.target_lane,
        )
    }

    /// Return the exact asset-definition incarnation authenticated by this replay key.
    #[must_use]
    pub const fn asset_definition_incarnation(&self) -> AxtAssetIncarnationV1 {
        self.asset_definition_incarnation
    }

    /// Validate the exact asset incarnation carried by a decoded replay key.
    ///
    /// # Errors
    ///
    /// Rejects the absence sentinel or a non-canonical hash marker.
    pub fn validate(&self) -> Result<(), AxtHandleReplayKeyValidationError> {
        self.asset_definition_incarnation
            .validate()
            .map_err(AxtHandleReplayKeyValidationError::InvalidAssetIncarnation)?;
        if self.handle_era == 0 {
            return Err(AxtHandleReplayKeyValidationError::ZeroHandleEra);
        }
        if self.sub_nonce == 0 {
            return Err(AxtHandleReplayKeyValidationError::ZeroSubNonce);
        }
        Ok(())
    }
}
/// Failure returned while validating a persisted AXT handle replay key.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AxtHandleReplayKeyValidationError {
    /// The key carries an absent or malformed asset-definition incarnation.
    #[error("replay key has an invalid asset-definition incarnation: {0}")]
    InvalidAssetIncarnation(AxtAssetIncarnationValidationError),
    /// V1 handles never authenticate era zero.
    #[error("replay key handle era must be non-zero")]
    ZeroHandleEra,
    /// V1 handles never authenticate sub-nonce zero.
    #[error("replay key sub-nonce must be non-zero")]
    ZeroSubNonce,
}
/// Ledger entry capturing when a handle was consumed.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtReplayRecord")]
pub struct AxtReplayRecord {
    /// Redundant observational dataspace recorded with the handle use.
    ///
    /// Replay and cleanup authority comes from [`AxtHandleReplayKey::asset_dsid`];
    /// consumers must not use this copy to select the replay scope.
    pub dataspace: DataSpaceId,
    /// Exact issuer-authenticated family whose durable budget proves this use.
    ///
    /// The replay key intentionally carries only the compact nonce identity, so
    /// this field is required to preserve a fail-closed link to the complete
    /// signed capability family across snapshots and Kura replay.
    pub budget_key: AxtHandleBudgetKey,
    /// Slot when the handle was observed.
    pub used_slot: u64,
    /// Slot after which the replay guard can be evicted.
    pub retain_until_slot: u64,
}
/// Failure returned while validating a persisted AXT replay-ledger entry.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AxtReplayRecordValidationError {
    /// The authoritative replay key carries an absent or malformed asset incarnation.
    #[error("invalid authoritative replay key: {0}")]
    InvalidReplayKey(AxtHandleReplayKeyValidationError),
    /// The referenced family key carries an absent or malformed asset incarnation.
    #[error("replay record references an invalid handle budget family: {0}")]
    InvalidBudgetKey(AxtAssetIncarnationValidationError),
    /// The redundant record dataspace differs from the authoritative key.
    #[error("replay record dataspace does not match its authoritative key")]
    DataspaceMismatch,
    /// The compact replay identity and referenced family authenticate different incarnations.
    #[error("replay record budget family has a different asset incarnation")]
    BudgetIncarnationMismatch,
    /// The compact replay identity and referenced family authenticate different generations.
    #[error("replay record budget family has a different authorization generation")]
    BudgetGenerationMismatch,
    /// The compact replay identity and referenced family authenticate different lanes.
    #[error("replay record budget family has a different target lane")]
    BudgetLaneMismatch,
    /// The compact replay identity and referenced family authenticate different bindings.
    #[error("replay record budget family has a different AXT binding")]
    BudgetBindingMismatch,
    /// A zeroed record cannot represent an accepted handle use.
    #[error("replay record has zero use and retention slots")]
    ZeroedSlots,
    /// The retention deadline precedes the slot at which the handle was used.
    #[error("replay record retention deadline precedes its use slot")]
    RetentionBeforeUse,
}
impl AxtReplayRecord {
    /// Validate a decoded persisted record against its authoritative replay key.
    ///
    /// The dataspace carried by the record is observational redundancy only;
    /// authorization and lookup always use the key.
    ///
    /// # Errors
    ///
    /// Returns [`AxtReplayRecordValidationError`] when the authoritative key is
    /// invalid, the redundant dataspace or signed budget family disagrees with
    /// the key, both slots are zero, or retention ends before the recorded use.
    pub fn validate_for_key(
        &self,
        key: &AxtHandleReplayKey,
    ) -> Result<(), AxtReplayRecordValidationError> {
        key.validate()
            .map_err(AxtReplayRecordValidationError::InvalidReplayKey)?;
        self.budget_key
            .validate()
            .map_err(AxtReplayRecordValidationError::InvalidBudgetKey)?;
        if self.dataspace != key.asset_dsid || self.budget_key.asset_dsid() != key.asset_dsid {
            return Err(AxtReplayRecordValidationError::DataspaceMismatch);
        }
        if self.budget_key.asset_definition_incarnation() != key.asset_definition_incarnation {
            return Err(AxtReplayRecordValidationError::BudgetIncarnationMismatch);
        }
        if self.budget_key.authorization_generation() != key.handle_era {
            return Err(AxtReplayRecordValidationError::BudgetGenerationMismatch);
        }
        if self.budget_key.target_lane != key.target_lane {
            return Err(AxtReplayRecordValidationError::BudgetLaneMismatch);
        }
        if self.budget_key.axt_binding != key.binding {
            return Err(AxtReplayRecordValidationError::BudgetBindingMismatch);
        }
        if self.used_slot == 0 && self.retain_until_slot == 0 {
            return Err(AxtReplayRecordValidationError::ZeroedSlots);
        }
        if self.retain_until_slot < self.used_slot {
            return Err(AxtReplayRecordValidationError::RetentionBeforeUse);
        }
        Ok(())
    }

    /// Determine whether the replay guard has expired for a given slot and retention window.
    ///
    /// Records with zeroed slots are treated as stale and expired.
    #[must_use]
    pub fn is_expired(&self, current_slot: u64, retention_slots: u64) -> bool {
        if self.used_slot == 0 && self.retain_until_slot == 0 {
            return true;
        }
        let retention_cutoff = self.used_slot.saturating_add(retention_slots);
        let effective_until = core::cmp::max(self.retain_until_slot, retention_cutoff);
        current_slot > effective_until
    }
}
/// Aggregate record used to persist and replicate AXT envelopes.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtEnvelopeRecord")]
pub struct AxtEnvelopeRecord {
    /// Binding derived from the descriptor.
    pub binding: AxtBinding,
    /// Lane executing the AXT.
    pub lane: LaneId,
    /// Canonical descriptor.
    pub descriptor: AxtDescriptor,
    /// Touch fragments per dataspace.
    pub touches: Vec<AxtTouchFragment>,
    /// Proof fragments per dataspace.
    pub proofs: Vec<AxtProofFragment>,
    /// Issuer-signed source-anchored spends selected for this envelope.
    pub spends: Vec<AxtAnchoredSpendV1>,
    /// Exact height of the block that persists this envelope.
    pub commit_height: u64,
}
/// Per-dataspace policy snapshot sourced from the Space Directory/WSV.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtPolicyEntry")]
pub struct AxtPolicyEntry {
    /// Manifest root the handle must reference.
    pub manifest_root: [u8; 32],
    /// Lane the handle must target.
    pub target_lane: LaneId,
    /// Exact active handle era.
    pub active_handle_era: u64,
    /// Exact next admissible handle counter.
    pub next_handle_counter: u64,
    /// Current slot used for expiry checks.
    pub current_slot: u64,
}
/// Binding between a dataspace id and its AXT policy.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtPolicyBinding")]
pub struct AxtPolicyBinding {
    /// Dataspace identifier.
    pub dsid: DataSpaceId,
    /// Policy entry.
    pub policy: AxtPolicyEntry,
}
/// Collection of AXT policy bindings for deterministic replication.
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
    Default,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtPolicySnapshot")]
pub struct AxtPolicySnapshot {
    /// Hash-derived snapshot version (truncated to u64 for gauges/telemetry).
    pub version: u64,
    /// Ordered bindings for each dataspace.
    pub entries: Vec<AxtPolicyBinding>,
}
/// Errors returned when validating an AXT policy snapshot.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum AxtPolicySnapshotValidationError {
    /// Snapshot repeats a dataspace identifier.
    #[error("duplicate policy binding for dataspace {0}")]
    DuplicateDataspaceId(DataSpaceId),
    /// Snapshot bindings are not strictly increasing by dataspace identifier.
    #[error(
        "policy bindings must be strictly ordered: dataspace {previous} appears before {current}"
    )]
    EntriesNotStrictlyOrdered {
        /// Dataspace identifier immediately before the ordering violation.
        previous: DataSpaceId,
        /// Dataspace identifier at the ordering violation.
        current: DataSpaceId,
    },
    /// Snapshot version does not bind the exact canonical entries.
    #[error("policy snapshot version mismatch: expected {expected}, found {actual}")]
    VersionMismatch {
        /// Version computed from the snapshot entries.
        expected: u64,
        /// Version advertised by the snapshot.
        actual: u64,
    },
    /// A policy projection disagrees with the permanent dataspace counter ratchet.
    #[error(
        "policy counter for dataspace {dataspace} is {policy_next}, permanent ratchet requires {ratchet_next}"
    )]
    CounterRatchetMismatch {
        /// Dataspace whose projected counter is inconsistent.
        dataspace: DataSpaceId,
        /// Next counter advertised by the policy snapshot.
        policy_next: u64,
        /// Exact next counter held by permanent consensus state.
        ratchet_next: u64,
    },
    /// A projected handle era disagrees with the permanent authorization generation.
    #[error(
        "policy authorization generation for dataspace {dataspace} is {policy_generation}, permanent ratchet requires {ratchet_generation}"
    )]
    AuthorizationGenerationRatchetMismatch {
        /// Dataspace whose projected generation is inconsistent.
        dataspace: DataSpaceId,
        /// Generation advertised as `active_handle_era` by the policy snapshot.
        policy_generation: u64,
        /// Exact generation held by permanent consensus state.
        ratchet_generation: u64,
    },
    /// A policy transition cannot revoke the final counter value without wrapping.
    #[error("AXT handle counter ratchet is exhausted for dataspace {dataspace}")]
    CounterRatchetExhausted {
        /// Dataspace whose permanent ratchet reached `u64::MAX`.
        dataspace: DataSpaceId,
    },
    /// A finalized local policy projection differs from the advertised snapshot.
    #[error("finalized AXT policy projection differs from advertised snapshot")]
    FinalizedPolicyMismatch,
    /// Non-genesis committed state did not expose consensus-authenticated time.
    #[error("committed non-genesis AXT state lacks authenticated ledger time")]
    AuthenticatedLedgerTimeUnavailable,
}
impl AxtPolicySnapshot {
    /// Compute a stable, truncated hash version for a policy snapshot.
    #[must_use]
    pub fn compute_version(entries: &[AxtPolicyBinding]) -> u64 {
        if entries.is_empty() {
            return 0;
        }
        let canonical_entries = entries.to_vec();
        let encoded = encode_adaptive(&canonical_entries);
        let hash = Hash::new(&encoded);
        let mut truncated = [0u8; 8];
        truncated.copy_from_slice(&hash.as_ref()[..8]);
        u64::from_le_bytes(truncated)
    }
    /// Populate the version field and reject non-canonical snapshot entries.
    ///
    /// # Errors
    ///
    /// Returns [`AxtPolicySnapshotValidationError`] when entries are duplicated
    /// or not strictly ordered.
    pub fn with_computed_version(mut self) -> Result<Self, AxtPolicySnapshotValidationError> {
        self.version = Self::compute_version(&self.entries);
        self.validate()?;
        Ok(self)
    }
    /// Validate canonical binding order and the exact derived snapshot version.
    ///
    /// # Errors
    ///
    /// Returns [`AxtPolicySnapshotValidationError`] when entries are duplicated,
    /// not strictly ordered, or do not match the advertised version.
    pub fn validate(&self) -> Result<(), AxtPolicySnapshotValidationError> {
        for pair in self.entries.windows(2) {
            let previous = pair[0].dsid;
            let current = pair[1].dsid;
            if previous == current {
                return Err(AxtPolicySnapshotValidationError::DuplicateDataspaceId(
                    current,
                ));
            }
            if previous > current {
                return Err(
                    AxtPolicySnapshotValidationError::EntriesNotStrictlyOrdered {
                        previous,
                        current,
                    },
                );
            }
        }
        let expected = Self::compute_version(&self.entries);
        if self.version != expected {
            return Err(AxtPolicySnapshotValidationError::VersionMismatch {
                expected,
                actual: self.version,
            });
        }
        Ok(())
    }
}
/// Context captured when an AXT envelope fails policy checks.
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
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtRejectContext")]
pub struct AxtRejectContext {
    /// Classified reason for the rejection.
    pub reason: AxtRejectReason,
    /// Dataspace associated with the rejection (if known).
    #[norito(required)]
    pub dataspace: Option<DataSpaceId>,
    /// Lane associated with the rejection (if known).
    #[norito(required)]
    pub lane: Option<LaneId>,
    /// Snapshot version advertised by the policy map used for validation, when one was installed.
    #[norito(required)]
    pub snapshot_version: Option<u64>,
    /// Human-readable detail string for operators.
    pub detail: String,
    /// Exact active handle era, when available.
    #[norito(required)]
    pub active_handle_era: Option<u64>,
    /// Exact next handle counter, when available.
    #[norito(required)]
    pub next_handle_counter: Option<u64>,
}
impl core::fmt::Display for AxtRejectContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} (lane={:?}, dsid={:?}",
            self.detail, self.lane, self.dataspace
        )?;
        if let Some(snapshot_version) = self.snapshot_version {
            write!(f, ", snapshot={snapshot_version}")?;
        }
        if let Some(era) = self.active_handle_era {
            write!(f, ", active_handle_era={era}")?;
        }
        if let Some(sub_nonce) = self.next_handle_counter {
            write!(f, ", next_handle_counter={sub_nonce}")?;
        }
        write!(f, ")")
    }
}
/// Canonical reason codes for AXT policy rejections.
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
#[norito(tag = "reason", content = "detail")]
#[repr(u8)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::axt::AxtRejectReason")]
pub enum AxtRejectReason {
    /// Dataspace or lane binding did not match the policy.
    Lane,
    /// Manifest root validation failed.
    Manifest,
    /// Handle era differs from the exact active era.
    HandleEra,
    /// Handle counter differs from the exact next counter.
    SubNonce,
    /// Proof or handle expired relative to the current slot.
    Expiry,
    /// Dataspace policy missing for the referenced handle/proof.
    MissingPolicy,
    /// Policy denied the request for any other reason (for example, scope mismatch).
    PolicyDenied,
    /// Proof payload failed validation.
    Proof,
    /// Envelope or handle referenced undeclared/invalid descriptor bindings.
    Descriptor,
    /// Budget constraints were exceeded.
    Budget,
    /// Replay guard or cache validation failed.
    ReplayCache,
    /// Duplicate fragment encountered.
    Duplicate,
}
impl AxtRejectReason {
    /// Stable label used for telemetry and debug outputs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Lane => "lane",
            Self::Manifest => "manifest",
            Self::HandleEra => "era",
            Self::SubNonce => "sub_nonce",
            Self::Expiry => "expiry",
            Self::MissingPolicy => "missing_policy",
            Self::PolicyDenied => "policy_denied",
            Self::Proof => "proof",
            Self::Descriptor => "descriptor",
            Self::Budget => "budget",
            Self::ReplayCache => "replay_cache",
            Self::Duplicate => "duplicate",
        }
    }
    /// Stable machine-readable code suitable for APIs and telemetry.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Lane => "AXT_LANE",
            Self::Manifest => "AXT_MANIFEST",
            Self::HandleEra => "AXT_HANDLE_ERA",
            Self::SubNonce => "AXT_SUB_NONCE",
            Self::Expiry => "AXT_EXPIRY",
            Self::MissingPolicy => "AXT_MISSING_POLICY",
            Self::PolicyDenied => "AXT_POLICY_DENIED",
            Self::Proof => "AXT_PROOF",
            Self::Descriptor => "AXT_DESCRIPTOR",
            Self::Budget => "AXT_BUDGET",
            Self::ReplayCache => "AXT_REPLAY_CACHE",
            Self::Duplicate => "AXT_DUPLICATE",
        }
    }
    /// Alias for telemetry call sites.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        self.label()
    }
    /// Resolve a reason label (e.g., from telemetry) back into a structured enum.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "lane" => Some(Self::Lane),
            "manifest" => Some(Self::Manifest),
            "era" => Some(Self::HandleEra),
            "sub_nonce" => Some(Self::SubNonce),
            "expiry" => Some(Self::Expiry),
            "missing_policy" => Some(Self::MissingPolicy),
            "policy_denied" => Some(Self::PolicyDenied),
            "proof" => Some(Self::Proof),
            "descriptor" => Some(Self::Descriptor),
            "budget" => Some(Self::Budget),
            "replay_cache" => Some(Self::ReplayCache),
            "duplicate" => Some(Self::Duplicate),
            _ => None,
        }
    }
}
/// Errors returned when validating an AXT descriptor.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum AxtValidationError {
    /// Descriptor lists no dataspaces.
    #[error("descriptor must include at least one dataspace")]
    EmptyDataspaceList,
    /// Descriptor repeats a dataspace identifier.
    #[error("duplicate dataspace id {0}")]
    DuplicateDataspaceId(DataSpaceId),
    /// Descriptor dataspace identifiers are not strictly increasing.
    #[error("dataspace ids must be strictly ordered: {previous} appears before {current}")]
    DataspaceIdsNotStrictlyOrdered {
        /// Dataspace identifier immediately before the ordering violation.
        previous: DataSpaceId,
        /// Dataspace identifier at the ordering violation.
        current: DataSpaceId,
    },
    /// Touch specification references a dataspace not present in `dsids`.
    #[error("touch references undeclared dataspace {0}")]
    TouchUndeclaredDataspace(DataSpaceId),
    /// Touch specification is duplicated for the same dataspace.
    #[error("duplicate touch entry for dataspace {0}")]
    DuplicateTouch(DataSpaceId),
    /// Touch specifications are not strictly increasing by dataspace identifier.
    #[error(
        "touch entries must be strictly ordered: dataspace {previous} appears before {current}"
    )]
    TouchesNotStrictlyOrdered {
        /// Dataspace identifier immediately before the ordering violation.
        previous: DataSpaceId,
        /// Dataspace identifier at the ordering violation.
        current: DataSpaceId,
    },
    /// A declared read path is empty or contains only whitespace.
    #[error("read path {index} for dataspace {dsid} must not be empty")]
    EmptyReadPath {
        /// Dataspace containing the invalid path.
        dsid: DataSpaceId,
        /// Zero-based path index.
        index: usize,
    },
    /// A declared read path has leading or trailing whitespace.
    #[error("read path {index} for dataspace {dsid} must be trimmed")]
    UntrimmedReadPath {
        /// Dataspace containing the invalid path.
        dsid: DataSpaceId,
        /// Zero-based path index.
        index: usize,
    },
    /// A declared read path duplicates an earlier path.
    #[error("read path {duplicate_index} for dataspace {dsid} duplicates path {first_index}")]
    DuplicateReadPath {
        /// Dataspace containing the duplicate path.
        dsid: DataSpaceId,
        /// Zero-based index of the first occurrence.
        first_index: usize,
        /// Zero-based index of the duplicate occurrence.
        duplicate_index: usize,
    },
    /// Declared read paths are not strictly lexicographically increasing.
    #[error(
        "read paths for dataspace {dsid} must be strictly ordered: path {previous_index} appears before path {current_index}"
    )]
    ReadPathsNotStrictlyOrdered {
        /// Dataspace containing the ordering violation.
        dsid: DataSpaceId,
        /// Zero-based index immediately before the ordering violation.
        previous_index: usize,
        /// Zero-based index at the ordering violation.
        current_index: usize,
    },
    /// A declared write path is empty or contains only whitespace.
    #[error("write path {index} for dataspace {dsid} must not be empty")]
    EmptyWritePath {
        /// Dataspace containing the invalid path.
        dsid: DataSpaceId,
        /// Zero-based path index.
        index: usize,
    },
    /// A declared write path has leading or trailing whitespace.
    #[error("write path {index} for dataspace {dsid} must be trimmed")]
    UntrimmedWritePath {
        /// Dataspace containing the invalid path.
        dsid: DataSpaceId,
        /// Zero-based path index.
        index: usize,
    },
    /// A declared write path duplicates an earlier path.
    #[error("write path {duplicate_index} for dataspace {dsid} duplicates path {first_index}")]
    DuplicateWritePath {
        /// Dataspace containing the duplicate path.
        dsid: DataSpaceId,
        /// Zero-based index of the first occurrence.
        first_index: usize,
        /// Zero-based index of the duplicate occurrence.
        duplicate_index: usize,
    },
    /// Declared write paths are not strictly lexicographically increasing.
    #[error(
        "write paths for dataspace {dsid} must be strictly ordered: path {previous_index} appears before path {current_index}"
    )]
    WritePathsNotStrictlyOrdered {
        /// Dataspace containing the ordering violation.
        dsid: DataSpaceId,
        /// Zero-based index immediately before the ordering violation.
        previous_index: usize,
        /// Zero-based index at the ordering violation.
        current_index: usize,
    },
}
/// Validate the canonical invariants of an AXT descriptor.
///
/// # Errors
///
/// Returns [`AxtValidationError`] when dataspace or touch entries are empty,
/// undeclared, duplicated, or out of order, or when read/write paths are empty,
/// untrimmed, duplicated, or out of order.
pub fn validate_descriptor(descriptor: &AxtDescriptor) -> Result<(), AxtValidationError> {
    if descriptor.dsids.is_empty() {
        return Err(AxtValidationError::EmptyDataspaceList);
    }
    let mut seen_dsids = BTreeSet::new();
    for dsid in &descriptor.dsids {
        if !seen_dsids.insert(*dsid) {
            return Err(AxtValidationError::DuplicateDataspaceId(*dsid));
        }
    }
    for pair in descriptor.dsids.windows(2) {
        if pair[0] >= pair[1] {
            return Err(AxtValidationError::DataspaceIdsNotStrictlyOrdered {
                previous: pair[0],
                current: pair[1],
            });
        }
    }
    let mut seen_touches = BTreeSet::new();
    for touch in &descriptor.touches {
        if !seen_dsids.contains(&touch.dsid) {
            return Err(AxtValidationError::TouchUndeclaredDataspace(touch.dsid));
        }
        if !seen_touches.insert(touch.dsid) {
            return Err(AxtValidationError::DuplicateTouch(touch.dsid));
        }
    }
    for pair in descriptor.touches.windows(2) {
        if pair[0].dsid >= pair[1].dsid {
            return Err(AxtValidationError::TouchesNotStrictlyOrdered {
                previous: pair[0].dsid,
                current: pair[1].dsid,
            });
        }
    }
    for touch in &descriptor.touches {
        validate_read_paths(touch.dsid, &touch.read)?;
        validate_write_paths(touch.dsid, &touch.write)?;
    }
    Ok(())
}
fn validate_read_paths(dsid: DataSpaceId, paths: &[String]) -> Result<(), AxtValidationError> {
    let mut first_indices = BTreeMap::new();
    for (index, path) in paths.iter().enumerate() {
        if path.trim().is_empty() {
            return Err(AxtValidationError::EmptyReadPath { dsid, index });
        }
        if path.trim() != path {
            return Err(AxtValidationError::UntrimmedReadPath { dsid, index });
        }
        if let Some(first_index) = first_indices.insert(path.as_str(), index) {
            return Err(AxtValidationError::DuplicateReadPath {
                dsid,
                first_index,
                duplicate_index: index,
            });
        }
    }
    for (previous_index, pair) in paths.windows(2).enumerate() {
        if pair[0] >= pair[1] {
            return Err(AxtValidationError::ReadPathsNotStrictlyOrdered {
                dsid,
                previous_index,
                current_index: previous_index + 1,
            });
        }
    }
    Ok(())
}
fn validate_write_paths(dsid: DataSpaceId, paths: &[String]) -> Result<(), AxtValidationError> {
    let mut first_indices = BTreeMap::new();
    for (index, path) in paths.iter().enumerate() {
        if path.trim().is_empty() {
            return Err(AxtValidationError::EmptyWritePath { dsid, index });
        }
        if path.trim() != path {
            return Err(AxtValidationError::UntrimmedWritePath { dsid, index });
        }
        if let Some(first_index) = first_indices.insert(path.as_str(), index) {
            return Err(AxtValidationError::DuplicateWritePath {
                dsid,
                first_index,
                duplicate_index: index,
            });
        }
    }
    for (previous_index, pair) in paths.windows(2).enumerate() {
        if pair[0] >= pair[1] {
            return Err(AxtValidationError::WritePathsNotStrictlyOrdered {
                dsid,
                previous_index,
                current_index: previous_index + 1,
            });
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod captured_axt_schema_tests;
