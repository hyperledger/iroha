//! Zero-knowledge proof payloads and identifiers.
//!
//! This module defines an opaque container for proofs that can be attached to query responses and
//! other messages without committing to a specific proving system. The container carries a backend
//! identifier (`Ident`) and raw bytes produced by that backend. Norito serialization preserves both
//! fields byte-for-byte to ensure stable hashing and compatibility across nodes.
use crate::{confidential::ConfidentialStatus, zk::BackendTag};

mod ivm_execution_statement;
pub use ivm_execution_statement::{
    IVM_EXECUTION_STATEMENT_DIGEST_DOMAIN_V1, IvmAccessDependencyClaimV1,
    IvmCompleteStateRootClaimV1, IvmExecutionStatementDigestV1, IvmExecutionStatementErrorV1,
    IvmExecutionStatementV1, IvmFinalizedPrestateClaimV1, IvmOrderedOutputClaimV1,
    IvmReturnClaimV1, IvmVerifierProfileV1,
};

use base64::Engine as _;

use base64::engine::general_purpose::STANDARD;
use iroha_schema::{Ident, IntoSchema};
use norito::{
    codec::{Decode, Encode},
    core as ncore,
};
const MAX_BACKEND_FIELD_BYTES: usize = 4 * 1024;
const MAX_REF_FIELD_BYTES: usize = 16 * 1024;
/// Maximum canonical encoded size of a [`ProofBox`] nested in a proof attachment.
pub const PROOF_BOX_MAX_ENCODED_BYTES_V1: usize = 64 * 1024 * 1024;
const MAX_LEN_PREFIXED_FIELD_BYTES: usize = PROOF_BOX_MAX_ENCODED_BYTES_V1;
/// Maximum opaque payload bytes accepted in a first-release [`VerifyingKeyBox`].
pub const VERIFYING_KEY_BOX_MAX_PAYLOAD_BYTES_V1: usize = 8 * 1024 * 1024;
// A `Vec<u8>` value carries an advertised sequence length inside the enclosing
// struct-field frame. Leave bounded room for either fixed or compact Norito
// length headers while still rejecting attacker-sized fields before decoding.
const VERIFYING_KEY_BOX_MAX_FIELD_BYTES_V1: usize = VERIFYING_KEY_BOX_MAX_PAYLOAD_BYTES_V1 + 16;
/// Maximum byte length for portable verifier-key registry id fields.
pub const VERIFYING_KEY_ID_MAX_FIELD_BYTES: usize = 256;
/// Read a length‑prefixed field produced by Norito struct serializers.
fn take_len_prefixed_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    max_len: usize,
) -> Result<&'a [u8], ncore::Error> {
    let tail = bytes.get(*offset..).ok_or(ncore::Error::LengthMismatch)?;
    let (len, hdr) = ncore::read_len_dyn_slice(tail)?;
    if len > max_len {
        return Err(ncore::Error::LengthMismatch);
    }
    let start = offset
        .checked_add(hdr)
        .ok_or(ncore::Error::LengthMismatch)?;
    let end = start.checked_add(len).ok_or(ncore::Error::LengthMismatch)?;
    let field = bytes.get(start..end).ok_or(ncore::Error::LengthMismatch)?;
    *offset = end;
    Ok(field)
}

/// Split the two fields shared by proof and verifier-key byte boxes without allocating.
///
/// These boxes use a bounded custom decoder over the length-prefixed `AoS` struct layout. The
/// returned byte field includes its sequence-length header, allowing callers to reject oversized
/// payloads before `Vec<u8>` allocates.
fn take_byte_box_fields(
    bytes: &[u8],
    max_byte_field_len: usize,
) -> Result<(&[u8], &[u8], usize), ncore::Error> {
    let mut offset = 0usize;
    let backend = take_len_prefixed_slice(bytes, &mut offset, MAX_BACKEND_FIELD_BYTES)?;
    let byte_field = take_len_prefixed_slice(bytes, &mut offset, max_byte_field_len)?;
    Ok((backend, byte_field, offset))
}

fn decode_byte_box_fields(
    bytes: &[u8],
    max_byte_field_len: usize,
    max_payload_len: Option<usize>,
    max_canonical_box_len: Option<usize>,
) -> Result<(Ident, Vec<u8>, usize), ncore::Error> {
    let (backend_bytes, byte_field, used) = take_byte_box_fields(bytes, max_byte_field_len)?;
    let (backend, backend_used) =
        <Ident as ncore::DecodeFromSlice>::decode_from_slice(backend_bytes)?;
    if backend_used != backend_bytes.len() {
        return Err(ncore::Error::LengthMismatch);
    }
    let (declared_len, _) = ncore::inspect_seq_len_slice(byte_field)?;
    if max_payload_len.is_some_and(|maximum| declared_len > maximum) {
        return Err(ncore::Error::LengthMismatch);
    }
    if max_canonical_box_len.is_some_and(|maximum| {
        proof_box_canonical_encoded_len_for_lengths_v1(backend.as_str().len(), declared_len)
            .is_none_or(|actual| actual > maximum)
    }) {
        return Err(ncore::Error::LengthMismatch);
    }
    let (payload, payload_used) =
        <Vec<u8> as ncore::DecodeFromSlice>::decode_from_slice(byte_field)?;
    if payload_used != byte_field.len() {
        return Err(ncore::Error::LengthMismatch);
    }
    Ok((backend, payload, used))
}
/// Opaque zero-knowledge proof bytes tagged with a backend identifier.
///
/// - `backend`: schema identifier for the proof backend (e.g., "pipa-r/pasta",
///   "groth16/bn254", "stark/fri"). The exact strings are out of scope for
///   this container and are treated as application-level identifiers.
/// - `bytes`: proof payload as produced by the backend. Consumers interpret the
///   bytes according to `backend`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::ProofBox")]
pub struct ProofBox {
    /// Identifier of the proof backend/format.
    pub backend: iroha_schema::Ident,
    /// Opaque proof bytes.
    pub bytes: Vec<u8>,
}
fn proof_box_canonical_encoded_len_for_lengths_v1(
    backend_len: usize,
    proof_len: usize,
) -> Option<usize> {
    // `Ident` is a string (compact byte-length plus UTF-8 bytes), and every
    // struct member is itself compact-length framed. `Vec<u8>` retains the
    // fixed-width V1 sequence count inside its member frame. Derive every
    // prefix from Norito's canonical primitives so boundary transitions at
    // 2^7, 2^14, ... cannot drift from the serializer.
    let backend_value_len = ncore::varint_len_prefix_len(backend_len).checked_add(backend_len)?;
    if backend_value_len > MAX_BACKEND_FIELD_BYTES {
        return None;
    }
    let backend_field_len =
        ncore::varint_len_prefix_len(backend_value_len).checked_add(backend_value_len)?;
    let proof_value_len = ncore::seq_len_prefix_len(proof_len).checked_add(proof_len)?;
    let proof_field_len =
        ncore::varint_len_prefix_len(proof_value_len).checked_add(proof_value_len)?;
    backend_field_len.checked_add(proof_field_len)
}
/// Return the largest proof payload that keeps the complete canonical nested [`ProofBox`] payload
/// within [`PROOF_BOX_MAX_ENCODED_BYTES_V1`] for the supplied UTF-8 backend id.
///
/// `None` means the backend and mandatory canonical framing alone exceed the
/// closed first-release limit.
#[must_use]
pub fn proof_box_max_proof_bytes_v1(backend: &str) -> Option<usize> {
    if proof_box_canonical_encoded_len_for_lengths_v1(backend.len(), 0)?
        > PROOF_BOX_MAX_ENCODED_BYTES_V1
    {
        return None;
    }
    // Prefix widths make the exact size monotone but piecewise-linear. A
    // bounded binary search avoids duplicating those transition points and
    // never allocates proof storage.
    let mut lower = 0usize;
    let mut upper = PROOF_BOX_MAX_ENCODED_BYTES_V1;
    while lower < upper {
        let distance = upper - lower;
        let candidate = lower + distance / 2 + distance % 2;
        if proof_box_canonical_encoded_len_for_lengths_v1(backend.len(), candidate)
            .is_some_and(|length| length <= PROOF_BOX_MAX_ENCODED_BYTES_V1)
        {
            lower = candidate;
        } else {
            upper = candidate - 1;
        }
    }
    Some(lower)
}
impl ProofBox {
    /// Construct a new proof container.
    pub fn new(backend: iroha_schema::Ident, bytes: Vec<u8>) -> Self {
        Self { backend, bytes }
    }
    /// Return the exact canonical nested payload length of this proof box.
    #[must_use]
    pub fn canonical_encoded_len_v1(&self) -> Option<usize> {
        proof_box_canonical_encoded_len_for_lengths_v1(
            self.backend.as_str().len(),
            self.bytes.len(),
        )
    }
}

impl<'de> norito::DeserializePayload<'de> for ProofBox {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("ProofBox deserialization must succeed for canonical archives")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        let (value, used) = <Self as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
        if norito::debug_trace_enabled() {
            eprintln!(
                "ProofBox::try_deserialize consumed {used} of {} bytes",
                bytes.len()
            );
        }
        if used != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        Ok(value)
    }
}
impl<'a> ncore::DecodeFromSlice<'a> for ProofBox {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let (backend, proof_bytes, used) = decode_byte_box_fields(
            bytes,
            MAX_LEN_PREFIXED_FIELD_BYTES,
            None,
            Some(PROOF_BOX_MAX_ENCODED_BYTES_V1),
        )?;
        if norito::debug_trace_enabled() {
            let mut head = [0u8; 8];
            let preview = &proof_bytes[..proof_bytes.len().min(8)];
            head[..preview.len()].copy_from_slice(preview);
            eprintln!(
                "ProofBox::decode_from_slice backend_len={} proof_len={} vec_head_le={}",
                backend.as_str().len(),
                proof_bytes.len(),
                u64::from_le_bytes(head)
            );
        }
        Ok((
            Self {
                backend,
                bytes: proof_bytes,
            },
            used,
        ))
    }
}
/// Opaque verifying key bytes tagged with a backend identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::VerifyingKeyBox")]
pub struct VerifyingKeyBox {
    /// Identifier of the proof backend/format (must match associated proofs).
    pub backend: iroha_schema::Ident,
    /// Opaque verifying key bytes.
    pub bytes: Vec<u8>,
}
impl VerifyingKeyBox {
    /// Construct a new verifying key container.
    pub fn new(backend: iroha_schema::Ident, bytes: Vec<u8>) -> Self {
        Self { backend, bytes }
    }
}

impl<'de> norito::DeserializePayload<'de> for VerifyingKeyBox {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("VerifyingKeyBox deserialization must succeed for canonical archives")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        let (value, used) = <Self as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
        if norito::debug_trace_enabled() {
            eprintln!(
                "VerifyingKeyBox::try_deserialize consumed {used} of {} bytes",
                bytes.len()
            );
        }
        if used != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        Ok(value)
    }
}
impl<'a> ncore::DecodeFromSlice<'a> for VerifyingKeyBox {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let (backend, vk_bytes, used) = decode_byte_box_fields(
            bytes,
            VERIFYING_KEY_BOX_MAX_FIELD_BYTES_V1,
            Some(VERIFYING_KEY_BOX_MAX_PAYLOAD_BYTES_V1),
            None,
        )?;
        Ok((
            Self {
                backend,
                bytes: vk_bytes,
            },
            used,
        ))
    }
}
/// Identifier for a registered verifying key in WSV.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::VerifyingKeyId")]
pub struct VerifyingKeyId {
    /// Identifier of the proof backend/format.
    pub backend: iroha_schema::Ident,
    /// Human-readable key name under backend namespace.
    pub name: String,
}
impl VerifyingKeyId {
    /// Create a new verifying key identifier using an explicit backend namespace and name.
    pub fn new(backend: impl Into<iroha_schema::Ident>, name: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
            name: name.into(),
        }
    }
    /// Returns true when both id components use bounded portable registry syntax.
    #[must_use]
    pub fn is_portable_registry_id(&self) -> bool {
        verifying_key_id_field_is_portable(self.backend.as_str())
            && verifying_key_id_field_is_portable(&self.name)
    }
}
/// Returns true when a verifier-key registry id component is bounded and portable.
#[must_use]
pub fn verifying_key_id_field_is_portable(field: &str) -> bool {
    !field.is_empty()
        && field.len() <= VERIFYING_KEY_ID_MAX_FIELD_BYTES
        && crate::zk::open_verify_circuit_id_is_portable(field)
}
impl<'a> ncore::DecodeFromSlice<'a> for VerifyingKeyId {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let mut offset = 0usize;
        let backend_bytes = take_len_prefixed_slice(bytes, &mut offset, MAX_BACKEND_FIELD_BYTES)?;
        let (backend, used) = <Ident as ncore::DecodeFromSlice>::decode_from_slice(backend_bytes)?;
        if used != backend_bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        let name_bytes = take_len_prefixed_slice(bytes, &mut offset, MAX_REF_FIELD_BYTES)?;
        let (name, used) = <String as ncore::DecodeFromSlice>::decode_from_slice(name_bytes)?;
        if used != name_bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        if offset != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        Ok((Self { backend, name }, offset))
    }
}
/// Registry record for a verifying key with governance versioning.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::VerifyingKeyRecord")]
pub struct VerifyingKeyRecord {
    /// Monotonic version number managed by governance.
    pub version: u32,
    /// Backend circuit identifier associated with the verifying key.
    pub circuit_id: String,
    /// Optional manifest identifier that owns this verifier. `None` or `"core"` denotes built-ins.
    #[norito(default)]
    pub owner_manifest_id: Option<String>,
    /// Namespace that this verifier is bound to (e.g., contract namespace or ISI namespace).
    pub namespace: String,
    /// Proving engine tag (native PIPA-R or STARK).
    pub backend: BackendTag,
    /// Curve name used by the backend (human readable; e.g., "pasta", "pallas").
    pub curve: String,
    /// Stable hash of the public input schema to detect witness layout changes.
    #[norito(
        with = "crate::json_helpers::fixed_bytes",
        bounded_with = "crate::json_helpers::fixed_bytes::serialize_bounded"
    )]
    pub public_inputs_schema_hash: [u8; 32],
    /// 32-byte domain-separated commitment of the verifying key bytes and backend.
    #[norito(
        with = "crate::json_helpers::fixed_bytes",
        bounded_with = "crate::json_helpers::fixed_bytes::serialize_bounded"
    )]
    pub commitment: [u8; 32],
    /// Length of the verifying key in bytes (if published off-ledger).
    pub vk_len: u32,
    /// Maximum proof byte length accepted when this verifier is active.
    pub max_proof_bytes: u32,
    /// Identifier of the deterministic gas schedule applied to this verifier.
    pub gas_schedule_id: Option<String>,
    /// Optional URI (CID) pointing to metadata describing the verifier.
    pub metadata_uri_cid: Option<String>,
    /// Optional URI (CID) pointing to the verifying key bytes bundle.
    pub vk_bytes_cid: Option<String>,
    /// Block height when the verifier becomes active (inclusive).
    pub activation_height: Option<u64>,
    /// Block height when the verifier is withdrawn and must not be used.
    pub withdraw_height: Option<u64>,
    /// Optional stored verifying key bytes. Some deployments may store only commitments.
    pub key: Option<VerifyingKeyBox>,
    /// Status of the verifying key record.
    pub status: ConfidentialStatus,
}
impl VerifyingKeyRecord {
    /// Create a new verifier record with baseline metadata. Optional fields
    /// default to `None` and can be filled in by governance instructions.
    #[must_use]
    pub fn new(
        version: u32,
        circuit_id: impl Into<String>,
        backend: BackendTag,
        curve: impl Into<String>,
        public_inputs_schema_hash: [u8; 32],
        commitment: [u8; 32],
    ) -> Self {
        Self::new_with_owner(
            version,
            circuit_id,
            None,
            "core",
            backend,
            curve,
            public_inputs_schema_hash,
            commitment,
        )
    }
    /// Create a new verifier record with explicit owner/namespace metadata.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_owner(
        version: u32,
        circuit_id: impl Into<String>,
        owner_manifest_id: Option<String>,
        namespace: impl Into<String>,
        backend: BackendTag,
        curve: impl Into<String>,
        public_inputs_schema_hash: [u8; 32],
        commitment: [u8; 32],
    ) -> Self {
        Self {
            version,
            circuit_id: circuit_id.into(),
            owner_manifest_id,
            namespace: namespace.into(),
            backend,
            curve: curve.into(),
            public_inputs_schema_hash,
            commitment,
            vk_len: 0,
            max_proof_bytes: 0,
            gas_schedule_id: None,
            metadata_uri_cid: None,
            vk_bytes_cid: None,
            activation_height: None,
            withdraw_height: None,
            key: None,
            status: ConfidentialStatus::Proposed,
        }
    }
    /// Returns true if the record is permitted for verification at the current height.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }
    /// Returns true if the record is permitted for verification at `height`.
    #[must_use]
    pub fn is_active_at(&self, height: u64) -> bool {
        self.is_active()
            && self
                .activation_height
                .is_none_or(|activation| height >= activation)
            && self
                .withdraw_height
                .is_none_or(|withdraw| height < withdraw)
    }
}
/// A zero-knowledge proof with the registry reference of its verifying key.
///
/// Instructions embed it directly. A signed transaction carries it wrapped,
/// as the canonical Norito frame inside one signed attachment occurrence
/// (a transaction-level proof carrier).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoSchema)]
#[norito(reuse_archived)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::ProofAttachment")]
pub struct ProofAttachment {
    /// Identifier of the proof backend/format.
    pub backend: Ident,
    /// Proof payload as produced by the backend.
    pub proof: ProofBox,
    /// Reference to a verifying key stored in WSV.
    pub vk_ref: VerifyingKeyId,
    /// Optional verifying key commitment (32-byte hash of VK bytes under backend).
    /// When present, it can be used for stateless deduplication with the proof hash.
    #[norito(
        with = "crate::json_helpers::fixed_bytes::option",
        bounded_with = "crate::json_helpers::fixed_bytes::option::serialize_bounded"
    )]
    #[norito(required)]
    pub vk_commitment: Option<[u8; 32]>,
    /// Optional hash of the verify envelope payload passed via pointer‑ABI TLV (e.g.,
    /// NoritoBytes(OpenVerifyEnvelope)). When present, it is used to bind the verification inputs
    /// to the transaction `call_hash` in emitted events and audit metadata.
    #[norito(
        with = "crate::json_helpers::fixed_bytes::option",
        bounded_with = "crate::json_helpers::fixed_bytes::option::serialize_bounded"
    )]
    #[norito(required)]
    pub envelope_hash: Option<[u8; 32]>,
    /// Optional lane privacy proof tying this attachment to a Nexus commitment.
    #[norito(required)]
    pub lane_privacy: Option<crate::nexus::LanePrivacyProof>,
}
impl ProofAttachment {
    /// Construct an attachment referencing a verifying key stored in WSV.
    pub fn new_ref(backend: Ident, proof: ProofBox, vk_ref: VerifyingKeyId) -> Self {
        Self {
            backend,
            proof,
            vk_ref,
            vk_commitment: None,
            envelope_hash: None,
            lane_privacy: None,
        }
    }
    fn backend_consistency_error(&self) -> Option<&'static str> {
        if self.proof.backend != self.backend {
            Some("proof.backend")
        } else if self.vk_ref.backend != self.backend {
            Some("vk_ref.backend")
        } else {
            None
        }
    }
    /// Return the first structural field error for this attachment, if any.
    ///
    /// This predicate is intentionally pure and layout-neutral so Norito decoding, JSON decoding,
    /// transaction admission, and SDK callers can enforce the same canonical attachment shape
    /// without changing the wire format.
    #[must_use]
    pub fn structural_error(&self) -> Option<(&'static str, &'static str)> {
        self.backend_consistency_error().map_or_else(
            || self.field_content_error(),
            |field| Some((field, "must match attachment backend")),
        )
    }
    fn field_content_error(&self) -> Option<(&'static str, &'static str)> {
        if self.backend.as_str().trim().is_empty() {
            Some(("backend", "must be non-empty"))
        } else if self.proof.backend.as_str().trim().is_empty() {
            Some(("proof.backend", "must be non-empty"))
        } else if self.vk_ref.backend.as_str().trim().is_empty() {
            Some(("vk_ref.backend", "must be non-empty"))
        } else if self.vk_ref.name.trim().is_empty() {
            Some(("vk_ref.name", "must be non-empty"))
        } else if !self.vk_ref.is_portable_registry_id() {
            Some(("vk_ref", "must use portable registry syntax"))
        } else if self.proof.bytes.is_empty() {
            Some(("proof.bytes", "must be non-empty"))
        } else if self
            .proof
            .canonical_encoded_len_v1()
            .is_none_or(|length| length > PROOF_BOX_MAX_ENCODED_BYTES_V1)
        {
            Some(("proof", "canonical encoding exceeds the 64 MiB limit"))
        } else if self
            .vk_commitment
            .is_some_and(|commitment| commitment.iter().all(|byte| *byte == 0))
        {
            Some(("vk_commitment", "must be non-zero"))
        } else if self
            .envelope_hash
            .is_some_and(|hash| hash.iter().all(|byte| *byte == 0))
        {
            Some(("envelope_hash", "must be non-zero"))
        } else if self.envelope_hash.is_some_and(|hash| {
            let expected: [u8; 32] = iroha_crypto::Hash::new(&self.proof.bytes).into();
            hash != expected
        }) {
            Some(("envelope_hash", "must match proof bytes"))
        } else if self
            .lane_privacy
            .as_ref()
            .is_some_and(|proof| proof.validate_structure_v1().is_err())
        {
            Some((
                "lane_privacy",
                "must be a complete canonical bounded Merkle witness",
            ))
        } else {
            None
        }
    }
}

const PROOF_ATTACHMENT_JSON_HASH_LITERAL_BYTES_V1: usize = 74;

fn proof_attachment_json_value_invalid(
    field: &'static str,
    message: &'static str,
) -> norito::json::Error {
    norito::json::Error::InvalidField {
        field: field.into(),
        message: message.into(),
    }
}

fn proof_attachment_json_value_object<'a>(
    value: &'a norito::json::Value,
    field: &'static str,
) -> Result<&'a norito::json::Map, norito::json::Error> {
    value
        .as_object()
        .ok_or_else(|| proof_attachment_json_value_invalid(field, "expected object"))
}

fn proof_attachment_json_value_exact_fields(
    object: &norito::json::Map,
    allowed: &[&str],
    field: &'static str,
) -> Result<(), norito::json::Error> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        // Do not copy an attacker-controlled key into the error. The strict
        // streaming pass provides detailed diagnostics after this allocation
        // preflight for values whose shape is safe to serialize.
        return Err(proof_attachment_json_value_invalid(
            field,
            "contains an unknown first-release field",
        ));
    }
    Ok(())
}

fn proof_attachment_json_value_required<'a>(
    object: &'a norito::json::Map,
    field: &'static str,
) -> Result<&'a norito::json::Value, norito::json::Error> {
    object
        .get(field)
        .ok_or_else(|| norito::json::Error::missing_field(field))
}

fn proof_attachment_json_value_string<'a>(
    value: &'a norito::json::Value,
    field: &'static str,
    maximum: usize,
) -> Result<&'a str, norito::json::Error> {
    let value = value
        .as_str()
        .ok_or_else(|| proof_attachment_json_value_invalid(field, "expected string"))?;
    if value.len() > maximum {
        return Err(proof_attachment_json_value_invalid(
            field,
            "string exceeds its first-release byte limit",
        ));
    }
    Ok(value)
}

fn proof_attachment_json_value_u64(
    value: &norito::json::Value,
    field: &'static str,
    maximum: u64,
) -> Result<u64, norito::json::Error> {
    let value = value
        .as_u64()
        .filter(|value| *value <= maximum)
        .ok_or_else(|| {
            proof_attachment_json_value_invalid(field, "expected bounded unsigned integer")
        })?;
    Ok(value)
}

fn proof_attachment_json_value_byte_array(
    value: &norito::json::Value,
    field: &'static str,
    exact_length: Option<usize>,
    maximum_length: usize,
) -> Result<(), norito::json::Error> {
    let values = value
        .as_array()
        .ok_or_else(|| proof_attachment_json_value_invalid(field, "expected byte array"))?;
    if values.len() > maximum_length || exact_length.is_some_and(|length| values.len() != length) {
        return Err(proof_attachment_json_value_invalid(
            field,
            "byte array has a non-canonical length",
        ));
    }
    if values.iter().any(|value| {
        value
            .as_u64()
            .is_none_or(|value| value > u64::from(u8::MAX))
    }) {
        return Err(proof_attachment_json_value_invalid(
            field,
            "byte array contains a value outside u8",
        ));
    }
    Ok(())
}

fn proof_attachment_json_value_preflight_lane(
    value: &norito::json::Value,
) -> Result<(), norito::json::Error> {
    let lane = proof_attachment_json_value_object(value, "lane_privacy")?;
    proof_attachment_json_value_exact_fields(lane, &["commitment_id", "witness"], "lane_privacy")?;
    let commitment_id = proof_attachment_json_value_required(lane, "commitment_id")?
        .as_array()
        .ok_or_else(|| {
            proof_attachment_json_value_invalid(
                "lane_privacy.commitment_id",
                "expected one-element tuple",
            )
        })?;
    if commitment_id.len() != 1 {
        return Err(proof_attachment_json_value_invalid(
            "lane_privacy.commitment_id",
            "expected one-element tuple",
        ));
    }
    proof_attachment_json_value_u64(
        &commitment_id[0],
        "lane_privacy.commitment_id",
        u64::from(u16::MAX),
    )?;
    let witness = proof_attachment_json_value_object(
        proof_attachment_json_value_required(lane, "witness")?,
        "lane_privacy.witness",
    )?;
    proof_attachment_json_value_exact_fields(
        witness,
        &["kind", "payload"],
        "lane_privacy.witness",
    )?;
    proof_attachment_json_value_string(
        proof_attachment_json_value_required(witness, "kind")?,
        "lane_privacy.witness.kind",
        16,
    )?;
    let payload = proof_attachment_json_value_object(
        proof_attachment_json_value_required(witness, "payload")?,
        "lane_privacy.witness.payload",
    )?;
    proof_attachment_json_value_exact_fields(
        payload,
        &["leaf", "proof"],
        "lane_privacy.witness.payload",
    )?;
    proof_attachment_json_value_byte_array(
        proof_attachment_json_value_required(payload, "leaf")?,
        "lane_privacy.witness.payload.leaf",
        Some(32),
        32,
    )?;
    let proof = proof_attachment_json_value_object(
        proof_attachment_json_value_required(payload, "proof")?,
        "lane_privacy.witness.payload.proof",
    )?;
    proof_attachment_json_value_exact_fields(
        proof,
        &["leaf_index", "audit_path"],
        "lane_privacy.witness.payload.proof",
    )?;
    proof_attachment_json_value_u64(
        proof_attachment_json_value_required(proof, "leaf_index")?,
        "lane_privacy.witness.payload.proof.leaf_index",
        u64::from(u32::MAX),
    )?;
    let audit_path = proof_attachment_json_value_required(proof, "audit_path")?
        .as_array()
        .ok_or_else(|| {
            proof_attachment_json_value_invalid(
                "lane_privacy.witness.payload.proof.audit_path",
                "expected array",
            )
        })?;
    if audit_path.is_empty() || audit_path.len() > crate::nexus::LANE_PRIVACY_MAX_MERKLE_DEPTH_V1 {
        return Err(proof_attachment_json_value_invalid(
            "lane_privacy.witness.payload.proof.audit_path",
            "Merkle path has a non-canonical depth",
        ));
    }
    for sibling in audit_path {
        proof_attachment_json_value_string(
            sibling,
            "lane_privacy.witness.payload.proof.audit_path",
            PROOF_ATTACHMENT_JSON_HASH_LITERAL_BYTES_V1,
        )?;
    }
    Ok(())
}

fn proof_attachment_json_value_preflight<const MAX_PROOF_BYTES: usize>(
    value: &norito::json::Value,
) -> Result<(), norito::json::Error> {
    let attachment = proof_attachment_json_value_object(value, "ProofAttachment")?;
    proof_attachment_json_value_exact_fields(
        attachment,
        &[
            "backend",
            "proof",
            "vk_ref",
            "vk_commitment",
            "envelope_hash",
            "lane_privacy",
        ],
        "ProofAttachment",
    )?;
    proof_attachment_json_value_string(
        proof_attachment_json_value_required(attachment, "backend")?,
        "backend",
        VERIFYING_KEY_ID_MAX_FIELD_BYTES,
    )?;
    let proof = proof_attachment_json_value_object(
        proof_attachment_json_value_required(attachment, "proof")?,
        "proof",
    )?;
    proof_attachment_json_value_exact_fields(proof, &["backend", "bytes"], "proof")?;
    let proof_backend = proof_attachment_json_value_string(
        proof_attachment_json_value_required(proof, "backend")?,
        "proof.backend",
        VERIFYING_KEY_ID_MAX_FIELD_BYTES,
    )?;
    let maximum_proof_bytes = proof_box_max_proof_bytes_v1(proof_backend)
        .ok_or_else(|| {
            proof_attachment_json_value_invalid(
                "proof.backend",
                "backend framing exceeds the ProofBox limit",
            )
        })?
        .min(MAX_PROOF_BYTES);
    proof_attachment_json_value_byte_array(
        proof_attachment_json_value_required(proof, "bytes")?,
        "proof.bytes",
        None,
        maximum_proof_bytes,
    )?;
    let vk_ref = proof_attachment_json_value_object(
        proof_attachment_json_value_required(attachment, "vk_ref")?,
        "vk_ref",
    )?;
    proof_attachment_json_value_exact_fields(vk_ref, &["backend", "name"], "vk_ref")?;
    for field in ["backend", "name"] {
        proof_attachment_json_value_string(
            proof_attachment_json_value_required(vk_ref, field)?,
            if field == "backend" {
                "vk_ref.backend"
            } else {
                "vk_ref.name"
            },
            VERIFYING_KEY_ID_MAX_FIELD_BYTES,
        )?;
    }
    for field in ["vk_commitment", "envelope_hash"] {
        let value = proof_attachment_json_value_required(attachment, field)?;
        if !value.is_null() {
            proof_attachment_json_value_byte_array(value, field, Some(32), 32)?;
        }
    }
    let lane_privacy = proof_attachment_json_value_required(attachment, "lane_privacy")?;
    if !lane_privacy.is_null() {
        proof_attachment_json_value_preflight_lane(lane_privacy)?;
    }
    Ok(())
}

fn proof_attachment_json_mark_field(
    seen: &mut u8,
    field_bit: u8,
    field: &str,
) -> Result<(), norito::json::Error> {
    if *seen & field_bit != 0 {
        return Err(norito::json::Error::duplicate_field(field));
    }
    *seen |= field_bit;
    Ok(())
}

fn proof_attachment_json_unknown_field(field: &str, parent: &str) -> norito::json::Error {
    let qualified = if parent.is_empty() {
        field.to_owned()
    } else {
        format!("{parent}.{field}")
    };
    if matches!(
        field,
        "vk_inline" | "vkInline" | "verifyingKeyInline" | "verifying_key_inline"
    ) {
        norito::json::Error::InvalidField {
            field: qualified,
            message: "retired inline verifying-key field is not supported; use vk_ref".into(),
        }
    } else {
        norito::json::Error::InvalidField {
            field: qualified,
            message: "unknown fields are not part of the first-release schema".into(),
        }
    }
}
/// A string whose exact decoded UTF-8 length is bounded before an owned allocation is created.
struct ProofAttachmentJsonBoundedStringV1<const MAX: usize>(String);

impl<const MAX: usize> norito::json::JsonDeserialize for ProofAttachmentJsonBoundedStringV1<MAX> {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let mut probe = *parser;
        probe.skip_string_bounded(MAX)?;
        let value = String::json_deserialize(parser)?;
        if value.len() > MAX {
            return Err(norito::json::Error::Message(format!(
                "proof attachment string exceeds the {MAX}-byte decoded limit"
            )));
        }
        Ok(Self(value))
    }
}

struct ProofAttachmentJsonBytes32V1([u8; 32]);

impl norito::json::JsonDeserialize for ProofAttachmentJsonBytes32V1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let mut sequence = norito::json::SeqVisitor::new(parser)?;
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let raw = sequence.next_element::<u64>()?.ok_or_else(|| {
                norito::json::Error::Message(format!("expected 32 bytes, got {index}"))
            })?;
            *byte = u8::try_from(raw).map_err(|_| norito::json::Error::InvalidField {
                field: "byte array".into(),
                message: format!("byte at index {index} is not a valid u8"),
            })?;
        }
        if !sequence.is_finished() {
            return Err(norito::json::Error::Message(
                "expected exactly 32 bytes".into(),
            ));
        }
        sequence.finish()?;
        Ok(Self(bytes))
    }
}
/// Streaming byte-array decoder used for proof payloads. The length check is
/// performed before reserving or pushing the next byte, so an over-limit
/// element can never grow the output allocation.
struct ProofAttachmentJsonBoundedBytesVisitorV1 {
    maximum: usize,
}

impl ProofAttachmentJsonBoundedBytesVisitorV1 {
    fn expected_array() -> norito::json::Error {
        norito::json::Error::InvalidField {
            field: "proof.bytes".into(),
            message: "expected a JSON byte array".into(),
        }
    }
}

impl<'a> norito::json::Visitor<'a> for ProofAttachmentJsonBoundedBytesVisitorV1 {
    type Value = Vec<u8>;
    fn visit_null(self) -> Result<Self::Value, norito::json::Error> {
        Err(Self::expected_array())
    }
    fn visit_bool(self, _value: bool) -> Result<Self::Value, norito::json::Error> {
        Err(Self::expected_array())
    }
    fn visit_i64(self, _value: i64) -> Result<Self::Value, norito::json::Error> {
        Err(Self::expected_array())
    }
    fn visit_u64(self, _value: u64) -> Result<Self::Value, norito::json::Error> {
        Err(Self::expected_array())
    }
    fn visit_f64(self, _value: f64) -> Result<Self::Value, norito::json::Error> {
        Err(Self::expected_array())
    }
    fn visit_string(self, _value: String) -> Result<Self::Value, norito::json::Error> {
        Err(Self::expected_array())
    }
    fn visit_map(
        self,
        _visitor: norito::json::MapVisitor<'a, '_>,
    ) -> Result<Self::Value, norito::json::Error> {
        Err(Self::expected_array())
    }
    fn visit_seq(
        self,
        mut sequence: norito::json::SeqVisitor<'a, '_>,
    ) -> Result<Self::Value, norito::json::Error> {
        let mut bytes = Vec::new();
        while !sequence.is_finished() {
            if bytes.len() == self.maximum {
                return Err(norito::json::Error::Message(format!(
                    "proof bytes exceed the {}-byte streaming limit",
                    self.maximum
                )));
            }
            if bytes.len() == bytes.capacity() {
                let remaining = self.maximum - bytes.len();
                let additional = bytes.capacity().max(4 * 1024).min(remaining);
                bytes.try_reserve_exact(additional).map_err(|_| {
                    norito::json::Error::Message(
                        "unable to reserve bounded proof byte storage".into(),
                    )
                })?;
            }
            let index = bytes.len();
            let raw = sequence
                .next_element::<u64>()?
                .ok_or_else(|| norito::json::Error::Message("expected proof byte".into()))?;
            let byte = u8::try_from(raw).map_err(|_| norito::json::Error::InvalidField {
                field: "proof.bytes".into(),
                message: format!("byte at index {index} is not a valid u8"),
            })?;
            bytes.push(byte);
        }
        sequence.finish()?;
        Ok(bytes)
    }
}

struct ProofAttachmentJsonProofBoxV1<const MAX: usize> {
    backend: String,
    bytes: Vec<u8>,
}

fn proof_attachment_json_probe_proof_backend(
    parser: &norito::json::Parser<'_>,
) -> Result<String, norito::json::Error> {
    let mut probe = *parser;
    let mut object = norito::json::MapVisitor::new(&mut probe)?;
    let mut backend = None;
    while let Some(field) = object.next_key()? {
        if field.as_str() == "backend" {
            if backend.is_some() {
                return Err(norito::json::Error::duplicate_field("backend"));
            }
            backend = Some(
                object
                    .parse_value::<ProofAttachmentJsonBoundedStringV1<
                        VERIFYING_KEY_ID_MAX_FIELD_BYTES,
                    >>()?
                    .0,
            );
        } else {
            // This first pass discovers the backend without materializing the
            // potentially enormous numeric proof array. The strict pass below
            // still rejects every unknown or retired member.
            object.skip_value()?;
        }
    }
    object.finish()?;
    backend.ok_or_else(|| norito::json::Error::missing_field("proof.backend"))
}

impl<const MAX: usize> norito::json::JsonDeserialize for ProofAttachmentJsonProofBoxV1<MAX> {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        const BACKEND: u8 = 1 << 0;
        const BYTES: u8 = 1 << 1;
        let probed_backend = proof_attachment_json_probe_proof_backend(parser)?;
        let maximum_proof_bytes = proof_box_max_proof_bytes_v1(&probed_backend)
            .ok_or_else(|| norito::json::Error::InvalidField {
                field: "proof.backend".into(),
                message: "backend and canonical framing exceed the 64 MiB ProofBox limit".into(),
            })?
            .min(MAX);
        let mut object = norito::json::MapVisitor::new(parser)?;
        let mut seen = 0_u8;
        let mut backend = None;
        let mut bytes = None;
        while let Some(field) = object.next_key()? {
            match field.as_str() {
                "backend" => {
                    proof_attachment_json_mark_field(&mut seen, BACKEND, "backend")?;
                    backend =
                        Some(
                            object
                                .parse_value::<ProofAttachmentJsonBoundedStringV1<
                                    VERIFYING_KEY_ID_MAX_FIELD_BYTES,
                                >>()?
                                .0,
                        );
                }
                "bytes" => {
                    proof_attachment_json_mark_field(&mut seen, BYTES, "bytes")?;
                    object.parser().skip_ws();
                    if object.parser().peek() != Some(b'[') {
                        return Err(ProofAttachmentJsonBoundedBytesVisitorV1::expected_array());
                    }
                    bytes = Some(object.parse_value_with(
                        ProofAttachmentJsonBoundedBytesVisitorV1 {
                            maximum: maximum_proof_bytes,
                        },
                    )?);
                }
                field => return Err(proof_attachment_json_unknown_field(field, "proof")),
            }
        }
        object.finish()?;
        let backend = backend.ok_or_else(|| norito::json::Error::missing_field("proof.backend"))?;
        let bytes = bytes.ok_or_else(|| norito::json::Error::missing_field("proof.bytes"))?;
        if backend != probed_backend {
            return Err(norito::json::Error::InvalidField {
                field: "proof.backend".into(),
                message: "backend changed between bounded parser passes".into(),
            });
        }
        Ok(Self { backend, bytes })
    }
}

struct ProofAttachmentJsonVerifyingKeyRefV1 {
    backend: String,
    name: String,
}

impl norito::json::JsonDeserialize for ProofAttachmentJsonVerifyingKeyRefV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        const BACKEND: u8 = 1 << 0;
        const NAME: u8 = 1 << 1;
        let mut object = norito::json::MapVisitor::new(parser)?;
        let mut seen = 0_u8;
        let mut backend = None;
        let mut name = None;
        while let Some(field) = object.next_key()? {
            match field.as_str() {
                "backend" => {
                    proof_attachment_json_mark_field(&mut seen, BACKEND, "backend")?;
                    backend =
                        Some(
                            object
                                .parse_value::<ProofAttachmentJsonBoundedStringV1<
                                    VERIFYING_KEY_ID_MAX_FIELD_BYTES,
                                >>()?
                                .0,
                        );
                }
                "name" => {
                    proof_attachment_json_mark_field(&mut seen, NAME, "name")?;
                    name =
                        Some(
                            object
                                .parse_value::<ProofAttachmentJsonBoundedStringV1<
                                    VERIFYING_KEY_ID_MAX_FIELD_BYTES,
                                >>()?
                                .0,
                        );
                }
                field => return Err(proof_attachment_json_unknown_field(field, "vk_ref")),
            }
        }
        object.finish()?;
        Ok(Self {
            backend: backend.ok_or_else(|| norito::json::Error::missing_field("vk_ref.backend"))?,
            name: name.ok_or_else(|| norito::json::Error::missing_field("vk_ref.name"))?,
        })
    }
}

struct ProofAttachmentJsonLaneCommitmentIdV1(u16);

impl norito::json::JsonDeserialize for ProofAttachmentJsonLaneCommitmentIdV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let mut sequence = norito::json::SeqVisitor::new(parser)?;
        let commitment_id =
            sequence
                .next_element::<u16>()?
                .ok_or_else(|| norito::json::Error::InvalidField {
                    field: "lane_privacy.commitment_id".into(),
                    message: "expected one-element lane commitment tuple".into(),
                })?;
        if !sequence.is_finished() {
            return Err(norito::json::Error::InvalidField {
                field: "lane_privacy.commitment_id".into(),
                message: "expected one-element lane commitment tuple".into(),
            });
        }
        sequence.finish()?;
        Ok(Self(commitment_id))
    }
}

struct ProofAttachmentJsonMerkleSiblingV1([u8; 32]);

impl norito::json::JsonDeserialize for ProofAttachmentJsonMerkleSiblingV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        parser.skip_ws();
        if parser.peek() != Some(b'"') {
            return Err(norito::json::Error::InvalidField {
                field: "lane_privacy.witness.payload.proof.audit_path".into(),
                message: "expected a canonical hash literal for every Merkle sibling".into(),
            });
        }
        // `hash:` + 64 hex digits + `#` + four checksum digits.
        let literal = ProofAttachmentJsonBoundedStringV1::<
            PROOF_ATTACHMENT_JSON_HASH_LITERAL_BYTES_V1,
        >::json_deserialize(parser)?
        .0;
        let body = norito::literal::parse("hash", &literal).map_err(|error| {
            norito::json::Error::InvalidField {
                field: "lane_privacy.witness.payload.proof.audit_path".into(),
                message: error.to_string(),
            }
        })?;
        if body.bytes().any(|byte| byte.is_ascii_lowercase()) {
            return Err(norito::json::Error::InvalidField {
                field: "lane_privacy.witness.payload.proof.audit_path".into(),
                message: "canonical hash literals must use uppercase hex digits".into(),
            });
        }
        let hash = body.parse::<iroha_crypto::Hash>().map_err(|error| {
            norito::json::Error::InvalidField {
                field: "lane_privacy.witness.payload.proof.audit_path".into(),
                message: error.to_string(),
            }
        })?;
        let bytes: [u8; 32] = *hash.as_ref();
        if bytes[31] & 1 == 0 {
            return Err(norito::json::Error::InvalidField {
                field: "lane_privacy.witness.payload.proof.audit_path".into(),
                message: "Merkle sibling is not canonically pre-hashed".into(),
            });
        }
        Ok(Self(bytes))
    }
}

struct ProofAttachmentJsonAuditPathV1<const MAX: usize>(Vec<[u8; 32]>);

impl<const MAX: usize> norito::json::JsonDeserialize for ProofAttachmentJsonAuditPathV1<MAX> {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let mut sequence = norito::json::SeqVisitor::new(parser)?;
        let mut path = Vec::with_capacity(MAX.min(32));
        while !sequence.is_finished() {
            if path.len() == MAX {
                return Err(norito::json::Error::InvalidField {
                    field: "lane_privacy.witness.payload.proof.audit_path".into(),
                    message: format!("Merkle path exceeds the {MAX}-sibling limit"),
                });
            }
            let sibling = sequence
                .next_element::<ProofAttachmentJsonMerkleSiblingV1>()?
                .ok_or_else(|| norito::json::Error::Message("expected Merkle sibling".into()))?;
            path.push(sibling.0);
        }
        sequence.finish()?;
        if path.is_empty() {
            return Err(norito::json::Error::InvalidField {
                field: "lane_privacy.witness.payload.proof.audit_path".into(),
                message: "Merkle path must not be empty".into(),
            });
        }
        Ok(Self(path))
    }
}

struct ProofAttachmentJsonLaneMerkleProofV1 {
    leaf_index: u32,
    audit_path: ProofAttachmentJsonAuditPathV1<{ crate::nexus::LANE_PRIVACY_MAX_MERKLE_DEPTH_V1 }>,
}

impl norito::json::JsonDeserialize for ProofAttachmentJsonLaneMerkleProofV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        const LEAF_INDEX: u8 = 1 << 0;
        const AUDIT_PATH: u8 = 1 << 1;
        let mut object = norito::json::MapVisitor::new(parser)?;
        let mut seen = 0_u8;
        let mut leaf_index = None;
        let mut audit_path = None;
        while let Some(field) = object.next_key()? {
            match field.as_str() {
                "leaf_index" => {
                    proof_attachment_json_mark_field(&mut seen, LEAF_INDEX, "leaf_index")?;
                    leaf_index = Some(object.parse_value::<u32>()?);
                }
                "audit_path" => {
                    proof_attachment_json_mark_field(&mut seen, AUDIT_PATH, "audit_path")?;
                    audit_path = Some(object.parse_value::<ProofAttachmentJsonAuditPathV1<
                        { crate::nexus::LANE_PRIVACY_MAX_MERKLE_DEPTH_V1 },
                    >>()?);
                }
                field => {
                    return Err(proof_attachment_json_unknown_field(
                        field,
                        "lane_privacy.witness.payload.proof",
                    ));
                }
            }
        }
        object.finish()?;
        Ok(Self {
            leaf_index: leaf_index.ok_or_else(|| {
                norito::json::Error::missing_field("lane_privacy.witness.payload.proof.leaf_index")
            })?,
            audit_path: audit_path.ok_or_else(|| {
                norito::json::Error::missing_field("lane_privacy.witness.payload.proof.audit_path")
            })?,
        })
    }
}

struct ProofAttachmentJsonLaneMerklePayloadV1 {
    leaf: [u8; 32],
    proof: ProofAttachmentJsonLaneMerkleProofV1,
}

impl norito::json::JsonDeserialize for ProofAttachmentJsonLaneMerklePayloadV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        const LEAF: u8 = 1 << 0;
        const PROOF: u8 = 1 << 1;
        let mut object = norito::json::MapVisitor::new(parser)?;
        let mut seen = 0_u8;
        let mut leaf = None;
        let mut proof = None;
        while let Some(field) = object.next_key()? {
            match field.as_str() {
                "leaf" => {
                    proof_attachment_json_mark_field(&mut seen, LEAF, "leaf")?;
                    leaf = Some(object.parse_value::<ProofAttachmentJsonBytes32V1>()?.0);
                }
                "proof" => {
                    proof_attachment_json_mark_field(&mut seen, PROOF, "proof")?;
                    proof = Some(object.parse_value::<ProofAttachmentJsonLaneMerkleProofV1>()?);
                }
                field => {
                    return Err(proof_attachment_json_unknown_field(
                        field,
                        "lane_privacy.witness.payload",
                    ));
                }
            }
        }
        object.finish()?;
        Ok(Self {
            leaf: leaf.ok_or_else(|| {
                norito::json::Error::missing_field("lane_privacy.witness.payload.leaf")
            })?,
            proof: proof.ok_or_else(|| {
                norito::json::Error::missing_field("lane_privacy.witness.payload.proof")
            })?,
        })
    }
}

struct ProofAttachmentJsonLaneWitnessV1 {
    kind: String,
    payload: ProofAttachmentJsonLaneMerklePayloadV1,
}

impl norito::json::JsonDeserialize for ProofAttachmentJsonLaneWitnessV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        const KIND: u8 = 1 << 0;
        const PAYLOAD: u8 = 1 << 1;
        let mut object = norito::json::MapVisitor::new(parser)?;
        let mut seen = 0_u8;
        let mut kind = None;
        let mut payload = None;
        while let Some(field) = object.next_key()? {
            match field.as_str() {
                "kind" => {
                    proof_attachment_json_mark_field(&mut seen, KIND, "kind")?;
                    kind = Some(
                        object
                            .parse_value::<ProofAttachmentJsonBoundedStringV1<16>>()?
                            .0,
                    );
                }
                "payload" => {
                    proof_attachment_json_mark_field(&mut seen, PAYLOAD, "payload")?;
                    payload = Some(object.parse_value::<ProofAttachmentJsonLaneMerklePayloadV1>()?);
                }
                field => {
                    return Err(proof_attachment_json_unknown_field(
                        field,
                        "lane_privacy.witness",
                    ));
                }
            }
        }
        object.finish()?;
        Ok(Self {
            kind: kind
                .ok_or_else(|| norito::json::Error::missing_field("lane_privacy.witness.kind"))?,
            payload: payload.ok_or_else(|| {
                norito::json::Error::missing_field("lane_privacy.witness.payload")
            })?,
        })
    }
}

struct ProofAttachmentJsonLanePrivacyV1 {
    commitment_id: u16,
    witness: ProofAttachmentJsonLaneWitnessV1,
}

impl norito::json::JsonDeserialize for ProofAttachmentJsonLanePrivacyV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        const COMMITMENT_ID: u8 = 1 << 0;
        const WITNESS: u8 = 1 << 1;
        let mut object = norito::json::MapVisitor::new(parser)?;
        let mut seen = 0_u8;
        let mut commitment_id = None;
        let mut witness = None;
        while let Some(field) = object.next_key()? {
            match field.as_str() {
                "commitment_id" => {
                    proof_attachment_json_mark_field(&mut seen, COMMITMENT_ID, "commitment_id")?;
                    commitment_id = Some(
                        object
                            .parse_value::<ProofAttachmentJsonLaneCommitmentIdV1>()?
                            .0,
                    );
                }
                "witness" => {
                    proof_attachment_json_mark_field(&mut seen, WITNESS, "witness")?;
                    witness = Some(object.parse_value::<ProofAttachmentJsonLaneWitnessV1>()?);
                }
                field => {
                    return Err(proof_attachment_json_unknown_field(field, "lane_privacy"));
                }
            }
        }
        object.finish()?;
        Ok(Self {
            commitment_id: commitment_id
                .ok_or_else(|| norito::json::Error::missing_field("lane_privacy.commitment_id"))?,
            witness: witness
                .ok_or_else(|| norito::json::Error::missing_field("lane_privacy.witness"))?,
        })
    }
}

impl ProofAttachmentJsonLanePrivacyV1 {
    fn into_lane_privacy_proof(
        self,
    ) -> Result<crate::nexus::LanePrivacyProof, norito::json::Error> {
        if self.witness.kind != "merkle" {
            return Err(norito::json::Error::InvalidField {
                field: "lane_privacy.witness.kind".into(),
                message: "only the canonical merkle witness is supported".into(),
            });
        }
        let ProofAttachmentJsonLaneMerklePayloadV1 { leaf, proof } = self.witness.payload;
        let ProofAttachmentJsonLaneMerkleProofV1 {
            leaf_index,
            audit_path,
        } = proof;
        crate::nexus::LanePrivacyProof::merkle_from_raw_path(
            iroha_crypto::LaneCommitmentId::new(self.commitment_id),
            leaf,
            leaf_index,
            audit_path.0.into_iter().map(Some).collect(),
        )
        .map_err(|error| norito::json::Error::InvalidField {
            field: "lane_privacy".into(),
            message: error.to_string(),
        })
    }
}

impl norito::json::JsonDeserialize for ProofAttachment {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        const BACKEND: u8 = 1 << 0;
        const PROOF: u8 = 1 << 1;
        const VK_REF: u8 = 1 << 2;
        const VK_COMMITMENT: u8 = 1 << 3;
        const ENVELOPE_HASH: u8 = 1 << 4;
        const LANE_PRIVACY: u8 = 1 << 5;
        let mut object = norito::json::MapVisitor::new(parser)?;
        let mut seen = 0_u8;
        let mut backend = None;
        let mut proof = None;
        let mut vk_ref = None;
        let mut vk_commitment = None;
        let mut envelope_hash = None;
        let mut lane_privacy = None;
        while let Some(field) = object.next_key()? {
            match field.as_str() {
                "backend" => {
                    proof_attachment_json_mark_field(&mut seen, BACKEND, "backend")?;
                    backend =
                        Some(
                            object
                                .parse_value::<ProofAttachmentJsonBoundedStringV1<
                                    VERIFYING_KEY_ID_MAX_FIELD_BYTES,
                                >>()?
                                .0,
                        );
                }
                "proof" => {
                    proof_attachment_json_mark_field(&mut seen, PROOF, "proof")?;
                    proof = Some(object.parse_value::<ProofAttachmentJsonProofBoxV1<
                        PROOF_BOX_MAX_ENCODED_BYTES_V1,
                    >>()?);
                }
                "vk_ref" => {
                    proof_attachment_json_mark_field(&mut seen, VK_REF, "vk_ref")?;
                    vk_ref = Some(object.parse_value::<ProofAttachmentJsonVerifyingKeyRefV1>()?);
                }
                "vk_commitment" => {
                    proof_attachment_json_mark_field(&mut seen, VK_COMMITMENT, "vk_commitment")?;
                    vk_commitment = object
                        .parse_value::<Option<ProofAttachmentJsonBytes32V1>>()?
                        .map(|value| value.0);
                }
                "envelope_hash" => {
                    proof_attachment_json_mark_field(&mut seen, ENVELOPE_HASH, "envelope_hash")?;
                    envelope_hash = object
                        .parse_value::<Option<ProofAttachmentJsonBytes32V1>>()?
                        .map(|value| value.0);
                }
                "lane_privacy" => {
                    proof_attachment_json_mark_field(&mut seen, LANE_PRIVACY, "lane_privacy")?;
                    lane_privacy =
                        object.parse_value::<Option<ProofAttachmentJsonLanePrivacyV1>>()?;
                }
                field => return Err(proof_attachment_json_unknown_field(field, "")),
            }
        }
        object.finish()?;
        for (field_bit, field) in [
            (BACKEND, "backend"),
            (PROOF, "proof"),
            (VK_REF, "vk_ref"),
            (VK_COMMITMENT, "vk_commitment"),
            (ENVELOPE_HASH, "envelope_hash"),
            (LANE_PRIVACY, "lane_privacy"),
        ] {
            if seen & field_bit == 0 {
                return Err(norito::json::Error::missing_field(field));
            }
        }
        let backend = backend.ok_or_else(|| norito::json::Error::missing_field("backend"))?;
        let proof = proof.ok_or_else(|| norito::json::Error::missing_field("proof"))?;
        let vk_ref = vk_ref.ok_or_else(|| norito::json::Error::missing_field("vk_ref"))?;
        let attachment = Self {
            backend,
            proof: ProofBox::new(proof.backend, proof.bytes),
            vk_ref: VerifyingKeyId::new(vk_ref.backend, vk_ref.name),
            vk_commitment,
            envelope_hash,
            lane_privacy: lane_privacy
                .map(ProofAttachmentJsonLanePrivacyV1::into_lane_privacy_proof)
                .transpose()?,
        };
        if let Some((field, message)) = attachment.structural_error() {
            return Err(norito::json::Error::InvalidField {
                field: field.into(),
                message: message.into(),
            });
        }
        Ok(attachment)
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        // A Value supplied by an API caller already owns its storage. Walk it
        // by reference first so hostile oversized fields cannot trigger the
        // additional canonical JSON allocation used to re-enter the one true
        // streaming decoder below.
        proof_attachment_json_value_preflight::<PROOF_BOX_MAX_ENCODED_BYTES_V1>(value)?;
        let canonical_json = norito::json::to_json(value)?;
        norito::json::from_str(&canonical_json)
    }
}

impl norito::SerializePayload for ProofAttachment {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        ncore::write_len_prefixed(writer, &self.backend)?;
        ncore::write_len_prefixed(writer, &self.proof)?;
        ncore::write_len_prefixed(writer, &self.vk_ref)?;
        // Omit trailing default fields to keep payloads compact and deterministic.
        let tail = if self.lane_privacy.is_some() {
            3
        } else if self.envelope_hash.is_some() {
            2
        } else {
            i32::from(self.vk_commitment.is_some())
        };
        if tail >= 1 {
            ncore::write_len_prefixed(writer, &self.vk_commitment)?;
        }
        if tail >= 2 {
            ncore::write_len_prefixed(writer, &self.envelope_hash)?;
        }
        if tail >= 3 {
            ncore::write_len_prefixed(writer, &self.lane_privacy)?;
        }
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.encoded_len_exact()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        fn add_field<T: norito::NoritoSerialize>(total: &mut usize, value: &T) -> Option<()> {
            let field_len = value.encoded_len_exact()?;
            *total = total
                .checked_add(ncore::len_prefix_len(field_len))?
                .checked_add(field_len)?;
            Some(())
        }
        let mut total = 0_usize;
        add_field(&mut total, &self.backend)?;
        add_field(&mut total, &self.proof)?;
        add_field(&mut total, &self.vk_ref)?;
        let tail = if self.lane_privacy.is_some() {
            3
        } else if self.envelope_hash.is_some() {
            2
        } else {
            usize::from(self.vk_commitment.is_some())
        };
        if tail >= 1 {
            add_field(&mut total, &self.vk_commitment)?;
        }
        if tail >= 2 {
            add_field(&mut total, &self.envelope_hash)?;
        }
        if tail >= 3 {
            add_field(&mut total, &self.lane_privacy)?;
        }
        Some(total)
    }
}

impl<'de> norito::DeserializePayload<'de> for ProofAttachment {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("ProofAttachment deserialization must succeed for canonical archives")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        let (value, used) = <Self as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
        if norito::debug_trace_enabled() {
            eprintln!(
                "ProofAttachment::try_deserialize consumed {used} of {} bytes",
                bytes.len()
            );
        }
        if used != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        Ok(value)
    }
}
impl<'a> ncore::DecodeFromSlice<'a> for ProofAttachment {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let mut offset = 0usize;
        let backend_bytes = take_len_prefixed_slice(bytes, &mut offset, MAX_BACKEND_FIELD_BYTES)?;
        let (backend, used) = <Ident as ncore::DecodeFromSlice>::decode_from_slice(backend_bytes)?;
        if used != backend_bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        let proof_slice =
            take_len_prefixed_slice(bytes, &mut offset, MAX_LEN_PREFIXED_FIELD_BYTES)?;
        let (proof, used) = <ProofBox as ncore::DecodeFromSlice>::decode_from_slice(proof_slice)?;
        if used != proof_slice.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        let vk_ref_slice = take_len_prefixed_slice(bytes, &mut offset, MAX_REF_FIELD_BYTES)?;
        let (vk_ref, used) =
            <VerifyingKeyId as ncore::DecodeFromSlice>::decode_from_slice(vk_ref_slice)?;
        if used != vk_ref_slice.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        // Optional fields may be omitted in compact payloads; treat missing tail as `None`.
        let mut present_tail_fields = 0_usize;
        let vk_commitment = if offset == bytes.len() {
            None
        } else {
            present_tail_fields = 1;
            let slice = take_len_prefixed_slice(bytes, &mut offset, MAX_REF_FIELD_BYTES)?;
            let (value, used) =
                <Option<[u8; 32]> as ncore::DecodeFromSlice>::decode_from_slice(slice)?;
            if used != slice.len() {
                return Err(ncore::Error::LengthMismatch);
            }
            value
        };
        let envelope_hash = if offset == bytes.len() {
            None
        } else {
            present_tail_fields = 2;
            let slice = take_len_prefixed_slice(bytes, &mut offset, MAX_REF_FIELD_BYTES)?;
            let (value, used) =
                <Option<[u8; 32]> as ncore::DecodeFromSlice>::decode_from_slice(slice)?;
            if used != slice.len() {
                return Err(ncore::Error::LengthMismatch);
            }
            value
        };
        let lane_privacy = if offset == bytes.len() {
            None
        } else {
            present_tail_fields = 3;
            let slice = take_len_prefixed_slice(bytes, &mut offset, MAX_LEN_PREFIXED_FIELD_BYTES)?;
            let (value, used) =
                <Option<crate::nexus::LanePrivacyProof> as ncore::DecodeFromSlice>::decode_from_slice(
                    slice,
                )?;
            if used != slice.len() {
                return Err(ncore::Error::LengthMismatch);
            }
            value
        };
        if offset != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        let canonical_tail_fields = if lane_privacy.is_some() {
            3
        } else if envelope_hash.is_some() {
            2
        } else {
            usize::from(vk_commitment.is_some())
        };
        if present_tail_fields != canonical_tail_fields {
            return Err(ncore::Error::Message(
                "non-canonical redundant ProofAttachment optional tail".into(),
            ));
        }
        let attachment = Self {
            backend,
            proof,
            vk_ref,
            vk_commitment,
            envelope_hash,
            lane_privacy,
        };
        if let Some((field, message)) = attachment.structural_error() {
            return Err(ncore::Error::Message(format!("{field} {message}")));
        }
        Ok((attachment, offset))
    }
}
/// Maximum complete canonical Norito frame for a first-release proof attachment list.
///
/// The list is the body format of Torii's non-consensus prover API and a
/// staging container of SDK builders. It is not a signed-transaction field: a
/// transaction carries proofs as signed attachment occurrences
/// ([`crate::transaction::signed_attachments::SignedAttachmentsV1`]), whose
/// frame bound admits a ceiling-sized proof. This intrinsic 8 MiB binary
/// ceiling is not a claim that a maximal frame fits Torii's 8 MiB JSON proof
/// body: base64 and JSON quotes expand the transport, whose exact largest
/// decoded binary string at that body limit is 6,291,453 bytes.
pub const PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1: usize = 8 * 1024 * 1024;
/// Maximum attachments carried by one first-release proof attachment list.
///
/// This matches the governed `zk.max_verify_batch` default.
pub const PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1: usize = 16;
#[cfg(test)]
std::thread_local! {
    static PROOF_ATTACHMENT_LIST_AUTHORITATIVE_LENGTH_PASSES: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
/// Failure to construct a bounded first-release proof attachment list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofAttachmentListError {
    /// A present list carries at least one attachment.
    #[error("proof attachment list must not be empty")]
    Empty,
    /// The verifier batch boundary would be exceeded.
    #[error("proof attachment count {actual} exceeds the first-release maximum of {maximum}")]
    TooMany {
        /// Supplied attachment count.
        actual: usize,
        /// First-release maximum.
        maximum: usize,
    },
    /// Canonical length arithmetic or the authoritative counting
    /// serialization pass could not produce a frame length.
    #[error("proof attachment list canonical frame could not be encoded")]
    CanonicalEncodingFailed,
    /// The complete canonical frame would exceed the intrinsic V1 ceiling.
    #[error(
        "proof attachment list canonical frame is {actual} bytes, exceeding the {maximum}-byte first-release maximum"
    )]
    CanonicalFrameTooLarge {
        /// Complete canonical frame size.
        actual: usize,
        /// First-release maximum.
        maximum: usize,
    },
}
/// A bounded list of proof attachments.
///
/// Torii's non-consensus prover API reads this list and SDK builders stage
/// proof attachments in it. A signed transaction does not carry it: each proof
/// attachment travels as one transaction-level carrier of
/// [`crate::transaction::signed_attachments::SignedAttachmentsV1`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoSchema)]
#[norito(reuse_archived)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::ProofAttachmentList")]
pub struct ProofAttachmentList(
    /// Ordered attachments that make up the proof payload.
    Vec<ProofAttachment>,
);
impl ProofAttachmentList {
    fn canonical_frame_len_from_payload_len(payload_len: usize) -> Option<usize> {
        let alignment = ncore::archived_payload_align::<Self>();
        let remainder = ncore::Header::SIZE % alignment;
        let padding = if remainder == 0 {
            0
        } else {
            alignment - remainder
        };
        ncore::Header::SIZE
            .checked_add(padding)?
            .checked_add(payload_len)
    }
    fn canonical_frame_len_v1(&self) -> Result<usize, ProofAttachmentListError> {
        let _canonical_flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
        // `ProofAttachment::serialize` stages nested fields in temporary
        // vectors. Use its allocation-free exact-length arithmetic only as a
        // fail-fast rejection gate so a caller-provided 64 MiB proof cannot
        // make the authoritative pass allocate far beyond this list's 8 MiB
        // ceiling. A value at or below the ceiling is never admitted from the
        // hint: the real counting serializer below remains authoritative.
        let hinted_payload_len = norito::SerializePayload::encoded_len_exact(self)
            .ok_or(ProofAttachmentListError::CanonicalEncodingFailed)?;
        let hinted_frame_len = Self::canonical_frame_len_from_payload_len(hinted_payload_len)
            .ok_or(ProofAttachmentListError::CanonicalEncodingFailed)?;
        if hinted_frame_len > PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1 {
            return Ok(hinted_frame_len);
        }
        #[cfg(test)]
        PROOF_ATTACHMENT_LIST_AUTHORITATIVE_LENGTH_PASSES.with(|passes| {
            passes.set(passes.get().saturating_add(1));
        });
        ncore::encoded_frame_len(self)
            .map_err(|_| ProofAttachmentListError::CanonicalEncodingFailed)
    }
    #[cfg(test)]
    fn reset_authoritative_length_passes_for_current_test_thread() {
        PROOF_ATTACHMENT_LIST_AUTHORITATIVE_LENGTH_PASSES.with(|passes| passes.set(0));
    }
    #[cfg(test)]
    fn authoritative_length_passes_for_current_test_thread() -> usize {
        PROOF_ATTACHMENT_LIST_AUTHORITATIVE_LENGTH_PASSES.with(std::cell::Cell::get)
    }
    /// Borrow the ordered attachments.
    #[must_use]
    pub fn as_slice(&self) -> &[ProofAttachment] {
        &self.0
    }
    /// Return the attachment count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Return the allocated attachment capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }
    /// Return whether this list is empty.
    ///
    /// Valid constructed values always return `false`; the method is provided
    /// for ordinary collection-style inspection.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Consume the wrapper and return its ordered attachments.
    #[must_use]
    pub fn into_vec(self) -> Vec<ProofAttachment> {
        self.0
    }
    /// Append one attachment while preserving the first-release count and canonical-frame bounds.
    ///
    /// The list is left unchanged when the appended value would violate an invariant.
    ///
    /// # Errors
    ///
    /// Returns [`ProofAttachmentListError`] when the attachment count or the
    /// canonical encoded frame would exceed its first-release bound.
    pub fn try_push(
        &mut self,
        attachment: ProofAttachment,
    ) -> Result<(), ProofAttachmentListError> {
        if self.0.len() >= PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 {
            return Err(ProofAttachmentListError::TooMany {
                actual: self.0.len().saturating_add(1),
                maximum: PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1,
            });
        }
        self.0.push(attachment);
        let validation = match self.canonical_frame_len_v1() {
            Ok(canonical_frame_len)
                if canonical_frame_len <= PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1 =>
            {
                Ok(())
            }
            Ok(canonical_frame_len) => Err(ProofAttachmentListError::CanonicalFrameTooLarge {
                actual: canonical_frame_len,
                maximum: PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
            }),
            Err(error) => Err(error),
        };
        if validation.is_err() {
            let _ = self.0.pop();
        }
        validation
    }
}
impl TryFrom<Vec<ProofAttachment>> for ProofAttachmentList {
    type Error = ProofAttachmentListError;
    fn try_from(attachments: Vec<ProofAttachment>) -> Result<Self, Self::Error> {
        if attachments.is_empty() {
            return Err(ProofAttachmentListError::Empty);
        }
        if attachments.len() > PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 {
            return Err(ProofAttachmentListError::TooMany {
                actual: attachments.len(),
                maximum: PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1,
            });
        }
        let list = Self(attachments);
        let canonical_frame_len = list.canonical_frame_len_v1()?;
        if canonical_frame_len > PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1 {
            return Err(ProofAttachmentListError::CanonicalFrameTooLarge {
                actual: canonical_frame_len,
                maximum: PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
            });
        }
        Ok(list)
    }
}

impl norito::SerializePayload for ProofAttachmentList {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        let field_len = norito::SerializePayload::encoded_len_exact(&self.0)
            .ok_or(ncore::Error::LengthMismatch)?;
        ncore::write_len(
            writer,
            u64::try_from(field_len).map_err(|_| ncore::Error::LengthMismatch)?,
        )?;
        norito::SerializePayload::serialize(&self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.encoded_len_exact()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        let field_len = norito::SerializePayload::encoded_len_exact(&self.0)?;
        ncore::len_prefix_len(field_len).checked_add(field_len)
    }
}

impl<'de> norito::DeserializePayload<'de> for ProofAttachmentList {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("ProofAttachmentList deserialization requires a canonical bounded archive")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        let (list, used) = <Self as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
        if used != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        Ok(list)
    }
}
impl<'a> ncore::DecodeFromSlice<'a> for ProofAttachmentList {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let canonical_frame_len = Self::canonical_frame_len_from_payload_len(bytes.len())
            .ok_or(ncore::Error::LengthMismatch)?;
        if canonical_frame_len > PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1 {
            return Err(ncore::Error::Message(
                "ProofAttachmentList canonical frame exceeds the first-release byte limit".into(),
            ));
        }
        let mut offset = 0_usize;
        let field = take_len_prefixed_slice(
            bytes,
            &mut offset,
            PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        )?;
        if offset != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        // Inspect the fixed V1 sequence count before Vec's planner can reserve
        // storage or inspect attacker-controlled element spans.
        let (attachments, _) = ncore::inspect_seq_len_slice(field)?;
        if attachments == 0 {
            return Err(ncore::Error::Message(
                "ProofAttachmentList must not be empty".into(),
            ));
        }
        if attachments > PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 {
            return Err(ncore::Error::Message(format!(
                "ProofAttachmentList attachment count {attachments} exceeds the first-release maximum of {PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1}"
            )));
        }
        let (attachments, used) =
            <Vec<ProofAttachment> as ncore::DecodeFromSlice>::decode_from_slice(field)?;
        if used != field.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        let list = Self::try_from(attachments)
            .map_err(|error| ncore::Error::Message(error.to_string()))?;
        Ok((list, offset))
    }
}

fn proof_attachment_list_base64_encoded_len(decoded_len: usize) -> Option<usize> {
    decoded_len
        .checked_add(2)
        .and_then(|length| length.checked_div(3))
        .and_then(|length| length.checked_mul(4))
}

fn proof_attachment_list_base64_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn proof_attachment_list_json_error(message: &'static str) -> norito::json::Error {
    norito::json::Error::InvalidField {
        field: "ProofAttachmentList".into(),
        message: message.into(),
    }
}

fn proof_attachment_list_base64_decoded_len(
    encoded: &str,
    maximum_decoded_bytes: usize,
) -> Result<usize, norito::json::Error> {
    let maximum_encoded_bytes = proof_attachment_list_base64_encoded_len(maximum_decoded_bytes)
        .ok_or_else(|| proof_attachment_list_json_error("base64 length arithmetic overflow"))?;
    if encoded.is_empty()
        || encoded.len() > maximum_encoded_bytes
        || !encoded.len().is_multiple_of(4)
    {
        return Err(proof_attachment_list_json_error(
            "base64 token has a non-canonical length",
        ));
    }
    let padding = match encoded.as_bytes() {
        [.., b'=', b'='] => 2,
        [.., b'='] => 1,
        _ => 0,
    };
    let payload_len = encoded.len() - padding;
    let bytes = encoded.as_bytes();
    if bytes[..payload_len]
        .iter()
        .any(|byte| proof_attachment_list_base64_sextet(*byte).is_none())
        || bytes[payload_len..].iter().any(|byte| *byte != b'=')
    {
        return Err(proof_attachment_list_json_error(
            "expected canonical padded standard base64",
        ));
    }
    let tail_is_canonical = match padding {
        0 => true,
        1 => {
            payload_len % 4 == 3
                && proof_attachment_list_base64_sextet(bytes[payload_len - 1])
                    .is_some_and(|sextet| sextet.is_multiple_of(4))
        }
        2 => {
            payload_len % 4 == 2
                && proof_attachment_list_base64_sextet(bytes[payload_len - 1])
                    .is_some_and(|sextet| sextet.is_multiple_of(16))
        }
        _ => false,
    };
    if !tail_is_canonical {
        return Err(proof_attachment_list_json_error(
            "base64 token has non-canonical tail bits",
        ));
    }
    let decoded_len = encoded
        .len()
        .checked_div(4)
        .and_then(|length| length.checked_mul(3))
        .and_then(|length| length.checked_sub(padding))
        .ok_or_else(|| proof_attachment_list_json_error("invalid base64 decoded length"))?;
    if decoded_len > maximum_decoded_bytes {
        return Err(proof_attachment_list_json_error(
            "decoded frame exceeds the first-release byte limit",
        ));
    }
    Ok(decoded_len)
}

fn proof_attachment_list_borrowed_base64_token<'a>(
    parser: &mut norito::json::Parser<'a>,
    maximum_decoded_bytes: usize,
) -> Result<(&'a str, usize), norito::json::Error> {
    let maximum_encoded_bytes = proof_attachment_list_base64_encoded_len(maximum_decoded_bytes)
        .ok_or_else(|| proof_attachment_list_json_error("base64 length arithmetic overflow"))?;
    parser.skip_ws();
    let start = parser.position();
    let decoded_token_len = parser.skip_string_bounded(maximum_encoded_bytes)?;
    let end = parser.position();
    let encoded = parser
        .input()
        .get(start.saturating_add(1)..end.saturating_sub(1))
        .ok_or_else(|| proof_attachment_list_json_error("invalid JSON string bounds"))?;
    if encoded.len() != decoded_token_len || encoded.as_bytes().contains(&b'\\') {
        return Err(proof_attachment_list_json_error(
            "base64 token must use its unescaped canonical spelling",
        ));
    }
    let decoded_len = proof_attachment_list_base64_decoded_len(encoded, maximum_decoded_bytes)?;
    Ok((encoded, decoded_len))
}

fn proof_attachment_list_validate_limits(
    canonical_frame_bytes: usize,
    attachments: usize,
    maximum_frame_bytes: usize,
    maximum_attachments: usize,
) -> Result<(), norito::json::Error> {
    if canonical_frame_bytes > maximum_frame_bytes {
        return Err(proof_attachment_list_json_error(
            "canonical frame exceeds the first-release byte limit",
        ));
    }
    if attachments == 0 {
        return Err(proof_attachment_list_json_error(
            "proof attachment list must not be empty",
        ));
    }
    if attachments > maximum_attachments {
        return Err(proof_attachment_list_json_error(
            "attachment count exceeds the first-release limit",
        ));
    }
    Ok(())
}

fn proof_attachment_list_frame_attachment_count(
    canonical_frame: &[u8],
) -> Result<usize, norito::json::Error> {
    let header = ncore::Header::read(std::io::Cursor::new(canonical_frame)).map_err(|_| {
        proof_attachment_list_json_error("base64 payload is not a complete Norito frame")
    })?;
    if header.compression != ncore::Compression::None {
        return Err(proof_attachment_list_json_error(
            "canonical proof attachment lists must be uncompressed",
        ));
    }
    let payload_len = usize::try_from(header.length).map_err(|_| {
        proof_attachment_list_json_error("Norito payload length exceeds this platform")
    })?;
    let payload_start = canonical_frame
        .len()
        .checked_sub(payload_len)
        .filter(|start| *start >= ncore::Header::SIZE)
        .ok_or_else(|| proof_attachment_list_json_error("truncated Norito frame payload"))?;
    let payload = &canonical_frame[payload_start..];
    // ProofAttachmentList is a one-field tuple struct. Canonical V1 uses one
    // compact field length followed by the Vec's fixed-width sequence count
    // and elements. This mirrors the bounded custom Norito decoder.
    let _canonical_flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let (field_len, field_header_len) = ncore::read_len_dyn_slice(payload).map_err(|_| {
        proof_attachment_list_json_error("malformed proof attachment list field framing")
    })?;
    let field_end = field_header_len
        .checked_add(field_len)
        .filter(|end| *end == payload.len())
        .ok_or_else(|| {
            proof_attachment_list_json_error("non-canonical proof attachment list field length")
        })?;
    let field = payload
        .get(field_header_len..field_end)
        .ok_or_else(|| proof_attachment_list_json_error("truncated attachment sequence"))?;
    let (attachments, _) = ncore::inspect_seq_len_slice(field).map_err(|_| {
        proof_attachment_list_json_error("malformed proof attachment sequence length")
    })?;
    Ok(attachments)
}

impl norito::json::JsonSerialize for ProofAttachmentList {
    fn json_serialize(&self, out: &mut String) {
        norito::json::write_canonical_base64_json(self, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_canonical_base64_json_to(self, out)
    }
}

impl norito::json::JsonDeserialize for ProofAttachmentList {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let (encoded, decoded_len) = proof_attachment_list_borrowed_base64_token(
            parser,
            PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        )?;
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|err| norito::json::Error::Message(err.to_string()))?;
        if bytes.len() != decoded_len {
            return Err(proof_attachment_list_json_error(
                "base64 decoder length disagrees with canonical preflight",
            ));
        }
        let attachments = proof_attachment_list_frame_attachment_count(&bytes)?;
        proof_attachment_list_validate_limits(
            bytes.len(),
            attachments,
            PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
            PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1,
        )?;
        let list = norito::decode_canonical::<ProofAttachmentList>(&bytes)
            .map_err(|err| norito::json::Error::Message(err.to_string()))?;
        proof_attachment_list_validate_limits(
            bytes.len(),
            list.len(),
            PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
            PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1,
        )?;
        Ok(list)
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        let encoded = value
            .as_str()
            .ok_or_else(|| proof_attachment_list_json_error("expected canonical base64 string"))?;
        proof_attachment_list_base64_decoded_len(
            encoded,
            PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        )?;
        let canonical_json = norito::json::to_json(value)?;
        norito::json::from_str(&canonical_json)
    }
}
/// Identifier of a proof for storage and deduplication.
/// Combines backend identifier with a stable 32-byte proof hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::ProofId")]
pub struct ProofId {
    /// Identifier of the proof backend/format.
    pub backend: iroha_schema::Ident,
    /// Stable 32-byte hash of the proof bytes (and optionally normalized inputs).
    #[norito(
        with = "crate::json_helpers::fixed_bytes",
        bounded_with = "crate::json_helpers::fixed_bytes::serialize_bounded"
    )]
    pub proof_hash: [u8; 32],
}
#[inline]
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + (c - b'a')),
        b'A'..=b'F' => Some(10 + (c - b'A')),
        _ => None,
    }
}
impl core::fmt::Display for ProofId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Print as backend:HEX
        write!(f, "{}:", self.backend)?;
        for b in &self.proof_hash {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl norito::json::JsonSerialize for ProofId {
    fn json_serialize(&self, out: &mut String) {
        let repr = self.to_string();
        norito::json::JsonSerialize::json_serialize(&repr, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        fn write_escaped_fragment(
            value: &str,
            out: &mut dyn norito::json::JsonWriteSink,
        ) -> Result<(), norito::json::BoundedJsonError> {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for ch in value.chars() {
                match ch {
                    '"' => out.push_str("\\\"")?,
                    '\\' => out.push_str("\\\\")?,
                    '\n' => out.push_str("\\n")?,
                    '\r' => out.push_str("\\r")?,
                    '\t' => out.push_str("\\t")?,
                    '\u{08}' => out.push_str("\\b")?,
                    '\u{0C}' => out.push_str("\\f")?,
                    control if (control as u32) < 0x20 => {
                        let byte = control as u8;
                        out.push_str("\\u00")?;
                        out.push(char::from(HEX[usize::from(byte >> 4)]))?;
                        out.push(char::from(HEX[usize::from(byte & 0x0f)]))?;
                    }
                    ordinary => out.push(ordinary)?,
                }
            }
            Ok(())
        }
        const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
        out.push('"')?;
        write_escaped_fragment(self.backend.as_str(), out)?;
        out.push(':')?;
        for byte in self.proof_hash {
            out.push(char::from(UPPER_HEX[usize::from(byte >> 4)]))?;
            out.push(char::from(UPPER_HEX[usize::from(byte & 0x0f)]))?;
        }
        out.push('"')
    }
}
impl core::str::FromStr for ProofId {
    type Err = &'static str;
    /// Parse a stable string form produced by Display: `"<backend>:<hex32bytes>"`.
    ///
    /// - `backend` is parsed as `iroha_schema::Ident` (verbatim substring before the last ':').
    /// - `hex32bytes` must be exactly 64 hex chars (case-insensitive). Optional `0x` prefix is allowed.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (backend_str, hex_str) = s.rsplit_once(':').ok_or("missing ':'")?;
        if backend_str.is_empty() {
            return Err("empty backend");
        }
        let mut h = hex_str;
        if let Some(rest) = h.strip_prefix("0x") {
            h = rest;
        }
        if h.len() != 64 {
            return Err("invalid hash length");
        }
        let mut arr = [0u8; 32];
        let bytes = h.as_bytes();
        for i in 0..32 {
            let hi = hex_val(bytes[2 * i]).ok_or("invalid hex digit")?;
            let lo = hex_val(bytes[2 * i + 1]).ok_or("invalid hex digit")?;
            arr[i] = (hi << 4) | lo;
        }
        Ok(ProofId {
            backend: backend_str.into(),
            proof_hash: arr,
        })
    }
}

impl norito::json::JsonDeserialize for ProofId {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        value
            .parse()
            .map_err(|err: &str| norito::json::Error::Message(err.to_owned()))
    }
}
#[cfg(test)]
mod parse_tests {
    use super::*;
    #[test]
    fn proof_id_parse_roundtrip_upper_lower_and_0x() {
        let id = ProofId {
            backend: "halo2/ipa".into(),
            proof_hash: [0xAB; 32],
        };
        let disp = format!("{id}");
        // Uppercase produced by Display
        let parsed = disp.parse::<ProofId>().expect("parse");
        assert_eq!(parsed, id);
        // Lowercase hex accepted
        let lower = disp.to_lowercase();
        let parsed2 = lower.parse::<ProofId>().expect("parse lower");
        assert_eq!(parsed2, id);
        // 0x prefix also accepted
        let mut hex_lower = String::with_capacity(64);
        for b in &id.proof_hash {
            use std::fmt::Write as _;
            let _ = write!(&mut hex_lower, "{b:02x}");
        }
        let with0x = format!("{}:0x{}", id.backend, hex_lower);
        let parsed3 = with0x.parse::<ProofId>().expect("parse 0x");
        assert_eq!(parsed3, id);
    }
    #[test]
    fn proof_id_parse_roundtrips_backend_labels_with_colons() {
        let id = ProofId {
            backend: "halo2/ipa:colon-profile".into(),
            proof_hash: [0xCD; 32],
        };
        let parsed = id.to_string().parse::<ProofId>().expect("parse");
        assert_eq!(parsed, id);
    }
}
/// Verification status of a submitted proof artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::ProofStatus")]
pub enum ProofStatus {
    /// Proof was observed/queued for verification.
    Submitted,
    /// Proof was successfully verified against the specified verifying key.
    Verified,
    /// Proof failed to verify.
    Rejected,
}

impl norito::json::JsonSerialize for ProofStatus {
    fn json_serialize(&self, out: &mut String) {
        let label = match self {
            ProofStatus::Submitted => "Submitted",
            ProofStatus::Verified => "Verified",
            ProofStatus::Rejected => "Rejected",
        };
        norito::json::write_json_string(label, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        let label = match self {
            ProofStatus::Submitted => "Submitted",
            ProofStatus::Verified => "Verified",
            ProofStatus::Rejected => "Rejected",
        };
        norito::json::write_json_string_to(label, out)
    }
}

impl norito::json::JsonDeserialize for ProofStatus {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        match value.as_str() {
            "Submitted" => Ok(ProofStatus::Submitted),
            "Verified" => Ok(ProofStatus::Verified),
            "Rejected" => Ok(ProofStatus::Rejected),
            other => Err(norito::json::Error::unknown_field(other.to_owned())),
        }
    }
}
/// Stored record for a proof verification outcome.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::ProofRecord")]
pub struct ProofRecord {
    /// Proof identifier (backend + hash of proof bytes).
    pub id: ProofId,
    /// Optional reference to a verifying key stored in WSV.
    pub vk_ref: Option<VerifyingKeyId>,
    /// Optional verifying key commitment (32-byte stable hash) used during verification.
    #[norito(
        with = "crate::json_helpers::fixed_bytes::option",
        bounded_with = "crate::json_helpers::fixed_bytes::option::serialize_bounded"
    )]
    pub vk_commitment: Option<[u8; 32]>,
    /// Resulting status of verification.
    pub status: ProofStatus,
    /// Height at which verification was recorded (if applicable).
    pub verified_at_height: Option<u64>,
    /// Optional bridge-proof payload and metadata when the proof records a bridge artifact.
    pub bridge: Option<crate::bridge::BridgeProofRecord>,
}
/// Wrapper for attaching an optional proof to a committed transaction response.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::ProofedCommittedTransaction")]
pub struct ProofedCommittedTransaction {
    /// Base committed transaction returned by the ledger.
    pub base: crate::query::CommittedTransaction,
    /// Optional proof attached to the transaction result.
    pub proof: Option<ProofBox>,
}
impl ProofedCommittedTransaction {
    /// Wrap a committed transaction with an optional proof payload.
    pub fn new(base: crate::query::CommittedTransaction, proof: Option<ProofBox>) -> Self {
        Self { base, proof }
    }
}
#[cfg(test)]
#[path = "proof/tests.rs"]
mod tests;

#[cfg(test)]
mod captured_proof_schema_tests;
