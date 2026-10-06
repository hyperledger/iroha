//! Zero-knowledge envelope types (Norito TLV payloads).
use crate::{
    AssetDefinitionId, NetworkId,
    account::AccountId,
    privacy::{
        GoldilocksDigest384V1, PRIVACY_EXACT12_CATALOG_ID_V1, PrivacyProtocolIdV1,
        PrivacyZkAceIdentityCommitmentV1, PrivacyZkAceReplayNullifierV1,
        ZkAcePqAuthorizationStatementV1, privacy_protocol_label_is_exact12_v1,
    },
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
/// Canonical ZK-ACE circuit identifier for post-quantum authorization v1.
pub const ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID: &str = "zk_ace_pq_authorization_v1";
/// Canonical verifier-registry label used by ZK-ACE authorization v1.
pub const ZK_ACE_PQ_AUTHORIZATION_V1_BACKEND: &str = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
/// Sole canonical native STARK/FRI verifier profile for the first release.
pub const ZK_BACKEND_STARK_FRI_V1: &str = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
/// Canonical empty root of the first-release depth-16 Pasta Poseidon
/// confidential commitment tree.
///
/// This is the little-endian Pasta field representation produced by the
/// `cfleaf03`/`cfnode03` Axiom Poseidon construction. Hosts and SDK test doubles
/// use the fixed value so an empty registered tree is never represented by an
/// all-zero sentinel or an omitted root.
pub const CONFIDENTIAL_TREE_POSEIDON_PASTA_V1_EMPTY_ROOT: [u8; 32] = [
    0xea, 0x06, 0x0f, 0x4e, 0x4b, 0xe3, 0x78, 0x13, 0x28, 0x09, 0x2c, 0x94, 0xbc, 0xa4, 0x26, 0x8e,
    0x6e, 0x9b, 0x24, 0x6b, 0x0e, 0xc6, 0xea, 0x33, 0x9a, 0xdc, 0x76, 0x6a, 0x2b, 0x9b, 0x92, 0x01,
];
/// Exact verifier-registry labels admitted by native Rust dispatch.
///
/// This closed set is intentionally separate from [`BackendTag`]. A registry
/// label selects one concrete verifier configuration, while [`BackendTag`]
/// identifies the low-level proof engine encoded in an [`OpenVerifyEnvelope`].
/// Callers must compare these labels byte-for-byte: aliases, normalization,
/// case folding, and surrounding whitespace are never accepted.
pub const ZK_VERIFIER_BACKEND_REGISTRY_LABELS_V1: &[&str] = &[
    "halo2/ipa",
    "halo2/pasta/kaigi-authorization-v1",
    "halo2/pasta/kaigi-usage-v1",
    "halo2/pasta/confidential-transfer-2x2-merkle16-axiom-poseidon-v3",
    "halo2/pasta/confidential-unshield-full-merkle16-axiom-poseidon-v3",
    "halo2/pasta/confidential-unshield-change-merkle16-axiom-poseidon-v4",
    "stark/fri/poseidon-x7-goldilocks-6x64-v1",
];
/// Return true only for the admitted STARK/FRI verifier profile.
#[inline]
#[must_use]
pub fn is_stark_fri_v1_backend_label(backend: &str) -> bool {
    backend == ZK_BACKEND_STARK_FRI_V1
}
/// Domain tag bound as a protocol field by ZK-ACE commitments and nullifiers.
pub const ZK_ACE_PQ_AUTHORIZATION_V1_DOMAIN_TAG: &str = "iroha:zk-ace:pq-authorization:v1";
/// Fixed action class of the first-release ZK-ACE relation.
pub const ZK_ACE_PQ_AUTHORIZATION_V1_ACTION_TRANSFER: &str = "transparent_asset_transfer";
/// Shared six-lane digest profile bound by every ZK-ACE hash invocation.
pub const ZK_ACE_GOLDILOCKS_DIGEST384_PROFILE_V1: &[u8] = b"poseidon-x7-goldilocks-6x64-v1";
/// Identity-commitment role in the typed six-lane hash domain.
pub const ZK_ACE_IDENTITY_COMMITMENT_ROLE_V1: &[u8] = b"identity";
/// Replay-nullifier role in the typed six-lane hash domain.
pub const ZK_ACE_REPLAY_NULLIFIER_ROLE_V1: &[u8] = b"replay";
/// Action-digest role in the typed six-lane hash domain.
pub const ZK_ACE_ACTION_DIGEST_ROLE_V1: &[u8] = b"action";
/// Authorization-projection role in the typed six-lane hash domain.
pub const ZK_ACE_AUTHORIZATION_DIGEST_ROLE_V1: &[u8] = b"authorization";
/// Public-transcript role in the typed six-lane hash domain.
pub const ZK_ACE_PUBLIC_TRANSCRIPT_ROLE_V1: &[u8] = b"public-transcript";
/// Identity-commitment phase in the typed six-lane hash domain.
pub const ZK_ACE_IDENTITY_COMMITMENT_PHASE_V1: &[u8] = b"commitment";
/// Replay-nullifier phase in the typed six-lane hash domain.
pub const ZK_ACE_REPLAY_NULLIFIER_PHASE_V1: &[u8] = b"nullifier";
/// Permanent Norito schema identity for the typed ZK-ACE public-input wrapper.
pub const ZK_ACE_PRIVACY_PUBLIC_INPUTS_SCHEMA_NAME_V1: &str =
    "iroha.privacy.zk-ace.public-inputs.v1";
/// Exact type-name-independent transfer-digest preimage schema.
pub const ZK_ACE_TRANSFER_DIGEST_SCHEMA_V1: &[u8] = b"framing=goldilocks-digest384-v1:typed-domain+ordered-length-delimited-7byte-le-fields|field0=this-schema|field1=source:account-canonical-hex-v1-utf8|field2=destination:account-canonical-hex-v1-utf8|field3=asset-definition-id:uuid-bytes16|field4=amount:u128be|field5=network-id:bytes32|field6=action-class:utf8|field7=policy-digest:bytes32";
/// Maximum source accounts that one ZK-ACE identity commitment may authorize.
pub const ZK_ACE_MAX_ALLOWED_ACCOUNTS: usize = 16;
/// Number of bytes packed into each Goldilocks field limb for ZK-ACE hashes.
pub const ZK_ACE_PACKED_LIMB_BYTES: usize = 7;
/// Default maximum proof payload size accepted by generic `OpenVerify` admission.
pub const OPEN_VERIFY_DEFAULT_MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
/// Default maximum circuit identifier size accepted by generic `OpenVerify` admission.
pub const OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES: usize = 256;
/// Default maximum public-input metadata size accepted by generic `OpenVerify` admission.
pub const OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES: usize = 1024 * 1024;
/// Default maximum auxiliary metadata size for non-admission `OpenVerify` callers.
pub const OPEN_VERIFY_DEFAULT_MAX_AUX_BYTES: usize = 64 * 1024;
/// Low-level proof engine supported by generic [`OpenVerifyEnvelope`] verification.
///
/// Privacy protocols and verifier profiles are deliberately not represented by
/// this enum. They have protocol-specific data-model types and must not be
/// inferred from aliases or free-form catalog labels.
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
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::zk::BackendTag")]
pub enum BackendTag {
    /// Halo2 IPA over Pasta curves.
    Halo2IpaPasta,
    /// Native transparent STARK/FRI.
    Stark,
}
impl BackendTag {
    /// All generic `OpenVerify` engines, in canonical Norito order.
    pub const ALL: [Self; 2] = [Self::Halo2IpaPasta, Self::Stark];
    /// Return the canonical JSON label for this engine.
    #[must_use]
    pub const fn canonical_label(self) -> &'static str {
        match self {
            BackendTag::Halo2IpaPasta => "halo2-ipa-pasta",
            BackendTag::Stark => "stark",
        }
    }
    /// Parse an exact canonical JSON label.
    ///
    /// This parser intentionally performs no trimming, case folding, family
    /// inference, or alias normalization.
    #[must_use]
    pub const fn from_canonical_label(label: &str) -> Option<Self> {
        match label.as_bytes() {
            b"halo2-ipa-pasta" => Some(Self::Halo2IpaPasta),
            b"stark" => Some(Self::Stark),
            _ => None,
        }
    }
}
/// Return the low-level engine for one exact verifier-registry label.
///
/// This function deliberately has no fallback family matching. Adding a new
/// verifier configuration therefore requires an explicit consensus-visible
/// source change and corresponding cross-SDK update.
#[inline]
#[must_use]
pub fn verifier_backend_registry_tag_v1(label: &str) -> Option<BackendTag> {
    match label {
        "halo2/ipa"
        | "halo2/pasta/kaigi-authorization-v1"
        | "halo2/pasta/kaigi-usage-v1"
        | "halo2/pasta/confidential-transfer-2x2-merkle16-axiom-poseidon-v3"
        | "halo2/pasta/confidential-unshield-full-merkle16-axiom-poseidon-v3"
        | "halo2/pasta/confidential-unshield-change-merkle16-axiom-poseidon-v4" => {
            Some(BackendTag::Halo2IpaPasta)
        }
        "stark/fri/poseidon-x7-goldilocks-6x64-v1" => Some(BackendTag::Stark),
        _ => None,
    }
}
/// Return whether `label` is one exact native verifier-registry label.
#[inline]
#[must_use]
pub fn is_verifier_backend_registry_label_v1(label: &str) -> bool {
    verifier_backend_registry_tag_v1(label).is_some()
}

impl norito::json::JsonSerialize for BackendTag {
    fn json_serialize(&self, out: &mut String) {
        norito::json::write_json_string(self.canonical_label(), out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(self.canonical_label(), out)
    }
}

impl norito::json::JsonDeserialize for BackendTag {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let label = parser.parse_string()?;
        BackendTag::from_canonical_label(&label).ok_or_else(|| norito::json::Error::InvalidField {
            field: "backend".to_owned(),
            message: format!("unknown or non-canonical backend label `{label}`"),
        })
    }
}
/// Size and policy bounds for validating an [`OpenVerifyEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenVerifyEnvelopeBounds {
    /// Maximum circuit identifier bytes.
    pub max_circuit_id_bytes: usize,
    /// Maximum public-input metadata bytes.
    pub max_public_input_bytes: usize,
    /// Maximum backend proof bytes.
    pub max_proof_bytes: usize,
    /// Maximum auxiliary metadata bytes.
    pub max_aux_bytes: usize,
    /// Whether auxiliary bytes are allowed at all.
    pub allow_aux: bool,
    /// Whether the verifier-key hash must be non-zero.
    pub require_nonzero_vk_hash: bool,
}
impl Default for OpenVerifyEnvelopeBounds {
    fn default() -> Self {
        Self {
            max_circuit_id_bytes: OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES,
            max_public_input_bytes: OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES,
            max_proof_bytes: OPEN_VERIFY_DEFAULT_MAX_PROOF_BYTES,
            max_aux_bytes: OPEN_VERIFY_DEFAULT_MAX_AUX_BYTES,
            allow_aux: false,
            require_nonzero_vk_hash: true,
        }
    }
}
/// Validation failure for a generic [`OpenVerifyEnvelope`] admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVerifyEnvelopeValidationError {
    /// The circuit identifier is empty or whitespace-only.
    EmptyCircuitId,
    /// The circuit identifier contains unsupported characters or delimiters.
    InvalidCircuitId,
    /// The circuit identifier reuses an Exact12 privacy-protocol label.
    ReservedPrivacyProtocolCircuitId,
    /// The circuit identifier exceeds configured bounds.
    CircuitIdTooLarge {
        /// Observed circuit identifier byte length.
        len: usize,
        /// Configured maximum circuit identifier byte length.
        max: usize,
    },
    /// The verifier-key hash is all zeros.
    ZeroVerifierKeyHash,
    /// The public-input metadata is empty.
    EmptyPublicInputs,
    /// The public-input metadata is present but contains only zero bytes.
    AllZeroPublicInputs,
    /// The public-input metadata exceeds configured bounds.
    PublicInputsTooLarge {
        /// Observed public-input metadata length.
        len: usize,
        /// Configured maximum public-input metadata length.
        max: usize,
    },
    /// The proof byte payload is empty.
    EmptyProofBytes,
    /// The proof byte payload is present but contains only zero bytes.
    AllZeroProofBytes,
    /// The proof byte payload exceeds configured bounds.
    ProofBytesTooLarge {
        /// Observed proof byte length.
        len: usize,
        /// Configured maximum proof byte length.
        max: usize,
    },
    /// The envelope carries auxiliary metadata where admission forbids it.
    NonEmptyAux,
    /// The auxiliary metadata exceeds configured bounds.
    AuxTooLarge {
        /// Observed auxiliary metadata length.
        len: usize,
        /// Configured maximum auxiliary metadata length.
        max: usize,
    },
}
impl core::fmt::Display for OpenVerifyEnvelopeValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyCircuitId => write!(f, "OpenVerifyEnvelope circuit id is empty"),
            Self::InvalidCircuitId => write!(
                f,
                "OpenVerifyEnvelope circuit id must be a portable canonical identifier"
            ),
            Self::ReservedPrivacyProtocolCircuitId => write!(
                f,
                "OpenVerifyEnvelope circuit id uses a reserved privacy protocol label"
            ),
            Self::CircuitIdTooLarge { len, max } => write!(
                f,
                "OpenVerifyEnvelope circuit id length {len} exceeds maximum {max}"
            ),
            Self::ZeroVerifierKeyHash => {
                write!(f, "OpenVerifyEnvelope verifier-key hash is zero")
            }
            Self::EmptyPublicInputs => {
                write!(f, "OpenVerifyEnvelope public inputs are empty")
            }
            Self::AllZeroPublicInputs => {
                write!(f, "OpenVerifyEnvelope public inputs must not be all zeros")
            }
            Self::PublicInputsTooLarge { len, max } => write!(
                f,
                "OpenVerifyEnvelope public inputs length {len} exceeds maximum {max}"
            ),
            Self::EmptyProofBytes => write!(f, "OpenVerifyEnvelope proof bytes are empty"),
            Self::AllZeroProofBytes => {
                write!(f, "OpenVerifyEnvelope proof bytes must not be all zeros")
            }
            Self::ProofBytesTooLarge { len, max } => write!(
                f,
                "OpenVerifyEnvelope proof bytes length {len} exceeds maximum {max}"
            ),
            Self::NonEmptyAux => {
                write!(f, "OpenVerifyEnvelope auxiliary bytes must be empty")
            }
            Self::AuxTooLarge { len, max } => write!(
                f,
                "OpenVerifyEnvelope auxiliary bytes length {len} exceeds maximum {max}"
            ),
        }
    }
}
impl std::error::Error for OpenVerifyEnvelopeValidationError {}
/// Envelope for open-verify operations (canonical `SignedQuery` layout).
///
/// This structure is serialized with Norito and used as the TLV payload for
/// `&NoritoBytes` pointer-ABI types passed to IVM verify syscalls or host vendor bridges.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema)]
#[norito(decode_from_slice)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::zk::OpenVerifyEnvelope")]
pub struct OpenVerifyEnvelope {
    /// Backend tag string (e.g., `halo2-ipa-pasta`).
    pub backend: BackendTag,
    /// Circuit identifier string (backend-specific; opaque to host).
    pub circuit_id: String,
    /// Domain-separated verifying-key hash.
    ///
    /// Generic codecs may still represent an unavailable key binding as all
    /// zeros, but chain admission for registered proof attachments requires an
    /// exact match with the active verifier-key commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub vk_hash: [u8; 32],
    /// Public-input metadata bytes (opaque; backend-specific canonical encoding).
    ///
    /// For backends that separate schema from values (e.g., `stark/fri` wrappers),
    /// this field carries the stable schema descriptor while concrete values are
    /// stored inside backend-specific payloads.
    pub public_inputs: Vec<u8>,
    /// Proof bytes (opaque, backend-specific canonical encoding).
    pub proof_bytes: Vec<u8>,
    /// Opaque aux map encoded as JSON bytes (for small structured extras).
    ///
    /// Production chain proof-admission paths require this to be empty unless a
    /// future instruction explicitly defines and validates auxiliary semantics.
    pub aux: Vec<u8>,
}
impl OpenVerifyEnvelope {
    /// Create a new envelope with required fields; `aux` defaults to empty.
    pub fn new(
        backend: BackendTag,
        circuit_id: impl Into<String>,
        vk_hash: [u8; 32],
        public_inputs: Vec<u8>,
        proof_bytes: Vec<u8>,
    ) -> Self {
        Self {
            backend,
            circuit_id: circuit_id.into(),
            vk_hash,
            public_inputs,
            proof_bytes,
            aux: Vec::new(),
        }
    }
    /// Validate the generic shape required before registered proof admission.
    ///
    /// Backend-specific verifiers must still validate circuit semantics,
    /// public-input interpretation, verifier-key registry matching, and proof
    /// verification. This method only enforces the shared fail-closed envelope
    /// invariants that all admitted proof paths rely on.
    ///
    /// # Errors
    ///
    /// Returns [`OpenVerifyEnvelopeValidationError`] when the envelope is not
    /// acceptable for registered proof admission.
    pub fn validate_for_admission(&self) -> Result<(), OpenVerifyEnvelopeValidationError> {
        self.validate_with_bounds(OpenVerifyEnvelopeBounds::default())
    }
    /// Validate generic shape and size invariants with caller-provided bounds.
    ///
    /// # Errors
    ///
    /// Returns [`OpenVerifyEnvelopeValidationError`] when the envelope violates
    /// the supplied size or non-empty field bounds.
    pub fn validate_with_bounds(
        &self,
        bounds: OpenVerifyEnvelopeBounds,
    ) -> Result<(), OpenVerifyEnvelopeValidationError> {
        if self.circuit_id.trim().is_empty() {
            return Err(OpenVerifyEnvelopeValidationError::EmptyCircuitId);
        }
        if self.circuit_id.len() > bounds.max_circuit_id_bytes {
            return Err(OpenVerifyEnvelopeValidationError::CircuitIdTooLarge {
                len: self.circuit_id.len(),
                max: bounds.max_circuit_id_bytes,
            });
        }
        if !open_verify_circuit_id_is_portable(&self.circuit_id) {
            return Err(OpenVerifyEnvelopeValidationError::InvalidCircuitId);
        }
        if open_verify_circuit_id_uses_reserved_privacy_protocol_namespace_v1(&self.circuit_id) {
            return Err(OpenVerifyEnvelopeValidationError::ReservedPrivacyProtocolCircuitId);
        }
        if bounds.require_nonzero_vk_hash && self.vk_hash.iter().all(|byte| *byte == 0) {
            return Err(OpenVerifyEnvelopeValidationError::ZeroVerifierKeyHash);
        }
        if self.public_inputs.is_empty() {
            return Err(OpenVerifyEnvelopeValidationError::EmptyPublicInputs);
        }
        if self.public_inputs.len() > bounds.max_public_input_bytes {
            return Err(OpenVerifyEnvelopeValidationError::PublicInputsTooLarge {
                len: self.public_inputs.len(),
                max: bounds.max_public_input_bytes,
            });
        }
        if self.public_inputs.iter().all(|byte| *byte == 0) {
            return Err(OpenVerifyEnvelopeValidationError::AllZeroPublicInputs);
        }
        if self.proof_bytes.is_empty() {
            return Err(OpenVerifyEnvelopeValidationError::EmptyProofBytes);
        }
        if self.proof_bytes.len() > bounds.max_proof_bytes {
            return Err(OpenVerifyEnvelopeValidationError::ProofBytesTooLarge {
                len: self.proof_bytes.len(),
                max: bounds.max_proof_bytes,
            });
        }
        if self.proof_bytes.iter().all(|byte| *byte == 0) {
            return Err(OpenVerifyEnvelopeValidationError::AllZeroProofBytes);
        }
        if !bounds.allow_aux && !self.aux.is_empty() {
            return Err(OpenVerifyEnvelopeValidationError::NonEmptyAux);
        }
        if self.aux.len() > bounds.max_aux_bytes {
            return Err(OpenVerifyEnvelopeValidationError::AuxTooLarge {
                len: self.aux.len(),
                max: bounds.max_aux_bytes,
            });
        }
        Ok(())
    }
}
/// Returns `true` when a circuit identifier uses the portable `OpenVerify` grammar.
#[must_use]
pub fn open_verify_circuit_id_is_portable(circuit_id: &str) -> bool {
    let bytes = circuit_id.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    let Some(last) = bytes.last() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !(last.is_ascii_lowercase() || last.is_ascii_digit())
    {
        return false;
    }
    if ["..", "//", ":::", "/:", ":/", "/.", "./", ":.", ".:"]
        .iter()
        .any(|separator| circuit_id.contains(separator))
    {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(*byte, b'-' | b'_' | b'/' | b':' | b'.')
    })
}
fn privacy_protocol_namespace_component_is_reserved_v1(component: &str) -> bool {
    if privacy_protocol_label_is_exact12_v1(component) {
        return true;
    }
    PrivacyProtocolIdV1::ALL.into_iter().any(|protocol_id| {
        let canonical = protocol_id.canonical_label();
        let stem = canonical
            .strip_suffix("-v1")
            .expect("every Exact12 label has the final -v1 suffix");
        let hyphen_version = component
            .strip_prefix(stem)
            .and_then(|suffix| suffix.strip_prefix("-v"));
        if hyphen_version.is_some_and(|version| {
            !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            return true;
        }
        let snake_stem = stem.replace('-', "_");
        component
            .strip_prefix(&snake_stem)
            .and_then(|suffix| suffix.strip_prefix("_v"))
            .is_some_and(|version| {
                !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
            })
    })
}

/// Return whether an `OpenVerify` circuit identifier enters a privacy protocol namespace.
///
/// Final Exact12 labels and every numeric version spelling of their hyphenated
/// or snake-case namespaces are reserved as complete `:`- or `/`-delimited
/// components. This makes retired labels fail without retaining aliases or a
/// compatibility dispatch table, while portable near misses remain available.
#[must_use]
pub fn open_verify_circuit_id_uses_reserved_privacy_protocol_namespace_v1(
    circuit_id: &str,
) -> bool {
    circuit_id
        .split([':', '/'])
        .any(privacy_protocol_namespace_component_is_reserved_v1)
}
// Note: Norito serialization is derived via `Encode`/`Decode` (packed structs compatible)
/// STARK/FRI proof payload embedded inside [`OpenVerifyEnvelope::proof_bytes`] when
/// [`OpenVerifyEnvelope::backend`] is [`BackendTag::Stark`].
///
/// This wrapper carries:
/// - `public_inputs`: public inputs expressed as 32-byte words, column-major (matching
///   the instance-column layout used by Halo2 envelopes), and
/// - `envelope_bytes`: backend-native proof bytes (typically a Norito-encoded STARK/FRI
///   envelope such as `StarkVerifyEnvelopeV1`).
///
/// Higher-level flows (governance voting, `Executable::IvmProved`, etc.) interpret the public
/// inputs according to the circuit/policy definitions and must validate their semantics.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::zk::StarkFriOpenProofV1")]
pub struct StarkFriOpenProofV1 {
    /// Version tag for format evolution.
    pub version: u16,
    /// Public inputs encoded as 32-byte words, column-major.
    pub public_inputs: Vec<Vec<[u8; 32]>>,
    /// Backend-native proof envelope bytes.
    pub envelope_bytes: Vec<u8>,
}
/// Exact public inputs accepted by the native privacy ZK-ACE engine.
///
/// The consensus statement is carried without a second, partially overlapping
/// action schema. `genesis_hash` is supplied by the trusted ledger context and
/// duplicates the exact genesis-derived network identity so inconsistent
/// trusted-context construction fails closed before proof verification.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::zk::ZkAcePrivacyPublicInputsV1",
    frame = "iroha.privacy.zk-ace.public-inputs.v1"
)]
pub struct ZkAcePrivacyPublicInputsV1 {
    /// Public-input schema version.
    pub version: u16,
    /// Exact typed consensus statement being authorized.
    pub statement: ZkAcePqAuthorizationStatementV1,
    /// Trusted genesis-block digest.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub genesis_hash: [u8; 32],
}
/// Canonical byte packing used by ZK-ACE dense-MDS Poseidon `x^7` hashing.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::zk::ZkAcePackedBytesV1")]
pub struct ZkAcePackedBytesV1 {
    /// Original byte length before padding.
    pub length: u64,
    /// Little-endian 7-byte Goldilocks limbs.
    pub limbs: Vec<u64>,
}
impl ZkAcePrivacyPublicInputsV1 {
    /// Construct the only admitted first-release public-input schema.
    #[must_use]
    pub const fn new(statement: ZkAcePqAuthorizationStatementV1, genesis_hash: [u8; 32]) -> Self {
        Self {
            version: 1,
            statement,
            genesis_hash,
        }
    }
}
/// Derive the exact action projection used by the native privacy ZK-ACE AIR.
///
/// The replay nullifier is derived from this digest and is therefore zeroed to
/// avoid a cyclic fixed-point construction. The transaction-intent digest is
/// already computed from a projection that zeroes this protocol's nullifier,
/// so it remains committed here together with trusted genesis and every other
/// typed statement field.
///
/// # Errors
///
/// Returns [`norito::Error`] if the normalized statement cannot be encoded
/// canonically.
pub fn derive_zk_ace_privacy_authorization_digest(
    public_inputs: &ZkAcePrivacyPublicInputsV1,
) -> Result<GoldilocksDigest384V1, norito::Error> {
    let mut normalized = public_inputs.statement.clone();
    normalized.replay_nullifier = PrivacyZkAceReplayNullifierV1::default();
    let statement_bytes = norito::encode_canonical(&normalized)?;
    Ok(zk_ace_digest384_v1(
        ZK_ACE_AUTHORIZATION_DIGEST_ROLE_V1,
        b"statement-projection",
        &[
            &public_inputs.version.to_be_bytes(),
            &public_inputs.genesis_hash,
            &statement_bytes,
        ],
    ))
}
/// Pack arbitrary bytes into canonical 7-byte Goldilocks limbs.
#[must_use]
pub fn zk_ace_pack_bytes_to_field_limbs(bytes: &[u8]) -> ZkAcePackedBytesV1 {
    let mut limbs = Vec::with_capacity(bytes.len().div_ceil(ZK_ACE_PACKED_LIMB_BYTES));
    let mut offset = 0usize;
    while offset < bytes.len() {
        let take = core::cmp::min(ZK_ACE_PACKED_LIMB_BYTES, bytes.len() - offset);
        let mut chunk = [0u8; 8];
        chunk[..take].copy_from_slice(&bytes[offset..offset + take]);
        limbs.push(u64::from_le_bytes(chunk));
        offset += take;
    }
    ZkAcePackedBytesV1 {
        length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        limbs,
    }
}
/// Construct one exact typed domain for a ZK-ACE six-lane digest.
#[must_use]
pub const fn zk_ace_digest384_domain_v1<'a>(
    role: &'a [u8],
    phase: &'a [u8],
) -> fastpq_isi::GoldilocksDigestDomainV1<'a> {
    fastpq_isi::GoldilocksDigestDomainV1 {
        catalog: PRIVACY_EXACT12_CATALOG_ID_V1,
        protocol: ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID.as_bytes(),
        profile: ZK_ACE_GOLDILOCKS_DIGEST384_PROFILE_V1,
        role,
        phase,
        level: 0,
        index: 0,
        counter: 0,
    }
}

fn zk_ace_digest384_v1(role: &[u8], phase: &[u8], fields: &[&[u8]]) -> GoldilocksDigest384V1 {
    fastpq_isi::hash_bytes_384_v1(zk_ace_digest384_domain_v1(role, phase), fields)
        .expect("bounded ZK-ACE fields fit the canonical digest frame")
        .into()
}
/// Derive the ZK-ACE identity commitment from its private witness components.
///
/// The temporary concatenated preimage is erased on return and unwind. The
/// caller retains ownership of, and must erase, its original witness fields.
pub fn derive_zk_ace_identity_commitment(
    identity_root: &[u8; 32],
    identity_blinding: &[u8; 32],
    domain_tag: &str,
) -> PrivacyZkAceIdentityCommitmentV1 {
    let mut scratch = [0_u8; 64];
    let witness = ZkAceIdentityPreimageGuard(&mut scratch);
    witness.0[..32].copy_from_slice(identity_root);
    witness.0[32..].copy_from_slice(identity_blinding);
    PrivacyZkAceIdentityCommitmentV1::from_digest(zk_ace_digest384_v1(
        ZK_ACE_IDENTITY_COMMITMENT_ROLE_V1,
        ZK_ACE_IDENTITY_COMMITMENT_PHASE_V1,
        &[domain_tag.as_bytes(), witness.0],
    ))
}
/// Borrowed owner avoids moving or duplicating the populated witness scratch.
struct ZkAceIdentityPreimageGuard<'a>(&'a mut [u8; 64]);

impl Drop for ZkAceIdentityPreimageGuard<'_> {
    fn drop(&mut self) {
        iroha_crypto::zeroize_value_for_confidential_discard(self.0);
    }
}
/// Derive the ZK-ACE replay nullifier for a specific action.
pub fn derive_zk_ace_replay_nullifier(
    replay_secret: &[u8; 32],
    authorization_digest: &GoldilocksDigest384V1,
    network_id: &NetworkId,
    action_class: &str,
    domain_tag: &str,
) -> PrivacyZkAceReplayNullifierV1 {
    PrivacyZkAceReplayNullifierV1::from_digest(zk_ace_digest384_v1(
        ZK_ACE_REPLAY_NULLIFIER_ROLE_V1,
        ZK_ACE_REPLAY_NULLIFIER_PHASE_V1,
        &[
            authorization_digest.as_ref(),
            network_id.as_bytes(),
            action_class.as_bytes(),
            domain_tag.as_bytes(),
            replay_secret,
        ],
    ))
}
/// Derive the action digest for a ZK-ACE-authorized transparent asset transfer.
///
/// Account identities use their domainless canonical hex payload and the asset
/// uses its raw canonical UUID. The result is therefore independent of I105
/// display prefixes, ambient chain-discriminant guards, and Rust type names.
///
/// # Errors
///
/// Returns a typed error if either account controller cannot be represented by
/// the canonical domainless account-address encoding.
pub fn derive_zk_ace_transfer_digest(
    from: &AccountId,
    to: &AccountId,
    asset: &AssetDefinitionId,
    amount: u128,
    network_id: &NetworkId,
    action_class: &str,
    policy_hash: &[u8; 32],
) -> Result<GoldilocksDigest384V1, ZkAceTransferDigestErrorV1> {
    let from_literal = from
        .to_canonical_hex()
        .map_err(|_| ZkAceTransferDigestErrorV1::SourceAccountEncoding)?;
    let to_literal = to
        .to_canonical_hex()
        .map_err(|_| ZkAceTransferDigestErrorV1::DestinationAccountEncoding)?;
    let asset_bytes = asset.aid_bytes();
    let amount_bytes = amount.to_be_bytes();
    Ok(zk_ace_digest384_v1(
        ZK_ACE_ACTION_DIGEST_ROLE_V1,
        b"transparent-transfer",
        &[
            ZK_ACE_TRANSFER_DIGEST_SCHEMA_V1,
            from_literal.as_bytes(),
            to_literal.as_bytes(),
            &asset_bytes,
            &amount_bytes,
            network_id.as_bytes(),
            action_class.as_bytes(),
            policy_hash,
        ],
    ))
}
/// Canonical account encoding failure while deriving a ZK-ACE transfer digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ZkAceTransferDigestErrorV1 {
    /// The source account controller has no canonical domainless address encoding.
    #[error("ZK-ACE source account cannot be encoded canonically")]
    SourceAccountEncoding,
    /// The destination account controller has no canonical domainless address encoding.
    #[error("ZK-ACE destination account cannot be encoded canonically")]
    DestinationAccountEncoding,
}
#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]
    use super::*;
    use crate::{account::address::ChainDiscriminantGuard, block::BlockHeader};
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use std::{
        collections::BTreeSet,
        str::FromStr as _,
        sync::{Arc, Barrier},
        thread,
    };
    fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([seed; Hash::LENGTH]),
        ))
    }
    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture seed derives Ed25519 keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn asset_definition_id() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain"),
            Name::from_str("xor").expect("asset name"),
        )
    }
    #[test]
    fn zk_ace_transfer_digest_is_domainless_and_discriminant_independent() {
        let from = account(0x42);
        let to = account(0x43);
        let asset = asset_definition_id();
        let network_id = network_id(0x45);
        let policy_hash = [0x44; 32];
        let amount = 123u128;
        let action_class = ZK_ACE_PQ_AUTHORIZATION_V1_ACTION_TRANSFER;
        let digest = derive_zk_ace_transfer_digest(
            &from,
            &to,
            &asset,
            amount,
            &network_id,
            action_class,
            &policy_hash,
        )
        .expect("single-key accounts have canonical domainless encodings");
        let from_canonical = from.to_canonical_hex().expect("canonical source encoding");
        let to_canonical = to
            .to_canonical_hex()
            .expect("canonical destination encoding");
        let asset_bytes = asset.aid_bytes();
        let amount_bytes = amount.to_be_bytes();
        let expected = zk_ace_digest384_v1(
            ZK_ACE_ACTION_DIGEST_ROLE_V1,
            b"transparent-transfer",
            &[
                ZK_ACE_TRANSFER_DIGEST_SCHEMA_V1,
                from_canonical.as_bytes(),
                to_canonical.as_bytes(),
                &asset_bytes,
                &amount_bytes,
                network_id.as_bytes(),
                action_class.as_bytes(),
                &policy_hash,
            ],
        );
        assert_eq!(digest, expected);
        let barrier = Arc::new(Barrier::new(8));
        let results = thread::scope(|scope| {
            let mut handles = Vec::new();
            for discriminant in [0_u16, 1, 42, 73, 369, 655, 4096, u16::MAX] {
                let barrier = Arc::clone(&barrier);
                let from = &from;
                let to = &to;
                let asset = &asset;
                let network_id = &network_id;
                handles.push(scope.spawn(move || {
                    let _guard = ChainDiscriminantGuard::enter(discriminant);
                    let source_display = from.to_string();
                    barrier.wait();
                    let digest = derive_zk_ace_transfer_digest(
                        from,
                        to,
                        asset,
                        amount,
                        network_id,
                        action_class,
                        &policy_hash,
                    )
                    .expect("display discriminant cannot affect domainless encoding");
                    (source_display, digest)
                }));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().expect("digest worker must not panic"))
                .collect::<Vec<_>>()
        });
        assert!(
            results
                .iter()
                .map(|(display, _)| display)
                .collect::<BTreeSet<_>>()
                .len()
                > 1,
            "adversarial workers must observe distinct ambient I105 displays"
        );
        assert!(
            results
                .iter()
                .all(|(_, observed_digest)| *observed_digest == digest),
            "ambient display state must not enter the consensus digest"
        );
    }
    fn valid_open_verify_admission_envelope() -> OpenVerifyEnvelope {
        OpenVerifyEnvelope::new(
            BackendTag::Stark,
            "stark/fri/poseidon-x7-goldilocks-6x64-v1:generic_binding_v1",
            [0x55; 32],
            vec![0x01, 0x02],
            vec![0x03, 0x04, 0x05],
        )
    }
    #[test]
    fn stark_fri_v1_backend_label_accepts_only_admitted_profiles() {
        assert!(is_stark_fri_v1_backend_label(ZK_BACKEND_STARK_FRI_V1));
        for backend in [
            "stark/fri",
            "stark/fri/poseidon2-goldilocks",
            "stark/fri/sha256_goldilocks.v1",
            "stark/fri/debug-proof",
            "stark/fri/mock",
            "stark/fri/latest",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1 ",
            "stark/fri/ sha256-goldilocks",
            "stark/fri/sha512-goldilocks",
            "stark/fri/poseidon2-goldilocks/extra",
            "stark/fri-v2",
            "halo2/ipa",
        ] {
            assert!(
                !is_stark_fri_v1_backend_label(backend),
                "{backend} must be rejected",
            );
        }
    }

    fn assert_json_roundtrip<T>(value: &T)
    where
        T: PartialEq
            + core::fmt::Debug
            + norito::json::JsonSerialize
            + norito::json::JsonDeserialize,
    {
        let json = norito::json::to_json(value).expect("serialize to json");
        let decoded: T = norito::json::from_json(&json).expect("deserialize from json");
        assert_eq!(&decoded, value);
    }
    #[test]
    fn backend_tag_norito_discriminants_are_exhaustive_and_canonical() {
        for (backend, expected_tag) in [(BackendTag::Halo2IpaPasta, 0u32), (BackendTag::Stark, 1)] {
            let encoded = backend.encode();
            assert_eq!(
                encoded.as_slice(),
                expected_tag.to_le_bytes().as_slice(),
                "{} must keep its Norito enum discriminant",
                backend.canonical_label()
            );
            let decoded = BackendTag::decode(&mut encoded.as_slice()).expect("decode backend tag");
            assert_eq!(decoded, backend);
            let framed = norito::to_bytes(&backend).expect("encode framed backend tag");
            let decoded: BackendTag =
                norito::decode_from_bytes(&framed).expect("decode framed backend tag");
            assert_eq!(decoded, backend);
        }
    }
    #[test]
    fn backend_tag_norito_rejects_unknown_discriminants() {
        for tag in [2_u32, 3, u32::MAX] {
            let encoded = tag.to_le_bytes();
            assert!(
                BackendTag::decode(&mut encoded.as_slice()).is_err(),
                "unknown discriminant {tag} must be rejected",
            );
        }
    }
    #[test]
    fn backend_tag_parser_accepts_only_canonical_engine_labels() {
        for (label, expected) in [
            ("halo2-ipa-pasta", BackendTag::Halo2IpaPasta),
            ("stark", BackendTag::Stark),
        ] {
            assert_eq!(
                BackendTag::from_canonical_label(label),
                Some(expected),
                "{label} must parse exactly",
            );
        }
    }
    #[test]
    fn verifier_backend_registry_is_closed_exact_and_engine_typed() {
        assert_eq!(ZK_VERIFIER_BACKEND_REGISTRY_LABELS_V1.len(), 7);
        let mut unique = std::collections::BTreeSet::new();
        for &label in ZK_VERIFIER_BACKEND_REGISTRY_LABELS_V1 {
            assert!(unique.insert(label), "duplicate registry label: {label}");
            let tag = verifier_backend_registry_tag_v1(label)
                .unwrap_or_else(|| panic!("listed registry label must resolve: {label}"));
            assert!(is_verifier_backend_registry_label_v1(label));
            if label.starts_with("halo2/") {
                assert_eq!(tag, BackendTag::Halo2IpaPasta, "{label}");
            } else {
                assert!(label.starts_with("stark/fri"), "{label}");
                assert_eq!(tag, BackendTag::Stark, "{label}");
            }
        }
        for rejected in [
            "",
            "halo2/pasta/ivm-execution-v1",
            " halo2/ipa",
            "halo2/ipa ",
            "HALO2/IPA",
            "halo2//ipa",
            "halo2/ipa:",
            "halo2/ipa:ivm-replay-binding-v1",
            "halo2/ipa::ivm-replay-binding-v1",
            "halo2/ipa/ivm-replay-binding-v1",
            "halo2/pasta/ipa/ivm-replay-binding-v1",
            "halo2/pasta/ivm-replay-binding-v1",
            "halo2/ipa:ivm-execution-v1",
            "halo2/ipa::ivm-execution-v1",
            "halo2/ipa/ivm-execution-v1",
            "halo2/pasta/ipa/ivm-execution-v1",
            "halo2/pasta/ivm-execution-v1",
            "halo2/pasta/ivm_execution_v1",
            "halo2/pasta/ivm-replay-binding-v1/",
            "halo2/pasta/ivm-replay-binding-v1\0",
            "halo2/pasta/ipa-pasta-cycle-v1",
            "halo2/pasta/ivm-overlay-bind",
            "halo2/pasta/tiny-add",
            "halo2/pasta/kaigi-roster-v1",
            "halo2/pasta/ipa/kaigi-roster-v1",
            "halo2/pasta/ipa/kaigi-authorization-v1",
            "halo2/pasta/kaigi-authorization-v1/",
            "stark",
            "stark/fri",
            "STARK/FRI",
            "stark/fri/",
            "stark/fri/latest",
            "stark/fri/poseidon2-goldilocks",
            "stark/fri/sha256_goldilocks.v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1/extra",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1\u{200b}",
            "groth16",
            "groth16/bn254",
            "halo2/bn254",
            "halo2/kzg",
            "aztec-plonkish-private-kernel",
            "zkat",
            "silent-threshold-anoncred",
            "sis-hints-anoncred-pq-v0",
            "sis-with-hints",
        ] {
            assert_eq!(
                verifier_backend_registry_tag_v1(rejected),
                None,
                "{rejected:?} must not resolve",
            );
            assert!(
                !is_verifier_backend_registry_label_v1(rejected),
                "{rejected:?} must be rejected",
            );
        }
    }
    #[test]
    fn backend_tag_parser_rejects_aliases_retired_families_and_adversarial_labels() {
        for label in [
            "halo2/ipa:kzg",
            "halo2/ipa:KZG",
            "halo2/ipa:bn254",
            "halo2/ipa:groth16",
            "halo2/ipa:trusted-setup",
            "halo2/ipa:universal-srs",
            "halo2/ipa:debug-proof",
            "halo2/ipa:d-e-b-u-g-proof",
            "halo2/ipa:mock-proof",
            "halo2/ipa:m-o-c-k-proof",
            "halo2/ipa:dev-fixture",
            "halo2/ipa:d-e-v-f-i-x-t-u-r-e",
            "halo2/ipa:todo-proof",
            "halo2/ipa:t-o-d-o-proof",
            "halo2/ipa:draft-proof",
            "halo2/ipa:d-r-a-f-t-proof",
            "halo2/ipa:pending-audit",
            "halo2/ipa:replace-before-production",
            "halo2/ipa:not-for-production",
            "halo2/ipa:placeholder",
            "halo2/ipa:p-l-a-c-e-h-o-l-d-e-r",
            "halo2/ipa:production-ready",
            "halo2/ipa:release-ready",
            "halo2/ipa:certified-mainnet",
            "halo2/ipa:third-party-audited",
            "halo2/ipa/orchard:production-ready",
            "orchard:mainnet-ready",
            "penumbra-masp:external-security-review",
            "monero-fcmp++:third-party-audited",
            "jindo-lattice-pcs-zk:release-ready",
            "miden-stark:dev-fixture",
            "aztec-private-kernel:mock-proof",
            "anonymous-pgc:placeholder",
            "sis-hints-anoncred-pq-v0",
            "sis-with-hints",
            "sis-with-hints:s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
            "halo2/ipa/orchard:kzg",
            "orchard:universal-srs",
            "penumbra-masp:kzg",
            "monero-fcmp++:bn254",
            "jindo-lattice-pcs-zk:trusted-setup",
            "miden-stark:ptau",
            "aztec-private-kernel:ceremony",
            "anonymous-pgc:bls12-381",
            "sis-with-hints:groth16",
            "pq-masp-stark-fri:kzg",
            "stark/fri/prod-kzg",
            "stark/fri/prod-bn-254",
            "stark/fri/prod-groth-16",
            "stark/fri/prod-srs",
            "stark/fri/prod-powers-of-tau",
            "stark/fri/dev-fixture",
            "stark/fri/d-e-v-f-i-x-t-u-r-e",
            "stark/fri/todo",
            "stark/fri/t-o-d-o",
            "stark/fri/draft-only",
            "stark/fri/d-r-a-f-t",
            "stark/fri/pending-audit",
            "stark/fri/replace-before-mainnet",
            "stark/fri/not-production-ready",
            "stark/fri/placeholder",
            "stark/fri/p-l-a-c-e-h-o-l-d-e-r",
            "stark/fri/production-ready",
            "stark/fri/release-approved",
            "stark/fri/boi-audited",
            "stark/fri/external-security-review",
            "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
        ] {
            assert!(
                BackendTag::from_canonical_label(label).is_none(),
                "{label} must not collapse into a supported backend tag",
            );
        }
    }
    #[test]
    fn open_verify_envelope_admission_validation_accepts_canonical_shape() {
        for backend in BackendTag::ALL {
            let mut envelope = valid_open_verify_admission_envelope();
            envelope.backend = backend;
            envelope
                .validate_for_admission()
                .unwrap_or_else(|error| panic!("{}: {error}", backend.canonical_label()));
        }
    }
    #[test]
    fn open_verify_envelope_admission_validation_accepts_portable_circuit_ids() {
        for circuit_id in [
            "stark/fri/poseidon-x7-goldilocks-6x64-v1:generic_binding_v1",
            "halo2/ipa::transfer_v1",
            "halo2/pasta/kaigi-usage-v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1:public_relation_v1",
        ] {
            let mut envelope = valid_open_verify_admission_envelope();
            envelope.circuit_id = circuit_id.to_owned();
            envelope
                .validate_for_admission()
                .unwrap_or_else(|err| panic!("{circuit_id} should be accepted: {err}"));
        }
    }
    #[test]
    fn open_verify_admission_reserves_every_exact12_privacy_namespace_and_retired_version() {
        use crate::privacy::PrivacyProtocolIdV1;
        fn assert_reserved(label: &str) {
            let stem = label
                .strip_suffix("-v1")
                .expect("every final Exact12 label ends in -v1");
            let snake_stem = stem.replace('-', "_");
            for reserved_label in [
                label.to_owned(),
                format!("{snake_stem}_v1"),
                format!("{stem}-v0"),
                format!("{snake_stem}_v0"),
            ] {
                for circuit_id in [
                    reserved_label.clone(),
                    format!("halo2/ipa::{reserved_label}"),
                    format!("halo2/pasta/{reserved_label}"),
                    format!("stark/fri:{reserved_label}"),
                    format!("stark/fri/poseidon-x7-goldilocks-6x64-v1:{reserved_label}"),
                    format!("generic/namespace/{reserved_label}"),
                ] {
                    assert!(
                        open_verify_circuit_id_is_portable(&circuit_id),
                        "reserved control {circuit_id:?} must otherwise be portable"
                    );
                    assert!(
                        open_verify_circuit_id_uses_reserved_privacy_protocol_namespace_v1(
                            &circuit_id
                        ),
                        "privacy namespace component must be detected in {circuit_id:?}"
                    );
                    let mut envelope = valid_open_verify_admission_envelope();
                    envelope.circuit_id = circuit_id.clone();
                    assert_eq!(
                        envelope.validate_for_admission().unwrap_err(),
                        OpenVerifyEnvelopeValidationError::ReservedPrivacyProtocolCircuitId,
                        "reserved generic circuit id {circuit_id:?}"
                    );
                }
            }
            for near_miss in [
                format!("generic-{label}"),
                format!("{label}-generic"),
                format!("stark/fri/poseidon-x7-goldilocks-6x64-v1:generic-{label}"),
                format!("halo2/ipa::{label}-generic"),
            ] {
                assert!(open_verify_circuit_id_is_portable(&near_miss));
                assert!(
                    !open_verify_circuit_id_uses_reserved_privacy_protocol_namespace_v1(&near_miss),
                    "portable near miss {near_miss:?} must remain outside the reservation"
                );
                let mut envelope = valid_open_verify_admission_envelope();
                envelope.circuit_id = near_miss.clone();
                envelope
                    .validate_for_admission()
                    .unwrap_or_else(|error| panic!("near miss {near_miss:?}: {error}"));
            }
        }
        for protocol in PrivacyProtocolIdV1::ALL {
            assert_reserved(protocol.canonical_label());
        }
    }
    #[test]
    fn open_verify_envelope_admission_validation_rejects_malformed_circuit_ids() {
        use OpenVerifyEnvelopeValidationError::{CircuitIdTooLarge, InvalidCircuitId};
        for (name, circuit_id) in [
            ("uppercase", "Stark/fri/sha256-goldilocks"),
            (
                "control",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1\nforged",
            ),
            (
                "zero-width",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1\u{200B}",
            ),
            ("path-traversal", "stark/fri/../zk_ace_pq_authorization_v1"),
            (
                "leading-delimiter",
                "/stark/fri/poseidon-x7-goldilocks-6x64-v1",
            ),
            (
                "trailing-delimiter",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1/",
            ),
            ("repeated-slash", "stark//fri/sha256-goldilocks"),
            ("dot-segment", "stark/fri/./zk_ace_pq_authorization_v1"),
            ("hidden-segment", "stark/fri/.zk_ace_pq_authorization_v1"),
            (
                "slash-colon-adjacent",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1/:zk_ace",
            ),
            (
                "colon-slash-adjacent",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:/zk_ace",
            ),
            (
                "dot-colon-adjacent",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1.:zk_ace",
            ),
            (
                "colon-dot-adjacent",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:.zk_ace",
            ),
            ("triple-colon", "halo2/ipa:::transfer_v1"),
            ("percent-escape", "stark/fri/%2e%2e/zk_ace"),
            ("backslash", "stark\\fri\\zk_ace"),
        ] {
            let mut envelope = valid_open_verify_admission_envelope();
            envelope.circuit_id = circuit_id.to_owned();
            assert_eq!(
                envelope.validate_for_admission().unwrap_err(),
                InvalidCircuitId,
                "{name}",
            );
        }
        let mut oversized = valid_open_verify_admission_envelope();
        oversized.circuit_id = "stark".to_owned();
        assert_eq!(
            oversized
                .validate_with_bounds(OpenVerifyEnvelopeBounds {
                    max_circuit_id_bytes: 4,
                    ..OpenVerifyEnvelopeBounds::default()
                })
                .unwrap_err(),
            CircuitIdTooLarge { len: 5, max: 4 },
            "oversized circuit id",
        );
    }
    #[test]
    fn open_verify_envelope_admission_validation_rejects_adversarial_shapes() {
        use OpenVerifyEnvelopeValidationError::{
            AllZeroProofBytes, AllZeroPublicInputs, EmptyCircuitId, EmptyProofBytes,
            EmptyPublicInputs, NonEmptyAux, ProofBytesTooLarge, PublicInputsTooLarge,
            ZeroVerifierKeyHash,
        };
        let cases: [(
            &str,
            fn(&mut OpenVerifyEnvelope),
            OpenVerifyEnvelopeValidationError,
        ); 10] = [
            (
                "empty circuit id",
                |env| env.circuit_id = " \t\n".to_owned(),
                EmptyCircuitId,
            ),
            (
                "zero verifier-key hash",
                |env| env.vk_hash = [0; 32],
                ZeroVerifierKeyHash,
            ),
            (
                "empty public inputs",
                |env| env.public_inputs.clear(),
                EmptyPublicInputs,
            ),
            (
                "all-zero public inputs",
                |env| env.public_inputs = vec![0; 3],
                AllZeroPublicInputs,
            ),
            (
                "oversized all-zero public inputs",
                |env| env.public_inputs = vec![0; 4],
                PublicInputsTooLarge { len: 4, max: 3 },
            ),
            (
                "oversized public inputs",
                |env| env.public_inputs = vec![0xAA; 4],
                PublicInputsTooLarge { len: 4, max: 3 },
            ),
            (
                "empty proof bytes",
                |env| env.proof_bytes.clear(),
                EmptyProofBytes,
            ),
            (
                "all-zero proof bytes",
                |env| env.proof_bytes = vec![0; 4],
                AllZeroProofBytes,
            ),
            (
                "oversized proof bytes",
                |env| env.proof_bytes = vec![0xBB; 5],
                ProofBytesTooLarge { len: 5, max: 4 },
            ),
            (
                "non-empty aux",
                |env| env.aux = b"side-channel".to_vec(),
                NonEmptyAux,
            ),
        ];
        for (name, mutate, expected) in cases {
            let mut envelope = valid_open_verify_admission_envelope();
            mutate(&mut envelope);
            let err = envelope
                .validate_with_bounds(OpenVerifyEnvelopeBounds {
                    max_public_input_bytes: 3,
                    max_proof_bytes: 4,
                    ..OpenVerifyEnvelopeBounds::default()
                })
                .unwrap_err();
            assert_eq!(err, expected, "{name}");
        }
    }

    /// The default proof bound of an `OpenVerify` envelope is inclusive: a proof field of
    /// exactly 64 MiB passes admission validation and one byte more is refused.
    #[test]
    fn open_verify_default_proof_bound_admits_the_limit_and_rejects_one_byte_over() {
        assert_eq!(OPEN_VERIFY_DEFAULT_MAX_PROOF_BYTES, 64 * 1024 * 1024);
        assert_eq!(
            OpenVerifyEnvelopeBounds::default().max_proof_bytes,
            OPEN_VERIFY_DEFAULT_MAX_PROOF_BYTES
        );
        let mut envelope = valid_open_verify_admission_envelope();
        envelope.proof_bytes = vec![0xA5; OPEN_VERIFY_DEFAULT_MAX_PROOF_BYTES];
        envelope
            .validate_for_admission()
            .expect("a proof field of exactly the bound is admitted");
        envelope.proof_bytes.push(0xA5);
        assert_eq!(
            envelope.validate_for_admission().unwrap_err(),
            OpenVerifyEnvelopeValidationError::ProofBytesTooLarge {
                len: OPEN_VERIFY_DEFAULT_MAX_PROOF_BYTES + 1,
                max: OPEN_VERIFY_DEFAULT_MAX_PROOF_BYTES,
            }
        );
    }

    /// The default bounds of the other fields of an `OpenVerify` envelope are inclusive too:
    /// a circuit identifier, a public-input field and an auxiliary field of exactly the
    /// bound pass validation and one byte more is refused. Admission refuses any auxiliary
    /// field, so its bound is exercised where a caller allows one.
    #[test]
    fn open_verify_default_field_bounds_admit_the_limit_and_reject_one_byte_over() {
        let defaults = OpenVerifyEnvelopeBounds::default();
        assert_eq!(
            (
                defaults.max_circuit_id_bytes,
                defaults.max_public_input_bytes,
                defaults.max_aux_bytes
            ),
            (
                OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES,
                OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES,
                OPEN_VERIFY_DEFAULT_MAX_AUX_BYTES
            )
        );
        assert_eq!(
            (
                OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES,
                OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES,
                OPEN_VERIFY_DEFAULT_MAX_AUX_BYTES
            ),
            (256, 1024 * 1024, 64 * 1024)
        );

        let mut envelope = valid_open_verify_admission_envelope();
        envelope.circuit_id = "c".repeat(OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES);
        envelope
            .validate_for_admission()
            .expect("a circuit identifier of exactly the bound is admitted");
        envelope.circuit_id.push('c');
        assert_eq!(
            envelope.validate_for_admission().unwrap_err(),
            OpenVerifyEnvelopeValidationError::CircuitIdTooLarge {
                len: OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES + 1,
                max: OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES,
            }
        );

        let mut envelope = valid_open_verify_admission_envelope();
        envelope.public_inputs = vec![0xA5; OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES];
        envelope
            .validate_for_admission()
            .expect("a public-input field of exactly the bound is admitted");
        envelope.public_inputs.push(0xA5);
        assert_eq!(
            envelope.validate_for_admission().unwrap_err(),
            OpenVerifyEnvelopeValidationError::PublicInputsTooLarge {
                len: OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES + 1,
                max: OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES,
            }
        );

        let with_aux = OpenVerifyEnvelopeBounds {
            allow_aux: true,
            ..OpenVerifyEnvelopeBounds::default()
        };
        let mut envelope = valid_open_verify_admission_envelope();
        envelope.aux = vec![0x5A; OPEN_VERIFY_DEFAULT_MAX_AUX_BYTES];
        envelope
            .validate_with_bounds(with_aux)
            .expect("an auxiliary field of exactly the bound passes where one is allowed");
        assert_eq!(
            envelope.validate_for_admission().unwrap_err(),
            OpenVerifyEnvelopeValidationError::NonEmptyAux,
            "admission refuses every auxiliary field"
        );
        envelope.aux.push(0x5A);
        assert_eq!(
            envelope.validate_with_bounds(with_aux).unwrap_err(),
            OpenVerifyEnvelopeValidationError::AuxTooLarge {
                len: OPEN_VERIFY_DEFAULT_MAX_AUX_BYTES + 1,
                max: OPEN_VERIFY_DEFAULT_MAX_AUX_BYTES,
            }
        );
    }

    #[test]
    fn backend_tag_json_accepts_only_exact_canonical_labels() {
        for backend in BackendTag::ALL {
            let json = format!("\"{}\"", backend.canonical_label());
            let decoded = norito::json::from_str::<BackendTag>(&json)
                .expect("canonical backend label must decode");
            assert_eq!(decoded, backend);
            assert_json_roundtrip(&backend);
        }
        for alias in [
            "",
            "halo2/ipa",
            "HALO2-IPA-PASTA",
            " halo2-ipa-pasta",
            "halo2-ipa-pasta ",
            "halo2_ipa_pasta",
            "halo2-ipa-pasta\0",
            "stark/fri",
            "STARK",
            "stark ",
            "st\u{0430}rk",
            "halo2-bn254",
            "groth16",
            "groth16/bn254",
            "unsupported",
            "halo2-ipa-orchard",
            "orchard",
            "groth16-bls12-377",
            "fcmp-plus-plus-curve-tree",
            "lattice-pcs-sis",
            "miden-stark",
            "aztec-plonkish-private-kernel",
            "pq-masp-stark-fri",
            "anonymous-pgc",
            "verange",
            "zkat",
            "recursive-anonymous-admission",
            "vega-existing-credential-zk",
            "silent-threshold-anoncred",
            "zk-x509",
            "sis-hints-anoncred-pq-v0",
            "sis-with-hints",
            "unknown/privacy/backend",
        ] {
            let json = norito::json::to_json(alias).expect("encode adversarial label");
            norito::json::from_str::<BackendTag>(&json)
                .expect_err("backend aliases and unknown labels must be rejected by JSON");
        }
        for invalid_json in ["null", "true", "0", "{}", "[]"] {
            norito::json::from_str::<BackendTag>(invalid_json)
                .expect_err("non-string backend labels must be rejected");
        }
    }
    #[test]
    fn open_verify_envelope_validation_allows_explicit_aux_and_zero_key_only_when_configured() {
        let mut envelope = valid_open_verify_admission_envelope();
        envelope.vk_hash = [0; 32];
        envelope.aux = b"bounded-aux".to_vec();
        envelope
            .validate_with_bounds(OpenVerifyEnvelopeBounds {
                allow_aux: true,
                require_nonzero_vk_hash: false,
                max_aux_bytes: envelope.aux.len(),
                ..OpenVerifyEnvelopeBounds::default()
            })
            .expect("custom non-admission bounds can allow zero key and aux");
        let err = envelope
            .validate_with_bounds(OpenVerifyEnvelopeBounds {
                allow_aux: true,
                require_nonzero_vk_hash: false,
                max_aux_bytes: envelope.aux.len() - 1,
                ..OpenVerifyEnvelopeBounds::default()
            })
            .unwrap_err();
        assert_eq!(
            err,
            OpenVerifyEnvelopeValidationError::AuxTooLarge {
                len: envelope.aux.len(),
                max: envelope.aux.len() - 1,
            }
        );
    }
    #[test]
    fn zk_ace_identity_preimage_is_erased_on_return_and_unwind() {
        for unwind in [false, true] {
            let mut scratch = [0_u8; 64];
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let guarded = ZkAceIdentityPreimageGuard(&mut scratch);
                guarded.0.fill(0xa5);
                assert!(!unwind, "exercise private preimage cleanup")
            }));
            assert_eq!(result.is_err(), unwind);
            assert_eq!(scratch, [0; 64]);
        }
    }

    #[test]
    fn zk_ace_identity_commitment_binds_each_private_component_and_domain() {
        let root = [0x11; 32];
        let blinding = [0x22; 32];
        let domain = ZK_ACE_PQ_AUTHORIZATION_V1_DOMAIN_TAG;
        let original = derive_zk_ace_identity_commitment(&root, &blinding, domain);
        for index in [0, 15, 31] {
            let mut changed_root = root;
            changed_root[index] ^= 1;
            assert_ne!(
                original,
                derive_zk_ace_identity_commitment(&changed_root, &blinding, domain)
            );
            let mut changed_blinding = blinding;
            changed_blinding[index] ^= 1;
            assert_ne!(
                original,
                derive_zk_ace_identity_commitment(&root, &changed_blinding, domain)
            );
        }
        assert_ne!(
            original,
            derive_zk_ace_identity_commitment(&root, &blinding, "other-domain")
        );
        assert_eq!(root, [0x11; 32]);
        assert_eq!(blinding, [0x22; 32]);
    }

    #[test]
    fn zk_ace_packing_and_hash_vectors_are_stable() {
        let packed = zk_ace_pack_bytes_to_field_limbs(b"ABCDEFGH");
        assert_eq!(packed.length, 8);
        assert_eq!(packed.limbs, vec![0x0047_4645_4443_4241, 0x48]);
        let identity_root = [0x11; 32];
        let identity_blinding = [0x22; 32];
        let replay_secret = [0x33; 32];
        let policy_hash = [0x44; 32];
        let network_id = network_id(0x45);
        let from = account(1);
        let to = account(2);
        let asset = asset_definition_id();
        let identity_commitment = derive_zk_ace_identity_commitment(
            &identity_root,
            &identity_blinding,
            ZK_ACE_PQ_AUTHORIZATION_V1_DOMAIN_TAG,
        );
        let tx_digest = derive_zk_ace_transfer_digest(
            &from,
            &to,
            &asset,
            17,
            &network_id,
            ZK_ACE_PQ_AUTHORIZATION_V1_ACTION_TRANSFER,
            &policy_hash,
        )
        .expect("single-key fixture accounts have canonical encodings");
        let replay_nullifier = derive_zk_ace_replay_nullifier(
            &replay_secret,
            &tx_digest,
            &network_id,
            ZK_ACE_PQ_AUTHORIZATION_V1_ACTION_TRANSFER,
            ZK_ACE_PQ_AUTHORIZATION_V1_DOMAIN_TAG,
        );
        assert_eq!(
            hex::encode(identity_commitment.as_bytes()),
            "1eea6c6ac08b188b9b8902f545257924b1c7296e523d7e9d8b83a48d3dd4b6080e5c67ba09bb9a5bf692d6ef2cd18063"
        );
        assert_eq!(
            hex::encode(tx_digest.to_le_bytes()),
            "f5ca14b54445acea75f775e4cc276310e88a6e73d50eac360603ee13a70dc6c95f1e2cdb5c15d277771c3077a5b9ea31"
        );
        assert_eq!(
            hex::encode(replay_nullifier.as_bytes()),
            "3a561ef8446963f7a969e59483443e8a5a58dccbc37f3d2fabe1acb46243cb4ff6fd1a2cbcd65feddd775cd01bc4486f"
        );
    }
    #[test]
    fn zk_ace_six_lane_domains_reject_cross_role_substitution() {
        let fields: [&[u8]; 2] = [b"same", b"preimage"];
        let identity = zk_ace_digest384_v1(
            ZK_ACE_IDENTITY_COMMITMENT_ROLE_V1,
            ZK_ACE_IDENTITY_COMMITMENT_PHASE_V1,
            &fields,
        );
        let replay = zk_ace_digest384_v1(
            ZK_ACE_REPLAY_NULLIFIER_ROLE_V1,
            ZK_ACE_REPLAY_NULLIFIER_PHASE_V1,
            &fields,
        );
        let phase_substitution = zk_ace_digest384_v1(
            ZK_ACE_IDENTITY_COMMITMENT_ROLE_V1,
            ZK_ACE_REPLAY_NULLIFIER_PHASE_V1,
            &fields,
        );
        assert_ne!(identity, replay);
        assert_ne!(identity, phase_substitution);
        assert_ne!(replay, phase_substitution);
        assert_eq!(
            identity
                .words()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            fastpq_isi::GOLDILOCKS_DIGEST384_LANES_V1,
            "independently parameterized lanes must not collapse on the KAT input"
        );
    }

    #[test]
    fn zk_ace_json_roundtrips_generic_stark_wrapper_and_packing() {
        let packed = zk_ace_pack_bytes_to_field_limbs(b"ABCDEFGH");
        let open_proof = StarkFriOpenProofV1 {
            version: 1,
            public_inputs: vec![vec![[0xAA; 32], [0xBB; 32]], vec![[0xCC; 32]]],
            envelope_bytes: vec![0x01, 0x02, 0x03, 0x04],
        };
        assert_json_roundtrip(&packed);
        assert_json_roundtrip(&open_proof);
    }
}

#[cfg(test)]
mod captured_zk_schema_tests;
