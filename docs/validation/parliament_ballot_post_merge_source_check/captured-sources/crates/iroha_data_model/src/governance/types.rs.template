//! Canonical governance and SORA Parliament data-model types.
//!
//! V1 Parliament types distinguish immutable proposal content from retryable
//! governance, body-election, and ballot attempts. Consensus code must use the
//! typed identifiers and closed lifecycle enums defined here rather than
//! reconstructing stage or result semantics from strings.
//!
//! Notes:
//! - Use the `SignedBlock` v1 Norito serialization for any `call_selector(inner)` and certificate hashing contexts.
//! - Fixed-point thresholds are represented as integers; Q-format mapping is specified in docs.
use crate::{
    NetworkId,
    account::AccountId,
    asset::AssetId,
    isi::sorafs::SorafsProviderGovernanceActionV1,
    musubi::MusubiParliamentActionV1,
    runtime::RuntimeUpgradeManifest,
    smart_contract::{ContractAddress, manifest::ManifestProvenance},
    validation_fee::{ValidationFeePolicyV1, ValidationFeeTreasuryPayoutBindingV1},
};
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use norito::json::{self, JsonDeserialize, JsonSerialize, Parser};
use std::{collections::BTreeSet, fmt, str::FromStr, string::String, vec::Vec};

/// Voting mode for a referendum.
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
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::VotingMode")]
pub enum VotingMode {
    /// Zero-knowledge voting flow (default ballot type).
    Zk,
    /// Plain-text quadratic voting flow.
    Plain,
}

impl norito::json::JsonSerialize for VotingMode {
    fn json_serialize(&self, out: &mut String) {
        norito::json::write_json_string(
            match self {
                Self::Zk => "Zk",
                Self::Plain => "Plain",
            },
            out,
        );
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(
            match self {
                Self::Zk => "Zk",
                Self::Plain => "Plain",
            },
            out,
        )
    }
}

impl norito::json::JsonDeserialize for VotingMode {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        match value.as_str() {
            "Zk" => Ok(Self::Zk),
            "Plain" => Ok(Self::Plain),
            other => Err(norito::json::Error::unknown_field(other.to_owned())),
        }
    }
}
/// Errors emitted when parsing hex-encoded hashes used by governance payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashParseError {
    /// The decoded byte length differed from the expected size.
    InvalidLength {
        /// Number of bytes required by the target hash type.
        expected: usize,
        /// Actual number of bytes produced by the decoder.
        actual: usize,
    },
    /// The provided string was not valid lowercase hexadecimal.
    InvalidHex {
        /// Human-readable error message returned by the hex decoder.
        message: String,
    },
}
impl fmt::Display for HashParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            Self::InvalidHex { message } => write!(f, "{message}"),
        }
    }
}
impl std::error::Error for HashParseError {}
const HASH_WIRE_VERSION_V1: u16 = 1;
#[derive(Clone, Copy, Debug, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::HashWire32")]
#[norito(decode_fields)]
struct HashWire32 {
    version: u16,
    declared_len: u16,
    bytes: [u8; 32],
}
fn decode_prepared_hash32_field<T>(
    field: norito::core::CanonicalField<'_, T>,
) -> Result<[u8; 32], norito::core::DecodeIntoError<std::convert::Infallible>> {
    use norito::core::{
        CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, DecodeRecordFields,
        FieldDestination,
    };
    struct Fields(HashWire32);
    impl FieldDestination for Fields {
        type Error = std::convert::Infallible;
    }
    impl DecodeField<0, u16> for Fields {
        type Value = ();
        fn decode_field(
            &mut self,
            field: CanonicalField<'_, u16>,
        ) -> Result<(), DecodeIntoError<Self::Error>> {
            field.with_payload(|bytes| {
                let (value, used) = u16::decode_from_slice(bytes)?;
                if used != bytes.len() {
                    return Err(norito::Error::LengthMismatch.into());
                }
                self.0.version = value;
                Ok(())
            })
        }
    }
    impl DecodeField<1, u16> for Fields {
        type Value = ();
        fn decode_field(
            &mut self,
            field: CanonicalField<'_, u16>,
        ) -> Result<(), DecodeIntoError<Self::Error>> {
            field.with_payload(|bytes| {
                let (value, used) = u16::decode_from_slice(bytes)?;
                if used != bytes.len() {
                    return Err(norito::Error::LengthMismatch.into());
                }
                self.0.declared_len = value;
                Ok(())
            })
        }
    }
    impl DecodeField<2, [u8; 32]> for Fields {
        type Value = ();
        fn decode_field(
            &mut self,
            field: CanonicalField<'_, [u8; 32]>,
        ) -> Result<(), DecodeIntoError<Self::Error>> {
            // The original generated raw byte-array field has alignment one,
            // exact length and no alignment or owned-child allocation.
            self.0.bytes = field.decode_owned()?;
            Ok(())
        }
    }
    field.with_payload(|bytes| {
        let mut destination = Fields(HashWire32::new([0; 32]));
        let (_, used) = HashWire32::decode_fields(bytes, &mut destination)?;
        if used != bytes.len() {
            return Err(norito::Error::LengthMismatch.into());
        }
        destination
            .0
            .try_into_bytes()
            .map_err(DecodeIntoError::Codec)
    })
}
impl HashWire32 {
    const fn new(bytes: [u8; 32]) -> Self {
        Self {
            version: HASH_WIRE_VERSION_V1,
            declared_len: 32,
            bytes,
        }
    }
    fn try_into_bytes(self) -> Result<[u8; 32], norito::core::Error> {
        if self.version != HASH_WIRE_VERSION_V1 {
            return Err(norito::core::Error::LengthMismatch);
        }
        if self.declared_len as usize != 32 {
            return Err(norito::core::Error::LengthMismatch);
        }
        Ok(self.bytes)
    }
}
fn decode_hex_array<const N: usize>(input: &str) -> Result<[u8; N], HashParseError> {
    if !input.len().is_multiple_of(2) {
        return Err(HashParseError::InvalidHex {
            message: "hash must contain an even number of hexadecimal digits".to_owned(),
        });
    }
    if input.len() / 2 != N {
        return Err(HashParseError::InvalidLength {
            expected: N,
            actual: input.len() / 2,
        });
    }
    let mut array = [0_u8; N];
    hex::decode_to_slice(input, &mut array).map_err(|err| HashParseError::InvalidHex {
        message: format!("{err}"),
    })?;
    Ok(array)
}
fn decode_lowercase_hex_array<const N: usize>(input: &str) -> Result<[u8; N], HashParseError> {
    if !input
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HashParseError::InvalidHex {
            message: "hash must use lowercase hexadecimal without a prefix".to_owned(),
        });
    }
    decode_hex_array(input)
}
macro_rules! define_hash32_newtype {
    ($name:ident, $schema_name:literal, $doc:literal) => {
        #[doc = $doc]
        /// JSON values and object keys use exactly 64 lowercase hexadecimal digits.
        #[repr(transparent)]
        #[derive(
            Clone,
            Copy,
            Debug,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(name = $schema_name)]
        pub struct $name([u8; 32]);
        impl $name {
            /// Decode an original canonical field through the same hash-wire
            /// walk and version/length checks using only fixed stack storage.
            ///
            /// This prepared leaf allocates no alignment buffer and grants no
            /// complete-frame authority; the enclosing canonical verifier must
            /// still authenticate the original frame and its advertised flags.
            ///
            /// # Errors
            /// Returns the original field, depth, resource or hash-wire error.
            pub fn decode_prepared_field_v1(
                field: norito::core::CanonicalField<'_, Self>,
            ) -> Result<Self, norito::core::DecodeIntoError<std::convert::Infallible>> {
                decode_prepared_hash32_field(field).map(Self)
            }
            /// Number of bytes in the encoded hash.
            pub const LENGTH: usize = 32;
            /// Construct the hash wrapper from raw bytes.
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// Attempt to parse the hash from a lowercase hexadecimal string.
            ///
            /// # Errors
            /// Returns [`HashParseError`] when the input is not a valid 32-byte hex string.
            pub fn from_hex_str(input: &str) -> Result<Self, HashParseError> {
                decode_lowercase_hex_array::<32>(input).map(Self)
            }
            /// Borrow the raw hash bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            /// Consume the wrapper and return the raw bytes.
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
            /// Render the hash as a lowercase hexadecimal string.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }
        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self::new(bytes)
            }
        }
        impl From<$name> for [u8; 32] {
            fn from(hash: $name) -> Self {
                hash.into_bytes()
            }
        }
        impl AsRef<[u8; 32]> for $name {
            fn as_ref(&self) -> &[u8; 32] {
                self.as_bytes()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }
        impl norito::core::SerializePayload for $name {
            fn serialize(
                &self,
                writer: &mut norito::core::Encoder<'_>,
            ) -> Result<(), norito::core::Error> {
                let wire = HashWire32::new(self.0);
                <HashWire32 as norito::core::SerializePayload>::serialize(&wire, writer)
            }
            fn encoded_len_hint(&self) -> Option<usize> {
                let wire = HashWire32::new(self.0);
                <HashWire32 as norito::core::SerializePayload>::encoded_len_hint(&wire)
            }
            fn encoded_len_exact(&self) -> Option<usize> {
                let wire = HashWire32::new(self.0);
                <HashWire32 as norito::core::SerializePayload>::encoded_len_exact(&wire)
            }
        }
        impl<'de> norito::core::DeserializePayload<'de> for $name {
            fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
                Self::try_deserialize(archived).expect("fixed-length hash decode should succeed")
            }
            fn try_deserialize(
                archived: &'de norito::core::Archived<Self>,
            ) -> Result<Self, norito::core::Error> {
                let ptr = core::ptr::from_ref(archived).cast::<u8>();
                let bytes = norito::core::payload_slice_from_ptr(ptr)?;
                let (wire, _used) = norito::core::decode_field_canonical::<HashWire32>(bytes)?;
                wire.try_into_bytes().map(Self)
            }
        }
        impl<'a> norito::core::DecodeFromSlice<'a> for $name {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let (wire, used) = norito::core::decode_field_canonical::<HashWire32>(bytes)?;
                wire.try_into_bytes().map(|array| (Self(array), used))
            }
        }

        impl JsonSerialize for $name {
            fn json_serialize(&self, out: &mut String) {
                json::write_json_string(&self.to_hex(), out);
            }
            fn json_serialize_to(
                &self,
                out: &mut dyn json::JsonWriteSink,
            ) -> Result<(), json::BoundedJsonError> {
                json::write_json_string_to(&self.to_hex(), out)
            }
        }

        impl JsonDeserialize for $name {
            fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, json::Error> {
                let buf = parser.parse_string()?;
                Self::from_hex_str(&buf).map_err(|err| json::Error::Message(format!("{err}")))
            }
        }

        impl json::JsonObjectKey for $name {
            fn visit_json_key_text<E>(
                &self,
                mut visitor: impl FnMut(&str) -> Result<(), E>,
            ) -> Result<(), E> {
                const HEX: &str = "0123456789abcdef";
                for byte in &self.0 {
                    let high = usize::from(byte >> 4);
                    let low = usize::from(byte & 0x0f);
                    visitor(&HEX[high..=high])?;
                    visitor(&HEX[low..=low])?;
                }
                Ok(())
            }
        }

        impl json::JsonObjectKeyOwned for $name {
            fn from_json_key_text(key: &str) -> Result<Self, json::Error> {
                if key.len() != Self::LENGTH * 2 {
                    return Err(json::Error::Message(
                        "governance hash key must contain exactly 64 lowercase hex digits"
                            .to_owned(),
                    ));
                }
                Self::from_hex_str(key).map_err(|err| json::Error::Message(err.to_string()))
            }
        }
        impl FromStr for $name {
            type Err = HashParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::from_hex_str(s)
            }
        }
    };
}
define_hash32_newtype!(
    ContractCodeHash,
    "iroha_data_model::parliament_types::ContractCodeHash",
    "Blake2b-32 hash identifying a contract bytecode artifact."
);
define_hash32_newtype!(
    ContractAbiHash,
    "iroha_data_model::parliament_types::ContractAbiHash",
    "Blake2b-32 hash describing the ABI surface of a contract."
);
define_hash32_newtype!(
    AgendaItemId,
    "iroha_data_model::parliament_types::AgendaItemId",
    "Immutable content identifier for an admitted Parliament agenda item."
);
define_hash32_newtype!(
    DraftId,
    "iroha_data_model::parliament_types::DraftId",
    "Immutable content identifier for a deliberative Parliament draft."
);
define_hash32_newtype!(
    ProposalContentId,
    "iroha_data_model::parliament_types::ProposalContentId",
    "Immutable identifier for proposal content shared by every retry attempt."
);
define_hash32_newtype!(
    GovernanceAttemptId,
    "iroha_data_model::parliament_types::GovernanceAttemptId",
    "Identifier for one retryable end-to-end governance attempt."
);
define_hash32_newtype!(
    BodyInstanceId,
    "iroha_data_model::parliament_types::BodyInstanceId",
    "Identifier for one sealed Parliament body instance."
);
define_hash32_newtype!(
    BodyElectionAttemptId,
    "iroha_data_model::parliament_types::BodyElectionAttemptId",
    "Identifier for one retryable Parliament body-election attempt."
);
define_hash32_newtype!(
    AssignmentId,
    "iroha_data_model::parliament_types::AssignmentId",
    "Identifier for one deterministic Parliament service assignment."
);
define_hash32_newtype!(
    SortitionRequestId,
    "iroha_data_model::parliament_types::SortitionRequestId",
    "Identifier for one immutable future-pulse sortition request."
);
define_hash32_newtype!(
    BallotAttemptId,
    "iroha_data_model::parliament_types::BallotAttemptId",
    "Identifier for one retryable hidden Parliament ballot attempt."
);
define_hash32_newtype!(
    BeaconSessionId,
    "iroha_data_model::parliament_types::BeaconSessionId",
    "Stable network-scoped identifier for the logical Parliament beacon."
);
impl BeaconSessionId {
    /// Derive the canonical stable Parliament beacon identifier for a network.
    ///
    /// This logical identifier deliberately does not name a DKG key session;
    /// future Parliament slots remain valid across legitimate validator-roster
    /// and threshold-key rotations.
    #[must_use]
    pub fn for_network_v1(network_id: &NetworkId) -> Self {
        let mut bytes = crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::LOGICAL_BEACON_SESSION_ID_V1,
            network_id,
        );
        if bytes.iter().all(|byte| *byte == 0) {
            bytes[0] = 1;
        }
        Self::new(bytes)
    }
}
define_hash32_newtype!(
    BeaconPulseId,
    "iroha_data_model::parliament_types::BeaconPulseId",
    "Identifier for one finalized threshold-beacon pulse."
);
define_hash32_newtype!(
    TleSessionId,
    "iroha_data_model::parliament_types::TleSessionId",
    "Identifier for one ballot-specific threshold timelock-encryption session."
);
define_hash32_newtype!(
    TleKeySessionId,
    "iroha_data_model::parliament_types::TleKeySessionId",
    "Identifier for one finalized threshold-BLS key session dedicated to TLE releases."
);
define_hash32_newtype!(
    GovernanceCertificateId,
    "iroha_data_model::parliament_types::GovernanceCertificateId",
    "Content identifier for one finalized V1 governance certificate."
);

/// ABI version targeted by the contract manifest.
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
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::AbiVersion")]
pub struct AbiVersion(u16);
impl AbiVersion {
    /// Create a new ABI version wrapper.
    pub const fn new(version: u16) -> Self {
        Self(version)
    }
    /// Borrow the underlying numeric version.
    pub const fn get(self) -> u16 {
        self.0
    }
}
impl Default for AbiVersion {
    fn default() -> Self {
        Self::new(1)
    }
}
impl From<u16> for AbiVersion {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}
impl From<AbiVersion> for u16 {
    fn from(version: AbiVersion) -> Self {
        version.get()
    }
}
impl fmt::Display for AbiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl JsonSerialize for AbiVersion {
    fn json_serialize(&self, out: &mut String) {
        json::JsonSerialize::json_serialize(&self.0, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.0.json_serialize_to(out)
    }
}

impl JsonDeserialize for AbiVersion {
    fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, json::Error> {
        u16::json_deserialize(parser).map(Self::from)
    }
}
/// Largest integer admitted in first-release public JSON number fields.
///
/// Public proposal JSON is consumed by SDK runtimes whose number type is IEEE-754 binary64.
/// Bounding every number-encoded `u64` at `2^53 - 1` keeps those values exact without giving
/// structurally shared runtime, Musubi, or SCCP types a context-specific string encoding.
pub const FIRST_RELEASE_MAX_EXACT_JSON_U64: u64 = (1_u64 << 53) - 1;
/// Governance proposal kinds supported today.
#[allow(
    clippy::large_enum_variant,
    reason = "proposal variants retain their canonical public Norito payload shapes"
)]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(tag = "kind", content = "payload", deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ProposalKind")]
pub enum ProposalKind {
    /// Deploy an IVM contract identified by its canonical public address and content hashes.
    #[codec(index = 0)]
    DeployContract(DeployContractProposal),
    /// Schedule a runtime upgrade manifest through governance.
    #[codec(index = 1)]
    RuntimeUpgrade(RuntimeUpgradeProposal),
    /// Apply one SCCP v1 governance proposal (`specs/sccp.md` §4.14.3).
    #[codec(index = 2)]
    SccpRouteGovernance(SccpRouteGovernanceProposal),
    /// Enact one validation-fee policy through SORA Parliament.
    #[codec(index = 3)]
    ValidationFeePolicy(ValidationFeePolicyProposal),
    /// Authorize one exact validation-fee treasury payout lifecycle.
    #[codec(index = 4)]
    ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal),
    /// Enact one exact Musubi recovery, alias-retarget, takedown, or policy action.
    #[codec(index = 5)]
    MusubiRegistryGovernance(MusubiParliamentActionV1),
    /// Establish, replace, or remove one `SoraFS` provider owner through governance.
    #[codec(index = 6)]
    SorafsProviderGovernance(SorafsProviderGovernanceProposal),
    /// Apply one owner-consented contract lifecycle transition.
    #[codec(index = 7)]
    ContractLifecycleGovernance(ContractLifecycleGovernanceProposalV1),
    /// Impose one narrow, time-bounded emergency execution hold.
    #[codec(index = 8)]
    ContractEmergencyHold(ContractEmergencyHoldProposalV1),
    /// Grant or revoke one exact account's global data-trigger capability.
    #[codec(index = 9)]
    GlobalDataTriggerPermissionGovernance(GlobalDataTriggerPermissionGovernanceProposalV1),
}
/// Proposal payload for deploying an IVM contract via governance.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::DeployContractProposal")]
pub struct DeployContractProposal {
    /// Canonical transaction authority that created this proposal.
    ///
    /// The operator is part of the exact proposal and effect preimages so
    /// transaction ordering cannot change deployment provenance.
    pub proposal_operator: AccountId,
    /// Canonical public contract address governed by the proposal.
    pub contract_address: ContractAddress,
    /// Blake2b-32 hash of the compiled `.to` bytecode.
    pub code_hash: ContractCodeHash,
    /// Blake2b-32 hash of the ABI surface expected by hosts.
    pub abi_hash: ContractAbiHash,
    /// ABI version (currently `1`).
    pub abi_version: AbiVersion,
    /// Optional manifest provenance used to attest the manifest when absent on-chain.
    #[norito(required)]
    pub manifest_provenance: Option<ManifestProvenance>,
}
/// Owner-consented lifecycle action available to Parliament.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ActivateContractGovernanceActionV1")]
pub struct ActivateContractGovernanceActionV1 {
    /// Exact compiled artifact hash.
    pub code_hash: ContractCodeHash,
    /// Exact ABI surface hash.
    pub abi_hash: ContractAbiHash,
    /// ABI version (currently `1`).
    pub abi_version: AbiVersion,
    /// Optional provenance used when the manifest is absent on-chain.
    #[norito(required)]
    pub manifest_provenance: Option<ManifestProvenance>,
}
/// Payload for a governed contract deactivation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::DeactivateContractGovernanceActionV1")]
pub struct DeactivateContractGovernanceActionV1 {
    /// Exact active code hash expected by the proposal.
    pub expected_code_hash: ContractCodeHash,
    /// Optional audit reason.
    pub reason: Option<String>,
}
/// Payload for a Parliament-owned contract's ownership offer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::parliament_types::OfferContractOwnershipGovernanceActionV1"
)]
pub struct OfferContractOwnershipGovernanceActionV1 {
    /// Proposed account owner.
    pub new_owner: AccountId,
}
/// Payload completing the mandatory retrospective for one expired emergency hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::parliament_types::CompleteContractEmergencyHoldRetrospectiveGovernanceActionV1"
)]
pub struct CompleteContractEmergencyHoldRetrospectiveGovernanceActionV1 {
    /// Exact proposal content identifier retained by the hold being reviewed.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub hold_proposal_content_id: [u8; 32],
    /// Exact governance-attempt identifier retained by the hold being reviewed.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub hold_governance_attempt_id: [u8; 32],
    /// Exact incident digest retained by the hold being reviewed.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub incident_digest: [u8; 32],
    /// Non-zero root of Parliament's certified retrospective finding.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub retrospective_finding_root: [u8; 32],
}
/// Certificate-enacted lifecycle action available to Parliament.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "action", content = "payload", deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ContractLifecycleGovernanceActionV1")]
pub enum ContractLifecycleGovernanceActionV1 {
    /// Activate or replace the contract's code.
    #[codec(index = 0)]
    Activate(ActivateContractGovernanceActionV1),
    /// Deactivate the currently active code.
    #[codec(index = 1)]
    Deactivate(DeactivateContractGovernanceActionV1),
    /// Offer Parliament-owned lifecycle authority to an account.
    #[codec(index = 2)]
    OfferOwnership(OfferContractOwnershipGovernanceActionV1),
    /// Cancel Parliament's outstanding ownership offer.
    #[codec(index = 3)]
    CancelOwnershipOffer,
    /// Accept an account owner's outstanding offer to Parliament.
    #[codec(index = 4)]
    AcceptParliamentOwnership,
    /// Complete the certified retrospective for one expired emergency hold.
    #[codec(index = 5)]
    CompleteEmergencyHoldRetrospective(
        CompleteContractEmergencyHoldRetrospectiveGovernanceActionV1,
    ),
}

/// Complete compare-and-swap proposal for a certificate-enacted lifecycle transition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ContractLifecycleGovernanceProposalV1")]
pub struct ContractLifecycleGovernanceProposalV1 {
    /// Canonical transaction authority that created this proposal.
    ///
    /// The operator is part of the exact proposal and effect preimages because
    /// activation and deactivation consume its lifecycle authority.
    pub proposal_operator: AccountId,
    /// Contract whose lifecycle changes.
    pub contract_address: ContractAddress,
    /// Exact lifecycle revision required at enactment.
    pub expected_revision: u64,
    /// Closed lifecycle action; any variant is applied only by exact-due certificate execution.
    pub action: ContractLifecycleGovernanceActionV1,
}

/// Complete emergency-containment proposal for one active contract.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ContractEmergencyHoldProposalV1")]
pub struct ContractEmergencyHoldProposalV1 {
    /// Contract whose execution is contained.
    pub contract_address: ContractAddress,
    /// Exact lifecycle revision required at enactment.
    pub expected_revision: u64,
    /// Exact active code hash required at enactment.
    pub expected_code_hash: ContractCodeHash,
    /// Non-zero digest of the incident evidence.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub incident_digest: [u8; 32],
    /// Human-readable containment reason.
    pub reason: String,
    /// Hold duration, bounded by `MAX_CONTRACT_EMERGENCY_HOLD_BLOCKS_V1`.
    pub duration_blocks: u64,
}
/// Closed Parliament action for the global data-trigger capability.
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
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(
    tag = "action",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::parliament_types::GlobalDataTriggerPermissionGovernanceActionV1"
)]
pub enum GlobalDataTriggerPermissionGovernanceActionV1 {
    /// Grant the capability to the exact account.
    #[codec(index = 0)]
    Grant,
    /// Revoke the capability from the exact account.
    #[codec(index = 1)]
    Revoke,
}
/// Complete Parliament proposal for one exact account's global data-trigger capability.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::parliament_types::GlobalDataTriggerPermissionGovernanceProposalV1"
)]
pub struct GlobalDataTriggerPermissionGovernanceProposalV1 {
    /// Exact account whose capability is granted or revoked.
    pub authority: AccountId,
    /// Closed grant-or-revoke effect.
    pub action: GlobalDataTriggerPermissionGovernanceActionV1,
}
/// Proposal payload for scheduling a runtime upgrade through governance.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::RuntimeUpgradeProposal")]
pub struct RuntimeUpgradeProposal {
    /// Canonical transaction authority that created this proposal.
    ///
    /// The operator is part of the exact proposal and effect preimages so the
    /// retained runtime-upgrade attribution cannot depend on transaction order.
    pub proposal_operator: AccountId,
    /// Canonical runtime-upgrade manifest payload.
    pub manifest: RuntimeUpgradeManifest,
}
/// Proposal payload for one SCCP v1 governance decision (`specs/sccp.md` §4.14.3).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::SccpRouteGovernanceProposal")]
pub struct SccpRouteGovernanceProposal {
    /// Complete network-bound SCCP v1 proposal: base revisions and ordered actions.
    pub proposal: Box<crate::sccp::governance::SccpGovernanceProposalV1>,
}
/// Proposal payload for one closed `SoraFS` provider-owner transition.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::SorafsProviderGovernanceProposal")]
pub struct SorafsProviderGovernanceProposal {
    /// Exact compare-and-set provider-owner action to execute on enactment.
    pub action: Box<SorafsProviderGovernanceActionV1>,
}
/// Proposal payload for one governed validation-fee policy.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ValidationFeePolicyProposal")]
pub struct ValidationFeePolicyProposal {
    /// Canonical transaction authority that created this proposal.
    ///
    /// Binding the operator into the typed preimage prevents transaction
    /// ordering from assigning an otherwise identical payload to a different
    /// retained proposer.
    pub proposal_operator: AccountId,
    /// Complete policy to append to the protected validation-fee registry.
    pub policy: ValidationFeePolicyV1,
}
/// Proposal payload authorizing one exact validation-fee payout lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ValidationFeePayoutLifecycleProposal")]
pub struct ValidationFeePayoutLifecycleProposal {
    /// Canonical transaction authority that created this proposal.
    ///
    /// This identity is part of the exact proposal fingerprint and must agree
    /// with the retained governance record's proposer.
    pub proposal_operator: AccountId,
    /// Exact payout binding authorized by this lifecycle.
    ///
    /// Its deterministic non-zero lifecycle seal is derived from this complete
    /// payload, so the native proposal fingerprint binds the seal transitively
    /// without accepting a redundant caller-supplied value.
    pub payout_binding: ValidationFeeTreasuryPayoutBindingV1,
}
/// Inclusive execution window for enactment certificates.
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
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::AtWindow")]
pub struct AtWindow {
    /// First block in the enactment window (inclusive).
    #[norito(json = "crate::json_helpers::u64_string")]
    pub lower: u64,
    /// Last block in the enactment window (inclusive).
    #[norito(json = "crate::json_helpers::u64_string")]
    pub upper: u64,
}
/// Governance parameters (subset) — see gov.md for full spec.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::GovernanceParameters")]
pub struct GovernanceParameters {
    /// Asset used to denominate voting power.
    pub voting_asset: AssetId,
    /// Base lock period applied to deposits in blocks.
    pub base_lock_period_blocks: u32,
    /// Whether abstain ballots count toward turnout.
    pub count_abstain_in_turnout: bool,
    /// Approval threshold encoded as Q32.32.
    pub approval_threshold: u64,
    /// Quorum threshold encoded as Q32.32.
    pub quorum_threshold: u64,
    /// Maximum number of simultaneously active referenda.
    pub max_active_referenda: u16,
    /// Maximum reduction in lock period for fast-track referenda (blocks).
    pub fast_track_max_reduction_blocks: u32,
    /// Slack applied when validating enactment windows (blocks).
    pub window_slack_blocks: u32,
    /// Base deposit required to submit a proposal.
    pub deposit_base: Quantity,
    /// Additional deposit required per byte of preimage.
    pub deposit_per_byte: Quantity,
    /// Additional deposit required per block of desired enactment window.
    pub deposit_per_block: Quantity,
}
/// Content-addressable proposal identifier (32-byte hash).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ProposalId")]
pub struct ProposalId(pub [u8; 32]);

impl norito::core::SerializePayload for ProposalId {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        let wire = HashWire32::new(self.0);
        <HashWire32 as norito::core::SerializePayload>::serialize(&wire, writer)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for ProposalId {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("ProposalId must decode from fixed-length payload")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let bytes =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        let (wire, _used) = norito::core::decode_field_canonical::<HashWire32>(bytes)?;
        wire.try_into_bytes().map(Self)
    }
}

impl JsonSerialize for ProposalId {
    fn json_serialize(&self, out: &mut String) {
        json::write_json_string(&hex::encode(self.0), out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_string_to(&hex::encode(self.0), out)
    }
}

impl JsonDeserialize for ProposalId {
    fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, json::Error> {
        let buf = parser.parse_string()?;
        decode_lowercase_hex_array::<32>(&buf)
            .map(Self)
            .map_err(|err| json::Error::Message(format!("{err}")))
    }
}
/// Minimal referendum status enumeration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ReferendumStatus")]
pub enum ReferendumStatus {
    /// Referendum has been submitted but not yet opened for voting.
    Proposed,
    /// Referendum is open for voting between the provided block bounds (inclusive `start`, `end`).
    Open(AtWindow),
    /// Referendum was approved by the electorate.
    Approved,
    /// Referendum was rejected by the electorate.
    Rejected,
    /// Referendum has been enacted on-chain.
    Enacted,
    /// Referendum was superseded by a newer proposal.
    Superseded,
    /// Referendum expired without reaching a conclusion.
    Expired,
}
/// Referendum shell (subset of fields).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::Referendum")]
pub struct Referendum {
    /// Deterministic identifier derived from the referendum preimage.
    pub id: ProposalId,
    /// Account that submitted the referendum.
    pub proposer: AccountId,
    /// Blake2b-32 hash of the preimage payload.
    pub preimage_hash: [u8; 32],
    /// Referenda that must be approved prior to enacting this one.
    pub requires: Vec<ProposalId>,
    /// Human-readable summary of the proposal intent.
    pub summary: String,
    /// Deposit locked while the referendum is active.
    pub deposit: Quantity,
    /// Current referendum lifecycle stage.
    pub status: ReferendumStatus,
    /// Optional enactment window associated with approval.
    pub schedule: Option<AtWindow>,
}
/// Voter choice variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::VoteChoice")]
pub enum VoteChoice {
    /// Support the referendum (Aye).
    Aye,
    /// Oppose the referendum (Nay).
    Nay,
    /// Neither support nor oppose (Abstain).
    Abstain,
}
/// Vote shell (conviction index is abstract for now).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::Vote")]
pub struct Vote {
    /// Referendum being voted on.
    pub referendum_id: ProposalId,
    /// Account casting the vote.
    pub voter: AccountId,
    /// Conviction strength index (e.g., `0..=k_max`); mapping in docs.
    pub conviction: u8,
    /// Ballot choice (Aye, Nay, or Abstain).
    pub choice: VoteChoice,
}
/// Parliament governance body identifiers.
///
/// JSON values and object keys share the canonical lowercase, hyphenated body labels.
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
    Default,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentBody")]
pub enum ParliamentBody {
    /// Rules Committee — intake and rulebook gate.
    #[codec(index = 0)]
    RulesCommittee,
    /// Agenda Council — schedules referendum windows and admission order.
    #[default]
    #[codec(index = 1)]
    AgendaCouncil,
    /// Interest Panels — subject-matter reviewers for the proposal domain.
    #[codec(index = 2)]
    InterestPanel,
    /// Review Panel — cross-domain review ahead of policy jury.
    #[codec(index = 3)]
    ReviewPanel,
    /// Coordination Council — reconciles the review record before specialist review.
    #[codec(index = 4)]
    CoordinationCouncil,
    /// Monetary Policy Committee — specialist review for monetary-policy effects.
    #[codec(index = 5)]
    MpcCommittee,
    /// Financial Markets Authority committee — specialist review for market effects.
    #[codec(index = 6)]
    FmaCommittee,
    /// Oversight Committee — monitors deadlines and escalation paths.
    #[codec(index = 7)]
    OversightCommittee,
    /// Policy Jury — large-jury decision body for approval/rejection.
    #[codec(index = 8)]
    PolicyJury,
    /// Confirmation Jury — a fresh disjoint jury for narrowly approved proposals.
    #[codec(index = 9)]
    ConfirmationJury,
}
/// Canonical V1 Parliament body order used by sortition, pipelines, and APIs.
pub const PARLIAMENT_BODIES_V1: [ParliamentBody; 10] = [
    ParliamentBody::RulesCommittee,
    ParliamentBody::AgendaCouncil,
    ParliamentBody::InterestPanel,
    ParliamentBody::ReviewPanel,
    ParliamentBody::CoordinationCouncil,
    ParliamentBody::MpcCommittee,
    ParliamentBody::FmaCommittee,
    ParliamentBody::OversightCommittee,
    ParliamentBody::PolicyJury,
    ParliamentBody::ConfirmationJury,
];

impl ParliamentBody {
    const fn json_label(self) -> &'static str {
        match self {
            Self::RulesCommittee => "rules-committee",
            Self::AgendaCouncil => "agenda-council",
            Self::InterestPanel => "interest-panel",
            Self::ReviewPanel => "review-panel",
            Self::CoordinationCouncil => "coordination-council",
            Self::MpcCommittee => "mpc-committee",
            Self::FmaCommittee => "fma-committee",
            Self::OversightCommittee => "oversight-committee",
            Self::PolicyJury => "policy-jury",
            Self::ConfirmationJury => "confirmation-jury",
        }
    }
    fn parse_json_label(value: &str) -> Result<Self, json::Error> {
        match value {
            "rules-committee" => Ok(Self::RulesCommittee),
            "agenda-council" => Ok(Self::AgendaCouncil),
            "interest-panel" => Ok(Self::InterestPanel),
            "review-panel" => Ok(Self::ReviewPanel),
            "coordination-council" => Ok(Self::CoordinationCouncil),
            "mpc-committee" => Ok(Self::MpcCommittee),
            "fma-committee" => Ok(Self::FmaCommittee),
            "oversight-committee" => Ok(Self::OversightCommittee),
            "policy-jury" => Ok(Self::PolicyJury),
            "confirmation-jury" => Ok(Self::ConfirmationJury),
            other => Err(json::Error::UnknownField {
                field: other.to_owned(),
            }),
        }
    }
}

impl json::JsonSerialize for ParliamentBody {
    fn json_serialize(&self, out: &mut String) {
        json::write_json_string(self.json_label(), out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_string_to(self.json_label(), out)
    }
}

impl json::JsonDeserialize for ParliamentBody {
    fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, json::Error> {
        Self::parse_json_label(&parser.parse_string()?)
    }
}

impl json::JsonObjectKey for ParliamentBody {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        visitor(self.json_label())
    }
}

impl json::JsonObjectKeyOwned for ParliamentBody {
    fn from_json_key_text(key: &str) -> Result<Self, json::Error> {
        Self::parse_json_label(key)
    }
}
/// Closed V1 governance risk classification.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema,
)]
#[norito(tag = "tier", content = "details", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::RiskTierV1")]
pub enum RiskTierV1 {
    /// Deterministic execution already authorized by an active mandate.
    #[codec(index = 0)]
    Routine,
    /// Bounded, reversible policy change using the affected-domain bodies.
    #[default]
    #[codec(index = 1)]
    Standard,
    /// Constitutional, consensus, rights, monetary, or highly irreversible change.
    #[codec(index = 2)]
    Constitutional,
    /// Time-bounded containment action followed by constitutional retrospective review.
    #[codec(index = 3)]
    Emergency,
}
impl RiskTierV1 {
    const fn rank(self) -> u8 {
        match self {
            Self::Routine => 0,
            Self::Standard => 1,
            Self::Constitutional => 2,
            Self::Emergency => 3,
        }
    }

    /// Return whether `target` is an upward-only escalation from this tier.
    #[must_use]
    pub const fn can_escalate_to(self, target: Self) -> bool {
        self.rank() <= target.rank()
    }
}

/// Sequential stage occupied by a V1 governance attempt.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema,
)]
#[norito(tag = "stage", content = "details", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::GovernanceStageV1")]
pub enum GovernanceStageV1 {
    /// Qualification and proposal-content admission.
    #[default]
    #[codec(index = 0)]
    Qualification,
    /// Rules Committee review.
    #[codec(index = 1)]
    Rules,
    /// Agenda Council scheduling.
    #[codec(index = 2)]
    Agenda,
    /// Public, nonbinding Interest Panel deliberation.
    #[codec(index = 3)]
    Interest,
    /// Affected-domain Review Panel deliberation.
    #[codec(index = 4)]
    Review,
    /// Coordination Council reconciliation.
    #[codec(index = 5)]
    Coordination,
    /// Applicable Monetary Policy Committee review.
    #[codec(index = 6)]
    Mpc,
    /// Applicable Financial Markets Authority review.
    #[codec(index = 7)]
    Fma,
    /// Oversight Committee review.
    #[codec(index = 8)]
    Oversight,
    /// Policy Jury decision.
    #[codec(index = 9)]
    PolicyJury,
    /// Disjoint Confirmation Jury decision when the first margin is narrow.
    #[codec(index = 10)]
    ConfirmationJury,
    /// Governance certificate construction.
    #[codec(index = 11)]
    Certification,
    /// Deterministic on-chain enactment.
    #[codec(index = 12)]
    Enactment,
}

/// Terminal or active state of a retryable governance attempt.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema,
)]
#[norito(tag = "status", content = "details", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::GovernanceAttemptStatusV1")]
pub enum GovernanceAttemptStatusV1 {
    /// The attempt is processing its current stage.
    #[default]
    #[codec(index = 0)]
    Active,
    /// The attempt produced a complete governance certificate.
    #[codec(index = 1)]
    Certified,
    /// A binding Parliament body rejected the proposal.
    #[codec(index = 2)]
    Rejected,
    /// The certified effect was enacted.
    #[codec(index = 3)]
    Enacted,
    /// A competing compare-and-set certificate won first.
    #[codec(index = 4)]
    Superseded,
    /// The exact certified effect failed deterministic execution.
    #[codec(index = 5)]
    ExecutionFailed,
}

/// Canonical snapshot of one retryable end-to-end governance attempt.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::GovernanceAttemptV1")]
pub struct GovernanceAttemptV1 {
    /// Identifier unique to this retry attempt.
    pub id: GovernanceAttemptId,
    /// Immutable proposal content shared by all retries.
    pub proposal_content_id: ProposalContentId,
    /// Zero-based retry sequence for the proposal content.
    pub sequence: u32,
    /// Upward-only risk tier fixed before the Policy Jury draw.
    pub risk_tier: RiskTierV1,
    /// Current sequential stage.
    pub stage: GovernanceStageV1,
    /// Current attempt status.
    pub status: GovernanceAttemptStatusV1,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::GovernanceAttemptIdPreimageV1")]
struct GovernanceAttemptIdPreimageV1 {
    proposal_content_id: ProposalContentId,
    sequence: u32,
}

impl GovernanceAttemptId {
    /// Derive the only valid V1 identifier for a proposal retry sequence.
    #[must_use]
    pub fn derive_v1(proposal_content_id: ProposalContentId, sequence: u32) -> Self {
        Self::new(crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::GOVERNANCE_ATTEMPT_ID_V1,
            &GovernanceAttemptIdPreimageV1 {
                proposal_content_id,
                sequence,
            },
        ))
    }
}

impl GovernanceAttemptV1 {
    /// Return whether the stored identifier is canonical for this retry.
    #[must_use]
    pub fn has_canonical_id(&self) -> bool {
        self.id == GovernanceAttemptId::derive_v1(self.proposal_content_id, self.sequence)
    }
}

/// Maximum target seats for any single V1 Parliament body.
///
/// The bound accommodates the largest permitted Confirmation Jury while
/// keeping ballot and certificate resource limits finite.
pub const MAX_PARLIAMENT_BODY_TARGET_SEATS_V1: u32 = 1_000;
/// Minimum frozen survivor and accepted-ballot count for a hidden Parliament ballot.
///
/// V1 publishes an exact aggregate tally. Requiring at least three participants
/// prevents the reachable two-person corpus from disclosing both choices when
/// unanimous, or one choice when the other participant's choice is known.
pub const MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1: u32 = 3;
/// The sole consensus policy version implemented by first-release Parliament.
pub const PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1: u64 = 1;
/// Hard protocol ceiling for end-to-end governance retries after sequence zero.
pub const MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1: u32 = 16;
/// Hard protocol ceiling for future-pulse body-election retries after sequence zero.
pub const MAX_PARLIAMENT_SORTITION_RETRIES_V1: u32 = 16;
/// Hard protocol ceiling for private-ballot retries after the initial attempt.
pub const MAX_PARLIAMENT_BALLOT_RETRIES_V1: u32 = 16;
/// Hard protocol ceiling for registration, survivor, and ballot corpora.
pub const MAX_PARLIAMENT_BALLOT_CORPUS_ENTRIES_V1: u32 = 1_000;
/// Exact canonical width of one timed-OVN participant-registration record.
pub const PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1: usize = 3_624;
/// Exact canonical width of one timed-OVN masked-ballot record.
pub const PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1: usize = 2_858;
/// Maximum number of contiguous timed-OVN ballot records accepted by one lifecycle transition.
///
/// The complete survivor corpus may contain up to the protocol-wide participant cap. Core derives
/// each chunk's starting survivor offset from committed state and seals the corpus automatically
/// after exact survivor coverage, so callers cannot skip, overlap, or reorder records.
pub const PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1: usize = 32;
/// Hard protocol ceiling for one canonical framed Parliament attempt state.
pub const MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1: usize = 16 * 1024 * 1024;
/// Hard protocol ceiling for registered citizens eligible to enter a Parliament snapshot.
///
/// Core rejects a new citizenship before it would exceed this bound. This keeps
/// complete-electorate sortition finite without truncating or otherwise biasing
/// the canonically ordered citizen set.
pub const MAX_PARLIAMENT_CITIZENS_V1: u32 = 65_536;
/// Hard protocol ceiling for the canonical Norito payload of one candidate snapshot.
///
/// A snapshot receives half of the complete attempt-state budget so candidate
/// derivation cannot consume the whole reducer allowance before lifecycle state
/// is added. Core enforces this while streaming the citizen registry, before it
/// clones an account identifier into the snapshot.
pub const MAX_PARLIAMENT_CANDIDATE_SNAPSHOT_BYTES_V1: usize =
    MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1 / 2;

/// Return the minimum number of blocks needed to admit a configured ballot corpus.
///
/// V1 charges enough gas that a block is only guaranteed to carry one maximum-sized chunk. A
/// commitment window shorter than this ceiling would therefore make its configured maximum corpus
/// objectively impossible to seal under the standard default-genesis block gas limit.
#[must_use]
pub fn parliament_timed_ovn_required_chunk_blocks_v1(max_corpus_entries: u32) -> u64 {
    let chunk_records = u64::try_from(PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1)
        .expect("the V1 Parliament ballot chunk bound fits u64");
    u64::from(max_corpus_entries).div_ceil(chunk_records)
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentCandidateRootPreimageV1")]
struct ParliamentCandidateRootPreimageV1 {
    governance_attempt_id: GovernanceAttemptId,
    body: ParliamentBody,
    candidates: Vec<AccountId>,
}

/// Commit an exact canonically ordered candidate snapshot for one body draw.
#[must_use]
pub fn parliament_candidate_root_v1(
    governance_attempt_id: GovernanceAttemptId,
    body: ParliamentBody,
    candidates: &[AccountId],
) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::CANDIDATE_ROOT_V1,
        &ParliamentCandidateRootPreimageV1 {
            governance_attempt_id,
            body,
            candidates: candidates.to_vec(),
        },
    )
}

/// Validation error for an immutable future-pulse sortition request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortitionRequestErrorV1 {
    /// One of the request, attempt, snapshot, or beacon-session bindings was zero.
    ZeroBinding,
    /// The request identifier did not hash the complete immutable request preimage.
    NonCanonicalIdentifier,
    /// The frozen candidate snapshot contained no eligible candidates.
    EmptyCandidateSnapshot,
    /// The frozen candidate snapshot exceeded the V1 citizen-registry ceiling.
    CandidateCountExceedsMaximum {
        /// Candidate count committed by the request.
        candidate_count: u32,
        /// V1 protocol maximum.
        maximum: u32,
    },
    /// The requested body target had zero seats.
    ZeroTargetSeats,
    /// The requested body target exceeded the V1 protocol maximum.
    TargetSeatsExceedMaximum {
        /// Requested seat count.
        target_seats: u32,
        /// V1 protocol maximum.
        maximum: u32,
    },
    /// Height zero cannot identify the block committing the request.
    ZeroRequestHeight,
    /// Height zero cannot identify a threshold-beacon pulse.
    ZeroPulseHeight,
    /// The pulse was not strictly later than request commitment.
    PulseNotStrictlyFuture {
        /// Height committing the immutable request.
        request_height: u64,
        /// Requested beacon-pulse height.
        pulse_height: u64,
    },
    /// The pulse height was already consumed in the same beacon session.
    PulseAlreadyConsumed {
        /// Requested beacon-pulse height.
        pulse_height: u64,
        /// Highest consumed pulse height supplied for the same session.
        last_consumed_pulse_height: u64,
    },
}
impl fmt::Display for SortitionRequestErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBinding => {
                f.write_str("sortition request bindings must be non-zero canonical digests")
            }
            Self::NonCanonicalIdentifier => {
                f.write_str("sortition request identifier is not canonical")
            }
            Self::EmptyCandidateSnapshot => f.write_str("sortition candidate snapshot is empty"),
            Self::CandidateCountExceedsMaximum {
                candidate_count,
                maximum,
            } => write!(
                f,
                "sortition candidate count {candidate_count} exceeds V1 maximum {maximum}"
            ),
            Self::ZeroTargetSeats => f.write_str("sortition target seats must be non-zero"),
            Self::TargetSeatsExceedMaximum {
                target_seats,
                maximum,
            } => write!(
                f,
                "sortition target seats {target_seats} exceed V1 maximum {maximum}"
            ),
            Self::ZeroRequestHeight => f.write_str("sortition request height must be non-zero"),
            Self::ZeroPulseHeight => f.write_str("sortition pulse height must be non-zero"),
            Self::PulseNotStrictlyFuture {
                request_height,
                pulse_height,
            } => write!(
                f,
                "sortition pulse height {pulse_height} must be strictly after request height {request_height}"
            ),
            Self::PulseAlreadyConsumed {
                pulse_height,
                last_consumed_pulse_height,
            } => write!(
                f,
                "sortition pulse height {pulse_height} is not newer than consumed pulse height {last_consumed_pulse_height}"
            ),
        }
    }
}
impl std::error::Error for SortitionRequestErrorV1 {}

/// Immutable candidate-snapshot request committed before a future beacon pulse.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::SortitionRequestV1")]
pub struct SortitionRequestV1 {
    /// Unique immutable request identifier.
    pub id: SortitionRequestId,
    /// End-to-end governance attempt requesting the body.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Body-election attempt that must consume this request.
    pub body_election_attempt_id: BodyElectionAttemptId,
    /// Parliament body to draw.
    pub body: ParliamentBody,
    /// Root of the frozen, canonically ordered candidate snapshot.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub candidate_root: [u8; 32],
    /// Candidates in the frozen snapshot.
    pub candidate_count: u32,
    /// Requested seats before feasible-pool concentration handling.
    pub target_seats: u32,
    /// Height at which this immutable request was committed.
    pub request_height: u64,
    /// Strictly future finalized pulse height consumed by the draw.
    pub pulse_height: u64,
    /// Stable network-scoped logical beacon expected to produce the pulse.
    pub beacon_session_id: BeaconSessionId,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::SortitionRequestIdPreimageV1")]
struct SortitionRequestIdPreimageV1 {
    governance_attempt_id: GovernanceAttemptId,
    body_election_attempt_id: BodyElectionAttemptId,
    body: ParliamentBody,
    candidate_root: [u8; 32],
    candidate_count: u32,
    target_seats: u32,
    request_height: u64,
    pulse_height: u64,
    beacon_session_id: BeaconSessionId,
}

impl SortitionRequestV1 {
    /// Derive the identifier that commits every immutable request field.
    #[must_use]
    pub fn canonical_id(&self) -> SortitionRequestId {
        SortitionRequestId::new(crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::SORTITION_REQUEST_ID_V1,
            &SortitionRequestIdPreimageV1 {
                governance_attempt_id: self.governance_attempt_id,
                body_election_attempt_id: self.body_election_attempt_id,
                body: self.body,
                candidate_root: self.candidate_root,
                candidate_count: self.candidate_count,
                target_seats: self.target_seats,
                request_height: self.request_height,
                pulse_height: self.pulse_height,
                beacon_session_id: self.beacon_session_id,
            },
        ))
    }

    /// Construct a request and derive its identifier from the complete V1 preimage.
    ///
    /// # Errors
    /// Returns [`SortitionRequestErrorV1`] when any immutable request invariant fails.
    #[expect(
        clippy::too_many_arguments,
        reason = "the constructor makes every consensus-bound request field explicit"
    )]
    pub fn try_new_canonical(
        governance_attempt_id: GovernanceAttemptId,
        body_election_attempt_id: BodyElectionAttemptId,
        body: ParliamentBody,
        candidate_root: [u8; 32],
        candidate_count: u32,
        target_seats: u32,
        request_height: u64,
        pulse_height: u64,
        beacon_session_id: BeaconSessionId,
        last_consumed_pulse_height: Option<u64>,
    ) -> Result<Self, SortitionRequestErrorV1> {
        let mut request = Self {
            id: SortitionRequestId::new([0; 32]),
            governance_attempt_id,
            body_election_attempt_id,
            body,
            candidate_root,
            candidate_count,
            target_seats,
            request_height,
            pulse_height,
            beacon_session_id,
        };
        request.id = request.canonical_id();
        request.validate(last_consumed_pulse_height)?;
        Ok(request)
    }

    /// Construct and validate an immutable sortition request.
    ///
    /// `last_consumed_pulse_height` must describe only the supplied beacon
    /// session. An undersubscribed but nonempty candidate snapshot remains valid;
    /// the sealed roster retains the exact resulting seat count.
    ///
    /// # Errors
    /// Returns [`SortitionRequestErrorV1`] for an empty pool, an invalid target,
    /// a zero request height, or a pulse that is zero, non-future, or already consumed.
    #[expect(
        clippy::too_many_arguments,
        reason = "the constructor makes every consensus-bound request field explicit"
    )]
    pub fn try_new(
        id: SortitionRequestId,
        governance_attempt_id: GovernanceAttemptId,
        body_election_attempt_id: BodyElectionAttemptId,
        body: ParliamentBody,
        candidate_root: [u8; 32],
        candidate_count: u32,
        target_seats: u32,
        request_height: u64,
        pulse_height: u64,
        beacon_session_id: BeaconSessionId,
        last_consumed_pulse_height: Option<u64>,
    ) -> Result<Self, SortitionRequestErrorV1> {
        let request = Self {
            id,
            governance_attempt_id,
            body_election_attempt_id,
            body,
            candidate_root,
            candidate_count,
            target_seats,
            request_height,
            pulse_height,
            beacon_session_id,
        };
        request.validate(last_consumed_pulse_height)?;
        Ok(request)
    }

    /// Revalidate the request against the highest consumed pulse in its session.
    ///
    /// # Errors
    /// Returns [`SortitionRequestErrorV1`] when any constructor invariant fails.
    pub fn validate(
        &self,
        last_consumed_pulse_height: Option<u64>,
    ) -> Result<(), SortitionRequestErrorV1> {
        self.validate_with_candidate_policy(last_consumed_pulse_height, false)
    }

    /// Validate a pre-request capacity intent while permitting an empty candidate snapshot.
    ///
    /// Parliament sortition-request instruction preflight
    /// (`ParliamentLifecycleTransitionV1::validate_static`) uses this before Core
    /// authenticates the live candidate corpus and hidden-body decision mode, so
    /// it exists only with the `governance` instruction surface. Every other
    /// identifier, target, height, and pulse-reuse invariant remains identical to
    /// [`Self::validate`].
    ///
    /// # Errors
    /// Returns [`SortitionRequestErrorV1`] for every malformed binding other
    /// than an empty candidate snapshot.
    #[cfg(feature = "governance")]
    pub(crate) fn validate_capacity_intent(
        &self,
        last_consumed_pulse_height: Option<u64>,
    ) -> Result<(), SortitionRequestErrorV1> {
        self.validate_with_candidate_policy(last_consumed_pulse_height, true)
    }

    fn validate_with_candidate_policy(
        &self,
        last_consumed_pulse_height: Option<u64>,
        allow_empty_candidate_snapshot: bool,
    ) -> Result<(), SortitionRequestErrorV1> {
        if self.id.as_bytes() == &[0; 32]
            || self.governance_attempt_id.as_bytes() == &[0; 32]
            || self.body_election_attempt_id.as_bytes() == &[0; 32]
            || self.candidate_root == [0; 32]
            || self.beacon_session_id.as_bytes() == &[0; 32]
        {
            return Err(SortitionRequestErrorV1::ZeroBinding);
        }
        if self.id != self.canonical_id() {
            return Err(SortitionRequestErrorV1::NonCanonicalIdentifier);
        }
        if self.candidate_count == 0 && !allow_empty_candidate_snapshot {
            return Err(SortitionRequestErrorV1::EmptyCandidateSnapshot);
        }
        if self.candidate_count > MAX_PARLIAMENT_CITIZENS_V1 {
            return Err(SortitionRequestErrorV1::CandidateCountExceedsMaximum {
                candidate_count: self.candidate_count,
                maximum: MAX_PARLIAMENT_CITIZENS_V1,
            });
        }
        if self.target_seats == 0 {
            return Err(SortitionRequestErrorV1::ZeroTargetSeats);
        }
        if self.target_seats > MAX_PARLIAMENT_BODY_TARGET_SEATS_V1 {
            return Err(SortitionRequestErrorV1::TargetSeatsExceedMaximum {
                target_seats: self.target_seats,
                maximum: MAX_PARLIAMENT_BODY_TARGET_SEATS_V1,
            });
        }
        if self.request_height == 0 {
            return Err(SortitionRequestErrorV1::ZeroRequestHeight);
        }
        if self.pulse_height == 0 {
            return Err(SortitionRequestErrorV1::ZeroPulseHeight);
        }
        if self.pulse_height <= self.request_height {
            return Err(SortitionRequestErrorV1::PulseNotStrictlyFuture {
                request_height: self.request_height,
                pulse_height: self.pulse_height,
            });
        }
        if let Some(last_consumed_pulse_height) = last_consumed_pulse_height
            && self.pulse_height <= last_consumed_pulse_height
        {
            return Err(SortitionRequestErrorV1::PulseAlreadyConsumed {
                pulse_height: self.pulse_height,
                last_consumed_pulse_height,
            });
        }
        Ok(())
    }
}

/// Lifecycle state of one retryable Parliament body-election attempt.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema,
)]
#[norito(tag = "status", content = "details", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::BodyElectionAttemptStatusV1")]
pub enum BodyElectionAttemptStatusV1 {
    /// The immutable request awaits its committed future pulse.
    #[default]
    #[codec(index = 0)]
    AwaitingPulse,
    /// Deterministic scores and cross-body assignments are being derived.
    #[codec(index = 1)]
    Drawing,
    /// Selected candidates and alternates may accept invitations.
    #[codec(index = 2)]
    AcceptingInvitations,
    /// A nonempty feasible roster was sealed into a body instance.
    #[codec(index = 3)]
    Sealed,
    /// No nonempty eligible roster could be sealed from the request.
    #[codec(index = 4)]
    NoRoster,
    /// A fresh election attempt replaced this one.
    #[codec(index = 5)]
    Superseded,
}

/// Binding error for a body-election attempt and its immutable request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyElectionAttemptErrorV1 {
    /// The immutable sortition request was itself malformed.
    InvalidSortitionRequest(SortitionRequestErrorV1),
    /// The request names a different governance attempt.
    GovernanceAttemptMismatch,
    /// The request names a different body-election attempt.
    ElectionAttemptMismatch,
    /// The attempt identifier did not bind its attempt, body, and retry sequence.
    NonCanonicalIdentifier,
    /// The zero-based retry sequence exceeded the V1 protocol maximum.
    RetryLimitExceeded {
        /// Supplied retry sequence.
        sequence: u32,
        /// V1 protocol maximum.
        maximum: u32,
    },
}
impl fmt::Display for BodyElectionAttemptErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSortitionRequest(error) => {
                write!(f, "invalid body-election sortition request: {error}")
            }
            Self::GovernanceAttemptMismatch => {
                f.write_str("sortition request governance attempt does not match election attempt")
            }
            Self::ElectionAttemptMismatch => {
                f.write_str("sortition request body-election id does not match election attempt")
            }
            Self::NonCanonicalIdentifier => {
                f.write_str("body-election attempt identifier is not canonical")
            }
            Self::RetryLimitExceeded { sequence, maximum } => write!(
                f,
                "body-election retry sequence {sequence} exceeds V1 maximum {maximum}"
            ),
        }
    }
}
impl std::error::Error for BodyElectionAttemptErrorV1 {}

/// Canonical snapshot of one retryable Parliament body-election attempt.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::BodyElectionAttemptV1")]
pub struct BodyElectionAttemptV1 {
    /// Unique body-election attempt identifier.
    pub id: BodyElectionAttemptId,
    /// End-to-end governance attempt served by the election.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Zero-based retry sequence within the body stage.
    pub sequence: u32,
    /// Immutable future-pulse request consumed by this election attempt.
    pub request: SortitionRequestV1,
    /// Current body-election lifecycle status.
    pub status: BodyElectionAttemptStatusV1,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::BodyElectionAttemptIdPreimageV1")]
struct BodyElectionAttemptIdPreimageV1 {
    governance_attempt_id: GovernanceAttemptId,
    body: ParliamentBody,
    sequence: u32,
}

impl BodyElectionAttemptId {
    /// Derive the only valid V1 identifier for one body-election retry.
    #[must_use]
    pub fn derive_v1(
        governance_attempt_id: GovernanceAttemptId,
        body: ParliamentBody,
        sequence: u32,
    ) -> Self {
        Self::new(crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::BODY_ELECTION_ATTEMPT_ID_V1,
            &BodyElectionAttemptIdPreimageV1 {
                governance_attempt_id,
                body,
                sequence,
            },
        ))
    }
}

impl BodyElectionAttemptV1 {
    /// Construct an election attempt whose IDs agree with its sortition request.
    ///
    /// # Errors
    /// Returns [`BodyElectionAttemptErrorV1`] when either request binding differs.
    pub fn try_new(
        id: BodyElectionAttemptId,
        governance_attempt_id: GovernanceAttemptId,
        sequence: u32,
        request: SortitionRequestV1,
        status: BodyElectionAttemptStatusV1,
    ) -> Result<Self, BodyElectionAttemptErrorV1> {
        request
            .validate(None)
            .map_err(BodyElectionAttemptErrorV1::InvalidSortitionRequest)?;
        if request.governance_attempt_id != governance_attempt_id {
            return Err(BodyElectionAttemptErrorV1::GovernanceAttemptMismatch);
        }
        if request.body_election_attempt_id != id {
            return Err(BodyElectionAttemptErrorV1::ElectionAttemptMismatch);
        }
        if id != BodyElectionAttemptId::derive_v1(governance_attempt_id, request.body, sequence) {
            return Err(BodyElectionAttemptErrorV1::NonCanonicalIdentifier);
        }
        if sequence > MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
            return Err(BodyElectionAttemptErrorV1::RetryLimitExceeded {
                sequence,
                maximum: MAX_PARLIAMENT_SORTITION_RETRIES_V1,
            });
        }
        Ok(Self {
            id,
            governance_attempt_id,
            sequence,
            request,
            status,
        })
    }
}

/// Deliberative phase occupied by a Parliament body instance.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema,
)]
#[norito(tag = "phase", content = "details", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::DeliberationPhaseV1")]
pub enum DeliberationPhaseV1 {
    /// Member orientation and protocol briefing.
    #[default]
    #[codec(index = 0)]
    Orientation,
    /// Balanced evidence submission and review.
    #[codec(index = 1)]
    Evidence,
    /// Questions from selected members.
    #[codec(index = 2)]
    Questions,
    /// Responses entered into the public record.
    #[codec(index = 3)]
    Responses,
    /// Member deliberation.
    #[codec(index = 4)]
    Deliberation,
    /// Mandatory reflection interval.
    #[codec(index = 5)]
    Reflection,
    /// Hidden formal ballot, when the body is binding.
    #[codec(index = 6)]
    Vote,
}

/// Lifecycle state of one sealed Parliament body instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "status", content = "phase", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::BodyInstanceStatusV1")]
pub enum BodyInstanceStatusV1 {
    /// Candidate snapshot is frozen and awaiting a future beacon pulse.
    #[codec(index = 0)]
    AwaitingSortition,
    /// Selected members and alternates may accept their invitations.
    #[codec(index = 1)]
    AcceptingInvitations,
    /// A nonempty feasible roster has been sealed.
    #[codec(index = 2)]
    RosterSealed,
    /// The body is in a specified deliberative phase.
    #[codec(index = 3)]
    Deliberating(DeliberationPhaseV1),
    /// The body has an active hidden-ballot attempt.
    #[codec(index = 4)]
    Balloting,
    /// The body approved the proposal or issued its nonbinding finding.
    #[codec(index = 5)]
    Approved,
    /// The body rejected the proposal.
    #[codec(index = 6)]
    Rejected,
    /// Turnout did not meet the immutable original-seat quorum.
    #[codec(index = 7)]
    NoQuorum,
    /// Cryptographic opening did not produce a valid aggregate result.
    #[codec(index = 8)]
    NoResult,
    /// A fresh body instance replaced this one.
    #[codec(index = 9)]
    Superseded,
}

/// Canonical snapshot of one sealed Parliament body instance.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentBodyInstanceV1")]
pub struct ParliamentBodyInstanceV1 {
    /// Unique body-instance identifier.
    pub id: BodyInstanceId,
    /// End-to-end governance attempt served by the body.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Sortition attempt that produced this instance.
    pub election_attempt_id: BodyElectionAttemptId,
    /// Body role served by this instance.
    pub body: ParliamentBody,
    /// Book-faithful requested seat count.
    pub target_seats: u32,
    /// Immutable actual-seat count used as the quorum denominator.
    pub original_seats: u32,
    /// Current body lifecycle state.
    pub status: BodyInstanceStatusV1,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::BodyInstanceIdPreimageV1")]
struct BodyInstanceIdPreimageV1 {
    election_attempt_id: BodyElectionAttemptId,
    roster_root: [u8; 32],
}

impl BodyInstanceId {
    /// Derive the V1 body identifier from its election and exact sealed roster.
    #[must_use]
    pub fn derive_v1(election_attempt_id: BodyElectionAttemptId, roster_root: [u8; 32]) -> Self {
        Self::new(crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::BODY_INSTANCE_ID_V1,
            &BodyInstanceIdPreimageV1 {
                election_attempt_id,
                roster_root,
            },
        ))
    }
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::AssignmentIdPreimageV1")]
struct AssignmentIdPreimageV1 {
    election_attempt_id: BodyElectionAttemptId,
    member: AccountId,
}

impl AssignmentId {
    /// Derive the V1 assignment identifier for a member in one election attempt.
    #[must_use]
    pub fn derive_v1(election_attempt_id: BodyElectionAttemptId, member: &AccountId) -> Self {
        Self::new(crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::ASSIGNMENT_ID_V1,
            &AssignmentIdPreimageV1 {
                election_attempt_id,
                member: member.clone(),
            },
        ))
    }
}

/// Canonical assignment of one citizen to one sealed Parliament seat.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentSeatAssignmentV1")]
pub struct ParliamentSeatAssignmentV1 {
    /// Identifier derived from the election attempt and member identity.
    pub assignment_id: AssignmentId,
    /// Citizen selected for the seat.
    pub member: AccountId,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::parliament_types::ParliamentAssignmentPlanRootPreimageV1"
)]
struct ParliamentAssignmentPlanRootPreimageV1 {
    election_attempt_id: BodyElectionAttemptId,
    primary: Vec<ParliamentSeatAssignmentV1>,
    alternates: Vec<ParliamentSeatAssignmentV1>,
    cross_body_assignment_cap: u32,
}

/// Commit the exact ranked primary and alternate draw for one body election.
///
/// Unlike the sealed roster root, vector order is significant here: it fixes
/// the deterministic invitation and replacement order produced by the future
/// beacon pulse. Callers must supply canonical assignment identifiers and a
/// duplicate-free draw plan.
#[must_use]
pub fn parliament_assignment_plan_root_v1(
    election_attempt_id: BodyElectionAttemptId,
    primary: &[ParliamentSeatAssignmentV1],
    alternates: &[ParliamentSeatAssignmentV1],
    cross_body_assignment_cap: u32,
) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::ASSIGNMENT_PLAN_ROOT_V1,
        &ParliamentAssignmentPlanRootPreimageV1 {
            election_attempt_id,
            primary: primary.to_vec(),
            alternates: alternates.to_vec(),
            cross_body_assignment_cap,
        },
    )
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentRosterRootPreimageV1")]
struct ParliamentRosterRootPreimageV1 {
    election_attempt_id: BodyElectionAttemptId,
    assignments: Vec<ParliamentSeatAssignmentV1>,
}

/// Commit a canonically ordered, nonempty seated roster for one election.
#[must_use]
pub fn parliament_roster_root_v1(
    election_attempt_id: BodyElectionAttemptId,
    assignments: &[ParliamentSeatAssignmentV1],
) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::ROSTER_ROOT_V1,
        &ParliamentRosterRootPreimageV1 {
            election_attempt_id,
            assignments: assignments.to_vec(),
        },
    )
}

/// Lifecycle state of one hidden Parliament ballot attempt.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema,
)]
#[norito(tag = "status", content = "details", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::BallotAttemptStatusV1")]
pub enum BallotAttemptStatusV1 {
    /// OVN registration keys and proofs are being accepted.
    #[default]
    #[codec(index = 0)]
    Registration,
    /// The canonical nonempty survivor roster is being frozen before ballots.
    #[codec(index = 1)]
    SurvivorFreeze,
    /// Folded timed-OVN ciphertexts and one-hot proofs are being accepted.
    #[codec(index = 2)]
    TimedCommitment,
    /// The complete seal awaits its target finalized height.
    #[codec(index = 3)]
    AwaitingRelease,
    /// Finalized timelock material is opening the canonical corpus.
    #[codec(index = 4)]
    Opening,
    /// A valid aggregate tally was finalized.
    #[codec(index = 5)]
    Finalized,
    /// The attempt terminally failed to produce a valid result.
    #[codec(index = 6)]
    NoResult,
    /// A fresh ballot attempt replaced this one.
    #[codec(index = 7)]
    Superseded,
}

/// Deterministic reason a private ballot attempt ended without a result.
///
/// Invalid caller-supplied proofs are rejected and never become lifecycle
/// state. These reasons are reserved for objective terminal conditions derived
/// from persisted state: phase expiry, an unavailable finalized release pulse,
/// insufficient fresh Confirmation Jury capacity after a narrow opening, or
/// exhaustion of the proposal-wide randomness-redraw budget needed to draw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "reason", content = "details", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentBallotFailureKindV1")]
pub enum ParliamentBallotFailureKindV1 {
    /// The proof-validated registration corpus was not frozen by its deadline.
    #[codec(index = 0)]
    RegistrationDeadlineExpired,
    /// A nonempty canonical survivor roster was not frozen by its deadline.
    #[codec(index = 1)]
    SurvivorDeadlineExpired,
    /// The complete survivor ballot corpus was not frozen by its deadline.
    #[codec(index = 2)]
    CommitmentDeadlineExpired,
    /// The exact committed threshold-beacon pulse was unavailable after its height.
    #[codec(index = 3)]
    ReleasePulseUnavailable,
    /// The aggregate was not validly opened before its immutable deadline.
    #[codec(index = 4)]
    OpeningDeadlineExpired,
    /// Fewer than the hidden-ballot anonymity floor remained outside the sealed Policy Jury.
    #[codec(index = 5)]
    ConfirmationJuryCapacityUnavailable,
    /// A narrow Policy approval required a fresh Confirmation Jury after the
    /// proposal-wide randomness-redraw budget was exhausted.
    #[codec(index = 6)]
    RandomnessRedrawBudgetExhausted,
}

/// Closed audit classification for every Parliament body that ends without a result.
///
/// Public-finding failures and private-ballot failures share this event-facing
/// vocabulary so telemetry and audit consumers never need to infer terminal
/// causes from identifiers or private protocol material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "reason", content = "details", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentNoResultKindV1")]
pub enum ParliamentNoResultKindV1 {
    /// Authenticated absences or immutable split endorsements made quorum unreachable.
    #[codec(index = 0)]
    PublicFindingQuorumUnreachable,
    /// A public-finding body remained below quorum after its frozen deadline.
    #[codec(index = 1)]
    PublicFindingDeadlineExpired,
    /// The proof-validated private-ballot registration corpus missed its deadline.
    #[codec(index = 2)]
    BallotRegistrationDeadlineExpired,
    /// The private-ballot survivor roster missed its deadline.
    #[codec(index = 3)]
    BallotSurvivorDeadlineExpired,
    /// The complete private-ballot commitment corpus missed its deadline.
    #[codec(index = 4)]
    BallotCommitmentDeadlineExpired,
    /// The exact committed private-ballot release pulse was unavailable.
    #[codec(index = 5)]
    BallotReleasePulseUnavailable,
    /// The private-ballot aggregate missed its immutable opening deadline.
    #[codec(index = 6)]
    BallotOpeningDeadlineExpired,
    /// The current body exhausted its bounded future-pulse sortition retries.
    #[codec(index = 7)]
    SortitionRetriesExhausted,
    /// A narrow Policy Jury result lacked the hidden-ballot anonymity floor of fresh confirmers.
    #[codec(index = 8)]
    ConfirmationJuryCapacityUnavailable,
    /// A required fresh Confirmation draw exceeded the proposal-wide redraw budget.
    #[codec(index = 9)]
    RandomnessRedrawBudgetExhausted,
}

impl From<ParliamentBallotFailureKindV1> for ParliamentNoResultKindV1 {
    fn from(value: ParliamentBallotFailureKindV1) -> Self {
        match value {
            ParliamentBallotFailureKindV1::RegistrationDeadlineExpired => {
                Self::BallotRegistrationDeadlineExpired
            }
            ParliamentBallotFailureKindV1::SurvivorDeadlineExpired => {
                Self::BallotSurvivorDeadlineExpired
            }
            ParliamentBallotFailureKindV1::CommitmentDeadlineExpired => {
                Self::BallotCommitmentDeadlineExpired
            }
            ParliamentBallotFailureKindV1::ReleasePulseUnavailable => {
                Self::BallotReleasePulseUnavailable
            }
            ParliamentBallotFailureKindV1::OpeningDeadlineExpired => {
                Self::BallotOpeningDeadlineExpired
            }
            ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable => {
                Self::ConfirmationJuryCapacityUnavailable
            }
            ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted => {
                Self::RandomnessRedrawBudgetExhausted
            }
        }
    }
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentBallotFailureRootPreimageV1")]
struct ParliamentBallotFailureRootPreimageV1 {
    governance_attempt_id: GovernanceAttemptId,
    ballot_attempt_id: BallotAttemptId,
    failure_kind: ParliamentBallotFailureKindV1,
    failure_height: u64,
}

/// Derive the only valid failure root for an objectively failed private ballot.
///
/// The root binds the exact governance and ballot attempts, the failure class
/// derived by Core, and the containing finalized block height. No lifecycle
/// submitter supplies discretionary failure evidence.
#[must_use]
pub fn parliament_ballot_failure_root_v1(
    governance_attempt_id: GovernanceAttemptId,
    ballot_attempt_id: BallotAttemptId,
    failure_kind: ParliamentBallotFailureKindV1,
    failure_height: u64,
) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::PARLIAMENT_BALLOT_FAILURE_ROOT_V1,
        &ParliamentBallotFailureRootPreimageV1 {
            governance_attempt_id,
            ballot_attempt_id,
            failure_kind,
            failure_height,
        },
    )
}

/// Canonical snapshot of one retryable hidden Parliament ballot attempt.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentBallotAttemptV1")]
pub struct ParliamentBallotAttemptV1 {
    /// Unique ballot-attempt identifier.
    pub id: BallotAttemptId,
    /// Body instance whose formal decision the ballot determines.
    pub body_instance_id: BodyInstanceId,
    /// Zero-based retry sequence within the body instance.
    pub sequence: u32,
    /// Immutable original-seat quorum denominator copied from the body instance.
    pub original_seats: u32,
    /// Current ballot lifecycle state.
    pub status: BallotAttemptStatusV1,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::BallotAttemptIdPreimageV1")]
struct BallotAttemptIdPreimageV1 {
    body_instance_id: BodyInstanceId,
    sequence: u32,
}

impl BallotAttemptId {
    /// Derive the only valid V1 ballot identifier for one body retry.
    #[must_use]
    pub fn derive_v1(body_instance_id: BodyInstanceId, sequence: u32) -> Self {
        Self::new(crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::BALLOT_ATTEMPT_ID_V1,
            &BallotAttemptIdPreimageV1 {
                body_instance_id,
                sequence,
            },
        ))
    }
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::parliament_types::ParliamentBallotParticipantHashPreimageV1"
)]
struct ParliamentBallotParticipantHashPreimageV1 {
    ballot_attempt_id: BallotAttemptId,
    member: AccountId,
}

/// Derive the only valid timed-OVN participant hash for one seated member.
///
/// Binding the participant identity to both the authenticated universal
/// account and the exact ballot attempt prevents a Parliament manager from
/// registering substitute masking keys or replaying a registration between
/// ballots.
#[must_use]
pub fn parliament_ballot_participant_hash_v1(
    ballot_attempt_id: BallotAttemptId,
    member: &AccountId,
) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::BALLOT_PARTICIPANT_HASH_V1,
        &ParliamentBallotParticipantHashPreimageV1 {
            ballot_attempt_id,
            member: member.clone(),
        },
    )
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::TleSessionIdPreimageV1")]
struct TleSessionIdPreimageV1 {
    ballot_attempt_id: BallotAttemptId,
    tle_key_session_id: TleKeySessionId,
    release_beacon_session_id: BeaconSessionId,
    release_height: u64,
}

impl TleSessionId {
    /// Derive the dedicated V1 timelock session for one ballot and release slot.
    #[must_use]
    pub fn derive_v1(
        ballot_attempt_id: BallotAttemptId,
        tle_key_session_id: TleKeySessionId,
        release_beacon_session_id: BeaconSessionId,
        release_height: u64,
    ) -> Self {
        Self::new(crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::TLE_SESSION_ID_V1,
            &TleSessionIdPreimageV1 {
                ballot_attempt_id,
                tle_key_session_id,
                release_beacon_session_id,
                release_height,
            },
        ))
    }
}

/// Return the immutable-seat quorum `ceil(2 × original_seats / 3)`.
#[must_use]
pub const fn parliament_quorum_seats_v1(original_seats: u32) -> u32 {
    let quotient = original_seats / 3;
    let remainder = original_seats % 3;
    quotient * 2
        + match remainder {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => unreachable!(),
        }
}

/// Deterministic aggregate result of a hidden Parliament ballot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "outcome", content = "details", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentAggregateOutcomeV1")]
pub enum ParliamentAggregateOutcomeV1 {
    /// Quorum was met and Aye strictly exceeded Nay.
    #[codec(index = 0)]
    Approved,
    /// Quorum was met but Aye did not strictly exceed Nay.
    #[codec(index = 1)]
    Rejected,
    /// The accepted corpus did not meet the immutable original-seat quorum.
    #[codec(index = 2)]
    NoQuorum,
    /// The cryptographic protocol terminally failed to yield a valid tally.
    #[codec(index = 3)]
    NoResult,
}

/// Error returned when aggregate ballot counts do not describe one canonical corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParliamentTallyErrorV1 {
    /// The option counts did not add up to the accepted corpus size.
    CountSumMismatch {
        /// Accepted corpus size committed by the attempt.
        accepted_ballots: u32,
        /// Sum of Aye, Nay, and Abstain counts.
        counted_ballots: u64,
    },
    /// The accepted corpus exceeded the immutable original-seat count.
    CorpusExceedsOriginalSeats {
        /// Accepted corpus size committed by the attempt.
        accepted_ballots: u32,
        /// Immutable original-seat count.
        original_seats: u32,
    },
    /// The exact public tally would describe fewer than the V1 anonymity floor.
    CorpusBelowAnonymityFloor {
        /// Accepted corpus size committed by the attempt.
        accepted_ballots: u32,
        /// Canonical minimum accepted corpus size.
        minimum: u32,
    },
}
impl fmt::Display for ParliamentTallyErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountSumMismatch {
                accepted_ballots,
                counted_ballots,
            } => write!(
                f,
                "accepted ballot corpus has {accepted_ballots} entries but option counts total {counted_ballots}"
            ),
            Self::CorpusExceedsOriginalSeats {
                accepted_ballots,
                original_seats,
            } => write!(
                f,
                "accepted ballot corpus {accepted_ballots} exceeds original seat count {original_seats}"
            ),
            Self::CorpusBelowAnonymityFloor {
                accepted_ballots,
                minimum,
            } => write!(
                f,
                "accepted ballot corpus {accepted_ballots} is below the hidden-ballot anonymity floor {minimum}"
            ),
        }
    }
}
impl std::error::Error for ParliamentTallyErrorV1 {}

/// Canonical aggregate counts for one hidden Parliament ballot attempt.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentAggregateTallyV1")]
pub struct ParliamentAggregateTallyV1 {
    /// Immutable actual seats selected before absence or dropout.
    pub original_seats: u32,
    /// Ballots in the frozen accepted corpus.
    pub accepted_ballots: u32,
    /// Final decoded Aye count.
    pub aye: u32,
    /// Final decoded Nay count.
    pub nay: u32,
    /// Final decoded Abstain count, included in turnout.
    pub abstain: u32,
}
impl ParliamentAggregateTallyV1 {
    /// Validate count conservation, the immutable-seat upper bound, and the anonymity floor.
    ///
    /// # Errors
    /// Returns [`ParliamentTallyErrorV1`] when counts do not describe the
    /// accepted corpus, the corpus exceeds the original seats, or it falls
    /// below the canonical hidden-ballot anonymity floor.
    pub fn validate(&self) -> Result<(), ParliamentTallyErrorV1> {
        let counted_ballots = u64::from(self.aye) + u64::from(self.nay) + u64::from(self.abstain);
        if counted_ballots != u64::from(self.accepted_ballots) {
            return Err(ParliamentTallyErrorV1::CountSumMismatch {
                accepted_ballots: self.accepted_ballots,
                counted_ballots,
            });
        }
        if self.accepted_ballots > self.original_seats {
            return Err(ParliamentTallyErrorV1::CorpusExceedsOriginalSeats {
                accepted_ballots: self.accepted_ballots,
                original_seats: self.original_seats,
            });
        }
        if self.accepted_ballots < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1 {
            return Err(ParliamentTallyErrorV1::CorpusBelowAnonymityFloor {
                accepted_ballots: self.accepted_ballots,
                minimum: MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1,
            });
        }
        Ok(())
    }

    /// Evaluate quorum and the strict `Aye > Nay` approval rule.
    ///
    /// A corpus below the canonical anonymity floor is malformed and cannot
    /// produce a public decision.
    ///
    /// # Errors
    /// Returns [`ParliamentTallyErrorV1`] for malformed aggregate counts.
    pub fn decision(&self) -> Result<ParliamentAggregateOutcomeV1, ParliamentTallyErrorV1> {
        self.validate()?;
        if self.original_seats == 0
            || self.accepted_ballots < parliament_quorum_seats_v1(self.original_seats)
        {
            return Ok(ParliamentAggregateOutcomeV1::NoQuorum);
        }
        if self.aye > self.nay {
            Ok(ParliamentAggregateOutcomeV1::Approved)
        } else {
            Ok(ParliamentAggregateOutcomeV1::Rejected)
        }
    }

    /// Return whether an approved result has a strictly sub-five-percent margin.
    ///
    /// The comparison is performed by integer cross multiplication; no division
    /// or zero-denominator special case can change consensus output.
    ///
    /// # Errors
    /// Returns [`ParliamentTallyErrorV1`] for malformed aggregate counts.
    pub fn requires_confirmation(&self) -> Result<bool, ParliamentTallyErrorV1> {
        if self.decision()? != ParliamentAggregateOutcomeV1::Approved {
            return Ok(false);
        }
        let decisive_ballots = u64::from(self.aye) + u64::from(self.nay);
        if decisive_ballots == 0 {
            return Ok(false);
        }
        let margin = u64::from(self.aye.abs_diff(self.nay));
        Ok(margin * 100 < decisive_ballots * 5)
    }
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentBallotResultRootPreimageV1")]
struct ParliamentBallotResultRootPreimageV1 {
    governance_attempt_id: GovernanceAttemptId,
    body_instance_id: BodyInstanceId,
    ballot_attempt_id: BallotAttemptId,
    opening_root: [u8; 32],
    tally: ParliamentAggregateTallyV1,
    outcome: ParliamentAggregateOutcomeV1,
    result_height: u64,
}

/// Derive the only valid result root for an aggregate-only private ballot.
///
/// The root binds the complete attempt/body/ballot lineage, the replay-derived
/// threshold-opening root, deterministic tally and outcome, and the finalized
/// result height. A lifecycle submitter cannot choose a private body result.
#[must_use]
pub fn parliament_ballot_result_root_v1(
    governance_attempt_id: GovernanceAttemptId,
    body_instance_id: BodyInstanceId,
    ballot_attempt_id: BallotAttemptId,
    opening_root: [u8; 32],
    tally: ParliamentAggregateTallyV1,
    outcome: ParliamentAggregateOutcomeV1,
    result_height: u64,
) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::PARLIAMENT_BALLOT_RESULT_ROOT_V1,
        &ParliamentBallotResultRootPreimageV1 {
            governance_attempt_id,
            body_instance_id,
            ballot_attempt_id,
            opening_root,
            tally,
            outcome,
            result_height,
        },
    )
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::parliament_types::ParliamentPublicFindingEndorsementRootPreimageV1"
)]
struct ParliamentPublicFindingEndorsementRootPreimageV1 {
    governance_attempt_id: GovernanceAttemptId,
    body_instance_id: BodyInstanceId,
    result_root: [u8; 32],
    endorsing_assignments: Vec<AssignmentId>,
}

/// Derive the canonical root of the exact seated assignments endorsing one
/// public, nonbinding finding.
///
/// Callers must supply assignment identifiers in strict canonical order. Core
/// derives this list from authority-authenticated endorsements; a lifecycle
/// submitter cannot choose the certificate binding.
#[must_use]
pub fn parliament_public_finding_endorsement_root_v1(
    governance_attempt_id: GovernanceAttemptId,
    body_instance_id: BodyInstanceId,
    result_root: [u8; 32],
    endorsing_assignments: &[AssignmentId],
) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::PARLIAMENT_PUBLIC_FINDING_ENDORSEMENT_ROOT_V1,
        &ParliamentPublicFindingEndorsementRootPreimageV1 {
            governance_attempt_id,
            body_instance_id,
            result_root,
            endorsing_assignments: endorsing_assignments.to_vec(),
        },
    )
}

/// Absent compare-and-set head required by a governed effect.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::GovernanceExpectedHeadAbsentV1")]
pub struct GovernanceExpectedHeadAbsentV1 {
    /// Stable hash identifying the governed registry subject.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub subject_id: [u8; 32],
}

/// Present compare-and-set head required by a governed effect.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::GovernanceExpectedHeadPresentV1")]
pub struct GovernanceExpectedHeadPresentV1 {
    /// Stable hash identifying the governed registry subject.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub subject_id: [u8; 32],
    /// Exact expected registry or policy version.
    pub version: u64,
    /// Exact expected canonical head root.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub head_root: [u8; 32],
}

/// Commit the complete canonical value of a present Parliament compare-and-set head.
#[must_use]
pub fn parliament_expected_head_root_v1(value: &impl Encode) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::PARLIAMENT_EXPECTED_HEAD_ROOT_V1,
        value,
    )
}

/// Typed compare-and-set head bound into a V1 governance certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "state", content = "head", deny_unknown_fields)]
#[derive(JsonSerialize, JsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::GovernanceExpectedHeadV1")]
pub enum GovernanceExpectedHeadV1 {
    /// The governed subject must not exist when the certificate executes.
    #[codec(index = 0)]
    Absent(GovernanceExpectedHeadAbsentV1),
    /// The governed subject must match this exact version and root.
    #[codec(index = 1)]
    Present(GovernanceExpectedHeadPresentV1),
}

/// Final ballot transcript bound into a body result.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentBallotCertificateBindingV1")]
pub struct ParliamentBallotCertificateBindingV1 {
    /// Ballot attempt whose accepted corpus was opened.
    pub ballot_attempt_id: BallotAttemptId,
    /// Zero-based retry sequence of the ballot attempt.
    pub ballot_attempt_sequence: u32,
    /// Dedicated timelock-encryption key session.
    pub tle_session_id: TleSessionId,
    /// Long-lived threshold-BLS key session used only for TLE release signatures.
    pub tle_key_session_id: TleKeySessionId,
    /// Root of the complete proof-validated registration corpus.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub registration_root: [u8; 32],
    /// Root of the pre-ballot dropout decisions.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub dropout_root: [u8; 32],
    /// Root of the immutable survivor roster.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub survivor_root: [u8; 32],
    /// Root of the frozen accepted ballot corpus.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub corpus_root: [u8; 32],
    /// Sentinel root binding registration, pre-ballot dropout decisions, and the frozen survivor
    /// transcript to the mandatory absence of any post-freeze recovery path.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub no_recovery_root: [u8; 32],
    /// Root of the intrinsic timed-OVN ciphertext and one-hot-proof commitments.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub timed_commitment_root: [u8; 32],
    /// Stable network-scoped logical beacon committed for timed opening.
    pub release_beacon_session_id: BeaconSessionId,
    /// Height at which the ballot attempt and release slot were committed.
    pub registered_at_height: u64,
    /// First height after the proof-registration submission window.
    pub registration_close_height: u64,
    /// First height after the survivor-declaration window.
    pub survivor_freeze_height: u64,
    /// First height after the masked-ballot commitment window.
    pub commitment_close_height: u64,
    /// Height at which consensus froze the exact registration corpus.
    pub registration_closed_at_height: u64,
    /// Height at which consensus froze the exact survivor roster.
    pub survivors_frozen_at_height: u64,
    /// Height within the commitment window at which consensus completed the exact corpus.
    pub commitment_closed_at_height: u64,
    /// Configured retry limit frozen for this ballot lifecycle.
    pub max_ballot_retries: u32,
    /// Configured exact-corpus entry limit frozen for this ballot lifecycle.
    pub max_corpus_entries: u32,
    /// Earliest finalized pulse height permitted to release the aggregate.
    pub release_height: u64,
    /// Last height at which the release pulse or aggregate opening may be consumed.
    pub opening_deadline_height: u64,
    /// Exact finalized threshold-beacon pulse that released the aggregate.
    pub release_pulse_id: BeaconPulseId,
    /// Height at which the exact release pulse was consumed for opening.
    pub opening_height: u64,
    /// Root of the aggregate-only threshold opening transcript.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub opening_root: [u8; 32],
    /// Canonically decoded aggregate tally.
    pub tally: ParliamentAggregateTallyV1,
    /// Final ballot outcome, including protocol-level `NoResult` where applicable.
    pub outcome: ParliamentAggregateOutcomeV1,
}

/// Quorum evidence binding one public, nonbinding Parliament body finding.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::parliament_types::ParliamentPublicFindingCertificateBindingV1"
)]
pub struct ParliamentPublicFindingCertificateBindingV1 {
    /// Root of the strict assignment-id sequence endorsing the accepted result root.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub endorsement_root: [u8; 32],
    /// Strictly ordered distinct seated assignments whose authorities endorsed the result.
    pub endorsing_assignments: Vec<AssignmentId>,
    /// Number of distinct seated assignments endorsing the accepted result.
    pub endorsements: u32,
    /// Immutable `ceil(2 × original_seats / 3)` threshold.
    pub quorum: u32,
}

/// Sortition, roster, deliberation, and optional ballot result bound for one body.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::ParliamentBodyCertificateBindingV1")]
pub struct ParliamentBodyCertificateBindingV1 {
    /// Body instance contributing this result.
    pub body_instance_id: BodyInstanceId,
    /// Election attempt that produced the roster.
    pub election_attempt_id: BodyElectionAttemptId,
    /// Zero-based retry sequence of the body-election attempt.
    pub election_attempt_sequence: u32,
    /// Immutable sortition request committed before the future pulse.
    pub sortition_request_id: SortitionRequestId,
    /// Complete immutable request, including candidate snapshot and request/pulse heights.
    ///
    /// The individually repeated identifiers below are retained as convenient
    /// indexes, but validation requires exact equality with this request.
    pub sortition_request: SortitionRequestV1,
    /// Body role of this result.
    pub body: ParliamentBody,
    /// Immutable sealed-seat denominator for this body result.
    pub original_seats: u32,
    /// Beacon key session used for the sortition pulse.
    pub beacon_session_id: BeaconSessionId,
    /// Finalized future pulse consumed by sortition.
    pub beacon_pulse_id: BeaconPulseId,
    /// Root of the ordered sealed roster and alternates.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub roster_root: [u8; 32],
    /// Root of deterministic body and cross-body assignments.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub assignment_root: [u8; 32],
    /// Root of the public evidence, deliberation, and dissent record.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub result_root: [u8; 32],
    /// Height at which this body result became immutable.
    pub result_height: u64,
    /// Authority-authenticated quorum binding for a public nonbinding finding.
    pub public_finding: Option<ParliamentPublicFindingCertificateBindingV1>,
    /// Hidden-ballot binding for a formally voting body; absent for public nonbinding findings.
    pub ballot: Option<ParliamentBallotCertificateBindingV1>,
}

/// Complete automatic V1 governance certificate payload.
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
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::parliament_types::GovernanceCertificateV1")]
pub struct GovernanceCertificateV1 {
    /// Immutable proposal content authorized by the certificate.
    pub proposal_content_id: ProposalContentId,
    /// Successful end-to-end attempt that produced the certificate.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Zero-based retry sequence of the successful governance attempt.
    pub governance_attempt_sequence: u32,
    /// Final upward-only risk tier applied by the attempt.
    pub risk_tier: RiskTierV1,
    /// Ordered binding for every required body instance.
    pub body_bindings: Vec<ParliamentBodyCertificateBindingV1>,
    /// Governance policy version under which every stage was evaluated.
    pub policy_version: u64,
    /// Hash of the exact deterministic effect preimage.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub effect_preimage_hash: [u8; 32],
    /// Compare-and-set head required when the effect executes.
    pub expected_head: GovernanceExpectedHeadV1,
    /// Height of the final body result, at which the complete certificate was
    /// atomically finalized.
    pub certified_at_height: u64,
    /// Exact height at which deterministic enactment is due.
    pub enact_at_height: u64,
}

/// Structural validation failure for a complete V1 governance certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernanceCertificateErrorV1 {
    /// A typed identifier or commitment root used an inert all-zero value.
    ZeroBinding,
    /// A typed identifier did not match its complete domain-separated V1 preimage.
    NonCanonicalIdentifier,
    /// An attempt sequence exceeded its first-release retry ceiling.
    RetryLimitExceeded,
    /// A successful certificate contained no Parliament body results.
    EmptyBodyBindings,
    /// Body results were not in strict canonical V1 body order.
    NonCanonicalBodyOrder,
    /// A body index disagreed with its complete immutable future-pulse request.
    SortitionRequestMismatch,
    /// A sealed body claimed more seats than its target or eligible candidate snapshot.
    InvalidSeatCount,
    /// Two body results reused an attempt, instance, request, ballot, or TLE identifier.
    DuplicateBinding,
    /// The certificate did not contain exactly one Policy Jury result.
    MissingPolicyJury,
    /// A Policy or Confirmation Jury result omitted its private ballot binding.
    MissingBindingBallot,
    /// A nonbinding body result omitted its authenticated public-finding quorum.
    MissingPublicFinding,
    /// A public-finding endorsement count/root/quorum was structurally invalid.
    InvalidPublicFinding,
    /// A successful certificate carried a rejected, no-quorum, or no-result ballot.
    NonApprovingBallot,
    /// An emergency Policy Jury lacked affirmative votes from two thirds of original seats.
    EmergencyPolicyJuryThreshold,
    /// The stored tally was malformed.
    InvalidTally(ParliamentTallyErrorV1),
    /// The stored outcome disagreed with the deterministic tally decision.
    TallyOutcomeMismatch,
    /// A private body result root was not derived from its immutable opening and tally.
    BallotResultRootMismatch,
    /// A narrow Policy Jury approval did not have exactly one fresh Confirmation Jury result,
    /// or a non-narrow result carried one.
    ConfirmationJuryMismatch,
    /// The policy version or certification/enactment chronology was invalid.
    InvalidLifecycle,
    /// The compare-and-set head contained an inert subject or head commitment.
    InvalidExpectedHead,
}
impl fmt::Display for GovernanceCertificateErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBinding => f.write_str("governance certificate bindings must be non-zero"),
            Self::NonCanonicalIdentifier => {
                f.write_str("governance certificate contains a noncanonical identifier")
            }
            Self::RetryLimitExceeded => {
                f.write_str("governance certificate contains an over-limit retry sequence")
            }
            Self::EmptyBodyBindings => {
                f.write_str("governance certificate has no Parliament body bindings")
            }
            Self::NonCanonicalBodyOrder => {
                f.write_str("governance certificate body bindings are not in canonical order")
            }
            Self::SortitionRequestMismatch => {
                f.write_str("governance certificate sortition request binding is inconsistent")
            }
            Self::InvalidSeatCount => {
                f.write_str("governance certificate contains an impossible sealed-seat count")
            }
            Self::DuplicateBinding => {
                f.write_str("governance certificate reuses an attempt-local binding")
            }
            Self::MissingPolicyJury => {
                f.write_str("governance certificate must contain one Policy Jury result")
            }
            Self::MissingBindingBallot => {
                f.write_str("binding jury result is missing its private ballot")
            }
            Self::MissingPublicFinding => {
                f.write_str("nonbinding body result is missing public-finding quorum evidence")
            }
            Self::InvalidPublicFinding => {
                f.write_str("public-finding endorsement binding is invalid")
            }
            Self::NonApprovingBallot => {
                f.write_str("successful governance certificate contains a non-approving ballot")
            }
            Self::EmergencyPolicyJuryThreshold => f.write_str(
                "emergency Policy Jury requires affirmative votes from two thirds of original seats",
            ),
            Self::InvalidTally(error) => write!(f, "invalid governance tally: {error}"),
            Self::TallyOutcomeMismatch => {
                f.write_str("governance ballot outcome does not match its aggregate tally")
            }
            Self::BallotResultRootMismatch => {
                f.write_str("governance private-ballot result root is not canonical")
            }
            Self::ConfirmationJuryMismatch => {
                f.write_str("Confirmation Jury presence or future-pulse binding is invalid")
            }
            Self::InvalidLifecycle => {
                f.write_str("governance certificate lifecycle ordering is invalid")
            }
            Self::InvalidExpectedHead => {
                f.write_str("governance certificate compare-and-set head is invalid")
            }
        }
    }
}
impl std::error::Error for GovernanceCertificateErrorV1 {}
impl From<ParliamentTallyErrorV1> for GovernanceCertificateErrorV1 {
    fn from(error: ParliamentTallyErrorV1) -> Self {
        Self::InvalidTally(error)
    }
}

impl GovernanceCertificateV1 {
    /// Validate the certificate's context-free canonical structure.
    ///
    /// Consensus must additionally compare every binding with the persisted
    /// attempt, sortition, roster, beacon, ballot, effect, and compare-and-set
    /// state. This method rejects malformed certificates before those stateful
    /// checks and never infers a missing result.
    ///
    /// # Errors
    /// Returns `GovernanceCertificateErrorV1` for an inert, duplicated,
    /// reordered, incomplete, non-approving, or temporally invalid certificate.
    pub fn validate(&self) -> Result<(), GovernanceCertificateErrorV1> {
        self.validate_certificate_context()?;
        let mut body_instance_ids = BTreeSet::new();
        let mut election_attempt_ids = BTreeSet::new();
        let mut sortition_request_ids = BTreeSet::new();
        let mut ballot_attempt_ids = BTreeSet::new();
        let mut tle_session_ids = BTreeSet::new();
        let mut sortition_pulse_ids = BTreeSet::new();
        let mut release_pulse_ids = BTreeSet::new();
        let mut release_slots = BTreeSet::new();
        let mut previous_body = None;
        let mut policy = None;
        let mut confirmation = None;

        for binding in &self.body_bindings {
            if previous_body.is_some_and(|previous| previous >= binding.body) {
                return Err(GovernanceCertificateErrorV1::NonCanonicalBodyOrder);
            }
            previous_body = Some(binding.body);
            self.validate_body_identity(binding)?;
            sortition_pulse_ids.insert(binding.beacon_pulse_id);
            if !body_instance_ids.insert(binding.body_instance_id)
                || !election_attempt_ids.insert(binding.election_attempt_id)
                || !sortition_request_ids.insert(binding.sortition_request_id)
            {
                return Err(GovernanceCertificateErrorV1::DuplicateBinding);
            }

            self.validate_body_evidence(binding)?;
            if let Some(ballot) = binding.ballot {
                Self::validate_ballot_identity(binding, &ballot)?;
                if !ballot_attempt_ids.insert(ballot.ballot_attempt_id)
                    || !tle_session_ids.insert(ballot.tle_session_id)
                    || !release_pulse_ids.insert(ballot.release_pulse_id)
                    || !release_slots
                        .insert((ballot.release_beacon_session_id, ballot.release_height))
                {
                    return Err(GovernanceCertificateErrorV1::DuplicateBinding);
                }
                Self::validate_ballot_lifecycle(binding, &ballot)?;
                self.validate_ballot_outcome(binding, &ballot)?;
            }

            match binding.body {
                ParliamentBody::PolicyJury => policy = Some(binding),
                ParliamentBody::ConfirmationJury => confirmation = Some(binding),
                _ => {}
            }
        }

        if !sortition_pulse_ids.is_disjoint(&release_pulse_ids) {
            return Err(GovernanceCertificateErrorV1::DuplicateBinding);
        }

        let policy = policy.ok_or(GovernanceCertificateErrorV1::MissingPolicyJury)?;
        let policy_ballot = policy
            .ballot
            .ok_or(GovernanceCertificateErrorV1::MissingBindingBallot)?;
        let requires_confirmation = policy_ballot.tally.requires_confirmation()?;
        match (requires_confirmation, confirmation) {
            (false, None) => {}
            (true, Some(confirmation))
                if (if confirmation.election_attempt_sequence == 0 {
                    confirmation.sortition_request.request_height == policy.result_height
                } else {
                    confirmation.sortition_request.request_height > policy.result_height
                }) && confirmation.beacon_pulse_id != policy.beacon_pulse_id => {}
            _ => return Err(GovernanceCertificateErrorV1::ConfirmationJuryMismatch),
        }
        Ok(())
    }

    fn validate_certificate_context(&self) -> Result<(), GovernanceCertificateErrorV1> {
        if self.proposal_content_id.as_bytes() == &[0; 32]
            || self.governance_attempt_id.as_bytes() == &[0; 32]
            || self.effect_preimage_hash == [0; 32]
        {
            return Err(GovernanceCertificateErrorV1::ZeroBinding);
        }
        if self.governance_attempt_id
            != GovernanceAttemptId::derive_v1(
                self.proposal_content_id,
                self.governance_attempt_sequence,
            )
        {
            return Err(GovernanceCertificateErrorV1::NonCanonicalIdentifier);
        }
        if self.governance_attempt_sequence > MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1 {
            return Err(GovernanceCertificateErrorV1::RetryLimitExceeded);
        }
        let final_result_height = self
            .body_bindings
            .iter()
            .map(|binding| binding.result_height)
            .max()
            .ok_or(GovernanceCertificateErrorV1::EmptyBodyBindings)?;
        if self.policy_version != PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1
            || self.certified_at_height == 0
            || self.certified_at_height != final_result_height
            || self.enact_at_height <= self.certified_at_height
        {
            return Err(GovernanceCertificateErrorV1::InvalidLifecycle);
        }
        match self.expected_head {
            GovernanceExpectedHeadV1::Absent(head) => {
                if head.subject_id == [0; 32] {
                    return Err(GovernanceCertificateErrorV1::InvalidExpectedHead);
                }
            }
            GovernanceExpectedHeadV1::Present(head) => {
                if head.subject_id == [0; 32] || head.version == 0 || head.head_root == [0; 32] {
                    return Err(GovernanceCertificateErrorV1::InvalidExpectedHead);
                }
            }
        }
        Ok(())
    }

    fn validate_body_identity(
        &self,
        binding: &ParliamentBodyCertificateBindingV1,
    ) -> Result<(), GovernanceCertificateErrorV1> {
        let request = &binding.sortition_request;
        if binding.body_instance_id.as_bytes() == &[0; 32]
            || binding.election_attempt_id.as_bytes() == &[0; 32]
            || binding.sortition_request_id.as_bytes() == &[0; 32]
            || binding.beacon_session_id.as_bytes() == &[0; 32]
            || binding.beacon_pulse_id.as_bytes() == &[0; 32]
            || binding.roster_root == [0; 32]
            || binding.assignment_root == [0; 32]
            || binding.result_root == [0; 32]
            || binding.original_seats == 0
        {
            return Err(GovernanceCertificateErrorV1::ZeroBinding);
        }
        if request.validate(None).is_err()
            || (
                request.id,
                request.governance_attempt_id,
                request.body_election_attempt_id,
                request.body,
                request.beacon_session_id,
            ) != (
                binding.sortition_request_id,
                self.governance_attempt_id,
                binding.election_attempt_id,
                binding.body,
                binding.beacon_session_id,
            )
        {
            return Err(GovernanceCertificateErrorV1::SortitionRequestMismatch);
        }
        if binding.original_seats > request.target_seats
            || binding.original_seats > request.candidate_count
        {
            return Err(GovernanceCertificateErrorV1::InvalidSeatCount);
        }
        if binding.election_attempt_sequence > MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
            return Err(GovernanceCertificateErrorV1::RetryLimitExceeded);
        }
        if binding.election_attempt_id
            != BodyElectionAttemptId::derive_v1(
                self.governance_attempt_id,
                binding.body,
                binding.election_attempt_sequence,
            )
            || binding.body_instance_id
                != BodyInstanceId::derive_v1(binding.election_attempt_id, binding.roster_root)
        {
            return Err(GovernanceCertificateErrorV1::NonCanonicalIdentifier);
        }
        if binding.result_height <= request.pulse_height
            || binding.result_height > self.certified_at_height
        {
            return Err(GovernanceCertificateErrorV1::InvalidLifecycle);
        }
        Ok(())
    }

    fn validate_body_evidence(
        &self,
        binding: &ParliamentBodyCertificateBindingV1,
    ) -> Result<(), GovernanceCertificateErrorV1> {
        if matches!(
            binding.body,
            ParliamentBody::PolicyJury | ParliamentBody::ConfirmationJury
        ) {
            if binding.ballot.is_none() || binding.public_finding.is_some() {
                return Err(GovernanceCertificateErrorV1::MissingBindingBallot);
            }
        } else if binding.public_finding.is_none() || binding.ballot.is_some() {
            return Err(GovernanceCertificateErrorV1::MissingPublicFinding);
        }
        if let Some(public_finding) = binding.public_finding.as_ref() {
            let quorum = parliament_quorum_seats_v1(binding.original_seats);
            let endorsements = u32::try_from(public_finding.endorsing_assignments.len())
                .map_err(|_| GovernanceCertificateErrorV1::InvalidPublicFinding)?;
            if public_finding.endorsement_root == [0; 32]
                || public_finding.quorum != quorum
                || public_finding.endorsements != quorum
                || endorsements != public_finding.endorsements
                || public_finding
                    .endorsing_assignments
                    .iter()
                    .any(|assignment| assignment.as_bytes() == &[0; 32])
                || !public_finding
                    .endorsing_assignments
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                || public_finding.endorsement_root
                    != parliament_public_finding_endorsement_root_v1(
                        self.governance_attempt_id,
                        binding.body_instance_id,
                        binding.result_root,
                        &public_finding.endorsing_assignments,
                    )
            {
                return Err(GovernanceCertificateErrorV1::InvalidPublicFinding);
            }
        }
        Ok(())
    }

    fn validate_ballot_identity(
        binding: &ParliamentBodyCertificateBindingV1,
        ballot: &ParliamentBallotCertificateBindingV1,
    ) -> Result<(), GovernanceCertificateErrorV1> {
        if ballot.ballot_attempt_id.as_bytes() == &[0; 32]
            || ballot.tle_session_id.as_bytes() == &[0; 32]
            || ballot.tle_key_session_id.as_bytes() == &[0; 32]
            || ballot.registration_root == [0; 32]
            || ballot.dropout_root == [0; 32]
            || ballot.survivor_root == [0; 32]
            || ballot.corpus_root == [0; 32]
            || ballot.no_recovery_root == [0; 32]
            || ballot.timed_commitment_root == [0; 32]
            || ballot.release_beacon_session_id.as_bytes() == &[0; 32]
            || ballot.release_pulse_id.as_bytes() == &[0; 32]
            || ballot.opening_root == [0; 32]
        {
            return Err(GovernanceCertificateErrorV1::ZeroBinding);
        }
        if ballot.ballot_attempt_id
            != BallotAttemptId::derive_v1(binding.body_instance_id, ballot.ballot_attempt_sequence)
            || ballot.tle_session_id
                != TleSessionId::derive_v1(
                    ballot.ballot_attempt_id,
                    ballot.tle_key_session_id,
                    ballot.release_beacon_session_id,
                    ballot.release_height,
                )
        {
            return Err(GovernanceCertificateErrorV1::NonCanonicalIdentifier);
        }
        Ok(())
    }

    fn validate_ballot_lifecycle(
        binding: &ParliamentBodyCertificateBindingV1,
        ballot: &ParliamentBallotCertificateBindingV1,
    ) -> Result<(), GovernanceCertificateErrorV1> {
        let request = &binding.sortition_request;
        let registration_not_after_sortition = ballot.registered_at_height <= request.pulse_height;
        if ballot.registered_at_height == 0
            || registration_not_after_sortition
            || ballot.registration_close_height <= ballot.registered_at_height
            || ballot.survivor_freeze_height <= ballot.registration_close_height
            || ballot.commitment_close_height <= ballot.survivor_freeze_height
            || ballot.release_height <= ballot.commitment_close_height
            || ballot.opening_deadline_height <= ballot.release_height
            || ballot.registration_closed_at_height != ballot.registration_close_height
            || ballot.survivors_frozen_at_height != ballot.survivor_freeze_height
            || ballot.commitment_closed_at_height <= ballot.survivor_freeze_height
            || ballot.commitment_closed_at_height > ballot.commitment_close_height
            || ballot
                .registration_close_height
                .saturating_sub(ballot.registered_at_height)
                < u64::from(ballot.max_corpus_entries).saturating_add(1)
            || ballot
                .survivor_freeze_height
                .saturating_sub(ballot.registration_close_height)
                < u64::from(ballot.max_corpus_entries)
            || ballot
                .commitment_close_height
                .saturating_sub(ballot.survivor_freeze_height)
                < parliament_timed_ovn_required_chunk_blocks_v1(ballot.max_corpus_entries)
            || ballot.max_ballot_retries > MAX_PARLIAMENT_BALLOT_RETRIES_V1
            || ballot.ballot_attempt_sequence > ballot.max_ballot_retries
            || !(1..=MAX_PARLIAMENT_BALLOT_CORPUS_ENTRIES_V1).contains(&ballot.max_corpus_entries)
            || !(binding.original_seats..).contains(&ballot.max_corpus_entries)
            || ballot.tally.accepted_ballots > ballot.max_corpus_entries
            || ballot.tally.original_seats != binding.original_seats
            || ballot.opening_height < ballot.release_height
            || ballot.opening_height > ballot.opening_deadline_height
            || !(ballot.opening_height..=ballot.opening_deadline_height)
                .contains(&binding.result_height)
        {
            return Err(GovernanceCertificateErrorV1::InvalidLifecycle);
        }
        Ok(())
    }

    fn validate_ballot_outcome(
        &self,
        binding: &ParliamentBodyCertificateBindingV1,
        ballot: &ParliamentBallotCertificateBindingV1,
    ) -> Result<(), GovernanceCertificateErrorV1> {
        let decision = ballot.tally.decision()?;
        if decision != ballot.outcome {
            return Err(GovernanceCertificateErrorV1::TallyOutcomeMismatch);
        }
        if binding.result_root
            != parliament_ballot_result_root_v1(
                self.governance_attempt_id,
                binding.body_instance_id,
                ballot.ballot_attempt_id,
                ballot.opening_root,
                ballot.tally,
                ballot.outcome,
                binding.result_height,
            )
        {
            return Err(GovernanceCertificateErrorV1::BallotResultRootMismatch);
        }
        if decision != ParliamentAggregateOutcomeV1::Approved {
            return Err(GovernanceCertificateErrorV1::NonApprovingBallot);
        }
        if self.risk_tier == RiskTierV1::Emergency
            && binding.body == ParliamentBody::PolicyJury
            && ballot.tally.aye < parliament_quorum_seats_v1(binding.original_seats)
        {
            return Err(GovernanceCertificateErrorV1::EmergencyPolicyJuryThreshold);
        }
        Ok(())
    }
}

impl GovernanceCertificateId {
    /// Derive the content identifier for an exact validated V1 certificate.
    #[must_use]
    pub fn derive_v1(certificate: &GovernanceCertificateV1) -> Self {
        Self::new(crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::GOVERNANCE_CERTIFICATE_ID_V1,
            certificate,
        ))
    }
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::parliament_types::ParliamentExecutionFailureRootPreimageV1"
)]
struct ParliamentExecutionFailureRootPreimageV1 {
    certificate: GovernanceCertificateV1,
    enactment_height: u64,
}

/// Derive the only valid failure root for deterministic certified-effect execution.
///
/// The root commits to the complete canonical certificate and the exact
/// finalized height at which its effect was due. Core derives it only after an
/// isolated effect transaction fails and validates that `enactment_height`
/// equals the certificate's committed `enact_at_height`; no lifecycle
/// submitter contributes error text or discretionary failure evidence.
#[must_use]
pub fn parliament_execution_failure_root_v1(
    certificate: &GovernanceCertificateV1,
    enactment_height: u64,
) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::PARLIAMENT_EXECUTION_FAILURE_ROOT_V1,
        &ParliamentExecutionFailureRootPreimageV1 {
            certificate: certificate.clone(),
            enactment_height,
        },
    )
}

impl ProposalKind {
    /// Return the transaction operator committed by effect-sensitive proposal kinds.
    ///
    /// These proposal effects either consume the operator as execution authority or
    /// persist it as immutable provenance. The retained governance proposer must
    /// therefore agree with this payload-bound identity.
    #[must_use]
    pub const fn proposal_operator_v1(&self) -> Option<&AccountId> {
        match self {
            Self::DeployContract(payload) => Some(&payload.proposal_operator),
            Self::RuntimeUpgrade(payload) => Some(&payload.proposal_operator),
            Self::ValidationFeePolicy(payload) => Some(&payload.proposal_operator),
            Self::ValidationFeePayoutLifecycle(payload) => Some(&payload.proposal_operator),
            Self::ContractLifecycleGovernance(payload) => Some(&payload.proposal_operator),
            Self::SccpRouteGovernance(_)
            | Self::MusubiRegistryGovernance(_)
            | Self::SorafsProviderGovernance(_)
            | Self::ContractEmergencyHold(_)
            | Self::GlobalDataTriggerPermissionGovernance(_) => None,
        }
    }

    /// Return the first proposal-owned `u64` that cannot be represented exactly by every SDK.
    ///
    /// This is an exhaustive traversal of the closed first-release proposal enum, including
    /// nested SCCP and Musubi payloads. Admission and restore paths use it before proposal state
    /// can become authoritative.
    #[must_use]
    pub fn first_release_exact_json_u64_invariant_error(&self) -> Option<&'static str> {
        let maximum = FIRST_RELEASE_MAX_EXACT_JSON_U64;
        match self {
            Self::DeployContract(_)
            | Self::ValidationFeePolicy(_)
            | Self::ValidationFeePayoutLifecycle(_)
            | Self::GlobalDataTriggerPermissionGovernance(_)
            | Self::SorafsProviderGovernance(_) => None,
            Self::ContractLifecycleGovernance(proposal) => (proposal.expected_revision > maximum)
                .then_some(
                    "contract lifecycle expected revision exceeds the exact JSON integer maximum",
                ),
            Self::ContractEmergencyHold(proposal) => {
                if proposal.expected_revision > maximum {
                    Some(
                        "contract emergency-hold expected revision exceeds the exact JSON integer maximum",
                    )
                } else if proposal.duration_blocks > maximum {
                    Some("contract emergency-hold duration exceeds the exact JSON integer maximum")
                } else {
                    None
                }
            }
            Self::RuntimeUpgrade(proposal) => {
                if proposal.manifest.start_height > maximum {
                    Some(
                        "runtime-upgrade proposal start height exceeds the exact JSON integer maximum",
                    )
                } else if proposal.manifest.end_height > maximum {
                    Some(
                        "runtime-upgrade proposal end height exceeds the exact JSON integer maximum",
                    )
                } else {
                    None
                }
            }
            Self::SccpRouteGovernance(proposal) => proposal.proposal.first_json_u64_violation(),
            Self::MusubiRegistryGovernance(action) => {
                action.first_release_exact_json_u64_invariant_error(maximum)
            }
        }
    }

    /// Compute the deterministic, proposal-kind-separated fingerprint (`Blake2b-32`).
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        let domain = match self {
            Self::DeployContract(_) => crate::governance_fingerprint::DEPLOY_CONTRACT_V1,
            Self::RuntimeUpgrade(_) => crate::governance_fingerprint::RUNTIME_UPGRADE_V1,
            Self::SccpRouteGovernance(_) => crate::governance_fingerprint::SCCP_ROUTE_GOVERNANCE_V1,
            Self::ValidationFeePolicy(_) => crate::governance_fingerprint::VALIDATION_FEE_POLICY_V1,
            Self::ValidationFeePayoutLifecycle(_) => {
                crate::governance_fingerprint::VALIDATION_FEE_PAYOUT_LIFECYCLE_V1
            }
            Self::MusubiRegistryGovernance(_) => {
                crate::governance_fingerprint::MUSUBI_REGISTRY_GOVERNANCE_V1
            }
            Self::SorafsProviderGovernance(_) => {
                crate::governance_fingerprint::SORAFS_PROVIDER_GOVERNANCE_V1
            }
            Self::ContractLifecycleGovernance(_) => {
                crate::governance_fingerprint::CONTRACT_LIFECYCLE_GOVERNANCE_V1
            }
            Self::ContractEmergencyHold(_) => {
                crate::governance_fingerprint::CONTRACT_EMERGENCY_HOLD_V1
            }
            Self::GlobalDataTriggerPermissionGovernance(_) => {
                crate::governance_fingerprint::GLOBAL_DATA_TRIGGER_PERMISSION_GOVERNANCE_V1
            }
        };
        crate::governance_fingerprint::fingerprint(domain, self)
    }

    /// Hash the exact deterministic effect preimage under a purpose-distinct domain.
    ///
    /// This deliberately commits the complete closed proposal variant again instead of reusing
    /// its content identifier, so a certificate cannot substitute a proposal identity digest for
    /// the independently checked execution binding.
    #[must_use]
    pub fn effect_preimage_hash_v1(&self) -> [u8; 32] {
        crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::GOVERNANCE_EFFECT_PREIMAGE_V1,
            self,
        )
    }

    /// Derive the compare-and-set subject affected by this proposal.
    ///
    /// Proposal identity and governed-subject identity are deliberately distinct:
    /// competing proposals for the same contract, registry, package, alias, release,
    /// provider, or payout lifecycle must contend on one subject head even when their
    /// complete effect preimages differ.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the validation-fee payout binding cannot be
    /// encoded while deriving its canonical lifecycle seal.
    pub fn governed_subject_id_v1(&self) -> Result<[u8; 32], norito::Error> {
        let subject = match self {
            Self::DeployContract(proposal) => {
                GovernanceSubjectPreimageV1::Contract(proposal.contract_address.clone())
            }
            Self::ContractLifecycleGovernance(proposal) => {
                GovernanceSubjectPreimageV1::Contract(proposal.contract_address.clone())
            }
            Self::ContractEmergencyHold(proposal) => {
                GovernanceSubjectPreimageV1::Contract(proposal.contract_address.clone())
            }
            Self::RuntimeUpgrade(proposal) => {
                GovernanceSubjectPreimageV1::RuntimeUpgrade(proposal.manifest.id())
            }
            Self::SccpRouteGovernance(proposal) => {
                GovernanceSubjectPreimageV1::Sccp(proposal.proposal.subjects())
            }
            Self::ValidationFeePolicy(_) => {
                GovernanceSubjectPreimageV1::ValidationFeePolicyRegistry
            }
            Self::ValidationFeePayoutLifecycle(_) => {
                GovernanceSubjectPreimageV1::ValidationFeePayoutPolicyRegistry
            }
            Self::MusubiRegistryGovernance(action) => match action {
                MusubiParliamentActionV1::RecoverPackageOwners(recovery) => {
                    GovernanceSubjectPreimageV1::MusubiPackage(recovery.package.clone())
                }
                MusubiParliamentActionV1::RetargetAlias(recovery) => {
                    GovernanceSubjectPreimageV1::MusubiAlias(recovery.alias.clone())
                }
                MusubiParliamentActionV1::TakedownArtifact(takedown) => {
                    GovernanceSubjectPreimageV1::MusubiRelease(takedown.release.clone())
                }
                MusubiParliamentActionV1::SetRegistryPolicy(_) => {
                    GovernanceSubjectPreimageV1::MusubiRegistryPolicy
                }
            },
            Self::SorafsProviderGovernance(proposal) => match proposal.action.as_ref() {
                SorafsProviderGovernanceActionV1::Admission(action) => action
                    .provider_id()
                    .map_err(|error| norito::Error::Message(error.to_string()))?
                    .map_or(
                        GovernanceSubjectPreimageV1::SorafsAdmissionCouncil,
                        GovernanceSubjectPreimageV1::SorafsProviderAdmission,
                    ),
                _ => GovernanceSubjectPreimageV1::SorafsProvider(
                    proposal.action.provider_id().ok_or_else(|| {
                        norito::Error::Message("missing provider identity".into())
                    })?,
                ),
            },
            Self::GlobalDataTriggerPermissionGovernance(proposal) => {
                GovernanceSubjectPreimageV1::GlobalDataTriggerPermission(proposal.authority.clone())
            }
        };
        Ok(crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::GOVERNANCE_SUBJECT_ID_V1,
            &subject,
        ))
    }
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parliament_types::GovernanceSubjectPreimageV1")]
enum GovernanceSubjectPreimageV1 {
    #[codec(index = 0)]
    Contract(ContractAddress),
    #[codec(index = 1)]
    RuntimeUpgrade(crate::runtime::RuntimeUpgradeId),
    #[codec(index = 2)]
    Sccp(Vec<crate::sccp::governance::SccpGovernanceSubjectV1>),
    #[codec(index = 3)]
    ValidationFeePolicyRegistry,
    #[codec(index = 4)]
    ValidationFeePayoutPolicyRegistry,
    #[codec(index = 5)]
    MusubiPackage(crate::musubi::MusubiPackageIdV1),
    #[codec(index = 6)]
    MusubiAlias(crate::musubi::MusubiAliasNameV1),
    #[codec(index = 7)]
    MusubiRelease(crate::musubi::MusubiReleaseIdV1),
    #[codec(index = 8)]
    MusubiRegistryPolicy,
    #[codec(index = 9)]
    SorafsProvider(crate::sorafs::capacity::ProviderId),
    #[codec(index = 10)]
    GlobalDataTriggerPermission(AccountId),
    #[codec(index = 11)]
    SorafsAdmissionCouncil,
    #[codec(index = 12)]
    SorafsProviderAdmission(crate::sorafs::capacity::ProviderId),
}

impl ProposalContentId {
    /// Derive the immutable identifier for exact typed proposal content.
    #[must_use]
    pub fn derive_v1(proposal: &ProposalKind) -> Self {
        Self::new(proposal.fingerprint())
    }
}
#[cfg(test)]
#[path = "types/tests.rs"]
mod tests;

#[cfg(test)]
mod captured_types_schema_tests;

#[cfg(test)]
mod prepared_hash32_field_tests {
    use super::*;

    fn framed_payload(value: &dyn norito::core::SerializePayload) -> Vec<u8> {
        let mut payload = Vec::new();
        norito::core::serialize_to_writer(value, &mut payload).unwrap();
        let mut framed = Vec::new();
        norito::core::write_len_with_flags(
            &mut framed,
            payload.len() as u64,
            norito::core::default_encode_flags(),
        )
        .unwrap();
        framed.extend_from_slice(&payload);
        framed
    }

    #[test]
    fn every_hash32_prepared_consumer_preserves_exact_canonical_bytes_without_heap_leaf_work() {
        macro_rules! check {
            ($ty:ident) => {{
                let value = $ty::new([0x63; 32]);
                let framed = framed_payload(&value);
                let mut offset = 0;
                let field = norito::core::framed_field::<$ty>(&framed, &mut offset).unwrap();
                assert_eq!(offset, framed.len());
                let decoded = norito::with_decode_limits_scope(
                    norito::core::DecodeLimits::new(16_384, usize::MAX, usize::MAX, 36, 64),
                    || $ty::decode_prepared_field_v1(field),
                )
                .unwrap();
                assert_eq!(decoded, value);
                assert_eq!(
                    norito::encode_canonical(&decoded).unwrap(),
                    norito::encode_canonical(&value).unwrap()
                );
            }};
        }
        check!(ContractCodeHash);
        check!(ContractAbiHash);
        check!(AgendaItemId);
        check!(DraftId);
        check!(ProposalContentId);
        check!(GovernanceAttemptId);
        check!(BodyInstanceId);
        check!(BodyElectionAttemptId);
        check!(AssignmentId);
        check!(SortitionRequestId);
        check!(BallotAttemptId);
        check!(BeaconSessionId);
        check!(BeaconPulseId);
        check!(TleSessionId);
        check!(TleKeySessionId);
        check!(GovernanceCertificateId);
    }

    #[test]
    fn prepared_hash32_field_keeps_original_version_length_and_complete_consumption_checks() {
        for mutation in 0..3 {
            let mut wire = HashWire32::new([0x61; 32]);
            match mutation {
                0 => wire.version += 1,
                1 => wire.declared_len -= 1,
                2 => {}
                _ => unreachable!(),
            }
            let mut framed = framed_payload(&wire);
            if mutation == 2 {
                // Rewrite only the field's canonical length prefix to include
                // one trailing byte, preserving an otherwise exact hash body.
                framed[0] += 1;
                framed.push(0);
            }
            let mut offset = 0;
            let field =
                norito::core::framed_field::<TleKeySessionId>(&framed, &mut offset).unwrap();
            assert!(TleKeySessionId::decode_prepared_field_v1(field).is_err());
        }
    }
}
