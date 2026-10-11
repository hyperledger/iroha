//! This module contains data and structures related only to smart contract execution
mod artifact_id;
use crate::{
    account::{AccountAddressError, AccountId, rekey::AccountAliasDomain},
    id::NetworkId,
    nexus::DataSpaceCatalog,
};
pub use artifact_id::ContractArtifactId;
use bech32::{Bech32m, Hrp};
use iroha_data_model_derive::model;
use iroha_model_base::topology::DataSpaceId;
use iroha_model_base::{error::ParseError, name::Name};
use iroha_primitives::conststr::ConstString;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::{format, str::FromStr, string::String, vec::Vec};
use thiserror::Error;
/// Domain separator for the canonical deployable contract artifact hash.
///
/// The hash deliberately covers the complete `.to` image, including the fixed
/// execution header. Contract debug information belongs in a sidecar and is
/// therefore not part of a deployable artifact.
pub const CONTRACT_CODE_HASH_DOMAIN: &[u8] = b"iroha:ivm:contract-artifact:v1\0";
/// Compute the canonical identity of a deployable IVM contract artifact.
///
/// This binds every execution-relevant header field as well as embedded
/// interface metadata, literals, and code. Hashing alone does not validate
/// artifact structure, ABI compatibility, or execution admission.
#[must_use]
pub fn contract_code_hash(artifact: &[u8]) -> iroha_crypto::Hash {
    iroha_crypto::Hash::new_from_chunks(&[CONTRACT_CODE_HASH_DOMAIN, artifact])
}
#[cfg(test)]
mod contract_code_hash_tests {
    use super::{CONTRACT_CODE_HASH_DOMAIN, contract_code_hash};
    use iroha_crypto::Hash;

    #[test]
    fn contract_code_hash_uses_the_exact_domain_and_complete_image() {
        let mut artifact = b"IVM\0header-and-contract-body".to_vec();
        let original = contract_code_hash(&artifact);
        assert_eq!(
            CONTRACT_CODE_HASH_DOMAIN,
            b"iroha:ivm:contract-artifact:v1\0"
        );
        assert_eq!(
            original,
            Hash::new_from_chunks(&[CONTRACT_CODE_HASH_DOMAIN, &artifact])
        );
        assert_ne!(original, Hash::new(&artifact));
        for index in [0, artifact.len() - 1] {
            artifact[index] ^= 1;
            assert_ne!(contract_code_hash(&artifact), original);
            artifact[index] ^= 1;
        }
        assert_eq!(contract_code_hash(&artifact), original);
        artifact.push(0);
        assert_ne!(contract_code_hash(&artifact), original);
    }
}
pub mod payloads {
    //! Contexts with function arguments for different entrypoints
    use crate::{block::BlockHeader, prelude::*};
    use norito::{
        codec::{Decode, Encode},
        core::DecodeFromSlice,
    };
    /// Context for migrate entrypoint
    #[derive(Debug, Clone, Encode, Decode)]
    #[norito(decode_from_slice)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::smart_contract::payloads::ExecutorContext")]
    pub struct ExecutorContext {
        /// Account that is executing the operation
        pub authority: AccountId,
        /// Block currently being processed (or latest block hash for queries)
        pub curr_block: BlockHeader,
    }
    /// Generic payload for `validate_*()` entrypoints of executor.
    #[derive(Debug, Clone, Encode, Decode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::smart_contract::payloads::Validate")]
    pub struct Validate<T> {
        /// Context of the executor
        pub context: ExecutorContext,
        /// Operation to be validated
        pub target: T,
    }
    impl<'a, T> DecodeFromSlice<'a> for Validate<T>
    where
        T: for<'de> norito::NoritoDeserialize<'de> + norito::NoritoSerialize,
    {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
            norito::core::decode_field_canonical::<Self>(bytes)
        }
    }
    #[cfg(test)]
    mod payloads_tests {
        use super::*;
        use core::num::NonZeroU64;
        use iroha_crypto::KeyPair;
        use norito::core::DecodeFromSlice;
        fn checked_random_account_id() -> AccountId {
            AccountId::new(
                KeyPair::try_random()
                    .expect("test fixture random key generation should succeed")
                    .public_key()
                    .clone(),
            )
        }
        #[test]
        fn validate_decode_from_slice_roundtrips_any_query() {
            let authority = checked_random_account_id();
            let header = BlockHeader {
                height: NonZeroU64::new(1).expect("nonzero height"),
                prev_block_hash: None,
                merkle_root: None,
                da_proof_policies_hash: None,
                da_commitments_hash: None,
                da_pin_intents_hash: None,
                npos_effects_hash: None,
                global_beacon_pulse_hash: None,
                execution_context_hash: None,
                creation_time_ms: 0,
                view_change_index: 0,
                confidential_features: None,
            };
            let context = ExecutorContext {
                authority: authority.clone(),
                curr_block: header,
            };
            let target = crate::query::AnyQueryBox::Singular(
                crate::query::SingularQueryBox::FindExecutorDataModel(
                    crate::query::executor::prelude::FindExecutorDataModel,
                ),
            );
            let validate = Validate { context, target };
            let bytes = validate.encode();
            let (decoded, used) = Validate::<crate::query::AnyQueryBox>::decode_from_slice(&bytes)
                .expect("decode validate");
            assert_eq!(used, bytes.len());
            assert_eq!(decoded.context.authority, authority);
            assert_eq!(decoded.context.curr_block, header);
            assert!(matches!(
                decoded.target,
                crate::query::AnyQueryBox::Singular(
                    crate::query::SingularQueryBox::FindExecutorDataModel(_)
                )
            ));
        }
    }
}
/// Metadata key tracking the next public contract deploy nonce for an account.
pub const CONTRACT_DEPLOY_NONCE_METADATA_KEY: &str = "contract_deploy_nonce";
/// Maximum duration of a certified Parliament emergency hold, in blocks.
pub const MAX_CONTRACT_EMERGENCY_HOLD_BLOCKS_V1: u64 = 3_600;
/// Exact first-release contract lifecycle schema version.
pub const CONTRACT_LIFECYCLE_CONTROL_VERSION_V1: u16 = 1;
/// Canonical human-readable prefix for every Bech32m contract address.
///
/// Exact genesis-derived network identity is committed inside the address digest. The presentation
/// prefix is therefore deliberately network-independent and parsers reject every other prefix.
pub const CONTRACT_ADDRESS_HRP: &str = "irohac";
const CONTRACT_ADDRESS_VERSION_V1: u8 = 1;
const CONTRACT_ADDRESS_TAG_V1: &[u8] = b"iroha:contract-address:v1";
const CONTRACT_SUBJECT_HASH_TO_POINT_TAG_V1: &[u8] = b"iroha:contract-subject:hash-to-point:v1:";
const CONTRACT_ADDRESS_HASH_LEN: usize = 20;
const CONTRACT_ADDRESS_PAYLOAD_LEN_V1: usize = 1 + 8 + CONTRACT_ADDRESS_HASH_LEN;
/// Exact ASCII byte length of a canonical V1 Bech32m contract address.
/// The layout is the fixed HRP, separator, five-bit payload, and six checksum characters.
pub const CONTRACT_ADDRESS_LITERAL_LEN_V1: usize =
    CONTRACT_ADDRESS_HRP.len() + 1 + (CONTRACT_ADDRESS_PAYLOAD_LEN_V1 * 8).div_ceil(5) + 6;

pub use self::model::*;
#[model]
mod model {
    use super::*;
    use derive_more::Display;
    /// Canonical contract alias: `name::namespace` or `name::dataspace.namespace`.
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, IntoSchema)]
    #[repr(transparent)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::smart_contract::model::ContractAlias")]
    pub struct ContractAlias(pub(super) ConstString);
    /// Canonical Bech32m-encoded public contract address.
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, IntoSchema)]
    #[repr(transparent)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::smart_contract::model::ContractAddress")]
    pub struct ContractAddress(pub(super) ConstString);
    /// Active smart-contract instance binding.
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
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::smart_contract::model::ContractInstance")]
    pub struct ContractInstance {
        /// Canonical deployed contract address.
        pub contract_address: ContractAddress,
        /// Optional stable alias bound to the instance.
        pub contract_alias: Option<ContractAlias>,
        /// Code hash currently activated for this address.
        pub code_hash: iroha_crypto::Hash,
    }
    /// Authority that controls the mutable lifecycle of a deployed contract.
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
    #[norito(tag = "owner", content = "value", deny_unknown_fields)]
    pub enum ContractLifecycleOwnerV1 {
        /// Lifecycle changes are authorized by this account.
        #[codec(index = 0)]
        Account(AccountId),
        /// Lifecycle changes are authorized only by a certified Parliament effect.
        #[codec(index = 1)]
        Parliament,
    }
    /// Immutable provenance payload for a direct contract deployment.
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
    pub struct DirectContractDeploymentOriginV1 {
        /// Account whose nonce derived the address.
        pub deployer: AccountId,
    }
    /// Immutable provenance payload for a Parliament contract deployment.
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
    pub struct ParliamentContractDeploymentOriginV1 {
        /// Account that submitted the proposal.
        pub proposer: AccountId,
        /// Immutable proposal content identifier.
        pub proposal_content_id: [u8; 32],
        /// Successful governance-attempt identifier.
        pub governance_attempt_id: [u8; 32],
    }
    /// Immutable provenance of a contract address's first deployment.
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
    #[norito(tag = "origin", content = "value", deny_unknown_fields)]
    pub enum ContractDeploymentOriginV1 {
        /// Direct deployment by an account.
        #[codec(index = 0)]
        Direct(DirectContractDeploymentOriginV1),
        /// Deployment enacted by a certified Parliament proposal.
        #[codec(index = 1)]
        Parliament(ParliamentContractDeploymentOriginV1),
    }
    /// Revocable authority delegated by an account owner to Parliament.
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
    #[norito(tag = "delegation", content = "value", deny_unknown_fields)]
    pub enum ContractParliamentDelegationV1 {
        /// Parliament has no consensual lifecycle authority.
        #[codec(index = 0)]
        None,
        /// Parliament may activate or deactivate the contract, but may not transfer ownership.
        #[codec(index = 1)]
        Lifecycle,
    }
    /// Time-bounded containment imposed by the Parliament emergency corridor.
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
    pub struct ContractEmergencyHoldV1 {
        /// Non-zero digest of the incident evidence.
        pub incident_digest: [u8; 32],
        /// Certified proposal content identifier.
        pub proposal_content_id: [u8; 32],
        /// Certified governance-attempt identifier.
        pub governance_attempt_id: [u8; 32],
        /// Human-readable containment reason.
        pub reason: String,
        /// Block at which containment was imposed.
        pub imposed_at_height: u64,
        /// First block at which execution is allowed again.
        pub expires_at_height: u64,
    }
    /// Consensus-persisted ownership and lifecycle-control record for one contract address.
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
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::smart_contract::model::ContractLifecycleControlV1")]
    pub struct ContractLifecycleControlV1 {
        /// Exact persisted schema version; first-release snapshots require `1`.
        pub version: u16,
        /// Immutable first-deployment provenance.
        pub origin: ContractDeploymentOriginV1,
        /// Current lifecycle owner.
        pub owner: ContractLifecycleOwnerV1,
        /// Offered owner awaiting explicit acceptance.
        pub pending_owner: Option<ContractLifecycleOwnerV1>,
        /// Revocable consensual Parliament delegation.
        pub parliament_delegation: ContractParliamentDelegationV1,
        /// Code hash currently active at this address, or `None` while suspended.
        pub active_code_hash: Option<iroha_crypto::Hash>,
        /// Last artifact bound at this address, retained across suspension, including pending hooks.
        /// An active code hash must equal this value. Retention is not proof that a pending hook ran.
        #[norito(required)]
        pub retained_code_hash: Option<iroha_crypto::Hash>,
        /// Non-zero compare-and-swap revision.
        pub revision: u64,
        /// Optional time-bounded emergency containment.
        pub emergency_hold: Option<ContractEmergencyHoldV1>,
    }
}

impl ContractLifecycleControlV1 {
    /// Construct a first-revision direct-deployment lifecycle record.
    #[must_use]
    pub fn direct(deployer: AccountId) -> Self {
        Self {
            version: CONTRACT_LIFECYCLE_CONTROL_VERSION_V1,
            origin: ContractDeploymentOriginV1::Direct(DirectContractDeploymentOriginV1 {
                deployer: deployer.clone(),
            }),
            owner: ContractLifecycleOwnerV1::Account(deployer),
            pending_owner: None,
            parliament_delegation: ContractParliamentDelegationV1::None,
            active_code_hash: None,
            retained_code_hash: None,
            revision: 1,
            emergency_hold: None,
        }
    }

    /// Construct a first-revision Parliament-deployment lifecycle record.
    #[must_use]
    pub fn parliament(
        proposer: AccountId,
        proposal_content_id: [u8; 32],
        governance_attempt_id: [u8; 32],
    ) -> Self {
        Self {
            version: CONTRACT_LIFECYCLE_CONTROL_VERSION_V1,
            origin: ContractDeploymentOriginV1::Parliament(ParliamentContractDeploymentOriginV1 {
                proposer,
                proposal_content_id,
                governance_attempt_id,
            }),
            owner: ContractLifecycleOwnerV1::Parliament,
            pending_owner: None,
            parliament_delegation: ContractParliamentDelegationV1::None,
            active_code_hash: None,
            retained_code_hash: None,
            revision: 1,
            emergency_hold: None,
        }
    }

    /// Validate context-free lifecycle invariants.
    ///
    /// # Errors
    /// Returns a stable explanation when the record cannot be consensus-authoritative.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != CONTRACT_LIFECYCLE_CONTROL_VERSION_V1 {
            return Err(
                "incompatible contract lifecycle schema version; regenerate first-release genesis and snapshots",
            );
        }
        if self.revision == 0 {
            return Err("contract lifecycle revision must be non-zero");
        }
        if self.active_code_hash.is_some() && self.active_code_hash != self.retained_code_hash {
            return Err("active contract code must equal its retained artifact identity");
        }
        if self.pending_owner.as_ref() == Some(&self.owner) {
            return Err("pending contract owner must differ from current owner");
        }
        if self.owner == ContractLifecycleOwnerV1::Parliament
            && self.parliament_delegation != ContractParliamentDelegationV1::None
        {
            return Err("Parliament-owned contract cannot carry delegated Parliament authority");
        }
        if matches!(
            &self.origin,
            ContractDeploymentOriginV1::Parliament(origin)
                if origin.proposal_content_id == [0; 32]
                    || origin.governance_attempt_id == [0; 32]
        ) {
            return Err("Parliament contract origin identifiers must be non-zero");
        }
        if let Some(hold) = &self.emergency_hold
            && (hold.incident_digest == [0; 32]
                || hold.proposal_content_id == [0; 32]
                || hold.governance_attempt_id == [0; 32]
                || hold.reason.trim().is_empty()
                || hold.imposed_at_height == 0
                || hold.expires_at_height <= hold.imposed_at_height
                || hold.expires_at_height - hold.imposed_at_height
                    > MAX_CONTRACT_EMERGENCY_HOLD_BLOCKS_V1)
        {
            return Err("invalid contract emergency hold");
        }
        Ok(())
    }

    /// Return whether execution is contained at `height`.
    #[must_use]
    pub fn is_held_at(&self, height: u64) -> bool {
        self.emergency_hold
            .as_ref()
            .is_some_and(|hold| height >= hold.imposed_at_height && height < hold.expires_at_height)
    }
}
struct ContractAliasSegments<'a> {
    name: &'a str,
    domain: Option<&'a str>,
    dataspace: &'a str,
}
impl ContractAlias {
    /// Build a contract alias from validated components.
    ///
    /// # Errors
    /// Returns [`ParseError`] when any component is invalid.
    pub fn from_components(
        name: &str,
        domain_alias: Option<&str>,
        dataspace_alias: &str,
    ) -> Result<Self, ParseError> {
        let name = normalize_contract_alias_segment(name, "contract alias name")?;
        let domain_alias = domain_alias
            .map(|value| normalize_contract_alias_segment(value, "contract alias domain"))
            .transpose()?;
        let dataspace_alias =
            normalize_contract_alias_segment(dataspace_alias, "contract alias dataspace")?;
        let literal = domain_alias.map_or_else(
            || format!("{name}::{dataspace_alias}"),
            |domain_alias| format!("{name}::{domain_alias}.{dataspace_alias}"),
        );
        literal.parse()
    }
    /// Contract alias name segment (`<name>`).
    #[must_use]
    pub fn name_segment(&self) -> &str {
        let segments = split_contract_alias_segments(self.as_ref())
            .expect("contract alias must remain valid after construction");
        segments.name
    }
    /// Optional alias-domain segment (`<domain>`).
    #[must_use]
    pub fn domain_segment(&self) -> Option<&str> {
        let segments = split_contract_alias_segments(self.as_ref())
            .expect("contract alias must remain valid after construction");
        segments.domain
    }
    /// Dataspace segment (`<dataspace>`).
    #[must_use]
    pub fn dataspace_segment(&self) -> &str {
        let segments = split_contract_alias_segments(self.as_ref())
            .expect("contract alias must remain valid after construction");
        segments.dataspace
    }
    /// Resolve the alias components against the dataspace catalog.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the dataspace alias is unknown.
    pub fn resolve_components(
        &self,
        catalog: &DataSpaceCatalog,
    ) -> Result<(Name, Option<AccountAliasDomain>, DataSpaceId), ParseError> {
        let name = self
            .name_segment()
            .parse()
            .map_err(|_| ParseError::new("contract alias name segment is invalid"))?;
        let domain = self
            .domain_segment()
            .map(str::parse::<AccountAliasDomain>)
            .map(|result| {
                result.map_err(|_| ParseError::new("contract alias domain segment is invalid"))
            })
            .transpose()?;
        let dataspace = catalog
            .by_alias(self.dataspace_segment())
            .map(|entry| entry.id)
            .ok_or_else(|| ParseError::new("unknown dataspace alias in contract alias"))?;
        Ok((name, domain, dataspace))
    }
}
fn split_contract_alias_segments(input: &str) -> Result<ContractAliasSegments<'_>, ParseError> {
    let (name, right) = input.split_once("::").ok_or_else(|| {
        ParseError::new(
            "contract alias must use `<name>::<domain>.<dataspace>` or `<name>::<dataspace>` format",
        )
    })?;
    if right.contains("::") {
        return Err(ParseError::new(
            "contract alias must contain exactly one `::` separator",
        ));
    }
    if right.contains('@') {
        return Err(ParseError::new(
            "contract alias must use `.` instead of `@` between domain and dataspace",
        ));
    }
    let dot_count = right.bytes().filter(|byte| *byte == b'.').count();
    if dot_count == 1 {
        let (domain, dataspace) = right.split_once('.').expect("counted dot");
        return Ok(ContractAliasSegments {
            name,
            domain: Some(domain),
            dataspace,
        });
    }
    if dot_count > 1 {
        return Err(ParseError::new(
            "contract alias must contain at most one `.` after `::`",
        ));
    }
    Ok(ContractAliasSegments {
        name,
        domain: None,
        dataspace: right,
    })
}
fn normalize_contract_alias_segment(
    value: &str,
    segment: &'static str,
) -> Result<String, ParseError> {
    if value.is_empty() {
        return Err(ParseError::new("contract alias segments must not be empty"));
    }
    if value.contains(':') {
        return Err(ParseError::new(match segment {
            "contract alias name" => "contract alias name segment must not contain `:`",
            "contract alias domain" => "contract alias domain segment must not contain `:`",
            "contract alias dataspace" => "contract alias dataspace segment must not contain `:`",
            _ => "contract alias segment must not contain `:`",
        }));
    }
    if matches!(
        segment,
        "contract alias domain" | "contract alias dataspace"
    ) && value.contains('.')
    {
        return Err(ParseError::new(match segment {
            "contract alias domain" => "contract alias domain segment must not contain `.`",
            "contract alias dataspace" => "contract alias dataspace segment must not contain `.`",
            _ => "contract alias segment must not contain `.`",
        }));
    }
    let normalized = Name::from_str(value).map_err(|_| {
        ParseError::new(match segment {
            "contract alias name" => "contract alias name segment is invalid",
            "contract alias domain" => "contract alias domain segment is invalid",
            "contract alias dataspace" => "contract alias dataspace segment is invalid",
            _ => "contract alias segment is invalid",
        })
    })?;
    Ok(normalized.as_ref().to_owned())
}
impl FromStr for ContractAlias {
    type Err = ParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ParseError::new("contract alias must not be empty"));
        }
        if trimmed != value {
            return Err(ParseError::new(
                "contract alias must not contain leading or trailing whitespace",
            ));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(ParseError::new(
                "contract alias must not contain control characters",
            ));
        }
        let segments = split_contract_alias_segments(trimmed)?;
        let name = normalize_contract_alias_segment(segments.name, "contract alias name")?;
        let domain = segments
            .domain
            .map(|value| normalize_contract_alias_segment(value, "contract alias domain"))
            .transpose()?;
        let dataspace =
            normalize_contract_alias_segment(segments.dataspace, "contract alias dataspace")?;
        let canonical = domain.map_or_else(
            || format!("{name}::{dataspace}"),
            |domain| format!("{name}::{domain}.{dataspace}"),
        );
        Ok(Self(ConstString::from(&*canonical)))
    }
}
impl AsRef<str> for ContractAlias {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl norito::core::SerializePayload for ContractAlias {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        <&str as norito::core::SerializePayload>::serialize(&self.as_ref(), writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        <&str as norito::core::SerializePayload>::encoded_len_hint(&self.as_ref())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        <&str as norito::core::SerializePayload>::encoded_len_exact(&self.as_ref())
    }
}

impl<'a> norito::core::DeserializePayload<'a> for ContractAlias {
    fn deserialize(archived: &'a norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("ContractAlias deserialization must succeed for valid archives")
    }
    fn try_deserialize(
        archived: &'a norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let value = <String as norito::core::DeserializePayload>::try_deserialize(archived.cast())?;
        ContractAlias::from_str(&value)
            .map_err(|err| norito::core::Error::Message(err.reason().into()))
    }
}

impl norito::json::FastJsonWrite for ContractAlias {
    fn write_json(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(self.as_ref(), out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(self.as_ref(), out)
    }
}

impl norito::json::JsonDeserialize for ContractAlias {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        reserve_contract_json_decode(value.len(), 6)?;
        value.parse().map_err(|_: ParseError| {
            norito::json::Error::Message("invalid contract alias".to_owned())
        })
    }
}
/// Errors returned when deriving or parsing a [`ContractAddress`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContractAddressError {
    /// The supplied literal was empty or malformed.
    #[error("invalid contract address: {0}")]
    InvalidLiteral(String),
    /// The Bech32m HRP is malformed or is not the canonical contract-address HRP.
    #[error("invalid contract address hrp: {0}")]
    InvalidHrp(String),
    /// The payload version is not recognized.
    #[error("unsupported contract address version {0}")]
    UnsupportedVersion(u8),
    /// The payload length does not match the expected version layout.
    #[error("invalid contract address payload length {found}; expected {expected}")]
    InvalidPayloadLength {
        /// Bytes actually decoded from the payload.
        found: usize,
        /// Bytes expected for the active address format version.
        expected: usize,
    },
    /// Deployer account canonicalization failed during address derivation.
    #[error("failed to derive contract address from deployer account: {0}")]
    InvalidDeployer(String),
}
impl ContractAddress {
    /// Exact optional string allocation made by [`Self::try_clone_for_admission`].
    #[must_use]
    pub fn admission_clone_layout(&self) -> Option<std::alloc::Layout> {
        (!self.0.is_inlined()).then(|| {
            std::alloc::Layout::array::<u8>(self.as_ref().len())
                .expect("existing canonical address layout")
        })
    }
    /// Clone an authenticated address fallibly into independently prepaid storage.
    ///
    /// The caller retains the exact charge reported by [`Self::admission_clone_layout`]
    /// until the returned immutable address is destroyed.
    ///
    /// # Errors
    /// Preserves the exact codec resource or allocator refusal.
    pub fn try_clone_for_admission(&self) -> Result<Self, norito::Error> {
        ConstString::try_from_str_for_decode(self.as_ref()).map(Self)
    }
    /// Derive a deterministic contract address from deployer identity, nonce, and dataspace.
    ///
    /// The address payload is versioned and encoded as:
    /// `version || dataspace_id_be || blake3(preimage)[..20]`.
    ///
    /// The preimage is domain-separated and commits the exact 32-byte genesis-lineage identity.
    /// Deployer bytes remain length-prefixed so the framing is unambiguous.
    ///
    /// # Errors
    /// Returns an error when the derived HRP is invalid, the deployer account cannot be
    /// canonicalized into an address, or the final Bech32m literal cannot be encoded.
    pub fn derive(
        network_id: &NetworkId,
        deployer: &AccountId,
        deploy_nonce: u64,
        dataspace_id: DataSpaceId,
    ) -> Result<Self, ContractAddressError> {
        let hrp = Hrp::parse(CONTRACT_ADDRESS_HRP)
            .map_err(|err| ContractAddressError::InvalidHrp(err.to_string()))?;
        let deployer_bytes = deployer
            .to_account_address()
            .and_then(|address| address.canonical_bytes())
            .map_err(|err: AccountAddressError| {
                ContractAddressError::InvalidDeployer(err.to_string())
            })?;
        let deployer_len = u32::try_from(deployer_bytes.len()).map_err(|_| {
            ContractAddressError::InvalidDeployer(
                "canonical deployer bytes exceed the contract-address framing limit".to_owned(),
            )
        })?;
        let mut preimage = Vec::with_capacity(
            CONTRACT_ADDRESS_TAG_V1.len()
                + iroha_crypto::Hash::LENGTH
                + 8
                + 8
                + 4
                + deployer_bytes.len(),
        );
        preimage.extend_from_slice(CONTRACT_ADDRESS_TAG_V1);
        preimage.extend_from_slice(network_id.as_bytes());
        preimage.extend_from_slice(&dataspace_id.as_u64().to_be_bytes());
        preimage.extend_from_slice(&deploy_nonce.to_be_bytes());
        preimage.extend_from_slice(&deployer_len.to_be_bytes());
        preimage.extend_from_slice(&deployer_bytes);
        let digest = blake3::hash(&preimage);
        let mut payload = Vec::with_capacity(CONTRACT_ADDRESS_PAYLOAD_LEN_V1);
        payload.push(CONTRACT_ADDRESS_VERSION_V1);
        payload.extend_from_slice(&dataspace_id.as_u64().to_be_bytes());
        payload.extend_from_slice(&digest.as_bytes()[..CONTRACT_ADDRESS_HASH_LEN]);
        let encoded = bech32::encode::<Bech32m>(hrp, &payload)
            .map_err(|err| ContractAddressError::InvalidLiteral(err.to_string()))?;
        encoded.parse()
    }
    /// Decode the dataspace identifier embedded in the address payload.
    ///
    /// # Errors
    /// Returns an error when the address literal cannot be decoded or when it uses an unsupported
    /// payload version.
    pub fn dataspace_id(&self) -> Result<DataSpaceId, ContractAddressError> {
        let (_, payload) = decode_contract_address(self.as_ref())?;
        let version = payload[0];
        if version != CONTRACT_ADDRESS_VERSION_V1 {
            return Err(ContractAddressError::UnsupportedVersion(version));
        }
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&payload[1..9]);
        Ok(DataSpaceId::new(u64::from_be_bytes(bytes)))
    }
    /// Derive the canonical, non-signable contract subject identifier used for contract-owned
    /// authority.
    ///
    /// The first-release algorithm hashes the canonical contract address directly into a valid
    /// Ed25519 public point. It deliberately does not derive a scalar/private key: knowing the
    /// public contract address therefore does not reveal signing material for the subject account.
    /// The domain and retry counter encoding are consensus-critical ABI V1 constants.
    ///
    /// This owning path retains the ordinary cached public-key parser, including its key,
    /// rejection and cache allocations. [`Self::try_subject_key_bytes`] derives without those
    /// allocations; constructing a retained public key or account then requires separate funding.
    #[must_use]
    pub fn subject_id(&self) -> AccountId {
        let public_key = match self.try_subject_candidate(
            |_| Ok::<(), core::convert::Infallible>(()),
            |candidate| {
                iroha_crypto::PublicKey::from_bytes(iroha_crypto::Algorithm::Ed25519, candidate)
                    .ok()
            },
        ) {
            Ok(public_key) => public_key,
            Err(never) => match never {},
        };
        AccountId::new(public_key)
    }
    /// Derive the subject's Ed25519 public-key bytes with caller-admitted work for every attempt.
    ///
    /// Before each hash and strict point check, `admit_attempt` receives the exact number of
    /// bytes to hash (the V1 tag, the stored address spelling, and the four-byte big-endian
    /// counter). The caller must admit that hash work and one strict Ed25519 candidate check.
    /// No attempt is made after admission fails. A retry starts again at counter zero; a local
    /// work refusal does not make the contract address invalid or impose a consensus limit.
    ///
    /// The derivation itself allocates no heap storage and never accesses the key parse cache.
    /// The callback is responsible for its own resources. Constructing a retained public key or
    /// [`AccountId`] from the returned bytes is a separate allocation requiring its own funding.
    ///
    /// # Errors
    /// Returns the callback's original error on work refusal, without producing subject bytes.
    ///
    /// # Panics
    /// Panics if all candidates exhaust the V1 `u32` retry counter, as does [`Self::subject_id`].
    pub fn try_subject_key_bytes<E>(
        &self,
        admit_attempt: impl FnMut(usize) -> Result<(), E>,
    ) -> Result<[u8; 32], E> {
        self.try_subject_candidate(admit_attempt, |candidate| {
            iroha_crypto::ed25519_public_key_is_valid(candidate).then_some(*candidate)
        })
    }
    // One V1 hash/counter algorithm for the owning and bytes-only paths. Keep the candidate
    // acceptor private: both public consumers use the same strict Ed25519 key relation.
    fn try_subject_candidate<T, E>(
        &self,
        mut admit_attempt: impl FnMut(usize) -> Result<(), E>,
        mut accept_candidate: impl FnMut(&[u8; 32]) -> Option<T>,
    ) -> Result<T, E> {
        let address_bytes = self.as_ref().as_bytes();
        // ContractAddress admits only the fixed V1 Bech32 payload and HRP.
        let hashed_len = CONTRACT_SUBJECT_HASH_TO_POINT_TAG_V1.len()
            + address_bytes.len()
            + core::mem::size_of::<u32>();
        let mut counter = 0_u32;
        loop {
            admit_attempt(hashed_len)?;
            let counter_bytes = counter.to_be_bytes();
            let candidate: [u8; 32] = iroha_crypto::Hash::new_from_chunks(&[
                CONTRACT_SUBJECT_HASH_TO_POINT_TAG_V1,
                address_bytes,
                &counter_bytes,
            ])
            .into();
            if let Some(accepted) = accept_candidate(&candidate) {
                return Ok(accepted);
            }
            counter = counter
                .checked_add(1)
                .expect("contract subject hash-to-point retry counter exhausted");
        }
    }
    /// Borrow the canonical encoded literal.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
}
impl AsRef<str> for ContractAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl norito::core::SerializePayload for ContractAddress {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        <&str as norito::core::SerializePayload>::serialize(&self.as_ref(), writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        <&str as norito::core::SerializePayload>::encoded_len_hint(&self.as_ref())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        <&str as norito::core::SerializePayload>::encoded_len_exact(&self.as_ref())
    }
}

impl<'a> norito::core::DeserializePayload<'a> for ContractAddress {
    fn deserialize(archived: &'a norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("ContractAddress deserialization must succeed for valid archives")
    }
    fn try_deserialize(
        archived: &'a norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let value = <String as norito::core::DeserializePayload>::try_deserialize(archived.cast())?;
        ContractAddress::from_str(&value)
            .map_err(|err| norito::core::Error::Message(err.to_string()))
    }
}
impl FromStr for ContractAddress {
    type Err = ContractAddressError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        decode_contract_address(value)?;
        Ok(Self(ConstString::from(value)))
    }
}

impl norito::json::FastJsonWrite for ContractAddress {
    fn write_json(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(self.as_ref(), out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(self.as_ref(), out)
    }
}

impl norito::json::JsonDeserialize for ContractAddress {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        reserve_contract_json_decode(value.len(), 3)?;
        value.parse().map_err(|_: ContractAddressError| {
            norito::json::Error::Message("invalid contract address".to_owned())
        })
    }
}

fn reserve_contract_json_decode(
    raw_bytes: usize,
    live_units: usize,
) -> Result<(), norito::json::Error> {
    // Alias parsing can retain three normalized segments, their canonical join,
    // Name/UTS-46 normalization scratch, and the final ConstString (6S).
    // Contract addresses retain Bech32 decode/canonical scratch plus the final
    // ConstString (3S). Both derivations use the raw UTF-8 length as a strict
    // upper bound; no decoded component expands beyond its source text.
    let bytes = raw_bytes
        .checked_mul(live_units)
        .ok_or(norito::json::Error::DecodeResourceLimit)?;
    norito::core::reserve_decode_allocation(bytes)
        .map_err(norito::json::Error::from_decode_resource)
}
fn decode_contract_address(value: &str) -> Result<(Hrp, Vec<u8>), ContractAddressError> {
    if value.trim().is_empty() {
        return Err(ContractAddressError::InvalidLiteral(
            "contract address must not be empty".to_owned(),
        ));
    }
    if value.trim() != value {
        return Err(ContractAddressError::InvalidLiteral(
            "contract address must not contain leading or trailing whitespace".to_owned(),
        ));
    }
    let (hrp, payload) = bech32::decode(value)
        .map_err(|err| ContractAddressError::InvalidLiteral(err.to_string()))?;
    if payload.is_empty() {
        return Err(ContractAddressError::InvalidPayloadLength {
            found: 0,
            expected: CONTRACT_ADDRESS_PAYLOAD_LEN_V1,
        });
    }
    match payload[0] {
        CONTRACT_ADDRESS_VERSION_V1 => {
            if payload.len() != CONTRACT_ADDRESS_PAYLOAD_LEN_V1 {
                return Err(ContractAddressError::InvalidPayloadLength {
                    found: payload.len(),
                    expected: CONTRACT_ADDRESS_PAYLOAD_LEN_V1,
                });
            }
        }
        version => return Err(ContractAddressError::UnsupportedVersion(version)),
    }
    if hrp.as_str() != CONTRACT_ADDRESS_HRP {
        return Err(ContractAddressError::InvalidHrp(format!(
            "expected `{CONTRACT_ADDRESS_HRP}`, found `{hrp}`"
        )));
    }
    Ok((hrp, payload))
}
/// Re-export commonly used smart-contract types.
pub mod prelude {
    pub use super::{
        CONTRACT_ADDRESS_HRP, CONTRACT_DEPLOY_NONCE_METADATA_KEY, ContractAddress, ContractAlias,
        ContractInstance,
    };
}
#[cfg(test)]
mod contract_address_tests {
    use super::*;
    use crate::block::BlockHeader;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_model_base::chain::ChainId;
    fn network_id(seed: &[u8]) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            seed,
        )))
    }
    fn cross_sdk_network_id() -> NetworkId {
        "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
            .parse()
            .expect("fixed network identity must be canonical")
    }
    fn checked_random_account_id() -> AccountId {
        AccountId::new(
            KeyPair::try_random()
                .expect("test fixture random key generation should succeed")
                .public_key()
                .clone(),
        )
    }
    #[test]
    fn contract_address_derivation_is_deterministic() {
        let authority = checked_random_account_id();
        let network_id = network_id(b"contract-address-determinism-test");
        let first = ContractAddress::derive(&network_id, &authority, 7, DataSpaceId::UNIVERSAL)
            .expect("derive contract address");
        let second = ContractAddress::derive(&network_id, &authority, 7, DataSpaceId::UNIVERSAL)
            .expect("derive contract address");
        assert_eq!(first, second);
        assert_eq!(
            first.dataspace_id().expect("dataspace"),
            DataSpaceId::UNIVERSAL
        );
        assert!(first.as_str().starts_with(CONTRACT_ADDRESS_HRP));
        assert_eq!(first.as_str().len(), CONTRACT_ADDRESS_LITERAL_LEN_V1);
        assert_eq!(CONTRACT_ADDRESS_LITERAL_LEN_V1, 60);
    }
    #[test]
    fn contract_address_derivation_matches_cross_sdk_vector() {
        let private_key =
            hex::decode("CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53")
                .expect("fixed Ed25519 seed must be hexadecimal");
        let authority = AccountId::new(
            KeyPair::try_from_seed(private_key, Algorithm::Ed25519)
                .expect("fixed Ed25519 seed must derive")
                .public_key()
                .clone(),
        );
        let address = ContractAddress::derive(
            &cross_sdk_network_id(),
            &authority,
            7,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive pinned contract address");
        assert_eq!(
            address.as_str(),
            "irohac1qyqqqqqqqqqqqq8y2pcrtkxvkrn5nt74kjjkjcst6kc56qcqa2dqp"
        );
    }
    #[test]
    fn contract_address_derivation_changes_with_nonce_and_exact_network_id() {
        let authority = checked_random_account_id();
        let first_deployment = (
            ChainId::from("contract-address-shared-name"),
            network_id(b"contract-address-genesis-alpha"),
        );
        let second_deployment = (
            ChainId::from("contract-address-shared-name"),
            network_id(b"contract-address-genesis-beta"),
        );
        assert_eq!(first_deployment.0, second_deployment.0);
        assert_ne!(first_deployment.1, second_deployment.1);
        let first =
            ContractAddress::derive(&first_deployment.1, &authority, 0, DataSpaceId::UNIVERSAL)
                .expect("first-network address");
        let next_nonce =
            ContractAddress::derive(&first_deployment.1, &authority, 1, DataSpaceId::UNIVERSAL)
                .expect("nonce+1 address");
        let second =
            ContractAddress::derive(&second_deployment.1, &authority, 0, DataSpaceId::UNIVERSAL)
                .expect("second-network address");
        assert_ne!(first, next_nonce);
        assert_ne!(first, second);
        assert!(second.as_str().starts_with(CONTRACT_ADDRESS_HRP));
    }
    #[test]
    fn contract_address_derivation_ignores_account_display_discriminant() {
        let authority = checked_random_account_id();
        let network_id = network_id(b"contract-address-display-independence");
        let first = {
            let _display_prefix = crate::account::address::ChainDiscriminantGuard::enter(42);
            ContractAddress::derive(&network_id, &authority, 0, DataSpaceId::UNIVERSAL)
                .expect("derive with first display prefix")
        };
        let second = {
            let _display_prefix = crate::account::address::ChainDiscriminantGuard::enter(73);
            ContractAddress::derive(&network_id, &authority, 0, DataSpaceId::UNIVERSAL)
                .expect("derive with second display prefix")
        };
        assert_eq!(first, second);
        assert!(first.as_str().starts_with(CONTRACT_ADDRESS_HRP));
    }
    #[test]
    fn contract_address_subject_is_deterministic_and_unique_per_address() {
        let authority = checked_random_account_id();
        let network_id = network_id(b"contract-address-subject-test");
        let first = ContractAddress::derive(&network_id, &authority, 0, DataSpaceId::UNIVERSAL)
            .expect("first contract address");
        let second = ContractAddress::derive(&network_id, &authority, 1, DataSpaceId::UNIVERSAL)
            .expect("second contract address");
        assert_eq!(first.subject_id(), first.subject_id());
        assert_ne!(first.subject_id(), second.subject_id());
    }
    #[test]
    fn contract_address_subject_consensus_vector() {
        let address: ContractAddress =
            "irohac1qyqqqqqqqqqqqqpze5aq5vfxha4qlvu4q80e0ff4yesw50c37z96q"
                .parse()
                .expect("pinned contract address");
        assert_eq!(
            hex::encode(address.subject_id().expect_single_signatory().to_bytes().1),
            "c19d0326bf14cb44e4e11d5c561f5f69367c305e2bc3ee29086b49aa07df3a55"
        );
    }
    #[test]
    fn contract_address_parser_rejects_invalid_literals() {
        let err = "not-an-address"
            .parse::<ContractAddress>()
            .expect_err("invalid address must fail");
        assert!(
            matches!(
                err,
                ContractAddressError::InvalidLiteral(_) | ContractAddressError::InvalidHrp(_)
            ),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    fn contract_address_parser_rejects_a_valid_payload_with_the_wrong_hrp() {
        let authority = checked_random_account_id();
        let address = ContractAddress::derive(
            &network_id(b"contract-address-wrong-hrp-test"),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        let (_, payload) = bech32::decode(address.as_str()).expect("decode derived address");
        let wrong_hrp = Hrp::parse("sorac").expect("static wrong HRP");
        let wrong_literal =
            bech32::encode::<Bech32m>(wrong_hrp, &payload).expect("encode wrong-HRP literal");
        assert!(matches!(
            wrong_literal.parse::<ContractAddress>(),
            Err(ContractAddressError::InvalidHrp(_))
        ));
    }
    #[test]
    fn contract_alias_parses_long_literal() {
        let alias: ContractAlias = "router::dex.universal".parse().expect("valid alias");
        assert_eq!(alias.name_segment(), "router");
        assert_eq!(alias.domain_segment(), Some("dex"));
        assert_eq!(alias.dataspace_segment(), "universal");
    }
    #[test]
    fn contract_alias_parses_short_literal() {
        let alias: ContractAlias = "router::universal".parse().expect("valid alias");
        assert_eq!(alias.name_segment(), "router");
        assert_eq!(alias.domain_segment(), None);
        assert_eq!(alias.dataspace_segment(), "universal");
    }
    #[test]
    fn contract_alias_resolves_alias_domain_segment() {
        let alias: ContractAlias = "router::dex.centralbank".parse().expect("valid alias");
        let catalog = DataSpaceCatalog::new(vec![
            crate::nexus::DataSpaceMetadata::default(),
            crate::nexus::DataSpaceMetadata {
                id: DataSpaceId::new(9),
                alias: "centralbank".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("catalog");
        let (name, domain, dataspace) = alias.resolve_components(&catalog).expect("resolve");
        assert_eq!(name, "router".parse::<Name>().expect("name"));
        assert_eq!(
            domain,
            Some(
                "dex"
                    .parse::<AccountAliasDomain>()
                    .expect("alias-domain segment")
            )
        );
        assert_eq!(dataspace, DataSpaceId::new(9));
    }
    #[test]
    fn contract_alias_rejects_invalid_literals() {
        for raw in [
            "",
            " ",
            "router",
            "router@universal",
            "router#universal",
            "router:::universal",
            "router::dex.universal.extra",
            "router::",
            "::universal",
        ] {
            assert!(raw.parse::<ContractAlias>().is_err(), "must fail: {raw}");
        }
    }

    fn assert_measured_json_decode<T>(json: &str)
    where
        T: norito::json::JsonDeserialize + core::fmt::Debug,
    {
        let limits = |bytes| {
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(limits(usize::MAX), || {
                norito::json::from_str::<T>(json)
            });
        decoded.expect("unbounded measured decode");
        let exact = usage.total_allocated_bytes();
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits(exact), || {
            norito::json::from_str::<T>(json)
        });
        decoded.expect("exact measured decode");
        assert_eq!(usage.total_allocated_bytes(), exact);
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits(exact - 1), || {
            norito::json::from_str::<T>(json)
        });
        assert!(matches!(
            decoded,
            Err(norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert!(usage.total_allocated_bytes() < exact);
    }

    #[test]
    fn contract_alias_and_address_json_decode_are_measured_exactly() {
        assert_measured_json_decode::<ContractAlias>("\"router::dex.universal\"");
        assert_measured_json_decode::<ContractAddress>(
            "\"irohac1qyqqqqqqqqqqqq8y2pcrtkxvkrn5nt74kjjkjcst6kc56qcqa2dqp\"",
        );
    }
    #[test]
    fn contract_alias_norito_wire_is_validated_string_literal() {
        let alias: ContractAlias = "router::dex.universal".parse().expect("valid alias");
        let alias_bytes = norito::codec::Encode::encode(&alias);
        let string_bytes = norito::codec::Encode::encode(&alias.as_ref().to_owned());
        assert_eq!(alias_bytes, string_bytes);
        let decoded = <ContractAlias as norito::codec::Decode>::decode(&mut alias_bytes.as_slice())
            .expect("decode contract alias");
        assert_eq!(decoded, alias);
        let invalid_bytes = norito::codec::Encode::encode(&"router".to_owned());
        let err = <ContractAlias as norito::codec::Decode>::decode(&mut invalid_bytes.as_slice())
            .expect_err("invalid alias literal must fail");
        assert!(err.to_string().contains("contract alias"));
    }
    #[test]
    fn contract_instance_frame_preserves_address_alias_and_code_binding() {
        let authority = checked_random_account_id();
        let address = ContractAddress::derive(
            &network_id(b"contract-instance-frame-test"),
            &authority,
            12,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        assert_eq!(
            <ContractInstance as norito::NoritoSchema>::nominal_name(),
            "iroha_data_model::smart_contract::model::ContractInstance",
        );
        assert_eq!(
            <ContractInstance as norito::NoritoSchema>::frame_name(),
            "iroha_data_model::smart_contract::model::ContractInstance",
        );
        for alias in [
            None,
            Some("router::dex.universal".parse().expect("valid alias")),
        ] {
            let instance = ContractInstance {
                contract_address: address.clone(),
                contract_alias: alias,
                code_hash: Hash::new(b"contract-instance-activated-code"),
            };
            let frame = norito::encode_canonical(&instance).expect("contract instance frame");
            assert_eq!(
                frame[6..22],
                norito::schema::identity::frame_hash::<ContractInstance>()
            );
            let decoded: ContractInstance =
                norito::decode_canonical(&frame).expect("instance roundtrip");
            assert_eq!(decoded, instance);
            assert_eq!(
                norito::encode_canonical(&decoded).expect("re-encode instance"),
                frame
            );
            let wrong_owner = norito::encode_canonical(&address).expect("different existing root");
            assert!(matches!(
                norito::decode_canonical::<ContractInstance>(&wrong_owner),
                Err(norito::Error::SchemaMismatch)
            ));
            assert!(
                norito::decode_canonical::<ContractInstance>(&frame[..frame.len() - 1]).is_err()
            );
            let mut trailing = frame;
            trailing.push(0);
            assert!(norito::decode_canonical::<ContractInstance>(&trailing).is_err());
        }
    }
    #[test]
    fn contract_address_norito_wire_is_validated_string_literal() {
        let authority = checked_random_account_id();
        let address = ContractAddress::derive(
            &network_id(b"contract-address-norito-test"),
            &authority,
            12,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        let address_bytes = norito::codec::Encode::encode(&address);
        let string_bytes = norito::codec::Encode::encode(&address.as_ref().to_owned());
        assert_eq!(address_bytes, string_bytes);
        let decoded =
            <ContractAddress as norito::codec::Decode>::decode(&mut address_bytes.as_slice())
                .expect("decode contract address");
        assert_eq!(decoded, address);
        let invalid_bytes = norito::codec::Encode::encode(&"not-an-address".to_owned());
        let err = <ContractAddress as norito::codec::Decode>::decode(&mut invalid_bytes.as_slice())
            .expect_err("invalid address literal must fail");
        assert!(err.to_string().contains("invalid contract address"));
    }
}
mod declaration_table;
/// Exact recursive schemas for public Kotodama entrypoint boundaries.
pub mod entrypoint;
/// Authenticated native event declarations and committed emissions.
pub mod event;
#[path = "smart_contract/manifest_projection.rs"]
mod manifest_projection;
/// Canonical bounded continuation positions for live durable-map pagination.
pub mod state_cursor;
// Smart contract manifest types and helpers.
#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use iroha_crypto::KeyPair;

    fn account() -> AccountId {
        AccountId::new(
            KeyPair::try_random()
                .expect("generate lifecycle test key")
                .public_key()
                .clone(),
        )
    }

    #[test]
    fn lifecycle_control_enforces_revision_and_bounded_hold() {
        let mut lifecycle = ContractLifecycleControlV1::direct(account());
        assert_eq!(lifecycle.version, CONTRACT_LIFECYCLE_CONTROL_VERSION_V1);
        assert!(lifecycle.validate().is_ok());
        assert!(lifecycle.active_code_hash.is_none());
        lifecycle.version = 0;
        assert_eq!(
            lifecycle.validate(),
            Err(
                "incompatible contract lifecycle schema version; regenerate first-release genesis and snapshots"
            )
        );
        lifecycle.version = CONTRACT_LIFECYCLE_CONTROL_VERSION_V1;
        lifecycle.revision = 0;
        assert_eq!(
            lifecycle.validate(),
            Err("contract lifecycle revision must be non-zero")
        );
        lifecycle.revision = 1;
        lifecycle.active_code_hash = Some(iroha_crypto::Hash::new(b"active lifecycle code"));
        lifecycle.retained_code_hash = Some(iroha_crypto::Hash::new(b"active lifecycle code"));
        lifecycle.emergency_hold = Some(ContractEmergencyHoldV1 {
            incident_digest: [1; 32],
            proposal_content_id: [2; 32],
            governance_attempt_id: [3; 32],
            reason: "containment".to_owned(),
            imposed_at_height: 10,
            expires_at_height: 10 + MAX_CONTRACT_EMERGENCY_HOLD_BLOCKS_V1,
        });
        assert!(lifecycle.validate().is_ok());
        assert!(lifecycle.is_held_at(10));
        assert!(lifecycle.is_held_at(3_609));
        assert!(!lifecycle.is_held_at(3_610));
        lifecycle
            .emergency_hold
            .as_mut()
            .expect("hold")
            .expires_at_height += 1;
        assert_eq!(lifecycle.validate(), Err("invalid contract emergency hold"));
    }

    #[test]
    fn lifecycle_control_norito_roundtrip_preserves_active_code_and_authority() {
        let mut lifecycle = ContractLifecycleControlV1::direct(account());
        lifecycle.active_code_hash = Some(iroha_crypto::Hash::new(b"lifecycle roundtrip"));
        lifecycle.retained_code_hash = Some(iroha_crypto::Hash::new(b"lifecycle roundtrip"));
        lifecycle.pending_owner = Some(ContractLifecycleOwnerV1::Parliament);
        lifecycle.parliament_delegation = ContractParliamentDelegationV1::Lifecycle;
        lifecycle.revision = 9;
        let encoded = norito::to_bytes(&lifecycle).expect("encode lifecycle record");
        let decoded: ContractLifecycleControlV1 =
            norito::decode_from_bytes(&encoded).expect("decode lifecycle record");
        assert_eq!(decoded, lifecycle);
        assert!(decoded.validate().is_ok());
    }
    #[test]
    fn lifecycle_retains_artifact_identity_while_suspended() {
        let mut lifecycle = ContractLifecycleControlV1::direct(account());
        let code_hash = iroha_crypto::Hash::new(b"retained schema artifact");
        lifecycle.active_code_hash = Some(code_hash);
        assert!(lifecycle.validate().is_err());
        lifecycle.retained_code_hash = Some(code_hash);
        assert!(lifecycle.validate().is_ok());
        lifecycle.active_code_hash = None;
        assert!(lifecycle.validate().is_ok());
        let encoded = norito::to_bytes(&lifecycle).unwrap();
        let decoded: ContractLifecycleControlV1 = norito::decode_from_bytes(&encoded).unwrap();
        assert_eq!(decoded, lifecycle);
        let json = norito::json::to_value(&lifecycle).unwrap();
        let mut missing = json.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("retained_code_hash");
        assert!(norito::json::from_value::<ContractLifecycleControlV1>(missing).is_err());
        assert_eq!(
            norito::json::from_value::<ContractLifecycleControlV1>(json).unwrap(),
            lifecycle
        );
    }
}

pub mod manifest {
    //! Manifest metadata for IVM smart contracts. It can be attached to a transaction's `metadata`
    //! under a well-known key for admission-time checks. When attached or registered, a V1 manifest
    //! must carry both consensus-binding hashes.

    pub use super::event::{ContractEventDescriptorV1, validate_contract_event_table};
    pub use super::manifest_projection::{
        BorrowedEntrypoints, BorrowedManifestValue, BorrowedStates,
        ContractManifestSignaturePayloadView, EntrypointDescriptorView,
        ManifestEntrypointSequenceV1, ManifestSigningError, ManifestStateSequenceV1,
        ManifestStateTypeNameV1, ManifestStateTypeNodeV1, ManifestStateTypeV1,
        ManifestTypeNameView, StateDescriptorView,
    };

    use crate::{
        DeriveFastJson as DeriveFast, DeriveJsonDeserialize as DeriveJsonDe,
        DeriveJsonSerialize as DeriveJsonSer,
    };
    use crate::{
        account::AccountId,
        events::EventFilterBox,
        smart_contract::entrypoint::{EntrypointArgumentSchemaV1, EntrypointValueTypeV1},
        trigger::{TriggerId, action::Repeats},
    };
    use iroha_crypto::{Hash, KeyPair, PublicKey, Signature};
    use iroha_model_base::{metadata::Metadata, name::Name};
    use iroha_schema::IntoSchema;
    use norito::codec::{Decode, Encode};

    use norito::json::{self, FastJsonWrite, JsonDeserialize, JsonSerialize};
    /// Well-known metadata key used to attach a contract manifest.
    pub const MANIFEST_METADATA_KEY: &str = "contract_manifest";
    /// Smart contract manifest used for admission-time validation.
    ///
    /// `code_hash` and `abi_hash` remain represented as options so malformed external payloads can
    /// be decoded into a stable, structured admission error. Every V1 registration and every
    /// admission path that observes a manifest rejects either field when absent. The permission
    /// declaration table is also required, including an explicit empty table when no roles exist.
    #[derive(Debug, Clone, Encode, Decode, IntoSchema, PartialEq, Eq, PartialOrd, Ord)]
    #[norito(reuse_archived)]
    #[derive(DeriveFast, DeriveJsonSer, DeriveJsonDe)]
    #[norito(deny_unknown_fields)]
    #[norito(no_fast_from_json)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::smart_contract::manifest::ContractManifest")]
    pub struct ContractManifest {
        /// Canonical source-level seiyaku name embedded by the compiler.
        #[norito(default)]
        pub seiyaku_name: Option<String>,
        /// Content-addressed hash of the compiled `.to` bytecode.
        /// Required in V1 and compared with the complete submitted artifact.
        pub code_hash: Option<Hash>,
        /// ABI hash computed by the node for the `abi_version` policy. Required in V1 and must
        /// match the artifact's authenticated CNTR binding and the node's canonical ABI descriptor.
        pub abi_hash: Option<Hash>,
        /// Optional compiler fingerprint (e.g., rustc/LLVM versions).
        pub compiler_fingerprint: Option<String>,
        /// Compiler-derived, hash-covered execution capability bitmap.
        ///
        /// V1 mirrors the artifact's ZK and VECTOR execution-mode bits. This is not
        /// source-selectable metadata and never describes host SIMD, Metal, or CUDA availability.
        pub features_bitmap: Option<u64>,
        /// Optional advisory access-set hints for scheduler.
        ///
        /// When present, the scheduler may use these read/write keys for conflict detection without
        /// requiring a dynamic VM prepass. Keys are canonical strings of the form `account:…`,
        /// `domain:…`, `asset_def:…`, `asset:…`, `nft:…`, or their `*.detail:…` variants, matching
        /// the internal pipeline access-key format.
        #[norito(default)]
        pub access_set_hints: Option<AccessSetHints>,
        /// Sorted, unique permission declarations authenticated by the artifact.
        pub permissions: Vec<ContractPermissionDescriptorV1>,
        /// Sorted, unique source event declarations authenticated by the artifact.
        pub events: Vec<ContractEventDescriptorV1>,
        /// Optional entrypoint descriptors advertised by the compiler.
        #[norito(default)]
        pub entrypoints: Option<Vec<EntrypointDescriptor>>,
        /// Optional durable state schema advertised by the compiler.
        #[norito(default)]
        pub states: Option<Vec<StateDescriptor>>,
        /// Exact nominal error type identities and variant schemas advertised by the compiler.
        #[norito(default)]
        pub error_types: Option<Vec<ContractErrorTypeDescriptor>>,
        /// Complete ordinary enum declaration inventory, sorted by nominal identity.
        pub enum_types: Vec<ContractEnumTypeDescriptorV1>,
        /// Authenticated presentation text, separate from nominal error schemas.
        #[norito(default)]
        pub error_messages: Option<Vec<ContractErrorMessage>>,
        /// Optional localization tables extracted from `kotoba { ... }` blocks.
        #[norito(default)]
        pub kotoba: Option<Vec<KotobaTranslationEntry>>,
        /// Provenance metadata for the manifest, including signer and signature.
        #[norito(default)]
        pub provenance: Option<ManifestProvenance>,
    }
    /// Bounded dynamic state access advertised by a compiler.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(deny_unknown_fields)]
    #[norito(no_fast_from_json)]
    pub struct DynamicAccessHint {
        /// Canonical state-map base key, for example `state:Balances`.
        pub base_key: String,
        /// Canonical Kotodama key type name for the map.
        pub key_type: String,
        /// Human-readable bound source, for example `take` or `range`.
        pub bound_kind: String,
        /// Maximum number of state keys touched by this dynamic access.
        pub max_keys: u32,
    }
    /// Advisory read/write keys used by the scheduler when present in a manifest.
    #[derive(Debug, Clone, Encode, Decode, IntoSchema, PartialEq, Eq, PartialOrd, Ord)]
    pub struct AccessSetHints {
        /// Keys that the contract expects to read for a given entrypoint.
        pub read_keys: Vec<String>,
        /// Keys that the contract expects to write for a given entrypoint.
        pub write_keys: Vec<String>,
        /// Bounded dynamic state-map reads generated by the compiler.
        #[norito(default)]
        pub dynamic_reads: Vec<DynamicAccessHint>,
        /// Bounded dynamic state-map writes generated by the compiler.
        #[norito(default)]
        pub dynamic_writes: Vec<DynamicAccessHint>,
    }

    impl FastJsonWrite for AccessSetHints {
        fn write_json(&self, out: &mut String) {
            out.push('{');
            json::write_json_string("read_keys", out);
            out.push(':');
            JsonSerialize::json_serialize(&self.read_keys, out);
            out.push(',');
            json::write_json_string("write_keys", out);
            out.push(':');
            JsonSerialize::json_serialize(&self.write_keys, out);
            out.push(',');
            json::write_json_string("dynamic_reads", out);
            out.push(':');
            JsonSerialize::json_serialize(&self.dynamic_reads, out);
            out.push(',');
            json::write_json_string("dynamic_writes", out);
            out.push(':');
            JsonSerialize::json_serialize(&self.dynamic_writes, out);
            out.push('}');
        }
        fn write_json_to(
            &self,
            out: &mut dyn json::JsonWriteSink,
        ) -> Result<(), json::BoundedJsonError> {
            out.begin_container()?;
            let result = (|| -> Result<(), norito::json::BoundedJsonError> {
                out.push_str("{\"read_keys\":")?;
                self.read_keys.json_serialize_to(out)?;
                out.push_str(",\"write_keys\":")?;
                self.write_keys.json_serialize_to(out)?;
                out.push_str(",\"dynamic_reads\":")?;
                self.dynamic_reads.json_serialize_to(out)?;
                out.push_str(",\"dynamic_writes\":")?;
                self.dynamic_writes.json_serialize_to(out)?;
                out.push('}')?;
                Ok(())
            })();
            out.end_container();
            result?;
            Ok(())
        }
    }

    impl JsonDeserialize for AccessSetHints {
        fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
            parser.skip_ws();
            parser.consume_char(b'{')?;
            let mut read_keys: Option<Vec<String>> = None;
            let mut write_keys: Option<Vec<String>> = None;
            let mut dynamic_reads: Option<Vec<DynamicAccessHint>> = None;
            let mut dynamic_writes: Option<Vec<DynamicAccessHint>> = None;
            loop {
                parser.skip_ws();
                if parser.try_consume_char(b'}')? {
                    break;
                }
                let key = parser.parse_key()?;
                match key.as_str() {
                    "read_keys" => {
                        if read_keys.is_some() {
                            return Err(json::Error::duplicate_field("read_keys"));
                        }
                        read_keys = Some(Vec::<String>::json_deserialize(parser)?);
                    }
                    "write_keys" => {
                        if write_keys.is_some() {
                            return Err(json::Error::duplicate_field("write_keys"));
                        }
                        write_keys = Some(Vec::<String>::json_deserialize(parser)?);
                    }
                    "dynamic_reads" => {
                        if dynamic_reads.is_some() {
                            return Err(json::Error::duplicate_field("dynamic_reads"));
                        }
                        dynamic_reads = Some(Vec::<DynamicAccessHint>::json_deserialize(parser)?);
                    }
                    "dynamic_writes" => {
                        if dynamic_writes.is_some() {
                            return Err(json::Error::duplicate_field("dynamic_writes"));
                        }
                        dynamic_writes = Some(Vec::<DynamicAccessHint>::json_deserialize(parser)?);
                    }
                    other => {
                        return Err(json::Error::unknown_field(other));
                    }
                }
                if parser.consume_comma_if_present()? {
                    continue;
                }
                parser.skip_ws();
                parser.consume_char(b'}')?;
                break;
            }
            let read_keys = read_keys.ok_or_else(|| json::Error::missing_field("read_keys"))?;
            let write_keys = write_keys.ok_or_else(|| json::Error::missing_field("write_keys"))?;
            Ok(AccessSetHints {
                read_keys,
                write_keys,
                dynamic_reads: dynamic_reads.unwrap_or_default(),
                dynamic_writes: dynamic_writes.unwrap_or_default(),
            })
        }
    }
    /// Signature metadata binding a manifest to an approved signer.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(deny_unknown_fields)]
    #[norito(no_fast_from_json)]
    pub struct ManifestProvenance {
        /// Public key that signed the manifest payload.
        pub signer: PublicKey,
        /// Signature over the manifest payload (see [`ContractManifestSignaturePayload`]).
        pub signature: Signature,
    }
    /// Explicit invocation policy; permission aliases resolve through the signed declaration table.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    #[norito(tag = "kind", content = "value", deny_unknown_fields)]
    pub enum EntrypointAuthorizationV1 {
        /// Any caller may enter; ledger operations still require their own authority.
        Anyone,
        /// The caller must hold the permission declared under this source-level name.
        Permission(Name),
        /// Runtime-managed lifecycle invocation, unavailable as a source-selected policy.
        RuntimeLifecycle,
    }
    /// Identity scope of a declared permission.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    #[norito(tag = "kind", content = "value", deny_unknown_fields)]
    pub enum ContractPermissionScopeV1 {
        /// An instance-local token bound to the canonical deployed contract address.
        Instance,
        /// An explicitly imported chain-global token with an exact JSON-null payload.
        Chain {
            /// Canonical name of the imported chain permission.
            permission_name: Name,
        },
    }
    /// Authenticated declaration of an instance permission or explicit chain import.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    #[norito(deny_unknown_fields)]
    pub struct ContractPermissionDescriptorV1 {
        /// Unique source-level name used by entrypoint authorization.
        pub name: Name,
        /// Token identity scope.
        pub scope: ContractPermissionScopeV1,
    }

    /// Check the canonical source names and strict ordering of the signed permission table.
    ///
    /// Chain token names are already validated by [`Name`]; only the local alias is a
    /// Kotodama identifier. Unused declarations remain part of the authenticated table.
    pub fn validate_contract_permission_table(
        permissions: &[ContractPermissionDescriptorV1],
    ) -> bool {
        permissions.iter().all(|declaration| {
            declaration.name.as_ref() != "anyone"
                && super::entrypoint::is_canonical_kotodama_identifier(declaration.name.as_ref())
        }) && permissions
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
    }

    impl EntrypointAuthorizationV1 {
        /// Check a declaration's invocation policy against a validated signed permission table.
        ///
        /// Call [`validate_contract_permission_table`] before this method. Lifecycle hooks
        /// cannot opt into public or role-based access, and public functions cannot request
        /// runtime lifecycle authority.
        pub fn is_valid_for(
            &self,
            kind: EntryPointKind,
            permissions: &[ContractPermissionDescriptorV1],
        ) -> bool {
            match (kind, self) {
                (EntryPointKind::Hajimari | EntryPointKind::Kaizen, Self::RuntimeLifecycle)
                | (EntryPointKind::Kotoage | EntryPointKind::View, Self::Anyone) => true,
                (EntryPointKind::Kotoage | EntryPointKind::View, Self::Permission(name)) => {
                    permissions
                        .binary_search_by(|declaration| declaration.name.cmp(name))
                        .is_ok()
                }
                _ => false,
            }
        }
    }
    /// Declarative metadata for a compiled entrypoint.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    #[norito(deny_unknown_fields)]
    pub struct EntrypointDescriptor {
        /// Symbol name as declared in the Kotodama source file.
        pub name: String,
        /// Logical kind: `kotoage`/`言挙げ`, view, `hajimari`/`始まり`, or
        /// `kaizen`/`改善`. Trigger declarations attach to one of these
        /// descriptors through [`EntrypointDescriptor::triggers`].
        pub kind: EntryPointKind,
        /// Ordered public parameters advertised by the compiler.
        #[norito(default)]
        pub params: Vec<EntrypointParamDescriptor>,
        /// Exact recursive schema for the complete public argument record.
        /// Zero-parameter entrypoints have no argument schema.
        #[norito(default)]
        pub argument_schema: Option<EntrypointArgumentSchemaV1>,
        /// Exact return type, including `()` when the source omits its return annotation.
        /// Public entrypoint admission rejects an absent value.
        #[norito(default)]
        pub return_type: Option<String>,
        /// Exact recursive schema for every public return value, including one zero scalar Unit.
        /// Public entrypoint admission rejects an absent schema.
        #[norito(default)]
        pub return_schema: Option<EntrypointValueTypeV1>,
        /// Explicit dispatcher authorization authenticated by the artifact.
        pub authorization: EntrypointAuthorizationV1,
        /// Advisory read keys for this entrypoint (flattened `state:...` strings).
        #[norito(default)]
        pub read_keys: Vec<String>,
        /// Advisory write keys for this entrypoint.
        #[norito(default)]
        pub write_keys: Vec<String>,
        /// Whether access-set hints are complete or explicitly provided.
        #[norito(default)]
        pub access_hints_complete: Option<bool>,
        /// Reasons access hints were skipped for this entrypoint.
        #[norito(default)]
        pub access_hints_skipped: Vec<String>,
        /// Trigger declarations that call this entrypoint.
        #[norito(default)]
        pub triggers: Vec<TriggerDescriptor>,
    }
    /// Declarative parameter metadata for a public or view entrypoint.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    pub struct EntrypointParamDescriptor {
        /// Stable parameter name as declared in the Kotodama source file.
        pub name: String,
        /// Canonical type name advertised to clients.
        pub type_name: String,
    }
    /// Declarative durable state schema advertised by a compiled contract.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    pub struct StateDescriptor {
        /// Stable state key as declared in Kotodama source.
        pub name: String,
        /// Canonical durable value type stored under this key.
        pub type_name: String,
    }
    /// Stable application error code exposed by a compiled contract.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json, deny_unknown_fields)]
    pub struct ContractErrorVariantDescriptor {
        /// Symbolic variant name within its nominal error type.
        pub name: String,
        /// Explicit non-zero numeric code returned on abort.
        pub code: u32,
    }
    /// Maximum UTF-8 bytes in a static contract error message.
    pub const MAX_CONTRACT_ERROR_MESSAGE_BYTES: usize = 4096;

    /// Authenticated presentation text for one nominal error variant.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json, deny_unknown_fields)]
    pub struct ContractErrorMessage {
        /// Exact nominal identity in the contract's error type catalog.
        pub error_type: String,
        /// Declared nonzero enum-local variant code.
        pub code: u32,
        /// Static UTF-8 presentation text, without interpolation or localization.
        pub message: String,
    }

    /// Validate sorted, unique presentation entries against an exact error catalog.
    #[must_use]
    pub fn validate_contract_error_messages(
        errors: &[ContractErrorTypeDescriptor],
        messages: &[ContractErrorMessage],
    ) -> bool {
        messages.len() <= 256 * 256
            && messages.windows(2).all(|pair| {
                (&pair[0].error_type, pair[0].code) < (&pair[1].error_type, pair[1].code)
            })
            && messages.iter().all(|entry| {
                !entry.message.trim().is_empty()
                    && entry.message.len() <= MAX_CONTRACT_ERROR_MESSAGE_BYTES
                    && errors.iter().any(|error| {
                        error.identity == entry.error_type && error.variant(entry.code).is_some()
                    })
            })
    }
    /// Exact nominal identity and finite variant schema of one Kotodama error type.
    #[derive(Debug, Clone, Encode, Decode, IntoSchema, PartialEq, Eq, PartialOrd, Ord)]
    #[norito(decode_from_slice)]
    #[derive(DeriveFast, DeriveJsonSer, DeriveJsonDe)]
    #[norito(no_fast_from_json, deny_unknown_fields)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_data_model::smart_contract::manifest::ContractErrorTypeDescriptor"
    )]
    pub struct ContractErrorTypeDescriptor {
        /// Stable locked-package, source-unit and enum identity; never a linker ordinal.
        pub identity: String,
        /// Variants in increasing numeric-code order, with unique names and nonzero codes.
        pub variants: Vec<ContractErrorVariantDescriptor>,
    }
    impl ContractErrorTypeDescriptor {
        /// Validate the bounded canonical identity and enum-local variant namespace.
        #[must_use]
        pub fn validate(&self) -> bool {
            validate_nominal_enum_schema(
                &self.identity,
                self.variants
                    .iter()
                    .map(|variant| (variant.name.as_str(), variant.code)),
            )
        }
        /// Hash the canonical variant schema independently of the separately bound nominal identity.
        #[must_use]
        pub fn schema_hash(&self) -> [u8; 32] {
            Hash::new_from_chunks(&[b"iroha:kotodama:error-schema:v1\0", &self.variants.encode()])
                .into()
        }
        /// Resolve one validated nonzero variant code without crossing nominal types.
        #[must_use]
        pub fn variant(&self, code: u32) -> Option<&ContractErrorVariantDescriptor> {
            self.variants.iter().find(|variant| variant.code == code)
        }
    }
    /// One explicitly numbered variant of an ordinary nominal enum.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json, deny_unknown_fields)]
    pub struct ContractEnumVariantDescriptorV1 {
        /// Exact source variant name within its enum.
        pub name: String,
        /// Explicit nonzero enum-local code, independent of declaration order.
        pub code: u32,
    }

    /// Exact source identity and finite schema of an ordinary Kotodama enum.
    ///
    /// Ordinary enum values are distinct from application errors even when all
    /// names and codes happen to match. They never enter an error catalog.
    #[derive(Debug, Clone, Encode, Decode, IntoSchema, PartialEq, Eq, PartialOrd, Ord)]
    #[norito(decode_from_slice)]
    #[derive(DeriveFast, DeriveJsonSer, DeriveJsonDe)]
    #[norito(no_fast_from_json, deny_unknown_fields)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_data_model::smart_contract::manifest::ContractEnumTypeDescriptorV1"
    )]
    pub struct ContractEnumTypeDescriptorV1 {
        /// Stable locked-package, source-unit and enum identity; never a linker ordinal.
        pub identity: String,
        /// Unique variant names and nonzero codes in increasing code order.
        pub variants: Vec<ContractEnumVariantDescriptorV1>,
    }

    impl ContractEnumTypeDescriptorV1 {
        /// Validate the bounded canonical identity and variant namespace.
        #[must_use]
        pub fn validate(&self) -> bool {
            validate_nominal_enum_schema(
                &self.identity,
                self.variants
                    .iter()
                    .map(|variant| (variant.name.as_str(), variant.code)),
            )
        }

        /// Hash the finite schema in the ordinary-enum domain, excluding nominal identity.
        #[must_use]
        pub fn schema_hash(&self) -> [u8; 32] {
            Hash::new_from_chunks(&[b"iroha:kotodama:enum-schema:v1\0", &self.variants.encode()])
                .into()
        }

        /// Resolve one enum-local code against this exact descriptor.
        #[must_use]
        pub fn variant(&self, code: u32) -> Option<&ContractEnumVariantDescriptorV1> {
            self.variants.iter().find(|variant| variant.code == code)
        }
    }

    /// Maximum number of ordinary nominal enum declarations in one interface.
    pub const MAX_CONTRACT_ENUM_TYPES_V1: usize = 256;
    /// Maximum canonical framed bytes in the ordinary enum declaration inventory.
    pub const MAX_CONTRACT_ENUM_TABLE_BYTES_V1: usize = 64 * 1024;

    /// Validate the bounded sorted ordinary enum table, independent of application errors.
    #[must_use]
    pub fn validate_contract_enum_table(types: &[ContractEnumTypeDescriptorV1]) -> bool {
        types.len() <= MAX_CONTRACT_ENUM_TYPES_V1
            && types.iter().all(ContractEnumTypeDescriptorV1::validate)
            && types
                .windows(2)
                .all(|pair| pair[0].identity < pair[1].identity)
            && super::declaration_table::canonical_len(types)
                .is_ok_and(|bytes| bytes <= MAX_CONTRACT_ENUM_TABLE_BYTES_V1)
    }

    fn validate_nominal_enum_schema<'a>(
        identity: &'a str,
        variants: impl ExactSizeIterator<Item = (&'a str, u32)>,
    ) -> bool {
        if identity.is_empty()
            || identity.len() > 1024
            || !identity
                .chars()
                .all(|character| character.is_alphanumeric() || "_:/@.-".contains(character))
            || identity.contains("__kotodama_link_")
            || !(1..=256).contains(&variants.len())
        {
            return false;
        }
        // Both enum kinds use the same allocation-free namespace policy.
        let count = variants.len();
        let mut names = [""; 256];
        let mut previous_code = 0;
        for (index, (name, code)) in variants.enumerate() {
            let valid_name = super::entrypoint::is_canonical_kotodama_identifier(name)
                || (!name.is_ascii()
                    && name
                        .chars()
                        .next()
                        .is_some_and(|first| first.is_alphabetic() || first == '_')
                    && name
                        .chars()
                        .all(|character| character.is_alphanumeric() || character == '_'));
            if code <= previous_code || !valid_name {
                return false;
            }
            previous_code = code;
            names[index] = name;
        }
        let names = &mut names[..count];
        names.sort_unstable();
        names.windows(2).all(|pair| pair[0] != pair[1])
    }

    /// Localized message text for a specific language tag.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    pub struct KotobaTranslation {
        /// Language tag, e.g. "en", "ja".
        pub lang: String,
        /// Localized message text.
        pub text: String,
    }
    /// Translation entry keyed by a stable message id.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    pub struct KotobaTranslationEntry {
        /// Stable message identifier.
        pub msg_id: String,
        /// Localized translations for this message.
        pub translations: Vec<KotobaTranslation>,
    }
    /// Entrypoint callback target referenced by a trigger declaration.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    pub struct TriggerCallback {
        /// Optional contract namespace for cross-contract callbacks.
        #[norito(default)]
        pub namespace: Option<String>,
        /// Entrypoint name to invoke.
        pub entrypoint: String,
    }
    /// Declarative trigger metadata attached to an entrypoint.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    pub struct TriggerDescriptor {
        /// Trigger identifier.
        pub id: TriggerId,
        /// Repeat policy for the trigger action.
        pub repeats: Repeats,
        /// Event filter that drives execution.
        pub filter: EventFilterBox,
        /// Optional explicit authority override.
        #[norito(default)]
        pub authority: Option<AccountId>,
        /// Trigger metadata payload (JSON map).
        #[norito(default)]
        pub metadata: Metadata,
        /// Callback target for this trigger.
        pub callback: TriggerCallback,
    }
    /// Entry point category advertised by Kotodama.
    #[derive(
        Debug,
        Clone,
        Copy,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    #[norito(tag = "kind", content = "value")]
    pub enum EntryPointKind {
        /// Transaction dispatcher entrypoint (`kotoage`/`言挙げ fn`).
        Kotoage,
        /// Read-only query entrypoint (`view fn`).
        View,
        /// Deployment `hajimari`/`始まり` declaration.
        Hajimari,
        /// `kaizen`/`改善` lifecycle declaration.
        Kaizen,
    }
    /// Canonical payload signed to attest a manifest.
    #[derive(
        Debug,
        Clone,
        Encode,
        Decode,
        IntoSchema,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        DeriveFast,
        DeriveJsonSer,
        DeriveJsonDe,
    )]
    #[norito(no_fast_from_json)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_data_model::smart_contract::manifest::ContractManifestSignaturePayload"
    )]
    pub struct ContractManifestSignaturePayload {
        /// Canonical source-level seiyaku name.
        #[norito(default)]
        pub seiyaku_name: Option<String>,
        /// Content-addressed hash of the compiled `.to` bytecode.
        pub code_hash: Option<Hash>,
        /// ABI hash computed by the node for the `abi_version` policy.
        pub abi_hash: Option<Hash>,
        /// Optional compiler fingerprint (e.g., rustc/LLVM versions).
        pub compiler_fingerprint: Option<String>,
        /// Compiler-derived, hash-covered ZK/VECTOR execution capability bitmap.
        ///
        /// This mirrors the signed manifest field and is unrelated to host
        /// hardware acceleration availability.
        pub features_bitmap: Option<u64>,
        /// Optional advisory access-set hints for scheduler.
        #[norito(default)]
        pub access_set_hints: Option<AccessSetHints>,
        /// Sorted, unique permission declarations authenticated by the artifact.
        pub permissions: Vec<ContractPermissionDescriptorV1>,
        /// Sorted, unique source event declarations authenticated by the artifact.
        pub events: Vec<ContractEventDescriptorV1>,
        /// Optional entrypoint descriptors advertised by the compiler.
        #[norito(default)]
        pub entrypoints: Option<Vec<EntrypointDescriptor>>,
        /// Optional durable state schema advertised by the compiler.
        #[norito(default)]
        pub states: Option<Vec<StateDescriptor>>,
        /// Exact nominal error type identities and variant schemas advertised by the compiler.
        #[norito(default)]
        pub error_types: Option<Vec<ContractErrorTypeDescriptor>>,
        /// Complete ordinary enum declaration inventory, sorted by nominal identity.
        pub enum_types: Vec<ContractEnumTypeDescriptorV1>,
        /// Authenticated presentation text, separate from nominal error schemas.
        #[norito(default)]
        pub error_messages: Option<Vec<ContractErrorMessage>>,
        /// Optional localization tables extracted from `kotoba { ... }` blocks.
        #[norito(default)]
        pub kotoba: Option<Vec<KotobaTranslationEntry>>,
    }
    impl ContractManifest {
        /// Compare the exact canonical signing content without copying its owned graph.
        ///
        /// Provenance is excluded, just as in [`Self::signature_payload`]. Optional absent
        /// fields remain distinct from present empty fields; nested vector order and every
        /// descriptor value remain significant. This comparison allocates nothing.
        #[must_use]
        pub fn same_signed_content(&self, other: &Self) -> bool {
            // Exhaustive destructuring makes a new manifest field require an explicit
            // decision here instead of silently excluding it from admission comparisons.
            let Self {
                seiyaku_name,
                code_hash,
                abi_hash,
                compiler_fingerprint,
                features_bitmap,
                access_set_hints,
                permissions,
                events,
                entrypoints,
                states,
                error_types,
                enum_types,
                error_messages,
                kotoba,
                provenance: _,
            } = self;
            seiyaku_name == &other.seiyaku_name
                && code_hash == &other.code_hash
                && abi_hash == &other.abi_hash
                && compiler_fingerprint == &other.compiler_fingerprint
                && features_bitmap == &other.features_bitmap
                && access_set_hints == &other.access_set_hints
                && permissions == &other.permissions
                && events == &other.events
                && entrypoints == &other.entrypoints
                && states == &other.states
                && error_types == &other.error_types
                && enum_types == &other.enum_types
                && error_messages == &other.error_messages
                && kotoba == &other.kotoba
        }
        /// Borrow the canonical payload that must be signed for provenance checks.
        #[must_use]
        pub fn signature_payload(&self) -> ContractManifestSignaturePayloadView<'_> {
            ContractManifestSignaturePayloadView::from(self)
        }
        /// Encode one bounded canonical signing frame under the caller's original context.
        ///
        /// The caller retains its physical graph/output owner through consumption. The supplied
        /// cumulative context does not grant independent allocation or lifetime authority.
        ///
        /// # Errors
        ///
        /// Returns the original native frame, allocation or serialization refusal.
        pub fn signature_payload_bytes(
            &self,
            context: &norito::core::DecodeBudgetContext,
            max_frame_bytes: usize,
        ) -> Result<Vec<u8>, norito::core::BoundedEncodeError> {
            self.signature_payload().to_bytes(context, max_frame_bytes)
        }
        /// Attach provenance by signing the canonical payload with the provided key pair.
        ///
        /// # Errors
        ///
        /// Returns the original native encoder refusal or selected signing backend error.
        pub fn try_signed(
            mut self,
            context: &norito::core::DecodeBudgetContext,
            max_frame_bytes: usize,
            key_pair: &KeyPair,
        ) -> Result<Self, ManifestSigningError> {
            let payload = self.signature_payload_bytes(context, max_frame_bytes)?;
            let signature = Signature::try_new(key_pair.private_key(), &payload)?;
            let signer = context
                .with(|| key_pair.public_key().try_clone_for_admission())
                .map_err(norito::core::BoundedEncodeError::from)?;
            self.provenance = Some(ManifestProvenance { signer, signature });
            Ok(self)
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn ordinary_enum_descriptor_is_bounded_nominal_and_separate_from_errors() {
            let descriptor = ContractEnumTypeDescriptorV1 {
                identity: "example/vault@1::Vault::Phase".into(),
                variants: vec![
                    ContractEnumVariantDescriptorV1 {
                        name: "Open".into(),
                        code: 1,
                    },
                    ContractEnumVariantDescriptorV1 {
                        name: "Closed".into(),
                        code: 7,
                    },
                ],
            };
            assert!(descriptor.validate());
            assert_eq!(descriptor.variant(7).unwrap().name, "Closed");
            assert!(descriptor.variant(0).is_none());
            assert!(descriptor.variant(2).is_none());
            let frame = norito::to_bytes(&descriptor).unwrap();
            assert_eq!(
                norito::decode_canonical::<ContractEnumTypeDescriptorV1>(&frame).unwrap(),
                descriptor
            );
            let json = norito::json::to_json(&descriptor).unwrap();
            assert_eq!(
                norito::json::from_str::<ContractEnumTypeDescriptorV1>(&json).unwrap(),
                descriptor
            );
            let unknown = json.replacen('{', "{\"unknown\":true,", 1);
            assert!(norito::json::from_str::<ContractEnumTypeDescriptorV1>(&unknown).is_err());
            let error = ContractErrorTypeDescriptor {
                identity: descriptor.identity.clone(),
                variants: descriptor
                    .variants
                    .iter()
                    .map(|variant| ContractErrorVariantDescriptor {
                        name: variant.name.clone(),
                        code: variant.code,
                    })
                    .collect(),
            };
            assert!(error.validate());
            assert_ne!(descriptor.schema_hash(), error.schema_hash());
            let mut other = descriptor.clone();
            other.identity = "example/other@1::Vault::Phase".into();
            assert_eq!(descriptor.schema_hash(), other.schema_hash());
            assert_ne!(descriptor, other);
            for identity in ["", "__kotodama_link_0", "invalid identity"] {
                let mut invalid = descriptor.clone();
                invalid.identity = identity.into();
                assert!(!invalid.validate());
            }
            let mut invalid = descriptor.clone();
            invalid.variants[0].code = 0;
            assert!(!invalid.validate());
            invalid = descriptor.clone();
            invalid.variants.reverse();
            assert!(!invalid.validate());
            invalid = descriptor.clone();
            invalid.variants[1].name = "Open".into();
            assert!(!invalid.validate());
            invalid = descriptor.clone();
            invalid.variants[1].name = "not a variant".into();
            assert!(!invalid.validate());
            invalid = descriptor.clone();
            invalid.variants.clear();
            assert!(!invalid.validate());
            invalid.variants = (1..=257)
                .map(|code| ContractEnumVariantDescriptorV1 {
                    name: format!("Case{code}"),
                    code,
                })
                .collect();
            assert!(!invalid.validate());
            invalid.variants.pop();
            assert!(invalid.validate());
        }
        #[test]
        fn ordinary_enum_table_binds_order_identity_and_total_size() {
            let mut descriptor = ContractEnumTypeDescriptorV1 {
                identity: "local::Status".into(),
                variants: vec![ContractEnumVariantDescriptorV1 {
                    name: "Open".into(),
                    code: 1,
                }],
            };
            assert!(validate_contract_enum_table(&[]));
            assert!(validate_contract_enum_table(&[descriptor.clone()]));
            assert!(!validate_contract_enum_table(&[
                descriptor.clone(),
                descriptor.clone()
            ]));
            let table: Vec<_> = (0..=256)
                .map(|index| ContractEnumTypeDescriptorV1 {
                    identity: format!("local::Status{index:03}"),
                    ..descriptor.clone()
                })
                .collect();
            assert!(!validate_contract_enum_table(&table));
            assert!(validate_contract_enum_table(&table[..256]));
            let reversed: Vec<_> = table[..2].iter().rev().cloned().collect();
            assert!(!validate_contract_enum_table(&reversed));
            descriptor.variants = (1..=256)
                .map(|code| ContractEnumVariantDescriptorV1 {
                    name: format!("Variant{}_{code}", "a".repeat(64)),
                    code,
                })
                .collect();
            let oversized: Vec<_> = (0..8)
                .map(|index| ContractEnumTypeDescriptorV1 {
                    identity: format!("local::Status{index}"),
                    ..descriptor.clone()
                })
                .collect();
            assert!(oversized.iter().all(ContractEnumTypeDescriptorV1::validate));
            assert!(!validate_contract_enum_table(&oversized));
        }
        #[test]
        fn error_message_catalog_is_bounded_and_separate_from_nominal_schema() {
            let descriptor = ContractErrorTypeDescriptor {
                identity: "example/Vault::Failure".into(),
                variants: vec![ContractErrorVariantDescriptor {
                    name: "Missing".into(),
                    code: 1,
                }],
            };
            let hash = descriptor.schema_hash();
            let catalog = [descriptor];
            let mut messages = vec![ContractErrorMessage {
                error_type: catalog[0].identity.clone(),
                code: 1,
                message: "残高が不足しています".into(),
            }];
            assert!(validate_contract_error_messages(&catalog, &messages));
            let bytes = norito::codec::Encode::encode(&messages);
            let decoded: Vec<ContractErrorMessage> =
                norito::codec::DecodeAll::decode_all(&mut bytes.as_slice()).unwrap();
            assert_eq!(decoded, messages);
            let json = norito::json::to_json(&messages).unwrap();
            assert_eq!(
                norito::json::from_str::<Vec<ContractErrorMessage>>(&json).unwrap(),
                messages
            );
            messages[0].message = "A revised explanation".into();
            assert_eq!(catalog[0].schema_hash(), hash);
            messages[0].message = "é".repeat(2048);
            assert!(validate_contract_error_messages(&catalog, &messages));
            messages[0].message.push('a');
            assert!(!validate_contract_error_messages(&catalog, &messages));
            messages[0].message = " \n\t".into();
            assert!(!validate_contract_error_messages(&catalog, &messages));
            messages[0].message = "Missing".into();
            messages[0].code = 2;
            assert!(!validate_contract_error_messages(&catalog, &messages));
            messages[0].code = 1;
            messages.push(messages[0].clone());
            assert!(!validate_contract_error_messages(&catalog, &messages));
        }
        #[test]
        fn shared_sdk_fixture_preserves_nominal_errors_and_cursor_page_schemas() {
            let fixture: norito::json::Value = norito::json::from_str(include_str!(
                "../../../fixtures/kotodama/nominal_errors_v1.json"
            ))
            .unwrap();
            let manifest: ContractManifest =
                norito::json::from_value(fixture.get("manifest").unwrap().clone()).unwrap();
            let entrypoints = manifest.entrypoints.as_ref().unwrap();
            assert_eq!(entrypoints.len(), 3);
            for entrypoint in entrypoints {
                assert_eq!(
                    entrypoint
                        .return_schema
                        .as_ref()
                        .unwrap()
                        .canonical_type_name(),
                    entrypoint.return_type
                );
            }
            assert_eq!(
                entrypoints[1].return_schema.as_ref().unwrap().word_count(),
                Some(1)
            );
            assert_eq!(
                entrypoints[2].return_schema.as_ref().unwrap().word_count(),
                Some(2)
            );
            let errors = manifest.error_types.as_ref().unwrap();
            assert_eq!(errors[0].variants[0].name, "不足");
            assert_eq!(errors[0].variants[0].code, errors[1].variants[0].code);
            let frame = norito::encode_canonical(&manifest).unwrap();
            assert_eq!(
                norito::decode_canonical::<ContractManifest>(&frame).unwrap(),
                manifest
            );
        }
        #[test]
        fn nominal_error_schema_identity_codes_and_wire_shape_are_exact() {
            let descriptor = ContractErrorTypeDescriptor {
                identity: "example/vault@1::金庫::拒否".into(),
                variants: vec![
                    ContractErrorVariantDescriptor {
                        name: "不足".into(),
                        code: 1,
                    },
                    ContractErrorVariantDescriptor {
                        name: "CapacityExceeded".into(),
                        code: 2,
                    },
                ],
            };
            assert!(descriptor.validate());
            let frame = norito::encode_canonical(&descriptor).unwrap();
            assert_eq!(
                norito::decode_canonical::<ContractErrorTypeDescriptor>(&frame).unwrap(),
                descriptor
            );
            let schema_hash = descriptor.schema_hash();
            let mut different = descriptor.clone();
            different.identity = "example/other@1::Other::Error".into();
            assert_eq!(
                schema_hash,
                different.schema_hash(),
                "nominal identity is bound separately"
            );
            different.variants[0].name = "OtherFailure".into();
            assert_ne!(schema_hash, different.schema_hash());
            different = descriptor.clone();
            different.variants[1].code = 3;
            assert_ne!(schema_hash, different.schema_hash());
            let flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _alternate = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(
                descriptor.schema_hash(),
                schema_hash,
                "schema identity ignores ambient layout"
            );
            for identity in [
                "",
                "bad identity",
                "bad<identity>",
                "__kotodama_link_hidden",
                "bad\nidentity",
            ] {
                different = descriptor.clone();
                different.identity = identity.into();
                assert!(!different.validate(), "{identity:?}");
            }
            for variants in [
                vec![],
                vec![ContractErrorVariantDescriptor {
                    name: "Zero".into(),
                    code: 0,
                }],
                vec![
                    descriptor.variants[1].clone(),
                    descriptor.variants[0].clone(),
                ],
                vec![
                    descriptor.variants[0].clone(),
                    descriptor.variants[0].clone(),
                ],
                vec![ContractErrorVariantDescriptor {
                    name: "Bad<Name>".into(),
                    code: 1,
                }],
            ] {
                different = descriptor.clone();
                different.variants = variants;
                assert!(!different.validate());
            }
            let json = norito::json::to_json(&descriptor).unwrap();
            assert_eq!(
                norito::json::from_str::<ContractErrorTypeDescriptor>(&json).unwrap(),
                descriptor
            );
            for forged in [
                json.replacen('{', "{\"unexpected\":true,", 1),
                json.replacen("\"name\":", "\"unexpected\":true,\"name\":", 1),
            ] {
                assert!(norito::json::from_str::<ContractErrorTypeDescriptor>(&forged).is_err());
            }
        }
        #[test]
        fn access_set_hints_roundtrip() {
            let hints = AccessSetHints {
                read_keys: vec!["account:satoshi".to_owned()],
                write_keys: vec!["asset:btc#iroha".to_owned()],
                dynamic_reads: Vec::new(),
                dynamic_writes: Vec::new(),
            };
            let json = norito::json::to_json(&hints).expect("serialize access hints");
            assert_eq!(
                json,
                "{\"read_keys\":[\"account:satoshi\"],\"write_keys\":[\"asset:btc#iroha\"],\"dynamic_reads\":[],\"dynamic_writes\":[]}"
            );
            let decoded: AccessSetHints = norito::json::from_str(&json).expect("deserialize hints");
            assert_eq!(decoded.read_keys, hints.read_keys);
            assert_eq!(decoded.write_keys, hints.write_keys);
        }
        #[test]
        fn entrypoint_kind_json_uses_only_branded_v1_names() {
            for (kind, name) in [
                (EntryPointKind::Kotoage, "Kotoage"),
                (EntryPointKind::View, "View"),
                (EntryPointKind::Hajimari, "Hajimari"),
                (EntryPointKind::Kaizen, "Kaizen"),
            ] {
                let json = norito::json::to_json(&kind).expect("serialize entrypoint kind");
                assert_eq!(json, format!(r#"{{"kind":"{name}","value":null}}"#));
                let decoded: EntryPointKind =
                    norito::json::from_str(&json).expect("deserialize branded entrypoint kind");
                assert_eq!(decoded, kind);
            }
            for retired in ["Public", "public", "Init", "init", "Upgrade", "upgrade"] {
                let json = format!(r#"{{"kind":"{retired}","value":null}}"#);
                norito::json::from_str::<EntryPointKind>(&json)
                    .expect_err("retired English entrypoint kind must be rejected");
            }
        }
        #[test]
        fn entrypoint_descriptor_includes_triggers() {
            use crate::{events::EventFilterBox, trigger::action::Repeats};
            let trigger = TriggerDescriptor {
                id: "wake".parse().expect("trigger id"),
                repeats: Repeats::Indefinitely,
                filter: EventFilterBox::Time(crate::events::time::TimeEventFilter(
                    crate::events::time::ExecutionTime::PreCommit,
                )),
                authority: None,
                metadata: Metadata::default(),
                callback: TriggerCallback {
                    namespace: None,
                    entrypoint: "run".to_string(),
                },
            };
            let entrypoint = EntrypointDescriptor {
                name: "run".to_string(),
                kind: EntryPointKind::Kotoage,
                params: vec![EntrypointParamDescriptor {
                    name: "amount".to_string(),
                    type_name: "quantity".to_string(),
                }],
                argument_schema: Some(EntrypointArgumentSchemaV1 {
                    fields: vec![
                        crate::smart_contract::entrypoint::EntrypointArgumentFieldV1 {
                            name: "amount".to_string(),
                            ty: EntrypointValueTypeV1 {
                                nodes: vec![crate::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                                    crate::smart_contract::entrypoint::EntrypointValueKindV1::Quantity,
                                )],
                            },
                        },
                    ],
                }),
                return_type: Some("int".to_string()),
                return_schema: Some(EntrypointValueTypeV1 {
                    nodes: vec![crate::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                        crate::smart_contract::entrypoint::EntrypointValueKindV1::Int,
                    )],
                }),
                authorization: EntrypointAuthorizationV1::Permission("ExecuteContract".parse().unwrap()),
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: vec![trigger],
            };
            let json = norito::json::to_json(&entrypoint).expect("serialize entrypoint");
            assert!(json.contains("\"triggers\""));
            let decoded: EntrypointDescriptor =
                norito::json::from_str(&json).expect("deserialize entrypoint");
            assert_eq!(decoded.triggers.len(), 1);
            assert_eq!(decoded.triggers[0].callback.entrypoint, "run");
        }
        #[test]
        fn access_set_hints_missing_fields_fail() {
            let err = norito::json::from_str::<AccessSetHints>("{}")
                .expect_err("missing fields must fail");
            match err {
                norito::json::Error::MissingField { field } => {
                    assert_eq!(field, "read_keys", "unexpected field: {field}");
                }
                norito::json::Error::Message(msg) => {
                    assert!(msg.contains("read_keys"), "unexpected error: {msg}");
                }
                other => panic!("unexpected error: {other}"),
            }
        }
        #[test]
        fn authorization_and_permission_scopes_roundtrip_without_legacy_defaults() {
            for authorization in [
                EntrypointAuthorizationV1::Anyone,
                EntrypointAuthorizationV1::Permission("Admin".parse().unwrap()),
                EntrypointAuthorizationV1::RuntimeLifecycle,
            ] {
                let frame = authorization.encode();
                assert_eq!(
                    EntrypointAuthorizationV1::decode(&mut &frame[..]).unwrap(),
                    authorization
                );
                let json = norito::json::to_json(&authorization).unwrap();
                assert_eq!(
                    norito::json::from_str::<EntrypointAuthorizationV1>(&json).unwrap(),
                    authorization
                );
            }
            for scope in [
                ContractPermissionScopeV1::Instance,
                ContractPermissionScopeV1::Chain {
                    permission_name: "Treasury".parse().unwrap(),
                },
            ] {
                let declaration = ContractPermissionDescriptorV1 {
                    name: "Admin".parse().unwrap(),
                    scope,
                };
                let frame = declaration.encode();
                assert_eq!(
                    ContractPermissionDescriptorV1::decode(&mut &frame[..]).unwrap(),
                    declaration
                );
                let json = norito::json::to_json(&declaration).unwrap();
                assert_eq!(
                    norito::json::from_str::<ContractPermissionDescriptorV1>(&json).unwrap(),
                    declaration
                );
            }
            for retired in [
                "null",
                "\"Admin\"",
                "{}",
                "{\"kind\":\"Scoped\",\"value\":\"Admin\"}",
            ] {
                assert!(norito::json::from_str::<EntrypointAuthorizationV1>(retired).is_err());
            }
        }

        #[test]
        fn permission_tables_and_authorization_enforce_declarations_and_kind() {
            let instance = ContractPermissionDescriptorV1 {
                name: "Admin".parse().unwrap(),
                scope: ContractPermissionScopeV1::Instance,
            };
            let shared = ContractPermissionDescriptorV1 {
                name: "Treasury".parse().unwrap(),
                scope: ContractPermissionScopeV1::Chain {
                    permission_name: "CanManageTreasury".parse().unwrap(),
                },
            };
            let table = [instance.clone(), shared.clone()];
            assert!(validate_contract_permission_table(&[]));
            assert!(validate_contract_permission_table(&table));
            assert!(!validate_contract_permission_table(&[
                shared,
                instance.clone()
            ]));
            assert!(!validate_contract_permission_table(&[
                instance.clone(),
                instance
            ]));
            for name in ["anyone", "permission", "a-b"] {
                assert!(!validate_contract_permission_table(&[
                    ContractPermissionDescriptorV1 {
                        name: name.parse().unwrap(),
                        scope: ContractPermissionScopeV1::Instance,
                    }
                ]));
            }
            for kind in [EntryPointKind::Kotoage, EntryPointKind::View] {
                assert!(EntrypointAuthorizationV1::Anyone.is_valid_for(kind, &table));
                for name in ["Admin", "Treasury"] {
                    assert!(
                        EntrypointAuthorizationV1::Permission(name.parse().unwrap())
                            .is_valid_for(kind, &table)
                    );
                }
                assert!(
                    !EntrypointAuthorizationV1::Permission("Admn".parse().unwrap())
                        .is_valid_for(kind, &table)
                );
                assert!(!EntrypointAuthorizationV1::RuntimeLifecycle.is_valid_for(kind, &table));
            }
            for kind in [EntryPointKind::Hajimari, EntryPointKind::Kaizen] {
                assert!(EntrypointAuthorizationV1::RuntimeLifecycle.is_valid_for(kind, &table));
                assert!(!EntrypointAuthorizationV1::Anyone.is_valid_for(kind, &table));
                assert!(
                    !EntrypointAuthorizationV1::Permission("Admin".parse().unwrap())
                        .is_valid_for(kind, &table)
                );
            }
        }
    }
    #[cfg(test)]
    mod manifest_signing_tests {
        use super::*;
        use iroha_crypto::KeyPair;
        fn checked_random_keypair() -> KeyPair {
            KeyPair::try_random().expect("test fixture random key generation should succeed")
        }
        const TEST_FRAME_MAX: usize = 64 * 1024;
        fn signing_context() -> (
            iroha_allocation::AllocationBudget,
            iroha_allocation::AllocationReservation,
            norito::core::DecodeBudgetContext,
        ) {
            let grant_bytes = 512 * 1024;
            let owner = iroha_allocation::AllocationBudget::new(1024 * 1024);
            let grant = owner
                .try_reserve_bytes(grant_bytes)
                .expect("physical fixture grant");
            let context = norito::core::DecodeBudgetContext::try_new_owned(
                norito::core::DecodeLimits::new(65_536, TEST_FRAME_MAX, 65_536, grant_bytes, 256),
                &owner,
            )
            .expect("original owned cumulative fixture context");
            (owner, grant, context)
        }
        #[test]
        fn signature_payload_excludes_provenance_and_verifies() {
            let (_owner, _grant, context) = signing_context();
            let kp = checked_random_keypair();
            let mut manifest = ContractManifest {
                permissions: Vec::new(),
                events: Vec::new(),
                enum_types: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(Hash::new(b"code-bytes")),
                abi_hash: Some(Hash::new(b"abi-bytes")),
                compiler_fingerprint: Some("rustc-1.78".to_owned()),
                features_bitmap: Some(0xAA),
                access_set_hints: None,
                entrypoints: None,
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: Some(vec![ContractErrorTypeDescriptor {
                    identity: "PaymentError".to_owned(),
                    variants: vec![ContractErrorVariantDescriptor {
                        name: "Unauthorized".to_owned(),
                        code: 1001,
                    }],
                }]),
                provenance: None,
            };
            let payload = manifest
                .signature_payload_bytes(&context, TEST_FRAME_MAX)
                .expect("bounded signature payload");
            {
                let alternate_flags =
                    norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
                let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
                assert_eq!(
                    manifest
                        .signature_payload_bytes(&context, TEST_FRAME_MAX)
                        .expect("bounded signature payload"),
                    payload,
                    "manifest signature identity must ignore the caller's ambient Norito layout"
                );
            }
            let signature = Signature::try_new(kp.private_key(), &payload)
                .expect("checked contract manifest fixture signature");
            manifest.provenance = Some(ManifestProvenance {
                signer: kp.public_key().clone(),
                signature: signature.clone(),
            });
            // Provenance should not affect the payload bytes.
            assert_eq!(
                payload,
                manifest
                    .signature_payload_bytes(&context, TEST_FRAME_MAX)
                    .expect("bounded signature payload")
            );
            signature
                .verify(kp.public_key(), &payload)
                .expect("signature must verify");
            manifest.error_messages = Some(vec![ContractErrorMessage {
                error_type: "PaymentError".into(),
                code: 1001,
                message: "Permission denied".into(),
            }]);
            assert!(
                signature
                    .verify(
                        kp.public_key(),
                        &manifest
                            .signature_payload_bytes(&context, TEST_FRAME_MAX)
                            .expect("bounded signature payload")
                    )
                    .is_err(),
                "manifest provenance must bind static presentation text"
            );
            let explained = manifest
                .clone()
                .try_signed(&context, TEST_FRAME_MAX, &kp)
                .expect("sign explained manifest");
            let explained_signature = &explained.provenance.as_ref().expect("signature").signature;
            explained_signature
                .verify(
                    kp.public_key(),
                    &explained
                        .signature_payload_bytes(&context, TEST_FRAME_MAX)
                        .expect("bounded signature payload"),
                )
                .expect("explained manifest signature must verify");
            manifest.error_messages.as_mut().expect("messages")[0].message =
                "Revised explanation".into();
            assert!(
                explained_signature
                    .verify(
                        kp.public_key(),
                        &manifest
                            .signature_payload_bytes(&context, TEST_FRAME_MAX)
                            .expect("bounded signature payload")
                    )
                    .is_err(),
                "changing only presentation text must invalidate provenance"
            );
            manifest.error_messages = None;
            manifest.error_types.as_mut().expect("error types")[0].variants[0].code = 1002;
            assert!(
                signature
                    .verify(
                        kp.public_key(),
                        &manifest
                            .signature_payload_bytes(&context, TEST_FRAME_MAX)
                            .expect("bounded signature payload")
                    )
                    .is_err(),
                "manifest provenance must bind nominal error variant codes"
            );
            manifest.error_types.as_mut().unwrap()[0].variants[0].code = 1001;
            manifest.permissions.push(ContractPermissionDescriptorV1 {
                name: "UnusedRole".parse().unwrap(),
                scope: ContractPermissionScopeV1::Instance,
            });
            assert!(
                signature
                    .verify(
                        kp.public_key(),
                        &manifest
                            .signature_payload_bytes(&context, TEST_FRAME_MAX)
                            .unwrap()
                    )
                    .is_err(),
                "a declared role must be signed even when no entrypoint references it"
            );
            let mut json = norito::json::to_value(&manifest).unwrap();
            json.as_object_mut().unwrap().remove("permissions");
            assert!(
                norito::json::from_value::<ContractManifest>(json).is_err(),
                "a missing declaration table must not decode as an empty table"
            );
        }
        #[test]
        fn try_signed_attaches_verifiable_provenance() {
            let (_owner, _grant, context) = signing_context();
            let kp = checked_random_keypair();
            let manifest = ContractManifest {
                permissions: Vec::new(),
                events: Vec::new(),
                enum_types: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(Hash::new(b"contract-code")),
                abi_hash: Some(Hash::new(b"contract-abi")),
                compiler_fingerprint: Some("kotodama-test".to_owned()),
                features_bitmap: Some(0x55),
                access_set_hints: None,
                entrypoints: None,
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: None,
                provenance: None,
            };
            let signed = manifest
                .try_signed(&context, TEST_FRAME_MAX, &kp)
                .expect("sign manifest");
            let provenance = signed.provenance.as_ref().expect("manifest provenance");
            let payload = signed
                .signature_payload_bytes(&context, TEST_FRAME_MAX)
                .expect("bounded signature payload");
            assert_eq!(provenance.signer, kp.public_key().clone());
            provenance
                .signature
                .verify(kp.public_key(), &payload)
                .expect("signature must verify");
        }
    }
}

#[cfg(test)]
mod frame_owner_identity_tests {
    //! Frame roots observed in the original codec before the identity cutover.

    #[test]
    fn captured_frame_owner_identities() {
        crate::frame_owner_identity_tests::assert_bidirectional::<
            super::manifest::ContractManifestSignaturePayload,
        >("iroha_data_model::smart_contract::manifest::ContractManifestSignaturePayload");
    }
}

#[cfg(test)]
mod additional_frame_owner_identity_tests {
    //! Typed frame contracts observed with the original codec.

    #[test]
    fn captured_additional_frame_owner_identities() {
        crate::frame_owner_identity_tests::assert_bidirectional::<
            crate::smart_contract::manifest::ContractErrorTypeDescriptor,
        >("iroha_data_model::smart_contract::manifest::ContractErrorTypeDescriptor");
        crate::frame_owner_identity_tests::assert_bidirectional::<
            crate::smart_contract::manifest::ContractManifest,
        >("iroha_data_model::smart_contract::manifest::ContractManifest");
        crate::frame_owner_identity_tests::assert_bidirectional::<
            crate::smart_contract::model::ContractLifecycleControlV1,
        >("iroha_data_model::smart_contract::model::ContractLifecycleControlV1");
    }
}

/// Canonical current contract-multisig construction shared by clients and Torii.
pub mod multisig_call;

#[cfg(test)]
mod checked_container_cleanup_tests {
    //! Original owning writer refusal and nested-depth controls.
    use crate::checked_container_refusal_controls::audit;

    #[test]
    fn original_access_hints_checked_container_retains_original_key_vectors_and_depth() {
        let value = crate::smart_contract::manifest::AccessSetHints {
            read_keys: vec!["a".into()],
            write_keys: vec!["b".into()],
            dynamic_reads: Vec::new(),
            dynamic_writes: Vec::new(),
        };
        let reads = value.read_keys.as_ptr();
        let writes = value.write_keys.as_ptr();
        audit(&value);
        assert_eq!(value.read_keys.as_ptr(), reads);
        assert_eq!(value.write_keys.as_ptr(), writes);
    }
}
