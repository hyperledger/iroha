//! Validation-fee policy data shared by validators and clients.

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use crate::{
    NetworkId,
    account::AccountId,
    asset::AssetDefinitionId,
    parameter::{CustomParameter, CustomParameterId},
    parliament_types::{GovernanceCertificateId, GovernanceCertificateV1, ProposalContentId},
    smart_contract::ContractAddress,
};
use iroha_crypto::Hash;
use iroha_model_base::name::Name;
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::collections::BTreeSet;
mod retail;
pub use retail::*;
mod payout;
pub use payout::*;
/// Schema version for the initial validation-fee policy.
pub const VALIDATION_FEE_POLICY_SCHEMA_VERSION: u16 = 1;
/// Decimal scale required for the initial policy fee asset.
pub const VALIDATION_FEE_DS_SCALE: u8 = 2;
/// Canonical fee amount required by the initial validation-fee policy (0.10 DS).
pub const VALIDATION_FEE_INITIAL_AMOUNT: &str = "0.10";
/// Only release exemption class implemented by validator admission.
pub const VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS: &str = "TREASURY_PAYOUT";
/// Domain separator for policy hashing.
pub const VALIDATION_FEE_POLICY_HASH_DOMAIN: &[u8] = b"iroha.validation_fee.policy.parliament.v1";
/// Domain separator for an exact Parliament-approved payout lifecycle.
pub const VALIDATION_FEE_PAYOUT_LIFECYCLE_SEAL_DOMAIN: &[u8] =
    b"iroha.validation_fee.payout_lifecycle.seal.v1";
/// Domain separator for the canonical full-registry snapshot hash.
pub const VALIDATION_FEE_REGISTRY_SNAPSHOT_HASH_DOMAIN: &[u8] =
    b"iroha.validation_fee.registry.snapshot.v1";
/// Current validation-fee synthetic witness format.
pub const VALIDATION_FEE_POLICY_SNAPSHOT_VERSION_V1: u16 = 1;
/// Exact sparse-tree depth of the execution-witness proof.
pub const VALIDATION_FEE_POLICY_WITNESS_SIBLINGS_V1: usize = 256;
/// Maximum canonical protected registry bytes retained in every fee evidence corpus.
/// Optional governance appends must preserve room for automatic reward materialization.
pub const MAX_VALIDATION_FEE_REGISTRY_BYTES: usize = 1024 * 1024;
pub use crate::execution_witness::VALIDATION_FEE_POLICY_WITNESS_KEY_V1;
/// Retired custom-parameter identifier for the pre-release governance keyset.
pub const RETIRED_VALIDATION_FEE_GOVERNANCE_KEYSET_PARAMETER_ID: &str =
    "iroha:validation_fee_governance_keyset_v1";
/// Retired custom-parameter identifier for the pre-release active-policy copy.
pub const RETIRED_VALIDATION_FEE_POLICY_PARAMETER_ID: &str = "iroha:validation_fee_policy_v1";
/// Return whether a custom parameter identifier belongs to the consensus-owned
/// validation-fee governance surface.
///
/// These parameters are enacted atomically by SORA Parliament and must never be writable through
/// the generic `SetParameter` instruction, including at genesis.
#[must_use]
pub fn is_reserved_validation_fee_parameter_id(id: &CustomParameterId) -> bool {
    id == &ValidationFeePolicyRegistryV1::parameter_id()
        || id.to_string() == RETIRED_VALIDATION_FEE_GOVERNANCE_KEYSET_PARAMETER_ID
        || id.to_string() == RETIRED_VALIDATION_FEE_POLICY_PARAMETER_ID
}
/// Error returned when a validation-fee policy registry is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationFeePolicyRegistryError {
    /// Canonical registry serialization failed.
    RegistryEncoding,
    /// The complete authenticated history exceeds its per-block evidence budget.
    RegistryByteLimit,
    /// No registered policy entries were supplied.
    EmptyRegistry,
    /// A policy entry did not continue the monotonic version chain.
    UnexpectedPolicyVersion {
        /// Version expected at this position in the chain.
        expected: u64,
        /// Version found in the registry entry.
        found: u64,
    },
    /// The same policy hash appeared more than once.
    DuplicatePolicyHash {
        /// Version of the duplicate policy entry.
        policy_version: u64,
    },
    /// A registry entry does not point at the immediately previous policy hash.
    BrokenPreviousPolicyHash {
        /// Version of the broken policy entry.
        policy_version: u64,
    },
    /// A policy hash could not be computed.
    PolicyHashEncoding,
    /// A policy payload violates the validation-fee policy invariants.
    InvalidPolicyInvariant {
        /// Version of the invalid policy.
        policy_version: u64,
    },
    /// An entry's stored hash does not match its complete policy.
    PolicyHashMismatch {
        /// Version of the malformed entry.
        policy_version: u64,
    },
    /// A successor was scheduled before its predecessor.
    ActivationOrderRollback {
        /// Version of the malformed entry.
        policy_version: u64,
    },
    /// A successor changed the immutable exact network binding.
    NetworkIdentityChanged {
        /// Version of the malformed entry.
        policy_version: u64,
    },
    /// Typed Parliament authorization evidence is malformed.
    InvalidParliamentAuthorization {
        /// Version of the malformed entry.
        policy_version: u64,
    },
    /// A payout lifecycle reference is missing, unexpected, or malformed.
    InvalidPayoutLifecycleReference {
        /// Version of the malformed entry.
        policy_version: u64,
    },
}
impl core::fmt::Display for ValidationFeePolicyRegistryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RegistryEncoding => write!(f, "validation-fee registry could not be encoded"),
            Self::RegistryByteLimit => write!(
                f,
                "validation-fee registry exceeds its canonical byte limit"
            ),
            Self::EmptyRegistry => write!(f, "validation-fee policy registry is empty"),
            Self::UnexpectedPolicyVersion { expected, found } => write!(
                f,
                "validation-fee policy registry version chain is not monotonic: expected {expected}, found {found}"
            ),
            Self::DuplicatePolicyHash { policy_version } => write!(
                f,
                "validation-fee policy registry contains duplicate hash at version {policy_version}"
            ),
            Self::BrokenPreviousPolicyHash { policy_version } => write!(
                f,
                "validation-fee policy registry previous hash is broken at version {policy_version}"
            ),
            Self::PolicyHashEncoding => {
                write!(
                    f,
                    "validation-fee registry policy hash could not be encoded"
                )
            }
            Self::InvalidPolicyInvariant { policy_version } => write!(
                f,
                "validation-fee registry policy version {policy_version} violates policy invariants"
            ),
            Self::PolicyHashMismatch { policy_version } => write!(
                f,
                "validation-fee registry policy hash mismatch at version {policy_version}"
            ),
            Self::ActivationOrderRollback { policy_version } => write!(
                f,
                "validation-fee policy enactment or calendar activation moves backwards at version {policy_version}"
            ),
            Self::NetworkIdentityChanged { policy_version } => write!(
                f,
                "validation-fee policy changes the immutable network identity at version {policy_version}"
            ),
            Self::InvalidParliamentAuthorization { policy_version } => write!(
                f,
                "validation-fee policy version {policy_version} has invalid Parliament authorization evidence"
            ),
            Self::InvalidPayoutLifecycleReference { policy_version } => write!(
                f,
                "validation-fee policy version {policy_version} has an invalid payout lifecycle reference"
            ),
        }
    }
}
impl std::error::Error for ValidationFeePolicyRegistryError {}
/// Validation-fee charging mode.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(
    tag = "charging_mode",
    content = "value",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeeChargingMode")]
pub enum ValidationFeeChargingMode {
    /// Monthly retail maintenance and included payments, with governed overage.
    RetailMonthlyAllowance,
}
/// Canonical Parliament certificate authorization for one enacted validation-fee proposal.
#[derive(
    Debug,
    Clone,
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
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeeParliamentAuthorizationV1")]
pub struct ValidationFeeParliamentAuthorizationV1 {
    /// Canonical transaction authority bound into the exact proposal preimage.
    pub proposal_operator: AccountId,
    /// Fingerprint of the exact stored proposal preimage.
    pub proposal_fingerprint: [u8; 32],
    /// Canonical content identifier of the complete retained Parliament certificate.
    pub governance_certificate_id: GovernanceCertificateId,
    /// Complete private-ballot Parliament certificate retained for independent validation.
    pub governance_certificate: GovernanceCertificateV1,
    /// Height at which the certified proposal was appended to its governed registry.
    #[norito(json = "crate::json_helpers::u64_string")]
    pub enacted_at_height: u64,
}
impl ValidationFeeParliamentAuthorizationV1 {
    /// Return a stable invariant violation, if any.
    #[must_use]
    pub fn invariant_error(&self) -> Option<&'static str> {
        if self.proposal_fingerprint == [0; 32] {
            return Some(
                "validation-fee Parliament proposal fingerprint must be a non-zero native identifier",
            );
        }
        if self.governance_certificate.validate().is_err() {
            return Some("validation-fee Parliament certificate is structurally invalid");
        }
        if self.governance_certificate_id.as_bytes() == &[0; 32]
            || self.governance_certificate_id
                != GovernanceCertificateId::derive_v1(&self.governance_certificate)
        {
            return Some(
                "validation-fee Parliament certificate identifier is not the canonical certificate hash",
            );
        }
        if self.governance_certificate.proposal_content_id
            != ProposalContentId::new(self.proposal_fingerprint)
        {
            return Some(
                "validation-fee Parliament certificate targets a different proposal fingerprint",
            );
        }
        if self.enacted_at_height != self.governance_certificate.enact_at_height {
            return Some(
                "validation-fee enactment height must equal the Parliament certificate due height",
            );
        }
        None
    }
}
/// One entry in the registered validation-fee policy hash chain.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeePolicyRegistryEntryV1")]
pub struct ValidationFeePolicyRegistryEntryV1 {
    /// Complete governed policy, retained so scheduled policies do not hide
    /// the policy that is effective at the current height.
    pub policy: ValidationFeePolicyV1,
    /// Domain-separated policy hash.
    pub policy_hash: [u8; 32],
    /// Typed, independently checkable Parliament certificate authorization.
    pub parliament_authorization: ValidationFeeParliamentAuthorizationV1,
}
impl ValidationFeePolicyRegistryEntryV1 {
    /// Build a registry entry from one enacted Parliament proposal.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the policy cannot be hashed.
    pub fn from_enactment(
        policy: ValidationFeePolicyV1,
        parliament_authorization: ValidationFeeParliamentAuthorizationV1,
    ) -> Result<Self, norito::Error> {
        let policy_hash = policy.policy_hash()?;
        Ok(Self {
            policy,
            policy_hash,
            parliament_authorization,
        })
    }
}
/// On-ledger validation-fee policy registry used to reject rollback and
/// skipped-version policy changes while retaining scheduled policy history.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeePolicyRegistryV1")]
pub struct ValidationFeePolicyRegistryV1 {
    /// Registered policy chain in ascending, contiguous version order.
    pub registered_policies: Vec<ValidationFeePolicyRegistryEntryV1>,
    /// Independently revised conversion policies under the same authenticated registry root.
    pub payout_policies: ValidationFeePayoutPolicyRegistryV1,
}
impl ValidationFeePolicyRegistryV1 {
    /// Identifier of the chain-level custom parameter carrying the policy registry.
    pub const PARAMETER_ID_STR: &'static str = "iroha:validation_fee_policy_registry_v1";
    /// Construct the custom-parameter identifier for this registry.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        Self::PARAMETER_ID_STR
            .parse()
            .expect("valid validation-fee policy registry parameter identifier")
    }
    /// Convert this registry into an on-ledger custom parameter.
    #[must_use]
    pub fn into_custom_parameter(self) -> CustomParameter {
        CustomParameter::new(Self::parameter_id(), Json::new(self))
    }
    /// Decode a validation-fee policy registry from a custom parameter.
    #[must_use]
    pub fn from_custom_parameter(custom: &CustomParameter) -> Option<Self> {
        if custom.id() != &Self::parameter_id() {
            return None;
        }
        custom.payload().try_into_any_norito::<Self>().ok()
    }
    /// Reconstruct the exact protected registry after the requested finalized height.
    ///
    /// Authenticate the complete offered history before selecting both independent enactment
    /// prefixes. A payout-only bootstrap remains a configured snapshot; no later conversion or
    /// pricing enactment may enter the historical registry hash.
    ///
    /// # Errors
    /// Returns the original registry validation error for an invalid full or retained history.
    pub fn retained_at_height(
        mut self,
        height: u64,
    ) -> Result<Option<Self>, ValidationFeePolicyRegistryError> {
        self.validate()?;
        self.registered_policies
            .retain(|entry| entry.parliament_authorization.enacted_at_height <= height);
        self.payout_policies
            .entries
            .retain(|entry| entry.parliament_authorization.enacted_at_height <= height);
        if self.registered_policies.is_empty() && self.payout_policies.entries.is_empty() {
            return Ok(None);
        }
        self.validate()?;
        Ok(Some(self))
    }
    /// Validate the complete contiguous policy chain and authenticate every retained Parliament
    /// proposal fingerprint.
    ///
    /// The validation-fee module reproduces the frozen V1 proposal preimages locally and validates
    /// each complete canonical Parliament certificate through the always-compiled type layer.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is empty, non-monotonic, broken, unauthenticated, or
    /// contains a policy whose stored hash differs from its payload.
    pub fn validate(&self) -> Result<(), ValidationFeePolicyRegistryError> {
        // TODO: authenticate compact historical registry checkpoints before
        // admitting revisions beyond this bound; never discard signed evidence.
        if norito::to_bytes(self)
            .map_err(|_| ValidationFeePolicyRegistryError::RegistryEncoding)?
            .len()
            > MAX_VALIDATION_FEE_REGISTRY_BYTES
        {
            return Err(ValidationFeePolicyRegistryError::RegistryByteLimit);
        }
        self.payout_policies.validate().map_err(|_| {
            ValidationFeePolicyRegistryError::InvalidPayoutLifecycleReference { policy_version: 0 }
        })?;
        let mut entries = self.registered_policies.iter();
        let Some(first) = entries.next() else {
            return Ok(());
        };
        let payout_custody = self
            .payout_policies
            .head()
            .expect("validated nonempty payout registry")
            .payout_binding
            .custody();
        if first.policy.reward_custody != payout_custody {
            return Err(ValidationFeePolicyRegistryError::InvalidPolicyInvariant {
                policy_version: first.policy.policy_version,
            });
        }
        if first.policy.policy_version != 1 {
            return Err(ValidationFeePolicyRegistryError::UnexpectedPolicyVersion {
                expected: 1,
                found: first.policy.policy_version,
            });
        }
        if first.policy.policy_invariant_error().is_some() {
            return Err(ValidationFeePolicyRegistryError::InvalidPolicyInvariant {
                policy_version: first.policy.policy_version,
            });
        }
        if first.policy.previous_policy_hash.is_some() {
            return Err(ValidationFeePolicyRegistryError::BrokenPreviousPolicyHash {
                policy_version: first.policy.policy_version,
            });
        }
        validate_registry_entry_authorization(first)?;
        let first_hash = first
            .policy
            .policy_hash()
            .map_err(|_| ValidationFeePolicyRegistryError::PolicyHashEncoding)?;
        if first_hash != first.policy_hash {
            return Err(ValidationFeePolicyRegistryError::PolicyHashMismatch {
                policy_version: first.policy.policy_version,
            });
        }
        let mut seen_hashes = BTreeSet::from([first.policy_hash]);
        let mut expected_version = 2u64;
        let mut previous_hash = first.policy_hash;
        let mut previous_enacted_height = first.parliament_authorization.enacted_at_height;
        let mut previous_effective_ms = first.policy.effective_from_ms;
        let network_id = first.policy.network_id;
        for entry in entries {
            if entry.policy.policy_version != expected_version {
                return Err(ValidationFeePolicyRegistryError::UnexpectedPolicyVersion {
                    expected: expected_version,
                    found: entry.policy.policy_version,
                });
            }
            if entry.policy.policy_invariant_error().is_some() {
                return Err(ValidationFeePolicyRegistryError::InvalidPolicyInvariant {
                    policy_version: entry.policy.policy_version,
                });
            }
            if !seen_hashes.insert(entry.policy_hash) {
                return Err(ValidationFeePolicyRegistryError::DuplicatePolicyHash {
                    policy_version: entry.policy.policy_version,
                });
            }
            if entry.policy.previous_policy_hash != Some(previous_hash) {
                return Err(ValidationFeePolicyRegistryError::BrokenPreviousPolicyHash {
                    policy_version: entry.policy.policy_version,
                });
            }
            if entry.policy.ds_asset_id != first.policy.ds_asset_id
                || entry.policy.treasury_account_id != first.policy.treasury_account_id
            {
                return Err(ValidationFeePolicyRegistryError::InvalidPolicyInvariant {
                    policy_version: entry.policy.policy_version,
                });
            }
            if entry.policy.reward_custody != first.policy.reward_custody {
                return Err(ValidationFeePolicyRegistryError::InvalidPolicyInvariant {
                    policy_version: entry.policy.policy_version,
                });
            }
            if entry.policy.network_id != network_id {
                return Err(ValidationFeePolicyRegistryError::NetworkIdentityChanged {
                    policy_version: entry.policy.policy_version,
                });
            }
            validate_registry_entry_authorization(entry)?;
            let policy_hash = entry
                .policy
                .policy_hash()
                .map_err(|_| ValidationFeePolicyRegistryError::PolicyHashEncoding)?;
            if policy_hash != entry.policy_hash {
                return Err(ValidationFeePolicyRegistryError::PolicyHashMismatch {
                    policy_version: entry.policy.policy_version,
                });
            }
            if entry.parliament_authorization.enacted_at_height < previous_enacted_height
                || entry.policy.effective_from_ms <= previous_effective_ms
            {
                return Err(ValidationFeePolicyRegistryError::ActivationOrderRollback {
                    policy_version: entry.policy.policy_version,
                });
            }
            expected_version = expected_version.checked_add(1).ok_or(
                ValidationFeePolicyRegistryError::UnexpectedPolicyVersion {
                    expected: u64::MAX,
                    found: entry.policy.policy_version,
                },
            )?;
            previous_hash = entry.policy_hash;
            previous_enacted_height = entry.parliament_authorization.enacted_at_height;
            previous_effective_ms = entry.policy.effective_from_ms;
        }
        Ok(())
    }
    /// Return the latest enacted entry, including a policy scheduled for a future calendar boundary.
    #[must_use]
    pub fn head(&self) -> Option<&ValidationFeePolicyRegistryEntryV1> {
        self.registered_policies.last()
    }
    /// Return the highest revision finalized before the evaluated block.
    #[must_use]
    pub fn scheduled_entry_at_height(
        &self,
        height: u64,
    ) -> Option<&ValidationFeePolicyRegistryEntryV1> {
        self.registered_policies
            .iter()
            .rev()
            .find(|entry| entry.parliament_authorization.enacted_at_height < height)
    }
    /// Select finalized pricing exclusively by its Honiara calendar activation.
    #[must_use]
    pub fn effective_entry_at(
        &self,
        height: u64,
        timestamp_ms: u64,
    ) -> Option<&ValidationFeePolicyRegistryEntryV1> {
        self.registered_policies.iter().rev().find(|entry| {
            entry.parliament_authorization.enacted_at_height < height
                && entry.policy.effective_from_ms <= timestamp_ms
        })
    }
    /// Hash the canonical complete registry for a finality-bound snapshot.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error when the registry cannot be serialized.
    pub fn snapshot_hash(&self) -> Result<[u8; 32], norito::Error> {
        let encoded = norito::encode_canonical(self)?;
        let mut preimage = Vec::with_capacity(
            VALIDATION_FEE_REGISTRY_SNAPSHOT_HASH_DOMAIN.len() + 1 + encoded.len(),
        );
        preimage.extend_from_slice(VALIDATION_FEE_REGISTRY_SNAPSHOT_HASH_DOMAIN);
        preimage.push(0);
        preimage.extend_from_slice(&encoded);
        Ok(*Hash::new(preimage).as_ref())
    }
}
/// Valid registry facts bound into each block's synthetic witness write.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeePolicySnapshotAvailableV1")]
pub struct ValidationFeePolicySnapshotAvailableV1 {
    /// Hash of the canonical complete registry.
    pub registry_hash: [u8; 32],
    /// Latest enacted policy hash, including a future scheduled successor.
    pub head_policy_hash: Option<[u8; 32]>,
    /// Highest-version policy whose effective height has arrived.
    pub scheduled_policy_hash: Option<[u8; 32]>,
    /// Scheduled policy hash when its validity window is active.
    pub effective_policy_hash: Option<[u8; 32]>,
}
/// Registry availability committed by a validation-fee synthetic witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema)]
#[norito(
    tag = "status",
    content = "value",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeePolicySnapshotStatusV1")]
pub enum ValidationFeePolicySnapshotStatusV1 {
    /// Parliament has not enacted the first policy.
    Unconfigured,
    /// A malformed protected registry was observed; the hash identifies the failure.
    Invalid(Hash),
    /// A validated full registry and its height-dependent selection.
    Available(ValidationFeePolicySnapshotAvailableV1),
}
/// Canonical validation-fee registry commitment written into every block witness.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeePolicySnapshotCommitmentV1")]
pub struct ValidationFeePolicySnapshotCommitmentV1 {
    /// Snapshot format version.
    pub version: u16,
    /// Block height whose post-execution registry state was evaluated.
    pub evaluated_height: u64,
    /// Consensus timestamp of that block header, used for Honiara month activation.
    pub evaluated_timestamp_ms: u64,
    /// Validated registry state and selected policy hashes.
    pub status: ValidationFeePolicySnapshotStatusV1,
}
impl ValidationFeePolicySnapshotCommitmentV1 {
    /// Derive a deterministic commitment from the protected registry state.
    #[must_use]
    pub fn from_registry(
        evaluated_height: u64,
        evaluated_timestamp_ms: u64,
        registry: Option<&ValidationFeePolicyRegistryV1>,
    ) -> Self {
        let Some(registry) = registry else {
            return Self {
                version: VALIDATION_FEE_POLICY_SNAPSHOT_VERSION_V1,
                evaluated_height,
                evaluated_timestamp_ms,
                status: ValidationFeePolicySnapshotStatusV1::Unconfigured,
            };
        };
        let available = registry.validate().and_then(|()| {
            let registry_hash = registry
                .snapshot_hash()
                .map_err(|_| ValidationFeePolicyRegistryError::PolicyHashEncoding)?;
            Ok(ValidationFeePolicySnapshotAvailableV1 {
                registry_hash,
                head_policy_hash: registry.head().map(|head| head.policy_hash),
                scheduled_policy_hash: registry
                    .scheduled_entry_at_height(evaluated_height)
                    .map(|entry| entry.policy_hash),
                effective_policy_hash: registry
                    .effective_entry_at(evaluated_height, evaluated_timestamp_ms)
                    .map(|entry| entry.policy_hash),
            })
        });
        let status = match available {
            Ok(available) => ValidationFeePolicySnapshotStatusV1::Available(available),
            Err(error) => {
                ValidationFeePolicySnapshotStatusV1::Invalid(Hash::new(error.to_string()))
            }
        };
        Self {
            version: VALIDATION_FEE_POLICY_SNAPSHOT_VERSION_V1,
            evaluated_height,
            evaluated_timestamp_ms,
            status,
        }
    }
    /// Derive the commitment directly from the protected custom parameter.
    #[must_use]
    pub fn from_custom_parameter_state(
        evaluated_height: u64,
        evaluated_timestamp_ms: u64,
        custom: Option<&CustomParameter>,
    ) -> Self {
        let Some(custom) = custom else {
            return Self::from_registry(evaluated_height, evaluated_timestamp_ms, None);
        };
        let Some(registry) = ValidationFeePolicyRegistryV1::from_custom_parameter(custom) else {
            let invalid_hash = norito::encode_canonical(custom)
                .map_or_else(|_| Hash::new(custom.id().to_string()), Hash::new);
            return Self {
                version: VALIDATION_FEE_POLICY_SNAPSHOT_VERSION_V1,
                evaluated_height,
                evaluated_timestamp_ms,
                status: ValidationFeePolicySnapshotStatusV1::Invalid(invalid_hash),
            };
        };
        Self::from_registry(evaluated_height, evaluated_timestamp_ms, Some(&registry))
    }
}
/// Sparse-SMT proof that the validation-fee snapshot is an ordinary write.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeePolicyWitnessProofV1")]
pub struct ValidationFeePolicyWitnessProofV1 {
    /// Fixed raw execution-witness key.
    pub key: Vec<u8>,
    /// Exact canonical encoded snapshot commitment.
    pub value: Vec<u8>,
    /// Exactly 256 siblings from leaf level to the ordinary-write root.
    pub siblings: Vec<Hash>,
}
impl ValidationFeePolicyWitnessProofV1 {
    /// Verify the fixed synthetic write against an ordinary-write SMT root.
    #[must_use]
    pub fn verify(&self, expected_ordinary_writes_root: Hash) -> bool {
        if self.key != VALIDATION_FEE_POLICY_WITNESS_KEY_V1
            || self.siblings.len() != VALIDATION_FEE_POLICY_WITNESS_SIBLINGS_V1
        {
            return false;
        }
        let Ok(commitment) =
            norito::decode_canonical::<ValidationFeePolicySnapshotCommitmentV1>(&self.value)
        else {
            return false;
        };
        if commitment.version != VALIDATION_FEE_POLICY_SNAPSHOT_VERSION_V1 {
            return false;
        }
        let path = Hash::new(&self.key);
        let value_hash = Hash::new(&self.value);
        let mut leaf_preimage = Vec::with_capacity(1 + 2 * Hash::LENGTH);
        leaf_preimage.push(0);
        leaf_preimage.extend_from_slice(path.as_ref());
        leaf_preimage.extend_from_slice(value_hash.as_ref());
        let mut current = Hash::new(leaf_preimage);
        for (level, sibling) in self.siblings.iter().copied().enumerate() {
            let path_bit = 255_usize.saturating_sub(level);
            let byte = path.as_ref()[path_bit / 8];
            let right = byte & (1_u8 << (path_bit % 8)) != 0;
            current = if right {
                validation_fee_ordinary_smt_node_hash(sibling, current)
            } else {
                validation_fee_ordinary_smt_node_hash(current, sibling)
            };
        }
        current == expected_ordinary_writes_root
    }
    /// Decode and return the exact canonical snapshot commitment.
    ///
    /// # Errors
    ///
    /// Returns an error when the stored value is not a valid canonical Norito
    /// encoding of [`ValidationFeePolicySnapshotCommitmentV1`].
    pub fn commitment(&self) -> Result<ValidationFeePolicySnapshotCommitmentV1, String> {
        norito::decode_canonical(&self.value).map_err(|error| {
            if matches!(&error, norito::Error::NonCanonicalEncoding) {
                "validation-fee snapshot commitment is non-canonical".into()
            } else {
                format!("validation-fee snapshot commitment is invalid: {error}")
            }
        })
    }
}
fn validation_fee_ordinary_smt_node_hash(left: Hash, right: Hash) -> Hash {
    let mut preimage = Vec::with_capacity(1 + 2 * Hash::LENGTH);
    preimage.push(1);
    preimage.extend_from_slice(left.as_ref());
    preimage.extend_from_slice(right.as_ref());
    Hash::new(preimage)
}
// Validation-fee registries are needed by lightweight data-model consumers
// that do not compile governance instructions or events, but their certificate
// checks must still reproduce the exact governance proposal fingerprint.
// Explicit V1 discriminants bind this private preimage to the matching
// `ProposalKind` wire tags. Each semantic proposal kind also has a distinct
// hash domain, so a future discriminant mistake cannot create a cross-kind
// fingerprint collision. Parity tests below verify the complete encoded bytes
// and fingerprints against the always-compiled Parliament type layer.
#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::validation_fee::ValidationFeePolicyProposalFingerprintEnvelopeV1"
)]
enum ValidationFeePolicyProposalFingerprintEnvelopeV1 {
    #[codec(index = 3)]
    ValidationFeePolicy(ValidationFeePolicyFingerprintPayloadV1),
}
#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::validation_fee::ValidationFeePayoutLifecycleProposalFingerprintEnvelopeV1"
)]
enum ValidationFeePayoutLifecycleProposalFingerprintEnvelopeV1 {
    #[codec(index = 4)]
    ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleFingerprintPayloadV1),
}
#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeePolicyFingerprintPayloadV1")]
struct ValidationFeePolicyFingerprintPayloadV1 {
    proposal_operator: AccountId,
    policy: ValidationFeePolicyV1,
}
#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::validation_fee::ValidationFeePayoutLifecycleFingerprintPayloadV1"
)]
struct ValidationFeePayoutLifecycleFingerprintPayloadV1 {
    proposal_operator: AccountId,
    payout_binding: ValidationFeeTreasuryPayoutBindingV1,
}
fn validation_fee_policy_proposal_fingerprint(
    proposal_operator: &AccountId,
    policy: &ValidationFeePolicyV1,
) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::VALIDATION_FEE_POLICY_V1,
        &ValidationFeePolicyProposalFingerprintEnvelopeV1::ValidationFeePolicy(
            ValidationFeePolicyFingerprintPayloadV1 {
                proposal_operator: proposal_operator.clone(),
                policy: policy.clone(),
            },
        ),
    )
}
fn validation_fee_payout_lifecycle_proposal_fingerprint(
    proposal_operator: &AccountId,
    payout_binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> [u8; 32] {
    crate::governance_fingerprint::fingerprint(
        crate::governance_fingerprint::VALIDATION_FEE_PAYOUT_LIFECYCLE_V1,
        &ValidationFeePayoutLifecycleProposalFingerprintEnvelopeV1::ValidationFeePayoutLifecycle(
            ValidationFeePayoutLifecycleFingerprintPayloadV1 {
                proposal_operator: proposal_operator.clone(),
                payout_binding: payout_binding.clone(),
            },
        ),
    )
}
fn validate_registry_entry_authorization(
    entry: &ValidationFeePolicyRegistryEntryV1,
) -> Result<(), ValidationFeePolicyRegistryError> {
    let policy_version = entry.policy.policy_version;
    if entry.parliament_authorization.invariant_error().is_some() {
        return Err(
            ValidationFeePolicyRegistryError::InvalidParliamentAuthorization { policy_version },
        );
    }
    let fingerprint = validation_fee_policy_proposal_fingerprint(
        &entry.parliament_authorization.proposal_operator,
        &entry.policy,
    );
    if entry.parliament_authorization.proposal_fingerprint != fingerprint {
        return Err(
            ValidationFeePolicyRegistryError::InvalidParliamentAuthorization { policy_version },
        );
    }
    Ok(())
}
/// Parliament-enacted conversion and validator reward configuration.
///
/// Customer pricing is independent of this lifecycle. Conversion returns XOR to
/// reserved custody; consensus allocates rewards from historical service records.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeeTreasuryPayoutBindingV1")]
pub struct ValidationFeeTreasuryPayoutBindingV1 {
    /// Immutable conversion wrapper contract.
    pub contract_address: ContractAddress,
    /// Exact wrapper artifact hash.
    pub code_hash: [u8; 32],
    /// Trigger-only conversion entrypoint.
    pub entrypoint: Name,
    /// Non-signable fee treasury contract subject.
    pub treasury_account_id: AccountId,
    /// SBD fee asset.
    pub ds_asset_id: AssetDefinitionId,
    /// XOR validator reward asset.
    pub xor_asset_id: AssetDefinitionId,
    /// Governed DLMM pool contract.
    pub pool_contract_address: ContractAddress,
    /// Exact governed DLMM pool artifact hash.
    pub pool_code_hash: [u8; 32],
    /// Pool custody receiving SBD and sourcing XOR.
    pub pool_vault_account_id: AccountId,
    /// Protected custody of reserved validator rewards.
    pub reward_pool_account_id: AccountId,
    /// Native signed reference feed reporting XOR per SBD.
    pub reference_feed_id: crate::oracle::FeedId,
    /// Exact governed native feed configuration version.
    pub reference_feed_config_version: u32,
    /// Five independently controlled provider accounts.
    pub reference_provider_accounts: Vec<AccountId>,
    /// Maximum SBD cents converted by one attempt (launch: 1,000).
    pub max_sbd_per_attempt_minor: u64,
    /// Maximum SBD cents converted per Honiara day (launch: 100,000).
    pub max_sbd_per_day_minor: u64,
    /// Minimum milliseconds between successful attempts (launch: 60,000).
    pub min_interval_ms: u64,
    /// Maximum age of original signed source observations (launch: 300,000).
    pub max_source_age_ms: u64,
    /// Maximum execution loss including pool fees, in basis points (launch: 100).
    pub max_slippage_bps: u16,
    /// Nexus lane whose authenticated service roster earns rewards.
    pub validator_lane_id: iroha_model_base::topology::LaneId,
    /// Minimum claim size in exact XOR minor units; smaller balances are retained.
    pub min_reward_claim_xor_minor: u64,
}
impl ValidationFeeTreasuryPayoutBindingV1 {
    /// Hash the exact independently enacted conversion lifecycle.
    ///
    /// # Errors
    /// Returns an error if canonical Norito encoding fails.
    pub fn lifecycle_seal(&self) -> Result<[u8; 32], norito::Error> {
        let encoded = norito::encode_canonical(self)?;
        let mut preimage = Vec::with_capacity(
            VALIDATION_FEE_PAYOUT_LIFECYCLE_SEAL_DOMAIN.len() + 1 + encoded.len(),
        );
        preimage.extend_from_slice(VALIDATION_FEE_PAYOUT_LIFECYCLE_SEAL_DOMAIN);
        preimage.push(0);
        preimage.extend_from_slice(&encoded);
        Ok(*Hash::new(preimage).as_ref())
    }
    /// Return a stable policy invariant violation, if any.
    #[must_use]
    pub fn invariant_error(&self) -> Option<&'static str> {
        if [
            &self.treasury_account_id,
            &self.pool_vault_account_id,
            &self.reward_pool_account_id,
        ]
        .into_iter()
        .chain(self.reference_provider_accounts.iter())
        .any(|account| crate::validation_fee_rewards::validate_reward_identity(account).is_err())
        {
            return Some("payout account identity exceeds the canonical reward byte bound");
        }
        if self.code_hash == [0; 32] || self.pool_code_hash == [0; 32] {
            return Some("conversion wrapper and pool code hashes must be non-zero");
        }
        if self.entrypoint.as_ref() != "autonomous_validation_fee_tick" {
            return Some("conversion entrypoint must be autonomous_validation_fee_tick");
        }
        if self.treasury_account_id == self.pool_vault_account_id
            || self.reward_pool_account_id == self.pool_vault_account_id
            || self.treasury_account_id == self.reward_pool_account_id
        {
            return Some("fee treasury, pool vault and reward custody must differ");
        }
        if self.contract_address.subject_id() != self.treasury_account_id
            || self.pool_contract_address.subject_id() != self.pool_vault_account_id
        {
            return Some("conversion and pool subjects must match their governed vaults");
        }
        if self.ds_asset_id == self.xor_asset_id {
            return Some("SBD and XOR asset definitions must differ");
        }
        if self.reference_feed_config_version == 0 || self.reference_provider_accounts.len() != 5 {
            return Some("conversion requires one versioned feed and five independent providers");
        }
        let mut keys = BTreeSet::new();
        for account in &self.reference_provider_accounts {
            let Some(key) = account.controller().single_signatory() else {
                return Some("reference providers must use single-signature controllers");
            };
            if !keys.insert(key.clone()) {
                return Some("reference providers must have distinct signing keys");
            }
        }
        if self.max_sbd_per_attempt_minor == 0
            || self.max_sbd_per_day_minor < self.max_sbd_per_attempt_minor
            || self.min_interval_ms == 0
            || self.max_source_age_ms == 0
            || self.max_slippage_bps >= 10_000
            || self.min_reward_claim_xor_minor == 0
        {
            return Some(
                "conversion limits, freshness and claim threshold must be positive and bounded",
            );
        }
        None
    }
}
/// Exact-network validation-fee policy.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::validation_fee::ValidationFeePolicyV1")]
pub struct ValidationFeePolicyV1 {
    /// Policy schema version.
    pub schema_version: u16,
    /// Exact genesis-derived network identity bound into the policy.
    pub network_id: NetworkId,
    /// Monotonic policy version.
    #[norito(json = "crate::json_helpers::u64_string")]
    pub policy_version: u64,
    /// Previous policy hash for policy-chain validation.
    #[norito(required)]
    pub previous_policy_hash: Option<[u8; 32]>,
    /// Concrete fee-asset definition charged by this policy.
    pub ds_asset_id: AssetDefinitionId,
    /// Required decimal precision of the charged fee asset.
    pub ds_scale: u8,
    /// Required retail monthly tariff.
    pub retail_schedule: RetailFeeScheduleV1,
    /// Honiara month boundary at which this revision becomes effective.
    pub effective_from_ms: u64,
    /// Public notice timestamp bound by the Parliament proposal.
    pub notice_published_at_ms: u64,
    /// Positive institutional fee charged for each qualifying transfer.
    pub fee: Quantity,
    /// Concrete validator treasury account.
    pub treasury_account_id: AccountId,
    /// Charging mode.
    pub charging_mode: ValidationFeeChargingMode,
    /// Explicit exemption classes recognized by this policy.
    pub exemption_classes: Vec<String>,
    /// Immutable protected custody identity; conversion settings are governed independently.
    pub reward_custody: ValidationFeeRewardCustodyV1,
}
impl ValidationFeePolicyV1 {
    /// Deterministic domain-separated policy hash.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the policy cannot be serialized.
    pub fn policy_hash(&self) -> Result<[u8; 32], norito::Error> {
        let bytes = norito::encode_canonical(self)?;
        let mut payload =
            Vec::with_capacity(VALIDATION_FEE_POLICY_HASH_DOMAIN.len() + 1 + bytes.len());
        payload.extend_from_slice(VALIDATION_FEE_POLICY_HASH_DOMAIN);
        payload.push(0);
        payload.extend_from_slice(&bytes);
        Ok(*Hash::new(payload.as_slice()).as_ref())
    }
    /// Return policy invariant violations, if any.
    #[must_use]
    pub fn policy_invariant_error(&self) -> Option<&'static str> {
        if self.schema_version != VALIDATION_FEE_POLICY_SCHEMA_VERSION {
            return Some("unsupported validation-fee policy schema version");
        }
        if self.network_id.as_bytes() == &[0; 32] {
            return Some("validation-fee policy network id must be non-zero");
        }
        if self.policy_version == 0 {
            return Some("validation-fee policy version must be positive");
        }
        if self.policy_version == 1 && self.previous_policy_hash.is_some() {
            return Some("initial validation-fee policy must not carry a previous policy hash");
        }
        if self.policy_version > 1 && self.previous_policy_hash.is_none() {
            return Some("non-initial validation-fee policy must carry a previous policy hash");
        }
        if self.ds_scale != VALIDATION_FEE_DS_SCALE {
            return Some("validation-fee policy asset scale must be 2");
        }
        if self.fee.is_zero() || self.fee.scale() > u32::from(self.ds_scale) {
            return Some("institutional payment fee must be positive exact minor units");
        }
        if self.retail_schedule.validate().is_err() {
            return Some("invalid retail monthly tariff");
        }
        if validate_retail_activation(self.notice_published_at_ms, self.effective_from_ms).is_err()
        {
            return Some("retail fee policy requires a month boundary after thirty days notice");
        }
        let mut exemption_classes = BTreeSet::new();
        for class in &self.exemption_classes {
            if class != VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS
                || !exemption_classes.insert(class)
            {
                return Some(
                    "validation-fee policy exemption classes must be unique approved release classes: TREASURY_PAYOUT",
                );
            }
        }
        if !self
            .exemption_classes
            .iter()
            .any(|class| class == VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS)
        {
            return Some("retail policy requires native governed reward conversion exemption");
        }
        if let Some(reason) = self.reward_custody.invariant_error() {
            return Some(reason);
        }
        if self.reward_custody.treasury_account_id != self.treasury_account_id
            || self.reward_custody.ds_asset_id != self.ds_asset_id
        {
            return Some("retail fee asset and treasury must match immutable reward custody");
        }
        None
    }
    /// Return initial policy invariant violations, if any.
    #[must_use]
    pub fn initial_policy_invariant_error(&self) -> Option<&'static str> {
        self.policy_invariant_error()
    }
}
/// Return the canonical initial validation-fee amount.
#[must_use]
pub fn initial_validation_fee_amount() -> Quantity {
    VALIDATION_FEE_INITIAL_AMOUNT
        .parse()
        .expect("hard-coded validation-fee amount is canonical")
}
#[cfg(test)]
mod parliament_tests {
    use super::*;
    use crate::parliament_types::{
        BallotAttemptId, BeaconPulseId, BeaconSessionId, BodyElectionAttemptId, BodyInstanceId,
        GovernanceAttemptId, GovernanceCertificateV1, GovernanceExpectedHeadPresentV1,
        GovernanceExpectedHeadV1, ParliamentAggregateOutcomeV1, ParliamentAggregateTallyV1,
        ParliamentBallotCertificateBindingV1, ParliamentBody, ParliamentBodyCertificateBindingV1,
        ProposalContentId, ProposalKind, RiskTierV1, SortitionRequestV1, TleKeySessionId,
        TleSessionId, ValidationFeePayoutLifecycleProposal, ValidationFeePolicyProposal,
        parliament_ballot_result_root_v1,
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use std::str::FromStr as _;
    const TEST_AUTHORIZATION_STRIDE: u64 = 10_000;

    fn account(seed: u8) -> AccountId {
        let key_pair =
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("key pair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn fee_asset() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("fees", "validation").expect("domain id"),
            Name::from_str("fee").expect("asset name"),
        )
    }
    fn xor_asset() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("xor", "validation").expect("domain id"),
            Name::from_str("xor").expect("asset name"),
        )
    }
    fn payout_binding() -> ValidationFeeTreasuryPayoutBindingV1 {
        let contract_address: ContractAddress =
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .parse()
                .expect("contract address");
        let pool_contract_address = ContractAddress::derive(
            &NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                Hash::prehashed([7; 32]),
            )),
            &account(2),
            43,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("pool address");
        ValidationFeeTreasuryPayoutBindingV1 {
            treasury_account_id: contract_address.subject_id(),
            contract_address,
            code_hash: [0x11; 32],
            entrypoint: Name::from_str("autonomous_validation_fee_tick").expect("entrypoint"),
            ds_asset_id: fee_asset(),
            xor_asset_id: xor_asset(),
            pool_vault_account_id: pool_contract_address.subject_id(),
            pool_contract_address,
            pool_code_hash: [0x22; 32],
            reward_pool_account_id: account(8),
            reference_feed_id: "xor_per_sbd".parse().expect("reference feed"),
            reference_feed_config_version: 1,
            reference_provider_accounts: (10..15).map(account).collect(),
            max_sbd_per_attempt_minor: 1000,
            max_sbd_per_day_minor: 100_000,
            min_interval_ms: 60000,
            max_source_age_ms: 300_000,
            max_slippage_bps: 100,
            validator_lane_id: iroha_model_base::topology::LaneId::new(0),
            min_reward_claim_xor_minor: 1,
        }
    }
    fn proposal_operator() -> AccountId {
        account(7)
    }
    fn policy_jury_body(
        governance_attempt_id: GovernanceAttemptId,
        marker: u8,
        base: u64,
    ) -> ParliamentBodyCertificateBindingV1 {
        let root = |offset: u8| [marker.wrapping_add(offset); 32];
        let election_attempt_sequence = 0;
        let election_attempt_id = BodyElectionAttemptId::derive_v1(
            governance_attempt_id,
            ParliamentBody::PolicyJury,
            election_attempt_sequence,
        );
        let beacon_session_id = BeaconSessionId::new(root(2));
        let sortition_request = SortitionRequestV1::try_new_canonical(
            governance_attempt_id,
            election_attempt_id,
            ParliamentBody::PolicyJury,
            root(1),
            3,
            3,
            base + 1,
            base + 2,
            beacon_session_id,
            None,
        )
        .expect("canonical validation-fee Policy Jury request");
        let roster_root = root(4);
        let body_instance_id = BodyInstanceId::derive_v1(election_attempt_id, roster_root);
        let ballot_attempt_sequence = 0;
        let ballot_attempt_id =
            BallotAttemptId::derive_v1(body_instance_id, ballot_attempt_sequence);
        let release_beacon_session_id = BeaconSessionId::new(root(7));
        let tle_key_session_id = TleKeySessionId::new(root(8));
        let release_height = base + 12;
        let tle_session_id = TleSessionId::derive_v1(
            ballot_attempt_id,
            tle_key_session_id,
            release_beacon_session_id,
            release_height,
        );
        let opening_root = root(16);
        let tally = ParliamentAggregateTallyV1 {
            original_seats: 3,
            accepted_ballots: 3,
            aye: 2,
            nay: 1,
            abstain: 0,
        };
        let outcome = ParliamentAggregateOutcomeV1::Approved;
        let result_height = base + 13;
        let result_root = parliament_ballot_result_root_v1(
            governance_attempt_id,
            body_instance_id,
            ballot_attempt_id,
            opening_root,
            tally,
            outcome,
            result_height,
        );
        ParliamentBodyCertificateBindingV1 {
            body_instance_id,
            election_attempt_id,
            election_attempt_sequence,
            sortition_request_id: sortition_request.id,
            sortition_request,
            body: ParliamentBody::PolicyJury,
            original_seats: tally.original_seats,
            beacon_session_id,
            beacon_pulse_id: BeaconPulseId::new(root(3)),
            roster_root,
            assignment_root: root(5),
            result_root,
            result_height,
            public_finding: None,
            ballot: Some(ParliamentBallotCertificateBindingV1 {
                ballot_attempt_id,
                ballot_attempt_sequence,
                tle_session_id,
                tle_key_session_id,
                registration_root: root(9),
                dropout_root: root(10),
                survivor_root: root(11),
                corpus_root: root(12),
                no_recovery_root: root(13),
                timed_commitment_root: root(14),
                release_beacon_session_id,
                registered_at_height: base + 3,
                registration_close_height: base + 7,
                survivor_freeze_height: base + 10,
                commitment_close_height: base + 11,
                registration_closed_at_height: base + 7,
                survivors_frozen_at_height: base + 10,
                commitment_closed_at_height: base + 11,
                max_ballot_retries: 3,
                max_corpus_entries: 3,
                release_height,
                opening_deadline_height: result_height,
                release_pulse_id: BeaconPulseId::new(root(15)),
                opening_height: release_height,
                opening_root,
                tally,
                outcome,
            }),
        }
    }
    fn authorization(
        proposal_fingerprint: [u8; 32],
        marker: u8,
    ) -> ValidationFeeParliamentAuthorizationV1 {
        let root = |offset: u8| [marker.wrapping_add(offset); 32];
        let base = u64::from(marker)
            .checked_mul(TEST_AUTHORIZATION_STRIDE)
            .expect("test authorization base height");
        let proposal_content_id = ProposalContentId::new(proposal_fingerprint);
        let governance_attempt_sequence = 0;
        let governance_attempt_id =
            GovernanceAttemptId::derive_v1(proposal_content_id, governance_attempt_sequence);
        let body = policy_jury_body(governance_attempt_id, marker, base);
        let certified_at_height = body.result_height;
        let enact_at_height = base + 15;
        let governance_certificate = GovernanceCertificateV1 {
            proposal_content_id,
            governance_attempt_id,
            governance_attempt_sequence,
            risk_tier: RiskTierV1::Standard,
            body_bindings: vec![body],
            policy_version: 1,
            effect_preimage_hash: root(19),
            expected_head: GovernanceExpectedHeadV1::Present(GovernanceExpectedHeadPresentV1 {
                subject_id: root(17),
                version: 1,
                head_root: root(18),
            }),
            certified_at_height,
            enact_at_height,
        };
        let governance_certificate_id = GovernanceCertificateId::derive_v1(&governance_certificate);
        ValidationFeeParliamentAuthorizationV1 {
            proposal_operator: proposal_operator(),
            proposal_fingerprint,
            governance_certificate_id,
            governance_certificate,
            enacted_at_height: enact_at_height,
        }
    }
    fn policy(version: u64, previous_policy_hash: Option<[u8; 32]>) -> ValidationFeePolicyV1 {
        let binding = payout_binding();
        ValidationFeePolicyV1 {
            retail_schedule: RetailFeeScheduleV1::default(),
            effective_from_ms: 1_793_451_600_000 + version.saturating_sub(1) * 30 * 86_400_000,
            notice_published_at_ms: 1_790_859_600_000,
            schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                Hash::prehashed([7; 32]),
            )),
            policy_version: version,
            previous_policy_hash,
            ds_asset_id: fee_asset(),
            ds_scale: VALIDATION_FEE_DS_SCALE,
            fee: initial_validation_fee_amount(),
            treasury_account_id: binding.treasury_account_id.clone(),
            charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,
            exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.to_owned()],
            reward_custody: binding.custody(),
        }
    }
    fn entry(policy: ValidationFeePolicyV1, marker: u8) -> ValidationFeePolicyRegistryEntryV1 {
        let proposal_id = validation_fee_policy_proposal_fingerprint(&proposal_operator(), &policy);
        ValidationFeePolicyRegistryEntryV1::from_enactment(
            policy,
            authorization(proposal_id, marker),
        )
        .expect("policy hash")
    }
    fn payout_registry() -> ValidationFeePayoutPolicyRegistryV1 {
        let binding = payout_binding();
        let proposal_id =
            validation_fee_payout_lifecycle_proposal_fingerprint(&proposal_operator(), &binding);
        ValidationFeePayoutPolicyRegistryV1 {
            entries: vec![ValidationFeePayoutPolicyEntryV1 {
                revision: 1,
                proposal_id,
                lifecycle_seal: binding.lifecycle_seal().expect("seal"),
                payout_binding: binding,
                parliament_authorization: authorization(proposal_id, 1),
            }],
        }
    }
    #[test]
    fn validation_fee_identity_hashes_ignore_and_restore_ambient_flags() {
        let policy = policy(1, None);
        let binding = payout_binding();
        let registry = ValidationFeePolicyRegistryV1 {
            payout_policies: payout_registry(),
            registered_policies: vec![entry(policy.clone(), 1)],
        };
        let baseline = (
            policy.policy_hash().expect("policy hash"),
            binding.lifecycle_seal().expect("lifecycle seal"),
            registry.snapshot_hash().expect("registry snapshot hash"),
        );
        let canonical_policy =
            norito::encode_canonical(&policy).expect("encode canonical validation-fee policy");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate_policy = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&policy).expect("encode alternate-layout validation-fee policy")
        };
        assert_ne!(
            alternate_policy, canonical_policy,
            "fixture must exercise a distinct advertised Norito layout"
        );
        let ambient = {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            let before =
                norito::to_bytes(&policy).expect("encode policy under caller ambient flags");
            let observed = (
                policy.policy_hash().expect("ambient policy hash"),
                binding.lifecycle_seal().expect("ambient lifecycle seal"),
                registry.snapshot_hash().expect("ambient registry hash"),
            );
            let after =
                norito::to_bytes(&policy).expect("re-encode policy under caller ambient flags");
            assert_eq!(
                before, after,
                "canonical identity helpers must restore the caller's ambient layout"
            );
            observed
        };
        assert_eq!(ambient, baseline);
    }
    #[test]
    fn decimal_string_validation_fee_u64_fields_keep_the_full_domain() {
        let mut policy = policy(1, None);
        policy.policy_version = u64::MAX;
        let proposal = ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
            proposal_operator: proposal_operator(),
            policy,
        });
        assert_eq!(
            proposal.first_release_exact_json_u64_invariant_error(),
            None,
            "decimal-string fields do not lose precision in JavaScript JSON runtimes"
        );
    }
    #[test]
    fn validation_fee_policy_roundtrips_canonical_network_id_wire() {
        let policy = policy(1, None);
        let canonical =
            norito::encode_canonical(&policy).expect("encode canonical validation-fee policy");
        let decoded: ValidationFeePolicyV1 =
            norito::decode_canonical(&canonical).expect("decode canonical validation-fee policy");
        assert_eq!(decoded, policy);
        assert_eq!(
            norito::encode_canonical(&decoded).expect("re-encode validation-fee policy"),
            canonical,
            "the mandatory typed NetworkId must have one canonical Norito representation"
        );
        let json = norito::json::to_json(&policy).expect("encode validation-fee policy JSON");
        assert!(json.contains("\"network_id\""));
        assert!(!json.contains("\"chain_id\""));
        assert!(!json.contains("\"genesis_hash\""));
        let decoded_json: ValidationFeePolicyV1 =
            norito::json::from_json(&json).expect("decode validation-fee policy JSON");
        assert_eq!(decoded_json, policy);
        let mut legacy = norito::json::to_value(&policy).expect("encode legacy mutation source");
        let legacy = legacy
            .as_object_mut()
            .expect("validation-fee policy JSON object");
        legacy.remove("network_id");
        legacy.insert("chain_id".into(), norito::json::Value::from("same-label"));
        legacy.insert(
            "genesis_hash".into(),
            norito::json::Value::from(hex::encode([7; 32])),
        );
        let legacy = norito::json::to_json(&legacy).expect("encode legacy identity fields");
        assert!(
            norito::json::from_json::<ValidationFeePolicyV1>(&legacy).is_err(),
            "the first-release decoder must not accept dual ChainId + genesis_hash identity"
        );
    }
    #[test]
    fn policy_rejects_caller_supplied_activation_height() {
        let mut value = norito::json::to_value(&policy(1, None)).unwrap();
        value.as_object_mut().unwrap().insert(
            "effective_from_height".into(),
            norito::json::Value::from("999999999"),
        );
        assert!(norito::json::from_value::<ValidationFeePolicyV1>(value).is_err());
    }
    #[test]
    fn finalized_policy_waits_for_calendar_boundary_without_another_height_gate() {
        let first = entry(policy(1, None), 1);
        let height = first.parliament_authorization.enacted_at_height;
        let activation = first.policy.effective_from_ms;
        let registry = ValidationFeePolicyRegistryV1 {
            payout_policies: payout_registry(),
            registered_policies: vec![first],
        };
        assert!(registry.effective_entry_at(height, activation).is_none());
        assert!(
            registry
                .effective_entry_at(height + 1, activation - 1)
                .is_none()
        );
        assert!(
            registry
                .effective_entry_at(height + 1, activation)
                .is_some()
        );
        assert!(
            registry
                .effective_entry_at(height + 100_000, activation - 1)
                .is_none()
        );
    }
    #[test]
    fn validation_fee_policy_json_requires_explicit_optional_and_list_fields() {
        let policy = policy(1, None);
        for field in [
            "previous_policy_hash",
            "exemption_classes",
            "reward_custody",
        ] {
            let mut value =
                norito::json::to_value(&policy).expect("encode validation-fee policy JSON value");
            value
                .as_object_mut()
                .expect("validation-fee policy JSON object")
                .remove(field);
            let value =
                norito::json::to_json(&value).expect("encode incomplete validation-fee policy");
            assert!(
                norito::json::from_json::<ValidationFeePolicyV1>(&value).is_err(),
                "missing `{field}` must be rejected"
            );
        }
    }
    #[test]
    fn validation_fee_nested_json_types_reject_unknown_fields() {
        let mut binding = norito::json::to_value(&payout_binding()).expect("binding JSON");
        binding
            .as_object_mut()
            .expect("binding object")
            .insert("recipients".into(), norito::json::Value::from("obsolete"));
        let binding = norito::json::to_json(&binding).expect("binding JSON");
        assert!(norito::json::from_json::<ValidationFeeTreasuryPayoutBindingV1>(&binding).is_err());

        let mut charging_mode =
            norito::json::to_value(&ValidationFeeChargingMode::RetailMonthlyAllowance)
                .expect("encode charging-mode JSON value");
        charging_mode
            .as_object_mut()
            .expect("charging-mode JSON object")
            .insert(
                "legacy_mode".into(),
                norito::json::Value::from("PER_TRANSFER"),
            );
        let charging_mode =
            norito::json::to_json(&charging_mode).expect("encode charging-mode unknown field");
        assert!(norito::json::from_json::<ValidationFeeChargingMode>(&charging_mode).is_err());
    }
    #[test]
    fn payout_binding_roundtrips_canonical_ds_fields() {
        let binding = payout_binding();
        let canonical =
            norito::encode_canonical(&binding).expect("encode canonical payout binding");
        let decoded: ValidationFeeTreasuryPayoutBindingV1 =
            norito::decode_canonical(&canonical).expect("decode canonical payout binding");
        assert_eq!(decoded, binding);
        assert_eq!(
            norito::encode_canonical(&decoded).expect("re-encode canonical payout binding"),
            canonical,
            "the payout binding must have one canonical Norito representation"
        );

        let json = norito::json::to_json(&binding).expect("encode payout binding JSON");
        assert!(json.contains(r#""ds_asset_id""#));
        assert!(json.contains(r#""max_sbd_per_attempt_minor""#));
        assert!(!json.contains(r#""sbd_asset_id""#));
        assert!(!json.contains(r#""batch_sbd""#));
        let decoded_json: ValidationFeeTreasuryPayoutBindingV1 =
            norito::json::from_json(&json).expect("decode payout binding JSON");
        assert_eq!(decoded_json, binding);

        let mut retired = norito::json::to_value(&binding)
            .expect("encode retired payout binding mutation source");
        let retired = retired.as_object_mut().expect("payout binding JSON object");
        let ds_asset_id = retired.get("ds_asset_id").expect("DS asset field").clone();
        retired.insert("sbd_asset_id".into(), ds_asset_id);
        let retired = norito::json::to_json(&retired).expect("encode retired payout binding JSON");
        assert!(
            norito::json::from_json::<ValidationFeeTreasuryPayoutBindingV1>(&retired).is_err(),
            "the first-release decoder must not preserve the retired SBD field name"
        );
    }
    #[test]
    fn lightweight_validation_fee_fingerprints_match_governance_proposal_bytes() {
        let payout_binding = payout_binding();
        let proposal_operator = proposal_operator();
        let lifecycle_governance =
            ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
                proposal_operator: proposal_operator.clone(),
                payout_binding: payout_binding.clone(),
            });
        let lifecycle_lightweight =
            ValidationFeePayoutLifecycleProposalFingerprintEnvelopeV1::ValidationFeePayoutLifecycle(
                ValidationFeePayoutLifecycleFingerprintPayloadV1 {
                    proposal_operator: proposal_operator.clone(),
                    payout_binding: payout_binding.clone(),
                },
            );
        assert_eq!(
            lifecycle_lightweight.encode(),
            lifecycle_governance.encode()
        );
        assert_eq!(
            validation_fee_payout_lifecycle_proposal_fingerprint(
                &proposal_operator,
                &payout_binding,
            ),
            lifecycle_governance.fingerprint()
        );
        let governed_policy = policy(1, None);
        let policy_governance = ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
            proposal_operator: proposal_operator.clone(),
            policy: governed_policy.clone(),
        });
        let policy_lightweight =
            ValidationFeePolicyProposalFingerprintEnvelopeV1::ValidationFeePolicy(
                ValidationFeePolicyFingerprintPayloadV1 {
                    proposal_operator: proposal_operator.clone(),
                    policy: governed_policy.clone(),
                },
            );
        assert_eq!(policy_lightweight.encode(), policy_governance.encode());
        assert_eq!(
            validation_fee_policy_proposal_fingerprint(&proposal_operator, &governed_policy),
            policy_governance.fingerprint()
        );
    }
    #[test]
    fn lightweight_validation_fee_preimages_use_frozen_v1_tags() {
        let policy = ValidationFeePolicyProposalFingerprintEnvelopeV1::ValidationFeePolicy(
            ValidationFeePolicyFingerprintPayloadV1 {
                proposal_operator: proposal_operator(),
                policy: policy(1, None),
            },
        );
        let lifecycle =
            ValidationFeePayoutLifecycleProposalFingerprintEnvelopeV1::ValidationFeePayoutLifecycle(
                ValidationFeePayoutLifecycleFingerprintPayloadV1 {
                    proposal_operator: proposal_operator(),
                    payout_binding: payout_binding(),
                },
            );
        assert_eq!(
            policy.encode().get(..4),
            Some(3_u32.to_le_bytes().as_slice())
        );
        assert_eq!(
            lifecycle.encode().get(..4),
            Some(4_u32.to_le_bytes().as_slice())
        );
    }
    #[test]
    fn registry_retains_history_and_selects_scheduled_policy() {
        let first = policy(1, None);
        let first_entry = entry(first, 1);
        let second = policy(2, Some(first_entry.policy_hash));
        let first_effective_height = first_entry.parliament_authorization.enacted_at_height + 1;
        let second_entry = entry(second, 2);
        let second_effective_height = second_entry.parliament_authorization.enacted_at_height + 1;
        let registry = ValidationFeePolicyRegistryV1 {
            payout_policies: payout_registry(),
            registered_policies: vec![first_entry, second_entry],
        };
        registry.validate().expect("valid policy chain");
        assert!(
            registry
                .scheduled_entry_at_height(first_effective_height - 1)
                .is_none()
        );
        assert_eq!(
            registry
                .effective_entry_at(first_effective_height, 1_793_451_600_000)
                .expect("first policy")
                .policy
                .policy_version,
            1
        );
        assert_eq!(
            registry
                .effective_entry_at(second_effective_height, 1_796_043_600_000)
                .expect("successor policy")
                .policy
                .policy_version,
            2
        );
    }
    #[test]
    fn registry_rejects_successor_from_another_exact_network() {
        let first = policy(1, None);
        let first_entry = entry(first, 1);
        let second = policy(2, Some(first_entry.policy_hash));
        let mut registry = ValidationFeePolicyRegistryV1 {
            payout_policies: payout_registry(),
            registered_policies: vec![first_entry, entry(second, 2)],
        };
        registry.registered_policies[1].policy.network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::prehashed([9; 32])),
        );
        assert!(matches!(
            registry.validate(),
            Err(ValidationFeePolicyRegistryError::NetworkIdentityChanged { policy_version: 2 })
        ));
    }
    #[test]
    fn registry_rejects_stale_predecessor() {
        let first = entry(policy(1, None), 1);
        let second = policy(2, Some([9; 32]));
        let registry = ValidationFeePolicyRegistryV1 {
            payout_policies: payout_registry(),
            registered_policies: vec![first, entry(second, 2)],
        };
        assert!(matches!(
            registry.validate(),
            Err(ValidationFeePolicyRegistryError::BrokenPreviousPolicyHash { policy_version: 2 })
        ));
    }
    #[test]
    fn parliament_can_change_positive_payment_rates() {
        let mut value = policy(1, None);
        for fee in ["0.01", "0.10", "0.20", "1"] {
            value.fee = fee.parse().expect("quantity");
            assert_eq!(value.policy_invariant_error(), None);
        }
        value.fee = Quantity::zero();
        assert!(value.policy_invariant_error().is_some());
    }
    #[test]
    fn retired_and_live_parameter_ids_are_reserved() {
        for raw in [
            RETIRED_VALIDATION_FEE_GOVERNANCE_KEYSET_PARAMETER_ID,
            RETIRED_VALIDATION_FEE_POLICY_PARAMETER_ID,
            ValidationFeePolicyRegistryV1::PARAMETER_ID_STR,
        ] {
            let id: CustomParameterId = raw.parse().expect("parameter id");
            assert!(is_reserved_validation_fee_parameter_id(&id));
        }
    }
    #[test]
    fn payout_binding_rejects_unsafe_conversion_configuration() {
        let binding = payout_binding();
        assert_eq!(binding.invariant_error(), None);
        for malformed in [
            {
                let mut value = binding.clone();
                value.max_sbd_per_attempt_minor = 0;
                value
            },
            {
                let mut value = binding.clone();
                value.max_sbd_per_day_minor = 999;
                value
            },
            {
                let mut value = binding.clone();
                value.max_source_age_ms = 0;
                value
            },
            {
                let mut value = binding.clone();
                value.max_slippage_bps = 10000;
                value
            },
            {
                let mut value = binding.clone();
                value.pool_code_hash = [0; 32];
                value
            },
            {
                let mut value = binding.clone();
                value.reference_provider_accounts[1] = value.reference_provider_accounts[0].clone();
                value
            },
            {
                let mut value = binding.clone();
                value.reference_provider_accounts.pop();
                value
            },
        ] {
            assert!(
                malformed.invariant_error().is_some(),
                "malformed payout binding must be rejected"
            );
        }
    }
    #[test]
    fn payout_binding_rejects_oversized_reward_custody_and_provider_identity() {
        use crate::account::{MultisigMember, MultisigPolicy};
        let mut binding = payout_binding();
        assert_eq!(binding.invariant_error(), None);
        let oversized = AccountId::new_multisig(
            MultisigPolicy::new(
                1,
                (0u8..16)
                    .map(|seed| {
                        MultisigMember::new(
                            iroha_crypto::KeyPair::from_seed(
                                vec![seed; 32],
                                iroha_crypto::Algorithm::Ed25519,
                            )
                            .public_key()
                            .clone(),
                            1,
                        )
                        .unwrap()
                    })
                    .collect(),
            )
            .unwrap(),
        );
        binding.reward_pool_account_id = oversized.clone();
        assert_eq!(
            binding.invariant_error(),
            Some("payout account identity exceeds the canonical reward byte bound")
        );
        binding = payout_binding();
        binding.reference_provider_accounts[0] = oversized;
        assert_eq!(
            binding.invariant_error(),
            Some("payout account identity exceeds the canonical reward byte bound")
        );
        assert_eq!(payout_binding().invariant_error(), None);
    }
    #[test]
    fn complete_registry_byte_limit_reserves_automatic_reward_evidence_capacity() {
        let mut registry = ValidationFeePolicyRegistryV1 {
            registered_policies: Vec::new(),
            payout_policies: payout_registry(),
        };
        registry.validate().unwrap();
        let retained = registry.payout_policies.entries[0].clone();
        while norito::to_bytes(&registry).unwrap().len() <= MAX_VALIDATION_FEE_REGISTRY_BYTES {
            let length = registry.payout_policies.entries.len();
            registry
                .payout_policies
                .entries
                .extend(vec![retained.clone(); length]);
        }
        assert!(norito::to_bytes(&registry).unwrap().len() > MAX_VALIDATION_FEE_REGISTRY_BYTES);
        assert_eq!(
            registry.validate(),
            Err(ValidationFeePolicyRegistryError::RegistryByteLimit)
        );
    }
    #[test]
    fn lifecycle_seal_and_fingerprint_bind_exact_binding_and_operator() {
        let binding = payout_binding();
        let proposal_operator = proposal_operator();
        let seal = binding.lifecycle_seal().expect("lifecycle seal");
        assert_ne!(seal, [0; 32]);
        let proposal_fingerprint =
            validation_fee_payout_lifecycle_proposal_fingerprint(&proposal_operator, &binding);
        let mut changed_binding = binding.clone();
        changed_binding.code_hash[0] ^= 1;
        let changed_seal = changed_binding
            .lifecycle_seal()
            .expect("changed lifecycle seal");
        let changed_fingerprint = validation_fee_payout_lifecycle_proposal_fingerprint(
            &proposal_operator,
            &changed_binding,
        );
        assert_ne!(seal, changed_seal);
        assert_ne!(proposal_fingerprint, changed_fingerprint);
        assert_ne!(
            proposal_fingerprint,
            validation_fee_payout_lifecycle_proposal_fingerprint(&account(8), &binding),
            "proposal operator must be part of the exact typed preimage"
        );
    }
    #[test]
    fn historical_registry_retains_both_enactment_prefixes_and_payout_only_bootstrap() {
        let payouts = payout_registry();
        let first_payout_height = payouts.entries[0]
            .parliament_authorization
            .enacted_at_height;
        let pricing = entry(policy(1, None), 2);
        let pricing_height = pricing.parliament_authorization.enacted_at_height;
        assert!(first_payout_height < pricing_height);
        let original = ValidationFeePolicyRegistryV1 {
            payout_policies: payouts,
            registered_policies: vec![pricing.clone()],
        };
        let mut complete = original.clone();
        let mut revised = complete.payout_policies.entries[0].clone();
        revised.revision = 2;
        revised.payout_binding.max_sbd_per_attempt_minor += 1;
        revised.proposal_id = validation_fee_payout_lifecycle_proposal_fingerprint(
            &proposal_operator(),
            &revised.payout_binding,
        );
        revised.lifecycle_seal = revised.payout_binding.lifecycle_seal().unwrap();
        revised.parliament_authorization = authorization(revised.proposal_id, 3);
        let conversion_height = revised.parliament_authorization.enacted_at_height;
        complete.payout_policies.entries.push(revised);
        let next_pricing = entry(policy(2, Some(pricing.policy_hash)), 4);
        let next_pricing_height = next_pricing.parliament_authorization.enacted_at_height;
        complete.registered_policies.push(next_pricing);
        complete
            .validate()
            .expect("complete independent mathematical Parliament fixtures");
        assert_eq!(
            complete
                .clone()
                .retained_at_height(first_payout_height - 1)
                .unwrap(),
            None
        );
        let bootstrap = complete
            .clone()
            .retained_at_height(first_payout_height)
            .unwrap()
            .unwrap();
        assert!(bootstrap.registered_policies.is_empty());
        assert_eq!(bootstrap.payout_policies.entries.len(), 1);
        let bootstrap_commitment = ValidationFeePolicySnapshotCommitmentV1::from_registry(
            first_payout_height,
            1_793_451_600_000,
            Some(&bootstrap),
        );
        assert!(
            matches!(
                bootstrap_commitment.status,
                ValidationFeePolicySnapshotStatusV1::Available(_)
            ),
            "configured payout-only history is not Unconfigured"
        );
        let historical = complete
            .clone()
            .retained_at_height(pricing_height)
            .unwrap()
            .unwrap();
        assert_eq!(historical, original);
        let witness = ValidationFeePolicySnapshotCommitmentV1::from_registry(
            pricing_height,
            1_793_451_600_000,
            Some(&original),
        );
        assert_eq!(
            ValidationFeePolicySnapshotCommitmentV1::from_registry(
                pricing_height,
                1_793_451_600_000,
                Some(&historical)
            ),
            witness
        );
        assert_ne!(
            ValidationFeePolicySnapshotCommitmentV1::from_registry(
                pricing_height,
                1_793_451_600_000,
                Some(&complete)
            ),
            witness,
            "later independently enacted conversion changes the committed registry root"
        );
        let revised_only = complete
            .clone()
            .retained_at_height(conversion_height)
            .unwrap()
            .unwrap();
        assert_eq!(revised_only.registered_policies.len(), 1);
        assert_eq!(revised_only.payout_policies.entries.len(), 2);
        assert_eq!(
            complete
                .clone()
                .retained_at_height(next_pricing_height)
                .unwrap(),
            Some(complete.clone())
        );
        let mut invalid_future = complete;
        invalid_future.payout_policies.entries[1].lifecycle_seal[0] ^= 1;
        assert!(
            invalid_future.retained_at_height(pricing_height).is_err(),
            "filtering must not hide an invalid offered later authority"
        );
    }
    #[test]
    fn independent_conversion_registry_requires_exact_authority_and_stable_custody() {
        let pricing = entry(policy(1, None), 1);
        let mut registry = ValidationFeePolicyRegistryV1 {
            payout_policies: payout_registry(),
            registered_policies: vec![pricing.clone()],
        };
        registry.validate().expect("independent enacted policies");
        let old_hash = pricing.policy_hash;
        let mut revised = registry.payout_policies.entries[0].clone();
        revised.revision = 2;
        revised.payout_binding.max_sbd_per_attempt_minor += 1;
        revised.proposal_id = validation_fee_payout_lifecycle_proposal_fingerprint(
            &proposal_operator(),
            &revised.payout_binding,
        );
        revised.lifecycle_seal = revised.payout_binding.lifecycle_seal().expect("seal");
        revised.parliament_authorization = authorization(revised.proposal_id, 2);
        let activation = revised.parliament_authorization.enacted_at_height;
        registry.payout_policies.entries.push(revised.clone());
        registry
            .validate()
            .expect("conversion update does not change pricing");
        assert_eq!(registry.registered_policies[0].policy_hash, old_hash);
        assert_eq!(
            registry
                .payout_policies
                .effective_entry_at_height(activation)
                .expect("previous")
                .revision,
            1
        );
        assert_eq!(
            registry
                .payout_policies
                .effective_entry_at_height(activation + 1)
                .expect("new")
                .revision,
            2
        );
        let mut changed_custody = registry.clone();
        changed_custody.registered_policies[0]
            .policy
            .reward_custody
            .reward_pool_account_id = account(9);
        assert!(changed_custody.validate().is_err());
        let mut bad_seal = registry.clone();
        bad_seal.payout_policies.entries[1].lifecycle_seal[0] ^= 1;
        assert!(bad_seal.validate().is_err());
        let mut bad_authority = registry.clone();
        bad_authority.payout_policies.entries[1]
            .parliament_authorization
            .proposal_operator = account(8);
        assert!(bad_authority.validate().is_err());
        let mut no_pricing = registry;
        no_pricing.registered_policies.clear();
        no_pricing.validate().expect("payout-only bootstrap");
        assert!(
            no_pricing
                .effective_entry_at(activation + 1, u64::MAX)
                .is_none()
        );
    }
    #[test]
    fn parliament_authorization_requires_exact_certificate_identity_and_due_height() {
        let valid = authorization([0x12; 32], 12);
        assert_eq!(valid.invariant_error(), None);
        assert_eq!(
            valid.governance_certificate.proposal_content_id,
            ProposalContentId::new(valid.proposal_fingerprint)
        );
        let encoded = norito::to_bytes(&valid).expect("encode certificate authorization");
        let decoded = norito::decode_from_bytes::<ValidationFeeParliamentAuthorizationV1>(&encoded)
            .expect("decode certificate authorization");
        assert_eq!(decoded, valid);
        assert_eq!(decoded.invariant_error(), None);
        let mut wrong_certificate_id = valid.clone();
        wrong_certificate_id.governance_certificate_id = GovernanceCertificateId::new([0xAA; 32]);
        assert_eq!(
            wrong_certificate_id.invariant_error(),
            Some(
                "validation-fee Parliament certificate identifier is not the canonical certificate hash"
            )
        );
        let mut wrong_proposal = authorization([0x13; 32], 13);
        wrong_proposal.proposal_fingerprint = valid.proposal_fingerprint;
        assert_eq!(
            wrong_proposal.invariant_error(),
            Some("validation-fee Parliament certificate targets a different proposal fingerprint")
        );
        let mut wrong_due_height = valid.clone();
        wrong_due_height.enacted_at_height = wrong_due_height.enacted_at_height.saturating_add(1);
        assert_eq!(
            wrong_due_height.invariant_error(),
            Some(
                "validation-fee enactment height must equal the Parliament certificate due height"
            )
        );
        let mut invalid_certificate = valid;
        invalid_certificate.governance_certificate.body_bindings[0].result_root = [0; 32];
        assert_eq!(
            invalid_certificate.invariant_error(),
            Some("validation-fee Parliament certificate is structurally invalid")
        );
    }
}
#[cfg(test)]
mod snapshot_tests {
    use super::*;
    fn witness_root(proof: &ValidationFeePolicyWitnessProofV1) -> Hash {
        let path = Hash::new(&proof.key);
        let value_hash = Hash::new(&proof.value);
        let mut leaf_preimage = Vec::with_capacity(1 + 2 * Hash::LENGTH);
        leaf_preimage.push(0);
        leaf_preimage.extend_from_slice(path.as_ref());
        leaf_preimage.extend_from_slice(value_hash.as_ref());
        let mut current = Hash::new(leaf_preimage);
        for (level, sibling) in proof.siblings.iter().copied().enumerate() {
            let path_bit = 255_usize.saturating_sub(level);
            let byte = path.as_ref()[path_bit / 8];
            let right = byte & (1_u8 << (path_bit % 8)) != 0;
            current = if right {
                validation_fee_ordinary_smt_node_hash(sibling, current)
            } else {
                validation_fee_ordinary_smt_node_hash(current, sibling)
            };
        }
        current
    }
    #[test]
    fn witness_commitment_rejects_alternate_norito_layout() {
        let commitment =
            ValidationFeePolicySnapshotCommitmentV1::from_registry(17, 1_793_451_600_000, None);
        let canonical = norito::encode_canonical(&commitment).expect("encode canonical commitment");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&commitment).expect("encode alternate-layout commitment")
        };
        assert_ne!(
            alternate, canonical,
            "fixture must exercise a distinct advertised Norito layout"
        );
        norito::decode_from_bytes::<ValidationFeePolicySnapshotCommitmentV1>(&alternate)
            .expect("ordinary Norito accepts the advertised alternate layout");
        let canonical_proof = ValidationFeePolicyWitnessProofV1 {
            key: VALIDATION_FEE_POLICY_WITNESS_KEY_V1.to_vec(),
            value: canonical,
            siblings: vec![
                Hash::new(b"validation-fee witness sibling");
                VALIDATION_FEE_POLICY_WITNESS_SIBLINGS_V1
            ],
        };
        assert_eq!(
            canonical_proof.commitment().expect("canonical commitment"),
            commitment
        );
        assert!(canonical_proof.verify(witness_root(&canonical_proof)));
        let alternate_proof = ValidationFeePolicyWitnessProofV1 {
            value: alternate,
            ..canonical_proof
        };
        assert_eq!(
            alternate_proof
                .commitment()
                .expect_err("alternate-layout commitment must fail"),
            "validation-fee snapshot commitment is non-canonical"
        );
        assert!(!alternate_proof.verify(witness_root(&alternate_proof)));
    }
    #[test]
    fn snapshot_identity_encoding_ignores_and_restores_ambient_flags() {
        let commitment =
            ValidationFeePolicySnapshotCommitmentV1::from_registry(17, 1_793_451_600_000, None);
        let canonical = norito::encode_canonical(&commitment).expect("encode canonical commitment");
        let malformed_parameter = CustomParameter::new(
            ValidationFeePolicyRegistryV1::parameter_id(),
            Json::new("not a validation-fee registry"),
        );
        let baseline_invalid = ValidationFeePolicySnapshotCommitmentV1::from_custom_parameter_state(
            19,
            1_793_451_600_000,
            Some(&malformed_parameter),
        );
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let (ambient_canonical, ambient_invalid) = {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            let before = norito::to_bytes(&commitment)
                .expect("encode commitment under caller ambient flags");
            let encoded = norito::encode_canonical(&commitment)
                .expect("canonicalize commitment under caller ambient flags");
            let invalid = ValidationFeePolicySnapshotCommitmentV1::from_custom_parameter_state(
                19,
                1_793_451_600_000,
                Some(&malformed_parameter),
            );
            let after = norito::to_bytes(&commitment)
                .expect("re-encode commitment under caller ambient flags");
            assert_eq!(
                before, after,
                "canonical helpers must restore the caller's ambient layout"
            );
            (encoded, invalid)
        };
        assert_eq!(ambient_canonical, canonical);
        assert_eq!(ambient_invalid, baseline_invalid);
    }
    #[test]
    fn snapshot_constructors_fail_closed_for_absent_and_malformed_registry() {
        let unconfigured =
            ValidationFeePolicySnapshotCommitmentV1::from_registry(17, 1_793_451_600_000, None);
        assert_eq!(
            unconfigured.version,
            VALIDATION_FEE_POLICY_SNAPSHOT_VERSION_V1
        );
        assert_eq!(unconfigured.evaluated_height, 17);
        assert!(matches!(
            unconfigured.status,
            ValidationFeePolicySnapshotStatusV1::Unconfigured
        ));
        let empty_registry = ValidationFeePolicyRegistryV1 {
            payout_policies: ValidationFeePayoutPolicyRegistryV1 {
                entries: Vec::new(),
            },
            registered_policies: Vec::new(),
        };
        let invalid_registry = ValidationFeePolicySnapshotCommitmentV1::from_registry(
            18,
            1_793_451_600_000,
            Some(&empty_registry),
        );
        assert!(matches!(
            invalid_registry.status,
            ValidationFeePolicySnapshotStatusV1::Invalid(_)
        ));
        let malformed_parameter = CustomParameter::new(
            ValidationFeePolicyRegistryV1::parameter_id(),
            Json::new("not a validation-fee registry"),
        );
        let first = ValidationFeePolicySnapshotCommitmentV1::from_custom_parameter_state(
            19,
            1_793_451_600_000,
            Some(&malformed_parameter),
        );
        let second = ValidationFeePolicySnapshotCommitmentV1::from_custom_parameter_state(
            19,
            1_793_451_600_000,
            Some(&malformed_parameter),
        );
        assert_eq!(
            first, second,
            "malformed-state commitment must be deterministic"
        );
        assert!(matches!(
            first.status,
            ValidationFeePolicySnapshotStatusV1::Invalid(_)
        ));
    }
}

#[cfg(test)]
mod captured_validation_fee_schema_tests;
