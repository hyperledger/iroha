//! First-release retail DAY limit types for a physically restricted asset.
//!
//! These types describe consensus state. Decoding them does not authenticate an
//! issuer, install a policy, or establish that one commitment denotes one person.

use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId, asset::AssetDefinitionId,
};
use iroha_crypto::{Hash, PublicKey, SignatureOf};
use iroha_model_base::{state_path::StatePath, topology::DataSpaceId};
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::collections::BTreeSet;

/// Domain of an issuer signature over one exact retail identity binding.
pub const RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1: &str = "iroha.bpng.retail-identity.v1";
/// Physical consensus-state namespace for the one owner-installed policy.
pub const RETAIL_POLICY_STATE_PREFIX_V1: &str = "retail_day_policy_v1/";
/// Physical consensus-state namespace for the immutable activation marker.
pub const RETAIL_ACTIVATION_STATE_PREFIX_V1: &str = "retail_day_activation_v1/";

fn retail_definition_state_digest_v1(definition: &AssetDefinitionId) -> String {
    hex::encode(Hash::new(definition.to_string().as_bytes()).as_ref())
}

/// The exact physical path that native execution uses for one retail policy.
///
/// Sharing this constructor with a proof verifier prevents an application from
/// authenticating a similarly named logical or other-dataspace key.
#[must_use]
pub fn retail_policy_state_path_v1(
    definition: &AssetDefinitionId,
    dataspace: DataSpaceId,
) -> StatePath {
    format!(
        "{}{}/{dataspace}",
        RETAIL_POLICY_STATE_PREFIX_V1,
        retail_definition_state_digest_v1(definition),
        dataspace = dataspace.as_u64()
    )
    .parse()
    .expect("fixed-size native retail policy path must be canonical")
}

/// The exact physical path that native execution uses for the activation marker.
#[must_use]
pub fn retail_activation_state_path_v1(definition: &AssetDefinitionId) -> StatePath {
    format!(
        "{}{}",
        RETAIL_ACTIVATION_STATE_PREFIX_V1,
        retail_definition_state_digest_v1(definition)
    )
    .parse()
    .expect("fixed-size native retail activation path must be canonical")
}

/// An opaque issuer-assigned identity shared by every enrolled account of one person.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::retail_daily_limit::RetailIdentityCommitmentV1")]
pub struct RetailIdentityCommitmentV1 {
    /// Issuer's opaque, nonzero commitment; never a name, phone number or UAID.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub digest: [u8; 32],
}

/// A typed purpose that can be exempted only by a future verified native path.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(
    tag = "purpose",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_data_model::asset::retail_daily_limit::RetailMovementPurposeV1")]
pub enum RetailMovementPurposeV1 {
    /// A verified mint or redemption by the monetary issuer.
    MonetaryIssuer,
    /// A verified bridge, settlement or reserve movement.
    ProtocolCustody,
}

/// Closed monetary effects for a freshly activated retail asset.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(
    tag = "purpose",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_data_model::asset::retail_daily_limit::RetailMonetaryPurposeV1")]
pub enum RetailMonetaryPurposeV1 {
    /// Monetary issuer creates supply only into the policy reserve.
    MintToReserve,
    /// Reserve authority credits an issuer-bound retail account.
    CreditRetail,
    /// Retail account authority returns value to the exact policy reserve.
    DefundRetail,
    /// Monetary issuer retires supply only from the policy reserve.
    BurnReserve,
}

/// One exact institutional source and typed purpose in an owner-installed policy.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::asset::retail_daily_limit::RetailInstitutionalExceptionV1"
)]
pub struct RetailInstitutionalExceptionV1 {
    /// Exact account permitted to originate the institutional movement.
    pub source_account: AccountId,
    /// Typed movement allowed for that account.
    pub purpose: RetailMovementPurposeV1,
}

/// Exact asset, physical dataspace and retail identity authority for a DAY cap.
///
/// The owner must authenticate and install this policy through a dedicated
/// consensus instruction before it may govern value. The public key is an
/// owner-selected trust input, never inferred from an attestation.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::retail_daily_limit::RetailDailyLimitPolicyV1")]
pub struct RetailDailyLimitPolicyV1 {
    /// Exact governed asset definition.
    pub asset_definition_id: AssetDefinitionId,
    /// Physical dataspace containing the governed balance.
    pub physical_dataspace: DataSpaceId,
    /// Positive owner-controlled policy revision.
    pub revision: u64,
    /// Positive integer Kina per UTC calendar day.
    pub daily_cap: Quantity,
    /// Account authorized to attest retail identities.
    pub identity_issuer: AccountId,
    /// Installed verification key for the identity issuer.
    pub identity_issuer_public_key: PublicKey,
    /// Owner-selected authority for supply issuance and retirement.
    pub monetary_issuer_account: AccountId,
    /// Owner-selected exact PGK reserve balance account.
    pub reserve_account: AccountId,
    /// Exact exception roster. The current movement kernel admits no exception.
    pub institutional_exceptions: BTreeSet<RetailInstitutionalExceptionV1>,
}

/// Immutable activation boundary for one exact owner-installed policy.
///
/// A newly installed policy does not admit governed debits until the next UTC
/// day. This prevents any earlier same-day use of a recycled definition ID
/// from escaping the first counted DAY bucket.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::retail_daily_limit::RetailDailyActivationV1")]
pub struct RetailDailyActivationV1 {
    /// Exact governed definition.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact physical dataspace.
    pub physical_dataspace: DataSpaceId,
    /// Digest of the canonical installed policy frame.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub policy_digest: [u8; 32],
    /// Consensus block timestamp at atomic definition registration and activation.
    pub activated_at_ms: u64,
    /// First UTC day start at which a governed debit may be admitted.
    pub enforce_from_day_start_ms: u64,
}

impl RetailDailyLimitPolicyV1 {
    /// Reject zero, fractional or nonphysical first-release policy claims.
    ///
    /// # Errors
    /// Returns the violated policy-shape rule.
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.physical_dataspace == DataSpaceId::UNIVERSAL {
            return Err("retail daily limit requires a physical dataspace");
        }
        if self.revision == 0 {
            return Err("retail daily limit revision must be positive");
        }
        if self.daily_cap.is_zero() || self.daily_cap.as_numeric().scale() != 0 {
            return Err("retail daily limit must be positive whole Kina");
        }
        if self.monetary_issuer_account == self.reserve_account {
            return Err("retail monetary issuer and reserve must be distinct accounts");
        }
        Ok(())
    }
}

/// Exact issuer assertion that this account belongs to one opaque retail identity.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::asset::retail_daily_limit::RetailIdentityAttestationBodyV1"
)]
pub struct RetailIdentityAttestationBodyV1 {
    /// Signature-domain separator for this attestation version.
    pub domain: String,
    /// Asset definition covered by the identity binding.
    pub asset_definition_id: AssetDefinitionId,
    /// Physical dataspace covered by the identity binding.
    pub physical_dataspace: DataSpaceId,
    /// Policy revision under which the issuer signed this binding.
    pub policy_revision: u64,
    /// Exact account assigned to the opaque retail identity.
    pub account_id: AccountId,
    /// Shared opaque identity commitment for all of the person's accounts.
    pub identity: RetailIdentityCommitmentV1,
    /// Nonzero commitment to issuer-held uniqueness and rekey-lineage evidence.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub uniqueness_evidence_digest: [u8; 32],
}

/// Issuer signature retained with the consensus account-to-identity binding.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::retail_daily_limit::RetailIdentityAttestationV1")]
pub struct RetailIdentityAttestationV1 {
    /// Exact issuer-signed binding fields.
    pub body: RetailIdentityAttestationBodyV1,
    /// Issuer signature over the canonical body.
    pub signature: SignatureOf<RetailIdentityAttestationBodyV1>,
}

impl RetailIdentityAttestationV1 {
    /// Authenticate this exact account and policy revision under the installed issuer key.
    ///
    /// # Errors
    /// Rejects a mismatched account, policy revision or issuer signature.
    pub fn verify_for(
        &self,
        policy: &RetailDailyLimitPolicyV1,
        account: &AccountId,
    ) -> Result<RetailIdentityCommitmentV1, &'static str> {
        let body = &self.body;
        if body.domain != RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1
            || body.asset_definition_id != policy.asset_definition_id
            || body.physical_dataspace != policy.physical_dataspace
            || body.policy_revision != policy.revision
            || &body.account_id != account
        {
            return Err(
                "retail identity attestation does not bind the installed policy and account",
            );
        }
        if body.identity.digest == [0; 32] || body.uniqueness_evidence_digest == [0; 32] {
            return Err("retail identity attestation commitments must be nonzero");
        }
        self.signature
            .verify(&policy.identity_issuer_public_key, body)
            .map_err(|_| "retail identity issuer signature is invalid")?;
        Ok(body.identity)
    }
}

/// Dedicated consensus usage key. Policy revisions do not reset a day's spending.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::retail_daily_limit::RetailDailyUsageKeyV1")]
pub struct RetailDailyUsageKeyV1 {
    /// Asset definition whose spending is counted.
    pub asset_definition_id: AssetDefinitionId,
    /// Physical dataspace whose spending is counted.
    pub physical_dataspace: DataSpaceId,
    /// Issuer-attested identity shared across accounts.
    pub identity: RetailIdentityCommitmentV1,
    /// Start of the UTC calendar day in Unix milliseconds.
    pub utc_day_start_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::domain::DomainId;
    use norito::codec::DecodeAll as _;

    fn fixture() -> (KeyPair, AccountId, RetailDailyLimitPolicyV1) {
        let issuer = KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519)
            .expect("test-only retail issuer key");
        let account = AccountId::new(issuer.public_key().clone());
        let reserve_key = KeyPair::try_from_seed(vec![0x72; 32], Algorithm::Ed25519)
            .expect("test-only reserve key");
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("retail", "universal").expect("test domain"),
            "kina".parse().expect("test asset name"),
        );
        let policy = RetailDailyLimitPolicyV1 {
            asset_definition_id: definition,
            physical_dataspace: DataSpaceId::new(7),
            revision: 1,
            daily_cap: Quantity::from(10_u32),
            identity_issuer: account.clone(),
            identity_issuer_public_key: issuer.public_key().clone(),
            monetary_issuer_account: account.clone(),
            reserve_account: AccountId::new(reserve_key.public_key().clone()),
            institutional_exceptions: BTreeSet::new(),
        };
        (issuer, account, policy)
    }

    #[test]
    fn policy_requires_positive_whole_kina_and_physical_scope() {
        let (_, _, mut policy) = fixture();
        assert_eq!(policy.validate_shape(), Ok(()));
        policy.daily_cap = Quantity::zero();
        assert!(policy.validate_shape().is_err());
        policy.daily_cap = "1.5".parse().expect("fractional test amount");
        assert!(policy.validate_shape().is_err());
        policy.daily_cap = Quantity::from(10_u32);
        policy.physical_dataspace = DataSpaceId::UNIVERSAL;
        assert!(policy.validate_shape().is_err());
    }

    #[test]
    fn signed_identity_is_exactly_bound_and_roundtrips() {
        let (issuer, account, policy) = fixture();
        let body = RetailIdentityAttestationBodyV1 {
            domain: RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1.to_owned(),
            asset_definition_id: policy.asset_definition_id.clone(),
            physical_dataspace: policy.physical_dataspace,
            policy_revision: policy.revision,
            account_id: account.clone(),
            identity: RetailIdentityCommitmentV1 { digest: [0xA5; 32] },
            uniqueness_evidence_digest: [0xB5; 32],
        };
        let attestation = RetailIdentityAttestationV1 {
            signature: SignatureOf::try_new(issuer.private_key(), &body)
                .expect("test-only issuer signature"),
            body,
        };
        assert_eq!(
            attestation.verify_for(&policy, &account),
            Ok(RetailIdentityCommitmentV1 { digest: [0xA5; 32] })
        );
        let bytes = attestation.encode();
        let decoded = RetailIdentityAttestationV1::decode_all(&mut bytes.as_slice())
            .expect("canonical attestation roundtrip");
        assert_eq!(decoded, attestation);

        let other = AccountId::new(
            KeyPair::try_from_seed(vec![0x72; 32], Algorithm::Ed25519)
                .expect("other test key")
                .public_key()
                .clone(),
        );
        assert!(attestation.verify_for(&policy, &other).is_err());
        let mut altered = attestation.clone();
        altered.body.identity.digest = [0xC5; 32];
        assert!(altered.verify_for(&policy, &account).is_err());
        let mut revised = policy;
        revised.revision += 1;
        assert!(attestation.verify_for(&revised, &account).is_err());
    }
}
