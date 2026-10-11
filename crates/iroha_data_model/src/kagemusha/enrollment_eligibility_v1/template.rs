//! Asset-independent provider policy DATA selected by authenticated issuer configuration.
//!
//! This template admits no asset or account. The issuer must independently authenticate current
//! registration and provider ownership before deriving and using an exact asset-specific policy.

use super::*;
use crate::kagemusha::KagemushaWalletAssetScopeV1;

/// Provider observation policy for registered assets under one authenticated scheme selection.
///
/// Neither decoding this template nor deriving a policy establishes provider authority or approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.eligibility.policy_template.v1")]
pub struct KagemushaEligibilityPolicyTemplateV1 {
    /// Exactly one.
    pub version: u16,
    /// Independently authenticated genesis identity.
    pub network_id: [u8; 32],
    /// Exact wallet scheme identity.
    pub scheme_id: [u8; 32],
    /// Positive current authority revision; derived requests bind the complete policy digest.
    pub revision: u64,
    /// Independently selected bank or authorized scheme operator.
    pub authority: KagemushaEligibilityAuthorityV1,
    /// Canonical strong Ed25519 middleware key, separate from the Enrollment-role P-256 key.
    pub public_key: [u8; 32],
    /// Positive upper bound on one fresh request's lifetime; no cached eligibility lease.
    pub maximum_response_ms: u64,
}
impl KagemushaEligibilityPolicyTemplateV1 {
    /// Validate public template fields without establishing authority.
    /// # Errors
    /// Rejects unknown version, zero scope/revision/lifetime and weak keys.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.revision == 0 || self.maximum_response_ms == 0 {
            return Err(invalid("eligibility.template"));
        }
        nonzero(&self.network_id)?;
        nonzero(&self.scheme_id)?;
        nonzero(&self.authority.scope_digest())?;
        ed25519_parse_public_key(&self.public_key)
            .map_err(|_| invalid("eligibility.public_key"))?;
        Ok(())
    }
    /// Derive exact policy DATA for a separately authenticated registered asset.
    /// # Errors
    /// Rejects malformed template or asset scope; this method does not verify registration.
    pub fn for_asset(
        &self,
        asset: &KagemushaWalletAssetScopeV1,
    ) -> Result<KagemushaEligibilityPolicyV1> {
        self.validate()?;
        asset.validate()?;
        let policy = KagemushaEligibilityPolicyV1 {
            version: self.version,
            network_id: self.network_id,
            scheme_id: self.scheme_id,
            asset_digest: asset.asset_digest(),
            revision: self.revision,
            authority: self.authority,
            public_key: self.public_key,
            maximum_response_ms: self.maximum_response_ms,
        };
        policy.validate()?;
        Ok(policy)
    }
    /// Encode one canonical bounded unsigned template.
    /// # Errors
    /// Rejects invalid fields or a frame exceeding the cap.
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)
    }
    /// Decode one template; the issuer must independently authenticate its selection.
    /// # Errors
    /// Rejects excessive, malformed, noncanonical or invalid input.
    pub fn decode_canonical(original: &[u8]) -> Result<Self> {
        let value: Self = decode_frame_v1(original, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)?;
        value.validate()?;
        Ok(value)
    }
}

/// Bounded middleware request carrying asset DATA under an independently selected template.
///
/// The asset supplies decoding context, never registration or authority. The serving issuer
/// authenticates ledger registration before dispatch, and middleware authenticates the issuer
/// transport and its own template selection before consulting current eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.eligibility.observation.v1")]
pub struct KagemushaEligibilityObservationV1 {
    /// Exactly one.
    pub version: u16,
    /// Exact asset/incarnation/scale selected by the serving issuer.
    pub asset: KagemushaWalletAssetScopeV1,
    /// Inner request; signatures and durable nonce accounting retain this exact protocol.
    pub request: KagemushaEligibilityRequestV1,
}
impl KagemushaEligibilityObservationV1 {
    /// Derive and validate the exact request policy against independent template selection.
    /// # Errors
    /// Rejects wrong version, malformed asset/template, foreign request identity or lifetime.
    pub fn policy(
        &self,
        template: &KagemushaEligibilityPolicyTemplateV1,
    ) -> Result<KagemushaEligibilityPolicyV1> {
        if self.version != 1 {
            return Err(invalid("eligibility.observation_version"));
        }
        let policy = template.for_asset(&self.asset)?;
        self.request.validate(&policy)?;
        Ok(policy)
    }
    /// Encode a bounded canonical envelope without conferring authority on its asset DATA.
    /// # Errors
    /// Rejects invalid or foreign request fields and excessive output.
    pub fn encode_canonical(
        &self,
        template: &KagemushaEligibilityPolicyTemplateV1,
    ) -> Result<Vec<u8>> {
        self.policy(template)?;
        encode_frame_v1(self, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)
    }
    /// Decode one complete bounded envelope against independently selected template authority.
    /// # Errors
    /// Rejects oversized, malformed, noncanonical or template-substituted requests.
    pub fn decode_canonical(
        original: &[u8],
        template: &KagemushaEligibilityPolicyTemplateV1,
    ) -> Result<Self> {
        let value: Self = decode_frame_v1(original, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)?;
        value.policy(template)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{asset::AssetDefinitionId, nexus::AxtAssetIncarnationV1};
    use iroha_crypto::KeyPair;

    fn template() -> KagemushaEligibilityPolicyTemplateV1 {
        KagemushaEligibilityPolicyTemplateV1 {
            version: 1,
            network_id: [1; 32],
            scheme_id: [2; 32],
            revision: 1,
            authority: KagemushaEligibilityAuthorityV1::Bank { fi_digest: [3; 32] },
            public_key: KeyPair::from_seed(vec![4; 32], Algorithm::Ed25519)
                .public_key()
                .to_bytes()
                .1
                .try_into()
                .unwrap(),
            maximum_response_ms: 1000,
        }
    }
    fn asset(seed: u8, scale: u32) -> KagemushaWalletAssetScopeV1 {
        let mut id = [seed; 16];
        id[6] = 0x40 | (id[6] & 15);
        id[8] = 0x80 | (id[8] & 63);
        KagemushaWalletAssetScopeV1::new(
            AssetDefinitionId::from_uuid_bytes(id).unwrap(),
            &AxtAssetIncarnationV1::try_from_bytes(*iroha_crypto::Hash::new([seed; 32]).as_ref())
                .unwrap(),
            scale,
        )
        .unwrap()
    }
    #[test]
    fn both_authorities_derive_exact_distinct_policies_for_universal_assets() {
        let mut template = template();
        for authority in [
            template.authority,
            KagemushaEligibilityAuthorityV1::SchemeOperator {
                operator_digest: [3; 32],
            },
        ] {
            template.authority = authority;
            let mut digests = std::collections::BTreeSet::new();
            for (seed, scale) in [(5, 0), (6, 2), (7, 28)] {
                let asset = asset(seed, scale);
                let policy = template.for_asset(&asset).unwrap();
                assert_eq!(policy.asset_digest, asset.asset_digest());
                assert_eq!(policy.authority, authority);
                assert_eq!(policy.public_key, template.public_key);
                assert_eq!(policy.maximum_response_ms, template.maximum_response_ms);
                assert!(digests.insert(policy.policy_digest().unwrap()));
                assert_eq!(
                    KagemushaEligibilityPolicyV1::decode_canonical(
                        &policy.encode_canonical().unwrap()
                    )
                    .unwrap(),
                    policy
                );
            }
            let encoded = template.encode_canonical().unwrap();
            assert!(encoded.len() <= KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1);
            assert_eq!(
                KagemushaEligibilityPolicyTemplateV1::decode_canonical(&encoded).unwrap(),
                template
            );
            let mut suffix = encoded;
            suffix.push(0);
            assert!(KagemushaEligibilityPolicyTemplateV1::decode_canonical(&suffix).is_err());
        }
    }
    #[test]
    fn malformed_template_and_asset_never_derive_policy() {
        let valid = template();
        let valid_asset = asset(5, 2);
        for index in 0..7 {
            let mut changed = valid;
            match index {
                0 => changed.version = 0,
                1 => changed.network_id = [0; 32],
                2 => changed.scheme_id = [0; 32],
                3 => changed.revision = 0,
                4 => {
                    changed.authority = KagemushaEligibilityAuthorityV1::SchemeOperator {
                        operator_digest: [0; 32],
                    }
                }
                5 => changed.public_key = [0; 32],
                _ => changed.maximum_response_ms = 0,
            }
            assert!(changed.validate().is_err());
            assert!(changed.for_asset(&valid_asset).is_err());
            assert!(changed.encode_canonical().is_err());
        }
        for index in 0..3 {
            let mut changed = valid_asset.clone();
            match index {
                0 => changed.version = 0,
                1 => changed.scale = 29,
                _ => changed.asset_incarnation = [0; 32],
            }
            assert!(valid.for_asset(&changed).is_err());
        }
        assert!(
            KagemushaEligibilityPolicyTemplateV1::decode_canonical(&vec![
                0;
                KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1
                    + 1
            ])
            .is_err()
        );
    }
    #[test]
    fn observation_binds_exact_asset_template_and_inner_request_before_lookup() {
        let template = template();
        let asset = asset(5, 2);
        let policy = template.for_asset(&asset).unwrap();
        let request = KagemushaEligibilityRequestV1 {
            version: 1,
            policy_digest: policy.policy_digest().unwrap(),
            account_digest: [5; 32],
            actor_digest: [6; 32],
            attempt_id: [7; 32],
            nonce: [8; 32],
            operation_digest: [9; 32],
            purpose: KagemushaEligibilityPurposeV1::PreKeyPermit,
            requested_at_ms: 1000,
            expires_at_ms: 2000,
        };
        let value = KagemushaEligibilityObservationV1 {
            version: 1,
            asset,
            request,
        };
        let bytes = value.encode_canonical(&template).unwrap();
        assert!(bytes.len() < KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1);
        assert_eq!(
            KagemushaEligibilityObservationV1::decode_canonical(&bytes, &template).unwrap(),
            value
        );
        assert_eq!(value.policy(&template).unwrap(), policy);
        for field in 0..6 {
            let mut changed = value.clone();
            match field {
                0 => changed.version = 0,
                1 => changed.asset.scale = 28,
                2 => changed.asset.asset_incarnation = [10; 32],
                3 => changed.request.policy_digest = [11; 32],
                4 => changed.request.expires_at_ms = 2001,
                _ => changed.request.nonce = [0; 32],
            }
            assert!(changed.encode_canonical(&template).is_err());
        }
        let mut other = template;
        other.authority = KagemushaEligibilityAuthorityV1::SchemeOperator {
            operator_digest: [3; 32],
        };
        assert!(KagemushaEligibilityObservationV1::decode_canonical(&bytes, &other).is_err());
        let mut suffix = bytes.clone();
        suffix.push(0);
        assert!(KagemushaEligibilityObservationV1::decode_canonical(&suffix, &template).is_err());
        assert!(
            KagemushaEligibilityObservationV1::decode_canonical(
                &bytes[..bytes.len() - 1],
                &template
            )
            .is_err()
        );
        assert!(
            KagemushaEligibilityObservationV1::decode_canonical(
                &vec![0; KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 + 1],
                &template
            )
            .is_err()
        );
    }
    fn vectors() -> norito::json::Value {
        let mut cases = Vec::new();
        let key = KeyPair::from_seed(vec![4; 32], Algorithm::Ed25519);
        for operator in [false, true] {
            let mut template = template();
            if operator {
                template.authority = KagemushaEligibilityAuthorityV1::SchemeOperator {
                    operator_digest: [3; 32],
                };
            }
            for (seed, scale) in [(5, 0), (6, 2), (7, 28)] {
                let asset = asset(seed, scale);
                let policy = template.for_asset(&asset).unwrap();
                for (purpose_index, purpose) in [
                    KagemushaEligibilityPurposeV1::PreKeyPermit,
                    KagemushaEligibilityPurposeV1::VerifyEvidence,
                    KagemushaEligibilityPurposeV1::IssueCredential,
                    KagemushaEligibilityPurposeV1::DeliverCredential,
                ]
                .into_iter()
                .enumerate()
                {
                    let request = KagemushaEligibilityRequestV1 {
                        version: 1,
                        policy_digest: policy.policy_digest().unwrap(),
                        account_digest: [5; 32],
                        actor_digest: [6; 32],
                        attempt_id: [7; 32],
                        nonce: [8; 32],
                        operation_digest: [9; 32],
                        purpose,
                        requested_at_ms: 1000,
                        expires_at_ms: 2000,
                    };
                    let observation = KagemushaEligibilityObservationV1 {
                        version: 1,
                        asset: asset.clone(),
                        request,
                    };
                    let body = KagemushaEligibilityResponseBodyV1 {
                        version: 1,
                        request_digest: request.request_digest(&policy).unwrap(),
                        decision: [
                            KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
                            KagemushaEligibilityDecisionV1::NotApproved,
                            KagemushaEligibilityDecisionV1::Frozen,
                        ][(purpose_index + usize::from(seed)) % 3],
                        source_revision: 1,
                        observed_at_ms: 1100,
                        valid_until_ms: 2000,
                    };
                    let response = KagemushaEligibilityResponseV1 {
                        signature: iroha_crypto::Signature::new(
                            key.private_key(),
                            &body.signing_message().unwrap(),
                        )
                        .payload()
                        .try_into()
                        .unwrap(),
                        body,
                    };
                    response.verify(&policy, &request, 1100).unwrap();
                    cases.push(norito::json!({
                        "authority":(if operator {"scheme-operator"} else {"bank"}), "asset_seed":seed,"scale":scale,
                        "purpose":(["pre-key-permit", "verify-evidence", "issue-credential", "deliver-credential"][purpose_index]),
                        "decision":(["approved-unfrozen", "not-approved", "frozen"][(purpose_index + usize::from(seed)) % 3]),
                        "template_hex":(hex::encode(template.encode_canonical().unwrap())),
                        "asset_hex":(hex::encode(norito::encode_canonical(&asset).unwrap())),
                        "asset_digest_hex":(hex::encode(asset.asset_digest())),
                        "policy_hex":(hex::encode(policy.encode_canonical().unwrap())),
                        "policy_digest_hex":(hex::encode(policy.policy_digest().unwrap())),
                        "request_hex":(hex::encode(request.encode_canonical(&policy).unwrap())),
                        "request_digest_hex":(hex::encode(request.request_digest(&policy).unwrap())),
                        "observation_hex":(hex::encode(observation.encode_canonical(&template).unwrap())),
                        "response_hex":(hex::encode(response.encode_canonical().unwrap())),
                        "response_body_hex":(hex::encode(encode_frame_v1(&body, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1).unwrap())),
                        "signature_hex":(hex::encode(response.signature)),
                        "signing_message_hex":(hex::encode(body.signing_message().unwrap())),
                    }));
                }
            }
        }
        norito::json!({"version":1,"scope":"Unsigned test DATA and synthetic provider signatures; no registration or provider authorization", "cases":cases})
    }
    #[test]
    #[ignore = "explicit maintenance generator for public DATA; never registration or provider admission"]
    fn generate_enrollment_eligibility_template_vectors() {
        println!("{}", norito::json::to_json_pretty(&vectors()).unwrap());
    }
    #[test]
    fn frozen_enrollment_eligibility_template_vectors_match_current_rust() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("fixtures/kagemusha/enrollment_eligibility_template_v1_vectors.json");
        let expected = norito::json::parse_value(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(vectors(), expected);
    }
}
