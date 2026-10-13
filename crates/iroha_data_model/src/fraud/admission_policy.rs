//! Committed metadata-assessment admission policy.
//!
//! An ordinary authorized SetParameter installs this exact V1 value. Core freezes
//! the predecessor's validated value for a block; a change governs the following
//! block. Endpoints and transport deadlines belong to the node, not this policy.

use iroha_crypto::PublicKey;
use iroha_primitives::json::Json;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::parameter::{CustomParameter, CustomParameterId};

/// Maximum number of distinct assessment engines in one policy.
pub const MAX_FRAUD_ATTESTERS_V1: usize = 256;
/// Maximum UTF-8 byte length of one canonical engine identifier.
pub const MAX_FRAUD_ENGINE_ID_BYTES_V1: usize = 128;

/// Severity supplied by the signed assessment metadata.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(tag = "band", content = "value", rename_all = "snake_case")]
#[norito_schema(name = "iroha:fraud:risk-band:v1")]
pub enum FraudRiskBandV1 {
    /// Lowest severity.
    Low,
    /// Elevated severity.
    Medium,
    /// High severity.
    High,
    /// Highest severity.
    Critical,
}

impl FraudRiskBandV1 {
    /// Canonical assessment metadata spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}
impl core::fmt::Display for FraudRiskBandV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}
impl core::str::FromStr for FraudRiskBandV1 {
    type Err = ();
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(()),
        }
    }
}

/// Exact identity and verification key of one assessment engine.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:fraud:admission-attester:v1")]
pub struct FraudAdmissionAttesterV1 {
    /// Canonical engine identifier with no ASCII uppercase letters used by the signed envelope.
    pub engine_id: String,
    /// Public key against which the original assessment signature is checked.
    pub public_key: PublicKey,
}

impl FraudAdmissionAttesterV1 {
    /// Exact canonical identifier used in telemetry after policy validation.
    #[must_use]
    pub fn engine_label(&self) -> &str {
        &self.engine_id
    }
}

/// The complete deterministic fraud-admission policy.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:fraud:admission-policy:v1")]
pub struct FraudAdmissionPolicyV1 {
    /// Exact first-release policy version; only one is supported.
    pub version: u8,
    /// Whether assessment admission is enforced.
    pub enabled: bool,
    /// Lowest accepted declared band; absence retains the existing ungated rule.
    pub required_minimum_band: Option<FraudRiskBandV1>,
    /// Whether missing assessment metadata is accepted.
    ///
    /// This is a boolean permission, not an elapsed-time grace window.
    pub missing_assessment_permitted: bool,
    /// Engines in strict ascending identifier order, without duplicates.
    ///
    /// An empty set preserves the existing metadata-only assessment rule.
    pub attesters: Vec<FraudAdmissionAttesterV1>,
}

/// Why supplied policy bytes cannot become committed State.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FraudAdmissionPolicyError {
    /// The payload is not the exact typed policy.
    #[error("fraud admission policy is malformed: {0}")]
    Malformed(String),
    /// Another version has no first-release interpretation.
    #[error("unsupported fraud admission policy version {0}")]
    UnsupportedVersion(u8),
    /// The finite engine-set bound was exceeded.
    #[error("fraud admission policy exceeds the attester bound")]
    TooManyAttesters,
    /// An identifier is empty, too long, noncanonical, or contains whitespace.
    #[error("fraud admission policy has a noncanonical engine identifier")]
    InvalidEngineId,
    /// Duplicate or unsorted engines have no canonical policy interpretation.
    #[error("fraud admission attesters must have strictly increasing unique engine identifiers")]
    AttesterOrder,
    /// An engine key has no supported algorithm identity.
    #[error("fraud admission policy has a malformed attester public key")]
    InvalidPublicKey,
}

impl FraudAdmissionPolicyV1 {
    /// Canonical custom-parameter identifier.
    pub const PARAMETER_ID_STR: &'static str = "fraud_admission_policy_v1";

    /// Return the identifier of the sole committed policy owner.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        Self::PARAMETER_ID_STR
            .parse()
            .expect("static policy identifier")
    }

    /// Fixed policy of a chain without an explicit parameter.
    #[must_use]
    pub const fn protocol_default() -> Self {
        Self {
            version: 1,
            enabled: false,
            required_minimum_band: None,
            missing_assessment_permitted: false,
            attesters: Vec::new(),
        }
    }

    /// Validate deterministic structure before a parameter mutation is published.
    ///
    /// # Errors
    /// Rejects unsupported versions and noncanonical, duplicate or oversized engine sets.
    pub fn validate(&self) -> Result<(), FraudAdmissionPolicyError> {
        if self.version != 1 {
            return Err(FraudAdmissionPolicyError::UnsupportedVersion(self.version));
        }
        if self.attesters.len() > MAX_FRAUD_ATTESTERS_V1 {
            return Err(FraudAdmissionPolicyError::TooManyAttesters);
        }
        let mut previous: Option<&str> = None;
        for attester in &self.attesters {
            let id = attester.engine_id.as_str();
            if id.is_empty()
                || id.len() > MAX_FRAUD_ENGINE_ID_BYTES_V1
                || id != id.trim()
                || id.chars().any(char::is_whitespace)
                || id.bytes().any(|byte| byte.is_ascii_uppercase())
            {
                return Err(FraudAdmissionPolicyError::InvalidEngineId);
            }
            if previous.is_some_and(|previous| previous >= id) {
                return Err(FraudAdmissionPolicyError::AttesterOrder);
            }
            attester
                .public_key
                .try_algorithm()
                .map_err(|_| FraudAdmissionPolicyError::InvalidPublicKey)?;
            previous = Some(id);
        }
        Ok(())
    }

    /// Resolve the exact, already normalized metadata engine identifier.
    #[must_use]
    pub fn attester(&self, engine_id: &str) -> Option<&FraudAdmissionAttesterV1> {
        self.attesters
            .iter()
            .find(|attester| attester.engine_id == engine_id)
    }

    /// Author the parameter carried by an ordinary authorized SetParameter.
    #[must_use]
    pub fn into_custom_parameter(self) -> CustomParameter {
        CustomParameter::new(Self::parameter_id(), Json::new(self))
    }

    /// Decode and validate a supplied parameter value.
    ///
    /// # Errors
    /// Rejects malformed bytes or invalid deterministic structure.
    pub fn from_payload(payload: &Json) -> Result<Self, FraudAdmissionPolicyError> {
        let policy = payload
            .try_into_any_norito::<Self>()
            .map_err(|error| FraudAdmissionPolicyError::Malformed(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};

    fn attester(id: &str) -> FraudAdmissionAttesterV1 {
        FraudAdmissionAttesterV1 {
            engine_id: id.to_owned(),
            public_key: KeyPair::from_seed(id.as_bytes().to_vec(), Algorithm::Ed25519)
                .public_key()
                .clone(),
        }
    }

    #[test]
    fn assessment_band_and_attester_lookup_use_the_canonical_typed_owner() {
        for band in [
            FraudRiskBandV1::Low,
            FraudRiskBandV1::Medium,
            FraudRiskBandV1::High,
            FraudRiskBandV1::Critical,
        ] {
            assert_eq!(band.as_str().parse::<FraudRiskBandV1>(), Ok(band));
            assert_eq!(band.to_string(), band.as_str());
        }
        assert!("High".parse::<FraudRiskBandV1>().is_err());
        let policy = FraudAdmissionPolicyV1 {
            attesters: vec![attester("risk-a")],
            ..FraudAdmissionPolicyV1::protocol_default()
        };
        assert_eq!(policy.attester("risk-a").unwrap().engine_label(), "risk-a");
        for foreign in ["", " risk-a", "risk-a ", "Risk-a"] {
            assert!(policy.attester(foreign).is_none());
        }
    }

    #[test]
    fn policy_has_exact_nominal_identity_and_each_semantic_field_changes_canonical_bytes() {
        use norito::NoritoSchema as _;
        assert_eq!(
            FraudAdmissionPolicyV1::nominal_name(),
            "iroha:fraud:admission-policy:v1"
        );
        let baseline = FraudAdmissionPolicyV1 {
            enabled: true,
            required_minimum_band: Some(FraudRiskBandV1::Medium),
            attesters: vec![attester("risk-a"), attester("risk-b")],
            ..FraudAdmissionPolicyV1::protocol_default()
        };
        let wire = norito::encode_canonical(&baseline).unwrap();
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(norito::encode_canonical(&baseline).unwrap(), wire);
        let mut changed = baseline.clone();
        changed.enabled = false;
        assert_ne!(norito::encode_canonical(&changed).unwrap(), wire);
        let mut changed = baseline.clone();
        changed.required_minimum_band = Some(FraudRiskBandV1::High);
        assert_ne!(norito::encode_canonical(&changed).unwrap(), wire);
        let mut changed = baseline.clone();
        changed.missing_assessment_permitted = true;
        assert_ne!(norito::encode_canonical(&changed).unwrap(), wire);
        let mut changed = baseline.clone();
        changed.attesters[1].engine_id = "risk-c".to_owned();
        changed.validate().unwrap();
        assert_ne!(norito::encode_canonical(&changed).unwrap(), wire);
        let mut changed = baseline.clone();
        changed.attesters[0].public_key = changed.attesters[1].public_key.clone();
        changed.validate().unwrap();
        assert_ne!(norito::encode_canonical(&changed).unwrap(), wire);
        let mut changed = baseline;
        changed.attesters.reverse();
        assert_eq!(
            changed.validate(),
            Err(FraudAdmissionPolicyError::AttesterOrder)
        );
        assert_ne!(norito::encode_canonical(&changed).unwrap(), wire);
    }

    #[test]
    fn typed_bands_and_policy_have_exact_norito_and_json_roundtrips() {
        for band in [
            FraudRiskBandV1::Low,
            FraudRiskBandV1::Medium,
            FraudRiskBandV1::High,
            FraudRiskBandV1::Critical,
        ] {
            let policy = FraudAdmissionPolicyV1 {
                version: 1,
                enabled: true,
                required_minimum_band: Some(band),
                missing_assessment_permitted: false,
                attesters: vec![attester("risk-a")],
            };
            policy.validate().unwrap();
            let wire = norito::encode_canonical(&policy).unwrap();
            assert_eq!(
                norito::decode_canonical::<FraudAdmissionPolicyV1>(&wire).unwrap(),
                policy
            );
            let json = norito::json::to_json(&policy).unwrap();
            assert_eq!(
                norito::json::from_str::<FraudAdmissionPolicyV1>(&json).unwrap(),
                policy
            );
        }
        let malformed = Json::new(norito::json!({
            "version": 1, "enabled": true,
            "required_minimum_band": {"band": "unknown"},
            "missing_assessment_permitted": false, "attesters": []
        }));
        assert!(matches!(
            FraudAdmissionPolicyV1::from_payload(&malformed),
            Err(FraudAdmissionPolicyError::Malformed(_))
        ));
    }

    #[test]
    fn policy_rejects_duplicate_unsorted_and_noncanonical_attesters() {
        for attesters in [
            vec![attester("risk-a"), attester("risk-a")],
            vec![attester("risk-b"), attester("risk-a")],
        ] {
            let policy = FraudAdmissionPolicyV1 {
                attesters,
                ..FraudAdmissionPolicyV1::protocol_default()
            };
            assert_eq!(
                policy.validate(),
                Err(FraudAdmissionPolicyError::AttesterOrder)
            );
        }
        for id in ["", " risk-a", "risk-a ", "Risk-a", "risk a"] {
            let policy = FraudAdmissionPolicyV1 {
                attesters: vec![attester(id)],
                ..FraudAdmissionPolicyV1::protocol_default()
            };
            assert_eq!(
                policy.validate(),
                Err(FraudAdmissionPolicyError::InvalidEngineId)
            );
        }
    }

    #[test]
    fn engine_identifier_normalization_is_ascii_only_and_preserves_exact_unicode_bytes() {
        let policy = FraudAdmissionPolicyV1 {
            attesters: vec![attester("Éngine")],
            ..FraudAdmissionPolicyV1::protocol_default()
        };
        policy.validate().unwrap();
        assert_eq!(policy.attesters[0].engine_id, "Éngine");
        assert_ne!(policy.attesters[0].engine_id, "éngine");
    }

    #[test]
    fn policy_rejects_unsupported_version_and_malformed_payload() {
        let policy = FraudAdmissionPolicyV1 {
            version: 2,
            ..FraudAdmissionPolicyV1::protocol_default()
        };
        assert_eq!(
            policy.validate(),
            Err(FraudAdmissionPolicyError::UnsupportedVersion(2))
        );
        assert!(matches!(
            FraudAdmissionPolicyV1::from_payload(&Json::new("not a policy")),
            Err(FraudAdmissionPolicyError::Malformed(_))
        ));
        let default = FraudAdmissionPolicyV1::protocol_default();
        assert_eq!(
            FraudAdmissionPolicyV1::from_payload(default.clone().into_custom_parameter().payload())
                .unwrap(),
            default
        );
    }

    #[test]
    fn engine_set_and_identifier_bounds_are_fixed_protocol_values() {
        let at_bound = (0..MAX_FRAUD_ATTESTERS_V1)
            .map(|index| attester(&format!("risk-{index:03}")))
            .collect::<Vec<_>>();
        let mut policy = FraudAdmissionPolicyV1 {
            attesters: at_bound,
            ..FraudAdmissionPolicyV1::protocol_default()
        };
        policy.validate().unwrap();
        policy.attesters.push(attester("risk-over"));
        assert_eq!(
            policy.validate(),
            Err(FraudAdmissionPolicyError::TooManyAttesters)
        );
        policy.attesters = vec![attester(&"a".repeat(MAX_FRAUD_ENGINE_ID_BYTES_V1))];
        policy.validate().unwrap();
        policy.attesters[0].engine_id.push('a');
        assert_eq!(
            policy.validate(),
            Err(FraudAdmissionPolicyError::InvalidEngineId)
        );
    }
}
