//! The chain's sole ordinary signing and account-controller algorithm policy.
//!
//! Genesis must explicitly authenticate one initial policy. Ordinary consumers
//! must read the frozen predecessor policy for the executing block. Genesis root
//! signature trust and consensus validator-key rules have their own purposes;
//! neither grants an ordinary account-controller exemption.
//!
//! This value describes protocol validity, independent of this binary's crypto
//! backends. A known algorithm without an implementation remains a known policy
//! member; startup must report the unavailable implementation separately.
//!
//! TODO: close ordinary transaction/controller consumers, genesis producers and
//! startup capability checks over this owner before qualifying F.4. This model
//! and bootstrap boundary alone do not retire the remaining local policy reads.

use iroha_crypto::Algorithm;
use iroha_primitives::json::Json;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::{
    DeriveJsonSerialize,
    account::curve::CurveId,
    parameter::{CustomParameter, CustomParameterId, Parameter},
};

/// Why an ordinary crypto policy is not a canonical protocol value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoAdmissionPolicyError {
    /// An ordinary policy must permit at least one canonical algorithm.
    #[error("the crypto admission policy has no allowed algorithms")]
    Empty,
    /// More entries were provided than the entire canonical algorithm registry.
    #[error("the crypto admission policy exceeds the canonical algorithm registry")]
    TooMany,
    /// Algorithm tags are repeated or not in strictly ascending canonical order.
    #[error("the crypto admission policy algorithms must be unique and in canonical tag order")]
    NonCanonical,
}

/// The exact first-release ordinary signing and controller policy.
///
/// The one list also determines permitted controller curves through the total
/// canonical `Algorithm` to `CurveId` mapping. No second curve allowlist exists.
/// Both canonical binary and JSON decoders validate this invariant before
/// returning the value. No invalid list can reach [`Self::allows`].
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::NoritoSchema,
    IntoSchema,
    DeriveJsonSerialize,
)]
#[norito_schema(name = "iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1")]
#[norito(decode_from_slice)]
#[norito(validate = "Self::checked")]
pub struct CryptoAdmissionPolicyV1 {
    allowed_algorithms: Vec<Algorithm>,
}

mod json_admission;
pub use json_admission::{AdmittedCryptoAdmissionPolicy, CryptoPolicyJsonAdmissionError};

impl norito::json::JsonDeserialize for CryptoAdmissionPolicyV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        json_admission::decode_ordinary(parser)
    }
}

impl CryptoAdmissionPolicyV1 {
    /// The sole custom parameter carrying ordinary crypto admission authority.
    pub const PARAMETER_ID_STR: &'static str = "crypto_admission_policy_v1";

    /// Validate a caller-authored canonical list without sorting or deduplicating it.
    ///
    /// # Errors
    /// Rejects empty, oversized, repeated, or out-of-order algorithm lists.
    pub fn new(allowed_algorithms: Vec<Algorithm>) -> Result<Self, CryptoAdmissionPolicyError> {
        let policy = Self { allowed_algorithms };
        policy.validate()?;
        Ok(policy)
    }

    /// Identifier of the canonical parameter.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        Self::PARAMETER_ID_STR
            .parse()
            .expect("fixed valid parameter name")
    }

    /// Borrow the canonical allowed algorithm list.
    #[must_use]
    pub fn allowed_algorithms(&self) -> &[Algorithm] {
        &self.allowed_algorithms
    }

    /// Whether an ordinary signature or account controller may use this algorithm.
    #[must_use]
    pub fn allows(&self, algorithm: Algorithm) -> bool {
        self.allowed_algorithms.binary_search(&algorithm).is_ok()
    }

    /// Derive allowed controller curves without allocating or storing another policy.
    pub fn allowed_curves(&self) -> impl ExactSizeIterator<Item = CurveId> + '_ {
        self.allowed_algorithms
            .iter()
            .copied()
            .map(CurveId::from_algorithm)
    }

    /// Validate the exact list using canonical identities, never local capabilities.
    ///
    /// # Errors
    /// Rejects any list that is not a nonempty strictly ordered subset of the
    /// complete canonical algorithm registry.
    pub fn validate(&self) -> Result<(), CryptoAdmissionPolicyError> {
        if self.allowed_algorithms.is_empty() {
            return Err(CryptoAdmissionPolicyError::Empty);
        }
        if self.allowed_algorithms.len() > Algorithm::ALL.len() {
            return Err(CryptoAdmissionPolicyError::TooMany);
        }
        if self
            .allowed_algorithms
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(CryptoAdmissionPolicyError::NonCanonical);
        }
        Ok(())
    }

    // Binary decode hook runs after canonical decoding; any earlier resource
    // refusal returns untouched before this semantic check.
    fn checked(self) -> Result<Self, norito::Error> {
        self.validate()
            .map_err(|error| norito::Error::Message(error.to_string()))?;
        Ok(self)
    }

    /// Author the one canonical parameter; this is not an admission capability.
    ///
    /// # Errors
    /// Preserves the original canonical JSON writer or decoder refusal.
    pub fn into_parameter(self) -> Result<Parameter, norito::Error> {
        self.validate()
            .map_err(|error| norito::Error::Message(error.to_string()))?;
        Ok(Parameter::Custom(CustomParameter::new(
            Self::parameter_id(),
            Json::try_new(self)?,
        )))
    }

    /// Decode an original parameter payload and preserve its exact decoder cause.
    ///
    /// # Errors
    /// Returns the original Norito error on unfinished decoding, or a completed
    /// policy-validation error if decoding produced a noncanonical list.
    pub fn from_payload(payload: &Json) -> Result<Self, norito::Error> {
        let policy = payload.try_into_any_norito::<Self>()?;
        policy
            .validate()
            .map_err(|error| norito::Error::Message(error.to_string()))?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_all_algorithm_policy_roundtrips_without_backend_selection() {
        let policy = CryptoAdmissionPolicyV1::new(Algorithm::ALL.to_vec()).unwrap();
        let decoded = CryptoAdmissionPolicyV1::decode(&mut policy.encode().as_slice()).unwrap();
        assert_eq!(decoded, policy);
        let json = norito::json::to_json(&policy).unwrap();
        assert_eq!(
            norito::json::from_str::<CryptoAdmissionPolicyV1>(&json).unwrap(),
            policy
        );
        assert_eq!(
            policy
                .allowed_curves()
                .map(CurveId::algorithm)
                .collect::<Vec<_>>(),
            Algorithm::ALL
        );
        for algorithm in Algorithm::ALL {
            assert!(policy.allows(*algorithm));
        }
    }

    #[test]
    fn empty_duplicate_descending_and_oversized_policies_are_not_normalized() {
        assert_eq!(
            CryptoAdmissionPolicyV1::new(vec![]),
            Err(CryptoAdmissionPolicyError::Empty)
        );
        assert_eq!(
            CryptoAdmissionPolicyV1::new(vec![Algorithm::Ed25519; 2]),
            Err(CryptoAdmissionPolicyError::NonCanonical)
        );
        assert_eq!(
            CryptoAdmissionPolicyV1::new(vec![Algorithm::Secp256k1, Algorithm::Ed25519]),
            Err(CryptoAdmissionPolicyError::NonCanonical)
        );
        assert_eq!(
            CryptoAdmissionPolicyV1::new(vec![Algorithm::Ed25519; Algorithm::ALL.len() + 1]),
            Err(CryptoAdmissionPolicyError::TooMany)
        );
    }

    #[test]
    fn parameter_projection_validates_canonical_values_and_retains_missing_members() {
        let policy = CryptoAdmissionPolicyV1::new(vec![Algorithm::Secp256k1]).unwrap();
        assert!(!policy.allows(Algorithm::Ed25519));
        assert!(policy.allows(Algorithm::Secp256k1));
        let Parameter::Custom(parameter) = policy.clone().into_parameter().unwrap() else {
            unreachable!()
        };
        assert_eq!(parameter.id(), &CryptoAdmissionPolicyV1::parameter_id());
        assert_eq!(
            CryptoAdmissionPolicyV1::from_payload(parameter.payload()).unwrap(),
            policy
        );
        for json in [
            r#"{"allowed_algorithms":[]}"#,
            r#"{"allowed_algorithms":["ed25519","ed25519"]}"#,
            r#"{"allowed_algorithms":["unknown"]}"#,
            r#"{"allowed_algorithms":["ed25519"],"allowed_curves":[1]}"#,
        ] {
            let payload: Json = norito::json::from_str(json).unwrap();
            assert!(CryptoAdmissionPolicyV1::from_payload(&payload).is_err());
        }
    }
}

#[cfg(test)]
mod decoder_invariant_tests {
    use super::*;

    #[test]
    fn direct_binary_and_json_decoders_reject_noncanonical_lists() {
        for algorithms in [
            vec![],
            vec![Algorithm::Ed25519, Algorithm::Ed25519],
            vec![Algorithm::Secp256k1, Algorithm::Ed25519],
            vec![Algorithm::Ed25519; Algorithm::ALL.len() + 1],
        ] {
            // Module-private source fixture bypasses the constructor solely to
            // encode invalid input; no decoded policy or State authority is invented.
            let invalid = CryptoAdmissionPolicyV1 {
                allowed_algorithms: algorithms,
            };
            let bytes = norito::encode_canonical(&invalid).unwrap();
            assert!(norito::decode_canonical::<CryptoAdmissionPolicyV1>(&bytes).is_err());
            let bare = invalid.encode();
            assert!(CryptoAdmissionPolicyV1::decode(&mut bare.as_slice()).is_err());
            let json = norito::json::to_json(&invalid).unwrap();
            assert!(norito::json::from_str::<CryptoAdmissionPolicyV1>(&json).is_err());
        }
        for source in [
            r#"{"allowed_algorithms":["ed25519"],"allowed_algorithms":["secp256k1"]}"#,
            r#"{"allowed_algorithms":["ed25519"],"allowed_curves":[1]}"#,
            r#"{"allowed_algorithms":["unknown"]}"#,
        ] {
            assert!(norito::json::from_str::<CryptoAdmissionPolicyV1>(source).is_err());
        }
    }

    #[test]
    fn direct_policy_decoders_preserve_original_local_refusal_and_retry() {
        let policy = CryptoAdmissionPolicyV1::new(Algorithm::ALL.to_vec()).unwrap();
        let bytes = norito::encode_canonical(&policy).unwrap();
        let json = norito::json::to_json(&policy).unwrap();
        let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            0,
            usize::MAX,
        ));
        let binary = zero
            .with(|| {
                norito::core::classify_decode_attempt(|| {
                    norito::decode_canonical::<CryptoAdmissionPolicyV1>(&bytes)
                })
            })
            .unwrap_err();
        assert_eq!(
            binary.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert!(binary.local_refusal().is_some());
        let mut captured = None;
        let json_error = zero
            .with(|| {
                norito::core::classify_decode_attempt(|| {
                    norito::json::from_str::<CryptoAdmissionPolicyV1>(&json).map_err(|original| {
                        let original = original.into_core_error();
                        if let norito::Error::ScopedDecodeResource(scope) = &original {
                            captured = Some(scope.clone());
                        }
                        original
                    })
                })
            })
            .unwrap_err();
        assert_eq!(
            json_error.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert!(json_error.local_refusal().is_some());
        let norito::Error::ScopedDecodeResource(original) = json_error.error() else {
            panic!("the actual JSON reader must retain its original observer");
        };
        assert_eq!(Some(original), captured.as_ref());
        let replay =
            norito::core::classify_decode_attempt(|| Err::<(), _>(json_error.into_error()))
                .unwrap_err();
        assert_eq!(replay.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
        assert_eq!(
            norito::decode_canonical::<CryptoAdmissionPolicyV1>(&bytes).unwrap(),
            policy
        );
        assert_eq!(
            norito::json::from_str::<CryptoAdmissionPolicyV1>(&json).unwrap(),
            policy
        );
    }
}
