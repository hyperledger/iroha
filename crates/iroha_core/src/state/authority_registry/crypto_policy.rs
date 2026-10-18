//! Deterministic cryptographic admission and IVM host policy from State.
//!
//! Transaction signature admission, controller registration and SM helper
//! selection inspect these values. The configured SM intrinsic policy and
//! OpenSSL preview flag select local implementations, which must produce the
//! same consensus result and are excluded from this projection.

use iroha_config::parameters::actual::Crypto;
use iroha_crypto::Algorithm;
use norito::{Decode, Encode, NoritoSchema};

/// Canonical first-release cryptographic policy projected from State config.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:crypto:v1")]
pub(super) struct CryptoAdmissionPolicyV1 {
    default_hash: String,
    allowed_signing: Vec<Algorithm>,
    sm2_distid_default: String,
    allowed_curve_ids: Vec<u8>,
}

impl CryptoAdmissionPolicyV1 {
    /// Borrow the fields that can change deterministic admission or host behavior.
    pub(super) fn from_actual(config: &Crypto) -> Self {
        let mut allowed_signing = config.allowed_signing.clone();
        allowed_signing.sort_unstable();
        allowed_signing.dedup();
        let mut allowed_curve_ids = config.allowed_curve_ids.clone();
        allowed_curve_ids.sort_unstable();
        allowed_curve_ids.dedup();
        Self {
            default_hash: config.default_hash.clone(),
            allowed_signing,
            sm2_distid_default: config.sm2_distid_default.clone(),
            allowed_curve_ids,
        }
    }
}

/// Fund only sorted references; variable leaves remain in the original policy.
pub(super) struct BorrowedCryptoPolicy<'a> {
    config: &'a Crypto,
    signing: super::policy_borrowed::SortedRefs<'a, Algorithm>,
    curves: super::policy_borrowed::SortedRefs<'a, u8>,
}
impl<'a> BorrowedCryptoPolicy<'a> {
    pub(super) fn new(
        config: &'a Crypto,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, super::policy_borrowed::OrderError> {
        use super::policy_borrowed::SortedRefs;
        Ok(Self {
            config,
            signing: SortedRefs::new_by(&config.allowed_signing, budget, Ord::cmp)?,
            curves: SortedRefs::new_by(&config.allowed_curve_ids, budget, Ord::cmp)?,
        })
    }
}
impl norito::SerializePayload for BorrowedCryptoPolicy<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        use super::policy_borrowed::{Payload, Ref, Seq, record};
        let curves = Payload(|writer: &mut norito::core::Encoder<'_>| {
            let values = self.curves.unique();
            norito::core::write_seq_len(
                writer,
                u64::try_from(values.len()).map_err(|_| norito::Error::LengthMismatch)?,
            )?;
            for value in values {
                writer.write_all(&[*value.0])?;
            }
            Ok(())
        });
        record!(
            Ref(&self.config.default_hash),
            Seq(self.signing.unique()),
            Ref(&self.config.sm2_distid_default),
            curves
        )
        .serialize(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::parameters::actual::SmIntrinsicsPolicy;

    fn policy() -> Crypto {
        Crypto {
            enable_sm_openssl_preview: false,
            sm_intrinsics: SmIntrinsicsPolicy::Auto,
            default_hash: "blake2b-256".to_owned(),
            allowed_signing: vec![Algorithm::Ed25519, Algorithm::Secp256k1],
            sm2_distid_default: "1234567812345678".to_owned(),
            allowed_curve_ids: vec![1, 2],
        }
    }

    fn frame(policy: &Crypto) -> Vec<u8> {
        super::super::policy_borrowed::assert_same_payload(
            &BorrowedCryptoPolicy::new(policy, &iroha_allocation::AllocationBudget::new(1 << 20))
                .unwrap(),
            &CryptoAdmissionPolicyV1::from_actual(policy),
        );
        norito::encode_canonical(&CryptoAdmissionPolicyV1::from_actual(policy)).unwrap()
    }

    #[test]
    fn crypto_admission_policy_roundtrips_with_explicit_v1_identity() {
        let projected = CryptoAdmissionPolicyV1::from_actual(&policy());
        assert_eq!(
            CryptoAdmissionPolicyV1::nominal_name(),
            "iroha:state:crypto:v1"
        );
        let encoded = norito::encode_canonical(&projected).unwrap();
        assert_eq!(
            norito::decode_canonical::<CryptoAdmissionPolicyV1>(&encoded).unwrap(),
            projected
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(norito::encode_canonical(&projected).unwrap(), encoded);
    }

    #[test]
    fn every_cryptographic_admission_input_changes_the_projection() {
        let baseline = policy();
        let expected = frame(&baseline);
        let mut changed = baseline.clone();
        changed.default_hash = "sm3-256".to_owned();
        assert_ne!(frame(&changed), expected, "default hash");
        let mut changed = baseline.clone();
        changed.allowed_signing.push(Algorithm::MlDsa);
        assert_ne!(frame(&changed), expected, "allowed signing algorithms");
        let mut changed = baseline.clone();
        changed.sm2_distid_default.push('x');
        assert_ne!(frame(&changed), expected, "SM2 distinguishing identifier");
        let mut changed = baseline;
        changed.allowed_curve_ids.push(3);
        assert_ne!(frame(&changed), expected, "allowed controller curves");
    }

    #[test]
    fn cryptographic_allow_lists_are_sets_and_backend_selection_is_local() {
        let baseline = policy();
        let expected = frame(&baseline);
        let mut reordered = baseline.clone();
        reordered.allowed_signing.reverse();
        reordered.allowed_signing.push(Algorithm::Ed25519);
        reordered.allowed_curve_ids.reverse();
        reordered.allowed_curve_ids.push(1);
        assert_eq!(frame(&reordered), expected);

        let mut local = baseline;
        local.sm_intrinsics = SmIntrinsicsPolicy::ForceDisable;
        local.enable_sm_openssl_preview = true;
        assert_eq!(frame(&local), expected);
    }
}
