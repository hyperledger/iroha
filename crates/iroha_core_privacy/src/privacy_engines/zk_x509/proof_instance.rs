//! Original public proof-instance custody for every dynamic X509 hash.

use crate::privacy_engines::transparent_stark::{
    PrivacyOuterProofFamilyV1, TransparentStarkDigestContextV1, TransparentStarkErrorV1,
    TransparentTranscriptV1,
};

/// Required public 32-byte nonce of one canonical X5S1 proof.
///
/// The honest constructor draws these bytes before any commitment, disjoint
/// from private masks. A verifier accepts every nonce value, including zero;
/// freshness cannot be established from an isolated proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ZkX509ProofInstanceV1([u8; 32]);
impl ZkX509ProofInstanceV1 {
    /// Retain the exact nonce bytes sampled by the prover or decoded from X5S1.
    pub const fn new_v1(nonce: [u8; 32]) -> Self {
        Self(nonce)
    }
    /// Consume exactly the next 32 checked bytes before any private mask draw.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn sample_v1<R: rand::TryCryptoRng + ?Sized>(
        rng: &mut crate::privacy_engines::prover_randomness::HealthCheckedTryCryptoRngV1<'_, R>,
    ) -> Result<Self, crate::privacy_engines::prover_randomness::TryCryptoProverRandomnessErrorV1>
    {
        use rand::TryRngCore as _;
        // Clear partial bytes on failure or unwind; the returned copy is public.
        let mut nonce = zeroize::Zeroizing::new([0_u8; 32]);
        rng.try_fill_bytes(nonce.as_mut())?;
        Ok(Self::new_v1(*nonce))
    }
    /// Exact public nonce serialized once in the outer credential envelope.
    pub const fn nonce_v1(self) -> [u8; 32] {
        self.0
    }
    pub(crate) const fn main_context_v1(self) -> TransparentStarkDigestContextV1 {
        TransparentStarkDigestContextV1::x509_scoped_v1(self.0, PrivacyOuterProofFamilyV1::Main)
    }
    pub(crate) const fn ca_context_v1(self) -> TransparentStarkDigestContextV1 {
        TransparentStarkDigestContextV1::x509_scoped_v1(self.0, PrivacyOuterProofFamilyV1::Ca)
    }
    pub(crate) const fn joint_context_v1(self) -> TransparentStarkDigestContextV1 {
        TransparentStarkDigestContextV1::x509_scoped_v1(self.0, PrivacyOuterProofFamilyV1::Joint)
    }
    pub(crate) fn check_local_transcript_v1(
        self,
        transcript: &TransparentTranscriptV1,
    ) -> Result<(), TransparentStarkErrorV1> {
        if transcript.context() == self.main_context_v1()
            || transcript.context() == self.ca_context_v1()
        {
            Ok(())
        } else {
            Err(TransparentStarkErrorV1::MalformedProof)
        }
    }
}
#[cfg(test)]
pub const TEST_PROOF_INSTANCE_V1: ZkX509ProofInstanceV1 = ZkX509ProofInstanceV1::new_v1([0x5a; 32]);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::prover_randomness::{
        HealthCheckedTryCryptoRngV1, TryCryptoProverRandomnessErrorV1,
    };
    use crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1;
    use iroha_data_model::privacy::PrivacyProtocolIdV1;
    use rand::{TryCryptoRng, TryRngCore};
    use std::{cell::RefCell, rc::Rc};

    #[derive(Debug)]
    struct InjectedEntropyFailure;
    impl core::fmt::Display for InjectedEntropyFailure {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("injected proof-instance entropy failure")
        }
    }

    struct RecordingRng {
        requests: Rc<RefCell<Vec<usize>>>,
        cursor: usize,
        fail_on: Option<usize>,
        panic_on_failure: bool,
        constant: bool,
    }
    impl RecordingRng {
        fn new(requests: Rc<RefCell<Vec<usize>>>) -> Self {
            Self {
                requests,
                cursor: 0,
                fail_on: None,
                panic_on_failure: false,
                constant: false,
            }
        }
        fn byte(index: usize) -> u8 {
            (index as u8).wrapping_mul(73).wrapping_add(11)
        }
    }
    impl TryRngCore for RecordingRng {
        type Error = InjectedEntropyFailure;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            panic!("the original health owner must request canonical byte blocks")
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            panic!("the original health owner must request canonical byte blocks")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            self.requests.borrow_mut().push(destination.len());
            if self.fail_on == Some(self.requests.borrow().len()) {
                for (index, byte) in destination.iter_mut().take(7).enumerate() {
                    *byte = Self::byte(self.cursor + index);
                }
                assert!(!self.panic_on_failure, "injected partial source unwind");
                return Err(InjectedEntropyFailure);
            }
            for byte in destination {
                *byte = if self.constant {
                    0x5a
                } else {
                    Self::byte(self.cursor)
                };
                self.cursor += 1;
            }
            Ok(())
        }
    }
    impl TryCryptoRng for RecordingRng {}

    #[test]
    fn nonce_consumes_exact_first_32_checked_bytes_before_disjoint_private_stream() {
        let requests = Rc::new(RefCell::new(Vec::new()));
        let mut source = RecordingRng::new(Rc::clone(&requests));
        let mut checked = HealthCheckedTryCryptoRngV1::new(&mut source).unwrap();
        assert_eq!(*requests.borrow(), [64]);
        let instance = ZkX509ProofInstanceV1::sample_v1(&mut checked).unwrap();
        assert_eq!(
            instance.nonce_v1(),
            core::array::from_fn(RecordingRng::byte)
        );
        assert_eq!(
            *requests.borrow(),
            [64],
            "the health prefix is consumed once"
        );
        let mut private = [0; 32];
        checked.try_fill_bytes(&mut private).unwrap();
        assert_eq!(
            private,
            core::array::from_fn(|i| RecordingRng::byte(32 + i))
        );
        assert_ne!(private, instance.nonce_v1());
        assert_eq!(*requests.borrow(), [64]);
        let mut next = [0; 17];
        checked.try_fill_bytes(&mut next).unwrap();
        assert_eq!(next, core::array::from_fn(|i| RecordingRng::byte(64 + i)));
        assert_eq!(*requests.borrow(), [64, 64]);
    }

    #[test]
    fn nonce_refill_failure_and_unwind_preserve_original_poison_without_source_reentry() {
        for panic_on_failure in [false, true] {
            let requests = Rc::new(RefCell::new(Vec::new()));
            let mut source = RecordingRng::new(Rc::clone(&requests));
            source.fail_on = Some(2);
            source.panic_on_failure = panic_on_failure;
            let mut checked = HealthCheckedTryCryptoRngV1::new(&mut source).unwrap();
            // Leave sixteen valid reservoir bytes so the nonce request crosses
            // an actual partial source failure after consuming its first half.
            checked.try_fill_bytes(&mut [0; 48]).unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ZkX509ProofInstanceV1::sample_v1(&mut checked)
            }));
            if panic_on_failure {
                assert!(result.is_err());
            } else {
                assert_eq!(
                    result.unwrap(),
                    Err(TryCryptoProverRandomnessErrorV1::Unavailable)
                );
            }
            assert_eq!(*requests.borrow(), [64, 64]);
            assert_eq!(
                ZkX509ProofInstanceV1::sample_v1(&mut checked),
                Err(TryCryptoProverRandomnessErrorV1::Unavailable)
            );
            let mut private = [0xa5; 32];
            assert_eq!(
                checked.try_fill_bytes(&mut private),
                Err(TryCryptoProverRandomnessErrorV1::Unavailable)
            );
            assert_eq!(private, [0; 32]);
            assert_eq!(
                *requests.borrow(),
                [64, 64],
                "poisoned owner must never reenter source"
            );
        }
    }

    #[test]
    fn unhealthy_or_unavailable_initial_entropy_never_mints_an_instance() {
        for unavailable in [false, true] {
            let requests = Rc::new(RefCell::new(Vec::new()));
            let mut source = RecordingRng::new(Rc::clone(&requests));
            source.constant = !unavailable;
            source.fail_on = unavailable.then_some(1);
            let result = HealthCheckedTryCryptoRngV1::new(&mut source)
                .and_then(|mut checked| ZkX509ProofInstanceV1::sample_v1(&mut checked));
            assert_eq!(
                result,
                Err(if unavailable {
                    TryCryptoProverRandomnessErrorV1::Unavailable
                } else {
                    TryCryptoProverRandomnessErrorV1::Unhealthy
                })
            );
            assert_eq!(*requests.borrow(), [64]);
        }
    }

    fn transcript(context: TransparentStarkDigestContextV1) -> TransparentTranscriptV1 {
        TransparentTranscriptV1::new(
            context,
            b"proof-instance-fixture",
            &PrivacyOuterDigestV1::from_bytes([3; 48]),
            &PrivacyOuterDigestV1::from_bytes([5; 48]),
        )
        .unwrap()
    }

    #[test]
    fn zero_nonce_and_each_family_have_distinct_contexts_and_foreign_scope_refuses() {
        let original = ZkX509ProofInstanceV1::new_v1([0; 32]);
        assert_eq!(original.nonce_v1(), [0; 32]);
        let contexts = [
            original.main_context_v1(),
            original.ca_context_v1(),
            original.joint_context_v1(),
        ];
        for (i, context) in contexts.iter().enumerate() {
            let local = transcript(*context);
            assert_eq!(original.check_local_transcript_v1(&local).is_ok(), i < 2);
            for other in &contexts[i + 1..] {
                assert_ne!(context, other);
                assert_ne!(local.state(), transcript(*other).state());
            }
        }
        for byte in 0..32 {
            let mut nonce = [0; 32];
            nonce[byte] = 1;
            let foreign = ZkX509ProofInstanceV1::new_v1(nonce);
            for context in [
                foreign.main_context_v1(),
                foreign.ca_context_v1(),
                foreign.joint_context_v1(),
            ] {
                let foreign_transcript = transcript(context);
                assert_eq!(
                    original.check_local_transcript_v1(&foreign_transcript),
                    Err(TransparentStarkErrorV1::MalformedProof)
                );
                for original_context in contexts {
                    assert_ne!(
                        foreign_transcript.state(),
                        transcript(original_context).state()
                    );
                }
            }
        }
        let unscoped = TransparentStarkDigestContextV1::new(
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            b"iroha-zk-x509-stark-p256-release-profile-v1",
        );
        assert_eq!(
            original.check_local_transcript_v1(&transcript(unscoped)),
            Err(TransparentStarkErrorV1::MalformedProof)
        );
    }
}
