//! Closed verifier-only/proving caches for the native confidential relations.

use super::relation::{Kind, NativeCircuit, Opening};
use crate::native_key_carrier::cached_success;
use ff::PrimeField;
use iroha_data_model::zk::NativePipaRProofV1;
use iroha_pasta::{Eq, Fp, msm::MemoryBudget};
use iroha_plonk::{
    DescriptorBinding, Protocol, ProvingKey, VerifyingKey,
    cs::InstanceType,
    frontend::Circuit,
    keys::{KeygenConfigV2, keygen_pk_v2, keygen_vk_with_binding_v2},
    pcs::ipa::PinnedParams,
    prover::{ProverConfig, ProverRandomness, Witness, create_proof_owned},
    verification_attempt::NativeVerifierInitError,
    verifier::{VerifyError, verify_full},
};
use std::sync::{Mutex, OnceLock};

/// Typed native producer failure retaining the original arithmetic or verifier cause.
#[derive(Debug)]
pub(crate) enum NativeProverError {
    /// Original verifier initialization failure.
    Init(NativeVerifierInitError),
    /// Original proving key construction failure.
    Key(iroha_plonk::keys::KeyError),
    /// Original witness or proof computation failure.
    Prove(iroha_plonk::prover::ProverError),
    /// Original self-verification failure, including local math refusal.
    Verify(iroha_plonk::verifier::VerifyError),
    /// Completed application input validation failure.
    Input(String),
    /// A completed compiled-material identity failure.
    Invariant(&'static str),
    /// A prior panic poisoned initialization; no prover was published.
    CachePoisoned,
}

impl std::fmt::Display for NativeProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init(original) => write!(f, "Init: {original}"),
            Self::Key(original) => write!(f, "Key: {original}"),
            Self::Prove(original) => write!(f, "Prove: {original}"),
            Self::Verify(original) => write!(f, "Verify: {original}"),
            Self::Input(original) => write!(f, "Input: {original}"),
            Self::Invariant(original) => write!(f, "Invariant: {original}"),
            Self::CachePoisoned => f.write_str("native material initialization lock is poisoned"),
        }
    }
}

impl std::error::Error for NativeProverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Init(original) => Some(original),
            Self::Key(original) => Some(original),
            Self::Prove(original) => Some(original),
            Self::Verify(original) => Some(original),
            Self::Input(_) => None,
            Self::Invariant(_) => None,
            Self::CachePoisoned => None,
        }
    }
}

const K: u32 = 13;
fn config() -> KeygenConfigV2 {
    KeygenConfigV2::pipa_r(vec![InstanceType::Field])
}
impl Kind {
    pub(super) fn verifier(self) -> Result<&'static Verifier, NativeVerifierInitError> {
        static TRANSFER: OnceLock<Verifier> = OnceLock::new();
        static TRANSFER_GATE: Mutex<()> = Mutex::new(());
        static FULL: OnceLock<Verifier> = OnceLock::new();
        static FULL_GATE: Mutex<()> = Mutex::new(());
        static CHANGE: OnceLock<Verifier> = OnceLock::new();
        static CHANGE_GATE: Mutex<()> = Mutex::new(());
        let (cache, gate) = match self {
            Self::Transfer => (&TRANSFER, &TRANSFER_GATE),
            Self::Full => (&FULL, &FULL_GATE),
            Self::Change => (&CHANGE, &CHANGE_GATE),
        };
        cached_success(
            cache,
            gate,
            || Verifier::new(self),
            NativeVerifierInitError::CachePoisoned,
        )
    }
    pub(super) fn prover(self) -> Result<&'static Prover, NativeProverError> {
        static TRANSFER: OnceLock<Prover> = OnceLock::new();
        static TRANSFER_GATE: Mutex<()> = Mutex::new(());
        static FULL: OnceLock<Prover> = OnceLock::new();
        static FULL_GATE: Mutex<()> = Mutex::new(());
        static CHANGE: OnceLock<Prover> = OnceLock::new();
        static CHANGE_GATE: Mutex<()> = Mutex::new(());
        let (cache, gate) = match self {
            Self::Transfer => (&TRANSFER, &TRANSFER_GATE),
            Self::Full => (&FULL, &FULL_GATE),
            Self::Change => (&CHANGE, &CHANGE_GATE),
        };
        cached_success(
            cache,
            gate,
            || Prover::new(self),
            NativeProverError::CachePoisoned,
        )
    }
}

pub(super) struct Verifier {
    kind: Kind,
    params: PinnedParams<Eq>,
    binding: DescriptorBinding,
    key: VerifyingKey<Eq>,
    carrier: Vec<u8>,
    proof_length: usize,
}
impl Verifier {
    fn new(kind: Kind) -> Result<Self, NativeVerifierInitError> {
        let params = PinnedParams::<Eq>::derive(K).map_err(NativeVerifierInitError::Params)?;
        let (binding, key) = match kind {
            Kind::Transfer => keygen_vk_with_binding_v2(
                &params,
                &NativeCircuit::<0, 16> { opening: None },
                &config(),
            ),
            Kind::Full => keygen_vk_with_binding_v2(
                &params,
                &NativeCircuit::<1, 16> { opening: None },
                &config(),
            ),
            Kind::Change => keygen_vk_with_binding_v2(
                &params,
                &NativeCircuit::<2, 16> { opening: None },
                &config(),
            ),
        }
        .map_err(NativeVerifierInitError::Key)?;
        let proof_length = Protocol::new(binding.descriptor())
            .map_err(NativeVerifierInitError::Protocol)?
            .proof_length();
        let carrier = crate::native_key_carrier::encode(binding.encoded(), key.to_bytes())?;
        Ok(Self {
            kind,
            params,
            binding,
            key,
            carrier,
            proof_length,
        })
    }
    pub(super) const fn proof_length(&self) -> usize {
        self.proof_length
    }
    pub(super) fn key_bytes(&self) -> &[u8] {
        &self.carrier
    }
    pub(super) fn verify(&self, public: &[[u8; 32]], proof: &[u8]) -> Result<(), VerifyError> {
        if public.len() != self.kind.rows() {
            return Err(VerifyError::InstanceLength {
                column: 0,
                expected: self.kind.rows(),
                found: public.len(),
            });
        }
        if proof.len() != self.proof_length {
            return Err(VerifyError::ProofLength {
                expected: self.proof_length,
                actual: proof.len(),
            });
        }
        let values = public
            .iter()
            .map(|bytes| {
                Option::<Fp>::from(Fp::from_repr(*bytes)).ok_or(VerifyError::Transcript(
                    iroha_plonk::transcript::TranscriptError::NonCanonicalScalar,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        verify_full(
            &self.params,
            &self.binding,
            &self.key,
            &[values],
            proof,
            MemoryBudget::DEFAULT,
        )
    }
}

pub(super) struct Prover {
    verifier: &'static Verifier,
    key: ProvingKey<Eq>,
}
impl Prover {
    fn new(kind: Kind) -> Result<Self, NativeProverError> {
        let verifier = kind.verifier().map_err(NativeProverError::Init)?;
        let key = match kind {
            Kind::Transfer => keygen_pk_v2(
                &verifier.params,
                &NativeCircuit::<0, 16> { opening: None },
                &config(),
            ),
            Kind::Full => keygen_pk_v2(
                &verifier.params,
                &NativeCircuit::<1, 16> { opening: None },
                &config(),
            ),
            Kind::Change => keygen_pk_v2(
                &verifier.params,
                &NativeCircuit::<2, 16> { opening: None },
                &config(),
            ),
        }
        .map_err(NativeProverError::Key)?;
        if key.binding() != &verifier.binding || key.vk().to_bytes() != verifier.key.to_bytes() {
            return Err(NativeProverError::Invariant(
                "native confidential proving/verifying identity mismatch",
            ));
        }
        Ok(Self { verifier, key })
    }
    pub(super) fn prove(
        &self,
        opening: Opening,
        public: Vec<Fp>,
    ) -> Result<NativePipaRProofV1, NativeProverError> {
        match self.verifier.kind {
            Kind::Transfer => self.prove_circuit(
                NativeCircuit::<0, 16> {
                    opening: Some(opening),
                },
                public,
            ),
            Kind::Full => self.prove_circuit(
                NativeCircuit::<1, 16> {
                    opening: Some(opening),
                },
                public,
            ),
            Kind::Change => self.prove_circuit(
                NativeCircuit::<2, 16> {
                    opening: Some(opening),
                },
                public,
            ),
        }
    }
    fn prove_circuit<C: Circuit<Fp>>(
        &self,
        circuit: C,
        public: Vec<Fp>,
    ) -> Result<NativePipaRProofV1, NativeProverError> {
        let witness = Witness::from_circuit(&self.key, &circuit, std::slice::from_ref(&public))
            .map_err(NativeProverError::Prove)?;
        drop(circuit);
        let proof = create_proof_owned(
            &self.verifier.params,
            &self.key,
            witness,
            ProverRandomness::hedged(),
            ProverConfig::default(),
        )
        .map_err(NativeProverError::Prove)?;
        let public: Vec<_> = public.into_iter().map(|v| v.to_repr()).collect();
        self.verifier
            .verify(&public, &proof)
            .map_err(NativeProverError::Verify)?;
        Ok(NativePipaRProofV1 {
            public_inputs: public,
            proof,
        })
    }
}

#[cfg(test)]
mod initialization_tests {
    use super::*;

    #[test]
    fn original_math_refusal_does_not_poison_success_cache() {
        let cache = OnceLock::<u8>::new();
        let gate = Mutex::new(());
        let refused = cached_success(
            &cache,
            &gate,
            || {
                MemoryBudget::new(0)
                    .check(17)
                    .map(|()| 7)
                    .map_err(|original| {
                        NativeVerifierInitError::Key(iroha_plonk::keys::KeyError::Msm(
                            iroha_pasta::msm::MsmError::Budget(original),
                        ))
                    })
            },
            NativeVerifierInitError::CachePoisoned,
        )
        .unwrap_err();
        assert!(matches!(refused, NativeVerifierInitError::Key(
            iroha_plonk::keys::KeyError::Msm(iroha_pasta::msm::MsmError::Budget(original)))
            if original.required == 17 && original.budget == 0));
        assert!(cache.get().is_none());
        let ready = cached_success(
            &cache,
            &gate,
            || Ok(7),
            NativeVerifierInitError::CachePoisoned,
        )
        .unwrap();
        let again = cached_success(
            &cache,
            &gate,
            || panic!("successful material must not be rebuilt"),
            NativeVerifierInitError::CachePoisoned,
        )
        .unwrap();
        assert_eq!(*ready, 7);
        assert!(std::ptr::eq(ready, again));
    }

    #[test]
    fn concurrent_initializers_publish_only_one_material_graph() {
        use std::sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        };
        let cache = OnceLock::<u8>::new();
        let gate = Mutex::new(());
        let barrier = Barrier::new(4);
        let attempts = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    barrier.wait();
                    let material = cached_success(
                        &cache,
                        &gate,
                        || {
                            attempts.fetch_add(1, Ordering::SeqCst);
                            Ok(9)
                        },
                        NativeVerifierInitError::CachePoisoned,
                    )
                    .unwrap();
                    assert_eq!(*material, 9);
                });
            }
        });
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn poisoned_initialization_gate_returns_typed_refusal_without_caching() {
        let cache = OnceLock::<u8>::new();
        let gate = Mutex::new(());
        assert!(
            std::panic::catch_unwind(|| {
                let _guard = gate.lock().unwrap();
                panic!("deliberate initializer panic");
            })
            .is_err()
        );
        let result = cached_success(
            &cache,
            &gate,
            || panic!("poisoned gate must refuse"),
            NativeVerifierInitError::CachePoisoned,
        );
        assert!(matches!(
            result,
            Err(NativeVerifierInitError::CachePoisoned)
        ));
        assert!(cache.get().is_none());
    }
}

#[cfg(test)]
mod carrier_initialization_tests {
    use super::*;

    #[test]
    fn original_decoder_refusal_leaves_initializer_cache_empty_and_same_carrier_can_retry() {
        let cache = OnceLock::<Vec<u8>>::new();
        let gate = Mutex::new(());
        let carrier = crate::native_pipa_r::CompiledVerifyingKeyV1 {
            descriptor: vec![17; 128],
            key: vec![23; 128],
        };
        let encoded = norito::encode_canonical(&carrier).unwrap();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        assert_eq!(
            norito::with_decode_limits_scope(limits, || norito::encode_canonical(&carrier))
                .unwrap(),
            encoded
        );
        // This initializer fixture exercises genuine reader refusal custody through the generic
        // success-only cache. Decoder limits deliberately do not constrain the canonical writer.
        // TODO: qualify actual native writer allocation refusal separately; this is decoder custody.
        let initialize = || {
            norito::core::classify_decode_attempt(|| {
                let decoded: crate::native_pipa_r::CompiledVerifyingKeyV1 =
                    norito::decode_canonical(&encoded)?;
                norito::encode_canonical(&decoded)
            })
            .map_err(NativeVerifierInitError::Codec)
        };
        let refused = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || {
                cached_success(
                    &cache,
                    &gate,
                    initialize,
                    NativeVerifierInitError::CachePoisoned,
                )
            },
        )
        .unwrap_err();
        let NativeVerifierInitError::Codec(original) = refused else {
            panic!("canonical reader lost its original typed refusal");
        };
        assert_eq!(
            original.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        let owner = original.local_refusal().unwrap();
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || {
                assert_eq!(original.local_refusal(), Some(owner.clone()));
            },
        );
        assert!(cache.get().is_none());
        let bytes = cached_success(
            &cache,
            &gate,
            initialize,
            NativeVerifierInitError::CachePoisoned,
        )
        .unwrap();
        assert_eq!(bytes, &norito::encode_canonical(&carrier).unwrap());
        assert!(std::ptr::eq(
            bytes,
            cached_success(
                &cache,
                &gate,
                || panic!("published carrier must not be rebuilt"),
                NativeVerifierInitError::CachePoisoned
            )
            .unwrap()
        ));
    }
}
