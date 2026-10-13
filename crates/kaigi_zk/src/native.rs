//! Fixed native PIPA-R keys and consuming-witness proofs for the two Kaigi relations.
//!
//! Verifier initialization builds only the verifier key and descriptor. Key bytes
//! are exact compiled identities, never attacker-selected circuit programs.

use ff::PrimeField;
use iroha_pasta::{Eq, msm::MemoryBudget};
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

use crate::{
    Scalar,
    authorization_v1::{
        KAIGI_AUTHORIZATION_CIRCUIT_ID_V1, KAIGI_AUTHORIZATION_CIRCUIT_K_V1,
        KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1, KaigiAuthorizationCircuitV1,
        KaigiAuthorizationContextV1, KaigiAuthorizationPublicInputsV1, KaigiAuthorizationWitnessV1,
        compute_authorization_v1,
    },
    usage_v1::{
        KAIGI_USAGE_CIRCUIT_ID_V1, KAIGI_USAGE_CIRCUIT_K_V1, KAIGI_USAGE_INSTANCE_ROWS_V1,
        KaigiUsageCircuitV1, KaigiUsageContextV1, KaigiUsagePublicInputsV1, compute_usage_v1,
    },
};

/// Typed native producer failure retaining the original arithmetic or verifier cause.
#[derive(Debug)]
pub enum NativeProverError {
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

// Only successful immutable material enters the cache. A failed attempt keeps
// its typed cause and leaves a future call free to retry the same construction.
// Serialize first construction so concurrent requests do not duplicate key graphs.
fn cached_success<'a, T, E>(
    cache: &'a OnceLock<T>,
    gate: &Mutex<()>,
    initialize: impl FnOnce() -> Result<T, E>,
    poisoned: E,
) -> Result<&'a T, E> {
    if let Some(ready) = cache.get() {
        return Ok(ready);
    }
    let _guard = gate.lock().map_err(|_| poisoned)?;
    if let Some(ready) = cache.get() {
        return Ok(ready);
    }
    let ready = initialize()?;
    Ok(cache.get_or_init(|| ready))
}

/// One exact built-in Kaigi relation; no caller-selected circuit or domain size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRelationV1 {
    /// Complete role-aware participation authorization.
    Authorization,
    /// Original host opening and exact usage tuple.
    Usage,
}
impl NativeRelationV1 {
    /// Canonical first-release native circuit identity.
    pub const fn circuit_id(self) -> &'static str {
        match self {
            Self::Authorization => KAIGI_AUTHORIZATION_CIRCUIT_ID_V1,
            Self::Usage => KAIGI_USAGE_CIRCUIT_ID_V1,
        }
    }
    /// Fixed circuit-domain exponent of this compiled relation.
    pub const fn k(self) -> u32 {
        match self {
            Self::Authorization => KAIGI_AUTHORIZATION_CIRCUIT_K_V1,
            Self::Usage => KAIGI_USAGE_CIRCUIT_K_V1,
        }
    }
    /// Exact public column length.
    pub const fn instance_rows(self) -> usize {
        match self {
            Self::Authorization => KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1,
            Self::Usage => KAIGI_USAGE_INSTANCE_ROWS_V1,
        }
    }
    /// Immutable verifier material, initialized without a proving key.
    ///
    /// # Errors
    /// Parameter/key construction or local arithmetic admission failed; failed
    /// initialization is never cached.
    pub fn verifier(self) -> Result<&'static NativeVerifierV1, NativeVerifierInitError> {
        static AUTHORIZATION: OnceLock<NativeVerifierV1> = OnceLock::new();
        static AUTHORIZATION_GATE: Mutex<()> = Mutex::new(());
        static USAGE: OnceLock<NativeVerifierV1> = OnceLock::new();
        static USAGE_GATE: Mutex<()> = Mutex::new(());
        let (cache, gate) = match self {
            Self::Authorization => (&AUTHORIZATION, &AUTHORIZATION_GATE),
            Self::Usage => (&USAGE, &USAGE_GATE),
        };
        cached_success(
            cache,
            gate,
            || NativeVerifierV1::new(self),
            NativeVerifierInitError::CachePoisoned,
        )
    }
    /// Immutable proving material for this exact relation.
    ///
    /// # Errors
    /// Parameter/key construction failed or verifier/prover identities diverged.
    pub fn prover(self) -> Result<&'static NativeProverV1, NativeProverError> {
        static AUTHORIZATION: OnceLock<NativeProverV1> = OnceLock::new();
        static AUTHORIZATION_GATE: Mutex<()> = Mutex::new(());
        static USAGE: OnceLock<NativeProverV1> = OnceLock::new();
        static USAGE_GATE: Mutex<()> = Mutex::new(());
        let (cache, gate) = match self {
            Self::Authorization => (&AUTHORIZATION, &AUTHORIZATION_GATE),
            Self::Usage => (&USAGE, &USAGE_GATE),
        };
        cached_success(
            cache,
            gate,
            || NativeProverV1::new(self),
            NativeProverError::CachePoisoned,
        )
    }
}
fn key_config() -> KeygenConfigV2 {
    KeygenConfigV2::pipa_r(vec![InstanceType::Field])
}
fn invalid_input(error: impl std::fmt::Display) -> NativeProverError {
    NativeProverError::Input(error.to_string())
}

/// Complete verifier-only material for one fixed compiled Kaigi relation.
pub struct NativeVerifierV1 {
    relation: NativeRelationV1,
    params: PinnedParams<Eq>,
    binding: DescriptorBinding,
    vk: VerifyingKey<Eq>,
}
impl NativeVerifierV1 {
    fn new(relation: NativeRelationV1) -> Result<Self, NativeVerifierInitError> {
        let k = relation.k();
        let params = PinnedParams::<Eq>::derive(k).map_err(NativeVerifierInitError::Params)?;
        let (binding, vk) = match relation {
            NativeRelationV1::Authorization => keygen_vk_with_binding_v2(
                &params,
                &KaigiAuthorizationCircuitV1::default(),
                &key_config(),
            ),
            NativeRelationV1::Usage => {
                keygen_vk_with_binding_v2(&params, &KaigiUsageCircuitV1::default(), &key_config())
            }
        }
        .map_err(NativeVerifierInitError::Key)?;
        Ok(Self {
            relation,
            params,
            binding,
            vk,
        })
    }
    /// Canonical circuit descriptor, including transcript and public-input types.
    pub fn descriptor_bytes(&self) -> &[u8] {
        self.binding.encoded()
    }
    /// Exact processed native key bytes; the descriptor is a separate identity.
    pub fn key_bytes(&self) -> &[u8] {
        self.vk.to_bytes()
    }
    /// Exact transcript byte count fixed by the compiled descriptor.
    pub fn proof_length(&self) -> usize {
        Protocol::new(self.binding.descriptor())
            .expect("generated descriptor")
            .proof_length()
    }
    /// Verify canonical public scalars and the complete native opening proof.
    ///
    /// # Errors
    /// Wrong arity/length, noncanonical scalar, or the original native proof/IPA
    /// error. Local arithmetic refusal is retained and is not an invalidity verdict.
    pub fn verify(&self, public_inputs: &[[u8; 32]], proof: &[u8]) -> Result<(), VerifyError> {
        if public_inputs.len() != self.relation.instance_rows() {
            return Err(VerifyError::InstanceLength {
                column: 0,
                expected: self.relation.instance_rows(),
                found: public_inputs.len(),
            });
        }
        if proof.len() != self.proof_length() {
            return Err(VerifyError::ProofLength {
                expected: self.proof_length(),
                actual: proof.len(),
            });
        }
        let inputs = public_inputs
            .iter()
            .map(|bytes| {
                Option::<Scalar>::from(Scalar::from_repr(*bytes)).ok_or(VerifyError::Transcript(
                    iroha_plonk::transcript::TranscriptError::NonCanonicalScalar,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        verify_full(
            &self.params,
            &self.binding,
            &self.vk,
            &[inputs],
            proof,
            MemoryBudget::DEFAULT,
        )
    }
}

/// Public proving material with no retained private witness.
pub struct NativeProverV1 {
    verifier: &'static NativeVerifierV1,
    key: ProvingKey<Eq>,
}
impl NativeProverV1 {
    fn new(relation: NativeRelationV1) -> Result<Self, NativeProverError> {
        let verifier = relation.verifier().map_err(NativeProverError::Init)?;
        let key = match relation {
            NativeRelationV1::Authorization => keygen_pk_v2(
                &verifier.params,
                &KaigiAuthorizationCircuitV1::default(),
                &key_config(),
            ),
            NativeRelationV1::Usage => keygen_pk_v2(
                &verifier.params,
                &KaigiUsageCircuitV1::default(),
                &key_config(),
            ),
        }
        .map_err(NativeProverError::Key)?;
        if key.binding() != &verifier.binding || key.vk().to_bytes() != verifier.key_bytes() {
            return Err(NativeProverError::Invariant(
                "Kaigi proving/verifying key identity mismatch",
            ));
        }
        Ok(Self { verifier, key })
    }
    fn prove<C: Circuit<Scalar>>(
        &self,
        circuit: C,
        inputs: Vec<Scalar>,
    ) -> Result<NativeProofV1, NativeProverError> {
        let witness = Witness::from_circuit(&self.key, &circuit, std::slice::from_ref(&inputs))
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
        let public_inputs: Vec<_> = inputs.into_iter().map(|value| value.to_repr()).collect();
        self.verifier
            .verify(&public_inputs, &proof)
            .map_err(NativeProverError::Verify)?;
        Ok(NativeProofV1 {
            public_inputs,
            proof,
        })
    }
    /// Prove the authorization context and consume its owned secret.
    ///
    /// # Errors
    /// Wrong material kind, invalid context or native proving/verification failure.
    pub fn prove_authorization(
        &self,
        context: KaigiAuthorizationContextV1,
        witness: KaigiAuthorizationWitnessV1,
    ) -> Result<NativeProofV1, NativeProverError> {
        if self.verifier.relation != NativeRelationV1::Authorization {
            return Err(NativeProverError::Invariant("wrong Kaigi proving relation"));
        }
        let outputs = compute_authorization_v1(&context, &witness).map_err(invalid_input)?;
        let inputs = KaigiAuthorizationPublicInputsV1 { context, outputs }.instance();
        let circuit = KaigiAuthorizationCircuitV1::new(context, witness).map_err(invalid_input)?;
        self.prove(circuit, inputs.to_vec())
    }
    /// Prove the usage context and consume its owned host-opening secret.
    ///
    /// # Errors
    /// Wrong material kind, invalid context or native proving/verification failure.
    pub fn prove_usage(
        &self,
        context: KaigiUsageContextV1,
        witness: KaigiAuthorizationWitnessV1,
    ) -> Result<NativeProofV1, NativeProverError> {
        if self.verifier.relation != NativeRelationV1::Usage {
            return Err(NativeProverError::Invariant("wrong Kaigi proving relation"));
        }
        let outputs = compute_usage_v1(&context, &witness).map_err(invalid_input)?;
        let inputs = KaigiUsagePublicInputsV1 { context, outputs }.instance();
        let circuit = KaigiUsageCircuitV1::new(context, witness).map_err(invalid_input)?;
        self.prove(circuit, inputs.to_vec())
    }
}
/// A fully self-verified native proof and its exact public column.
pub struct NativeProofV1 {
    public_inputs: Vec<[u8; 32]>,
    proof: Vec<u8>,
}
impl NativeProofV1 {
    /// Move the exact public scalars and transcript into the caller's Norito envelope.
    pub fn into_parts(self) -> (Vec<[u8; 32]>, Vec<u8>) {
        (self.public_inputs, self.proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization_v1::KaigiAuthorizationActionV1;

    fn authorization() -> KaigiAuthorizationContextV1 {
        KaigiAuthorizationContextV1 {
            network_id: [1; 32],
            call_id: [2; 6],
            host_id: [3; 6],
            subject_id: [3; 6],
            participation_sequence: 0,
            action: KaigiAuthorizationActionV1::HostCreate,
            pre_roster_root: [4; 32],
        }
    }
    fn secret() -> KaigiAuthorizationWitnessV1 {
        let mut bytes = Scalar::from(99).to_repr();
        let witness = KaigiAuthorizationWitnessV1::take_blinding(&mut bytes).unwrap();
        assert_eq!(bytes, [0; 32]);
        witness
    }
    fn usage() -> KaigiUsageContextV1 {
        let context = authorization();
        KaigiUsageContextV1 {
            network_id: context.network_id,
            call_id: context.call_id,
            host_id: context.host_id,
            pre_roster_root: context.pre_roster_root,
            segment_index: 1,
            duration_ms: 1200,
            billed_gas: 34,
        }
    }
    #[test]
    fn cached_material_and_consuming_proofs_bind_exact_relations_and_bytes() {
        for relation in [NativeRelationV1::Authorization, NativeRelationV1::Usage] {
            let verifier = relation.verifier().unwrap();
            assert!(std::ptr::eq(verifier, relation.verifier().unwrap()));
            assert!(!verifier.key_bytes().is_empty());
            assert!(relation.circuit_id().starts_with("pipa-r/pasta/kaigi-"));
            let prover = relation.prover().unwrap();
            let proof = match relation {
                NativeRelationV1::Authorization => {
                    prover.prove_authorization(authorization(), secret())
                }
                NativeRelationV1::Usage => prover.prove_usage(usage(), secret()),
            }
            .unwrap();
            let (public, proof) = proof.into_parts();
            assert_eq!(public.len(), relation.instance_rows());
            assert_eq!(proof.len(), verifier.proof_length());
            verifier.verify(&public, &proof).unwrap();
            for row in 0..public.len() {
                let mut changed = public.clone();
                changed[row][0] ^= 1;
                assert!(verifier.verify(&changed, &proof).is_err());
            }
            let mut noncanonical = public.clone();
            noncanonical[0] = [255; 32];
            assert_eq!(
                verifier.verify(&noncanonical, &proof),
                Err(VerifyError::Transcript(
                    iroha_plonk::transcript::TranscriptError::NonCanonicalScalar
                ))
            );
            assert_eq!(
                verifier.verify(&public[1..], &proof),
                Err(VerifyError::InstanceLength {
                    column: 0,
                    expected: relation.instance_rows(),
                    found: public.len() - 1
                })
            );
            assert_eq!(
                verifier.verify(&public, &proof[1..]),
                Err(VerifyError::ProofLength {
                    expected: verifier.proof_length(),
                    actual: proof.len() - 1
                })
            );
            let mut trailing = proof.clone();
            trailing.push(0);
            assert!(verifier.verify(&public, &trailing).is_err());
            for index in [0, proof.len() / 2, proof.len() - 1] {
                let mut changed = proof.clone();
                changed[index] ^= 1;
                assert!(verifier.verify(&public, &changed).is_err());
            }
        }
    }
    #[test]
    fn wrong_proving_kind_and_invalid_context_are_rejected() {
        let auth = NativeRelationV1::Authorization.prover().unwrap();
        let usage_prover = NativeRelationV1::Usage.prover().unwrap();
        assert!(auth.prove_usage(usage(), secret()).is_err());
        assert!(
            usage_prover
                .prove_authorization(authorization(), secret())
                .is_err()
        );
        let mut invalid = authorization();
        invalid.participation_sequence = 1;
        assert!(auth.prove_authorization(invalid, secret()).is_err());
        let mut invalid = usage();
        invalid.duration_ms = 0;
        assert!(usage_prover.prove_usage(invalid, secret()).is_err());
        assert_ne!(auth.verifier.key_bytes(), usage_prover.verifier.key_bytes());
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
