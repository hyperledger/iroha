//! Closed verifier-only/proving caches for the native confidential relations.

use super::relation::{Kind, NativeCircuit, Opening};
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
    verifier::verify_full,
};
use std::sync::OnceLock;

const K: u32 = 13;
fn config() -> KeygenConfigV2 {
    KeygenConfigV2::pipa_r(vec![InstanceType::Field])
}
fn message(error: impl std::fmt::Display) -> String {
    error.to_string()
}
impl Kind {
    pub(super) fn verifier(self) -> Result<&'static Verifier, String> {
        static TRANSFER: OnceLock<Result<Verifier, String>> = OnceLock::new();
        static FULL: OnceLock<Result<Verifier, String>> = OnceLock::new();
        static CHANGE: OnceLock<Result<Verifier, String>> = OnceLock::new();
        let cache = match self {
            Self::Transfer => &TRANSFER,
            Self::Full => &FULL,
            Self::Change => &CHANGE,
        };
        cache
            .get_or_init(|| Verifier::new(self))
            .as_ref()
            .map_err(Clone::clone)
    }
    pub(super) fn prover(self) -> Result<&'static Prover, String> {
        static TRANSFER: OnceLock<Result<Prover, String>> = OnceLock::new();
        static FULL: OnceLock<Result<Prover, String>> = OnceLock::new();
        static CHANGE: OnceLock<Result<Prover, String>> = OnceLock::new();
        let cache = match self {
            Self::Transfer => &TRANSFER,
            Self::Full => &FULL,
            Self::Change => &CHANGE,
        };
        cache
            .get_or_init(|| Prover::new(self))
            .as_ref()
            .map_err(Clone::clone)
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
    fn new(kind: Kind) -> Result<Self, String> {
        let params = PinnedParams::<Eq>::derive(K).map_err(message)?;
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
        .map_err(message)?;
        let proof_length = Protocol::new(binding.descriptor())
            .map_err(message)?
            .proof_length();
        let carrier = norito::encode_canonical(&crate::native_pipa_r::CompiledVerifyingKeyV1 {
            descriptor: binding.encoded().to_vec(),
            key: key.to_bytes().to_vec(),
        })
        .map_err(message)?;
        if carrier.len() > crate::native_pipa_r::MAX_KEY_BYTES {
            return Err("native confidential key exceeds registry cap".into());
        }
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
    pub(super) fn verify(&self, public: &[[u8; 32]], proof: &[u8]) -> Result<(), String> {
        if public.len() != self.kind.rows() || proof.len() != self.proof_length {
            return Err("wrong fixed confidential proof shape".into());
        }
        let values = public
            .iter()
            .map(|bytes| {
                Option::<Fp>::from(Fp::from_repr(*bytes))
                    .ok_or_else(|| "noncanonical confidential public scalar".to_owned())
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
        .map_err(message)
    }
}

pub(super) struct Prover {
    verifier: &'static Verifier,
    key: ProvingKey<Eq>,
}
impl Prover {
    fn new(kind: Kind) -> Result<Self, String> {
        let verifier = kind.verifier()?;
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
        .map_err(message)?;
        if key.binding() != &verifier.binding || key.vk().to_bytes() != verifier.key.to_bytes() {
            return Err("native confidential proving/verifying identity mismatch".into());
        }
        Ok(Self { verifier, key })
    }
    pub(super) fn prove(
        &self,
        opening: Opening,
        public: Vec<Fp>,
    ) -> Result<NativePipaRProofV1, String> {
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
    ) -> Result<NativePipaRProofV1, String> {
        let witness = Witness::from_circuit(&self.key, &circuit, std::slice::from_ref(&public))
            .map_err(message)?;
        drop(circuit);
        let proof = create_proof_owned(
            &self.verifier.params,
            &self.key,
            witness,
            ProverRandomness::hedged(),
            ProverConfig::default(),
        )
        .map_err(message)?;
        let public: Vec<_> = public.into_iter().map(|v| v.to_repr()).collect();
        self.verifier.verify(&public, &proof)?;
        Ok(NativePipaRProofV1 {
            public_inputs: public,
            proof,
        })
    }
}
