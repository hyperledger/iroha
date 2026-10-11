//! Native PIPA-R proof fixtures for retained, non-admitted RAM-LFE experiments.

use iroha_pasta::{Eq, Fp, PastaField, msm::MemoryBudget};
use iroha_plonk::{
    ProvingKey,
    check::{CheckMode, CheckReport, check_circuit},
    cs::InstanceType,
    frontend::{Circuit, Error},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    prover::{ProverConfig, ProverRandomness, Witness, create_proof_owned},
    verifier::{VerifyError, verify_full},
};

pub(super) fn check<F: PastaField, C: Circuit<F>>(
    k: u32,
    circuit: &C,
    public: Vec<Vec<F>>,
) -> Result<CheckReport<F>, Error> {
    check_circuit(circuit, k, &public, CheckMode::Strict)
}

/// Test-only compiled native proof material; never registered or admitted.
pub(super) struct NativeProof {
    params: PinnedParams<Eq>,
    key: ProvingKey<Eq>,
}

impl NativeProof {
    pub(super) fn new<C: Circuit<Fp>>(k: u32, circuit: &C) -> Self {
        let params = PinnedParams::derive(k).expect("native parameters");
        let key = keygen_pk_v2(
            &params,
            &circuit.without_witnesses(),
            &KeygenConfigV2::pipa_r(vec![InstanceType::Field]),
        )
        .expect("native proving key");
        Self { params, key }
    }

    pub(super) fn key_bytes(&self) -> usize {
        self.key.vk().to_bytes().len()
    }

    pub(super) fn prove<C: Circuit<Fp>>(&self, circuit: C, public: &[Fp]) -> Vec<u8> {
        let witness =
            Witness::from_circuit(&self.key, &circuit, &[public.to_vec()]).expect("native witness");
        drop(circuit);
        create_proof_owned(
            &self.params,
            &self.key,
            witness,
            ProverRandomness::hedged(),
            ProverConfig::default(),
        )
        .expect("native PIPA-R proof")
    }

    pub(super) fn verify(&self, public: &[Fp], proof: &[u8]) -> Result<(), VerifyError> {
        verify_full(
            &self.params,
            self.key.binding(),
            self.key.vk(),
            &[public.to_vec()],
            proof,
            MemoryBudget::DEFAULT,
        )
    }
}
