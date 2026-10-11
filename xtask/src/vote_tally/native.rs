//! Native fixed-witness arithmetic fixture. This is never an election relation.

use super::*;
use ff::{Field, PrimeField};
use iroha_data_model::{
    proof::{ProofBox, VerifyingKeyBox},
    zk::{BackendTag, NativePipaRProofV1, OpenVerifyEnvelope},
};
use iroha_pasta::{Eq, Fp, msm::MemoryBudget};
use iroha_plonk::{
    cs::{
        Advice, Column, ConstraintSystem, Expression, Instance, InstanceType, Rotation, Selector,
    },
    frontend::{Circuit, Error as CircuitError, Layouter, SimpleFloorPlanner, Value},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    prover::{ProverConfig, ProverRandomness, Witness, create_proof_owned},
    verifier::verify_full,
};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as NewRngCore, SeedableRng},
};
use rand_core_06::{CryptoRng, RngCore};

const BACKEND: &str = "pipa-r/pasta";
const CIRCUIT_ID: &str = "pipa-r/pasta/dev-vote-membership-v1";
const K: u32 = 6;

// Deliberately public deterministic stream for a public fixed-witness fixture.
// It is confined to this non-shipping module; production proving uses hedged
// entropy. The engine additionally binds recovery randomness to this witness.
struct FixtureRng(ChaCha20Rng);
impl RngCore for FixtureRng {
    fn next_u32(&mut self) -> u32 {
        NewRngCore::next_u32(&mut self.0)
    }
    fn next_u64(&mut self) -> u64 {
        NewRngCore::next_u64(&mut self.0)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        NewRngCore::fill_bytes(&mut self.0, dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for FixtureRng {}

#[derive(Clone)]
struct Config {
    limbs: [Column<Advice>; 3],
    instance: Column<Instance>,
    hash: Selector,
    boolean: Selector,
}
#[derive(Clone, Default)]
struct Membership {
    known: bool,
}
impl Circuit<Fp> for Membership {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let limbs = core::array::from_fn(|_| meta.advice_column());
        let instance = meta.instance_column(2);
        for column in limbs {
            meta.enable_equality(column);
        }
        meta.enable_equality(instance);
        let hash = meta.selector();
        let boolean = meta.selector();
        meta.create_gate("development membership compression", |meta| {
            let [left, right, output] = limbs.map(|c| meta.query_advice(c, Rotation::cur()));
            let pow5 = |v: Expression<Fp>| {
                let square = v.clone() * v.clone();
                square.clone() * square * v
            };
            let expected = pow5(left + Expression::Constant(Fp::from(7))) * Fp::from(2)
                + pow5(right + Expression::Constant(Fp::from(13))) * Fp::from(3);
            vec![meta.query_selector(hash) * (output - expected)]
        });
        meta.create_gate("development membership boolean", |meta| {
            let vote = meta.query_advice(limbs[0], Rotation::cur());
            vec![
                meta.query_selector(boolean)
                    * vote.clone()
                    * (vote - Expression::Constant(Fp::ONE)),
            ]
        });
        Config {
            limbs,
            instance,
            hash,
            boolean,
        }
    }
    fn synthesize(
        &self,
        config: Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), CircuitError> {
        let known = |v| {
            if self.known {
                Value::known(v)
            } else {
                Value::unknown()
            }
        };
        let (commitment, root) = layouter.assign_region(
            || "development membership",
            |mut region| {
                config.boolean.enable(&mut region, 0)?;
                let mut prior = None;
                let mut commitment = None;
                let mut value = Fp::ONE;
                for row in 0..9 {
                    config.hash.enable(&mut region, row)?;
                    let right = Fp::from(if row == 0 { 12345 } else { 19 + row as u64 });
                    let left = region
                        .assign_advice(config.limbs[0], row, known(value))?
                        .cell();
                    if let Some(previous) = prior {
                        region.constrain_equal(left, previous)?;
                    }
                    region.assign_advice(config.limbs[1], row, known(right))?;
                    value = compress(value, right);
                    let output = region
                        .assign_advice(config.limbs[2], row, known(value))?
                        .cell();
                    if row == 0 {
                        commitment = Some(output);
                    }
                    prior = Some(output);
                }
                Ok((
                    commitment.ok_or(CircuitError::Synthesis)?,
                    prior.ok_or(CircuitError::Synthesis)?,
                ))
            },
        )?;
        layouter.constrain_instance(commitment, config.instance, 0)?;
        layouter.constrain_instance(root, config.instance, 1)
    }
}

fn compress(left: Fp, right: Fp) -> Fp {
    Fp::from(2) * (left + Fp::from(7)).pow_vartime([5])
        + Fp::from(3) * (right + Fp::from(13)).pow_vartime([5])
}
fn public_values() -> [Fp; 2] {
    let commitment = compress(Fp::ONE, Fp::from(12345));
    let root = (20..28).fold(commitment, |prior, sibling| {
        compress(prior, Fp::from(sibling))
    });
    [commitment, root]
}

struct GeneratedBundle {
    summary: BundleSummary,
    key: Vec<u8>,
    proof: Vec<u8>,
}

fn generate() -> Result<GeneratedBundle, Box<dyn Error>> {
    let params = PinnedParams::<Eq>::derive(K)?;
    let circuit = Membership { known: true };
    let key = keygen_pk_v2(
        &params,
        &circuit.without_witnesses(),
        &KeygenConfigV2::pipa_r(vec![InstanceType::Field]),
    )?;
    let public = public_values();
    let instances = [public.to_vec()];
    let witness = Witness::from_circuit(&key, &circuit, &instances)?;
    let proof = create_proof_owned(
        &params,
        &key,
        witness,
        ProverRandomness::recovery(|context| {
            Ok::<_, ()>(FixtureRng(ChaCha20Rng::from_seed(*context)))
        }),
        ProverConfig::default(),
    )?;
    verify_full(
        &params,
        key.binding(),
        key.vk(),
        &instances,
        &proof,
        MemoryBudget::DEFAULT,
    )?;
    // Keep negative mathematical controls at the generator boundary as well as
    // the closed production-registry control below.
    for row in 0..2 {
        let mut changed = instances.clone();
        changed[0][row] += Fp::ONE;
        if verify_full(
            &params,
            key.binding(),
            key.vk(),
            &changed,
            &proof,
            MemoryBudget::DEFAULT,
        )
        .is_ok()
        {
            return Err("native development fixture lost its public binding".into());
        }
    }
    let vk_bytes =
        norito::encode_canonical(&iroha_core_zk::native_pipa_r::CompiledVerifyingKeyV1 {
            descriptor: key.binding().encoded().to_vec(),
            key: key.vk().to_bytes().to_vec(),
        })?;
    let vk = VerifyingKeyBox::new(BACKEND.into(), vk_bytes.clone());
    let vk_commitment = iroha_core_zk::hash_vk(&vk);
    let public_bytes = public.map(|value| value.to_repr());
    let envelope = OpenVerifyEnvelope {
        backend: BackendTag::NativePipaRPasta,
        circuit_id: CIRCUIT_ID.into(),
        vk_hash: vk_commitment,
        public_inputs: b"development-fixed-membership-v1".to_vec(),
        proof_bytes: norito::encode_canonical(&NativePipaRProofV1 {
            public_inputs: public_bytes.to_vec(),
            proof,
        })?,
        aux: Vec::new(),
    };
    let proof_bytes = norito::encode_canonical(&envelope)?;
    if iroha_core_zk::verify_backend(
        BACKEND,
        &ProofBox::new(BACKEND.into(), proof_bytes.clone()),
        Some(&vk),
    ) {
        return Err("development fixture unexpectedly admitted by production verifier".into());
    }
    let summary = BundleSummary {
        backend: BACKEND.into(),
        circuit_id: CIRCUIT_ID.into(),
        commit_hex: hex::encode(public_bytes[0]),
        root_hex: hex::encode(public_bytes[1]),
        public_inputs_hash_hex: hex::encode(iroha_hash(&public_bytes.concat())),
        vk_commit_hex: hex::encode(vk_commitment),
        vk_len: vk_bytes.len(),
        proof_len: proof_bytes.len(),
    };
    Ok(GeneratedBundle {
        summary,
        key: vk_bytes,
        proof: proof_bytes,
    })
}

pub(super) fn write_bundle(out_dir: &Path) -> Result<BundleSummary, Box<dyn Error>> {
    let GeneratedBundle {
        summary,
        key,
        proof,
    } = generate()?;
    fs::create_dir_all(out_dir)?;
    fs::write(out_dir.join("dev_vote_membership_vk.norito"), key)?;
    fs::write(out_dir.join("dev_vote_membership_proof.norito"), proof)?;
    let mut metadata = json::to_string_pretty(&summary_to_json(&summary))?;
    metadata.push('\n');
    fs::write(out_dir.join("dev_vote_membership_meta.json"), metadata)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_fixture_is_deterministic_and_canonical() {
        let GeneratedBundle {
            summary,
            key,
            proof,
        } = generate().unwrap();
        let GeneratedBundle {
            key: key_again,
            proof: proof_again,
            ..
        } = generate().unwrap();
        assert_eq!(key, key_again);
        assert_eq!(proof, proof_again);
        let envelope: OpenVerifyEnvelope = norito::decode_canonical(&proof).unwrap();
        assert_eq!(norito::encode_canonical(&envelope).unwrap(), proof);
        assert_eq!(
            summary.commit_hex,
            "20574662a58708e02e0000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            summary.root_hex,
            "b63752ff429362c3a9b3cd5966c23567fdb757ce3b38af724b9303a5ea2f5817"
        );
    }

    #[test]
    fn native_fixture_rejects_transcript_mutation_and_truncation() {
        let GeneratedBundle { proof, .. } = generate().unwrap();
        let outer: OpenVerifyEnvelope = norito::decode_canonical(&proof).unwrap();
        let inner: NativePipaRProofV1 = norito::decode_canonical(&outer.proof_bytes).unwrap();
        let params = PinnedParams::<Eq>::derive(K).unwrap();
        let key = keygen_pk_v2(
            &params,
            &Membership::default(),
            &KeygenConfigV2::pipa_r(vec![InstanceType::Field]),
        )
        .unwrap();
        let verify = |bytes: &[u8]| {
            verify_full(
                &params,
                key.binding(),
                key.vk(),
                &[public_values().to_vec()],
                bytes,
                MemoryBudget::DEFAULT,
            )
        };
        assert!(verify(&inner.proof).is_ok());
        for offset in [0, inner.proof.len() / 2, inner.proof.len() - 1] {
            let mut changed = inner.proof.clone();
            changed[offset] ^= 1;
            assert!(verify(&changed).is_err());
        }
        assert!(verify(&inner.proof[..inner.proof.len() - 1]).is_err());
        let mut trailing = inner.proof;
        trailing.push(0);
        assert!(verify(&trailing).is_err());
    }
}
