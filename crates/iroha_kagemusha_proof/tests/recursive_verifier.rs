//! Actual sigma PIPA-R proofs checked by the recursive interpreter, with
//! known/unknown layout parity and isolated verifier resource inventories.

mod common;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{Mutation, SigmaRelation, sample_witness};
use iroha_pasta::{Eq, Fp, Fq, PastaAffine, PastaField, msm::MemoryBudget};
use iroha_plonk::{
    Protocol, VerifyingKey,
    check::{CheckMode, check},
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, Column, ConstraintSystem, CurveV1,
        DescriptorConfig, Instance, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV1,
        TranscriptV2,
    },
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    bytes::{
        element::{decode_le_element, le_message_segments},
        tape::{BytesChip, BytesConfig},
    },
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    codec::ScalarCells,
    verifier::{VerificationMode, VerifierChip, VerifierConfig, VerifierPlan},
};

#[derive(Clone)]
struct RecursiveSigma {
    plan: VerifierPlan<Eq>,
    key: VerifyingKey<Eq>,
    proof: Vec<u8>,
    statement: Fp,
    known: bool,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Eq>,
    bytes: BytesConfig,
    output: Column<Instance>,
}
impl RecursiveSigma {
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
}
impl Circuit<Fq> for RecursiveSigma {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = usize;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn params(&self) -> usize {
        4 + usize::from(self.plan.binding().descriptor().k)
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) -> Config {
        Self::configure_with_params(meta, 18)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fq>, outputs: usize) -> Config {
        let verifier = VerifierConfig::configure(meta);
        let primary = meta.advice_column();
        let secondary = meta.advice_column();
        let bytes = BytesConfig::configure(meta, primary, secondary);
        let output = meta.instance_column(outputs);
        meta.enable_equality(output);
        Config {
            verifier,
            bytes,
            output,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fq>) -> Result<(), Error> {
        let mut chip = VerifierChip::<Eq>::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "isolated sigma succinct verifier",
            |mut region| {
                let key = chip.constant_key(&mut region, &self.plan, &self.key)?;
                let input: Vec<_> = self.proof.iter().map(|byte| self.value(*byte)).collect();
                let run = bytes.run(
                    &mut region,
                    &input,
                    &vec![16; input.len() / 16],
                    &le_message_segments(0, input.len() / 32),
                )?;
                let mut proof = Vec::new();
                for index in 0..input.len() / 32 {
                    proof.push(decode_le_element(
                        &mut chip.uint(),
                        &mut region,
                        &run,
                        32 * index,
                    )?);
                }
                let [lo, hi] = foreign_limbs(&self.statement);
                let lo = chip.uint().assign::<128>(&mut region, self.value(lo))?;
                let hi = chip.uint().assign::<127>(&mut region, self.value(hi))?;
                let instance =
                    ScalarCells::<Eq>::from_limbs(&mut chip.uint(), &mut region, &lo, &hi)?;
                let length = chip
                    .uint()
                    .assign::<32>(&mut region, self.value(self.proof.len() as u128))?;
                let output = chip.verify(
                    &mut region,
                    &self.plan,
                    &key,
                    &[vec![instance]],
                    &proof,
                    &length,
                    VerificationMode::Hard,
                )?;
                let mut cells = vec![
                    output.valid.cell(),
                    output.key_digest.cell(),
                    output.claim.g().x().cell(),
                    output.claim.g().y().cell(),
                ];
                for challenge in output.claim.challenges() {
                    cells.push(challenge.native_word().ok_or(Error::Synthesis)?.cell());
                }
                Ok(cells)
            },
        )?;
        for (row, cell) in outputs.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.output, row)?;
        }
        Ok(())
    }
}

fn inventory(relation: SigmaRelation, source_k: u32) {
    let shape = common::pinned_shape(common::folded(relation), (source_k, 1));
    let prover = common::vesta_prover(shape);
    let witness = sample_witness::<Fp>(common::CHECK_SEED + 1, relation, Mutation::None);
    let proof = prover
        .prove(&witness, common::recovery(7))
        .expect("real sigma proof");
    let verifier = prover.verifier();
    verifier
        .verify(&proof.public, &proof.bytes)
        .expect("full sigma verification");
    let claim = accumulate_generator(
        prover.params(),
        verifier.binding(),
        verifier.vk(),
        &[vec![proof.public.statement]],
        &proof.bytes,
        MemoryBudget::DEFAULT,
    )
    .expect("native succinct claim");
    let plan =
        VerifierPlan::new(verifier.binding().clone(), prover.params().clone()).expect("plan");
    let circuit = RecursiveSigma {
        plan,
        key: verifier.vk().clone(),
        proof: proof.bytes,
        statement: proof.public.statement,
        known: true,
    };
    let (x, y) = claim.g().coordinates().unwrap();
    let key_digest = Fq::from_repr(verifier.verifying_key_digest().expect("digest")).unwrap();
    let mut instances = vec![Fq::ONE, key_digest, x, y];
    instances.extend(
        claim
            .challenges()
            .iter()
            .map(|value| Fq::from_canonical_limbs(value.to_canonical_limbs()).unwrap()),
    );
    let k = 16;
    let known = synthesize(&circuit, k, Some(&[instances])).expect("known sigma verifier fits k16");
    let report = check(&known.cs, &known.tables, CheckMode::Strict).expect("constraint check");
    assert!(report.is_satisfied(), "{report:?}");
    let unknown =
        synthesize(&circuit.without_witnesses(), k, None).expect("unknown sigma verifier fits k16");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let used_rows = known
        .tables
        .advice_assigned()
        .iter()
        .filter_map(|column| {
            column
                .iter()
                .rposition(|assigned| *assigned)
                .map(|row| row + 1)
        })
        .max()
        .unwrap_or(0);
    let cells: usize = known
        .tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().filter(|assigned| **assigned).count())
        .sum();
    let finalized = known.cs.finalize(known.tables.selectors(), true).unwrap();
    let layout = CircuitDescriptorV1::from_constraint_system(
        &finalized,
        DescriptorConfig {
            curve: CurveV1::Pallas,
            k,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: InstanceModeV1::Direct,
            proof_suffix: ProofSuffixV1::FoldedGenerator,
        },
    )
    .unwrap();
    let descriptor = CircuitDescriptorV2::from_layout(
        layout,
        TranscriptV2::KagemushaPoseidonRp57Base,
        vec![InstanceType::Field],
    )
    .unwrap();
    let protocol = Protocol::new(&descriptor).unwrap();
    let shape = protocol.shape();
    let vk_bytes = 10
        + 32 * (shape.num_fixed + shape.permutation_columns)
        + descriptor.selectors.entries.len() * shape.n.div_ceil(8);
    println!(
        "SIGMA_RECURSIVE_INVENTORY relation={} source_k={source_k} sigma_actual_bytes={} verifier_k={k} usable_rows={} advice_rows={used_rows} advice_cells={cells} advice={} fixed={} equality={} lookups={} degree={} descriptor_bytes={} estimated_vk_bytes={vk_bytes} estimated_proof_bytes={} verifier_proof_generated=false known_unknown_shape_equal=true",
        relation.label(),
        circuit.proof.len(),
        shape.usable_rows,
        shape.num_advice,
        shape.num_fixed,
        shape.permutation_columns,
        shape.lookups,
        shape.degree,
        descriptor.encode().unwrap().len(),
        protocol.proof_length()
    );
}

#[test]
#[ignore = "actual sigma proofs and full recursive verifier inventories; run in release"]
fn real_sigma_k12_and_k14_recursive_verifier_inventory() {
    inventory(SigmaRelation::SEND, 12);
    inventory(common::SEND_EVERY, 14);
}
