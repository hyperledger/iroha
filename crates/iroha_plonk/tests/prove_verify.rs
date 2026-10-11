//! Black-box prove/verify through the public API with production randomness
//! (the hedged and OS sources; fixed seeds are not available outside the
//! crate's unit tests): a range-checked accumulator chain on both curves,
//! verified in full, from bytes, by succinct accumulation then `decide`, and
//! in a batch. Rejections assert their exact typed reason.

use ff::Field;
use iroha_pasta::{Ep, Eq, PastaCurve, PastaField, msm::MemoryBudget, poseidon::PoseidonField};
use iroha_plonk::{
    BatchItem, IpaError, ProverConfig, ProverError, ProverRandomness, VerifyError, Witness,
    accumulate_succinct, batch_verify, create_proof,
    cs::{
        Advice, Column, ConstraintSystem, Instance, InstanceModeV1, ProofSuffixV1, Rotation,
        Selector, TableColumn, TranscriptV1,
    },
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
    keys::{KeygenConfig, keygen_pk},
    pcs::ipa::PinnedParams,
    verify_full, verify_full_from_bytes,
};

const K: u32 = 6;
const BUDGET: MemoryBudget = MemoryBudget::DEFAULT;

/// Columns of [`Accumulator`].
#[derive(Clone, Copy, Debug)]
struct Config {
    step: Column<Advice>,
    total: Column<Advice>,
    instance: Column<Instance>,
    running: Selector,
    range: Selector,
    table: TableColumn,
}

/// `total_{i+1} = total_i + step_i` with every step in `0..8`, the final
/// total public.
#[derive(Clone, Debug)]
struct Accumulator {
    steps: Vec<u64>,
}

impl Accumulator {
    fn total(&self) -> u64 {
        self.steps.iter().sum()
    }
}

impl<F: PastaField> Circuit<F> for Accumulator {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        let step = meta.advice_column();
        let total = meta.advice_column();
        let instance = meta.instance_column(1);
        meta.enable_equality(total);
        meta.enable_equality(instance);
        let running = meta.selector();
        let range = meta.complex_selector();
        let table = meta.lookup_table_column();
        meta.create_gate("running", |cells| {
            let enabled = cells.query_selector(running);
            let increment = cells.query_advice(step, Rotation::cur());
            let current = cells.query_advice(total, Rotation::cur());
            let next = cells.query_advice(total, Rotation::next());
            vec![enabled * (current + increment - next)]
        });
        meta.lookup("range", |cells| {
            let enabled = cells.query_selector(range);
            let step = cells.query_advice(step, Rotation::cur());
            vec![(enabled * step, table)]
        });
        Config {
            step,
            total,
            instance,
            running,
            range,
            table,
        }
    }

    fn synthesize(&self, config: Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "steps",
            |mut table| {
                for value in 0..8_u64 {
                    let row = usize::try_from(value).map_err(|_| Error::Synthesis)?;
                    table.assign_cell(
                        || "v",
                        config.table,
                        row,
                        || Value::known(F::from(value)),
                    )?;
                }
                Ok(())
            },
        )?;
        let last = layouter.assign_region(
            || "chain",
            |mut region| {
                let mut total = 0_u64;
                for (row, step) in self.steps.iter().enumerate() {
                    config.running.enable(&mut region, row)?;
                    region.enable_selector(|| "range", &config.range, row)?;
                    region.assign_advice(config.step, row, Value::known(F::from(*step)))?;
                    region.assign_advice(config.total, row, Value::known(F::from(total)))?;
                    total += step;
                }
                let last = region.assign_advice(
                    config.total,
                    self.steps.len(),
                    Value::known(F::from(total)),
                )?;
                Ok(last.cell())
            },
        )?;
        layouter.constrain_instance(last, config.instance, 0)
    }
}

fn round_trip<C: PastaCurve>(transcript: TranscriptV1, mode: InstanceModeV1)
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let circuit = Accumulator {
        steps: vec![3, 7, 0, 5, 1, 6],
    };
    let params = PinnedParams::<C>::derive(K).expect("params");
    let mut config = KeygenConfig::new(transcript);
    config.instance_mode = mode;
    config.proof_suffix = ProofSuffixV1::FoldedGenerator;
    let pk = keygen_pk(&params, &circuit, &config).expect("proving key");
    let instances = vec![vec![C::ScalarExt::from(circuit.total())]];
    let witness = Witness::from_circuit(&pk, &circuit, &instances).expect("witness");
    let hedged = create_proof(
        &params,
        &pk,
        &witness,
        ProverRandomness::hedged(),
        ProverConfig::default(),
    )
    .expect("proof");
    let os = create_proof(
        &params,
        &pk,
        &witness,
        ProverRandomness::os(),
        ProverConfig::default(),
    )
    .expect("proof");
    assert_ne!(hedged, os);
    for proof in [&hedged, &os] {
        assert_eq!(
            verify_full(&params, pk.binding(), pk.vk(), &instances, proof, BUDGET),
            Ok(())
        );
        assert_eq!(
            verify_full_from_bytes(
                &params,
                pk.binding().encoded(),
                pk.vk().to_bytes(),
                &instances,
                proof,
                BUDGET
            ),
            Ok(())
        );
        // Succinct accumulation is not a verdict; deciding it is.
        let accumulator =
            accumulate_succinct(&params, pk.binding(), pk.vk(), &instances, proof, BUDGET)
                .expect("succinct");
        assert_eq!(accumulator.decide(&params, BUDGET), Ok(()));
    }
    let item = |proof| BatchItem {
        params: &params,
        binding: pk.binding(),
        vk: pk.vk(),
        instances: &instances,
        proof,
    };
    assert_eq!(
        batch_verify(&[item(hedged.as_slice()), item(os.as_slice())], BUDGET),
        Ok(())
    );
    // Another public total: every message still decodes, but the transcript
    // (and so every challenge) changes. The appended folded generator was
    // folded under the original round challenges, so full verification
    // rejects it as not `<s(u), g>` before the equation (spec section 8,
    // step 9).
    let wrong = vec![vec![
        C::ScalarExt::from(circuit.total()) + C::ScalarExt::ONE,
    ]];
    assert_eq!(
        verify_full(&params, pk.binding(), pk.vk(), &wrong, &hedged, BUDGET),
        Err(VerifyError::Ipa(IpaError::FoldedGeneratorMismatch))
    );
    let mut trailing = hedged.clone();
    trailing.push(0);
    assert!(matches!(
        verify_full(
            &params,
            pk.binding(),
            pk.vk(),
            &instances,
            &trailing,
            BUDGET
        ),
        Err(VerifyError::ProofLength { .. })
    ));
    // An out-of-range step (9 is not in the table) synthesizes, and the
    // prover refuses it at the lookup permutation. (The verifier side of a
    // lookup violation is covered by the malicious-prover unit tests, which
    // skip this refusal.)
    let out_of_range = Accumulator {
        steps: vec![3, 9, 0, 5, 1, 4],
    };
    let witness = Witness::from_circuit(&pk, &out_of_range, &instances).expect("synthesizes");
    assert_eq!(
        create_proof(
            &params,
            &pk,
            &witness,
            ProverRandomness::hedged(),
            ProverConfig::default(),
        ),
        Err(ProverError::LookupInputMissing { lookup: 0 })
    );
}

#[test]
fn public_api_round_trips_on_both_curves() {
    round_trip::<Ep>(TranscriptV1::Blake2bChallenge255, InstanceModeV1::Committed);
    round_trip::<Eq>(TranscriptV1::KagemushaPoseidonRp57, InstanceModeV1::Direct);
}
