//! A uniform fold schema binds k12/k14/k16 sigma parts without relabelling,
//! omitted transcript metadata or witness-dependent circuit shape.

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{Ep, Eq, PastaAffine, PastaCurve, msm::MemoryBudget};
use iroha_plonk::{
    check::{CheckMode, check},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::{
    bytes::{
        element::{decode_le_element, le_message_segments},
        tape::{BytesChip, BytesConfig},
    },
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    AccumulatorT, FOLD_WITNESS_BYTES, FoldConfig, FoldInput,
    accumulation_circuit::{FoldInputCells, FoldPlan, FoldSource},
    codec::ScalarCells,
    create_fold,
    verifier::{VerificationMode, VerifierChip, VerifierConfig},
};
#[derive(Clone)]
struct Choice<C: PastaCurve> {
    plan: FoldPlan<C>,
    claim: FoldInput<C>,
    source_k: u32,
    proof: [u8; FOLD_WITNESS_BYTES],
    trivial: AccumulatorT<C>,
    known: bool,
}
#[derive(Clone, Debug)]
struct Config<C: PastaCurve> {
    verifier: VerifierConfig<C>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl<C: PastaCurve> Choice<C> {
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn public(&self, output: &AccumulatorT<C>) -> Vec<C::Base> {
        let (x, y) = output.g().coordinates().unwrap();
        let mut values = vec![C::Base::from(u64::from(self.source_k)), x, y];
        for challenge in output.challenges() {
            values.extend(foreign_limbs(challenge).map(C::Base::from_u128));
        }
        values
    }
}
impl<C: PastaCurve> Circuit<C::Base> for Choice<C> {
    type Config = Config<C>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
        let (verifier, bytes) = VerifierConfig::configure_with_byte_tape(meta, FOLD_WITNESS_BYTES);
        let public = meta.instance_column(35);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::Base>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "dynamic sigma source",
            |mut region| {
                let values = self
                    .proof
                    .iter()
                    .map(|byte| self.value(*byte))
                    .collect::<Vec<_>>();
                let run = bytes.run(
                    &mut region,
                    &values,
                    &vec![16; FOLD_WITNESS_BYTES / 16],
                    &le_message_segments(0, FOLD_WITNESS_BYTES / 32),
                )?;
                let messages = (0..FOLD_WITNESS_BYTES / 32)
                    .map(|i| decode_le_element(&mut chip.uint(), &mut region, &run, 32 * i))
                    .collect::<Result<Vec<_>, _>>()?;
                let source = chip.uint().glue().witness(
                    &mut region,
                    self.value(C::Base::from(u64::from(self.source_k))),
                )?;
                let point =
                    chip.witness_point(&mut region, self.value(self.claim.g().to_curve()))?;
                let mut challenges = Vec::new();
                for challenge in self.claim.challenges() {
                    let [lo, hi] = foreign_limbs(challenge);
                    let lo = chip.uint().assign::<128>(&mut region, self.value(lo))?;
                    let hi = chip.uint().assign::<127>(&mut region, self.value(hi))?;
                    challenges.push(ScalarCells::from_limbs(
                        &mut chip.uint(),
                        &mut region,
                        &lo,
                        &hi,
                    )?);
                }
                let part = FoldInputCells::from_sigma_part(
                    &mut chip,
                    &mut region,
                    &source,
                    point,
                    challenges.try_into().map_err(|_| Error::Synthesis)?,
                )?;
                let trivial = chip.constant_point(&mut region, &self.trivial.g().to_curve())?;
                let lo = chip.uint().constant::<128>(&mut region, 1)?;
                let hi = chip.uint().constant::<127>(&mut region, 0)?;
                let one = ScalarCells::from_limbs(&mut chip.uint(), &mut region, &lo, &hi)?;
                let trivial = FoldInputCells::from_normalized(
                    &mut chip,
                    &mut region,
                    16,
                    trivial,
                    core::array::from_fn(|_| one.clone()),
                )?;
                let length = chip.uint().constant::<32>(&mut region, 1120)?;
                let output = chip.verify_fold(
                    &mut region,
                    &self.plan,
                    &[part, trivial],
                    &messages,
                    &length,
                    VerificationMode::Hard,
                )?;
                let mut out = vec![
                    source.cell(),
                    output.claim.g().x().cell(),
                    output.claim.g().y().cell(),
                ];
                for value in output.claim.challenges() {
                    out.extend([value.lo().cell(), value.hi().cell()]);
                }
                Ok(out)
            },
        )?;
        for (row, cell) in out.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.public, row)?;
        }
        Ok(())
    }
}
fn run<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(16).unwrap();
    let trivial = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let plan = FoldPlan::with_sources(
        &params,
        vec![FoldSource::SigmaChoice, FoldSource::Fixed(16)],
    )
    .unwrap();
    assert_eq!(FoldSource::SigmaChoice.original_k(), None);
    let mut fixed = None;
    for k in [12, 14, 16] {
        let g = params.params().g()[..1 << k]
            .iter()
            .fold(C::identity(), |sum, p| sum + p.to_curve())
            .to_affine();
        let claim = FoldInput::from_opening(g, &vec![C::ScalarExt::ONE; k]).unwrap();
        let (proof, output) = create_fold(
            &params,
            &[claim.clone(), trivial.as_input()],
            C::Base::from(23).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        let circuit = Choice {
            plan: plan.clone(),
            claim,
            source_k: u32::try_from(k).unwrap(),
            proof: proof.to_bytes(),
            trivial: trivial.clone(),
            known: true,
        };
        let public = vec![circuit.public(&output)];
        let assigned = synthesize(&circuit, 16, Some(&public)).unwrap();
        assert!(
            check(&assigned.cs, &assigned.tables, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
        assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
        assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
        let shape = (
            assigned.tables.fixed().to_vec(),
            assigned.tables.selectors().to_vec(),
            assigned.tables.permutation().clone(),
            assigned.tables.advice_assigned().to_vec(),
        );
        if let Some(expected) = &fixed {
            assert_eq!(&shape, expected, "all source choices use one circuit shape");
        } else {
            fixed = Some(shape);
        }
        for wrong in [0, 13, if k == 16 { 12 } else { 16 }] {
            let mut bad = circuit.clone();
            bad.source_k = wrong;
            let values = vec![bad.public(&output)];
            let assigned = synthesize(&bad, 16, Some(&values)).unwrap();
            assert!(
                !check(&assigned.cs, &assigned.tables, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
        let mut wrong = circuit.clone();
        wrong.proof[0] ^= 1;
        let assigned = synthesize(&wrong, 16, Some(&public)).unwrap();
        assert!(
            !check(&assigned.cs, &assigned.tables, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
}
#[test]
#[ignore = "full k16 folds on both curves; run in release"]
fn sigma_source_choice_binds_prefix_transcript_and_one_shape() {
    run::<Ep>();
    run::<Eq>();
}
