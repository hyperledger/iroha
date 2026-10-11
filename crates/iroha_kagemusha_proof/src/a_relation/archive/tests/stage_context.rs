//! Independent native/circuit checks for fixed-stage immutable context binding.

use super::{ArchiveStagePlan, Variant, operation};
use crate::a_relation::context::{ContextPlan, STAGE_DOMAIN};
use ff::{Field, PrimeField};
use group::{Curve, Group};
use iroha_pasta::{Ep, Fp, Fq, PastaAffine};
use iroha_plonk::{
    check::{CheckMode, check},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::statement::foreign_limbs;
use iroha_plonk_recursion::{
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    verifier::{VerifierChip, VerifierConfig},
};

#[derive(Clone)]
struct StageContext {
    plan: ContextPlan,
    stage: usize,
    context: Fp,
    point: Ep,
    challenges: [Fq; 16],
    source_k: u32,
    known: bool,
}

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    public: Column<Instance>,
}

impl Circuit<Fp> for StageContext {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        Config { verifier, public }
    }

    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let output = layouter.assign_region(
            || "fixed stage context",
            |mut region| {
                let value = |v| {
                    if self.known {
                        Value::known(v)
                    } else {
                        Value::unknown()
                    }
                };
                let context = chip
                    .uint()
                    .glue()
                    .witness(&mut region, value(self.context))?;
                let point = chip.witness_point(
                    &mut region,
                    if self.known {
                        Value::known(self.point)
                    } else {
                        Value::unknown()
                    },
                )?;
                let mut scalars = Vec::new();
                for scalar in self.challenges {
                    let [low, high] = foreign_limbs(&scalar);
                    let low = chip.uint().assign::<128>(
                        &mut region,
                        if self.known {
                            Value::known(low)
                        } else {
                            Value::unknown()
                        },
                    )?;
                    let high = chip.uint().assign::<127>(
                        &mut region,
                        if self.known {
                            Value::known(high)
                        } else {
                            Value::unknown()
                        },
                    )?;
                    scalars.push(ScalarCells::from_limbs(
                        &mut chip.uint(),
                        &mut region,
                        &low,
                        &high,
                    )?);
                }
                let carried = FoldInputCells::from_normalized(
                    &mut chip,
                    &mut region,
                    self.source_k,
                    point,
                    scalars.try_into().map_err(|_| Error::Synthesis)?,
                )?;
                self.plan
                    .stage_digest(&mut chip, &mut region, self.stage, &context, &carried)
            },
        )?;
        layouter.constrain_instance(output.cell(), config.public, 0)
    }
}

impl StageContext {
    fn public(&self) -> Vec<Vec<Fp>> {
        let (x, y) = self.point.to_affine().coordinates().unwrap();
        let mut words = vec![
            Fp::ONE,
            self.plan.schema()[1],
            Fp::from((self.stage + 1) as u64),
            self.context,
            Fp::from(u64::from(self.source_k)),
            x,
            y,
        ];
        for scalar in self.challenges {
            words.extend(foreign_limbs(&scalar).map(Fp::from_u128));
        }
        vec![vec![iroha_pasta::poseidon::hash_with_domain(
            u64::from_le_bytes(STAGE_DOMAIN),
            &words,
        )]]
    }

    fn accepts(&self, public: &[Vec<Fp>]) -> bool {
        synthesize(self, 16, Some(public)).is_ok_and(|layout| {
            check(&layout.cs, &layout.tables, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        })
    }
}

#[test]
fn fixed_stage_context_binds_current_claim_without_history() {
    let (operation, policy, _) = operation(Variant::ArchiveReceive);
    let plan = ArchiveStagePlan::full(operation, policy).unwrap();
    let mut source = StageContext {
        plan: plan.context().clone(),
        stage: 0,
        context: Fp::from(41),
        point: Ep::generator(),
        challenges: [Fq::ONE; 16],
        source_k: 16,
        known: true,
    };
    let mut prior_public = None;
    let mut prior_rows = None;
    for stage in 0..source.plan.stage_count() - 1 {
        source.stage = stage;
        let public = source.public();
        assert!(source.accepts(&public), "native parity at stage {stage}");
        if let Some(prior) = prior_public.replace(public.clone()) {
            assert!(
                !source.accepts(&prior),
                "previous stage digest cannot be reused"
            );
        }
        let known = synthesize(&source, 16, None).unwrap();
        let unknown = synthesize(&source.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        if let Some(prior) = prior_rows.replace(known.tables.advice_assigned().to_vec()) {
            assert_eq!(
                known.tables.advice_assigned(),
                prior,
                "stage index cannot grow the layout"
            );
        }
    }
    let public = source.public();
    let mut changed = source.clone();
    changed.context += Fp::ONE;
    assert!(!changed.accepts(&public));
    changed = source.clone();
    changed.point = -changed.point;
    assert!(!changed.accepts(&public));
    for index in 0..16 {
        for difference in [Fq::ONE, Fq::from(2).pow_vartime([128])] {
            changed = source.clone();
            changed.challenges[index] += difference;
            assert!(!changed.accepts(&public), "challenge {index}");
        }
    }
    let (operation, policy, _) = super::operation(Variant::ArchiveStatus);
    changed = source.clone();
    changed.plan = ArchiveStagePlan::full(operation, policy)
        .unwrap()
        .context()
        .clone();
    assert!(
        !changed.accepts(&public),
        "another variant cannot reuse D_i"
    );
    for stage in [
        source.plan.stage_count() - 1,
        source.plan.stage_count(),
        usize::MAX,
    ] {
        changed = source.clone();
        changed.stage = stage;
        assert!(!changed.accepts(&public), "terminal/unknown internal stage");
    }
    changed = source;
    changed.source_k = 15;
    changed.challenges[0] = Fq::ZERO;
    assert!(
        !changed.accepts(&public),
        "short source cannot be a carried P claim"
    );
}
