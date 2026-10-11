//! Exact committed-proof projection; raw-byte authentication belongs to its owner.

use super::*;
use crate::a_relation::archive::{stage::ArchiveStagePlan, tests::operation};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
use iroha_plonk_recursion::verifier::VerifierConfig;

#[derive(Clone)]
struct Projection {
    source: ContextPlan,
    projected: ContextPlan,
    claims: Vec<[Fp; 3]>,
    truncate: bool,
    known: bool,
}

impl Circuit<Fp> for Projection {
    type Config = (VerifierConfig<Ep>, Column<Instance>);
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let chip = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let public = meta.instance_column(6);
        meta.enable_equality(public);
        (chip, public)
    }

    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config);
        chip.load_tables(&mut layouter)?;
        let projected = layouter.assign_region(
            || "same retained proof claims across owners",
            |mut region| {
                let values = self
                    .claims
                    .iter()
                    .map(|row| {
                        row.map(|v| {
                            if self.known {
                                Value::known(v)
                            } else {
                                Value::unknown()
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                let mut objects =
                    self.source
                        .assign_archive_object_claims(&mut chip, &mut region, &values)?;
                if self.truncate {
                    objects.truncate(10);
                }
                Ok(
                    ArchiveRetainedProofs::from_context(&mut region, &self.projected, &objects)?
                        .context
                        .iter()
                        .flat_map(ContextObjectCells::commitment_words)
                        .collect::<Vec<_>>(),
                )
            },
        )?;
        for (row, word) in projected.iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, row)?;
        }
        Ok(())
    }
}

impl Projection {
    fn public(&self) -> Vec<Vec<Fp>> {
        vec![self.claims[9..11].iter().flatten().copied().collect()]
    }

    fn accepts(&self, public: &[Vec<Fp>]) -> bool {
        check_circuit(self, 16, public, CheckMode::Strict).is_ok_and(|report| report.is_satisfied())
    }
}

#[test]
fn committed_proof_projection_copies_all_words_and_requires_same_digest_and_schema() {
    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        let (operation, policy, _) = operation(variant);
        let source = ArchiveStagePlan::full(operation.clone(), policy)
            .unwrap()
            .context()
            .clone();
        let mut claims = source
            .object_specs()
            .iter()
            .enumerate()
            .map(|(i, spec)| {
                [
                    Fp::from(u64::try_from(i + 100).unwrap()),
                    Fp::from(u64::from(spec.capacity)),
                    Fp::from(u64::try_from(i + 200).unwrap()),
                ]
            })
            .collect::<Vec<_>>();
        claims[10][0] = claims[9][0];
        let honest = Projection {
            projected: source.clone(),
            source,
            claims,
            truncate: false,
            known: true,
        };
        assert!(honest.accepts(&honest.public()));
        for word in 0..6 {
            let mut public = honest.public();
            public[0][word] += Fp::ONE;
            assert!(!honest.accepts(&public), "unbound projected word {word}");
        }
        let mut changed = honest.clone();
        changed.claims[10][0] += Fp::ONE;
        assert!(
            !changed.accepts(&changed.public()),
            "distinct consuming digests"
        );
        let mut missing = honest.clone();
        missing.truncate = true;
        assert!(synthesize(&missing, 16, None).is_err());
        let mut specs = honest.source.object_specs().to_vec();
        specs[9].tag += 100;
        let mut foreign = honest.clone();
        foreign.projected =
            ContextPlan::with_schedule(operation, vec![vec![0], vec![1], vec![2]], Some(0), specs)
                .unwrap();
        assert!(
            synthesize(&foreign, 16, None).is_err(),
            "foreign proof slot schema"
        );
        let known = synthesize(&honest, 16, Some(&honest.public())).unwrap();
        let unknown = synthesize(&honest.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        // These are deliberately arbitrary proposed hashes, not authenticated
        // proof bytes. The separate mandatory owner must still derive them.
    }
}
