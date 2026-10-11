//! Archive result-schema completeness and every original opening word.

use super::*;
use ff::Field;
use iroha_pasta::{PastaAffine, poseidon::hash_with_domain};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
use iroha_plonk_recursion::{codec::ScalarCells, verifier::VerifierConfig};

fn groups() -> Vec<Vec<OperationTask>> {
    vec![
        vec![OperationTask::ArchiveOwnProof],
        vec![OperationTask::ArchiveProofs],
        vec![
            OperationTask::ArchiveRetainedPayment,
            OperationTask::ArchiveEvidence,
        ],
        vec![
            OperationTask::ArchiveSignatures,
            OperationTask::ArchiveAuthorization,
        ],
        vec![
            OperationTask::ArchiveEffects,
            OperationTask::ArchiveRetainedProofs,
            OperationTask::ArchiveCorePending,
            OperationTask::ArchiveLineagePending,
        ],
    ]
}
fn plan(variant: Variant) -> ArchiveResultPlan {
    ArchiveResultPlan::from_tasks(
        variant,
        &groups(),
        0,
        ArchiveResultPlan::context_spec(variant, 24).unwrap(),
    )
    .unwrap()
}
#[test]
fn archive_result_owners_require_every_named_task_and_terminal_effects() {
    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        let honest = plan(variant);
        assert_eq!(honest.owners, [1, 2, 3]);
        assert_eq!(
            honest.spec.capacity,
            if variant == Variant::ArchiveReceive {
                352
            } else {
                1472
            }
        );
        for (i, g) in groups().iter().enumerate() {
            for (j, task) in g.iter().enumerate() {
                let mut missing = groups();
                missing[i].remove(j);
                assert!(ArchiveResultPlan::from_tasks(variant, &missing, 0, honest.spec).is_err());
                let mut doubled = groups();
                doubled[i].push(*task);
                doubled[i].sort_unstable();
                assert!(ArchiveResultPlan::from_tasks(variant, &doubled, 0, honest.spec).is_err());
                let mut foreign = groups();
                foreign[i][j] = OperationTask::ReceiveEffects;
                foreign[i].sort_unstable();
                assert!(ArchiveResultPlan::from_tasks(variant, &foreign, 0, honest.spec).is_err());
            }
        }
        let mut wrong = groups();
        wrong.swap(1, 4);
        assert!(ArchiveResultPlan::from_tasks(variant, &wrong, 0, honest.spec).is_err());
        let mut wrong = groups();
        wrong[1].clear();
        wrong[4].insert(0, OperationTask::ArchiveProofs);
        assert!(ArchiveResultPlan::from_tasks(variant, &wrong, 0, honest.spec).is_err());
        let mut moved = groups();
        moved[1].clear();
        moved[0].insert(0, OperationTask::ArchiveProofs);
        let moved = ArchiveResultPlan::from_tasks(variant, &moved, 0, honest.spec).unwrap();
        assert_eq!(moved.owner(ArchiveResultTag::Proofs), 0);
        assert_ne!(moved, honest);
        let mut badspec = honest.spec;
        badspec.capacity += 32;
        assert!(ArchiveResultPlan::from_tasks(variant, &groups(), 0, badspec).is_err());
    }
    for variant in Variant::ALL {
        assert_eq!(
            ArchiveResultPlan::context_spec(variant, 24).is_ok(),
            matches!(variant, Variant::ArchiveReceive | Variant::ArchiveStatus)
        );
    }
    assert!(ArchiveResultPlan::context_spec(Variant::ArchiveStatus, 0).is_err());
}

#[test]
fn status_selection_requires_terminal_stage_and_preceding_original_proof_owner() {
    let status = plan(Variant::ArchiveStatus);
    assert!(status.require_status_selection(4, 5).is_ok());
    for stage in [0, 1, 2, 3, 5, u32::MAX] {
        assert!(status.require_status_selection(stage, 5).is_err());
    }
    for stage_count in [0, 1, 4, 6, usize::MAX] {
        assert!(status.require_status_selection(4, stage_count).is_err());
    }
    assert!(
        plan(Variant::ArchiveReceive)
            .require_status_selection(4, 5)
            .is_err()
    );
    for owner in [4, 5, u32::MAX] {
        let mut wrong = status;
        wrong.owners[ArchiveResultTag::Proofs as usize - 1] = owner;
        assert!(wrong.require_status_selection(4, 5).is_err());
    }
}

#[derive(Clone)]
struct Claims {
    variant: Variant,
    mask: u8,
    opening: bool,
    source_k: u32,
    limb: Option<usize>,
    point: bool,
    known: bool,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    public: Column<Instance>,
}
impl Circuit<Fp> for Claims {
    type Config = Config;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let public = meta.instance_column(3);
        meta.enable_equality(public);
        Config { verifier, public }
    }
    fn synthesize(&self, c: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(c.verifier);
        chip.load_tables(&mut layouter)?;
        let out = layouter.assign_region(
            || "Archive proposed results and original opening",
            |mut r| {
                let point = iroha_plonk::transcript::decode_point::<Ep>(
                    &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
                )
                .map_err(|_| Error::Synthesis)?;
                let point = if self.point {
                    -Ep::from(point)
                } else {
                    Ep::from(point)
                };
                let point = chip.constant_point(&mut r, &point)?;
                let challenges = (0..16)
                    .map(|i| {
                        let v = |x| {
                            if self.known {
                                Value::known(x)
                            } else {
                                Value::unknown()
                            }
                        };
                        let lo = chip
                            .uint()
                            .assign::<128>(&mut r, v(1 + u128::from(self.limb == Some(2 * i))))?;
                        let hi = chip
                            .uint()
                            .assign::<127>(&mut r, v(u128::from(self.limb == Some(2 * i + 1))))?;
                        ScalarCells::from_limbs(&mut chip.uint(), &mut r, &lo, &hi)
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                let original = FoldInputCells::from_normalized(
                    &mut chip,
                    &mut r,
                    self.source_k,
                    point,
                    challenges.try_into().map_err(|_| Error::Synthesis)?,
                )?;
                let proposed = ::core::array::from_fn(|i| {
                    if self.known {
                        Value::known(self.mask & (1 << i) != 0)
                    } else {
                        Value::unknown()
                    }
                });
                let claims = ArchiveResultClaims::assign(
                    &mut chip,
                    &mut r,
                    plan(self.variant),
                    proposed,
                    self.opening.then_some(&original),
                )?;
                Ok(claims.context().commitment_words())
            },
        )?;
        for (i, w) in out.iter().enumerate() {
            layouter.constrain_instance(w.cell(), c.public, i)?;
        }
        Ok(())
    }
}
impl Claims {
    fn public(&self) -> [Vec<Fp>; 1] {
        let p = plan(self.variant);
        let kind = if self.variant == Variant::ArchiveReceive {
            1
        } else {
            2
        };
        let mut words = vec![Fp::ONE, Fp::from(kind)];
        for tag in ArchiveResultTag::ALL {
            words.extend([Fp::from(tag as u64), Fp::from(u64::from(p.owner(tag)))]);
        }
        words.extend((0..3).map(|i| Fp::from(u64::from(self.mask & (1 << i) != 0))));
        if self.variant == Variant::ArchiveStatus {
            let point = iroha_plonk::transcript::decode_point::<Ep>(
                &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
            )
            .unwrap();
            let (x, y) = point.coordinates().unwrap();
            words.extend([Fp::from(16), x, y]);
            for _ in 0..16 {
                words.extend([Fp::ONE, Fp::ZERO]);
            }
        }
        let mut input = vec![
            Fp::from(u64::from(p.spec.tag)),
            Fp::from(words.len() as u64),
        ];
        input.extend(words);
        let digest = hash_with_domain(u64::from_le_bytes(*b"kgwciw_1"), &input);
        [vec![digest, Fp::from(u64::from(p.spec.capacity)), digest]]
    }
    fn accepts(&self, public: &[Vec<Fp>]) -> bool {
        check_circuit(self, 16, public, CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
}
#[test]
fn archive_result_commitment_binds_all_bits_and_every_original_opening_limb() {
    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        let c = Claims {
            variant,
            mask: 0,
            opening: variant == Variant::ArchiveStatus,
            source_k: 16,
            limb: None,
            point: false,
            known: true,
        };
        let public = c.public();
        assert!(c.accepts(&public));
        for mask in 1..8 {
            let changed = Claims { mask, ..c.clone() };
            assert!(changed.accepts(&changed.public()));
            assert!(!changed.accepts(&public));
        }
        assert!(
            !Claims {
                opening: !c.opening,
                ..c.clone()
            }
            .accepts(&public)
        );
        let known = synthesize(&c, 16, None).unwrap();
        let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        if variant == Variant::ArchiveStatus {
            for i in 0..32 {
                assert!(
                    !Claims {
                        limb: Some(i),
                        ..c.clone()
                    }
                    .accepts(&public),
                    "limb{i}"
                );
            }
            assert!(
                !Claims {
                    point: true,
                    ..c.clone()
                }
                .accepts(&public)
            );
            assert!(
                !Claims {
                    source_k: 15,
                    ..c.clone()
                }
                .accepts(&public)
            );
        }
    }
}

// Tests only the shared three-result/mode rule. These constructor metadata and
// proposed opening words never authenticate an Archive proof or map transition.
#[derive(Clone)]
struct MapVerdict {
    operation: AProofPlan,
    mask: u8,
    modes: Vec<[u64; 3]>,
    known: bool,
}
#[derive(Clone, Debug)]
struct VerdictConfig {
    verifier: VerifierConfig<Ep>,
    public: Column<Instance>,
}
impl Circuit<Fp> for MapVerdict {
    type Config = VerdictConfig;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> VerdictConfig {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        VerdictConfig { verifier, public }
    }
    fn synthesize(
        &self,
        config: VerdictConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let valid = layouter.assign_region(
            || "Archive adjusted map and terminal mode verdict",
            |mut region| {
                let variant = self.operation.frame().variant();
                let original = if variant == Variant::ArchiveStatus {
                    let point = iroha_plonk::transcript::decode_point::<Ep>(
                        &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
                    )
                    .map_err(|_| Error::Synthesis)?;
                    let point = chip.constant_point(&mut region, &Ep::from(point))?;
                    let one = chip.uint().glue().constant(&mut region, Fp::ONE)?;
                    let challenge =
                        ScalarCells::from_native_word(&mut chip.uint(), &mut region, &one)?;
                    Some(FoldInputCells::from_normalized(
                        &mut chip,
                        &mut region,
                        16,
                        point,
                        ::core::array::from_fn(|_| challenge.clone()),
                    )?)
                } else {
                    None
                };
                let proposed = ::core::array::from_fn(|i| {
                    if self.known {
                        Value::known(self.mask & (1 << i) != 0)
                    } else {
                        Value::unknown()
                    }
                });
                let claims = ArchiveResultClaims::assign(
                    &mut chip,
                    &mut region,
                    plan(variant),
                    proposed,
                    original.as_ref(),
                )?;
                let modes = self
                    .modes
                    .iter()
                    .map(|mode| {
                        let values = mode.map(|bit| {
                            if self.known {
                                Value::known(Fp::from(bit))
                            } else {
                                Value::unknown()
                            }
                        });
                        let words = chip
                            .uint()
                            .glue()
                            .witnesses(&mut region, &values)?
                            .try_into()
                            .map_err(|_| Error::Synthesis)?;
                        ModeCells::constrain(chip.uint().glue(), &mut region, &words)
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                claims.mode_verdict(&mut chip, &mut region, &self.operation, &modes)
            },
        )?;
        layouter.constrain_instance(valid.word().cell(), config.public, 0)
    }
}
impl MapVerdict {
    fn accepts(&self, expected: bool) -> bool {
        check_circuit(
            self,
            16,
            &[vec![Fp::from(u64::from(expected))]],
            CheckMode::Strict,
        )
        .is_ok_and(|report| report.is_satisfied())
    }
}

#[test]
fn corrected_claim_forces_adjusted_pending_noop_even_when_all_soft_results_are_true() {
    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        let (operation, _, _) = super::super::tests::operation(variant);
        let slots = if variant == Variant::ArchiveReceive {
            1
        } else {
            3
        };
        let accepted = MapVerdict {
            operation,
            mask: 7,
            modes: vec![[1, 0, 0]; slots],
            known: true,
        };
        assert!(accepted.accepts(true));
        assert!(!accepted.accepts(false));
        let discretionary = MapVerdict {
            modes: vec![[0, 1, 0]; slots],
            ..accepted.clone()
        };
        assert!(!discretionary.accepts(false));
        for slot in 0..slots {
            let mut corrected = discretionary.clone();
            corrected.modes[slot] = [0, 0, 1];
            assert!(corrected.accepts(false), "{variant:?} corrected slot{slot}");
            assert!(
                !corrected.accepts(true),
                "all-true soft results must not remove adjusted pending"
            );
            let known = synthesize(&corrected, 16, None).unwrap();
            let unknown = synthesize(&corrected.without_witnesses(), 16, None).unwrap();
            assert_eq!(known.tables.fixed(), unknown.tables.fixed());
            assert_eq!(known.tables.permutation(), unknown.tables.permutation());
            assert_eq!(
                known.tables.advice_assigned(),
                unknown.tables.advice_assigned()
            );
        }
        for mask in 0..7 {
            let failed = MapVerdict {
                mask,
                ..discretionary.clone()
            };
            assert!(failed.accepts(false));
            assert!(!failed.accepts(true));
        }
        if slots > 1 {
            let doubled = MapVerdict {
                modes: vec![[0, 0, 1]; slots],
                ..accepted
            };
            assert!(!doubled.accepts(false));
        }
    }
}
