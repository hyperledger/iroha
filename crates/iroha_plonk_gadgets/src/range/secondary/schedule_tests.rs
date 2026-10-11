//! Replay width/order, shared-clone, filler, source-binding and shape tests.
use super::*;
use crate::{cells::SharedRows, range::RunningSumChip};
use ff::Field;
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::Instance,
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};

#[derive(Clone)]
struct ReplayCircuit<F: PastaField> {
    values: Vec<Value<F>>,
    fail: u8,
}
impl<F: PastaField> Circuit<F> for ReplayCircuit<F> {
    type Config = (
        SecondaryRangeConfig,
        RunningSumConfig,
        Column<Advice>,
        Column<Instance>,
    );
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            values: vec![Value::unknown(); self.values.len()],
            fail: self.fail,
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let ports = core::array::from_fn(|_| meta.advice_column());
        let bus = meta.advice_column();
        let source = meta.advice_column();
        meta.enable_equality(source);
        let phases = PhaseColumns::allocate_with_idle_ecc(meta);
        let primary = RunningSumConfig::configure_tagged(meta, bus);
        let secondary = SecondaryRangeConfig::configure(meta, ports, phases, primary).unwrap();
        let public = meta.instance_column(8);
        meta.enable_equality(public);
        (secondary, primary, source, public)
    }
    fn synthesize(
        &self,
        (secondary, primary, source, public): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let widths = vec![81, 93, 128, 87, 17, 105, 81, 128];
        let mut phases = vec![None; 180];
        phases[16..49].fill(Some(SecondaryPhase::Glue));
        phases[55..76].fill(Some(SecondaryPhase::Poseidon));
        phases[76..90].fill(Some(SecondaryPhase::PairedPoseidon));
        phases[110..122].fill(Some(SecondaryPhase::Glue));
        let plan = SecondaryPlan::new(widths.clone(), phases)?;
        let mut chip = RunningSumChip::with_shared_cursor(
            primary,
            &SharedRows::new(RowCursor::starting_at(16)),
        )
        .with_secondary_plan(secondary, plan)?;
        chip.load_table(&mut layouter)?;
        let result = layouter.assign_region(
            || "checked secondary replay",
            |mut region| {
                let mut out = Vec::new();
                for (i, (bits, value)) in widths.iter().zip(&self.values).enumerate() {
                    if self.fail == 1 && i == 7 {
                        break;
                    }
                    let word = assign_word(&mut region, source, i, *value)?;
                    let requested = if self.fail == 2 && i == 1 { 92 } else { *bits };
                    let checked = if i % 2 == 0 {
                        chip.range_check(&mut region, &word, requested)?
                    } else {
                        chip.clone().range_check(&mut region, &word, requested)?
                    };
                    // A repeated exact source check must hit the same synthesis-local
                    // certificate and consume no extra scheduled event.
                    assert_eq!(
                        chip.range_check(&mut region, &word, requested)?.cell(),
                        checked.cell()
                    );
                    out.push(word);
                }
                if self.fail == 4 {
                    chip.witness_range_checked(&mut region, Value::known(F::ZERO), 81)?;
                }
                chip.finish_secondary(&mut region)?;
                if self.fail == 3 {
                    chip.finish_secondary(&mut region)?;
                }
                Ok(out)
            },
        )?;
        for (i, word) in result.iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, i)?;
        }
        Ok(())
    }
}
fn test_plan() -> SecondaryPlan {
    let mut phases = vec![None; 180];
    phases[16..49].fill(Some(SecondaryPhase::Glue));
    phases[55..76].fill(Some(SecondaryPhase::Poseidon));
    phases[76..90].fill(Some(SecondaryPhase::PairedPoseidon));
    phases[110..122].fill(Some(SecondaryPhase::Glue));
    SecondaryPlan::new(vec![81, 93, 128, 87, 17, 105, 81, 128], phases).unwrap()
}
fn replay_case<F: PastaField>() {
    let widths = [81, 93, 128, 87, 17, 105, 81, 128];
    let values = widths
        .map(|bits| F::from(2).pow_vartime([bits]) - F::ONE)
        .to_vec();
    let circuit = ReplayCircuit {
        values: values.iter().copied().map(Value::known).collect(),
        fail: 0,
    };
    let public = [values.clone()];
    let report = check_circuit(&circuit, 16, &public, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let known = synthesize(&circuit, 16, Some(&public)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    for fail in 1..=4 {
        assert!(
            synthesize(
                &ReplayCircuit {
                    fail,
                    ..circuit.clone()
                },
                16,
                Some(&public)
            )
            .is_err()
        );
    }
    for (i, bits) in widths.into_iter().enumerate() {
        let mut bad = circuit.clone();
        let value = F::from(2).pow_vartime([bits]);
        bad.values[i] = Value::known(value);
        let mut inputs = values.clone();
        inputs[i] = value;
        assert!(
            !check_circuit(&bad, 16, &[inputs], CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
    for (column, assigned) in known.tables.advice_assigned().iter().enumerate() {
        for (row, present) in assigned.iter().enumerate() {
            // Dummy primary cells serve only to keep the shared lookup active;
            // changing a dummy digit within its valid range is intentionally
            // unconstrained by the application. All real range/copy roots and
            // every secondary cell remain in this mutation sweep.
            if *present && (column != 10 || test_plan().real_primary_rows().contains(&row)) {
                let report = crate::tamper::check_tampered(
                    &circuit,
                    16,
                    &public,
                    Some(crate::tamper::Tamper {
                        column,
                        row,
                        delta: F::ONE,
                    }),
                )
                .unwrap();
                assert!(!report.is_satisfied(), "unbound replay cell {column}/{row}");
            }
        }
    }
}
#[test]
fn checked_secondary_replay_fp() {
    replay_case::<Fp>();
}
#[test]
fn checked_secondary_replay_fq() {
    replay_case::<Fq>();
}
#[test]
fn secondary_schedule_rejects_invalid_capacity_and_widths() {
    assert!(SecondaryPlan::new(vec![128], vec![None; 17]).is_err());
    assert!(SecondaryPlan::new(vec![253], vec![None; 300]).is_err());
    assert!(SecondaryPlan::new(vec![81], vec![Some(SecondaryPhase::Glue); 100]).is_err());
    let phases = (0..100)
        .map(|row| {
            if row < 16 {
                None
            } else if row % 2 == 0 {
                Some(SecondaryPhase::Glue)
            } else {
                Some(SecondaryPhase::Poseidon)
            }
        })
        .collect();
    assert!(matches!(
        SecondaryPlan::new(vec![3], phases),
        Err(Error::BoundsFailure)
    ));
}

#[test]
fn secondary_schedule_requires_terminal_successor() {
    let mut phases = vec![None; 64];
    phases[16..].fill(Some(SecondaryPhase::Glue));
    assert!(matches!(
        SecondaryPlan::new(vec![81], phases),
        Err(Error::BoundsFailure)
    ));
}

fn native_replay<C: iroha_pasta::PastaCurve>() {
    use iroha_plonk::{
        ProverConfig, ProverRandomness, Witness, create_proof_owned,
        cs::InstanceType,
        keys::{KeygenConfigV2, keygen_pk_v2},
        pcs::ipa::PinnedParams,
    };
    let values = [81, 93, 128, 87, 17, 105, 81, 128]
        .map(|bits| C::ScalarExt::from(2).pow_vartime([bits]) - C::ScalarExt::ONE)
        .to_vec();
    let circuit = ReplayCircuit {
        values: values.iter().copied().map(Value::known).collect(),
        fail: 0,
    };
    let public = [values];
    let params = PinnedParams::<C>::derive(16).unwrap();
    let key = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]),
    )
    .unwrap();
    let proof = create_proof_owned(
        &params,
        &key,
        Witness::from_circuit(&key, &circuit, &public).unwrap(),
        ProverRandomness::os(),
        ProverConfig::default(),
    )
    .unwrap();
    iroha_plonk::verify_full(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &proof,
        iroha_pasta::msm::MemoryBudget::DEFAULT,
    )
    .unwrap();
    let mut wrong = public;
    wrong[0][2] += C::ScalarExt::ONE;
    assert!(
        iroha_plonk::verify_full(
            &params,
            key.binding(),
            key.vk(),
            &wrong,
            &proof,
            iroha_pasta::msm::MemoryBudget::DEFAULT
        )
        .is_err()
    );
}
#[test]
fn secondary_replay_native_both_curves() {
    native_replay::<iroha_pasta::Ep>();
    native_replay::<iroha_pasta::Eq>();
}
