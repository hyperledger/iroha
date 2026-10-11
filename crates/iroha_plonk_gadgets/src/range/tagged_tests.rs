//! Exact tuple tags, narrow roots, padding, boundary and assignment adversaries.

use super::*;
use ff::Field;
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check, check_circuit},
    cs::Instance,
    frontend::{Circuit, SimpleFloorPlanner, synthesize},
};

#[derive(Clone)]
struct Tagged<F: PastaField> {
    values: Vec<(usize, F)>,
    start: usize,
    known: bool,
}
impl<F: PastaField> Circuit<F> for Tagged<F> {
    type Config = (RunningSumConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = usize;
    fn params(&self) -> usize {
        self.values.len()
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, 1)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, count: usize) -> Self::Config {
        let advice = meta.advice_column();
        let range = RunningSumConfig::configure_tagged(meta, advice);
        let public = meta.instance_column(count);
        meta.enable_equality(public);
        meta.set_minimum_degree(9);
        (range, public)
    }
    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut chip = RunningSumChip::with_cursor(config, RowCursor::starting_at(self.start));
        chip.load_table(&mut layouter)?;
        let words = layouter.assign_region(
            || "tagged ranges",
            |mut region| {
                self.values
                    .iter()
                    .map(|(bits, value)| {
                        let shape = chip.shape(*bits)?;
                        assert_eq!(shape.rows, bits.div_ceil(15));
                        assert!(!shape.shifted());
                        let value = if self.known {
                            Value::known(*value)
                        } else {
                            Value::unknown()
                        };
                        chip.witness_range_checked(&mut region, value, *bits)
                    })
                    .collect::<Result<Vec<_>, _>>()
            },
        )?;
        for (row, word) in words.iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, row)?;
        }
        Ok(())
    }
}
fn public<F: PastaField>(circuit: &Tagged<F>) -> [Vec<F>; 1] {
    [circuit.values.iter().map(|(_, value)| *value).collect()]
}
fn assert_value<F: PastaField>(bits: usize, value: F, accepted: bool) {
    let circuit = Tagged {
        values: vec![(bits, value)],
        start: 0,
        known: true,
    };
    let report = check_circuit(&circuit, 16, &public(&circuit), CheckMode::Strict).unwrap();
    assert_eq!(
        report.is_satisfied(),
        accepted,
        "width={bits}, value={value:?}: {report:?}"
    );
}
fn bounds<F: PastaField>() {
    let values = (1..=252)
        .map(|bits| (bits, F::from(2).pow_vartime([bits as u64]) - F::ONE))
        .collect();
    let circuit = Tagged {
        values,
        start: 0,
        known: true,
    };
    let known = synthesize(&circuit, 16, Some(&public(&circuit))).unwrap();
    assert!(
        check(&known.cs, &known.tables, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    assert_eq!(known.cs.lookups().len(), 1);
    assert_eq!(known.cs.lookups()[0].input_expressions().len(), 2);
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    // Both table columns have the same first/default tuple, including the two
    // usable rows after the final genuine table tuple (3,7).
    let tables = known.tables.fixed();
    for row in [0, 65_528, 65_529] {
        assert_eq!(tables[0][row], F::ZERO);
        assert_eq!(tables[1][row], F::from(15));
    }
    assert_eq!(tables[0][65_527], F::from(7));
    assert_eq!(tables[1][65_527], F::from(3));
    drop(known);
    drop(unknown);
    for bits in 1..=15 {
        let limit = F::from(2).pow_vartime([bits as u64]);
        assert_value(bits, F::ZERO, true);
        assert_value(bits, limit, false);
        assert_value(bits, -F::ONE, false);
        // These would land in another interval if a scalar offset union were
        // incorrectly substituted for the authenticating (tag,value) tuple.
        let positive_alias = F::from((16 - bits as u64) << 15) + F::ONE;
        let wrapped_alias = -F::from((bits as u64 + 1) << 15) + F::ONE;
        assert_value(bits, positive_alias, false);
        assert_value(bits, wrapped_alias, false);
    }
    for bits in [87, 105, 128, 252] {
        assert_value(bits, F::from(2).pow_vartime([bits as u64]), false);
    }
}
#[test]
fn tagged_widths_bounds_cross_tag_aliases_and_table_padding_both_fields() {
    bounds::<Fp>();
    bounds::<Fq>();
}
fn tamper_and_boundary<F: PastaField>() {
    let circuit = Tagged {
        values: [1, 2, 3, 15, 16, 31, 87, 128, 252]
            .map(|bits| (bits, F::from(2).pow_vartime([bits as u64]) - F::ONE))
            .to_vec(),
        start: 0,
        known: true,
    };
    assert!(
        crate::tamper::undetected_tampers(&circuit, 16, &public(&circuit))
            .unwrap()
            .is_empty()
    );
    let boundary = Tagged {
        values: vec![(15, F::from(32767))],
        start: 65_529,
        known: true,
    };
    assert!(
        check_circuit(&boundary, 16, &public(&boundary), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let overflow = Tagged {
        values: vec![(16, F::from(65535))],
        ..boundary
    };
    assert!(synthesize(&overflow, 16, Some(&public(&overflow))).is_err());
    assert!(synthesize(&circuit, 15, Some(&public(&circuit))).is_err());
}
#[test]
fn tagged_every_cell_and_final_usable_row_both_fields() {
    tamper_and_boundary::<Fp>();
    tamper_and_boundary::<Fq>();
}

fn native<C: iroha_pasta::PastaCurve>() {
    use iroha_plonk::{
        ProverConfig, ProverRandomness, Witness, create_proof_owned,
        cs::InstanceType,
        keys::{KeygenConfigV2, keygen_pk_v2},
        pcs::ipa::PinnedParams,
    };
    let circuit = Tagged {
        values: [1, 2, 3, 15, 16, 87, 105, 128, 252]
            .map(|bits| {
                (
                    bits,
                    C::ScalarExt::from(2).pow_vartime([bits as u64]) - C::ScalarExt::ONE,
                )
            })
            .to_vec(),
        start: 0,
        known: true,
    };
    let public = public(&circuit);
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
    let mut forged = public;
    forged[0][0] += C::ScalarExt::ONE;
    assert!(
        iroha_plonk::verify_full(
            &params,
            key.binding(),
            key.vk(),
            &forged,
            &proof,
            iroha_pasta::msm::MemoryBudget::DEFAULT
        )
        .is_err()
    );
}

#[test]
fn tagged_native_proof_binds_tuple_lookup_and_public_values_both_curves() {
    native::<iroha_pasta::Ep>();
    native::<iroha_pasta::Eq>();
}
