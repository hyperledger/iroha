//! Integer range, forgery, layout, and every-cell checks on both Pasta fields.

use super::*;
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};

#[derive(Clone)]
struct Circuit15<F: PastaField> {
    value: Value<F>,
    forged: Option<[F; 8]>,
}
impl<F: PastaField> Circuit<F> for Circuit15<F> {
    type Config = Algebraic15Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            value: Value::unknown(),
            forged: self.forged,
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let columns = core::array::from_fn(|_| meta.advice_column());
        Algebraic15Config::configure(meta, columns)
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "algebraic range and copied range",
            |mut region| {
                if let Some(digits) = self.forged {
                    region.assign_advice(config.columns[0], 0, self.value)?;
                    for (column, digit) in config.columns[1..].iter().zip(digits) {
                        region.assign_advice(*column, 0, Value::known(digit))?;
                    }
                    config.enabled.enable(&mut region, 0)?;
                } else {
                    let mut chip = Algebraic15Chip::with_cursor(config, RowCursor::starting_at(0));
                    let assigned = chip.assign(&mut region, self.value)?;
                    chip.range_check(&mut region, assigned.word())?;
                    assert_eq!(chip.next_row(), 2);
                }
                Ok(())
            },
        )
    }
}

fn boundaries<F: PastaField>() {
    for value in [
        F::ZERO,
        F::ONE,
        F::from(32767),
        F::from(32768),
        F::from(65535),
        -F::ONE,
    ] {
        let circuit = Circuit15 {
            value: Value::known(value),
            forged: None,
        };
        let accepted =
            value.to_canonical_limbs()[1..] == [0, 0, 0] && value.to_canonical_limbs()[0] < 32768;
        assert_eq!(
            check_circuit(&circuit, 5, &[], CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            accepted
        );
    }
    // Consistent forgeries also update the reconstructed input, so only the
    // root constraints (not a stale copy or recomposition) can reject them.
    for index in 0..8 {
        for digit in [F::from(if index == 7 { 2 } else { 4 }), -F::ONE] {
            let mut digits = [F::ZERO; 8];
            digits[index] = digit;
            let circuit = Circuit15 {
                value: Value::known(digit * F::from(1_u64 << (2 * index))),
                forged: Some(digits),
            };
            assert!(
                !check_circuit(&circuit, 5, &[], CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
    }
}

#[test]
fn algebraic_15_bit_range_is_integer_exact_and_rejects_consistent_forgeries() {
    boundaries::<Fp>();
    boundaries::<Fq>();
}

fn tamper<F: PastaField>() {
    let circuit = Circuit15 {
        value: Value::known(F::from(21845)),
        forged: None,
    };
    let known = synthesize(&circuit, 5, Some(&[])).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 5, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert!(
        crate::tamper::undetected_tampers(&circuit, 5, &[])
            .unwrap()
            .is_empty()
    );
    assert!(known.cs.lookups().is_empty());
    assert_eq!(known.cs.degree(), 5);
}

#[test]
fn algebraic_15_bit_range_binds_every_cell_and_has_no_lookup() {
    tamper::<Fp>();
    tamper::<Fq>();
}
