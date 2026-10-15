//! Source-bound rotated-point collision and product mutation controls.

use super::*;
use iroha_pasta::{Ep, Eq, PastaField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Cell, Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::tamper::{Tamper, check_tampered};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone)]
struct Probe<C: PastaCurve> {
    raw: C::ScalarExt,
    rotations: [i32; 3],
    known: bool,
    cells: Rc<RefCell<Vec<Cell>>>,
}
impl<C: PastaCurve> Circuit<C::Base> for Probe<C> {
    type Config = (VerifierConfig<C>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
        let verifier = VerifierConfig::configure(meta);
        let public = meta.instance_column(7);
        meta.enable_equality(public);
        (verifier, public)
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<C::Base>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::<C>::new(config);
        chip.load_tables(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "mapped rotated products",
            |mut region| {
                let raw = ScalarCells::<C>::assign_value(
                    &mut chip.uint(),
                    &mut region,
                    if self.known {
                        Value::known(self.raw)
                    } else {
                        Value::unknown()
                    },
                )?;
                let (_, x) = chip.total_challenge(&mut region, Challenge::X, raw)?;
                let read = Read {
                    scalars: vec![],
                    points: vec![],
                    challenges: vec![(Challenge::X, x.clone())],
                    round_cells: vec![],
                    suffix: None,
                };
                let mut valid = chip.glue.boolean(&mut region, Value::known(true))?;
                chip.glue
                    .enforce_constant(&mut region, valid.word(), C::Base::ONE)?;
                let points = chip.rotated_opening_points(
                    &mut region,
                    &read,
                    6,
                    &self.rotations,
                    &mut valid,
                )?;
                *self.cells.borrow_mut() = x
                    .limbs()
                    .iter()
                    .map(Word::cell)
                    .chain(
                        points
                            .iter()
                            .flat_map(|point| point.limbs().iter().map(Word::cell)),
                    )
                    .chain([valid.cell()])
                    .collect();
                let mut outputs = Vec::new();
                for point in points {
                    let point = chip.export(&mut region, &point)?;
                    outputs.extend([point.lo().cell(), point.hi().cell()]);
                }
                outputs.push(valid.cell());
                Ok(outputs)
            },
        )?;
        for (row, cell) in outputs.into_iter().enumerate() {
            layouter.constrain_instance(cell, public, row)?;
        }
        Ok(())
    }
}
fn cases<C: PastaCurve>() {
    let omega = iroha_plonk::protocol::omega::<C::ScalarExt>(6).unwrap();
    let omega_inverse = omega.invert().unwrap();
    for (raw, rotations, distinct) in [
        (C::ScalarExt::ZERO, [-1, 0, 1], true),
        (C::ScalarExt::ZERO, [-1, 63, 0], false),
        (C::ScalarExt::ZERO, [0, 64, -64], false),
        (C::ScalarExt::from(9), [-65, -1, 1], false),
        (-C::ScalarExt::ONE, [i32::MIN, -1, 1], true),
    ] {
        let circuit = Probe::<C> {
            raw,
            rotations,
            known: true,
            cells: Rc::default(),
        };
        let x = iroha_plonk::transcript::pipa_r::evaluation_challenge(raw);
        assert!(!bool::from(x.is_zero()));
        let points = rotations.map(|r| {
            x * if r >= 0 { omega } else { omega_inverse }
                .pow_vartime([u64::from(r.unsigned_abs())])
        });
        assert_eq!(
            distinct,
            points
                .iter()
                .enumerate()
                .all(|(i, point)| points[..i].iter().all(|other| point != other))
        );
        let mut public = Vec::new();
        for point in points {
            let limbs = point.to_canonical_limbs();
            public.extend([
                C::Base::from_u128(u128::from(limbs[0]) | (u128::from(limbs[1]) << 64)),
                C::Base::from_u128(u128::from(limbs[2]) | (u128::from(limbs[3]) << 64)),
            ]);
        }
        public.push(C::Base::from(u64::from(distinct)));
        let public = vec![public];
        assert!(
            check_circuit(&circuit, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let mut forged = public.clone();
        forged[0][6] = C::Base::from(u64::from(!distinct));
        assert!(
            !check_circuit(&circuit, 16, &forged, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        // Exercise every nonnative output limb of mapped X and each constrained
        // product, plus the public verdict, for both a valid and a collided set.
        if raw == C::ScalarExt::ZERO && (rotations == [-1, 0, 1] || rotations == [-1, 63, 0]) {
            let cells = circuit.cells.borrow().clone();
            for cell in cells {
                let report = check_tampered(
                    &circuit,
                    16,
                    &public,
                    Some(Tamper {
                        column: cell.column.index(),
                        row: cell.row_offset,
                        delta: C::Base::ONE,
                    }),
                )
                .unwrap();
                assert!(!report.is_satisfied());
            }
        }
        let known = synthesize(&circuit, 16, Some(&public)).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.selectors(), unknown.tables.selectors());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
    }
}
#[test]
fn mapped_rotated_products_collisions_and_mutations_both_curves() {
    cases::<Ep>();
    cases::<Eq>();
}
