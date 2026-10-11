//! Exact bridge reuse binds both cell identities and the canonical integer.

use super::*;
use crate::verifier::{VerifierChip, VerifierConfig};
use iroha_pasta::{Ep, Eq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    Word,
    ff::Form,
    tamper::{Tamper, check_tampered},
};
use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

#[derive(Clone)]
struct RoundTrip<C: PastaCurve> {
    known: bool,
    cells: Rc<RefCell<Vec<Cell>>>,
    marker: PhantomData<C>,
}
impl<C: PastaCurve> RoundTrip<C> {
    fn witness<T>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn remember(&self, value: &Scalar<C>) {
        self.cells
            .borrow_mut()
            .extend(value.limbs().iter().map(Word::cell));
    }
    fn remember_s6(&self, value: &ScalarCells<C>) {
        self.cells
            .borrow_mut()
            .extend([value.lo().cell(), value.hi().cell()]);
    }
}
impl<C: PastaCurve> Circuit<C::Base> for RoundTrip<C> {
    type Config = (VerifierConfig<C>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
        let config = VerifierConfig::configure_serialized_foreign(meta, 2).unwrap();
        let public = meta.instance_column(6);
        meta.enable_equality(public);
        (config, public)
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
        self.cells.borrow_mut().clear();
        let (original, first) = layouter.assign_region(
            || "FF to S6 and back",
            |mut region| {
                let original = chip.arithmetic.ff.witness_canonical(
                    &mut region,
                    Arithmetic::<C>::modulus(),
                    self.witness(C::ScalarExt::from(5).to_canonical_limbs()),
                )?;
                let first = chip.export(&mut region, &original)?;
                let before = chip.usage()?;
                let imported = chip.import(&mut region, &first)?;
                assert_eq!(
                    Arithmetic::<C>::cells(&imported),
                    Arithmetic::<C>::cells(&original)
                );
                let repeated = chip.export(&mut region, &imported)?;
                assert_eq!(
                    [first.lo().cell(), first.hi().cell()],
                    [repeated.lo().cell(), repeated.hi().cell()]
                );
                assert_eq!(
                    chip.usage()?,
                    before,
                    "the retained exact bridge adds no rows"
                );
                self.remember(&original);
                self.remember_s6(&first);
                Ok((original, first))
            },
        )?;
        let (second, third) = layouter.assign_region(
            || "fresh cells and unreduced alias",
            |mut region| {
                // Equal values in a different region must have a fresh certificate.
                let native = chip
                    .glue
                    .witness(&mut region, self.witness(C::Base::from(5)))?;
                let second =
                    ScalarCells::<C>::from_native_word(&mut chip.uint(), &mut region, &native)?;
                assert_ne!(
                    [first.lo().cell(), first.hi().cell()],
                    [second.lo().cell(), second.hi().cell()]
                );
                let imported = chip.import(&mut region, &second)?;
                assert_ne!(
                    Arithmetic::<C>::cells(&imported),
                    Arithmetic::<C>::cells(&original)
                );
                let before = chip.usage()?;
                let exported = chip.export(&mut region, &imported)?;
                assert_eq!(
                    [exported.lo().cell(), exported.hi().cell()],
                    [second.lo().cell(), second.hi().cell()]
                );
                assert_eq!(chip.usage()?, before);
                self.cells.borrow_mut().push(native.cell());
                self.remember(&imported);
                self.remember_s6(&second);

                let modulus = Arithmetic::<C>::modulus();
                let multiple = chip.arithmetic.ff.witness(
                    &mut region,
                    modulus,
                    self.witness(modulus.nat().low_words()),
                )?;
                for (word, value) in multiple.limbs().iter().zip(modulus.limbs()) {
                    chip.glue
                        .enforce_constant(&mut region, word, C::Base::from_u128(value))?;
                }
                let lazy =
                    chip.arithmetic
                        .ff
                        .add(&mut chip.glue, &mut region, &original, &multiple)?;
                assert_eq!(lazy.form(), Form::Bounded);
                let third = chip.export(&mut region, &lazy)?;
                let before = chip.usage()?;
                let canonical = chip.import(&mut region, &third)?;
                assert_eq!(canonical.form(), Form::Canonical);
                assert_ne!(
                    Arithmetic::<C>::cells(&canonical),
                    Arithmetic::<C>::cells(&lazy)
                );
                assert_eq!(chip.usage()?, before);
                let repeated = chip.export(&mut region, &canonical)?;
                assert_eq!(
                    [repeated.lo().cell(), repeated.hi().cell()],
                    [third.lo().cell(), third.hi().cell()]
                );
                assert_eq!(chip.usage()?, before);
                self.remember(&multiple);
                self.remember(&lazy);
                self.remember(&canonical);
                self.remember_s6(&third);
                Ok((second, third))
            },
        )?;
        for (index, value) in [first, second, third].into_iter().enumerate() {
            layouter.constrain_instance(value.lo().cell(), public, 2 * index)?;
            layouter.constrain_instance(value.hi().cell(), public, 2 * index + 1)?;
        }
        Ok(())
    }
}

fn cases<C: PastaCurve>() {
    let circuit = RoundTrip::<C> {
        known: true,
        cells: Rc::default(),
        marker: PhantomData,
    };
    let public = vec![vec![
        C::Base::from(5),
        C::Base::ZERO,
        C::Base::from(5),
        C::Base::ZERO,
        C::Base::from(5),
        C::Base::ZERO,
    ]];
    let report = check_circuit(&circuit, 16, &public, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let targets = circuit
        .cells
        .borrow()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for cell in targets {
        assert!(
            !check_tampered(
                &circuit,
                16,
                &public,
                Some(Tamper {
                    column: cell.column.index(),
                    row: cell.row_offset,
                    delta: C::Base::ONE,
                })
            )
            .unwrap()
            .is_satisfied()
        );
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

#[test]
fn inverse_bridge_cache_keeps_exact_cells_and_only_canonical_integers() {
    cases::<Ep>();
    cases::<Eq>();
}
