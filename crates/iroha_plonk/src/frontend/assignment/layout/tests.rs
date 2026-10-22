//! Differential coverage for typed occupancy capture.

use super::*;
use crate::{
    cs::{PermutationArgument, PermutationAssembly, PermutationError, TableColumn},
    frontend::{
        Circuit, Layouter, SimpleFloorPlanner, synthesize, synthesize_cancellable,
        synthesize_layout, synthesize_layout_cancellable,
    },
};
use iroha_pasta::{CancellationToken, Fp, Fq};

#[derive(Clone, Copy)]
struct Columns {
    a: Column<Advice>,
    b: Column<Advice>,
    disabled: Column<Advice>,
    fixed: Column<Fixed>,
    fill: Column<Fixed>,
    instance: Column<Instance>,
    selector: Selector,
}
fn columns<F: PastaField>(cs: &mut ConstraintSystem<F>) -> Columns {
    let c = Columns {
        a: cs.advice_column(),
        b: cs.advice_column(),
        disabled: cs.advice_column(),
        fixed: cs.fixed_column(),
        fill: cs.fixed_column(),
        instance: cs.instance_column(2),
        selector: cs.selector(),
    };
    cs.enable_equality(c.a);
    cs.enable_equality(c.b);
    cs.enable_equality(c.fixed);
    cs.enable_equality(c.instance);
    c
}
fn record<F: PastaField>(sink: &mut impl Assignment<F>, c: Columns) -> Result<(), Error> {
    sink.push_namespace("outer".into());
    sink.enter_region("record".into())?;
    sink.annotate_column("value".into(), c.a.into());
    sink.enable_selector(c.selector, 0)?;
    assert_eq!(sink.query_instance(c.instance, 1)?, Value::unknown());
    sink.assign_advice(c.a, 0, Value::unknown())?;
    sink.assign_advice(c.a, 0, Value::known(Assigned::Trivial(F::from(7))))?;
    sink.reserve_advice(c.b, 3)?;
    sink.assign_advice(c.b, 3, Value::unknown())?;
    sink.expect_fixed(c.fixed, 1, F::from(5))?;
    sink.assign_fixed(c.fixed, 1, Assigned::Rational(F::from(10), F::from(2)))?;
    sink.assign_fixed(c.fixed, 2, Assigned::Rational(F::ONE, F::ZERO))?;
    sink.fill_from_row(c.fill, 2, Value::known(Assigned::Trivial(F::from(9))))?;
    sink.copy(c.a.into(), 0, c.a.into(), 0)?;
    sink.copy(c.a.into(), 0, c.b.into(), 3)?;
    sink.copy(c.b.into(), 3, c.a.into(), 0)?;
    sink.copy(c.fixed.into(), 1, c.instance.into(), 1)?;
    sink.exit_region()?;
    sink.pop_namespace();
    Ok(())
}
fn assignment_parity<F: PastaField>() {
    let mut cs = ConstraintSystem::<F>::new();
    let c = columns(&mut cs);
    let mut full = Assembly::new(&cs, 4, None).unwrap();
    let mut layout = LayoutAssembly::new(&cs, 4, None).unwrap();
    record(&mut full, c).unwrap();
    record(&mut layout, c).unwrap();
    assert!(!full.permutation.is_identity());
    assert!(
        layout.0.permutation.is_identity(),
        "copy cycles never allocated"
    );
    assert_eq!(full.selectors, layout.0.selectors);
    assert_eq!(full.regions, layout.0.regions);
    assert_eq!(full.namespaces, layout.0.namespaces);
    let full = full.finish().unwrap();
    let layout = layout.finish().unwrap();
    assert!(full.advice().is_none());
    assert_eq!(full.fixed(), layout.fixed());
    assert_eq!(full.fixed_assigned(), layout.fixed_assigned());
    assert_eq!(full.advice_assigned(), layout.advice_assigned());
    assert_eq!(layout.fixed()[c.fixed.index()][2], F::ZERO);
}
#[test]
fn layout_assignment_matches_full_without_copy_cycles_both_fields() {
    assignment_parity::<Fp>();
    assignment_parity::<Fq>();
}

fn error_case<F: PastaField>(
    sink: &mut impl Assignment<F>,
    c: Columns,
    case: usize,
) -> Result<(), Error> {
    match case {
        0 => sink.copy(c.disabled.into(), 100, c.instance.into(), 9),
        1 => sink.copy(c.disabled.into(), 0, c.instance.into(), 100),
        2 => sink.copy(c.disabled.into(), 0, c.instance.into(), 2),
        3 => sink.copy(c.disabled.into(), 0, Column::new(99, Any::Advice), 0),
        4 => sink.copy(c.a.into(), 0, c.disabled.into(), 0),
        5 => sink.copy(Column::new(99, Any::Instance), 0, c.disabled.into(), 0),
        6 => sink.assign_advice(Column::new(99, Advice), 0, Value::unknown()),
        7 => sink.fill_from_row(c.fill, 0, Value::unknown()),
        8 => {
            sink.enter_region("first".into())?;
            sink.enter_region("nested".into())
        }
        9 => {
            sink.reserve_advice(c.a, 0)?;
            sink.reserve_advice(c.a, 0)
        }
        10 => {
            sink.expect_fixed(c.fixed, 0, F::ONE)?;
            sink.assign_fixed(c.fixed, 0, Assigned::Zero)
        }
        11 => sink.reserve_advice(c.a, 0),
        12 => sink.expect_fixed(c.fixed, 0, F::ONE),
        13 => sink.enter_region("unclosed".into()),
        14 => {
            sink.reserve_advice(c.a, 0)?;
            sink.assign_advice(c.a, 0, Value::unknown())?;
            sink.assign_advice(c.a, 0, Value::unknown())
        }
        _ => unreachable!(),
    }
}
fn error_parity<F: PastaField>() {
    let mut cs = ConstraintSystem::<F>::new();
    let c = columns(&mut cs);
    for case in 0..15 {
        let mut full = Assembly::new(&cs, 4, None).unwrap();
        let mut layout = LayoutAssembly::new(&cs, 4, None).unwrap();
        let a = error_case(&mut full, c, case);
        let b = error_case(&mut layout, c, case);
        assert_eq!(a, b, "assignment case {case}");
        if a.is_ok() {
            assert_eq!(
                full.finish().unwrap_err(),
                layout.finish().unwrap_err(),
                "finish case {case}"
            );
        } else {
            assert!(b.is_err());
        }
    }
    // Even the lazy representation rejects overflowing dimensions.
    let mut argument = PermutationArgument::new();
    argument.add_column(c.a.into());
    argument.add_column(c.b.into());
    assert_eq!(
        PermutationAssembly::new(usize::MAX, &argument).unwrap_err(),
        PermutationError::TooManyCells
    );
    let p = PermutationAssembly::new(8, &argument).unwrap();
    assert_eq!(
        p.checked_copy_cells(c.a.into(), 8, c.b.into(), 0),
        Err(PermutationError::RowOutOfBounds { row: 8, n: 8 })
    );
    assert!(p.is_identity());
}
#[test]
fn layout_errors_preserve_full_order_both_fields() {
    error_parity::<Fp>();
    error_parity::<Fq>();
}

#[derive(Clone)]
struct Probe {
    cancel: Option<CancellationToken>,
    at: u8,
}
impl<F: PastaField> Circuit<F> for Probe {
    type Config = (Columns, TableColumn);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let c = columns(cs);
        cs.enable_constant(c.fixed);
        let table = cs.lookup_table_column();
        (c, table)
    }
    fn synthesize(
        &self,
        (c, table): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let cell = layouter.assign_region(
            || "copies and constants",
            |mut region| {
                let a = region.assign_advice_from_constant(|| "constant", c.a, 0, F::from(3))?;
                let b = region.assign_advice(c.b, 0, Value::<F>::unknown())?;
                if self.at == 1 {
                    self.cancel.as_ref().unwrap().cancel();
                }
                // A chip can map cancellation; the operation boundary must restore it.
                region
                    .constrain_equal(a.cell(), b.cell())
                    .map_err(|_| Error::Synthesis)?;
                Ok(a.cell())
            },
        )?;
        layouter.constrain_instance(cell, c.instance, 0)?;
        layouter.assign_table(
            || "table",
            |mut t| {
                for row in 0..3 {
                    t.assign_cell(|| "row", table, row, || Value::known(F::from(row as u64)))?;
                }
                Ok(())
            },
        )?;
        if self.at == 2 {
            self.cancel.as_ref().unwrap().cancel();
        }
        Ok(())
    }
}
fn circuit_parity<F: PastaField>() {
    let probe = Probe {
        cancel: None,
        at: 0,
    };
    let full = synthesize::<F, _>(&probe, 4, None).unwrap();
    let layout = synthesize_layout::<F, _>(&probe, 4).unwrap();
    assert_eq!(full.tables.fixed(), layout.fixed());
    assert_eq!(full.tables.fixed_assigned(), layout.fixed_assigned());
    assert_eq!(full.tables.advice_assigned(), layout.advice_assigned());
    assert!(!full.tables.permutation().is_identity());
    for at in 0..=2 {
        for capture in [false, true] {
            let token = CancellationToken::new();
            if at == 0 {
                token.cancel();
            }
            let probe = Probe {
                cancel: Some(token.clone()),
                at,
            };
            let error = if capture {
                synthesize_layout_cancellable::<F, _>(&probe, 4, Some(&token)).unwrap_err()
            } else {
                synthesize_cancellable::<F, _>(&probe, 4, None, Some(&token)).unwrap_err()
            };
            assert_eq!(error, Error::Cancelled, "at={at} capture={capture}");
        }
    }
    let retry =
        synthesize_layout_cancellable::<F, _>(&probe, 4, Some(&CancellationToken::new())).unwrap();
    assert_eq!(retry.fixed(), full.tables.fixed());
    assert_eq!(retry.advice_assigned(), full.tables.advice_assigned());
}
#[test]
fn layout_circuit_and_cancellation_match_full_both_fields() {
    circuit_parity::<Fp>();
    circuit_parity::<Fq>();
}
