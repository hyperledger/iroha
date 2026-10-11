//! The per-cell tamper harness (the M8 `m8_custom_gate_checks` discipline,
//! applied to every cell).
//!
//! A chip is sound only if every advice cell it assigns is pinned by a gate,
//! a lookup or a copy: changing that one cell, with every other cell left
//! honest, must make the strict constraint checker
//! ([`iroha_plonk::check`]) fail. [`undetected_tampers`] synthesizes a
//! circuit once honestly, then once per assigned advice cell with that cell
//! shifted by one, and returns the cells whose change went unnoticed. Chip
//! tests assert that the list is empty.
//!
//! The harness wraps the synthesis backend ([`Assembly`]) in an
//! [`Assignment`] that perturbs one advice assignment, so the circuit code,
//! the floor planner and the checker are the production ones. Free inputs
//! that a circuit never uses are not pinned by anything and would be
//! reported; circuits under test copy or expose every value they assign.
//!
//! # Scope
//!
//! An empty result shows that every assigned cell is pinned by a gate, a
//! lookup or a copy. It does not show that the relation is semantically
//! complete. A free witness that is only copied into a hash input is pinned
//! by that copy, so a one-cell change is caught, yet a prover who assigns a
//! different value consistently (every copy and every downstream digest
//! recomputed) still satisfies the circuit. Whether such a value is bound to
//! anything the verifier checks is a property of the relation, which needs
//! its own consistent-forgery tests.

use iroha_pasta::PastaField;
use iroha_plonk::{
    check::{CheckMode, CheckReport, check},
    cs::{Advice, Any, Column, Fixed, Instance, Selector},
    frontend::{
        Assembly, Assigned, AssignedTables, Assignment, Circuit, Error, FloorPlanner, Value,
        configure,
    },
};

/// One advice cell to perturb: `cell += delta` at every assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tamper<F> {
    /// The advice column index.
    pub column: usize,
    /// The absolute row.
    pub row: usize,
    /// The amount added to the honest value.
    pub delta: F,
}

/// An [`Assignment`] backend that forwards to `inner` and perturbs selected
/// advice cells.
#[derive(Debug)]
struct Tampering<'a, F, A> {
    inner: A,
    tampers: &'a [Tamper<F>],
    hits: Vec<usize>,
}

impl<F: PastaField, A: Assignment<F>> Assignment<F> for Tampering<'_, F, A> {
    fn enter_region(&mut self, name: String) -> Result<(), Error> {
        self.inner.enter_region(name)
    }

    fn exit_region(&mut self) -> Result<(), Error> {
        self.inner.exit_region()
    }

    fn annotate_column(&mut self, name: String, column: Column<Any>) {
        self.inner.annotate_column(name, column);
    }

    fn enable_selector(&mut self, selector: Selector, row: usize) -> Result<(), Error> {
        self.inner.enable_selector(selector, row)
    }

    fn query_instance(&self, column: Column<Instance>, row: usize) -> Result<Value<F>, Error> {
        self.inner.query_instance(column, row)
    }

    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        row: usize,
        value: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        let mut value = value;
        for (index, tamper) in self.tampers.iter().enumerate() {
            if tamper.column == column.index() && tamper.row == row {
                self.hits[index] = self.hits[index].saturating_add(1);
                value = value.map(|honest| honest + tamper.delta);
            }
        }
        self.inner.assign_advice(column, row, value)
    }

    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        value: Assigned<F>,
    ) -> Result<(), Error> {
        self.inner.assign_fixed(column, row, value)
    }

    fn expect_fixed(&mut self, column: Column<Fixed>, row: usize, value: F) -> Result<(), Error> {
        self.inner.expect_fixed(column, row, value)
    }
    fn reserve_advice(&mut self, column: Column<Advice>, row: usize) -> Result<(), Error> {
        self.inner.reserve_advice(column, row)
    }

    fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error> {
        self.inner
            .copy(left_column, left_row, right_column, right_row)
    }

    fn fill_from_row(
        &mut self,
        column: Column<Fixed>,
        from_row: usize,
        value: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        self.inner.fill_from_row(column, from_row, value)
    }

    fn push_namespace(&mut self, name: String) {
        self.inner.push_namespace(name);
    }

    fn pop_namespace(&mut self) {
        self.inner.pop_namespace();
    }
}

/// Constraint program, witness tables and per-request assignment counts.
type TamperedSynthesis<F> = (
    iroha_plonk::ConstraintSystem<F>,
    AssignedTables<F>,
    Vec<usize>,
);

/// Synthesizes `circuit` with `instances` at `k`, applying `tampers`, and
/// returns the witness tables and assignment count for each requested cell.
fn synthesize_tampered<F: PastaField, C: Circuit<F>>(
    circuit: &C,
    k: u32,
    instances: &[Vec<F>],
    tampers: &[Tamper<F>],
) -> Result<TamperedSynthesis<F>, Error> {
    let (cs, config) = configure(circuit)?;
    let mut backend = Tampering {
        inner: Assembly::new(&cs, k, Some(instances))?,
        tampers,
        hits: vec![0; tampers.len()],
    };
    C::FloorPlanner::synthesize(&mut backend, circuit, config, cs.constants().to_vec())?;
    let tables = backend.inner.finish()?;
    Ok((cs, tables, backend.hits))
}

/// Checks `circuit` strictly with one advice cell perturbed (or none).
///
/// # Errors
///
/// [`Error`] from synthesis or the checker; [`Error::BoundsFailure`] when
/// `tamper` names a cell the circuit never assigns.
pub fn check_tampered<F: PastaField, C: Circuit<F>>(
    circuit: &C,
    k: u32,
    instances: &[Vec<F>],
    tamper: Option<Tamper<F>>,
) -> Result<CheckReport<F>, Error> {
    check_tampers(circuit, k, instances, tamper.as_slice())
}

/// Checks a coordinated change to several advice assignments strictly.
///
/// Unlike the per-cell sweep, this can model a consistent forged witness,
/// including all copies and derived accumulators. Every requested cell must
/// exist, and each cell may appear only once. An empty slice checks the honest
/// circuit.
///
/// # Errors
///
/// [`Error::BoundsFailure`] for a duplicate or unassigned cell, or [`Error`]
/// from synthesis or the constraint checker.
pub fn check_tampers<F: PastaField, C: Circuit<F>>(
    circuit: &C,
    k: u32,
    instances: &[Vec<F>],
    tampers: &[Tamper<F>],
) -> Result<CheckReport<F>, Error> {
    let unique: std::collections::BTreeSet<_> = tampers
        .iter()
        .map(|tamper| (tamper.column, tamper.row))
        .collect();
    if unique.len() != tampers.len() {
        return Err(Error::BoundsFailure);
    }
    let (cs, tables, hits) = synthesize_tampered(circuit, k, instances, tampers)?;
    if hits.contains(&0) {
        return Err(Error::BoundsFailure);
    }
    check(&cs, &tables, CheckMode::Strict)
}

/// The advice cells an honest synthesis assigns, as `(column, row)` pairs in
/// column-major order.
///
/// # Errors
///
/// [`Error`] from synthesis.
pub fn assigned_advice_cells<F: PastaField, C: Circuit<F>>(
    circuit: &C,
    k: u32,
    instances: &[Vec<F>],
) -> Result<Vec<(usize, usize)>, Error> {
    let (_, tables, _) = synthesize_tampered(circuit, k, instances, &[])?;
    Ok(tables
        .advice_assigned()
        .iter()
        .enumerate()
        .flat_map(|(column, rows)| {
            rows.iter()
                .enumerate()
                .filter(|(_, assigned)| **assigned)
                .map(move |(row, _)| (column, row))
        })
        .collect())
}

/// Every assigned advice cell whose `+1` tamper the strict checker accepts.
///
/// The honest witness must be accepted first; otherwise the result would be
/// meaningless and [`Error::Synthesis`] is returned.
///
/// # Errors
///
/// [`Error::Synthesis`] when the honest witness is rejected, and [`Error`]
/// from synthesis or the checker.
pub fn undetected_tampers<F: PastaField, C: Circuit<F>>(
    circuit: &C,
    k: u32,
    instances: &[Vec<F>],
) -> Result<Vec<(usize, usize)>, Error> {
    if !check_tampered(circuit, k, instances, None)?.is_satisfied() {
        return Err(Error::Synthesis);
    }
    let mut undetected = Vec::new();
    for (column, row) in assigned_advice_cells(circuit, k, instances)? {
        let tamper = Tamper {
            column,
            row,
            delta: F::ONE,
        };
        if check_tampered(circuit, k, instances, Some(tamper))?.is_satisfied() {
            undetected.push((column, row));
        }
    }
    Ok(undetected)
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use iroha_pasta::Fp;
    use iroha_plonk::{
        cs::{ConstraintSystem, Rotation},
        frontend::{Layouter, SimpleFloorPlanner},
    };

    use super::*;

    /// `b = a + 1` on one row, plus an unconstrained cell when `loose`.
    #[derive(Clone, Copy)]
    struct Increment {
        loose: bool,
    }

    impl Circuit<Fp> for Increment {
        type Config = (Column<Advice>, Column<Advice>, Column<Advice>, Selector);
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            *self
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let a = meta.advice_column();
            let b = meta.advice_column();
            let free = meta.advice_column();
            let s = meta.selector();
            meta.create_gate("increment", |cells| {
                let s = cells.query_selector(s);
                let a = cells.query_advice(a, Rotation::cur());
                let b = cells.query_advice(b, Rotation::cur());
                vec![s * (b - a - iroha_plonk::Expression::Constant(Fp::from(1u64)))]
            });
            (a, b, free, s)
        }

        fn synthesize(
            &self,
            (a, b, free, s): Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "increment",
                |mut region| {
                    s.enable(&mut region, 0)?;
                    region.assign_advice(a, 0, Value::known(Fp::from(4u64)))?;
                    region.assign_advice(b, 0, Value::known(Fp::from(5u64)))?;
                    if self.loose {
                        region.assign_advice(free, 0, Value::known(Fp::from(9u64)))?;
                    }
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn harness_finds_unpinned_cells_only() {
        let tight = Increment { loose: false };
        assert_eq!(
            assigned_advice_cells(&tight, 4, &[]),
            Ok(vec![(0, 0), (1, 0)])
        );
        assert_eq!(undetected_tampers(&tight, 4, &[]), Ok(Vec::new()));
        let loose = Increment { loose: true };
        assert_eq!(undetected_tampers(&loose, 4, &[]), Ok(vec![(2, 0)]));
        let report = check_tampered(
            &tight,
            4,
            &[],
            Some(Tamper {
                column: 1,
                row: 0,
                delta: Fp::from(1u64),
            }),
        )
        .expect("checked");
        assert!(!report.is_satisfied());
        // A tamper of a cell the circuit never assigns is a harness misuse.
        assert_eq!(
            check_tampered(
                &tight,
                4,
                &[],
                Some(Tamper {
                    column: 2,
                    row: 0,
                    delta: Fp::from(1u64),
                }),
            ),
            Err(Error::BoundsFailure)
        );
    }

    #[test]
    fn coordinated_tampers_distinguish_relation_binding_from_cell_binding() {
        let circuit = Increment { loose: false };
        let a = Tamper {
            column: 0,
            row: 0,
            delta: Fp::ONE,
        };
        let b = Tamper {
            column: 1,
            row: 0,
            delta: Fp::ONE,
        };
        assert!(
            !check_tampers(&circuit, 4, &[], &[a])
                .unwrap()
                .is_satisfied()
        );
        // Both inputs are free: the relation permits a consistent replacement.
        assert!(
            check_tampers(&circuit, 4, &[], &[a, b])
                .unwrap()
                .is_satisfied()
        );
        assert_eq!(
            check_tampers(&circuit, 4, &[], &[a, a]),
            Err(Error::BoundsFailure)
        );
        let absent = Tamper { row: 1, ..b };
        assert_eq!(
            check_tampers(&circuit, 4, &[], &[a, absent]),
            Err(Error::BoundsFailure)
        );
        assert!(check_tampers(&circuit, 4, &[], &[]).unwrap().is_satisfied());
    }
}
