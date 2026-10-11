//! The [`Circuit`] trait and the synthesis entry points.
//!
//! A circuit configures a [`ConstraintSystem`] once (`configure`) and assigns
//! its cells through a [`Layouter`] (`synthesize`). [`synthesize`] runs both
//! into an [`Assembly`]: without instances it records key-generation data,
//! with instances it records the witness for proving and checking.

use iroha_pasta::PastaField;

use super::{
    assignment::{Assembly, AssignedTables, Error},
    layouter::{FloorPlanner, Layouter},
};
use crate::cs::ConstraintSystem;

/// A circuit: a constraint system and an assignment of its cells.
pub trait Circuit<F: PastaField>: Sized {
    /// The columns and chips `configure` returns.
    type Config: Clone;
    /// The floor planner that lays the circuit out.
    type FloorPlanner: FloorPlanner;
    /// Parameters `configure_with_params` takes (`()` for most circuits).
    type Params: Clone + Default;

    /// This circuit with every witness value unknown (key generation).
    #[must_use]
    fn without_witnesses(&self) -> Self;

    /// The configuration parameters of this circuit instance.
    fn params(&self) -> Self::Params {
        Self::Params::default()
    }

    /// Configures the constraint system with `params`; the default ignores
    /// them and calls [`Self::configure`].
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let _ = params;
        Self::configure(meta)
    }

    /// Configures the constraint system.
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config;

    /// Assigns the circuit's cells.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layouter or the circuit's own checks.
    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error>;
}

/// Configures `circuit`'s constraint system.
///
/// # Errors
///
/// [`Error::ConstraintSystem`] when `configure` misused the builder.
pub fn configure<F: PastaField, C: Circuit<F>>(
    circuit: &C,
) -> Result<(ConstraintSystem<F>, C::Config), Error> {
    let mut cs = ConstraintSystem::new();
    let config = C::configure_with_params(&mut cs, circuit.params());
    cs.check()?;
    Ok((cs, config))
}

/// A configured and synthesized circuit.
#[derive(Clone, Debug)]
pub struct Synthesized<F: PastaField> {
    /// The constraint system before selector substitution.
    pub cs: ConstraintSystem<F>,
    /// The recorded tables.
    pub tables: AssignedTables<F>,
}

/// Configures and synthesizes `circuit` at `k`.
///
/// With `instances = None` this records key-generation data (advice values
/// are not recorded); with `Some(instances)` it records the witness, and every
/// instance column must have exactly its declared length.
///
/// # Errors
///
/// [`Error`] from configuration, the layout or the circuit.
pub fn synthesize<F: PastaField, C: Circuit<F>>(
    circuit: &C,
    k: u32,
    instances: Option<&[Vec<F>]>,
) -> Result<Synthesized<F>, Error> {
    synthesize_cancellable(circuit, k, instances, None)
}

/// Synthesizes with cancellation checked at every assignment and region boundary.
///
/// # Errors
/// As [`synthesize`], or [`Error::Cancelled`].
pub fn synthesize_cancellable<F: PastaField, C: Circuit<F>>(
    circuit: &C,
    k: u32,
    instances: Option<&[Vec<F>]>,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<Synthesized<F>, Error> {
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let (cs, config) = configure(circuit)?;
    let mut assembly = Assembly::new_cancellable(&cs, k, instances, cancellation)?;
    let assigned =
        C::FloorPlanner::synthesize(&mut assembly, circuit, config, cs.constants().to_vec());
    // This is an explicit operation boundary, including when a chip maps its
    // assignment error into Synthesis. Cancellation produces no circuit verdict.
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    assigned?;
    let tables = assembly.finish()?;
    Ok(Synthesized { cs, tables })
}

#[cfg(test)]
mod tests {
    use iroha_pasta::Fp;

    use super::*;
    use crate::{
        cs::{Expression, Rotation},
        frontend::{SimpleFloorPlanner, Value},
    };

    /// A circuit whose gate adds a simple selector to an advice cell.
    struct Misconfigured;

    impl Circuit<Fp> for Misconfigured {
        type Config = ();
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) {
            let advice = meta.advice_column();
            let selector = meta.selector();
            meta.create_gate("bad", |cells| {
                vec![cells.query_selector(selector) + cells.query_advice(advice, Rotation::cur())]
            });
        }

        fn synthesize(&self, (): (), _layouter: impl Layouter<Fp>) -> Result<(), Error> {
            Ok(())
        }
    }

    /// A circuit with one advice cell under an always-zero gate.
    struct OneCell(Value<Fp>);

    impl Circuit<Fp> for OneCell {
        type Config = crate::cs::Column<crate::cs::Advice>;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self(Value::unknown())
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let advice = meta.advice_column();
            meta.create_gate("free", |cells| {
                vec![
                    Expression::Constant(Fp::from(0)) * cells.query_advice(advice, Rotation::cur()),
                ]
            });
            advice
        }

        fn synthesize(
            &self,
            advice: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "cell",
                |mut region| {
                    region.assign_advice(advice, 0, self.0)?;
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn configure_reports_builder_misuse() {
        assert!(matches!(
            configure(&Misconfigured),
            Err(Error::ConstraintSystem(_))
        ));
        assert!(matches!(
            synthesize(&Misconfigured, 4, None),
            Err(Error::ConstraintSystem(_))
        ));
        let () = Misconfigured.params();
    }

    #[test]
    fn synthesize_in_both_modes() {
        let circuit = OneCell(Value::known(Fp::from(5)));
        let witness = synthesize(&circuit, 4, Some(&[])).expect("witness");
        assert_eq!(witness.tables.advice().expect("witness")[0][0], Fp::from(5));
        assert_eq!(witness.cs.gates().len(), 1);
        let keygen = synthesize(&circuit.without_witnesses(), 4, None).expect("keygen");
        assert!(keygen.tables.advice().is_none());
        assert!(keygen.tables.advice_assigned()[0][0]);
        assert_eq!(
            synthesize(&circuit.without_witnesses(), 4, Some(&[])).unwrap_err(),
            Error::Synthesis
        );
    }
}
