//! The inline step relation against A's own statement, on sampled genuine witnesses.

use super::*;
use crate::{
    circuit::PrefixMode,
    vectors::{Mutation, sample_witness},
    witness::SigmaRelation,
};
use ff::Field;
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::ConstraintSystem,
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_recursion::verifier::VerifierConfig;

#[derive(Clone)]
struct Inline {
    step: StepWitness<Fp>,
    native: NativeStep<Fp>,
    statement: [Fp; 26],
    variant: Variant,
    relation: SigmaRelation,
    known: bool,
}

impl Circuit<Fp> for Inline {
    type Config = VerifierConfig<Ep>;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        VerifierConfig::configure(meta)
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config);
        chip.load_tables(&mut layouter)?;
        layouter.assign_region(
            || "inline step relation",
            |mut region| {
                let value = |v| {
                    if self.known {
                        Value::known(v)
                    } else {
                        Value::unknown()
                    }
                };
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &self.statement.map(value))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    self.variant,
                    &fields,
                )?;
                TransitionInputs {
                    shape: RelationShape::new(self.relation, PrefixMode::Absorbed),
                    witness: self.known.then_some((&self.step, &self.native)),
                }
                .constrain(&mut chip, &mut region, &statement)
            },
        )
    }
}

impl Inline {
    fn receive(seed: u64, variant: Variant) -> Self {
        let step = sample_witness::<Fp>(seed, SigmaRelation::RECEIVE, Mutation::None);
        let native = step.evaluate(SigmaRelation::RECEIVE);
        assert!(native.violations.is_empty());
        Self {
            statement: native.statement,
            step,
            native,
            variant,
            relation: SigmaRelation::RECEIVE,
            known: true,
        }
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 16, &[], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
}

#[test]
fn receive_relation_binds_every_field_of_the_own_statement() {
    for (seed, variant) in [(7, Variant::Receive), (11, Variant::ReceiveRenewed)] {
        let honest = Inline::receive(seed, variant);
        assert!(honest.accepts(), "{variant:?}");
        // σ_recv certifies exactly these 26 inputs; any other own statement fails.
        for index in 0..26 {
            let mut wrong = honest.clone();
            wrong.statement[index] += Fp::ONE;
            assert!(!wrong.accepts(), "{variant:?} field {index}");
        }
        let known = synthesize(&honest, 16, None).unwrap();
        let unknown = synthesize(&honest.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    }
}

#[test]
fn inline_relation_must_be_the_statement_variants_own_step() {
    let honest = Inline::receive(13, Variant::Receive);
    // A Send relation cannot stand in for Receive's own step, and Receive's
    // relation cannot prove a Send or Load statement.
    let mut send = honest.clone();
    send.relation = SigmaRelation::SEND;
    assert!(synthesize(&send, 16, None).is_err());
    for variant in [Variant::Send, Variant::Load, Variant::ArchiveReceive] {
        let mut other = honest.clone();
        other.variant = variant;
        assert!(!other.accepts(), "{variant:?}");
    }
}
