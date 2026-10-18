//! The own step relation proved inline by a lean A (lean lineage).
//!
//! Send, Receive and `ReceiveRenewed` lay out their own σ step relation on A's
//! operation lane and assert each of its statement fields equal to A's own
//! statement, instead of verifying the own σ proof. Equal fields are exactly
//! the inputs of the statement digest σ would have certified, so A proves the
//! same relation without that digest or the σ bytes.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{AbsorbInput, GlueChip, UintChip, statement::StepRelation};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use crate::{
    circuit::RelationShape,
    operation_relation::statement::StatementCells,
    witness::{NativeStep, StepWitness},
};

/// The own step relation an inline transition task lays out on A's RP57 lane.
#[derive(Clone, Copy, Debug)]
pub struct TransitionInputs<'a> {
    /// The route's own σ relation (Send: its control mask) with absorbed prefixes.
    pub shape: RelationShape,
    /// The prepared step witness and its native evaluation; `None` at key generation.
    pub witness: Option<(&'a StepWitness<Fp>, &'a NativeStep<Fp>)>,
}

#[cfg(test)]
mod tests;

impl TransitionInputs<'_> {
    /// Lay out the step relation on A's lane and assert each of its statement
    /// fields equal to A's own. The relation must be the statement variant's own
    /// step: Send for Send, Receive for Receive and `ReceiveRenewed`.
    ///
    /// # Errors
    /// A shape of another step, layout failure or a statement field that differs.
    pub fn constrain(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        statement: &StatementCells,
    ) -> Result<(), Error> {
        let step = match statement.variant() {
            Variant::Send => StepRelation::Send,
            Variant::Receive | Variant::ReceiveRenewed => StepRelation::Receive,
            _ => return Err(Error::Synthesis),
        };
        if self.shape.relation.step() != step {
            return Err(Error::Synthesis);
        }
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        let relation = crate::relation::assign_single(
            &mut uint,
            lanes.hash,
            region,
            self.shape,
            self.witness,
        )?;
        let fields = relation.fields()?;
        if fields.len() != statement.fields().len() {
            return Err(Error::Synthesis);
        }
        for (field, own) in fields.iter().zip(statement.fields()) {
            match field {
                AbsorbInput::Word(word) => GlueChip::assert_equal(region, word, own)?,
                AbsorbInput::Constant(value) => GlueChip::assert_constant(region, own, *value)?,
            }
        }
        Ok(())
    }
}
