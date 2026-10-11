//! Fixed hard owner of the exact original two-proof consuming digest.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{GlueChip, UintChip, Word, bytes::variable::ActiveBytes};
use iroha_plonk_recursion::verifier::VerifierChip;

use super::{ReceiveObjects, maps::require_task};
use crate::a_relation::{
    context::{ContextInputs, ContextObjectCells, ContextPlan},
    schedule::OperationTask,
};

/// Exact combined consuming digest and original raw-proof commitments.
///
/// This is a hard producer, independent of all five soft result groups. The
/// mandatory Objects owner separately authenticates the sigma-only step digest
/// and binds the exact decoder projections to Q0. No proposed soft bit can skip
/// either original byte tape or replace an original tail with descriptor padding.
#[derive(Clone, Debug)]
pub struct ReceiveProofDigest {
    context: [ContextObjectCells; 2],
    specs: [crate::a_relation::context::ContextObjectSpec; 2],
}

impl ReceiveProofDigest {
    /// Hash both original active tapes with their LE32 lengths and no gap.
    ///
    /// `sigma_digest` is the slot-5 claim derived independently by Objects. This
    /// producer authenticates that slot's raw tape/length and the combined digest;
    /// it does not redundantly derive the sigma-only digest.
    /// # Errors
    /// Zero/overflowing capacity, incompatible sponge or layout failure.
    pub fn from_active(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        omega: &ActiveBytes<Fp>,
        sigma: &ActiveBytes<Fp>,
        sigma_digest: &Word<Fp>,
    ) -> Result<Self, Error> {
        let specs = ReceiveObjects::context_specs(omega.run().len(), sigma.run().len())?;
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        let left = omega.packed().length_prefixed(&mut uint, region)?;
        let right = sigma.packed().length_prefixed(&mut uint, region)?;
        let digest = left.concat(&mut uint, region, &right)?.digest(
            &mut uint,
            lanes.hash.sponge_mut()?,
            region,
            u64::from_le_bytes(*b"kgwprf_1"),
        )?;
        Ok(Self {
            specs: [specs[4], specs[5]],
            context: [
                ContextObjectCells::from_active(chip, region, specs[4], &digest, omega)?,
                ContextObjectCells::from_active(chip, region, specs[5], sigma_digest, sigma)?,
            ],
        })
    }

    /// Digest of the original pair, including both exact length prefixes.
    pub const fn digest(&self) -> &Word<Fp> {
        self.context[0].authenticated_digest()
    }

    /// Hard-bind both raw tapes and the derived digest to the one fixed context.
    /// This is required exactly once, including all burn/no-op branches.
    /// # Errors
    /// Wrong/missing task owner, context schema or source commitment.
    pub fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        require_task(plan, stage, OperationTask::ReceiveProofDigest)?;
        if input.objects.len() != 11 || plan.object_specs().len() != 11 {
            return Err(Error::Synthesis);
        }
        for (offset, actual) in self.context.iter().enumerate() {
            let index = offset + 4;
            if self.specs[offset] != plan.object_specs()[index] {
                return Err(Error::Synthesis);
            }
            for (a, b) in actual
                .commitment_words()
                .iter()
                .zip(input.objects[index].commitment_words())
            {
                GlueChip::assert_equal(region, a, &b)?;
            }
        }
        Ok(())
    }
}
