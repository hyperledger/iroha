//! Shared arithmetic/hash lane access for operation constraints between verifiers.

use iroha_pasta::{PastaCurve, poseidon::PoseidonField};
use iroha_plonk::frontend::Error;
use iroha_plonk_gadgets::{GlueChip, RunningSumChip, pow5_fq::DuplexChip};

use crate::verifier::VerifierChip;

/// Mutable lanes retaining the interpreter's exact row cursors.
/// No transcript, key, foreign-field state or accumulator is reset.
#[derive(Debug)]
pub struct OperationLanes<'a, F: PoseidonField> {
    /// Existing glue lane.
    pub glue: &'a mut GlueChip<F>,
    /// Existing integer range-check lane.
    pub range: &'a mut RunningSumChip<F>,
    /// Cleared RP57 lane, using the same columns as recursive transcripts.
    pub hash: &'a mut DuplexChip<F>,
}

impl<C: PastaCurve> VerifierChip<C> {
    /// Borrow operation lanes only between complete proof transcripts.
    ///
    /// Shared operation gadgets must preserve these chip cursors; the borrow
    /// prevents running a recursive verifier while its lanes are in use.
    ///
    /// # Errors
    /// A proof transcript still owns the duplex, or it has buffered state.
    pub fn operation_lanes(&mut self) -> Result<OperationLanes<'_, C::Base>, Error> {
        let hash = self.duplex.as_mut().ok_or(Error::Synthesis)?;
        if !hash.is_clear() || hash.buffered() != 0 {
            return Err(Error::Synthesis);
        }
        Ok(OperationLanes {
            glue: &mut self.glue,
            range: &mut self.range,
            hash,
        })
    }
}
