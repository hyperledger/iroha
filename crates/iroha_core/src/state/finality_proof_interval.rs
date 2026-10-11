//! One-shot current State publication custody for finite full-proof production.

use super::*;
use crate::sumeragi::finality::{
    NativeFinalityProofInterval, NativeFinalityProofIntervalError,
    NativeFinalityProofIntervalLimits, NativeFinalityProofSource, build_proof_interval,
};
use std::sync::atomic::AtomicBool;

/// Original State acquisition or finite historical proof production did not complete.
#[derive(Debug, thiserror::Error)]
pub enum FinalityProofIntervalReadError {
    /// Preserve the physical State writer/reader's original release observation.
    #[error(transparent)]
    StateView(#[from] StateViewError),
    /// Preserve exact native, portable, resource, source and original stop failures.
    #[error(transparent)]
    Proof(#[from] NativeFinalityProofIntervalError),
}

impl State {
    /// Produce finite historical full proofs from the original current State hash generation.
    ///
    /// Configured network/chain and versioned hash custody come from this exact State.
    /// Both generation captures are one-shot; active/changed publication returns the
    /// original Busy release observation. A stable appended tip is allowed if the
    /// captured final hash remains current. No World view or writer fence is retained
    /// during verification or any caller wait. Native full-prefix checks and a complete
    /// raw-source join precede return; captured hashes alone never certify authority.
    ///
    /// The caller retains its actual admitted worker/response/codec owners. The
    /// returned immutable response keeps all destination charges from that same pool;
    /// nested verifier graphs remain the documented producer funding obligation.
    ///
    /// # Errors
    /// Preserves State Busy, exact original native/portable refusal and stop policy.
    pub fn read_finality_proof_interval(
        &self,
        owner: &CanonicalHistoryReadBudget,
        limits: &NativeFinalityProofIntervalLimits,
        cancelled: &AtomicBool,
    ) -> Result<NativeFinalityProofInterval, FinalityProofIntervalReadError> {
        self.read_finality_proof_interval_after_read(owner, limits, cancelled, || {})
    }

    fn read_finality_proof_interval_after_read(
        &self,
        owner: &CanonicalHistoryReadBudget,
        limits: &NativeFinalityProofIntervalLimits,
        cancelled: &AtomicBool,
        after_read: impl FnOnce(),
    ) -> Result<NativeFinalityProofInterval, FinalityProofIntervalReadError> {
        owner.frames().with_deferred_refund_notifications(|_| {
            limits.check(cancelled)?;
            let mut releases = self.block_hashes.reader_release_batch();
            let (hashes, _) = self.try_event_source(&mut releases, || {})?;
            let final_height = limits.final_height();
            let index = usize::try_from(final_height)
                .ok()
                .and_then(|height| height.checked_sub(1))
                .ok_or(NativeFinalityProofIntervalError::Request)?;
            let expected = hashes.get(index).copied();
            let source = NativeFinalityProofSource::new(
                self.chain_id_ref(),
                self.network_id_ref(),
                &hashes,
                &self.kura,
            );
            let retained = build_proof_interval(&source, owner, limits, cancelled)?;
            after_read();
            limits.check(cancelled)?;
            #[cfg(not(all(test, sumeragi_core_mutation = "HC214")))]
            {
                let mut current_releases = self.block_hashes.reader_release_batch();
                let (current_hashes, _) = self.try_event_source(&mut current_releases, || {})?;
                if expected.is_none() || current_hashes.get(index).copied() != expected {
                    return Err(NativeFinalityProofIntervalError::Source {
                        height: final_height,
                    }
                    .into());
                }
            }
            #[cfg(all(test, sumeragi_core_mutation = "HC214"))]
            let _ = expected;
            Ok(retained)
        })
    }
}

#[cfg(test)]
mod tests;
