//! Native destructive review delegates exclusively to the same admitted custody owner.

use super::*;

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    /// Read exact Pending/Released custody for an explicit destructive warning.
    /// Retiring and ordinary collection never call this operation.
    /// # Errors
    /// Changed/missing custody, no committed head or an unresolved deletion attempt.
    pub fn review_custody_deletion(&mut self) -> Result<ReviewedCustodyDeletionV1, Error> {
        Ok(self
            .custody
            .review_custody_deletion(&self.scheme_id, &self.wallet_id)?)
    }

    /// Consume the actual review after fresh explicit confirmation of permanent key/value loss.
    /// On any attempted-publication error, ordinary operations stay frozen until reconciliation.
    /// # Errors
    /// Foreign/stale review, unavailable storage, or unknown publication/cleanup outcome.
    pub fn confirm_custody_deletion(
        &mut self,
        review: ReviewedCustodyDeletionV1,
    ) -> Result<CustodyDeletionProgressV1, Error> {
        Ok(self.custody.confirm_custody_deletion(review)?)
    }

    /// Reconcile only an existing attempt; never newly authorize or publish deletion.
    /// # Errors
    /// No prior attempt, missing custody, or incomplete terminal cleanup.
    pub fn resume_custody_deletion(&mut self) -> Result<CustodyDeletionProgressV1, Error> {
        Ok(self.custody.resume_custody_deletion()?)
    }

    /// Refuse foreign money operations while deletion is uncertain or terminal.
    /// # Errors
    /// A deletion was attempted and has not been proved uncommitted by reconciliation.
    pub fn require_custody_operations(&self) -> Result<(), Error> {
        Ok(self.custody.require_custody_operations()?)
    }
}
