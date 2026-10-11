//! Concrete read-only wallet inspector for lexical unsigned-closure validation.
//!
//! Account construction stays outside the read phase. Each inspection uses the canonical
//! purpose owner to reopen the optional existing journal, acquire its original lock, read
//! and authenticate every retained record, and release that lock before returning. Missing
//! custody remains Missing; this owner cannot create, prepare, retire, sign or dispatch.

use super::*;

/// Closed native inspection entry accepted by the unsigned transition read-phase owner.
/// Its fields grant neither currentness nor permission to replace the original request.
pub(in crate::managed) struct NativeClosureInspector<'a> {
    original: &'a Original,
    reader: iroha_wallet::operations::CustodyPreparationReader<'a>,
    deadline: Instant,
}

impl<'a> NativeClosureInspector<'a> {
    pub(super) fn new(
        original: &'a Original,
        account: &'a AccountService,
        deadline: Instant,
    ) -> Self {
        Self {
            original,
            reader: iroha_wallet::operations::CustodyPreparationReader::new(account),
            deadline,
        }
    }

    pub(in crate::managed) fn inspect(
        &mut self,
        attempt: &attempts::Attempt,
    ) -> Result<iroha_wallet::operations::VerifiedNativePreparation> {
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::ClosureWallet);
        // Construct the expected request anew on every call. The wallet owns only immutable
        // terminal records; every call re-enters native lock/byte custody and fresh selection.
        let value = self
            .original
            .request(attempt.terms(), attempt.observation()?, self.deadline)?
            .inspect_with_reader(&mut self.reader, attempt.directory());
        #[cfg(test)]
        closure_phase_tests::after_inspection(attempt, &value)?;
        value
    }
}
