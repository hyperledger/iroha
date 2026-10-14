//! Preserve the State publisher's original unfinished resource owner across the worker boundary.
use super::PublicationError;
use crate::state::storage_transactions::{MembershipAdmissionError, TransactionsBlockError};
use crate::sumeragi::driver::traits::PublicationDeferral;

pub(super) fn original_refusal(error: TransactionsBlockError) -> PublicationError {
    if cfg!(all(test, sumeragi_core_mutation = "HC63")) {
        return PublicationError::Retryable(error.to_string());
    }
    let original = match error {
        TransactionsBlockError::ExecutionDeferred(original) => {
            PublicationDeferral::Execution(original)
        }
        TransactionsBlockError::BlockHashesBusy(wait) => PublicationDeferral::BlockHashesBusy(wait),
        TransactionsBlockError::PublicationBusy(wait) => PublicationDeferral::PublicationBusy(wait),
        TransactionsBlockError::MembershipAdmission(MembershipAdmissionError::Busy(wait)) => {
            PublicationDeferral::MembershipBusy(wait)
        }
        error => return PublicationError::RecoveryRequired(error.to_string()),
    };
    PublicationError::Deferred(original)
}

#[cfg(test)]
mod tests;
