//! Original local output-maintenance refusal, kept outside deterministic results.

use crate::execution_attempt::{ExecutionAttemptError, ExecutionDeferred};
use crate::state::StateStorageAdmissionError;

/// Failure before the common output owner can retain or seal complete effects.
/// A discarded maintenance journal cannot erase either original local owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExecutionOutputAttemptError {
    /// Execution completed with inconsistent source, policy or output ownership.
    Owner(String),
    /// An actual local execution refusal; no deterministic output exists yet.
    Deferred(ExecutionDeferred),
    /// Original State storage admission refusal, including its release observation.
    Storage(StateStorageAdmissionError),
}

impl From<ExecutionAttemptError<String>> for ExecutionOutputAttemptError {
    fn from(error: ExecutionAttemptError<String>) -> Self {
        match error {
            ExecutionAttemptError::Rejected(reason) => Self::Owner(reason),
            ExecutionAttemptError::Deferred(reason) => Self::Deferred(reason),
        }
    }
}

impl From<StateStorageAdmissionError> for ExecutionOutputAttemptError {
    fn from(error: StateStorageAdmissionError) -> Self {
        Self::Storage(error)
    }
}

impl From<String> for ExecutionOutputAttemptError {
    fn from(error: String) -> Self {
        Self::Owner(error)
    }
}

impl From<&str> for ExecutionOutputAttemptError {
    fn from(error: &str) -> Self {
        Self::Owner(error.to_owned())
    }
}

impl core::fmt::Display for ExecutionOutputAttemptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Owner(error) => error.fmt(f),
            Self::Deferred(error) => write!(f, "execution deferred: {error}"),
            Self::Storage(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ExecutionOutputAttemptError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ExecutionOutputSealError;

    #[test]
    fn output_attempt_and_seal_preserve_original_storage_capacity_release() {
        // A full original pool refuses with a release observation.
        let budget = iroha_allocation::AllocationBudget::new(1);
        let occupied = budget.try_reserve_bytes(1).unwrap();
        let original =
            mv::storage::AdmittedStorageError::Allocation(budget.try_reserve_bytes(1).unwrap_err());
        let expected = StateStorageAdmissionError::World(original);
        assert!(expected.release_wait().is_some());
        let output: ExecutionOutputAttemptError = expected.clone().into();
        let sealed: ExecutionOutputSealError<()> = output.into();
        let ExecutionOutputSealError::Storage(observed) = sealed else {
            panic!("original storage refusal must not enter a deterministic owner error");
        };
        assert_eq!(observed, expected);
        assert!(observed.release_wait().is_some());
        drop(occupied);
        assert!(budget.try_reserve_bytes(1).is_ok());
    }
}
