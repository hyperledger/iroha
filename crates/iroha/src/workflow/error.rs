//! Typed workflow error carrying stage, step, bounds and the explicit progress snapshot.

use super::{
    contract::{WorkflowErrorCode, WorkflowStage},
    journal::{TransactionIdentityV1, WorkflowProgressV1},
};

/// Actual and maximum value of an exceeded bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkflowBounds {
    /// Observed value.
    pub actual: u64,
    /// Largest permitted value.
    pub maximum: u64,
}

/// Typed failure or non-terminal stop of a workflow call.
///
/// `progress` states partial completion explicitly. It is absent only when no
/// trustworthy journal could be read: a corrupted journal never produces a
/// manufactured snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowError {
    /// Closed error code.
    pub code: WorkflowErrorCode,
    /// Stage that produced the error.
    pub stage: WorkflowStage,
    /// Step the error refers to, when one is current.
    pub step_index: Option<u32>,
    /// Transaction identity the error refers to, when one exists.
    pub transaction: Option<Box<TransactionIdentityV1>>,
    /// Actual and maximum value for bound errors.
    pub bounds: Option<WorkflowBounds>,
    /// Diagnostic without secret material.
    pub detail: String,
    /// Snapshot of the last journal this call validated or stored.
    pub progress: Option<Box<WorkflowProgressV1>>,
    /// Sequence of the last journal record this call validated or stored.
    pub last_validated_sequence: Option<u64>,
}

impl WorkflowError {
    /// Create an error without step, identity, bounds or progress.
    #[must_use]
    pub fn new(code: WorkflowErrorCode, stage: WorkflowStage, detail: impl Into<String>) -> Self {
        Self {
            code,
            stage,
            step_index: None,
            transaction: None,
            bounds: None,
            detail: detail.into(),
            progress: None,
            last_validated_sequence: None,
        }
    }

    /// Create a bound error with its actual and maximum value.
    #[must_use]
    pub fn limit(stage: WorkflowStage, what: &str, actual: usize, maximum: usize) -> Self {
        let mut error = Self::new(
            WorkflowErrorCode::ResourceLimitExceeded,
            stage,
            format!("{what} is {actual}, maximum {maximum}"),
        );
        error.bounds = Some(WorkflowBounds {
            actual: actual as u64,
            maximum: maximum as u64,
        });
        error
    }

    /// Attach the step index.
    #[must_use]
    pub fn with_step(mut self, step_index: usize) -> Self {
        self.step_index = u32::try_from(step_index).ok();
        self
    }

    /// Attach the transaction identity.
    #[must_use]
    pub fn with_transaction(mut self, identity: Option<TransactionIdentityV1>) -> Self {
        self.transaction = identity.map(Box::new);
        self
    }

    /// Attach the progress snapshot of a validated journal.
    #[must_use]
    pub fn with_progress(mut self, progress: WorkflowProgressV1) -> Self {
        self.last_validated_sequence = Some(progress.sequence);
        self.progress = Some(Box::new(progress));
        self
    }

    /// Whether a later call on the same journal may make progress.
    ///
    /// Terminal workflow statuses and a corrupted journal are not resumable.
    #[must_use]
    pub fn is_resumable(&self) -> bool {
        if self.code == WorkflowErrorCode::StorageCorrupted {
            return false;
        }
        self.progress
            .as_ref()
            .is_none_or(|progress| !progress.status.is_terminal())
    }
}

impl core::fmt::Display for WorkflowError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "durable workflow {} at stage {}",
            self.code, self.stage
        )?;
        if let Some(step) = self.step_index {
            write!(formatter, ", step {step}")?;
        }
        if let Some(bounds) = self.bounds {
            write!(
                formatter,
                ", actual {} maximum {}",
                bounds.actual, bounds.maximum
            )?;
        }
        if !self.detail.is_empty() {
            write!(formatter, ": {}", self.detail)?;
        }
        Ok(())
    }
}

impl std::error::Error for WorkflowError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_names_code_stage_step_and_bounds() {
        let error = WorkflowError::limit(WorkflowStage::Prove, "payload bytes", 9, 8).with_step(2);
        assert_eq!(error.code, WorkflowErrorCode::ResourceLimitExceeded);
        assert_eq!(
            error.bounds,
            Some(WorkflowBounds {
                actual: 9,
                maximum: 8
            })
        );
        assert_eq!(
            error.to_string(),
            "durable workflow ResourceLimitExceeded at stage prove, step 2, actual 9 maximum 8: payload bytes is 9, maximum 8"
        );
        assert!(error.is_resumable());
    }

    #[test]
    fn corruption_is_never_resumable_and_carries_no_identity_by_default() {
        let error = WorkflowError::new(
            WorkflowErrorCode::StorageCorrupted,
            WorkflowStage::Load,
            "digest",
        )
        .with_transaction(None);
        assert!(!error.is_resumable());
        assert!(error.progress.is_none());
        assert!(error.last_validated_sequence.is_none());
        assert!(error.transaction.is_none());
    }
}
