impl PipelineStatusKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Approved => "Approved",
            Self::Committed => "Committed",
            Self::Applied => "Applied",
            Self::Rejected => "Rejected",
            Self::Expired => "Expired",
        }
    }
    fn rank(self) -> u8 {
        match self {
            Self::Queued => 0,
            Self::Approved => 1,
            Self::Expired => 2,
            Self::Rejected => 3,
            Self::Committed => 4,
            Self::Applied => 5,
        }
    }
    fn is_terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Rejected | Self::Expired)
    }
}
/// Stable machine-readable class of a transaction rejection (event streams).
fn transaction_rejection_code(
    reason: &iroha_data_model::transaction::error::TransactionRejectionReason,
) -> &'static str {
    use iroha_data_model::transaction::error::TransactionRejectionReason;
    match reason {
        TransactionRejectionReason::AccountDoesNotExist(_) => "account_does_not_exist",
        TransactionRejectionReason::LimitCheck(_) => "limit_check",
        TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::IvmFault(_)) => {
            "ivm_fault"
        }
        TransactionRejectionReason::Validation(_) => "validation",
        TransactionRejectionReason::InstructionExecution(_) => "instruction_execution",
        TransactionRejectionReason::TriggerExecution(_) => "trigger_execution",
    }
}
fn pipeline_rejection_summary(
    reason: &iroha_data_model::transaction::error::TransactionRejectionReason,
) -> &'static str {
    use iroha_data_model::transaction::error::TransactionRejectionReason;
    match reason {
        TransactionRejectionReason::AccountDoesNotExist(_) => "Account does not exist.",
        TransactionRejectionReason::LimitCheck(_) => "Transaction limits were exceeded.",
        TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::IvmFault(_)) => {
            "IVM execution failed."
        }
        TransactionRejectionReason::Validation(_) => "Transaction validation failed.",
        TransactionRejectionReason::InstructionExecution(_) => "Instruction execution failed.",
        TransactionRejectionReason::TriggerExecution(_) => "Trigger execution failed.",
    }
}
