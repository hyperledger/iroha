//! Direct native dispatch retains the exact signed source and approved executor path.
//!
//! Contract/ABI requests stay closed until their actual invocation queue is wired.
//! No request reference or audit digest is a permission or verification capability.
use super::{
    Executor, InstructionExecutionProfile,
    attachment_custody::{AttachmentCustody, CustodyError, Invocation},
};
use crate::{smartcontracts::isi::privacy, state::StateTransaction};
use iroha_data_model::{
    ValidationFail,
    account::AccountId,
    isi::{
        InstructionBox, error::InstructionExecutionError, privacy::BootstrapPrivacyPgcAccountsV1,
    },
    transaction::{signed::TransactionSignatureError, signed_attachments::SignedAttachmentErrorV1},
};

#[derive(Debug, thiserror::Error)]
enum DirectError {
    #[error(transparent)]
    Custody(#[from] CustodyError),
    #[error(transparent)]
    Execution(#[from] ValidationFail),
}

pub(super) fn custody_validation_error(
    state: &mut StateTransaction<'_, '_>,
    error: CustodyError,
) -> ValidationFail {
    match error {
        CustodyError::Declaration(SignedAttachmentErrorV1::LocalResource(original)) => {
            state.defer_execution(original)
        }
        CustodyError::Signature(TransactionSignatureError::UnsupportedImplementation(original)) => {
            state.defer_execution(
                ivm::error::ExecutionDeferral::CryptoImplementationUnavailable(original),
            )
        }
        original => ValidationFail::NotPermitted(format!(
            "original signed attachment custody refused: {original}"
        )),
    }
}

impl Executor {
    /// Execute one original signed direct item at its executable position.
    /// Both initial and installed executor validation remain before State application.
    pub(crate) fn execute_original_direct_instruction(
        &self,
        state: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        instruction: &InstructionBox,
        instruction_index: usize,
        custody: Option<&mut AttachmentCustody<'_>>,
    ) -> Result<(), ValidationFail> {
        let Some(custody) = custody else {
            return self.execute_instruction_with_attachment_context(
                state,
                authority,
                instruction,
                InstructionExecutionProfile::Runtime,
                None,
                None,
            );
        };
        let index = u32::try_from(instruction_index).map_err(|_| {
            ValidationFail::NotPermitted("direct instruction ordinal exceeds u32".into())
        })?;
        custody
            .require_original_direct_instruction(index, instruction)
            .map_err(|error| custody_validation_error(state, error))?;
        let result: Result<(), DirectError> = custody.direct(index, authority, |invocation| {
            self.execute_instruction_with_attachment_context(
                state,
                authority,
                instruction,
                InstructionExecutionProfile::Runtime,
                None,
                Some(invocation),
            )
            .map_err(Into::into)
        });
        result.map_err(|error| match error {
            DirectError::Custody(original) => custody_validation_error(state, original),
            DirectError::Execution(original) => original,
        })
    }
}

/// The shared application point after either executor has authorized the instruction.
pub(super) fn apply_authorized_instruction(
    instruction: &InstructionBox,
    authority: &AccountId,
    state: &mut StateTransaction<'_, '_>,
    invocation: Option<&mut Invocation<'_, '_>>,
) -> Result<(), InstructionExecutionError> {
    if let Some(bootstrap) = instruction
        .as_any()
        .downcast_ref::<BootstrapPrivacyPgcAccountsV1>()
    {
        if let Some(invocation) = invocation {
            return privacy::execute_pgc_bootstrap(bootstrap, authority, state, invocation);
        }
    }
    crate::smartcontracts::isi::execute_borrowed_instruction(instruction, authority, state)
}
