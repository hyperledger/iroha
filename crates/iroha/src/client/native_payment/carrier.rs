//! Request-bound authorization before signing or dispatching restored journal bytes.

use super::*;
use crate::workflow::{SignedStepTransaction, TransactionIdentityV1, WorkflowBindingV1};
use iroha_data_model::transaction::{Executable, TransactionPayload};

fn mismatch() -> StepFailure {
    StepFailure::new(
        WorkflowErrorCode::BindingMismatch,
        "native payment carrier differs from its independently retained request",
    )
}

impl NativePaymentRequest {
    pub(super) fn validate_payload(&self, payload: &TransactionPayload) -> Result<(), StepFailure> {
        if payload.network_id() != Some(&self.intent.network_id)
            || payload.authority() != self.intent.settlement_id.owner()
            || payload.fee_payment != self.fee_payment
            || !payload.metadata.is_empty()
            || payload.attachments.is_some()
        {
            return Err(mismatch());
        }
        let Executable::Instructions(instructions) = payload.instructions() else {
            return Err(mismatch());
        };
        let [instruction] = instructions.as_ref() else {
            return Err(mismatch());
        };
        let any = instruction.as_any();
        let intent = any.downcast_ref::<SettleAtomic>().or_else(|| match any
            .downcast_ref::<SettlementInstructionBox>()
        {
            Some(SettlementInstructionBox::Atomic(intent)) => Some(intent),
            _ => None,
        });
        if intent != Some(&self.intent) {
            return Err(mismatch());
        }
        Ok(())
    }

    pub(super) fn checked_signed_carrier(
        &self,
        bytes: &[u8],
    ) -> Result<(SignedTransaction, TransactionIdentityV1), StepFailure> {
        let transaction = super::super::workflow_ledger::decode_signed(bytes)?;
        self.validate_payload(transaction.payload())?;
        transaction.verify_signature().map_err(|_| mismatch())?;
        let identity = TransactionIdentityV1 {
            signed_transaction_hash: *Hash::from(transaction.hash()).as_ref(),
            entrypoint_hash: *Hash::from(transaction.hash_as_entrypoint()).as_ref(),
        };
        Ok((transaction, identity))
    }
}

pub(super) struct NativePaymentAccount {
    account: Arc<dyn WorkflowAccount>,
    request: NativePaymentRequest,
}

impl NativePaymentAccount {
    pub fn new(account: Arc<dyn WorkflowAccount>, request: NativePaymentRequest) -> Self {
        Self { account, request }
    }
}

impl WorkflowAccount for NativePaymentAccount {
    fn binding(&self) -> WorkflowBindingV1 {
        self.account.binding()
    }

    fn sign<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
        Box::pin(async move {
            let payload = super::super::workflow_ledger::decode_unsigned(bytes)?;
            self.request.validate_payload(&payload)?;
            let signed = self.account.sign(bytes).await?;
            let (transaction, identity) = self
                .request
                .checked_signed_carrier(&signed.signed_transaction)?;
            if transaction.payload() != &payload || signed.identity != identity {
                return Err(mismatch());
            }
            Ok(signed)
        })
    }

    fn identify(&self, bytes: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
        self.request
            .checked_signed_carrier(bytes)
            .map(|(_, identity)| identity)
    }
}

/// Resume has no signing authority, while retaining the same canonical identity checks.
pub(super) struct ResumePaymentAccount {
    binding: WorkflowBindingV1,
    request: NativePaymentRequest,
}
impl ResumePaymentAccount {
    pub fn new(binding: WorkflowBindingV1, request: NativePaymentRequest) -> Self {
        Self { binding, request }
    }
}
impl WorkflowAccount for ResumePaymentAccount {
    fn binding(&self) -> WorkflowBindingV1 {
        self.binding.clone()
    }
    fn sign<'a>(
        &'a self,
        _: &'a [u8],
    ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
        Box::pin(async {
            Err(StepFailure::new(
                WorkflowErrorCode::UnsupportedOperation,
                "payment resume cannot authorize another signed carrier",
            ))
        })
    }
    fn identify(&self, bytes: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
        self.request
            .checked_signed_carrier(bytes)
            .map(|(_, identity)| identity)
    }
}
/// Same bound driver identity; payload construction is unavailable during resume.
pub(super) struct ResumePaymentDriver(DriverIdentityV1);
impl ResumePaymentDriver {
    pub fn new(identity: DriverIdentityV1) -> Self {
        Self(identity)
    }
}
impl WorkflowDriver for ResumePaymentDriver {
    fn identity(&self) -> DriverIdentityV1 {
        self.0.clone()
    }
}
