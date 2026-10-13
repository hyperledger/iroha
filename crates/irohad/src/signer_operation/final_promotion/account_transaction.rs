//! Prepared Reserve/Complete transactions retain actual native Check authority and receipt pins.
//!
//! Preparation never authorizes key use. The signing continuation consumes fresh purpose-native
//! account Checks and keeps signatures private until both account and receipt authority have been
//! checked again. It retains the exact payload, original deadlines and the private completion
//! receipt through submission. Software and optional hardware adapters share this contract.
//! TODO: Connect the configured software provider, observer submission, approved spending journal,
//! qualified UTC source and independently retained floor store to this continuation.

use std::{fmt, sync::Arc};

use iroha_core::query::{
    final_promotion_account_custody::observation::{
        FinalPromotionAccountEligibilityTimeIntervalV1, VerifiedFinalPromotionAccountCheckV1,
        validate_final_promotion_account_transaction_envelope_v1,
    },
    final_promotion_authority::observation::{
        FinalPromotionEligibilityTimeIntervalV1, VerifiedFinalPromotionCheckV1,
    },
};
use iroha_data_model::{
    account::AccountId,
    isi::sorafs::MutateSorafsFinalPromotionAuthority,
    sorafs::final_promotion_authority::{
        FinalPromotionAuthorityActionV1, FinalPromotionCheckSubjectV1, FinalPromotionCompleteV1,
        FinalPromotionOperationOutcomeV1, FinalPromotionReserveV1,
    },
    transaction::{Executable, FeePaymentIntent, TransactionPayload},
};
use sha2::{Digest as _, Sha256};
use sorafs_manifest::signer::{
    custody::{SignerCustodyBindingV1, SignerCustodyUseContextV1, verify_signer_custody_use_v1},
    final_promotion::{
        SignerFinalPromotionExpectedV1, SignerFinalPromotionReceiptV1,
        signer_final_promotion_digest_v1, statement::prepare_final_promotion_statement_v1,
        validate_final_promotion_signatures_v1,
    },
    protocol::{
        SignerKeyAlgorithmV1, SignerOperationActionV1, SignerOperationIntentV1,
        SignerPurposeBindingV1, SignerRoleV1, signer_operation_signatures_digest_v1,
    },
};

use super::super::journal::{
    PinnedReceipt, SignerReceiptJournalReaderV1, SignerReceiptJournalV1, SignerReceiptPurposeV1,
};

mod signing;
mod software_key;
pub use signing::{
    AuthorizedFinalPromotionAccountTransactionV1, FinalPromotionAccountKeyRequestV1,
    PendingFinalPromotionAccountReleaseV1, PendingFinalPromotionAccountSignatureV1,
    SignedFinalPromotionAccountTransactionV1,
};
pub use software_key::SoftwareFinalPromotionAccountKeyV1;

const PAYLOAD_DOMAIN: &[u8] = b"iroha.sorafs.final-promotion-account.transaction-payload.v1\0";

/// Fixed failures of native account preparation, authority or signing; no backend detail escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalPromotionAccountTransactionErrorV1 {
    /// The independently reviewed role, network, deployment or statement does not match.
    Binding,
    /// The full payload, approved fee intent, native action or canonical envelope differs.
    Payload,
    /// An executed native Check is ineligible, expired, substituted or from another phase.
    Authority,
    /// The actual private completion receipt is absent, substituted or invalid.
    Receipt,
    /// The configured software or optional hardware provider did not return a valid signature.
    Provider,
    /// Local canonical-frame resources were unavailable; no semantic payload rejection occurred.
    /// This fixed service error carries no reusable signature or retry continuation.
    LocalCapacity,
}
impl fmt::Display for FinalPromotionAccountTransactionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Binding => "final-promotion account transaction binding rejected",
            Self::Payload => "final-promotion account transaction payload rejected",
            Self::Authority => "final-promotion account transaction authority rejected",
            Self::Receipt => "final-promotion account transaction receipt rejected",
            Self::Provider => "final-promotion account transaction signer unavailable",
            Self::LocalCapacity => {
                "final-promotion account transaction local resources unavailable"
            }
        })
    }
}
impl std::error::Error for FinalPromotionAccountTransactionErrorV1 {}
type Error = FinalPromotionAccountTransactionErrorV1;

/// Purpose-specific read capability over one independently reviewed statement and receipt lease.
///
/// Create this from the same journal before moving that journal into the final-promotion service.
/// It has no staging, role-14 signing or receipt-release API. Construction proves no native authority.
pub struct SignerFinalPromotionAccountPreparationV1 {
    binding: SignerCustodyBindingV1,
    expected: SignerFinalPromotionExpectedV1,
    statement: Arc<[u8]>,
    journal: SignerReceiptJournalReaderV1,
}
impl SignerFinalPromotionAccountPreparationV1 {
    /// Retain the exact reviewed statement and the original journal's read-only directory lease.
    ///
    /// # Errors
    /// Rejects another journal family or a statement differing from the reviewed coordinates.
    pub fn new(
        binding: SignerCustodyBindingV1,
        expected: SignerFinalPromotionExpectedV1,
        statement: Arc<[u8]>,
        journal: &SignerReceiptJournalV1,
    ) -> Result<Self, Error> {
        if journal.purpose() != SignerReceiptPurposeV1::FinalPromotionProvenance {
            return Err(Error::Receipt);
        }
        let prepared = prepare_final_promotion_statement_v1(&statement, &binding)
            .map_err(|_| Error::Binding)?;
        if expected.operation_id == [0; 32]
            || expected.statement_size != prepared.len() as u64
            || expected.statement_digest != signer_final_promotion_digest_v1(prepared.message())
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            binding,
            expected,
            statement,
            journal: journal.reader(),
        })
    }

    /// Prepare exactly the Reserve or Complete derived from one actual executed receipt Check.
    ///
    /// `approved_fees` is an independent, finite spending approval selected before this payload;
    /// this method compares it exactly and never quotes, increases or changes approved fees.
    /// Complete additionally validates and pins the actual four-signature staged receipt.
    ///
    /// # Errors
    /// Rejects another action/phase, network, account, fee choice, statement, receipt or payload.
    pub fn prepare(
        &self,
        receipt_check: VerifiedFinalPromotionCheckV1,
        account_binding: SignerCustodyBindingV1,
        approved_fees: &FeePaymentIntent,
        payload: TransactionPayload,
    ) -> Result<PreparedFinalPromotionAccountTransactionV1, Error> {
        receipt_check.ensure_live().map_err(|_| Error::Authority)?;
        validate_account_binding(&self.binding, &account_binding, &receipt_check)?;
        let checked_instruction = receipt_check.instruction();
        let FinalPromotionAuthorityActionV1::Check(check) = &checked_instruction.action else {
            return Err(Error::Authority);
        };
        if receipt_check.snapshot().control.policy.binding != self.binding
            || check.request.operation_id != self.expected.operation_id
            || check.request.statement_digest != self.expected.statement_digest
            || check.request.statement_size != self.expected.statement_size
        {
            return Err(Error::Binding);
        }
        check
            .request
            .validate_binding(&self.binding)
            .map_err(|_| Error::Binding)?;
        let (action, receipt) = match &check.subject {
            FinalPromotionCheckSubjectV1::Current(audit) => (
                FinalPromotionAuthorityActionV1::Reserve(FinalPromotionReserveV1 {
                    intent: SignerOperationIntentV1 {
                        action: SignerOperationActionV1::Sign,
                        operation_id: check.request.operation_id,
                        request_digest: check.request.digest().map_err(|_| Error::Binding)?,
                        previous_audit: *audit,
                    },
                    custody: check.request.original_custody,
                }),
                None,
            ),
            FinalPromotionCheckSubjectV1::BeforeCommit(operation) => {
                if operation.outcome != FinalPromotionOperationOutcomeV1::Reserved {
                    return Err(Error::Authority);
                }
                let pinned = self
                    .journal
                    .recover(self.expected.operation_id)
                    .map_err(|_| Error::Receipt)?;
                let receipt: SignerFinalPromotionReceiptV1 =
                    norito::decode_canonical(pinned.bytes()).map_err(|_| Error::Receipt)?;
                self.validate_receipt(&receipt, &receipt_check)?;
                if receipt.intent != operation.intent
                    || receipt.reservation != operation.reservation
                    || receipt.request.original_custody != operation.custody
                {
                    return Err(Error::Receipt);
                }
                let complete = FinalPromotionCompleteV1 {
                    intent: receipt.intent,
                    custody: receipt.request.original_custody,
                    reservation: receipt.reservation,
                    commitment: receipt.commitment,
                    signatures_digest: signer_operation_signatures_digest_v1(&receipt.signatures)
                        .map_err(|_| Error::Receipt)?,
                };
                pinned.recheck().map_err(|_| Error::Receipt)?;
                (
                    FinalPromotionAuthorityActionV1::Complete(complete),
                    Some(pinned),
                )
            }
            _ => return Err(Error::Authority),
        };
        let instruction = MutateSorafsFinalPromotionAuthority {
            deployment_id: checked_instruction.deployment_id.clone(),
            expected_control_revision: checked_instruction.expected_control_revision,
            expected_control_digest: checked_instruction.expected_control_digest,
            action,
        };
        let payload_digest =
            validate_payload(&account_binding, &instruction, approved_fees, &payload)?;
        receipt_check.ensure_live().map_err(|_| Error::Authority)?;
        Ok(PreparedFinalPromotionAccountTransactionV1 {
            binding: account_binding,
            payload,
            payload_digest,
            receipt_check,
            receipt,
        })
    }

    fn validate_receipt(
        &self,
        receipt: &SignerFinalPromotionReceiptV1,
        check: &VerifiedFinalPromotionCheckV1,
    ) -> Result<(), Error> {
        let snapshot = check.snapshot();
        let context = SignerCustodyUseContextV1 {
            now_unix_ms: check.eligibility_time_interval().latest_unix_ms,
            anchor_observed_at_unix_ms: check.eligibility_time_interval().earliest_unix_ms,
            current_anchor: snapshot.custody_anchor,
            active_head: snapshot.control.active_head.ok_or(Error::Authority)?,
            signer_revoked: snapshot.control.signer_revoked,
            attester_revoked: snapshot.control.attester_revoked,
        };
        if snapshot.control_record.enrollment.as_deref() != Some(receipt.custody_record.as_slice())
        {
            return Err(Error::Receipt);
        }
        let custody = verify_signer_custody_use_v1(
            &receipt.custody_record,
            &self.binding,
            &snapshot.control.policy.custody_trust(),
            &context,
        )
        .map_err(|_| Error::Authority)?;
        let signature = receipt.signatures.first().ok_or(Error::Receipt)?;
        validate_final_promotion_signatures_v1(
            receipt,
            &self.statement,
            &signature.signature,
            &self.expected,
            &custody,
        )
        .map(|_| ())
        .map_err(|_| Error::Receipt)
    }
}

/// Move-only exact unsigned account transaction retaining its original executed receipt Check.
/// It has no serialization, replacement payload, renewable deadline or signing authority.
pub struct PreparedFinalPromotionAccountTransactionV1 {
    binding: SignerCustodyBindingV1,
    payload: TransactionPayload,
    payload_digest: [u8; 32],
    receipt_check: VerifiedFinalPromotionCheckV1,
    receipt: Option<PinnedReceipt>,
}
impl PreparedFinalPromotionAccountTransactionV1 {
    /// Prepare observer signing with the exact identities retained by this account workflow.
    ///
    /// Fee approval is selected independently for the observer, not inherited from the operator.
    /// This does not authenticate a provider or replace fresh native Checks at later phases.
    ///
    /// # Errors
    /// Rejects an expired original Check or inconsistent observer configuration and fee approval.
    pub fn observer_transactions(
        &self,
        approved_fees: FeePaymentIntent,
    ) -> Result<super::observer_transaction::FinalPromotionObserverTransactionsV1, Error> {
        self.receipt_check
            .ensure_live()
            .map_err(|_| Error::Authority)?;
        super::observer_transaction::FinalPromotionObserverTransactionsV1::new(
            self.receipt_check.snapshot().control.policy.binding.clone(),
            self.binding.clone(),
            self.receipt_check.observer().clone(),
            approved_fees,
        )
        .map_err(|_| Error::Binding)
    }

    /// Exact full canonical-payload commitment to put in the distinct account Current Check.
    #[must_use]
    pub const fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }

    /// Exact reviewed role-15 binding; its public identity does not itself grant authority.
    #[must_use]
    pub const fn binding(&self) -> &SignerCustodyBindingV1 {
        &self.binding
    }

    fn recheck(&self, interval: FinalPromotionEligibilityTimeIntervalV1) -> Result<(), Error> {
        self.receipt_check
            .recheck_use_interval(interval)
            .map_err(|_| Error::Authority)?;
        if let Some(receipt) = &self.receipt {
            receipt.recheck().map_err(|_| Error::Receipt)?;
        }
        self.receipt_check
            .ensure_live()
            .map_err(|_| Error::Authority)
    }
}
impl fmt::Debug for PreparedFinalPromotionAccountTransactionV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedFinalPromotionAccountTransactionV1")
            .finish_non_exhaustive()
    }
}

fn validate_account_binding(
    receipt: &SignerCustodyBindingV1,
    account: &SignerCustodyBindingV1,
    checked: &VerifiedFinalPromotionCheckV1,
) -> Result<(), Error> {
    account.validate().map_err(|_| Error::Binding)?;
    let SignerPurposeBindingV1::FinalPromotionProvenance { deployment_id } = &receipt.purpose
    else {
        return Err(Error::Binding);
    };
    if account.role != SignerRoleV1::FinalPromotionAccountTransaction
        || account.algorithm != SignerKeyAlgorithmV1::Ed25519
        || account.purpose
            != (SignerPurposeBindingV1::FinalPromotionAccountTransaction {
                deployment_id: deployment_id.clone(),
            })
        || account.chain_id != receipt.chain_id
        || account.network_id != receipt.network_id
        || account.public_key == receipt.public_key
        || checked.expected_operator() != &AccountId::new(account.public_key.clone())
        || checked.observer() == &AccountId::new(account.public_key.clone())
        || checked.observer() == &AccountId::new(receipt.public_key.clone())
    {
        return Err(Error::Binding);
    }
    Ok(())
}

fn validate_payload(
    binding: &SignerCustodyBindingV1,
    instruction: &MutateSorafsFinalPromotionAuthority,
    approved_fees: &FeePaymentIntent,
    payload: &TransactionPayload,
) -> Result<[u8; 32], Error> {
    validate_final_promotion_account_transaction_envelope_v1(payload)
        .map_err(|_| Error::Payload)?;
    approved_fees.validate().map_err(|_| Error::Payload)?;
    let Executable::Instructions(instructions) = &payload.instructions else {
        return Err(Error::Payload);
    };
    if payload.authority != AccountId::new(binding.public_key.clone())
        || payload
            .network_id()
            .map(iroha_data_model::NetworkId::as_bytes)
            != Some(&binding.network_id)
        || payload.fee_payment_intent() != approved_fees
        || instructions.len() != 1
        || instructions[0]
            .as_any()
            .downcast_ref::<MutateSorafsFinalPromotionAuthority>()
            != Some(instruction)
        || !matches!(
            instruction.action,
            FinalPromotionAuthorityActionV1::Reserve(_)
                | FinalPromotionAuthorityActionV1::Complete(_)
        )
    {
        return Err(Error::Payload);
    }
    let canonical = norito::encode_canonical(payload).map_err(|_| Error::Payload)?;
    let mut hasher = Sha256::new();
    hasher.update(PAYLOAD_DOMAIN);
    hasher.update(&canonical);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests;
