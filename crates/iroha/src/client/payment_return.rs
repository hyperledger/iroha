//! Linked full returns through the existing native payment operation.

use super::{
    AccountClient, NativePaymentError, NativePaymentObservationError, NativePaymentOperation,
    NativePaymentRequest, NativePaymentRunOptions, VerifiedPaymentReceipt,
};
use crate::workflow::{WorkflowProgressV1, WorkflowStorage, domain_digest};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    asset::AssetBalanceScope,
    isi::{
        AtomicSettlementMovement, AtomicSettlementMovements, SettleAtomic, SettlementDetails,
        SettlementId,
    },
    sumeragi_finality::SumeragiFinalityVerifier,
    transaction::{FeePaymentIntent, SignedTransaction, TransactionEntrypoint},
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::json::Json;
use std::{num::NonZeroU64, sync::Arc};

/// Exact signed link identifying the successful original of a full native return.
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::JsonSerialize, norito::derive::JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct NativePaymentReturnLink {
    /// Genesis-derived network of both payments.
    pub original_network: NetworkId,
    /// Original payer-scoped business identity.
    pub original_settlement_id: SettlementId,
    /// Original independently verified successful signed carrier.
    pub original_transaction: HashOf<SignedTransaction>,
    /// Original complete signed native settlement terms.
    pub original_intent_hash: Hash,
}

/// A full reverse payment derived from an independently verified original.
///
/// The derived receiver-owned ID is stable across processes and gateways. Ordinary
/// transfers with another ID do not become verified linked returns. Partial returns
/// are unsupported until consensus owns a cumulative return allowance.
#[derive(Clone, Debug)]
pub struct NativePaymentFullReturnRequest {
    original: VerifiedPaymentReceipt,
    payment: NativePaymentRequest,
    link: NativePaymentReturnLink,
}
impl NativePaymentFullReturnRequest {
    /// Reverse the exact original Global bucket direction and full principal.
    /// The return has its own expiry and exact fee authorization.
    /// # Errors
    /// Original is not one Global movement, encoding fails, or return fees are unsupported.
    pub fn new(
        original: VerifiedPaymentReceipt,
        expiry_height: NonZeroU64,
        fee_payment: FeePaymentIntent,
    ) -> Result<Self, NativePaymentError> {
        let SettlementDetails::Atomic(details) = &original.settlement().details else {
            return Err(NativePaymentError::InvalidRequest(
                "full return requires an atomic original",
            ));
        };
        let [movement] = details.movements.as_slice() else {
            return Err(NativePaymentError::InvalidRequest(
                "full return requires one original movement",
            ));
        };
        if movement.source.scope() != &AssetBalanceScope::Global
            || movement.destination.scope() != &AssetBalanceScope::Global
        {
            return Err(NativePaymentError::InvalidRequest(
                "full return requires Global original buckets",
            ));
        }
        let link = NativePaymentReturnLink {
            original_network: original.network(),
            original_settlement_id: original.settlement_id().clone(),
            original_transaction: original.transaction_hash(),
            original_intent_hash: details.intent_hash,
        };
        let identity = norito::encode_canonical(&(
            original.network(),
            original.settlement_id().clone(),
            original.transaction_hash(),
        ))
        .map_err(NativePaymentObservationError::Encoding)?;
        let reference = format!(
            "return_{}",
            hex::encode(domain_digest(
                b"iroha:native-payment:full-return-id:v1\0",
                &[&identity]
            ))
        );
        let settlement_id = SettlementId::new(
            movement.destination.account().clone(),
            reference.parse().map_err(|_| {
                NativePaymentError::InvalidRequest("derived full return reference is invalid")
            })?,
        );
        let mut metadata = Metadata::default();
        metadata.insert(
            "native_payment_full_return"
                .parse()
                .expect("fixed metadata name"),
            Json::new(link.clone()),
        );
        let intent = SettleAtomic::new(
            original.network(),
            settlement_id,
            AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
                source: movement.destination.clone(),
                recipient: movement.source.account().clone(),
                quantity: movement.quantity.clone(),
            }])
            .map_err(NativePaymentError::InvalidRequest)?,
            expiry_height,
            metadata,
        );
        let payment = NativePaymentRequest::new(intent, fee_payment)?;
        Ok(Self {
            original,
            payment,
            link,
        })
    }

    /// Canonical receiver-owned identity to review before authorization or submission.
    #[must_use]
    pub fn settlement_id(&self) -> &SettlementId {
        &self.payment.intent().settlement_id
    }
    /// Exact reverse payment terms and fee authorization.
    #[must_use]
    pub const fn payment(&self) -> &NativePaymentRequest {
        &self.payment
    }
    /// Exact signed relationship with the original successful payment.
    #[must_use]
    pub const fn link(&self) -> &NativePaymentReturnLink {
        &self.link
    }
    /// Original verified settlement, unchanged by the reverse lifecycle.
    #[must_use]
    pub const fn original(&self) -> &VerifiedPaymentReceipt {
        &self.original
    }

    /// Bind an independently verified reverse receipt to this exact full return request.
    /// # Errors
    /// Changed original link, principal, buckets, identity, signed terms or fee authorization.
    pub fn verify_return(
        &self,
        reverse: VerifiedPaymentReceipt,
    ) -> Result<VerifiedPaymentReturn, NativePaymentError> {
        let SettlementDetails::Atomic(details) = &reverse.settlement().details else {
            return Err(NativePaymentError::InvalidRequest(
                "reverse receipt is not atomic",
            ));
        };
        let expected_hash = self
            .payment
            .intent()
            .intent_hash()
            .map_err(NativePaymentObservationError::Encoding)?;
        let TransactionEntrypoint::External(transaction) = reverse.evidence().entrypoint() else {
            return Err(NativePaymentError::InvalidRequest(
                "reverse receipt has no signed carrier",
            ));
        };
        if reverse.network() != self.original.network()
            || reverse.settlement_id() != self.settlement_id()
            || details.intent_hash != expected_hash
            || transaction.authority() != self.settlement_id().owner()
            || transaction.fee_payment_intent() != self.payment.fee_payment()
        {
            return Err(NativePaymentError::InvalidRequest(
                "verified reverse differs from the exact full return request",
            ));
        }
        Ok(VerifiedPaymentReturn {
            original: self.original.clone(),
            reverse,
            link: self.link.clone(),
        })
    }
}

/// Two independently verified payments joined by exact signed full-return terms.
/// The original receipt remains successful and unchanged; no status or ISO report constructs this.
/// ```compile_fail
/// use iroha::client::VerifiedPaymentReturn;
/// let _ = norito::decode_canonical::<VerifiedPaymentReturn>(&[]);
/// ```
#[derive(Clone, Debug)]
pub struct VerifiedPaymentReturn {
    original: VerifiedPaymentReceipt,
    reverse: VerifiedPaymentReceipt,
    link: NativePaymentReturnLink,
}
impl VerifiedPaymentReturn {
    /// Unchanged original successful settlement.
    #[must_use]
    pub const fn original(&self) -> &VerifiedPaymentReceipt {
        &self.original
    }
    /// Independently verified successful full reverse settlement and its own fee outcome.
    #[must_use]
    pub const fn reverse(&self) -> &VerifiedPaymentReceipt {
        &self.reverse
    }
    /// Signed original-to-return relationship.
    #[must_use]
    pub const fn link(&self) -> &NativePaymentReturnLink {
        &self.link
    }
}

/// Verified full return and separate current carrier progress.
#[derive(Debug)]
pub struct NativePaymentReturnSettlement {
    /// Original and exact verified reverse receipts.
    pub receipt: VerifiedPaymentReturn,
    /// Existing workflow carrier progress, including possible rejected retry.
    pub carrier: WorkflowProgressV1,
}
/// Read-only linked-return recovery; no receipt means success was not established.
#[derive(Debug)]
pub struct NativePaymentReturnRecovery {
    /// Verified original and exact reverse, if freshly established.
    pub receipt: Option<VerifiedPaymentReturn>,
    /// Existing carrier journal progress, if present.
    pub carrier: Option<WorkflowProgressV1>,
}
/// Full return using the same native-payment signing, journal, dispatch and proof owners.
#[derive(Debug)]
pub struct NativePaymentReturnOperation {
    request: NativePaymentFullReturnRequest,
    payment: NativePaymentOperation,
}
impl AccountClient {
    /// Bind a full return to the receiver's account, durable storage and independent finality root.
    /// # Errors
    /// Account is not the original receiver, trust differs, or storage/request is invalid.
    pub fn native_payment_return(
        &self,
        request: NativePaymentFullReturnRequest,
        storage: Arc<dyn WorkflowStorage>,
        verifier: SumeragiFinalityVerifier,
    ) -> Result<NativePaymentReturnOperation, NativePaymentError> {
        let payment = self.native_payment(request.payment.clone(), storage, verifier)?;
        Ok(NativePaymentReturnOperation { request, payment })
    }
}
impl NativePaymentReturnOperation {
    /// Canonical return identity, stable across gateways and restarts.
    #[must_use]
    pub fn settlement_id(&self) -> &SettlementId {
        self.request.settlement_id()
    }
    /// Explicitly authorize a paid full-return attempt with the exact reviewed return fee intent.
    /// # Errors
    /// Original native submission or exact link verification failure.
    pub async fn submit(
        &self,
        options: &NativePaymentRunOptions,
    ) -> Result<NativePaymentReturnSettlement, NativePaymentError> {
        let settled = self.payment.submit(options).await?;
        Ok(NativePaymentReturnSettlement {
            receipt: self.request.verify_return(settled.receipt)?,
            carrier: settled.carrier,
        })
    }
    /// Resume the original full-return carrier without creating or signing another identity.
    /// A fresh gateway may recover verified reverse success; otherwise explicit submission is required.
    /// # Errors
    /// Original native resume or exact link verification failure.
    pub async fn resume(
        &self,
        options: &NativePaymentRunOptions,
    ) -> Result<NativePaymentReturnSettlement, NativePaymentError> {
        let settled = self.payment.resume(options).await?;
        Ok(NativePaymentReturnSettlement {
            receipt: self.request.verify_return(settled.receipt)?,
            carrier: settled.carrier,
        })
    }
    /// Recover without signing or dispatching and reverify the original reverse block.
    /// # Errors
    /// Original native payment or exact link verification failure.
    pub async fn recover(
        &self,
        options: &NativePaymentRunOptions,
    ) -> Result<NativePaymentReturnRecovery, NativePaymentError> {
        let recovered = self.payment.recover(options).await?;
        Ok(NativePaymentReturnRecovery {
            receipt: recovered
                .receipt
                .map(|receipt| self.request.verify_return(receipt))
                .transpose()?,
            carrier: recovered.carrier,
        })
    }
}

#[cfg(test)]
mod tests;
