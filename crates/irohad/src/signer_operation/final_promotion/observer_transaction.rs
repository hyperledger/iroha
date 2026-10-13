//! Exact observer transactions preserve Core's original challenged Check through signing.
//!
//! This owner pins public signer separation and fee approval before invoking the observer key.
//! A returned pending Check establishes neither execution nor current authority; only the existing
//! Core consumer can establish those facts after ordinary submission and finality. No observer
//! callback can construct verified native authority, replace a challenge or renew its deadline.
//! TODO: connect the independently configured observer service, durable approved spending,
//! qualified UTC and rollback-protected floor persistence in the final-promotion source factory.

use crate::native_check_binding::{CheckTermination, complete_binding, complete_binding_waiting};
use iroha_core::query::{
    final_promotion_account_custody::observation::{
        PendingFinalPromotionAccountCheckV1, PreparedFinalPromotionAccountCheckV1,
        validate_final_promotion_account_transaction_envelope_v1,
    },
    final_promotion_authority::observation::{
        FinalPromotionCheckBindingFailureV1, PendingFinalPromotionCheckV1,
        PreparedFinalPromotionCheckV1,
    },
};
use iroha_crypto::{Algorithm, Signature};
use iroha_data_model::{
    account::AccountId,
    isi::InstructionBox,
    sorafs::{
        final_promotion_account_custody::FinalPromotionAccountCustodyActionV1,
        final_promotion_authority::FinalPromotionAuthorityActionV1,
    },
    transaction::{Executable, FeePaymentIntent, TransactionBuilder, TransactionPayload},
};
use sorafs_manifest::signer::{
    custody::SignerCustodyBindingV1,
    protocol::{SignerKeyAlgorithmV1, SignerPurposeBindingV1, SignerRoleV1},
};

/// Fixed observer signing failures; no credential, application payload or provider text escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalPromotionObserverTransactionErrorV1 {
    /// Public signer, observer, network, deployment or independent fee approval is inconsistent.
    Binding,
    /// The payload differs from the exact prepared Check or approved fee intent.
    Payload,
    /// The original Core Check lifetime ended or its signed envelope was rejected.
    Check,
    /// The configured observer service failed or returned a wrong-key/message signature.
    Provider,
    /// Local binding resources remained unavailable until the original Check deadline.
    Unavailable,
}
impl std::fmt::Display for FinalPromotionObserverTransactionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Binding => "final-promotion observer binding rejected",
            Self::Payload => "final-promotion observer payload rejected",
            Self::Check => "final-promotion observer Check rejected",
            Self::Provider => "final-promotion observer signer unavailable",
            Self::Unavailable => "final-promotion observer Check resources unavailable",
        })
    }
}
impl std::error::Error for FinalPromotionObserverTransactionErrorV1 {}
type Error = FinalPromotionObserverTransactionErrorV1;

/// One exact observer payload visible only after a live prepared Check and fee approval agree.
/// There is no public constructor, mutable payload or credential export.
pub struct FinalPromotionObserverKeyRequestV1<'a> {
    payload: &'a TransactionPayload,
    message: &'a [u8],
}
impl FinalPromotionObserverKeyRequestV1<'_> {
    /// Exact reviewed Check payload including fees, timing, metadata and admission intent.
    #[must_use]
    pub const fn payload(&self) -> &TransactionPayload {
        self.payload
    }
    /// Ordinary transaction prehash for precisely the retained full payload.
    #[must_use]
    pub const fn signing_message(&self) -> &[u8] {
        self.message
    }
}

/// Configured public identity and independently approved fees for both native Check purposes.
///
/// The observer is distinct from both protected keys and the original operation account.
/// Construction verifies structure and identity only. It does not authenticate live custody,
/// quote fees, reserve a spending budget, persist a floor or qualify a provider.
pub struct FinalPromotionObserverTransactionsV1 {
    receipt_binding: SignerCustodyBindingV1,
    account_binding: SignerCustodyBindingV1,
    observer: AccountId,
    approved_fees: FeePaymentIntent,
}
impl FinalPromotionObserverTransactionsV1 {
    pub(super) const fn receipt_binding(&self) -> &SignerCustodyBindingV1 {
        &self.receipt_binding
    }

    pub(super) const fn account_binding(&self) -> &SignerCustodyBindingV1 {
        &self.account_binding
    }

    pub(super) const fn observer(&self) -> &AccountId {
        &self.observer
    }

    /// Pin the two independently configured bindings, distinct observer and exact fee approval.
    ///
    /// # Errors
    /// Rejects malformed bindings, mismatched deployment/network, shared keys, unsupported observer
    /// identity or invalid fee intent. No key or State I/O occurs during construction.
    pub fn new(
        receipt_binding: SignerCustodyBindingV1,
        account_binding: SignerCustodyBindingV1,
        observer: AccountId,
        approved_fees: FeePaymentIntent,
    ) -> Result<Self, Error> {
        receipt_binding.validate().map_err(|_| Error::Binding)?;
        account_binding.validate().map_err(|_| Error::Binding)?;
        approved_fees.validate().map_err(|_| Error::Binding)?;
        let (
            SignerPurposeBindingV1::FinalPromotionProvenance {
                deployment_id: receipt,
            },
            SignerPurposeBindingV1::FinalPromotionAccountTransaction {
                deployment_id: account,
            },
        ) = (&receipt_binding.purpose, &account_binding.purpose)
        else {
            return Err(Error::Binding);
        };
        let observer_key = observer.try_signatory().ok_or(Error::Binding)?;
        if receipt_binding.role != SignerRoleV1::FinalPromotionProvenance
            || account_binding.role != SignerRoleV1::FinalPromotionAccountTransaction
            || receipt_binding.algorithm != SignerKeyAlgorithmV1::Ed25519
            || account_binding.algorithm != SignerKeyAlgorithmV1::Ed25519
            || observer_key.try_algorithm().map_err(|_| Error::Binding)? != Algorithm::Ed25519
            || receipt != account
            || receipt_binding.chain_id != account_binding.chain_id
            || receipt_binding.network_id != account_binding.network_id
            || receipt_binding.public_key == account_binding.public_key
            || observer_key == &receipt_binding.public_key
            || observer_key == &account_binding.public_key
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            receipt_binding,
            account_binding,
            observer,
            approved_fees,
        })
    }

    /// Sign precisely one original receipt Check, then return its existing Core pending owner.
    ///
    /// Provider failure, invalid signature and expiry consume the original challenge. This method
    /// never retries the signer or renews the original independent floor/deadline. Local binding
    /// refusals retain and retry only the exact signed Core owner until that deadline.
    ///
    /// # Errors
    /// Rejects a foreign Check, changed instruction/fees, expiry or substituted provider output.
    pub fn sign_receipt_with(
        &self,
        prepared: PreparedFinalPromotionCheckV1,
        payload: TransactionPayload,
        provider: impl FnOnce(&FinalPromotionObserverKeyRequestV1<'_>) -> Result<Signature, Error>,
    ) -> Result<PendingFinalPromotionCheckV1, Error> {
        self.sign_receipt_waiting(prepared, payload, provider, |_, delay| {
            std::thread::sleep(delay)
        })
    }

    /// Keep the same signed owner while the service waits on local binding resources.
    pub(super) fn sign_receipt_waiting(
        &self,
        prepared: PreparedFinalPromotionCheckV1,
        payload: TransactionPayload,
        provider: impl FnOnce(&FinalPromotionObserverKeyRequestV1<'_>) -> Result<Signature, Error>,
        wait: impl FnMut(&FinalPromotionCheckBindingFailureV1, std::time::Duration),
    ) -> Result<PendingFinalPromotionCheckV1, Error> {
        prepared.ensure_live().map_err(|_| Error::Check)?;
        if prepared.binding() != &self.receipt_binding
            || prepared.observer() != &self.observer
            || prepared.expected_operator()
                != &AccountId::new(self.account_binding.public_key.clone())
            || !matches!(
                prepared.instruction().action,
                FinalPromotionAuthorityActionV1::Check(_)
            )
        {
            return Err(Error::Binding);
        }
        self.validate_payload(&payload, &prepared.instruction().clone().into())?;
        let builder = TransactionBuilder::from_payload(payload).map_err(|_| Error::Payload)?;
        let message = builder.payload_hash_bytes();
        prepared.ensure_live().map_err(|_| Error::Check)?;
        let signature = self.sign(builder.payload(), &message, provider)?;
        prepared.ensure_live().map_err(|_| Error::Check)?;
        complete_binding_waiting(
            prepared.bind_signed_transaction(builder.build_with_signature(signature)),
            wait,
        )
        .map_err(|terminal| binding_error(&terminal))
    }

    /// Sign precisely one original account Check under the same distinct observer and fee policy.
    ///
    /// # Errors
    /// Rejects another complete account binding or observer, changed instruction or fee intent,
    /// expiry during provider I/O, or a substituted signature. The original challenge is consumed.
    pub fn sign_account_with(
        &self,
        prepared: PreparedFinalPromotionAccountCheckV1,
        payload: TransactionPayload,
        provider: impl FnOnce(&FinalPromotionObserverKeyRequestV1<'_>) -> Result<Signature, Error>,
    ) -> Result<PendingFinalPromotionAccountCheckV1, Error> {
        prepared.ensure_live().map_err(|_| Error::Check)?;
        let FinalPromotionAccountCustodyActionV1::Check(check) = &prepared.instruction().action
        else {
            return Err(Error::Binding);
        };
        let SignerPurposeBindingV1::FinalPromotionAccountTransaction { deployment_id } =
            &self.account_binding.purpose
        else {
            return Err(Error::Binding);
        };
        if prepared.binding() != &self.account_binding
            || prepared.observer() != &self.observer
            || &prepared.instruction().deployment_id != deployment_id
            || check.network_id != self.account_binding.network_id
            || check.expected_account != AccountId::new(self.account_binding.public_key.clone())
        {
            return Err(Error::Binding);
        }
        self.validate_payload(&payload, &prepared.instruction().clone().into())?;
        let builder = TransactionBuilder::from_payload(payload).map_err(|_| Error::Payload)?;
        let message = builder.payload_hash_bytes();
        prepared.ensure_live().map_err(|_| Error::Check)?;
        let signature = self.sign(builder.payload(), &message, provider)?;
        prepared.ensure_live().map_err(|_| Error::Check)?;
        complete_binding(prepared.bind_signed_transaction(builder.build_with_signature(signature)))
            .map_err(|terminal| binding_error(&terminal))
    }

    fn validate_payload(
        &self,
        payload: &TransactionPayload,
        instruction: &InstructionBox,
    ) -> Result<(), Error> {
        let Executable::Instructions(instructions) = &payload.instructions else {
            return Err(Error::Payload);
        };
        if payload.authority != self.observer
            || payload
                .network_id()
                .map(iroha_data_model::NetworkId::as_bytes)
                != Some(&self.receipt_binding.network_id)
            || payload.fee_payment_intent() != &self.approved_fees
            || instructions.len() != 1
            || &instructions[0] != instruction
        {
            return Err(Error::Payload);
        }
        validate_final_promotion_account_transaction_envelope_v1(payload)
            .map_err(|_| Error::Payload)
    }

    fn sign(
        &self,
        payload: &TransactionPayload,
        message: &[u8],
        provider: impl FnOnce(&FinalPromotionObserverKeyRequestV1<'_>) -> Result<Signature, Error>,
    ) -> Result<Signature, Error> {
        let signature = provider(&FinalPromotionObserverKeyRequestV1 { payload, message })
            .map_err(|_| Error::Provider)?;
        signature
            .verify(
                self.observer.try_signatory().ok_or(Error::Binding)?,
                message,
            )
            .map_err(|_| Error::Provider)?;
        Ok(signature)
    }
}

fn binding_error<F>(terminal: &CheckTermination<F>) -> Error {
    match terminal {
        CheckTermination::Terminal(_) => Error::Check,
        CheckTermination::Expired => Error::Unavailable,
    }
}
