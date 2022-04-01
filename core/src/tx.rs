//! `Transaction`-related functionality of Iroha.
//!
//! Types represent various stages of a `Transaction`'s lifecycle. For
//! example, `Transaction` is the start, when a transaction had been
//! received by Torii.
//!
//! This is also where the actual execution of instructions, as well
//! as various forms of validation are performed.
// TODO: Add full lifecycle docs.

use std::sync::Arc;

use eyre::{Result, WrapErr};
use iroha_crypto::SignaturesOf;
pub use iroha_data_model::prelude::*;
use iroha_version::{declare_versioned_with_scale, version_with_scale};
use parity_scale_codec::{Decode, Encode};

use crate::{
    prelude::*,
    smartcontracts::{
        permissions::{
            check_instruction_permissions, IsInstructionAllowedBoxed, IsQueryAllowedBoxed,
        },
        wasm, Evaluate, Execute, FindError,
    },
    wsv::WorldTrait,
};

/// Used to validate transaction and thus move transaction lifecycle forward
///
/// Permission validation is skipped for genesis.
#[derive(Clone)]
pub struct TransactionValidator<W: WorldTrait> {
    transaction_limits: TransactionLimits,

    is_instruction_allowed: Arc<IsInstructionAllowedBoxed<W>>,
    is_query_allowed: Arc<IsQueryAllowedBoxed<W>>,

    wsv: Arc<WorldStateView<W>>,
}

impl<W: WorldTrait> TransactionValidator<W> {
    /// Construct [`TransactionValidator`]
    pub fn new(
        transaction_limits: TransactionLimits,

        is_instruction_allowed: Arc<IsInstructionAllowedBoxed<W>>,
        is_query_allowed: Arc<IsQueryAllowedBoxed<W>>,

        wsv: Arc<WorldStateView<W>>,
    ) -> Self {
        Self {
            transaction_limits,
            is_instruction_allowed,
            is_query_allowed,
            wsv,
        }
    }

    /// Move transaction lifecycle forward by checking if the
    /// instructions can be applied to the `WorldStateView`.
    ///
    /// Permission validation is skipped for genesis.
    ///
    /// # Errors
    /// Fails if validation of instruction fails (e.g. permissions mismatch).
    pub fn validate(
        &self,
        tx: AcceptedTransaction,
        is_genesis: bool,
    ) -> Result<VersionedValidTransaction, VersionedRejectedTransaction> {
        if let Err(rejection_reason) = self.validate_internal(&tx, is_genesis) {
            return Err(RejectedTransaction {
                payload: tx.payload,
                signatures: tx.signatures,
                rejection_reason,
            }
            .into());
        }

        Ok(ValidTransaction {
            payload: tx.payload,
            signatures: tx.signatures,
        }
        .into())
    }

    fn validate_internal(
        &self,
        tx: &AcceptedTransaction,
        is_genesis: bool,
    ) -> Result<(), TransactionRejectionReason> {
        let account_id = &tx.payload.account_id;
        self.validate_signatures(tx, is_genesis)?;

        // Sanity check - should have been checked by now
        tx.check_limits(&self.transaction_limits)?;

        // WSV is cloned here so that instructions don't get applied to the blockchain
        // Therefore, this instruction execution validates before actually executing
        let wsv = WorldStateView::clone(&self.wsv);

        if !wsv
            .domain(&account_id.domain_id)
            .map_err(|_e| {
                TransactionRejectionReason::NotPermitted(NotPermittedFail {
                    reason: "Domain not found in Iroha".to_owned(),
                })
            })?
            .contains_account(account_id)
        {
            return Err(TransactionRejectionReason::NotPermitted(NotPermittedFail {
                reason: "Account not found in Iroha".to_owned(),
            }));
        }

        match &tx.payload.instructions {
            Executable::Instructions(instructions) => {
                for instruction in instructions {
                    if !is_genesis {
                        check_instruction_permissions(
                            account_id,
                            instruction,
                            &self.is_instruction_allowed,
                            &self.is_query_allowed,
                            &wsv,
                        )?
                    }

                    instruction
                        .clone()
                        .execute(account_id.clone(), &wsv)
                        .map_err(|reason| InstructionExecutionFail {
                            instruction: instruction.clone(),
                            reason: reason.to_string(),
                        })
                        .map_err(TransactionRejectionReason::InstructionExecution)?;
                }
            }
            Executable::Wasm(bytes) => {
                let mut wasm_runtime = wasm::Runtime::new()
                    .map_err(|reason| WasmExecutionFail {
                        reason: reason.to_string(),
                    })
                    .map_err(TransactionRejectionReason::WasmExecution)?;
                wasm_runtime
                    .validate(
                        &wsv,
                        account_id,
                        bytes,
                        self.transaction_limits.max_instruction_number,
                        Arc::clone(&self.is_instruction_allowed),
                        Arc::clone(&self.is_query_allowed),
                    )
                    .map_err(|reason| WasmExecutionFail {
                        reason: reason.to_string(),
                    })
                    .map_err(TransactionRejectionReason::WasmExecution)?;
            }
        }

        Ok(())
    }

    fn validate_signatures(
        &self,
        tx: &AcceptedTransaction,
        is_genesis: bool,
    ) -> Result<(), TransactionRejectionReason> {
        if !is_genesis && tx.payload().account_id == AccountId::genesis() {
            return Err(TransactionRejectionReason::UnexpectedGenesisAccountSignature);
        }

        let option_reason = match tx.check_signature_condition(&self.wsv) {
            Ok(true) => None,
            Ok(false) => Some("Signature condition not satisfied.".to_owned()),
            Err(reason) => Some(reason.to_string()),
        }
        .map(|reason| UnsatisfiedSignatureConditionFail { reason })
        .map(TransactionRejectionReason::UnsatisfiedSignatureCondition);

        if let Some(reason) = option_reason {
            return Err(reason);
        }

        Ok(())
    }
}

declare_versioned_with_scale!(VersionedAcceptedTransaction 1..2, Debug, Clone, iroha_macro::FromVariant);

impl VersionedAcceptedTransaction {
    /// Converts from `&VersionedAcceptedTransaction` to V1 reference
    pub const fn as_v1(&self) -> &AcceptedTransaction {
        match self {
            VersionedAcceptedTransaction::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedAcceptedTransaction` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut AcceptedTransaction {
        match self {
            VersionedAcceptedTransaction::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedAcceptedTransaction` to V1
    pub fn into_v1(self) -> AcceptedTransaction {
        match self {
            VersionedAcceptedTransaction::V1(v1) => v1,
        }
    }

    /// Accepts transaction
    /// # Errors
    /// Can fail if verification of some signature fails
    pub fn from_transaction(
        transaction: Transaction,
        limits: &TransactionLimits,
    ) -> Result<VersionedAcceptedTransaction> {
        AcceptedTransaction::from_transaction(transaction, limits).map(Into::into)
    }

    /// Checks that the signatures of this transaction satisfy the signature condition specified in the account.
    ///
    /// # Errors
    /// Can fail if signature condition account fails or if account is not found
    pub fn check_signature_condition<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
    ) -> Result<bool> {
        self.as_v1().check_signature_condition(wsv)
    }
}

impl Txn for VersionedAcceptedTransaction {
    type HashOf = VersionedTransaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.as_v1().payload
    }
}

/// `AcceptedTransaction` — a transaction accepted by iroha peer.
#[version_with_scale(n = 1, versioned = "VersionedAcceptedTransaction")]
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct AcceptedTransaction {
    /// Payload of this transaction.
    pub payload: Payload,
    /// Signatures for this transaction.
    pub signatures: SignaturesOf<Payload>,
}

impl AcceptedTransaction {
    /// Accepts transaction
    ///
    /// # Errors
    /// Can fail if verification of some signature fails
    pub fn from_transaction(transaction: Transaction, limits: &TransactionLimits) -> Result<Self> {
        transaction
            .check_limits(limits)
            .wrap_err("Failed to accept transaction")?;
        let signatures: SignaturesOf<_> = transaction
            .signatures
            .try_into()
            .map_err(eyre::Error::from)?;
        signatures
            .verify(&transaction.payload)
            .wrap_err("Failed to verify transaction signatures")?;

        Ok(Self {
            payload: transaction.payload,
            signatures,
        })
    }

    /// Checks that the signatures of this transaction satisfy the signature condition specified in the account.
    ///
    /// # Errors
    /// - Account not found
    /// - Signature verification fails
    pub fn check_signature_condition<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
    ) -> Result<bool> {
        let account_id = &self.payload.account_id;

        let signatories = self
            .signatures
            .iter()
            .map(|signature| &signature.public_key)
            .cloned();

        wsv.map_account(account_id, |account| {
            check_signature_condition(account, signatories)
                .evaluate(wsv, &Context::new())
                .map_err(|_err| FindError::Account(account_id.clone()))
        })?
        .wrap_err("Failed to find the account")
    }
}

/// Returns a prebuilt expression that when executed
/// returns if the needed signatures are gathered.
fn check_signature_condition(
    account: &Account,
    signatories: impl IntoIterator<Item = PublicKey>,
) -> EvaluatesTo<bool> {
    WhereBuilder::evaluate(account.signature_check_condition().as_expression().clone())
        .with_value(
            String::from(iroha_data_model::account::ACCOUNT_SIGNATORIES_VALUE),
            account.signatories().cloned().collect::<Vec<_>>(),
        )
        .with_value(
            String::from(iroha_data_model::account::TRANSACTION_SIGNATORIES_VALUE),
            signatories.into_iter().collect::<Vec<_>>(),
        )
        .build()
        .into()
}

impl Txn for AcceptedTransaction {
    type HashOf = Transaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.payload
    }
}

impl IsInBlockchain for VersionedAcceptedTransaction {
    #[inline]
    fn is_in_blockchain<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool {
        wsv.has_transaction(&self.hash())
    }
}
impl IsInBlockchain for VersionedValidTransaction {
    #[inline]
    fn is_in_blockchain<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool {
        wsv.has_transaction(&self.hash())
    }
}
impl IsInBlockchain for VersionedRejectedTransaction {
    #[inline]
    fn is_in_blockchain<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool {
        wsv.has_transaction(&self.hash())
    }
}

impl From<VersionedAcceptedTransaction> for VersionedTransaction {
    fn from(tx: VersionedAcceptedTransaction) -> Self {
        let tx: AcceptedTransaction = tx.into_v1();
        let tx: Transaction = tx.into();
        tx.into()
    }
}

impl From<AcceptedTransaction> for Transaction {
    fn from(transaction: AcceptedTransaction) -> Self {
        Transaction {
            payload: transaction.payload,
            signatures: transaction.signatures.into_iter().collect(),
        }
    }
}

impl From<VersionedValidTransaction> for VersionedAcceptedTransaction {
    fn from(tx: VersionedValidTransaction) -> Self {
        let tx: ValidTransaction = tx.into_v1();
        let tx: AcceptedTransaction = tx.into();
        tx.into()
    }
}

impl From<ValidTransaction> for AcceptedTransaction {
    fn from(transaction: ValidTransaction) -> Self {
        AcceptedTransaction {
            payload: transaction.payload,
            signatures: transaction.signatures,
        }
    }
}

impl From<VersionedRejectedTransaction> for VersionedAcceptedTransaction {
    fn from(tx: VersionedRejectedTransaction) -> Self {
        let tx: RejectedTransaction = tx.into_v1();
        let tx: AcceptedTransaction = tx.into();
        tx.into()
    }
}

impl From<RejectedTransaction> for AcceptedTransaction {
    fn from(transaction: RejectedTransaction) -> Self {
        AcceptedTransaction {
            payload: transaction.payload,
            signatures: transaction.signatures,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::restriction)]

    use std::str::FromStr as _;

    use eyre::Result;
    use iroha_data_model::transaction::DEFAULT_MAX_INSTRUCTION_NUMBER;

    use super::*;

    #[test]
    fn transaction_not_accepted_max_instruction_number() {
        let inst: Instruction = FailBox {
            message: "Will fail".to_owned(),
        }
        .into();
        let tx = Transaction::new(
            AccountId::from_str("root@global").expect("Valid"),
            vec![inst; DEFAULT_MAX_INSTRUCTION_NUMBER as usize + 1].into(),
            1000,
        );
        let tx_limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };
        let result: Result<AcceptedTransaction> =
            AcceptedTransaction::from_transaction(tx, &tx_limits);
        assert!(result.is_err());

        let err = result.unwrap_err();
        let mut chain = err.chain();
        assert_eq!(
            chain.next().unwrap().to_string(),
            "Failed to accept transaction"
        );
        assert_eq!(
            chain.next().unwrap().to_string(),
            "Too many instructions in payload"
        );
    }
}
