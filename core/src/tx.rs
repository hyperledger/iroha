//! `Transaction`-related functionality of Iroha.
//!
//! Types represent various stages of a `Transaction`'s lifecycle. For
//! example, `Transaction` is the start, when a transaction had been
//! received by Torii.
//!
//! This is also where the actual execution of instructions, as well
//! as various forms of validation are performed.
// TODO: Add full lifecycle docs.
#![allow(
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic
)]
use std::sync::Arc;

use eyre::{Result, WrapErr};
use iroha_crypto::SignaturesOf;
pub use iroha_data_model::prelude::*;
use iroha_primitives::must_use::MustUse;
use iroha_version::{declare_versioned_with_scale, version_with_scale};
use parity_scale_codec::{Decode, Encode};

use crate::{
    prelude::*,
    smartcontracts::{
        permissions::{check_instruction_permissions, judge::InstructionJudgeArc, prelude::*},
        wasm, Evaluate, Execute,
    },
};

/// Used to validate transaction and thus move transaction lifecycle forward
///
/// Permission validation is skipped for genesis.
#[derive(Clone)]
pub struct TransactionValidator {
    transaction_limits: TransactionLimits,
    instruction_judge: InstructionJudgeArc,
    query_judge: QueryJudgeArc,
    wsv: Arc<WorldStateView>,
}

impl TransactionValidator {
    /// Construct [`TransactionValidator`]
    pub fn new(
        transaction_limits: TransactionLimits,
        instruction_judge: InstructionJudgeArc,
        query_judge: QueryJudgeArc,
        wsv: Arc<WorldStateView>,
    ) -> Self {
        Self {
            transaction_limits,
            instruction_judge,
            query_judge,
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
        if let Err(rejection_reason) = self.validate_internal(tx.clone(), is_genesis) {
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

    /// Validate every transaction in `txs`
    ///
    /// # Errors
    /// Fails if validation of any transaction fails
    //
    // TODO (#2742): Accept `txs` by reference, not by value
    pub fn validate_every(
        &self,
        txs: impl IntoIterator<Item = VersionedAcceptedTransaction>,
    ) -> Result<(), TransactionRejectionReason> {
        for tx in txs {
            self.validate_internal(tx.into_v1(), true)?;
        }
        Ok(())
    }

    fn validate_internal(
        &self,
        tx: AcceptedTransaction,
        is_genesis: bool,
    ) -> Result<(), TransactionRejectionReason> {
        let account_id = &tx.payload.account_id;
        self.validate_signatures(&tx, is_genesis)?;

        // Sanity check - should have been checked by now
        tx.check_limits(&self.transaction_limits)?;

        if !self
            .wsv
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

        // WSV is cloned here so that instructions don't get applied to the blockchain
        // Therefore, this instruction execution validates before actually executing
        let wsv_for_builtin_validators = WorldStateView::clone(&self.wsv);
        self.validate_with_builtin_validators(&tx, &wsv_for_builtin_validators, is_genesis)?;

        // Making a new clone so that instructions applied in the previous step won't break validation
        let wsv_for_runtime_validators = WorldStateView::clone(&self.wsv);
        Self::validate_with_runtime_validators(tx, &wsv_for_runtime_validators)
    }

    /// Validate signatures for the given transaction
    fn validate_signatures(
        &self,
        tx: &AcceptedTransaction,
        is_genesis: bool,
    ) -> Result<(), TransactionRejectionReason> {
        if !is_genesis && tx.payload().account_id == AccountId::genesis() {
            return Err(TransactionRejectionReason::UnexpectedGenesisAccountSignature);
        }

        let option_reason = match tx.check_signature_condition(&self.wsv) {
            Ok(MustUse(true)) => None,
            Ok(MustUse(false)) => Some("Signature condition not satisfied.".to_owned()),
            Err(reason) => Some(reason.to_string()),
        }
        .map(|reason| UnsatisfiedSignatureConditionFail { reason })
        .map(TransactionRejectionReason::UnsatisfiedSignatureCondition);

        if let Some(reason) = option_reason {
            return Err(reason);
        }

        Ok(())
    }

    // TODO: Remove when runtime validators will replace the builtin ones
    // Should we move executable execution to runtime-checks as well?
    fn validate_with_builtin_validators(
        &self,
        tx: &AcceptedTransaction,
        wsv: &WorldStateView,
        is_genesis: bool,
    ) -> Result<(), TransactionRejectionReason> {
        let account_id = &tx.payload.account_id;

        match &tx.payload.instructions {
            Executable::Instructions(instructions) => {
                for instruction in instructions {
                    if !is_genesis {
                        check_instruction_permissions(
                            account_id,
                            instruction,
                            self.instruction_judge.as_ref(),
                            self.query_judge.as_ref(),
                            wsv,
                        )?;
                    }

                    instruction
                        .clone()
                        .execute(account_id.clone(), wsv)
                        .map_err(|reason| InstructionExecutionFail {
                            instruction: instruction.clone(),
                            reason: reason.to_string(),
                        })
                        .map_err(TransactionRejectionReason::InstructionExecution)?;
                }
                Ok(())
            }
            Executable::Wasm(bytes) => {
                let mut wasm_runtime = wasm::Runtime::new()
                    .map_err(|reason| WasmExecutionFail {
                        reason: reason.to_string(),
                    })
                    .map_err(TransactionRejectionReason::WasmExecution)?;
                wasm_runtime
                    .validate(
                        wsv,
                        account_id,
                        bytes,
                        self.transaction_limits.max_instruction_number,
                        Arc::clone(&self.instruction_judge),
                        Arc::clone(&self.query_judge),
                    )
                    .map_err(|reason| WasmExecutionFail {
                        reason: reason.to_string(),
                    })
                    .map_err(TransactionRejectionReason::WasmExecution)
            }
        }
    }

    fn validate_with_runtime_validators(
        tx: AcceptedTransaction,
        wsv: &WorldStateView,
    ) -> Result<(), TransactionRejectionReason> {
        let AcceptedTransaction {
            payload,
            signatures,
        } = tx;
        let signatures = signatures.into_iter().collect();

        let signed_tx = SignedTransaction {
            payload,
            signatures,
        };

        // Validating the transaction it-self
        wsv.validators_view()
            .validate(wsv, signed_tx.clone())
            .map_err(|reason| {
                TransactionRejectionReason::NotPermitted(NotPermittedFail { reason })
            })?;

        // Validating the transaction instructions
        if let Executable::Instructions(instructions) = signed_tx.payload.instructions {
            for isi in instructions {
                wsv.validators_view().validate(wsv, isi).map_err(|reason| {
                    TransactionRejectionReason::NotPermitted(NotPermittedFail { reason })
                })?;
            }
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
        transaction: SignedTransaction,
        limits: &TransactionLimits,
    ) -> Result<VersionedAcceptedTransaction> {
        AcceptedTransaction::from_transaction(transaction, limits).map(Into::into)
    }

    /// Checks that the signatures of this transaction satisfy the signature condition specified in the account.
    ///
    /// # Errors
    /// Can fail if signature condition account fails or if account is not found
    pub fn check_signature_condition(&self, wsv: &WorldStateView) -> Result<MustUse<bool>> {
        self.as_v1().check_signature_condition(wsv)
    }
}

impl Txn for VersionedAcceptedTransaction {
    type HashOf = VersionedSignedTransaction;

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
    pub fn from_transaction(
        transaction: SignedTransaction,
        limits: &TransactionLimits,
    ) -> Result<Self> {
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
    pub fn check_signature_condition(&self, wsv: &WorldStateView) -> Result<MustUse<bool>> {
        let account_id = &self.payload.account_id;

        let signatories = self
            .signatures
            .iter()
            .map(|signature| signature.public_key())
            .cloned();

        wsv.map_account(account_id, |account| {
            check_signature_condition(account, signatories)
                .evaluate(wsv, &Context::new())
                .map(MustUse::new)
                .map_err(Into::into)
        })?
    }
}

/// Returns a prebuilt expression that when executed
/// returns if the needed signatures are gathered.
fn check_signature_condition(
    account: &Account,
    signatories: impl IntoIterator<Item = PublicKey>,
) -> EvaluatesTo<bool> {
    let where_expr = WhereBuilder::evaluate(EvaluatesTo::new_evaluates_to_value(
        account.signature_check_condition().as_expression().clone(),
    ))
    .with_value(
        String::from(iroha_data_model::account::ACCOUNT_SIGNATORIES_VALUE),
        account.signatories().cloned().collect::<Vec<_>>(),
    )
    .with_value(
        String::from(iroha_data_model::account::TRANSACTION_SIGNATORIES_VALUE),
        signatories.into_iter().collect::<Vec<_>>(),
    )
    .build();
    EvaluatesTo::new_unchecked(where_expr.into())
}

impl Txn for AcceptedTransaction {
    type HashOf = SignedTransaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.payload
    }
}

impl IsInBlockchain for VersionedAcceptedTransaction {
    #[inline]
    fn is_in_blockchain(&self, wsv: &WorldStateView) -> bool {
        wsv.has_transaction(&self.hash())
    }
}
impl IsInBlockchain for VersionedValidTransaction {
    #[inline]
    fn is_in_blockchain(&self, wsv: &WorldStateView) -> bool {
        wsv.has_transaction(&self.hash())
    }
}
impl IsInBlockchain for VersionedRejectedTransaction {
    #[inline]
    fn is_in_blockchain(&self, wsv: &WorldStateView) -> bool {
        wsv.has_transaction(&self.hash())
    }
}

impl From<VersionedAcceptedTransaction> for VersionedSignedTransaction {
    fn from(tx: VersionedAcceptedTransaction) -> Self {
        let tx: AcceptedTransaction = tx.into_v1();
        let tx: SignedTransaction = tx.into();
        tx.into()
    }
}

impl From<AcceptedTransaction> for SignedTransaction {
    fn from(transaction: AcceptedTransaction) -> Self {
        SignedTransaction {
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
        let key_pair = KeyPair::generate().expect("Failed to generate key pair.");
        let inst: Instruction = FailBox {
            message: "Will fail".to_owned(),
        }
        .into();
        let tx = Transaction::new(
            AccountId::from_str("root@global").expect("Valid"),
            vec![inst; DEFAULT_MAX_INSTRUCTION_NUMBER as usize + 1].into(),
            1000,
        )
        .sign(key_pair)
        .expect("Valid");
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
            format!(
                "Too many instructions in payload, max number is {}, but got {}",
                tx_limits.max_instruction_number,
                DEFAULT_MAX_INSTRUCTION_NUMBER + 1
            )
        );
    }
}
