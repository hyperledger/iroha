//! `Transaction`-related functionality of Iroha.
//!
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
    clippy::arithmetic_side_effects
)]
use std::str::FromStr;

use eyre::Result;
pub use iroha_data_model::prelude::*;
use iroha_data_model::{evaluate::ExpressionEvaluator, query::error::FindError, ValidationFail};
use iroha_logger::{debug, error};
use iroha_primitives::must_use::MustUse;

use crate::{
    prelude::*,
    smartcontracts::{wasm, Execute as _},
};

/// Used to validate transaction and thus move transaction lifecycle forward
///
/// Validation is skipped for genesis.
#[derive(Clone, Copy)]
pub struct TransactionValidator {
    /// [`TransactionLimits`] field
    pub transaction_limits: TransactionLimits,
}

impl TransactionValidator {
    /// Construct [`TransactionValidator`]
    pub fn new(transaction_limits: TransactionLimits) -> Self {
        Self { transaction_limits }
    }

    /// Move transaction lifecycle forward by checking if the
    /// instructions can be applied to the `WorldStateView`.
    ///
    /// Validation is skipped for genesis.
    ///
    /// # Errors
    /// Fails if validation of instruction fails (e.g. permissions mismatch).
    pub fn validate(
        &self,
        tx: AcceptedTransaction,
        is_genesis: bool,
        wsv: &mut WorldStateView,
    ) -> Result<VersionedValidTransaction, VersionedRejectedTransaction> {
        if let Err(rejection_reason) = self.validate_internal(tx.clone(), is_genesis, wsv) {
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
    /// # Note
    /// Be advised that this function applies `txs` to `wsv`
    ///
    /// # Errors
    /// Fails if validation of any transaction fails
    //
    // TODO (#2742): Accept `txs` by reference, not by value
    pub fn validate_every(
        &self,
        txs: impl IntoIterator<Item = VersionedAcceptedTransaction>,
        wsv: &mut WorldStateView,
    ) -> Result<(), TransactionRejectionReason> {
        for tx in txs {
            self.validate_internal(tx.into_v1(), true, wsv)?;
        }
        Ok(())
    }

    fn validate_internal(
        &self,
        tx: AcceptedTransaction,
        is_genesis: bool,
        wsv: &mut WorldStateView,
    ) -> Result<(), TransactionRejectionReason> {
        let account_id = &tx.payload.account_id;
        Self::validate_signatures(&tx, is_genesis, wsv)?;

        if !wsv
            .domain(&account_id.domain_id)
            .map_err(|_e| {
                TransactionRejectionReason::AccountDoesNotExist(FindError::Domain(
                    account_id.domain_id.clone(),
                ))
            })?
            .accounts
            .contains_key(account_id)
        {
            return Err(TransactionRejectionReason::AccountDoesNotExist(
                FindError::Account(account_id.clone()),
            ));
        }

        if !is_genesis {
            debug!("Validating transaction: {:?}", tx);
            Self::validate_with_runtime_validator(account_id, tx.clone(), wsv)?;
        }

        match tx.payload.instructions {
            Executable::Instructions(instructions) => {
                // Non-genesis instructions have been executed in `validate_with_runtime_validators()`.
                if is_genesis {
                    for instruction in instructions {
                        instruction
                            .clone()
                            .execute(account_id, wsv)
                            .map_err(|reason| InstructionExecutionFail {
                                instruction,
                                reason: reason.to_string(),
                            })
                            .map_err(TransactionRejectionReason::InstructionExecution)?;
                    }
                }
            }
            Executable::Wasm(bytes) => self.validate_wasm(account_id.clone(), wsv, bytes)?,
        }

        (!is_genesis).then(|| debug!("Validation successful"));
        Ok(())
    }

    /// Validate signatures for the given transaction
    fn validate_signatures(
        tx: &AcceptedTransaction,
        is_genesis: bool,
        wsv: &WorldStateView,
    ) -> Result<(), TransactionRejectionReason> {
        if !is_genesis && tx.payload().account_id == AccountId::genesis() {
            return Err(TransactionRejectionReason::UnexpectedGenesisAccountSignature);
        }

        let option_reason = match tx.check_signature_condition(wsv) {
            Ok(MustUse(true)) => None,
            Ok(MustUse(false)) => Some("Signature condition not satisfied.".to_owned()),
            Err(reason) => Some(reason.to_string()),
        }
        .map(|reason| UnsatisfiedSignatureConditionFail { reason })
        .map(TransactionRejectionReason::from);

        if let Some(reason) = option_reason {
            return Err(reason);
        }

        Ok(())
    }

    fn validate_wasm(
        &self,
        account_id: <Account as Identifiable>::Id,
        wsv: &mut WorldStateView,
        wasm: WasmSmartContract,
    ) -> Result<(), TransactionRejectionReason> {
        debug!("Validating wasm");

        wasm::RuntimeBuilder::new()
            .build()
            .and_then(|mut wasm_runtime| {
                wasm_runtime.validate(
                    wsv,
                    account_id,
                    wasm,
                    self.transaction_limits.max_instruction_number,
                )
            })
            .map_err(|error| WasmExecutionFail {
                reason: format!("{:?}", eyre::Report::from(error)),
            })
            .map_err(TransactionRejectionReason::WasmExecution)
    }

    /// Validate transaction with runtime validators.
    ///
    /// Note: transaction instructions will be executed on the given `wsv`.
    fn validate_with_runtime_validator(
        authority: &<Account as Identifiable>::Id,
        tx: AcceptedTransaction,
        wsv: &mut WorldStateView,
    ) -> Result<(), TransactionRejectionReason> {
        let AcceptedTransaction {
            payload,
            signatures,
        } = tx;

        let signed_tx = SignedTransaction {
            payload,
            signatures,
        };

        wsv.validator_view()
            .clone() // Cloning validator is a cheap operation
            .validate(wsv, authority, signed_tx)
            .map_err(|error| {
                if let ValidationFail::InternalError(msg) = &error {
                    error!(
                        error = msg,
                        "Internal error occurred during transaction validation, \
                         is Runtime Validator correct?"
                    )
                }
                error.into()
            })
    }
}

/// Trait for signature check condition.
pub trait CheckSignatureCondition: Sized {
    /// Checks that the signatures of this transaction satisfy the signature condition specified in the account.
    ///
    /// Note that `check_signature_condition` does not verify signatures.
    /// Signature verification is done when transaction transit from `SignedTransaction` to `AcceptedTransaction` state.
    ///
    /// # Errors
    /// - Account not found
    fn check_signature_condition(&self, wsv: &WorldStateView) -> Result<MustUse<bool>>;
}

impl CheckSignatureCondition for AcceptedTransaction {
    fn check_signature_condition(&self, wsv: &WorldStateView) -> Result<MustUse<bool>> {
        let account_id = &self.payload.account_id;

        let signatories = self
            .signatures
            .iter()
            .map(|signature| signature.public_key())
            .cloned();

        wsv.map_account(account_id, |account| {
            wsv.evaluate(&check_signature_condition(account, signatories))
                .map(MustUse::new)
                .map_err(Into::into)
        })?
    }
}

impl CheckSignatureCondition for VersionedAcceptedTransaction {
    fn check_signature_condition(&self, wsv: &WorldStateView) -> Result<MustUse<bool>> {
        self.as_v1().check_signature_condition(wsv)
    }
}

/// Returns a prebuilt expression that when executed
/// returns if the needed signatures are gathered.
fn check_signature_condition(
    account: &Account,
    signatories: impl IntoIterator<Item = PublicKey>,
) -> EvaluatesTo<bool> {
    let where_expr = Where::new(EvaluatesTo::new_evaluates_to_value(Clone::clone(
        &*account.signature_check_condition.0.expression.clone(),
    )))
    .with_value(
        Name::from_str(iroha_data_model::account::ACCOUNT_SIGNATORIES_VALUE)
            .expect("ACCOUNT_SIGNATORIES_VALUE should be valid."),
        account.signatories.iter().cloned().collect::<Vec<_>>(),
    )
    .with_value(
        Name::from_str(iroha_data_model::account::TRANSACTION_SIGNATORIES_VALUE)
            .expect("TRANSACTION_SIGNATORIES_VALUE should be valid."),
        signatories.into_iter().collect::<Vec<_>>(),
    );

    EvaluatesTo::new_unchecked(where_expr)
}

impl IsInBlockchain for VersionedSignedTransaction {
    #[inline]
    fn is_in_blockchain(&self, wsv: &WorldStateView) -> bool {
        wsv.has_transaction(&self.hash())
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
