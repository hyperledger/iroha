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

use eyre::Result;
use iroha_crypto::{HashOf, SignatureVerificationFail, SignaturesOf};
pub use iroha_data_model::prelude::*;
use iroha_data_model::{
    query::error::FindError,
    transaction::{error::TransactionLimitError, TransactionLimits},
};
use iroha_genesis::GenesisTransaction;
use iroha_logger::{debug, error};
use iroha_macro::FromVariant;

use crate::{prelude::*, smartcontracts::wasm};

/// `AcceptedTransaction` — a transaction accepted by iroha peer.
#[derive(Debug, Clone, PartialEq, Eq)]
// TODO: Inner field should be private to maintain invariants
pub struct AcceptedTransaction(pub(crate) VersionedSignedTransaction);

/// Error type for transaction from [`VersionedSignedTransaction`] to [`AcceptedTransaction`]
#[derive(Debug, FromVariant, thiserror::Error, displaydoc::Display)]
pub enum AcceptTransactionFail {
    /// Failure during limits check
    TransactionLimit(#[source] TransactionLimitError),
    /// Failure during signature verification
    SignatureVerification(#[source] SignatureVerificationFail<TransactionPayload>),
    /// The genesis account can only sign transactions in the genesis block
    UnexpectedGenesisAccountSignature,
}

fn instruction_size(isi: &InstructionBox) -> usize {
    use InstructionBox::*;

    match isi {
        Register(isi) => isi.object.len() + 1,
        Unregister(isi) => isi.object_id.len() + 1,
        Mint(isi) => isi.destination_id.len() + isi.object.len() + 1,
        Burn(isi) => isi.destination_id.len() + isi.object.len() + 1,
        Transfer(isi) => isi.destination_id.len() + isi.object.len() + isi.source_id.len() + 1,
        If(isi) => {
            let otherwise = isi.otherwise.as_ref().map_or(0, instruction_size);
            isi.condition.len() + instruction_size(&isi.then) + otherwise + 1
        }
        Pair(isi) => {
            instruction_size(&isi.left_instruction) + instruction_size(&isi.right_instruction) + 1
        }
        Sequence(isi) => isi.instructions.iter().map(instruction_size).sum::<usize>() + 1,
        SetKeyValue(isi) => isi.object_id.len() + isi.key.len() + isi.value.len() + 1,
        RemoveKeyValue(isi) => isi.object_id.len() + isi.key.len() + 1,
        Grant(isi) => isi.object.len() + isi.destination_id.len() + 1,
        Revoke(isi) => isi.object.len() + isi.destination_id.len() + 1,
        SetParameter(isi) => isi.parameter.len() + 1,
        NewParameter(isi) => isi.parameter.len() + 1,
        Upgrade(isi) => isi.object.len() + 1,
        Log(isi) => isi.msg.len() + isi.msg.len() + 1,
        Fail(_) | ExecuteTrigger(_) => 1,
    }
}

impl AcceptedTransaction {
    /// Accept genesis transaction. Transition from [`GenesisTransaction`] to [`AcceptedTransaction`].
    pub fn accept_genesis(tx: GenesisTransaction) -> Self {
        Self(tx.0)
    }

    /// Accept transaction. Transition from [`VersionedSignedTransaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// - if it does not adhere to limits
    pub fn accept(
        transaction: VersionedSignedTransaction,
        limits: &TransactionLimits,
    ) -> Result<Self, AcceptTransactionFail> {
        if *iroha_genesis::GENESIS_ACCOUNT_ID == transaction.payload().authority {
            return Err(AcceptTransactionFail::UnexpectedGenesisAccountSignature);
        }

        match &transaction.payload().instructions {
            Executable::Instructions(instructions) => {
                let instruction_count: u64 = instructions
                    .iter()
                    .map(instruction_size)
                    .sum::<usize>()
                    .try_into()
                    .expect("`usize` should always fit in `u64`");

                if instruction_count > limits.max_instruction_number {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "Too many instructions in payload, max number is {}, but got {}",
                                limits.max_instruction_number, instruction_count
                            ),
                        },
                    ));
                }
            }
            // TODO: Can we check the number of instructions in wasm? Because we do this check
            // when executing wasm where we deny wasm if number of instructions exceeds the limit.
            //
            // Should we allow infinite instructions in wasm? And deny only based on fuel and size
            Executable::Wasm(smart_contract) => {
                let max_wasm_size_bytes = limits.max_wasm_size_bytes;

                let size_bytes: u64 = smart_contract
                    .size_bytes()
                    .try_into()
                    .expect("`u64` should always fit in `u64`");

                if size_bytes > max_wasm_size_bytes {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!("Wasm binary too large, max size is {max_wasm_size_bytes}, but got {size_bytes}"),
                        },
                    ));
                }
            }
        }

        Ok(Self(transaction))
    }

    /// Transaction hash
    pub fn hash(&self) -> HashOf<VersionedSignedTransaction> {
        self.0.hash()
    }

    /// Payload of the transaction
    pub fn payload(&self) -> &TransactionPayload {
        self.0.payload()
    }

    pub(crate) fn signatures(&self) -> &SignaturesOf<TransactionPayload> {
        self.0.signatures()
    }

    pub(crate) fn merge_signatures(&mut self, other: Self) -> bool {
        self.0.merge_signatures(other.0)
    }
}

impl From<AcceptedTransaction> for VersionedSignedTransaction {
    fn from(source: AcceptedTransaction) -> Self {
        source.0
    }
}

impl From<AcceptedTransaction> for (AccountId, Executable) {
    fn from(source: AcceptedTransaction) -> Self {
        source.0.into()
    }
}

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
        wsv: &mut WorldStateView,
    ) -> Result<VersionedSignedTransaction, (VersionedSignedTransaction, TransactionRejectionReason)>
    {
        if let Err(rejection_reason) = self.validate_internal(tx.clone(), wsv) {
            return Err((tx.0, rejection_reason));
        }

        Ok(tx.0)
    }

    fn validate_internal(
        &self,
        tx: AcceptedTransaction,
        wsv: &mut WorldStateView,
    ) -> Result<(), TransactionRejectionReason> {
        let authority = &tx.payload().authority;

        if !wsv
            .domain(&authority.domain_id)
            .map_err(|_e| {
                TransactionRejectionReason::AccountDoesNotExist(FindError::Domain(
                    authority.domain_id.clone(),
                ))
            })?
            .accounts
            .contains_key(authority)
        {
            return Err(TransactionRejectionReason::AccountDoesNotExist(
                FindError::Account(authority.clone()),
            ));
        }

        // Create clone wsv to try execute transaction against it to prevent failed transaction from changing wsv
        let mut wsv_for_validation = wsv.clone();

        debug!("Validating transaction: {:?}", tx);
        Self::validate_with_runtime_validator(tx.clone(), &mut wsv_for_validation)?;

        if let (authority, Executable::Wasm(bytes)) = tx.into() {
            self.validate_wasm(authority, &mut wsv_for_validation, bytes)?
        }

        // Replace wsv in case of successful execution
        *wsv = wsv_for_validation;

        debug!("Validation successful");
        Ok(())
    }

    fn validate_wasm(
        &self,
        authority: AccountId,
        wsv: &mut WorldStateView,
        wasm: WasmSmartContract,
    ) -> Result<(), TransactionRejectionReason> {
        debug!("Validating wasm");

        wasm::RuntimeBuilder::<wasm::state::SmartContract>::new()
            .build()
            .and_then(|mut wasm_runtime| {
                wasm_runtime.validate(
                    wsv,
                    authority,
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
        tx: AcceptedTransaction,
        wsv: &mut WorldStateView,
    ) -> Result<(), TransactionRejectionReason> {
        let tx: VersionedSignedTransaction = tx.into();
        let authority = tx.payload().authority.clone();

        wsv.validator()
            .clone() // Cloning validator is a cheap operation
            .validate_transaction(wsv, &authority, tx)
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

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::*;

    fn if_instruction(
        c: impl Into<Expression>,
        then: InstructionBox,
        otherwise: Option<InstructionBox>,
    ) -> InstructionBox {
        let condition: Expression = c.into();
        let condition = EvaluatesTo::new_unchecked(condition);
        Conditional {
            condition,
            then,
            otherwise,
        }
        .into()
    }

    fn fail() -> InstructionBox {
        FailBox {
            message: String::default(),
        }
        .into()
    }

    #[test]
    fn len_empty_sequence() {
        assert_eq!(instruction_size(&SequenceBox::new(vec![]).into()), 1);
    }

    #[test]
    fn len_if_one_branch() {
        let instructions = vec![if_instruction(
            ContextValue {
                value_name: Name::from_str("a").expect("Cannot fail."),
            },
            fail(),
            None,
        )];

        assert_eq!(instruction_size(&SequenceBox::new(instructions).into()), 4);
    }

    #[test]
    fn len_sequence_if() {
        let instructions = vec![
            fail(),
            if_instruction(
                ContextValue {
                    value_name: Name::from_str("b").expect("Cannot fail."),
                },
                fail(),
                Some(fail()),
            ),
            fail(),
        ];

        assert_eq!(instruction_size(&SequenceBox::new(instructions).into()), 7);
    }
}
