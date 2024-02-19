//! `Transaction`-related functionality of Iroha.
//!
//!
//! Types represent various stages of a `Transaction`'s lifecycle. For
//! example, `Transaction` is the start, when a transaction had been
//! received by Torii.
//!
//! This is also where the actual execution of instructions, as well
//! as various forms of validation are performed.

use eyre::Result;
use iroha_crypto::SignatureVerificationFail;
pub use iroha_data_model::prelude::*;
use iroha_data_model::{
    isi::error::Mismatch,
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
pub struct AcceptedTransaction(pub(crate) SignedTransaction);

/// Error type for transaction from [`SignedTransaction`] to [`AcceptedTransaction`]
#[derive(Debug, FromVariant, thiserror::Error, displaydoc::Display)]
pub enum AcceptTransactionFail {
    /// Failure during limits check
    TransactionLimit(#[source] TransactionLimitError),
    /// Failure during signature verification
    SignatureVerification(#[source] SignatureVerificationFail<TransactionPayload>),
    /// The genesis account can only sign transactions in the genesis block
    UnexpectedGenesisAccountSignature,
    /// Transaction's `chain_id` doesn't correspond to the id of current blockchain
    ChainIdMismatch(Mismatch<ChainId>),
}

impl AcceptedTransaction {
    /// Accept genesis transaction. Transition from [`GenesisTransaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// - if transaction chain id doesn't match
    pub fn accept_genesis(
        tx: GenesisTransaction,
        expected_chain_id: &ChainId,
    ) -> Result<Self, AcceptTransactionFail> {
        let actual_chain_id = tx.0.chain_id();

        if expected_chain_id != actual_chain_id {
            return Err(AcceptTransactionFail::ChainIdMismatch(Mismatch {
                expected: expected_chain_id.clone(),
                actual: actual_chain_id.clone(),
            }));
        }

        Ok(Self(tx.0))
    }

    /// Accept transaction. Transition from [`SignedTransaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// - if it does not adhere to limits
    pub fn accept(
        tx: SignedTransaction,
        expected_chain_id: &ChainId,
        limits: &TransactionLimits,
    ) -> Result<Self, AcceptTransactionFail> {
        let actual_chain_id = tx.chain_id();

        if expected_chain_id != actual_chain_id {
            return Err(AcceptTransactionFail::ChainIdMismatch(Mismatch {
                expected: expected_chain_id.clone(),
                actual: actual_chain_id.clone(),
            }));
        }

        if *iroha_genesis::GENESIS_ACCOUNT_ID == *tx.authority() {
            return Err(AcceptTransactionFail::UnexpectedGenesisAccountSignature);
        }

        match &tx.instructions() {
            Executable::Instructions(instructions) => {
                let instruction_count = instructions.len();
                if Self::len_u64(instruction_count) > limits.max_instruction_number {
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
                let size_bytes = Self::len_u64(smart_contract.size_bytes());
                let max_wasm_size_bytes = limits.max_wasm_size_bytes;

                if size_bytes > max_wasm_size_bytes {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!("Wasm binary too large, max size is {max_wasm_size_bytes}, but got {size_bytes}"),
                        },
                    ));
                }
            }
        }

        Ok(Self(tx))
    }

    #[inline]
    fn len_u64(instruction_count: usize) -> u64 {
        u64::try_from(instruction_count).expect("`usize` should always fit into `u64`")
    }
}

impl From<AcceptedTransaction> for SignedTransaction {
    fn from(source: AcceptedTransaction) -> Self {
        source.0
    }
}

impl From<AcceptedTransaction> for (AccountId, Executable) {
    fn from(source: AcceptedTransaction) -> Self {
        source.0.into()
    }
}

impl AsRef<SignedTransaction> for AcceptedTransaction {
    fn as_ref(&self) -> &SignedTransaction {
        &self.0
    }
}

/// Used to validate transaction and thus move transaction lifecycle forward
///
/// Validation is skipped for genesis.
#[derive(Clone, Copy)]
pub struct TransactionExecutor {
    /// [`TransactionLimits`] field
    pub transaction_limits: TransactionLimits,
}

impl TransactionExecutor {
    /// Construct [`TransactionExecutor`]
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
    ) -> Result<SignedTransaction, (SignedTransaction, TransactionRejectionReason)> {
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
        let authority = tx.as_ref().authority();

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
        Self::validate_with_runtime_executor(tx.clone(), &mut wsv_for_validation)?;

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

    /// Validate transaction with runtime executors.
    ///
    /// Note: transaction instructions will be executed on the given `wsv`.
    fn validate_with_runtime_executor(
        tx: AcceptedTransaction,
        wsv: &mut WorldStateView,
    ) -> Result<(), TransactionRejectionReason> {
        let tx: SignedTransaction = tx.into();
        let authority = tx.authority().clone();

        wsv.executor()
            .clone() // Cloning executor is a cheap operation
            .validate_transaction(wsv, &authority, tx)
            .map_err(|error| {
                if let ValidationFail::InternalError(msg) = &error {
                    error!(
                        error = msg,
                        "Internal error occurred during transaction validation, \
                         is Runtime Executor correct?"
                    )
                }
                error.into()
            })
    }
}
