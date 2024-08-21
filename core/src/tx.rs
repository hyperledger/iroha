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
use iroha_crypto::SignatureOf;
pub use iroha_data_model::prelude::*;
use iroha_data_model::{
    isi::error::Mismatch,
    query::error::FindError,
    transaction::{error::TransactionLimitError, TransactionPayload},
};
use iroha_logger::{debug, error};
use iroha_macro::FromVariant;
use storage::storage::StorageReadOnly;

use crate::{
    smartcontracts::wasm,
    state::{StateBlock, StateTransaction},
};

/// `AcceptedTransaction` — a transaction accepted by Iroha peer.
#[derive(Debug, Clone, PartialEq, Eq)]
// FIX: Inner field should be private to maintain invariants
pub struct AcceptedTransaction(pub(crate) SignedTransaction);

/// Verification failed of some signature due to following reason
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureVerificationFail {
    /// Signature which verification has failed
    pub signature: SignatureOf<TransactionPayload>,
    /// Error which happened during verification
    pub reason: String,
}

impl core::fmt::Display for SignatureVerificationFail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Failed to verify signatures: {}", self.reason,)
    }
}

impl std::error::Error for SignatureVerificationFail {}

/// Error type for transaction from [`SignedTransaction`] to [`AcceptedTransaction`]
#[derive(Debug, displaydoc::Display, PartialEq, Eq, FromVariant, thiserror::Error)]
pub enum AcceptTransactionFail {
    /// Failure during limits check
    TransactionLimit(#[source] TransactionLimitError),
    /// Failure during signature verification
    SignatureVerification(#[source] SignatureVerificationFail),
    /// The genesis account can only sign transactions in the genesis block
    UnexpectedGenesisAccountSignature,
    /// Chain id doesn't correspond to the id of current blockchain: {0}
    ChainIdMismatch(Mismatch<ChainId>),
}

impl AcceptedTransaction {
    /// Accept genesis transaction. Transition from [`SignedTransaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// - if transaction chain id doesn't match
    pub fn accept_genesis(
        tx: SignedTransaction,
        expected_chain_id: &ChainId,
        genesis_account: &AccountId,
    ) -> Result<Self, AcceptTransactionFail> {
        let actual_chain_id = tx.chain();

        if expected_chain_id != actual_chain_id {
            return Err(AcceptTransactionFail::ChainIdMismatch(Mismatch {
                expected: expected_chain_id.clone(),
                actual: actual_chain_id.clone(),
            }));
        }

        if genesis_account != tx.authority() {
            return Err(AcceptTransactionFail::UnexpectedGenesisAccountSignature);
        }

        Ok(Self(tx))
    }

    /// Accept transaction. Transition from [`SignedTransaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// - if it does not adhere to limits
    pub fn accept(
        tx: SignedTransaction,
        expected_chain_id: &ChainId,
        limits: TransactionParameters,
    ) -> Result<Self, AcceptTransactionFail> {
        let actual_chain_id = tx.chain();

        if expected_chain_id != actual_chain_id {
            return Err(AcceptTransactionFail::ChainIdMismatch(Mismatch {
                expected: expected_chain_id.clone(),
                actual: actual_chain_id.clone(),
            }));
        }

        if *iroha_genesis::GENESIS_DOMAIN_ID == *tx.authority().domain() {
            return Err(AcceptTransactionFail::UnexpectedGenesisAccountSignature);
        }

        match &tx.instructions() {
            Executable::Instructions(instructions) => {
                let instruction_limit = limits
                    .max_instructions
                    .get()
                    .try_into()
                    .expect("INTERNAL BUG: max instructions exceeds usize::MAX");

                if instructions.len() > instruction_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "Too many instructions in payload, max number is {}, but got {}",
                                limits.max_instructions,
                                instructions.len()
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
                let smart_contract_size_limit = limits
                    .smart_contract_size
                    .get()
                    .try_into()
                    .expect("INTERNAL BUG: smart contract size exceeds usize::MAX");

                if smart_contract.size_bytes() > smart_contract_size_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "WASM binary size is too large: max {}, got {} \
                                (configured by \"Parameter::SmartContractLimits\")",
                                limits.smart_contract_size,
                                smart_contract.size_bytes()
                            ),
                        },
                    ));
                }
            }
        }

        Ok(Self(tx))
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
    /// [`TransactionParameters`] field
    pub limits: TransactionParameters,
}

impl TransactionExecutor {
    /// Construct [`TransactionExecutor`]
    pub fn new(transaction_limits: TransactionParameters) -> Self {
        Self {
            limits: transaction_limits,
        }
    }

    /// Move transaction lifecycle forward by checking if the
    /// instructions can be applied to the [`StateBlock`].
    ///
    /// Validation is skipped for genesis.
    ///
    /// # Errors
    /// Fails if validation of instruction fails (e.g. permissions mismatch).
    pub fn validate(
        &self,
        tx: AcceptedTransaction,
        state_block: &mut StateBlock<'_>,
    ) -> Result<SignedTransaction, (SignedTransaction, TransactionRejectionReason)> {
        let mut state_transaction = state_block.transaction();
        if let Err(rejection_reason) = self.validate_internal(tx.clone(), &mut state_transaction) {
            return Err((tx.0, rejection_reason));
        }
        state_transaction.apply();

        Ok(tx.0)
    }

    fn validate_internal(
        &self,
        tx: AcceptedTransaction,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), TransactionRejectionReason> {
        let authority = tx.as_ref().authority();

        if state_transaction.world.accounts.get(authority).is_none() {
            return Err(TransactionRejectionReason::AccountDoesNotExist(
                FindError::Account(authority.clone()),
            ));
        }

        debug!(tx=%tx.as_ref().hash(), "Validating transaction");
        Self::validate_with_runtime_executor(tx.clone(), state_transaction)?;

        if let (authority, Executable::Wasm(bytes)) = tx.into() {
            self.validate_wasm(authority, state_transaction, bytes)?
        }

        debug!("Validation successful");
        Ok(())
    }

    fn validate_wasm(
        &self,
        authority: AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
        wasm: WasmSmartContract,
    ) -> Result<(), TransactionRejectionReason> {
        debug!("Validating wasm");

        wasm::RuntimeBuilder::<wasm::state::SmartContract>::new()
            .build()
            .and_then(|mut wasm_runtime| {
                wasm_runtime.validate(
                    state_transaction,
                    authority,
                    wasm,
                    self.limits.max_instructions,
                )
            })
            .map_err(|error| WasmExecutionFail {
                reason: format!("{:?}", eyre::Report::from(error)),
            })
            .map_err(TransactionRejectionReason::WasmExecution)
    }

    /// Validate transaction with runtime executors.
    ///
    /// Note: transaction instructions will be executed on the given `state_transaction`.
    fn validate_with_runtime_executor(
        tx: AcceptedTransaction,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), TransactionRejectionReason> {
        let tx: SignedTransaction = tx.into();
        let authority = tx.authority().clone();

        state_transaction
            .world
            .executor
            .clone() // Cloning executor is a cheap operation
            .validate_transaction(state_transaction, &authority, tx)
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
