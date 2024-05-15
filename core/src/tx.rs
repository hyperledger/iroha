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
    transaction::{error::TransactionLimitError, TransactionLimits, TransactionPayload},
};
use iroha_genesis::GenesisTransaction;
use iroha_logger::{debug, error};
use iroha_macro::FromVariant;

use crate::{
    smartcontracts::wasm,
    state::{StateBlock, StateTransaction, WorldReadOnly},
};

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
        genesis_public_key: &PublicKey,
    ) -> Result<Self, AcceptTransactionFail> {
        let actual_chain_id = tx.0.chain_id();

        if expected_chain_id != actual_chain_id {
            return Err(AcceptTransactionFail::ChainIdMismatch(Mismatch {
                expected: expected_chain_id.clone(),
                actual: actual_chain_id.clone(),
            }));
        }

        let signature = tx.0.signature();
        if signature.public_key() != genesis_public_key {
            return Err(SignatureVerificationFail {
                signature: signature.clone().into(),
                reason: "Signature doesn't correspond to genesis public key".to_string(),
            }
            .into());
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

        if *iroha_genesis::GENESIS_DOMAIN_ID == *tx.authority().domain_id() {
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

        if !state_transaction
            .world
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

        debug!("Validating transaction: {:?}", tx);
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
