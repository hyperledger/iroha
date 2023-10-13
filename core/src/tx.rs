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
}

mod len {
    use iroha_data_model::{expression::*, query::QueryBox, Value};

    pub trait ExprLen {
        fn len(&self) -> usize;
    }

    impl<V: TryFrom<Value>> ExprLen for EvaluatesTo<V> {
        fn len(&self) -> usize {
            self.expression.len()
        }
    }

    impl ExprLen for Expression {
        fn len(&self) -> usize {
            use Expression::*;

            match self {
                Add(add) => add.len(),
                Subtract(subtract) => subtract.len(),
                Greater(greater) => greater.len(),
                Less(less) => less.len(),
                Equal(equal) => equal.len(),
                Not(not) => not.len(),
                And(and) => and.len(),
                Or(or) => or.len(),
                If(if_expression) => if_expression.len(),
                Raw(raw) => raw.len(),
                Query(query) => query.len(),
                Contains(contains) => contains.len(),
                ContainsAll(contains_all) => contains_all.len(),
                ContainsAny(contains_any) => contains_any.len(),
                Where(where_expression) => where_expression.len(),
                ContextValue(context_value) => context_value.len(),
                Multiply(multiply) => multiply.len(),
                Divide(divide) => divide.len(),
                Mod(modulus) => modulus.len(),
                RaiseTo(raise_to) => raise_to.len(),
            }
        }
    }
    impl ExprLen for ContextValue {
        fn len(&self) -> usize {
            1
        }
    }
    impl ExprLen for QueryBox {
        fn len(&self) -> usize {
            1
        }
    }

    impl ExprLen for Add {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }
    impl ExprLen for Subtract {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }
    impl ExprLen for Multiply {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }
    impl ExprLen for RaiseTo {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }
    impl ExprLen for Divide {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }
    impl ExprLen for Mod {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }
    impl ExprLen for Greater {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }
    impl ExprLen for Less {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }
    impl ExprLen for Equal {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }
    impl ExprLen for And {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }
    impl ExprLen for Or {
        fn len(&self) -> usize {
            self.left.len() + self.right.len() + 1
        }
    }

    impl ExprLen for Not {
        fn len(&self) -> usize {
            self.expression.len() + 1
        }
    }

    impl ExprLen for Contains {
        fn len(&self) -> usize {
            self.collection.len() + self.element.len() + 1
        }
    }
    impl ExprLen for ContainsAll {
        fn len(&self) -> usize {
            self.collection.len() + self.elements.len() + 1
        }
    }
    impl ExprLen for ContainsAny {
        fn len(&self) -> usize {
            self.collection.len() + self.elements.len() + 1
        }
    }

    impl ExprLen for If {
        fn len(&self) -> usize {
            // TODO: This is wrong because we don't evaluate both branches
            self.condition.len() + self.then.len() + self.otherwise.len() + 1
        }
    }
    impl ExprLen for Where {
        fn len(&self) -> usize {
            self.expression.len() + self.values.values().map(EvaluatesTo::len).sum::<usize>() + 1
        }
    }
}

fn instruction_size(isi: &InstructionExpr) -> usize {
    use len::ExprLen as _;
    use InstructionExpr::*;

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

    /// Accept transaction. Transition from [`SignedTransaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// - if it does not adhere to limits
    pub fn accept(
        transaction: SignedTransaction,
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
    pub fn hash(&self) -> HashOf<SignedTransaction> {
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
        let authority = tx.payload().authority.clone();

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

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::*;

    fn if_instruction(
        c: impl Into<Expression>,
        then: InstructionExpr,
        otherwise: Option<InstructionExpr>,
    ) -> InstructionExpr {
        let condition: Expression = c.into();
        let condition = EvaluatesTo::new_unchecked(condition);
        ConditionalExpr {
            condition,
            then,
            otherwise,
        }
        .into()
    }

    fn fail() -> InstructionExpr {
        Fail {
            message: String::default(),
        }
        .into()
    }

    #[test]
    fn len_empty_sequence() {
        assert_eq!(instruction_size(&SequenceExpr::new(vec![]).into()), 1);
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

        assert_eq!(instruction_size(&SequenceExpr::new(instructions).into()), 4);
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

        assert_eq!(instruction_size(&SequenceExpr::new(instructions).into()), 7);
    }
}
