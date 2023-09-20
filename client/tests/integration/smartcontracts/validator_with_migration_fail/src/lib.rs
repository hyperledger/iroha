//! Runtime Validator which copies default validation logic but forbids any queries and fails to migrate.

#![no_std]
#![allow(missing_docs, clippy::missing_errors_doc)]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{borrow::ToOwned as _, format};

use anyhow::anyhow;
use iroha_validator::{
    data_model::evaluate::{EvaluationError, ExpressionEvaluator},
    iroha_wasm, parse,
    prelude::*,
};

struct Validator {
    transaction_verdict: MaybeVerdict<TransactionValidationOutput>,
    instruction_verdict: MaybeVerdict<InstructionValidationOutput>,
    query_verdict: MaybeVerdict<QueryValidationOutput>,

    block_height: u64,
    host: iroha_wasm::Host,
}

impl Validator {
    /// Construct [`Self`]
    pub fn new(block_height: u64) -> Self {
        Self {
            transaction_verdict: MaybeVerdict::default(),
            instruction_verdict: MaybeVerdict::default(),
            // TODO: Default initialize when queries will be executed inside validator
            query_verdict: MaybeVerdict::Verdict(Ok(())),
            block_height,
            host: iroha_wasm::Host,
        }
    }
}

macro_rules! defaults {
    ( $($validator:ident $(<$param:ident $(: $bound:path)?>)?($operation:ty)),+ $(,)? ) => { $(
        fn $validator $(<$param $(: $bound)?>)?(&mut self, authority: &AccountId, operation: $operation) {
            iroha_validator::default::$validator(self, authority, operation)
        } )+
    };
}

impl Visit for Validator {
    fn visit_query(&mut self, _authority: &AccountId, _query: &QueryBox) {
        deny_query!(self, "All queries are forbidden");
    }

    defaults! {
        visit_unsupported<T: core::fmt::Debug>(T),

        visit_transaction(&VersionedSignedTransaction),
        visit_wasm(&WasmSmartContract),
        visit_instruction(&InstructionBox),
        visit_expression<V>(&EvaluatesTo<V>),
        visit_sequence(&SequenceBox),
        visit_if(&Conditional),
        visit_pair(&Pair),

        // Peer validation
        visit_unregister_peer(Unregister<Peer>),

        // Domain validation
        visit_unregister_domain(Unregister<Domain>),
        visit_set_domain_key_value(SetKeyValue<Domain>),
        visit_remove_domain_key_value(RemoveKeyValue<Domain>),

        // Account validation
        visit_unregister_account(Unregister<Account>),
        visit_mint_account_public_key(Mint<Account, PublicKey>),
        visit_burn_account_public_key(Burn<Account, PublicKey>),
        visit_mint_account_signature_check_condition(Mint<Account, SignatureCheckCondition>),
        visit_set_account_key_value(SetKeyValue<Account>),
        visit_remove_account_key_value(RemoveKeyValue<Account>),

        // Asset validation
        visit_register_asset(Register<Asset>),
        visit_unregister_asset(Unregister<Asset>),
        visit_mint_asset(Mint<Asset, NumericValue>),
        visit_burn_asset(Burn<Asset, NumericValue>),
        visit_transfer_asset(Transfer<Asset, NumericValue, Account>),
        visit_set_asset_key_value(SetKeyValue<Asset>),
        visit_remove_asset_key_value(RemoveKeyValue<Asset>),

        // AssetDefinition validation
        visit_unregister_asset_definition(Unregister<AssetDefinition>),
        visit_transfer_asset_definition(Transfer<Account, AssetDefinition, Account>),
        visit_set_asset_definition_key_value(SetKeyValue<AssetDefinition>),
        visit_remove_asset_definition_key_value(RemoveKeyValue<AssetDefinition>),

        // Permission validation
        visit_grant_account_permission(Grant<Account, PermissionToken>),
        visit_revoke_account_permission(Revoke<Account, PermissionToken>),

        // Role validation
        visit_register_role(Register<Role>),
        visit_unregister_role(Unregister<Role>),
        visit_grant_account_role(Grant<Account, RoleId>),
        visit_revoke_account_role(Revoke<Account, RoleId>),

        // Trigger validation
        visit_unregister_trigger(Unregister<Trigger<TriggeringFilterBox, Executable>>),
        visit_mint_trigger_repetitions(Mint<Trigger<TriggeringFilterBox, Executable>, u32>),
        visit_execute_trigger(ExecuteTrigger),

        // Parameter validation
        visit_set_parameter(SetParameter),
        visit_new_parameter(NewParameter),

        // Upgrade validation
        visit_upgrade_validator(Upgrade<iroha_validator::data_model::validator::Validator>),

        // Retrieve validation
        visit_retrieve(&Retrieve),
    }
}

impl Validate for Validator {
    fn block_height(&self) -> u64 {
        self.block_height
    }

    fn transaction_verdict(&self) -> MaybeVerdict<&TransactionValidationOutput, &ValidationFail> {
        self.transaction_verdict.as_ref()
    }

    fn set_transaction_verdict(&mut self, verdict: Result<TransactionValidationOutput>) {
        self.transaction_verdict = MaybeVerdict::Verdict(verdict);
    }

    fn instruction_verdict(&self) -> MaybeVerdict<&InstructionValidationOutput, &ValidationFail> {
        self.instruction_verdict.as_ref()
    }

    fn set_instruction_verdict(&mut self, verdict: Result<InstructionValidationOutput>) {
        self.instruction_verdict = MaybeVerdict::Verdict(verdict);
    }

    fn query_verdict(&self) -> MaybeVerdict<&QueryValidationOutput, &ValidationFail> {
        self.query_verdict.as_ref()
    }

    fn set_query_verdict(&mut self, verdict: Result<QueryValidationOutput>) {
        self.query_verdict = MaybeVerdict::Verdict(verdict);
    }
}

impl ExpressionEvaluator for Validator {
    fn evaluate<E: Evaluate>(&self, expression: &E) -> Result<E::Value, EvaluationError> {
        self.host.evaluate(expression)
    }
}

#[entrypoint]
pub fn migrate(_block_height: u64) -> MigrationResult {
    // Performing side-effects to check in the test that it won't be applied after failure

    // Registering a new domain (using ISI)
    let domain_id = parse!("failed_migration_test_domain" as DomainId);
    RegisterBox::new(Domain::new(domain_id))
        .execute()
        .map_err(|error| {
            format!(
                "{:?}",
                anyhow!(error).context("Failed to register test domain")
            )
        })?;

    Err("This validator always fails to migrate".to_owned())
}

#[entrypoint]
pub fn validate_transaction(
    authority: AccountId,
    transaction: VersionedSignedTransaction,
    block_height: u64,
) -> Result<TransactionValidationOutput> {
    let mut validator = Validator::new(block_height);
    validator.visit_transaction(&authority, &transaction);
    validator.transaction_verdict.assume_verdict()
}

#[entrypoint]
pub fn validate_instruction(
    authority: AccountId,
    instruction: InstructionBox,
    block_height: u64,
) -> Result<InstructionValidationOutput> {
    let mut validator = Validator::new(block_height);
    validator.visit_instruction(&authority, &instruction);
    validator.instruction_verdict.assume_verdict()
}

#[entrypoint]
pub fn validate_query(
    authority: AccountId,
    query: QueryBox,
    block_height: u64,
) -> Result<QueryValidationOutput> {
    let mut validator = Validator::new(block_height);
    validator.visit_query(&authority, &query);
    validator.query_verdict.assume_verdict()
}
