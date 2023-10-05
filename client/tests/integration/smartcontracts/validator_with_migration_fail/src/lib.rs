//! Runtime Validator which copies default validation logic but forbids any queries and fails to migrate.

#![no_std]
#![allow(missing_docs, clippy::missing_errors_doc)]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{borrow::ToOwned as _, format};

use anyhow::anyhow;
use iroha_validator::{
    data_model::{
        evaluate::{EvaluationError, ExpressionEvaluator},
        ValidationFail,
    },
    parse,
    prelude::*,
    smart_contract,
};
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

struct Validator {
    verdict: Result,
    block_height: u64,
    host: smart_contract::Host,
}

impl Validator {
    /// Construct [`Self`]
    pub fn new(block_height: u64) -> Self {
        Self {
            verdict: Ok(()),
            block_height,
            host: smart_contract::Host,
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
        self.deny(ValidationFail::NotPermitted(
            "All queries are forbidden".to_owned(),
        ));
    }

    defaults! {
        visit_unsupported<T: core::fmt::Debug>(T),

        visit_transaction(&SignedTransaction),
        visit_instruction(&InstructionExpr),
        visit_expression<V>(&EvaluatesTo<V>),
        visit_sequence(&SequenceExpr),
        visit_if(&ConditionalExpr),
        visit_pair(&PairExpr),

        // Peer validation
        visit_unregister_peer(Unregister<Peer>),

        // Domain validation
        visit_unregister_domain(Unregister<Domain>),
        visit_transfer_domain(Transfer<Account, DomainId, Account>),
        visit_set_domain_key_value(SetKeyValue<Domain>),
        visit_remove_domain_key_value(RemoveKeyValue<Domain>),

        // Account validation
        visit_unregister_account(Unregister<Account>),
        visit_mint_account_public_key(Mint<PublicKey, Account>),
        visit_burn_account_public_key(Burn<PublicKey, Account>),
        visit_mint_account_signature_check_condition(Mint<SignatureCheckCondition, Account>),
        visit_set_account_key_value(SetKeyValue<Account>),
        visit_remove_account_key_value(RemoveKeyValue<Account>),

        // Asset validation
        visit_register_asset(Register<Asset>),
        visit_unregister_asset(Unregister<Asset>),
        visit_mint_asset(Mint<NumericValue, Asset>),
        visit_burn_asset(Burn<NumericValue, Asset>),
        visit_transfer_asset(Transfer<Asset, NumericValue, Account>),
        visit_set_asset_key_value(SetKeyValue<Asset>),
        visit_remove_asset_key_value(RemoveKeyValue<Asset>),

        // AssetDefinition validation
        visit_unregister_asset_definition(Unregister<AssetDefinition>),
        visit_transfer_asset_definition(Transfer<Account, AssetDefinitionId, Account>),
        visit_set_asset_definition_key_value(SetKeyValue<AssetDefinition>),
        visit_remove_asset_definition_key_value(RemoveKeyValue<AssetDefinition>),

        // Permission validation
        visit_grant_account_permission(Grant<PermissionToken>),
        visit_revoke_account_permission(Revoke<PermissionToken>),

        // Role validation
        visit_register_role(Register<Role>),
        visit_unregister_role(Unregister<Role>),
        visit_grant_account_role(Grant<RoleId>),
        visit_revoke_account_role(Revoke<RoleId>),

        // Trigger validation
        visit_unregister_trigger(Unregister<Trigger<TriggeringFilterBox, Executable>>),
        visit_mint_trigger_repetitions(Mint<u32, Trigger<TriggeringFilterBox, Executable>>),
        visit_burn_trigger_repetitions(Burn<u32, Trigger<TriggeringFilterBox, Executable>>),
        visit_execute_trigger(ExecuteTrigger),

        // Parameter validation
        visit_set_parameter(SetParameter),
        visit_new_parameter(NewParameter),

        // Upgrade validation
        visit_upgrade_validator(Upgrade<iroha_validator::data_model::validator::Validator>),
    }
}

impl Validate for Validator {
    fn verdict(&self) -> &Result {
        &self.verdict
    }

    fn block_height(&self) -> u64 {
        self.block_height
    }

    fn deny(&mut self, reason: ValidationFail) {
        self.verdict = Err(reason);
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
    RegisterExpr::new(Domain::new(domain_id))
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
    transaction: SignedTransaction,
    block_height: u64,
) -> Result {
    let mut validator = Validator::new(block_height);
    validator.visit_transaction(&authority, &transaction);
    validator.verdict
}

#[entrypoint]
pub fn validate_instruction(
    authority: AccountId,
    instruction: InstructionExpr,
    block_height: u64,
) -> Result {
    let mut validator = Validator::new(block_height);
    validator.visit_instruction(&authority, &instruction);
    validator.verdict
}

#[entrypoint]
pub fn validate_query(authority: AccountId, query: QueryBox, block_height: u64) -> Result {
    let mut validator = Validator::new(block_height);
    validator.visit_query(&authority, &query);
    validator.verdict
}
