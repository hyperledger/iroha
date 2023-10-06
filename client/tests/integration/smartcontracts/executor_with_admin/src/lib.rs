//! Runtime Executor which allows any instruction executed by `admin@admin` account.
//! If authority is not `admin@admin` then default validation is used as a backup.

#![no_std]
#![allow(missing_docs, clippy::missing_errors_doc)]

#[cfg(not(test))]
extern crate panic_halt;

use iroha_executor::{
    data_model::evaluate::{EvaluationError, ExpressionEvaluator},
    parse,
    prelude::*,
    smart_contract,
};
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

struct Executor {
    verdict: Result,
    block_height: u64,
    host: smart_contract::Host,
}

impl Executor {
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
    ( $($executor:ident $(<$param:ident $(: $bound:path)?>)?($operation:ty)),+ $(,)? ) => { $(
        fn $executor $(<$param $(: $bound)?>)?(&mut self, authority: &AccountId, operation: $operation) {
            iroha_executor::default::$executor(self, authority, operation)
        } )+
    };
}

impl Visit for Executor {
    fn visit_instruction(&mut self, authority: &AccountId, isi: &InstructionExpr) {
        if parse!("admin@admin" as AccountId) == *authority {
            pass!(self);
        }

        iroha_executor::default::visit_instruction(self, authority, isi);
    }

    defaults! {
        visit_unsupported<T: core::fmt::Debug>(T),

        visit_transaction(&SignedTransaction),
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
        visit_unregister_trigger(Unregister<Trigger<TriggeringFilterBox>>),
        visit_mint_trigger_repetitions(Mint<u32, Trigger<TriggeringFilterBox>>),
        visit_burn_trigger_repetitions(Burn<u32, Trigger<TriggeringFilterBox>>),
        visit_execute_trigger(ExecuteTrigger),

        // Parameter validation
        visit_set_parameter(SetParameter),
        visit_new_parameter(NewParameter),

        // Upgrade validation
        visit_upgrade_executor(Upgrade<iroha_executor::data_model::executor::Executor>),
    }
}

impl Validate for Executor {
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

impl ExpressionEvaluator for Executor {
    fn evaluate<E: Evaluate>(&self, expression: &E) -> Result<E::Value, EvaluationError> {
        self.host.evaluate(expression)
    }
}

#[entrypoint]
pub fn migrate(_block_height: u64) -> MigrationResult {
    Ok(())
}

#[entrypoint]
pub fn validate_transaction(
    authority: AccountId,
    transaction: SignedTransaction,
    block_height: u64,
) -> Result {
    let mut executor = Executor::new(block_height);
    executor.visit_transaction(&authority, &transaction);
    executor.verdict
}

#[entrypoint]
pub fn validate_instruction(
    authority: AccountId,
    instruction: InstructionExpr,
    block_height: u64,
) -> Result {
    let mut executor = Executor::new(block_height);
    executor.visit_instruction(&authority, &instruction);
    executor.verdict
}

#[entrypoint]
pub fn validate_query(authority: AccountId, query: QueryBox, block_height: u64) -> Result {
    let mut executor = Executor::new(block_height);
    executor.visit_query(&authority, &query);
    executor.verdict
}
