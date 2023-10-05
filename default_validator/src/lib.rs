//! Iroha default validator.

#![no_std]
#![allow(missing_docs, clippy::missing_errors_doc)]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::borrow::ToOwned as _;

use iroha_validator::{
    data_model::evaluate::ExpressionEvaluator, default::default_permission_token_schema,
    iroha_wasm, prelude::*,
};

/// Validator that replaces some of [`Validate`]'s methods with sensible defaults
///
/// # Warning
///
/// The defaults are not guaranteed to be stable.
#[derive(Debug, Clone)]
pub struct Validator {
    verdict: Result,
    block_height: u64,
    host: iroha_wasm::Host,
}

impl Validator {
    /// Construct [`Self`]
    pub fn new(block_height: u64) -> Self {
        Self {
            verdict: Ok(()),
            block_height,
            host: iroha_wasm::Host,
        }
    }

    fn ensure_genesis(block_height: u64) -> MigrationResult {
        if block_height != 0 {
            return Err("Default Validator is intended to be used only in genesis. \
                 Write your own validator if you need to upgrade validator on existing chain."
                .to_owned());
        }

        Ok(())
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
    defaults! {
        visit_unsupported<T: core::fmt::Debug>(T),

        visit_transaction(&VersionedSignedTransaction),
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
        visit_transfer_asset_definition(Transfer<Account, AssetDefinitionId, Account>),
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
    fn evaluate<E: Evaluate>(
        &self,
        expression: &E,
    ) -> core::result::Result<E::Value, iroha_wasm::data_model::evaluate::EvaluationError> {
        self.host.evaluate(expression)
    }
}

/// Migrate previous validator to the current version.
/// Called by Iroha once just before upgrading validator.
///
/// # Errors
///
/// Concrete errors are specific to the implementation.
///
/// If `migrate()` entrypoint fails then the whole `Upgrade` instruction
/// will be denied and previous validator will stay unchanged.
#[entrypoint]
pub fn migrate(block_height: u64) -> MigrationResult {
    Validator::ensure_genesis(block_height)?;

    let schema = default_permission_token_schema();
    let (token_ids, schema_str) = schema.serialize();
    iroha_validator::iroha_wasm::set_permission_token_schema(
        &iroha_validator::data_model::permission::PermissionTokenSchema::new(token_ids, schema_str),
    );

    Ok(())
}

#[entrypoint]
pub fn validate_transaction(
    authority: AccountId,
    transaction: VersionedSignedTransaction,
    block_height: u64,
) -> Result {
    let mut validator = Validator::new(block_height);
    validator.visit_transaction(&authority, &transaction);
    validator.verdict
}

#[entrypoint]
pub fn validate_instruction(
    authority: AccountId,
    instruction: InstructionBox,
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
