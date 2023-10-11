//! Runtime Executor which allows domain (un-)registration only for users who own
//! [`token::CanControlDomainLives`] permission token.
//!
//! This executor should be applied on top of the blockchain with default validation.
//!
//! It also doesn't have [`iroha_executor::default::domain::tokens::CanUnregisterDomain`].
//!
//! In migration it replaces [`iroha_executor::default::domain::tokens::CanUnregisterDomain`]
//! with [`token::CanControlDomainLives`] for all accounts.
//! So it doesn't matter which domain user was able to unregister before migration, they will
//! get access to control all domains. Remember that this is just a test example.

#![no_std]
#![allow(missing_docs, clippy::missing_errors_doc)]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{borrow::ToOwned, string::String};

use anyhow::anyhow;
use iroha_executor::{
    data_model::evaluate::{EvaluationError, ExpressionEvaluator},
    default::default_permission_token_schema,
    permission::Token as _,
    prelude::*,
    smart_contract,
};
use iroha_schema::IntoSchema;
use lol_alloc::{FreeListAllocator, LockedAllocator};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

use alloc::format;

mod token {
    //! Module with custom token.

    use super::*;

    /// Token to identify if user can (un-)register domains.
    #[derive(
        PartialEq,
        Eq,
        Token,
        ValidateGrantRevoke,
        Decode,
        Encode,
        IntoSchema,
        Serialize,
        Deserialize,
    )]
    #[validate(iroha_executor::permission::OnlyGenesis)]
    pub struct CanControlDomainLives;
}

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

    fn get_all_accounts_with_can_unregister_domain_permission(
    ) -> Result<Vec<(Account, DomainId)>, MigrationError> {
        let accounts = FindAllAccounts.execute().map_err(|error| {
            format!("{:?}", anyhow!(error).context("Failed to get all accounts"))
        })?;

        let mut found_accounts = Vec::new();

        for account in accounts {
            let permission_tokens = FindPermissionTokensByAccountId::new(account.id().clone())
                .execute()
                .map_err(|error| {
                    format!(
                        "{:?}",
                        anyhow!(error).context(format!(
                            "Failed to get permissions for account `{}`",
                            account.id()
                        ))
                    )
                })?;

            for token in permission_tokens {
                if let Ok(can_unregister_domain_token) =
                    iroha_executor::default::domain::tokens::CanUnregisterDomain::try_from(token)
                {
                    found_accounts.push((account, can_unregister_domain_token.domain_id));
                    break;
                }
            }
        }

        Ok(found_accounts)
    }

    fn replace_token(accounts: &[(Account, DomainId)]) -> MigrationResult {
        let can_unregister_domain_definition_id = PermissionTokenId::try_from(
            iroha_executor::default::domain::tokens::CanUnregisterDomain::type_name(),
        )
        .unwrap();

        let can_control_domain_lives_definition_id =
            PermissionTokenId::try_from(token::CanControlDomainLives::type_name()).unwrap();

        accounts
            .iter()
            .try_for_each(|(account, domain_id)| {
                RevokeExpr::new(
                    PermissionToken::new(
                        can_unregister_domain_definition_id.clone(),
                        &json!({ "domain_id": domain_id }),
                    ),
                    account.id().clone(),
                )
                .execute()
                .map_err(|error| {
                    format!(
                        "{:?}",
                        anyhow!(error).context(format!(
                            "Failed to revoke `{}` token from account `{}`",
                            can_unregister_domain_definition_id,
                            account.id()
                        ))
                    )
                })?;

                GrantExpr::new(
                    PermissionToken::new(
                        can_control_domain_lives_definition_id.clone(),
                        &json!(null),
                    ),
                    account.id().clone(),
                )
                .execute()
                .map_err(|error| {
                    format!(
                        "{:?}",
                        anyhow!(error).context(format!(
                            "Failed to grant `{}` token from account `{}`",
                            can_control_domain_lives_definition_id,
                            account.id()
                        ))
                    )
                })
            })
            .map_err(|error| {
                iroha_executor::log::error!(&error);
                format!(
                    "{:?}",
                    anyhow!(error).context(format!(
                        "Failed to replace `{}` token with `{}` for accounts",
                        can_unregister_domain_definition_id, can_control_domain_lives_definition_id,
                    ))
                )
            })
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
    fn visit_register_domain(&mut self, authority: &AccountId, _isi: Register<Domain>) {
        if self.block_height() == 0 {
            pass!(self);
        }
        if token::CanControlDomainLives.is_owned_by(authority) {
            pass!(self);
        }

        deny!(self, "You don't have permission to register a new domain");
    }

    fn visit_unregister_domain(&mut self, authority: &AccountId, _isi: Unregister<Domain>) {
        if self.block_height() == 0 {
            pass!(self);
        }
        if token::CanControlDomainLives.is_owned_by(authority) {
            pass!(self);
        }

        deny!(self, "You don't have permission to unregister domain");
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
    let accounts = Executor::get_all_accounts_with_can_unregister_domain_permission()?;

    let mut schema = default_permission_token_schema();
    schema.remove::<iroha_executor::default::domain::tokens::CanUnregisterDomain>();
    schema.insert::<token::CanControlDomainLives>();

    let (token_ids, schema_str) = schema.serialize();
    iroha_executor::set_permission_token_schema(
        &iroha_executor::data_model::permission::PermissionTokenSchema::new(token_ids, schema_str),
    );

    Executor::replace_token(&accounts)
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
