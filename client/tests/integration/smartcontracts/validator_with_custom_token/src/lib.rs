//! Runtime Validator which allows domain (un-)registration only for users who own
//! [`token::CanControlDomainLives`] permission token.
//!
//! This validator should be applied on top of the blockchain with default validation.
//!
//! It also doesn't have [`iroha_validator::default::domain::tokens::CanUnregisterDomain`].
//!
//! In migration it replaces [`iroha_validator::default::domain::tokens::CanUnregisterDomain`]
//! with [`token::CanControlDomainLives`] for all accounts.
//! So it doesn't matter which domain user was able to unregister before migration, they will
//! get access to control all domains. Remember that this is just a test example.

#![no_std]
#![allow(missing_docs, clippy::missing_errors_doc)]

extern crate alloc;

use alloc::string::String;

use anyhow::anyhow;
use iroha_schema::IntoSchema;
use iroha_validator::{
    data_model::evaluate::{EvaluationError, ExpressionEvaluator},
    default::default_permission_token_schema,
    iroha_wasm,
    permission::Token as _,
    prelude::*,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[cfg(not(test))]
extern crate panic_halt;

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
    #[validate(iroha_validator::permission::OnlyGenesis)]
    pub struct CanControlDomainLives;
}

struct Validator {
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
                    iroha_validator::default::domain::tokens::CanUnregisterDomain::try_from(token)
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
            iroha_validator::default::domain::tokens::CanUnregisterDomain::type_name(),
        )
        .unwrap();

        let can_control_domain_lives_definition_id =
            PermissionTokenId::try_from(token::CanControlDomainLives::type_name()).unwrap();

        accounts
            .iter()
            .try_for_each(|(account, domain_id)| {
                RevokeBox::new(
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

                GrantBox::new(
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
                iroha_validator::iroha_wasm::error!(&error);
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
    ( $($validator:ident $(<$param:ident $(: $bound:path)?>)?($operation:ty)),+ $(,)? ) => { $(
        fn $validator $(<$param $(: $bound)?>)?(&mut self, authority: &AccountId, operation: $operation) {
            iroha_validator::default::$validator(self, authority, operation)
        } )+
    };
}

impl Visit for Validator {
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

        visit_transaction(&VersionedSignedTransaction),
        visit_instruction(&InstructionBox),
        visit_expression<V>(&EvaluatesTo<V>),
        visit_sequence(&SequenceBox),
        visit_if(&Conditional),
        visit_pair(&Pair),

        // Peer validation
        visit_unregister_peer(Unregister<Peer>),

        // Domain validation
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
    fn evaluate<E: Evaluate>(&self, expression: &E) -> Result<E::Value, EvaluationError> {
        self.host.evaluate(expression)
    }
}

#[entrypoint]
pub fn migrate(_block_height: u64) -> MigrationResult {
    let accounts = Validator::get_all_accounts_with_can_unregister_domain_permission()?;

    let mut schema = default_permission_token_schema();
    schema.remove::<iroha_validator::default::domain::tokens::CanUnregisterDomain>();
    schema.insert::<token::CanControlDomainLives>();

    let (token_ids, schema_str) = schema.serialize();
    iroha_validator::iroha_wasm::set_permission_token_schema(
        &iroha_validator::data_model::permission::PermissionTokenSchema::new(token_ids, schema_str),
    );

    Validator::replace_token(&accounts)
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
