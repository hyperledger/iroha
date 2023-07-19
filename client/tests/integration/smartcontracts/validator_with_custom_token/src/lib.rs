//! Runtime Validator which allows domain (un-)registration only for users who own
//! [`token::CanControlDomainLives`] permission token.
//!
//! This validator should be applied on top of the blockchain with [`DefaultValidator`].
//!
//! It also doesn't have [`iroha_validator::default::domain::tokens::CanUnregisterDomain`].
//!
//! In migration it replaces [`iroha_validator::default::domain::tokens::CanUnregisterDomain`]
//! with [`token::CanControlDomainLives`] for all accounts.
//! So it doesn't matter which domain user was able to unregister before migration, they will
//! get access to control all domains. Remember that this is just a test example.

#![no_std]

extern crate alloc;

use alloc::string::String;

use anyhow::anyhow;
use iroha_schema::IntoSchema;
use iroha_validator::{
    data_model::evaluate::{EvaluationError, ExpressionEvaluator},
    permission::Token as _,
    prelude::*,
};
use parity_scale_codec::{Decode, Encode};

#[cfg(not(test))]
extern crate panic_halt;

use alloc::format;

mod token {
    //! Module with custom token.

    use super::*;

    /// Token to identify if user can (un-)register domains.
    #[derive(Token, ValidateGrantRevoke, Decode, Encode, IntoSchema)]
    #[validate(iroha_validator::permission::OnlyGenesis)]
    pub struct CanControlDomainLives;
}

struct CustomValidator(DefaultValidator);

macro_rules! delegate {
    ( $($visitor:ident$(<$bound:ident>)?($operation:ty)),+ $(,)? ) => { $(
        fn $visitor $(<$bound>)?(&mut self, authority: &AccountId, operation: $operation) {
            self.0.$visitor(authority, operation);
        } )+
    }
}

impl CustomValidator {
    const CAN_CONTROL_DOMAIN_LIVES: token::CanControlDomainLives = token::CanControlDomainLives;

    fn get_all_accounts_with_can_unregister_domain_permission(
    ) -> Result<Vec<(Account, DomainId)>, MigrationError> {
        let can_unregister_domain_definition_id = PermissionTokenId::try_from(
            iroha_validator::default::domain::tokens::CanUnregisterDomain::type_name(),
        )
        .unwrap();

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
                if token.definition_id() == &can_unregister_domain_definition_id {
                    let domain_id = DomainId::decode(&mut token.payload()).map_err(|error| {
                        format!(
                            "{:?}",
                            anyhow!(error)
                                .context("Failed to decode `DomainId` from token payload")
                        )
                    })?;
                    found_accounts.push((account, domain_id));
                    break;
                }
            }
        }

        Ok(found_accounts)
    }

    #[allow(single_use_lifetimes)] // Other suggested syntax is incorrect
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
                    PermissionToken::new(can_unregister_domain_definition_id.clone(), domain_id),
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
                    PermissionToken::new(can_control_domain_lives_definition_id.clone(), &()),
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

impl Visit for CustomValidator {
    fn visit_register_domain(&mut self, authority: &AccountId, _register_domain: Register<Domain>) {
        if Self::CAN_CONTROL_DOMAIN_LIVES.is_owned_by(authority) {
            pass!(self);
        }

        deny!(self, "You don't have permission to register a new domain");
    }

    fn visit_unregister_domain(
        &mut self,
        authority: &AccountId,
        _unregister_domain: Unregister<Domain>,
    ) {
        if Self::CAN_CONTROL_DOMAIN_LIVES.is_owned_by(authority) {
            pass!(self);
        }

        deny!(self, "You don't have permission to unregister domain");
    }

    delegate! {
        visit_expression<V>(&EvaluatesTo<V>),

        visit_sequence(&SequenceBox),
        visit_if(&Conditional),
        visit_pair(&Pair),

        visit_instruction(&InstructionBox),

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
        visit_transfer_asset_definition(Transfer<Account, AssetDefinition, Account>),
        visit_set_asset_definition_key_value(SetKeyValue<AssetDefinition>),
        visit_remove_asset_definition_key_value(RemoveKeyValue<AssetDefinition>),

        // Permission validation
        visit_grant_account_permission(Grant<Account, PermissionToken>),
        visit_revoke_account_permission(Revoke<Account, PermissionToken>),

        // Role validation
        visit_unregister_role(Unregister<Role>),
        visit_grant_account_role(Grant<Account, RoleId>),
        visit_revoke_account_role(Revoke<Account, RoleId>),

        // Trigger validation
        visit_unregister_trigger(Unregister<Trigger<FilterBox, Executable>>),
        visit_mint_trigger_repetitions(Mint<Trigger<FilterBox, Executable>, u32>),
        visit_execute_trigger(ExecuteTrigger),

        // Parameter validation
        visit_set_parameter(SetParameter),
        visit_new_parameter(NewParameter),

        // Upgrade validation
        visit_upgrade_validator(Upgrade<iroha_validator::data_model::validator::Validator>),
    }
}

impl Validate for CustomValidator {
    /// Migration should be applied on blockchain with [`DefaultValidator`]
    fn migrate() -> MigrationResult {
        let accounts = Self::get_all_accounts_with_can_unregister_domain_permission()?;

        let mut schema = DefaultValidator::permission_token_schema();
        schema.remove::<iroha_validator::default::domain::tokens::CanUnregisterDomain>();
        schema.insert::<token::CanControlDomainLives>();

        let (token_ids, schema_str) = schema.serialize();
        iroha_validator::iroha_wasm::set_permission_token_schema(
            &iroha_validator::data_model::permission::PermissionTokenSchema::new(
                token_ids, schema_str,
            ),
        );

        Self::replace_token(&accounts)
    }

    fn verdict(&self) -> &Result {
        self.0.verdict()
    }

    fn deny(&mut self, reason: ValidationFail) {
        self.0.deny(reason);
    }
}

impl ExpressionEvaluator for CustomValidator {
    fn evaluate<E: Evaluate>(
        &self,
        expression: &E,
    ) -> core::result::Result<E::Value, EvaluationError> {
        self.0.evaluate(expression)
    }
}

/// Migration entrypoint.
#[entrypoint]
pub fn migrate() -> MigrationResult {
    CustomValidator::migrate()
}

/// Validate operation
#[entrypoint(params = "[authority, operation]")]
pub fn validate(authority: AccountId, operation: NeedsValidationBox) -> Result {
    let mut validator = CustomValidator(DefaultValidator::new());

    match operation {
        NeedsValidationBox::Transaction(transaction) => {
            validator.visit_transaction(&authority, &transaction);
        }
        NeedsValidationBox::Instruction(instruction) => {
            validator.visit_instruction(&authority, &instruction);
        }
        NeedsValidationBox::Query(query) => {
            validator.visit_query(&authority, &query);
        }
    }

    validator.0.verdict
}
