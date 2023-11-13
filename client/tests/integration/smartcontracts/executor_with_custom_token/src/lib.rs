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

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{borrow::ToOwned, string::String};

use anyhow::anyhow;
use iroha_executor::{
    default::default_permission_token_schema, permission::Token as _, prelude::*, smart_contract,
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

#[derive(Constructor, ValidateEntrypoints, ExpressionEvaluator, Validate, Visit)]
#[visit(custom(visit_register_domain, visit_unregister_domain))]
struct Executor {
    verdict: Result,
    block_height: u64,
    host: smart_contract::Host,
}

impl Executor {
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

fn visit_register_domain(executor: &mut Executor, authority: &AccountId, _isi: Register<Domain>) {
    if executor.block_height() == 0 {
        pass!(executor)
    }
    if token::CanControlDomainLives.is_owned_by(authority) {
        pass!(executor);
    }

    deny!(
        executor,
        "You don't have permission to register a new domain"
    );
}

fn visit_unregister_domain(
    executor: &mut Executor,
    authority: &AccountId,
    _isi: Unregister<Domain>,
) {
    if executor.block_height() == 0 {
        pass!(executor);
    }
    if token::CanControlDomainLives.is_owned_by(authority) {
        pass!(executor);
    }

    deny!(executor, "You don't have permission to unregister domain");
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
