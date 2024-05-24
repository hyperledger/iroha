//! Runtime Executor which allows domain (un-)registration only for users who own
//! [`token::CanControlDomainLives`] permission token.
//!
//! This executor should be applied on top of the blockchain with default validation.
//!
//! It also doesn't have [`iroha_executor::default::permissions::domain::CanUnregisterDomain`].
//!
//! In migration it replaces [`iroha_executor::default::permissions::domain::CanUnregisterDomain`]
//! with [`token::CanControlDomainLives`] for all accounts.
//! So it doesn't matter which domain user was able to unregister before migration, they will
//! get access to control all domains. Remember that this is just a test example.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::string::String;

use anyhow::anyhow;
use iroha_executor::{prelude::*, DataModelBuilder};
use iroha_schema::IntoSchema;
use lol_alloc::{FreeListAllocator, LockedAllocator};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

use alloc::format;

mod token {
    //! Module with custom token.

    use super::*;

    /// Token to identify if user can (un-)register domains.
    #[derive(
        PartialEq,
        Eq,
        Permission,
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

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
#[visit(custom(visit_register_domain, visit_unregister_domain))]
struct Executor {
    verdict: Result,
    block_height: u64,
}

impl Executor {
    fn get_all_accounts_with_can_unregister_domain_permission(
    ) -> Result<Vec<(Account, DomainId)>, MigrationError> {
        let accounts = FindAllAccounts.execute().map_err(|error| {
            format!("{:?}", anyhow!(error).context("Failed to get all accounts"))
        })?;

        let mut found_accounts = Vec::new();

        for account in accounts {
            let account = account.map_err(|error| {
                format!("{:?}", anyhow!(error).context("Failed to get account"))
            })?;
            let permissions = FindPermissionsByAccountId::new(account.id().clone())
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

            for token in permissions {
                let token = token.map_err(|error| {
                    format!(
                        "{:?}",
                        anyhow!(error).context("Failed to get permission token")
                    )
                })?;

                if let Ok(can_unregister_domain_token) =
                    iroha_executor::default::permissions::domain::CanUnregisterDomain::try_from_object(
                        &token,
                    )
                {
                    found_accounts.push((account, can_unregister_domain_token.domain_id));
                    break;
                }
            }
        }

        Ok(found_accounts)
    }

    fn replace_token(accounts: &[(Account, DomainId)]) -> MigrationResult {
        let can_unregister_domain_definition_id =
            iroha_executor::default::permissions::domain::CanUnregisterDomain::id();

        let can_control_domain_lives_definition_id = token::CanControlDomainLives::id();

        accounts
            .iter()
            .try_for_each(|(account, domain_id)| {
                Revoke::permission(
                    Permission::new(
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

                Grant::permission(
                    Permission::new(can_control_domain_lives_definition_id.clone(), &json!(null)),
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

fn visit_register_domain(executor: &mut Executor, authority: &AccountId, isi: &Register<Domain>) {
    if executor.block_height() == 0 {
        execute!(executor, isi);
    }
    if token::CanControlDomainLives.is_owned_by(authority) {
        execute!(executor, isi);
    }

    deny!(
        executor,
        "You don't have permission to register a new domain"
    );
}

fn visit_unregister_domain(
    executor: &mut Executor,
    authority: &AccountId,
    isi: &Unregister<Domain>,
) {
    if executor.block_height() == 0 {
        execute!(executor, isi);
    }
    if token::CanControlDomainLives.is_owned_by(authority) {
        execute!(executor, isi);
    }

    deny!(executor, "You don't have permission to unregister domain");
}

#[entrypoint]
pub fn migrate(_block_height: u64) -> MigrationResult {
    let accounts = Executor::get_all_accounts_with_can_unregister_domain_permission()?;

    DataModelBuilder::with_default_permissions()
        .remove_permission::<iroha_executor::default::permissions::domain::CanUnregisterDomain>()
        .add_permission::<token::CanControlDomainLives>()
        .set();

    Executor::replace_token(&accounts)
}
