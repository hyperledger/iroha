//! Runtime Executor which allows domain (un-)registration only for users who own
//! [`CanControlDomainLives`] permission token.
//!
//! This executor should be applied on top of the blockchain with default validation.
//!
//! It also doesn't have [`CanUnregisterDomain`].
//!
//! In migration it replaces [`CanUnregisterDomain`]
//! with [`CanControlDomainLives`] for all accounts.
//! So it doesn't matter which domain user was able to unregister before migration, they will
//! get access to control all domains. Remember that this is just a test example.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use executor_custom_data_model::permissions::CanControlDomainLives;
use iroha_executor::{
    data_model::prelude::*, permission::ExecutorPermision as _, prelude::*, smart_contract::query,
    DataModelBuilder,
};
use iroha_executor_data_model::permission::domain::CanUnregisterDomain;

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
#[visit(custom(
    visit_register_domain,
    visit_unregister_domain,

    // FIXME: Don't derive manually (https://github.com/hyperledger/iroha/issues/3834)
    visit_grant_role_permission,
    visit_grant_role_permission,
    visit_revoke_role_permission,
    visit_revoke_role_permission
))]
struct Executor {
    verdict: Result,
    block_height: u64,
}

impl Executor {
    fn get_all_accounts_with_can_unregister_domain_permission() -> impl Iterator<Item = Account> {
        query(FindAccounts)
            .execute()
            .expect("INTERNAL BUG: Failed to execute `FindAllAccounts`")
            .filter_map(|res| {
                let account = res.dbg_unwrap();

                if query(FindPermissionsByAccountId::new(account.id().clone()))
                    .execute()
                    .expect("INTERNAL BUG: Failed to execute `FindPermissionsByAccountId`")
                    .filter_map(|res| {
                        let permission = res.dbg_unwrap();
                        CanUnregisterDomain::try_from(&permission).ok()
                    })
                    .next()
                    .is_some()
                {
                    return Some(account);
                }

                None
            })
    }

    fn replace_token(accounts: &[Account]) {
        for account in accounts {
            Grant::account_permission(CanControlDomainLives, account.id().clone())
                .execute()
                .dbg_unwrap();
        }
    }
}

fn visit_register_domain(executor: &mut Executor, authority: &AccountId, isi: &Register<Domain>) {
    if executor.block_height() == 0 {
        execute!(executor, isi);
    }
    if CanControlDomainLives.is_owned_by(authority) {
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
    if CanControlDomainLives.is_owned_by(authority) {
        execute!(executor, isi);
    }

    deny!(executor, "You don't have permission to unregister domain");
}

pub fn visit_grant_role_permission<V: Validate + Visit + ?Sized>(
    executor: &mut V,
    authority: &AccountId,
    isi: &Grant<Permission, Role>,
) {
    let role_id = isi.destination().clone();

    if let Ok(permission) = CanControlDomainLives::try_from(isi.object()) {
        let isi = Grant::role_permission(permission, role_id);
        execute!(executor, isi);
    }

    iroha_executor::default::visit_grant_role_permission(executor, authority, isi)
}

pub fn visit_revoke_role_permission<V: Validate + Visit + ?Sized>(
    executor: &mut V,
    authority: &AccountId,
    isi: &Revoke<Permission, Role>,
) {
    let role_id = isi.destination().clone();

    if let Ok(permission) = CanControlDomainLives::try_from(isi.object()) {
        let isi = Revoke::role_permission(permission, role_id);
        execute!(executor, isi);
    }

    iroha_executor::default::visit_revoke_role_permission(executor, authority, isi)
}

pub fn visit_grant_account_permission<V: Validate + Visit + ?Sized>(
    executor: &mut V,
    authority: &AccountId,
    isi: &Grant<Permission, Account>,
) {
    let account_id = isi.destination().clone();

    if let Ok(permission) = CanControlDomainLives::try_from(isi.object()) {
        let isi = Grant::account_permission(permission, account_id);
        execute!(executor, isi);
    }

    iroha_executor::default::visit_grant_account_permission(executor, authority, isi)
}

pub fn visit_revoke_account_permission<V: Validate + Visit + ?Sized>(
    executor: &mut V,
    authority: &AccountId,
    isi: &Revoke<Permission, Account>,
) {
    let account_id = isi.destination().clone();

    if let Ok(permission) = CanControlDomainLives::try_from(isi.object()) {
        let isi = Revoke::account_permission(permission, account_id);
        execute!(executor, isi);
    }

    iroha_executor::default::visit_revoke_account_permission(executor, authority, isi)
}

#[entrypoint]
pub fn migrate(_block_height: u64) {
    let accounts =
        Executor::get_all_accounts_with_can_unregister_domain_permission().collect::<Vec<_>>();

    DataModelBuilder::with_default_permissions()
        .remove_permission::<CanUnregisterDomain>()
        .add_permission::<CanControlDomainLives>()
        .build_and_set();

    Executor::replace_token(&accounts);
}
