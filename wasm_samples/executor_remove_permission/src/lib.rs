//! Runtime Executor which removes [`token::CanControlDomainLives`] permission token.
//! Needed for tests.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use iroha_executor::{prelude::*, DataModelBuilder};
use iroha_executor_data_model::permission::domain::CanUnregisterDomain;

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Visit, Execute, Entrypoints)]
struct Executor {
    host: Iroha,
    context: Context,
    verdict: Result,
}

#[entrypoint]
fn migrate(host: Iroha, _context: Context) {
    // Note that actually migration will reset token schema to default (minus `CanUnregisterDomain`)
    // So any added custom permission tokens will be also removed
    DataModelBuilder::with_default_permissions()
        .remove_permission::<CanUnregisterDomain>()
        .build_and_set(&host);
}
