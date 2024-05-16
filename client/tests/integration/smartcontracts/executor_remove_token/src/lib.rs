//! Runtime Executor which removes [`token::CanControlDomainLives`] permission token.
//! Needed for tests.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use iroha_executor::{default::tokens::domain::CanUnregisterDomain, prelude::*, DataModelBuilder};
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
struct Executor {
    verdict: Result,
    block_height: u64,
}

#[entrypoint]
pub fn migrate(_block_height: u64) -> MigrationResult {
    // Note that actually migration will reset token schema to default (minus `CanUnregisterDomain`)
    // So any added custom permission tokens will be also removed
    let mut data_model = DataModelBuilder::new();
    data_model.extend_with_default_permission_tokens();
    data_model.remove_permission_token::<CanUnregisterDomain>();

    iroha_executor::set_data_model(&data_model.serialize());

    Ok(())
}
