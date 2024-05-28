//! Runtime Executor which removes [`token::CanControlDomainLives`] permission token.
//! Needed for tests.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use iroha_executor::{
    default::permissions::domain::CanUnregisterDomain, prelude::*, DataModelBuilder,
};
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
    DataModelBuilder::with_default_permissions()
        .remove_permission::<CanUnregisterDomain>()
        .build_and_set();

    Ok(())
}
