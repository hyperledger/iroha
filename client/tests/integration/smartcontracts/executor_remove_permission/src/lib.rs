//! Runtime Executor which removes [`token::CanControlDomainLives`] permission token.
//! Needed for tests.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use iroha_executor::{default::default_permission_schema, prelude::*};
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
    let mut schema = default_permission_schema();
    schema.remove::<iroha_executor::default::tokens::domain::CanUnregisterDomain>();

    let (token_ids, schema_str) = schema.serialize();
    iroha_executor::set_permission_schema(
        &iroha_executor::data_model::permission::PermissionSchema::new(token_ids, schema_str),
    );

    Ok(())
}
