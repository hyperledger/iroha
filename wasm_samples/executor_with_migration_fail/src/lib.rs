//! Runtime Executor which copies default validation logic but forbids any queries and fails to migrate.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use iroha_executor::{debug::dbg_panic, prelude::*};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
struct Executor {
    verdict: Result,
    block_height: u64,
}

#[entrypoint]
fn migrate(_block_height: u64) {
    // Performing side-effects to check in the test that it won't be applied after failure

    // Registering a new domain (using ISI)
    let domain_id = "failed_migration_test_domain".parse().unwrap();
    Register::domain(Domain::new(domain_id)).execute().unwrap();

    dbg_panic("This executor always fails to migrate");
}
