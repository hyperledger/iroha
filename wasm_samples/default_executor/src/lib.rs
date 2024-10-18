//! Iroha default executor.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use iroha_executor::{
    data_model::block::BlockHeader, debug::dbg_panic, prelude::*, DataModelBuilder,
};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

/// Executor that replaces some of [`Execute`]'s methods with sensible defaults
///
/// # Warning
///
/// The defaults are not guaranteed to be stable.
#[derive(Debug, Clone, Visit, Execute, Entrypoints)]
struct Executor {
    host: Iroha,
    context: Context,
    verdict: Result,
}

impl Executor {
    fn ensure_genesis(curr_block: BlockHeader) {
        if !curr_block.is_genesis() {
            dbg_panic(
                "Default Executor is intended to be used only in genesis. \
                 Write your own executor if you need to upgrade executor on existing chain.",
            );
        }
    }
}

/// Migrate previous executor to the current version.
/// Called by Iroha once just before upgrading executor.
///
/// # Errors
///
/// Concrete errors are specific to the implementation.
///
/// If `migrate()` entrypoint fails then the whole `Upgrade` instruction
/// will be denied and previous executor will stay unchanged.
#[entrypoint]
fn migrate(host: Iroha, context: Context) {
    Executor::ensure_genesis(context.curr_block);
    DataModelBuilder::with_default_permissions().build_and_set(&host);
}
