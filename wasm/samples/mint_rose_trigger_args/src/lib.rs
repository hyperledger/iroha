//! trigger which mints rose for its owner based on input args.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use executor_custom_data_model::mint_rose_args::MintRoseArgs;
use iroha_trigger::{
    debug::{dbg_panic, DebugExpectExt as _},
    prelude::*,
};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

/// Mint 1 rose for owner
#[iroha_trigger::main]
fn main(host: Iroha, context: Context) {
    let EventBox::ExecuteTrigger(event) = context.event else {
        dbg_panic("Only work as by call trigger");
    };

    let args: MintRoseArgs = event
        .args()
        .try_into_any()
        .dbg_expect("Failed to parse args");

    let rose_definition_id = "rose#wonderland".parse().unwrap();
    let rose_id = AssetId::new(rose_definition_id, context.authority);

    host.submit(&Mint::asset_numeric(args.val, rose_id))
        .dbg_expect("Failed to mint rose");
}
