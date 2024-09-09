//! trigger which mints one rose or its owner.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use iroha_trigger::{debug::DebugExpectExt as _, prelude::*};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

/// Mint 1 rose for owner
#[iroha_trigger::main]
fn main(host: Iroha, context: Context) {
    let rose_id = AssetId::new("rose#wonderland".parse().unwrap(), context.authority);

    let val: u32 = host
        .query_single(FindTriggerMetadata::new(context.id, "VAL".parse().unwrap()))
        .dbg_unwrap()
        .try_into_any()
        .dbg_unwrap();

    host.submit(&Mint::asset_numeric(val, rose_id))
        .dbg_expect("Failed to mint rose");
}
