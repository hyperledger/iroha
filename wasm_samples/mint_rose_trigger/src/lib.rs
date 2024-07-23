//! trigger which mints one rose or its owner.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use core::str::FromStr as _;

use dlmalloc::GlobalDlmalloc;
use iroha_trigger::{prelude::*, smart_contract::query_single};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

/// Mint 1 rose for owner
#[iroha_trigger::main]
fn main(id: TriggerId, owner: AccountId, _event: EventBox) {
    let rose_definition_id = AssetDefinitionId::from_str("rose#wonderland")
        .dbg_expect("Failed to parse `rose#wonderland` asset definition id");
    let rose_id = AssetId::new(rose_definition_id, owner);

    let val: u32 = query_single(FindTriggerMetadata::new(id, "VAL".parse().unwrap()))
        .dbg_unwrap()
        .try_into_any()
        .dbg_unwrap();

    Mint::asset_numeric(val, rose_id)
        .execute()
        .dbg_expect("Failed to mint rose");
}
