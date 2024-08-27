//! trigger which mints rose for its owner based on input args.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use core::str::FromStr as _;

use dlmalloc::GlobalDlmalloc;
use executor_custom_data_model::mint_rose_args::MintRoseArgs;
use iroha_trigger::{debug::dbg_panic, prelude::*};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

/// Mint 1 rose for owner
#[iroha_trigger::main]
fn main(_id: TriggerId, owner: AccountId, event: EventBox) {
    let rose_definition_id = AssetDefinitionId::from_str("rose#wonderland")
        .dbg_expect("Failed to parse `rose#wonderland` asset definition id");
    let rose_id = AssetId::new(rose_definition_id, owner);

    let args: MintRoseArgs = match event {
        EventBox::ExecuteTrigger(event) => event
            .args()
            .dbg_expect("Trigger expect parameters")
            .clone()
            .try_into_any()
            .dbg_expect("Failed to parse args"),
        _ => dbg_panic("Only work as by call trigger"),
    };

    let val = args.val;

    Mint::asset_numeric(val, rose_id)
        .execute()
        .dbg_expect("Failed to mint rose");
}
