//! trigger which mints one rose or its owner.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use iroha_trigger::prelude::*;
use mint_rose_trigger_data_model::MintRoseArgs;

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

/// Mint 1 rose for owner
#[iroha_trigger::main]
fn main(host: Iroha, context: Context) {
    let EventBox::ExecuteTrigger(event) = context.event else {
        dbg_panic!("Only work as a by call trigger");
    };

    let val = event
        .args()
        .try_into_any::<MintRoseArgs>()
        .map_or_else(
            |_| {
                host.query_single(FindTriggerMetadata::new(context.id, "VAL".parse().unwrap()))
                    .dbg_unwrap()
                    .try_into_any::<u32>()
            },
            |args| Ok(args.val),
        )
        .dbg_expect("Failed get mint value");

    let rose_definition_id = "rose#wonderland".parse().unwrap();
    let rose_id = AssetId::new(rose_definition_id, context.authority);

    host.submit(&Mint::asset_numeric(val, rose_id))
        .dbg_expect("Failed to mint rose");
}
