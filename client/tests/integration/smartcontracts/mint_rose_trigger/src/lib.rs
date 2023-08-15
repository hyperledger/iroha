//! trigger which mints one rose or its owner.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use core::str::FromStr as _;

use iroha_trigger::prelude::*;

/// Mint 1 rose for owner
#[iroha_trigger::main]
fn main(owner: AccountId, _event: Event) {
    let rose_definition_id = AssetDefinitionId::from_str("rose#wonderland")
        .dbg_expect("Failed to parse `rose#wonderland` asset definition id");
    let rose_id = AssetId::new(rose_definition_id, owner);

    MintBox::new(1_u32, rose_id)
        .execute()
        .dbg_expect("Failed to mint rose");
}
