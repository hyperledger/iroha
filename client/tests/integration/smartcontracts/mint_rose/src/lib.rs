//! Smartcontract which creates new nft for every user
//!
//! This module isn't included in the build-tree,
//! but instead it is being built by a `client/build.rs`
#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use core::str::FromStr as _;

use iroha_wasm::data_model::prelude::*;

/// Mint 1 rose for authority
#[iroha_wasm::main(params = "[authority]")]
fn main(authority: AccountId) {
    let rose_definition_id = AssetDefinitionId::from_str("rose#wonderland")
        .dbg_expect("Failed to parse `rose#wonderland` asset definition id");
    let rose_id = AssetId::new(rose_definition_id, authority);

    MintBox::new(1_u32, rose_id)
        .execute()
        .dbg_expect("Failed to mint rose");
}
