//! Smart contract which executes [`FindAllAssets`] and saves cursor to the owner's metadata.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

extern crate alloc;

use alloc::string::ToString as _;

use iroha_smart_contract::{
    data_model::{metadata::MetadataValueBox, query::cursor::ForwardCursor},
    parse,
    prelude::*,
};
use lol_alloc::{FreeListAllocator, LockedAllocator};
use nonzero_ext::nonzero;
use parity_scale_codec::{Decode, DecodeAll, Encode};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_smart_contract::stub_getrandom);

#[derive(Debug, Decode)]
struct QueryOutputCursor {
    _batch: alloc::vec::Vec<Asset>,
    cursor: ForwardCursor,
}

/// Execute [`FindAllAssets`] and save cursor to the owner's metadata.
/// NOTE: DON'T TAKE THIS AS AN EXAMPLE, THIS IS ONLY FOR TESTING INTERNALS OF IROHA
#[iroha_smart_contract::main]
fn main(owner: AccountId) {
    // NOTE: QueryOutputCursor fields are private therefore
    // we guess the layout by encoding and then decoding
    let asset_cursor = QueryOutputCursor::decode_all(
        &mut &FindAllAssets
            .fetch_size(FetchSize::new(Some(nonzero!(1_u32))))
            .execute()
            .dbg_unwrap()
            .encode()[..],
    )
    .dbg_unwrap();

    SetKeyValue::account(
        owner,
        parse!("cursor" as Name),
        MetadataValueBox::String(
            serde_json::to_value(&asset_cursor.cursor)
                .dbg_expect("Failed to convert cursor to JSON")
                .to_string(),
        ),
    )
    .execute()
    .dbg_expect("Failed to save cursor to the owner's metadata");
}
