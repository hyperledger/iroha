//! Smart contract which executes [`FindAllAssets`] and saves cursor to the owner's metadata.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

extern crate alloc;

use alloc::string::ToString as _;
use core::num::NonZeroU32;

use iroha_smart_contract::{data_model::metadata::MetadataValueBox, parse, prelude::*};
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_smart_contract::stub_getrandom);

/// Execute [`FindAllAssets`] and save cursor to the owner's metadata.
#[iroha_smart_contract::main]
fn main(owner: AccountId) {
    let asset_cursor = FindAllAssets
        .fetch_size(FetchSize::new(Some(NonZeroU32::try_from(1).dbg_unwrap())))
        .execute()
        .dbg_unwrap();

    let (_batch, cursor) = asset_cursor.into_parts();

    SetKeyValue::account(
        owner,
        parse!("cursor" as Name),
        MetadataValueBox::String(
            serde_json::to_value(cursor)
                .dbg_expect("Failed to convert cursor to JSON")
                .to_string(),
        ),
    )
    .execute()
    .dbg_expect("Failed to save cursor to the owner's metadata");
}
