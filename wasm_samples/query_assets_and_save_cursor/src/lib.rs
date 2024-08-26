//! Smart contract which executes [`FindAssets`] and saves cursor to the owner's metadata.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

extern crate alloc;

use dlmalloc::GlobalDlmalloc;
use iroha_smart_contract::{
    data_model::query::{
        builder::QueryExecutor,
        parameters::{ForwardCursor, QueryParams},
        predicate::CompoundPredicate,
        QueryWithFilter, QueryWithParams,
    },
    prelude::*,
    SmartContractQueryExecutor,
};
use nonzero_ext::nonzero;
use parity_scale_codec::{Decode, DecodeAll, Encode};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_smart_contract::stub_getrandom);

/// Execute [`FindAssets`] and save cursor to the owner's metadata.
/// NOTE: DON'T TAKE THIS AS AN EXAMPLE, THIS IS ONLY FOR TESTING INTERNALS OF IROHA
#[iroha_smart_contract::main]
fn main(owner: AccountId) {
    #[derive(Clone, Debug, Decode)]
    pub struct SmartContractQueryCursor {
        pub cursor: ForwardCursor,
    }

    let (_batch, cursor) = SmartContractQueryExecutor
        .start_query(QueryWithParams::new(
            QueryWithFilter::new(FindAssets, CompoundPredicate::PASS).into(),
            QueryParams::new(
                Default::default(),
                Default::default(),
                FetchSize::new(Some(nonzero!(1_u64))),
            ),
        ))
        .dbg_unwrap();

    // break encapsulation by serializing and deserializing into a compatible type
    let asset_cursor =
        SmartContractQueryCursor::decode_all(&mut &cursor.dbg_unwrap().encode()[..]).dbg_unwrap();

    SetKeyValue::account(
        owner,
        "cursor".parse().unwrap(),
        JsonString::new(asset_cursor.cursor),
    )
    .execute()
    .dbg_expect("Failed to save cursor to the owner's metadata");
}
