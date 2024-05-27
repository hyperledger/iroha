//! Trigger responsible for activating newly recognized accounts in "wonderland"

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use iroha_trigger::prelude::*;
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

#[iroha_trigger::main]
fn main(_id: TriggerId, _owner: AccountId, event: EventBox) {
    let EventBox::Data(DataEvent::Domain(DomainEvent::Account(AccountEvent::Recognized(
        account_id,
    )))) = event
    else {
        return;
    };

    Register::account(Account::new(account_id))
        .execute()
        .dbg_expect(
        "authority should be alice, and alice should succeed to register accounts in wonderland",
    );
}
