//! Trigger of world-level authority to enable multisig functionality for domains

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::format;

use dlmalloc::GlobalDlmalloc;
use iroha_trigger::{
    debug::{dbg_panic, DebugExpectExt as _},
    prelude::*,
};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

// Binary containing common logic to each domain for handling multisig accounts
const MULTISIG_ACCOUNTS_WASM: &[u8] = core::include_bytes!(concat!(
    core::env!("CARGO_MANIFEST_DIR"),
    "/../../target/prebuilt/libs/multisig_accounts.wasm"
));

#[iroha_trigger::main]
fn main(host: Iroha, context: Context) {
    let EventBox::Data(DataEvent::Domain(event)) = context.event else {
        dbg_panic("trigger misused: must be triggered only by a domain event");
    };
    let (domain_id, domain_owner, owner_changed) = match event {
        DomainEvent::Created(domain) => (domain.id().clone(), domain.owned_by().clone(), false),
        DomainEvent::OwnerChanged(owner_changed) => (
            owner_changed.domain().clone(),
            owner_changed.new_owner().clone(),
            true,
        ),
        _ => dbg_panic(
            "trigger misused: must be triggered only when domain created or owner changed",
        ),
    };

    let accounts_registry_id: TriggerId = format!("multisig_accounts_{}", domain_id)
        .parse()
        .dbg_unwrap();

    let accounts_registry = if owner_changed {
        let existing = host
            .query(FindTriggers::new())
            .filter_with(|trigger| trigger.id.eq(accounts_registry_id.clone()))
            .execute_single()
            .dbg_expect("accounts registry should be existing");

        host.submit(&Unregister::trigger(existing.id().clone()))
            .dbg_expect("accounts registry should be successfully unregistered");

        Trigger::new(
            existing.id().clone(),
            Action::new(
                existing.action().executable().clone(),
                existing.action().repeats().clone(),
                domain_owner,
                existing.action().filter().clone(),
            ),
        )
    } else {
        Trigger::new(
            accounts_registry_id.clone(),
            Action::new(
                WasmSmartContract::from_compiled(MULTISIG_ACCOUNTS_WASM.to_vec()),
                Repeats::Indefinitely,
                domain_owner,
                ExecuteTriggerEventFilter::new().for_trigger(accounts_registry_id.clone()),
            ),
        )
    };

    host.submit(&Register::trigger(accounts_registry))
        .dbg_expect("accounts registry should be successfully registered");
}
