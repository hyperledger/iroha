//! Trigger of world-level authority to enable multisig functionality for domains

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::format;

use dlmalloc::GlobalDlmalloc;
use iroha_trigger::{debug::dbg_panic, prelude::*, smart_contract::query};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

// Binary containing common logic to each domain for handling multisig accounts
const WASM: &[u8] = core::include_bytes!(concat!(core::env!("OUT_DIR"), "/multisig_accounts.wasm"));

#[iroha_trigger::main]
fn main(_id: TriggerId, _owner: AccountId, event: EventBox) {
    let (domain_id, domain_owner, owner_changed) = match event {
        EventBox::Data(DataEvent::Domain(DomainEvent::Created(domain))) => {
            (domain.id().clone(), domain.owned_by().clone(), false)
        }
        EventBox::Data(DataEvent::Domain(DomainEvent::OwnerChanged(owner_changed))) => (
            owner_changed.domain().clone(),
            owner_changed.new_owner().clone(),
            true,
        ),
        _ => dbg_panic("should be triggered only by domain created events"),
    };

    let accounts_registry_id: TriggerId = format!("multisig_accounts_{}", domain_id)
        .parse()
        .dbg_unwrap();

    let accounts_registry = if owner_changed {
        let existing = query(FindTriggers::new())
            .filter_with(|trigger| trigger.id.eq(accounts_registry_id.clone()))
            .execute_single()
            .dbg_expect("accounts registry should be existing");

        Unregister::trigger(existing.id().clone())
            .execute()
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
                WasmSmartContract::from_compiled(WASM.to_vec()),
                Repeats::Indefinitely,
                domain_owner,
                ExecuteTriggerEventFilter::new().for_trigger(accounts_registry_id.clone()),
            ),
        )
    };

    Register::trigger(accounts_registry)
        .execute()
        .dbg_expect("accounts registry should be successfully registered");
}
