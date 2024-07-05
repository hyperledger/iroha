//! Trigger which register multisignature account and create trigger to control it

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::format;

use executor_custom_data_model::multisig::MultisigRegisterArgs;
use iroha_executor_data_model::permission::trigger::CanExecuteUserTrigger;
use iroha_trigger::{debug::dbg_panic, prelude::*};
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

// Trigger wasm code for handling multisig logic
const WASM: &[u8] = core::include_bytes!(concat!(core::env!("OUT_DIR"), "/multisig.wasm"));

#[iroha_trigger::main]
fn main(_id: TriggerId, _owner: AccountId, event: EventBox) {
    let args: MultisigRegisterArgs = match event {
        EventBox::ExecuteTrigger(event) => event
            .args()
            .dbg_expect("trigger expect args")
            .try_into_any()
            .dbg_expect("failed to parse args"),
        _ => dbg_panic("Only work as by call trigger"),
    };

    let account_id = args.account.id().clone();

    Register::account(args.account)
        .execute()
        .dbg_expect("failed to register multisig account");

    let trigger_id: TriggerId = format!(
        "{}_{}_multisig_trigger",
        account_id.signatory(),
        account_id.domain()
    )
    .parse()
    .dbg_expect("failed to parse trigger id");

    let payload = WasmSmartContract::from_compiled(WASM.to_vec());
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            payload,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
        ),
    );

    Register::trigger(trigger)
        .execute()
        .dbg_expect("failed to register multisig trigger");

    let role_id: RoleId = format!(
        "{}_{}_signatories",
        account_id.signatory(),
        account_id.domain()
    )
    .parse()
    .dbg_expect("failed to parse role");

    let can_execute_multisig_trigger = CanExecuteUserTrigger {
        trigger: trigger_id.clone(),
    };
    let role = Role::new(role_id.clone()).add_permission(can_execute_multisig_trigger);

    Register::role(role)
        .execute()
        .dbg_expect("failed to register multisig role");

    SetKeyValue::trigger(
        trigger_id,
        "signatories".parse().unwrap(),
        JsonString::new(&args.signatories),
    )
    .execute()
    .dbg_unwrap();

    for signatory in args.signatories {
        Grant::role(role_id.clone(), signatory)
            .execute()
            .dbg_expect("failed to grant multisig role to account");
    }
}
