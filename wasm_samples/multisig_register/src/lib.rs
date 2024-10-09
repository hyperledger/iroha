//! Trigger which register multisignature account and create trigger to control it

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::format;

use dlmalloc::GlobalDlmalloc;
use executor_custom_data_model::multisig::MultisigRegisterArgs;
use iroha_executor_data_model::permission::trigger::CanExecuteTrigger;
use iroha_trigger::{
    debug::{dbg_panic, DebugExpectExt as _},
    prelude::*,
};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

// Trigger wasm code for handling multisig logic
const WASM: &[u8] = core::include_bytes!(concat!(core::env!("OUT_DIR"), "/multisig.wasm"));

#[iroha_trigger::main]
fn main(host: Iroha, context: Context) {
    let EventBox::ExecuteTrigger(event) = context.event else {
        dbg_panic("Only work as by call trigger");
    };

    let args: MultisigRegisterArgs = event
        .args()
        .try_into_any()
        .dbg_expect("failed to parse args");

    let account_id = args.account.id().clone();
    host.submit(&Register::account(args.account))
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

    host.submit(&Register::trigger(trigger))
        .dbg_expect("failed to register multisig trigger");

    let role_id: RoleId = format!(
        "{}_{}_signatories",
        account_id.signatory(),
        account_id.domain()
    )
    .parse()
    .dbg_expect("failed to parse role");

    let can_execute_multisig_trigger = CanExecuteTrigger {
        trigger: trigger_id.clone(),
    };

    host.submit(&Register::role(
        // FIX: args.account.id() should be used but I can't
        // execute an instruction from a different account
        Role::new(role_id.clone(), context.authority).add_permission(can_execute_multisig_trigger),
    ))
    .dbg_expect("failed to register multisig role");

    host.submit(&SetKeyValue::trigger(
        trigger_id,
        "signatories".parse().unwrap(),
        JsonString::new(&args.signatories),
    ))
    .dbg_unwrap();

    for signatory in args.signatories {
        host.submit(&Grant::account_role(role_id.clone(), signatory))
            .dbg_expect("failed to grant multisig role to account");
    }
}
