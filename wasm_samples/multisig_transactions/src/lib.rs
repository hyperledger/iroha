//! Trigger given per multi-signature account to control multi-signature transactions

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    format,
    vec::Vec,
};

use dlmalloc::GlobalDlmalloc;
use executor_custom_data_model::multisig::MultisigTransactionArgs;
use iroha_trigger::{
    debug::dbg_panic,
    prelude::*,
    smart_contract::{query, query_single},
};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

#[iroha_trigger::main]
fn main(id: TriggerId, _owner: AccountId, event: EventBox) {
    let (args, signatory): (MultisigTransactionArgs, AccountId) = match event {
        EventBox::ExecuteTrigger(event) => (
            event
                .args()
                .dbg_expect("args should be attached")
                .try_into_any()
                .dbg_expect("args should be for a multisig transaction"),
            event.authority().clone(),
        ),
        _ => dbg_panic("should be triggered by a call"),
    };

    let instructions_hash = match &args {
        MultisigTransactionArgs::Propose(instructions) => HashOf::new(instructions),
        MultisigTransactionArgs::Approve(instructions_hash) => *instructions_hash,
    };
    let instructions_metadata_key: Name = format!("proposals/{instructions_hash}/instructions")
        .parse()
        .unwrap();
    let proposed_at_ms_metadata_key: Name = format!("proposals/{instructions_hash}/proposed_at_ms")
        .parse()
        .unwrap();
    let approvals_metadata_key: Name = format!("proposals/{instructions_hash}/approvals")
        .parse()
        .unwrap();

    let signatories: BTreeMap<AccountId, u8> = query_single(FindTriggerMetadata::new(
        id.clone(),
        "signatories".parse().unwrap(),
    ))
    .dbg_unwrap()
    .try_into_any()
    .dbg_unwrap();

    // Recursively deploy multisig authentication down to the personal leaf signatories
    for account_id in signatories.keys() {
        let sub_transactions_registry_id: TriggerId = format!(
            "multisig_transactions_{}_{}",
            account_id.signatory(),
            account_id.domain()
        )
        .parse()
        .unwrap();

        if let Ok(_sub_registry) = query(FindTriggers::new())
            .filter_with(|trigger| trigger.id.eq(sub_transactions_registry_id.clone()))
            .execute_single()
        {
            let propose_to_approve_me: InstructionBox = {
                let approve_me: InstructionBox = {
                    let args = MultisigTransactionArgs::Approve(instructions_hash);
                    ExecuteTrigger::new(id.clone()).with_args(&args).into()
                };
                let args = MultisigTransactionArgs::Propose([approve_me].to_vec());

                ExecuteTrigger::new(sub_transactions_registry_id.clone())
                    .with_args(&args)
                    .into()
            };
            propose_to_approve_me
                .execute()
                .dbg_expect("should successfully write to sub registry");
        }
    }

    let mut block_headers = query(FindBlockHeaders).execute().dbg_unwrap();
    let now_ms: u64 = block_headers
        .next()
        .dbg_unwrap()
        .dbg_unwrap()
        .creation_time()
        .as_millis()
        .try_into()
        .dbg_unwrap();

    let (approvals, instructions) = match args {
        MultisigTransactionArgs::Propose(instructions) => {
            query_single(FindTriggerMetadata::new(
                id.clone(),
                approvals_metadata_key.clone(),
            ))
            .expect_err("instructions shouldn't already be proposed");

            let approvals = BTreeSet::from([signatory.clone()]);

            SetKeyValue::trigger(
                id.clone(),
                instructions_metadata_key.clone(),
                JsonString::new(&instructions),
            )
            .execute()
            .dbg_unwrap();

            SetKeyValue::trigger(
                id.clone(),
                proposed_at_ms_metadata_key.clone(),
                JsonString::new(&now_ms),
            )
            .execute()
            .dbg_unwrap();

            SetKeyValue::trigger(
                id.clone(),
                approvals_metadata_key.clone(),
                JsonString::new(&approvals),
            )
            .execute()
            .dbg_unwrap();

            (approvals, instructions)
        }
        MultisigTransactionArgs::Approve(_instructions_hash) => {
            let mut approvals: BTreeSet<AccountId> = query_single(FindTriggerMetadata::new(
                id.clone(),
                approvals_metadata_key.clone(),
            ))
            .dbg_expect("instructions should be proposed first")
            .try_into_any()
            .dbg_unwrap();

            approvals.insert(signatory.clone());

            SetKeyValue::trigger(
                id.clone(),
                approvals_metadata_key.clone(),
                JsonString::new(&approvals),
            )
            .execute()
            .dbg_unwrap();

            let instructions: Vec<InstructionBox> = query_single(FindTriggerMetadata::new(
                id.clone(),
                instructions_metadata_key.clone(),
            ))
            .dbg_unwrap()
            .try_into_any()
            .dbg_unwrap();

            (approvals, instructions)
        }
    };

    let quorum: u16 = query_single(FindTriggerMetadata::new(
        id.clone(),
        "quorum".parse().unwrap(),
    ))
    .dbg_unwrap()
    .try_into_any()
    .dbg_unwrap();

    let is_authenticated = quorum
        <= signatories
            .into_iter()
            .filter(|(id, _)| approvals.contains(&id))
            .map(|(_, weight)| weight as u16)
            .sum();

    let is_expired = {
        let proposed_at_ms: u64 = query_single(FindTriggerMetadata::new(
            id.clone(),
            proposed_at_ms_metadata_key.clone(),
        ))
        .dbg_unwrap()
        .try_into_any()
        .dbg_unwrap();

        let transaction_ttl_secs: u32 = query_single(FindTriggerMetadata::new(
            id.clone(),
            "transaction_ttl_secs".parse().unwrap(),
        ))
        .dbg_unwrap()
        .try_into_any()
        .dbg_unwrap();

        proposed_at_ms + transaction_ttl_secs as u64 * 1_000 < now_ms
    };

    if is_authenticated || is_expired {
        // Cleanup approvals and instructions
        RemoveKeyValue::trigger(id.clone(), approvals_metadata_key)
            .execute()
            .dbg_unwrap();
        RemoveKeyValue::trigger(id.clone(), proposed_at_ms_metadata_key)
            .execute()
            .dbg_unwrap();
        RemoveKeyValue::trigger(id.clone(), instructions_metadata_key)
            .execute()
            .dbg_unwrap();

        if !is_expired {
            // Execute instructions proposal which collected enough approvals
            for isi in instructions {
                isi.execute().dbg_unwrap();
            }
        }
    }
}
