//! Trigger to control multisignature account

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{collections::btree_set::BTreeSet, format, vec::Vec};

use dlmalloc::GlobalDlmalloc;
use executor_custom_data_model::multisig::MultisigArgs;
use iroha_trigger::{debug::dbg_panic, prelude::*, smart_contract::query_single};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

#[iroha_trigger::main]
fn main(id: TriggerId, _owner: AccountId, event: EventBox) {
    let (args, signatory): (MultisigArgs, AccountId) = match event {
        EventBox::ExecuteTrigger(event) => (
            event
                .args()
                .dbg_expect("trigger expect args")
                .try_into_any()
                .dbg_expect("failed to parse arguments"),
            event.authority().clone(),
        ),
        _ => dbg_panic("only work as by call trigger"),
    };

    let instructions_hash = match &args {
        MultisigArgs::Instructions(instructions) => HashOf::new(instructions),
        MultisigArgs::Vote(instructions_hash) => *instructions_hash,
    };
    let votes_metadata_key: Name = format!("{instructions_hash}/votes").parse().unwrap();
    let instructions_metadata_key: Name =
        format!("{instructions_hash}/instructions").parse().unwrap();

    let (votes, instructions) = match args {
        MultisigArgs::Instructions(instructions) => {
            query_single(FindTriggerMetadata::new(
                id.clone(),
                votes_metadata_key.clone(),
            ))
            .expect_err("instructions are already submitted");

            let votes = BTreeSet::from([signatory.clone()]);

            SetKeyValue::trigger(
                id.clone(),
                instructions_metadata_key.clone(),
                JsonString::new(&instructions),
            )
            .execute()
            .dbg_unwrap();

            SetKeyValue::trigger(
                id.clone(),
                votes_metadata_key.clone(),
                JsonString::new(&votes),
            )
            .execute()
            .dbg_unwrap();

            (votes, instructions)
        }
        MultisigArgs::Vote(_instructions_hash) => {
            let mut votes: BTreeSet<AccountId> = query_single(FindTriggerMetadata::new(
                id.clone(),
                votes_metadata_key.clone(),
            ))
            .dbg_expect("instructions should be submitted first")
            .try_into_any()
            .dbg_unwrap();

            votes.insert(signatory.clone());

            SetKeyValue::trigger(
                id.clone(),
                votes_metadata_key.clone(),
                JsonString::new(&votes),
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

            (votes, instructions)
        }
    };

    let signatories: BTreeSet<AccountId> = query_single(FindTriggerMetadata::new(
        id.clone(),
        "signatories".parse().unwrap(),
    ))
    .dbg_unwrap()
    .try_into_any()
    .dbg_unwrap();

    // Require N of N signatures
    if votes.is_superset(&signatories) {
        // Cleanup votes and instructions
        RemoveKeyValue::trigger(id.clone(), votes_metadata_key)
            .execute()
            .dbg_unwrap();
        RemoveKeyValue::trigger(id.clone(), instructions_metadata_key)
            .execute()
            .dbg_unwrap();

        // Execute instructions proposal which collected enough votes
        for isi in instructions {
            isi.execute().dbg_unwrap();
        }
    }
}
