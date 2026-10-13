//! Inspect a Norito-framed genesis block for validator and `PoP` registrations.
use eyre::{Result, eyre};
use iroha_data_model::{
    isi::{
        register::RegisterPeerWithPop,
        staking::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
    },
    transaction::Executable,
};
use std::{env, path::Path};
fn main() -> Result<()> {
    iroha_genesis::init_instruction_registry();
    let path = env::args()
        .nth(1)
        .ok_or_else(|| eyre!("usage: genesis_inspect <genesis.nrt>"))?;
    let block = iroha_genesis::read_signed_genesis(Path::new(&path))?;
    let count_matching = |matches: fn(&iroha_data_model::isi::InstructionBox) -> bool| {
        block
            .external_transactions()
            .filter_map(|transaction| match transaction.instructions() {
                Executable::Instructions(batch) => Some(batch),
                _ => None,
            })
            .flat_map(|batch| batch.iter())
            .filter(|instruction| matches(instruction))
            .count()
    };
    let peers = count_matching(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<RegisterPeerWithPop>()
            .is_some()
    });
    let validators = count_matching(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<RegisterPublicLaneValidator>()
            .is_some()
    });
    let activations = count_matching(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<ActivatePublicLaneValidator>()
            .is_some()
    });
    println!("event=genesis_inspect peers_with_pop={peers}");
    for transaction in block.external_transactions() {
        let Executable::Instructions(batch) = transaction.instructions() else {
            continue;
        };
        for instruction in batch {
            if let Some(peer) = instruction.as_any().downcast_ref::<RegisterPeerWithPop>() {
                println!(
                    "peer={} pop_len={} activation_at={:?} expiry_at={:?}",
                    peer.peer,
                    peer.pop.len(),
                    peer.activation_at,
                    peer.expiry_at
                );
            }
        }
    }
    println!("event=genesis_inspect validators={validators}");
    for transaction in block.external_transactions() {
        let Executable::Instructions(batch) = transaction.instructions() else {
            continue;
        };
        for instruction in batch {
            if let Some(registration) = instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
            {
                println!(
                    "validator={} lane={} stake_account={} initial_stake={}",
                    registration.validator(),
                    registration.lane_id(),
                    registration.stake_account(),
                    registration.initial_stake()
                );
            }
        }
    }
    println!("event=genesis_inspect activations={activations}");
    for transaction in block.external_transactions() {
        let Executable::Instructions(batch) = transaction.instructions() else {
            continue;
        };
        for instruction in batch {
            if let Some(activation) = instruction
                .as_any()
                .downcast_ref::<ActivatePublicLaneValidator>()
            {
                println!(
                    "activation lane={} validator={}",
                    activation.lane_id(),
                    activation.validator()
                );
            }
        }
    }
    Ok(())
}
