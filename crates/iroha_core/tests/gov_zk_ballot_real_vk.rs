//! Production election key admission rejects unsupported semantic and retired fixture roles.
//! The remaining real-ballot positive is specified in `governance_privacy_qualification.md`.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]

#[path = "common/governance_closed_registry.rs"]
mod closed_registry;
#[path = "common/governance_closed_state.rs"]
mod closed_state;

use iroha_core::{smartcontracts::Execute, state::WorldReadOnly};
use iroha_data_model::{
    block::BlockHeader,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        verifying_keys::RegisterVerifyingKey,
        zk::CreateElection,
    },
};
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;

#[test]
fn zk_ballot_unqualified_keys_cannot_register_or_create_an_election() {
    let state = closed_state::state();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    for circuit_id in [
        "halo2/pasta/ipa/vote-ballot",
        "halo2/pasta/ipa/vote-tally",
        "halo2/pasta/ipa/vote-bool-commit-merkle8",
    ] {
        let mut transaction = block.transaction();
        closed_state::grant_permissions(&mut transaction, "ref-vk");
        let (id, record) = closed_registry::unqualified_key(circuit_id);
        let error = RegisterVerifyingKey {
            id: id.clone(),
            record: record.clone(),
        }
        .execute(&ALICE_ID, &mut transaction)
        .expect_err("the production registry has no semantic ballot/tally entry");
        assert_eq!(
            error,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                "native PIPA-R circuit_id is not in the compiled circuit registry".to_owned(),
            ),)
        );
        assert!(transaction.world.verifying_keys().get(&id).is_none());
        assert!(transaction.world.take_external_events().is_empty());

        let retained = closed_registry::retained_election(&id, &record);
        let request = CreateElection {
            election_id: "ref-vk".to_owned(),
            options: 2,
            eligible_root: retained.eligible_root,
            start_ts: 0,
            end_ts: 0,
            vk_ballot: id.clone(),
            vk_tally: id.clone(),
            domain_tag: retained.domain_tag,
        };
        assert_eq!(
            request.clone().execute(&ALICE_ID, &mut transaction),
            Err(InstructionExecutionError::InvariantViolation(
                "ballot verifying key not found".into()
            ),)
        );
        assert!(transaction.world.elections().get("ref-vk").is_none());

        // A corrupt restored registry must not bypass the same production role check.
        transaction
            .world
            .verifying_keys_mut_for_testing()
            .insert(id, record);
        assert_eq!(
            request.execute(&ALICE_ID, &mut transaction),
            Err(InstructionExecutionError::InvariantViolation(
                "ballot verifying key circuit mismatch".into()
            ),)
        );
        assert!(transaction.world.elections().get("ref-vk").is_none());
        assert!(transaction.world.governance_locks().get("ref-vk").is_none());
        assert!(transaction.world.take_external_events().is_empty());
        // CreateElection may provisionally seed the referendum before checking the key.
        // A rejected transaction drops that overlay together with the corrupt fixture row.
        drop(transaction);
        assert_eq!(block.world.verifying_keys().iter().count(), 0);
        assert_eq!(block.world.elections().iter().count(), 0);
        assert_eq!(block.world.governance_referenda().iter().count(), 0);
        assert_eq!(block.world.governance_locks().iter().count(), 0);
    }
}
