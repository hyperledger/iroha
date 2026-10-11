//! Production finalization rejects unqualified tally roles without changing the retained election.
//! Tiny arithmetic fixtures are not semantic tally proofs; positive qualification remains open.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]

#[path = "common/governance_closed_registry.rs"]
mod closed_registry;
#[path = "common/governance_closed_state.rs"]
mod closed_state;

use iroha_core::{
    smartcontracts::Execute,
    state::{StandaloneBallotCorpusEntryV1, WorldReadOnly},
};
use iroha_core_zk::native_pipa_r::BACKEND as NATIVE_BACKEND;
use iroha_data_model::{
    block::BlockHeader,
    isi::{error::InstructionExecutionError, zk::FinalizeElection},
    proof::{ProofAttachment, ProofBox},
};
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;

#[test]
fn zk_finalize_rejects_unqualified_tally_keys_without_mutating_state() {
    let state = closed_state::state();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    for circuit_id in ["halo2/pasta/ipa/vote-tally", "halo2/pasta/tiny-add-public"] {
        let mut transaction = block.transaction();
        closed_state::grant_permissions(&mut transaction, "ref-final");
        let (id, record) = closed_registry::unqualified_key(circuit_id);
        let mut retained = closed_registry::retained_election(&id, &record);
        retained
            .accepted_ballots
            .push(StandaloneBallotCorpusEntryV1 {
                nullifier: [0x44; 32],
                commitment: [0x55; 32],
            });
        transaction
            .world
            .verifying_keys_mut_for_testing()
            .insert(id.clone(), record);
        transaction
            .world
            .elections_mut()
            .insert("ref-final".into(), retained);
        let before =
            norito::to_bytes(transaction.world.elections().get("ref-final").unwrap()).unwrap();
        let error = FinalizeElection {
            election_id: "ref-final".to_owned(),
            tally: vec![4, 0],
            tally_proof: ProofAttachment::new_ref(
                NATIVE_BACKEND.to_owned(),
                ProofBox::new(NATIVE_BACKEND.to_owned(), vec![0]),
                id,
            ),
        }
        .execute(&ALICE_ID, &mut transaction)
        .expect_err("an unsupported tally role cannot finalize");
        assert_eq!(
            error,
            InstructionExecutionError::InvariantViolation(
                "tally verifying key circuit mismatch".into()
            )
        );
        let after = transaction
            .world
            .elections()
            .get("ref-final")
            .expect("retained election");
        assert!(!after.finalized);
        assert_eq!(after.tally, vec![0, 0]);
        assert_eq!(
            norito::to_bytes(after).unwrap(),
            before,
            "the ordered ballot corpus must remain intact"
        );
        assert!(transaction.world.take_external_events().is_empty());
    }
}
