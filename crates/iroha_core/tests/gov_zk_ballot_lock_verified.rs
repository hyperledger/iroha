//! Unqualified ballot proofs cannot create or change locks, consume nullifiers, or emit acceptance.
//! This retained-state rejection test does not establish the missing real-proof lock lifecycle.

#![cfg(feature = "zk-tests")]

#[path = "common/governance_closed_registry.rs"]
mod closed_registry;
#[path = "common/governance_closed_state.rs"]
mod closed_state;

use iroha_core::{
    smartcontracts::Execute,
    state::{
        GovernanceLockCustody, GovernanceLockRecord, GovernanceLocksForReferendum,
        GovernanceReferendumMode, GovernanceReferendumRecord, GovernanceReferendumStatus,
        StandaloneBallotCorpusEntryV1, WorldReadOnly,
    },
};
use iroha_data_model::{
    block::BlockHeader,
    events::data::{DataEvent, governance::GovernanceEvent},
    isi::{error::InstructionExecutionError, governance::CastZkBallot},
};
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use std::collections::BTreeMap;

#[test]
fn unqualified_ballots_cannot_create_extend_or_shrink_retained_locks() {
    let state = closed_state::state();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    for circuit_id in [
        "halo2/pasta/ipa/vote-ballot",
        "halo2/pasta/ipa/vote-bool-commit-merkle8",
    ] {
        // Preserve the original create/extend/shrink amounts and durations as adversarial inputs.
        for (previous, amount, duration) in [
            (None, 1000_u64, 200_u64),
            (Some((1000_u64, 200_u64)), 1200, 400),
            (Some((1200_u64, 400_u64)), 900, 250),
        ] {
            let mut transaction = block.transaction();
            closed_state::grant_permissions(&mut transaction, "ref-zk-lock");
            let (id, record) = closed_registry::unqualified_key(circuit_id);
            let mut election = closed_registry::retained_election(&id, &record);
            if previous.is_some() {
                election
                    .accepted_ballots
                    .push(StandaloneBallotCorpusEntryV1 {
                        nullifier: [0x44; 32],
                        commitment: [0x55; 32],
                    });
            }
            transaction
                .world
                .verifying_keys_mut_for_testing()
                .insert(id, record);
            transaction
                .world
                .elections_mut()
                .insert("ref-zk-lock".into(), election);
            let referendum = GovernanceReferendumRecord {
                h_start: 0,
                h_end: 100,
                status: GovernanceReferendumStatus::Open,
                mode: GovernanceReferendumMode::Zk,
                plain_context:
                    iroha_data_model::governance::conviction::PlainVotingContextV1::NotApplicable,
                plain_result:
                    iroha_data_model::governance::conviction::PlainVotingResultV1::NotApplicable,
            };
            transaction
                .world
                .governance_referenda_mut()
                .insert("ref-zk-lock".into(), referendum.clone());
            if let Some((previous_amount, previous_duration)) = previous {
                let lock = GovernanceLockRecord {
                    owner: ALICE_ID.clone(),
                    amount: previous_amount.into(),
                    slashed: 0_u64.into(),
                    expiry_height: 1 + previous_duration,
                    direction: 2,
                    duration_blocks: previous_duration,
                    custody: GovernanceLockCustody {
                        escrowed: false,
                        asset_definition_id: transaction.gov.voting_asset_id.clone(),
                        bond_escrow_account: transaction.gov.bond_escrow_account.clone(),
                        slash_receiver_account: transaction.gov.slash_receiver_account.clone(),
                    },
                };
                transaction.world.governance_locks_mut().insert(
                    "ref-zk-lock".into(),
                    GovernanceLocksForReferendum {
                        locks: BTreeMap::from([(ALICE_ID.clone(), lock)]),
                    },
                );
            }
            let before_election =
                norito::to_bytes(transaction.world.elections().get("ref-zk-lock").unwrap())
                    .unwrap();
            let before_locks = norito::to_bytes(
                &transaction
                    .world
                    .governance_locks()
                    .get("ref-zk-lock")
                    .cloned(),
            )
            .unwrap();
            transaction.world.take_external_events();
            let error = CastZkBallot {
                election_id: "ref-zk-lock".to_owned(),
                // Opaque rejected input, never represented as a valid ballot proof.
                proof_b64: "AA==".to_owned(),
                public_inputs_json: format!(
                    r#"{{"owner":"{}","amount":"{amount}","duration_blocks":{duration}}}"#,
                    &*ALICE_ID
                ),
            }
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("unsupported semantic role must fail before lock mutation");
            assert_eq!(
                error,
                InstructionExecutionError::InvariantViolation(
                    "ballot verifying key circuit mismatch".into()
                )
            );
            assert_eq!(
                norito::to_bytes(transaction.world.elections().get("ref-zk-lock").unwrap())
                    .unwrap(),
                before_election,
                "never consume or erase a retained ballot pair on rejection"
            );
            assert_eq!(
                norito::to_bytes(
                    &transaction
                        .world
                        .governance_locks()
                        .get("ref-zk-lock")
                        .cloned()
                )
                .unwrap(),
                before_locks
            );
            assert_eq!(
                transaction.world.governance_referenda().get("ref-zk-lock"),
                Some(&referendum)
            );
            let after = transaction.world.elections().get("ref-zk-lock").unwrap();
            assert_eq!(
                after.accepted_ballots.len(),
                usize::from(previous.is_some())
            );
            let events = transaction.world.take_external_events();
            assert_eq!(events.len(), 1);
            assert!(
                matches!(events[0].as_data_event(), Some(DataEvent::Governance(GovernanceEvent::BallotRejected(rejection)))
                if rejection.referendum_id == "ref-zk-lock" && rejection.reason == "ballot verifying key circuit mismatch")
            );
            assert!(!events.iter().any(|event| matches!(
                event.as_data_event(),
                Some(DataEvent::Governance(
                    GovernanceEvent::LockCreated(_)
                        | GovernanceEvent::LockExtended(_)
                        | GovernanceEvent::BallotAccepted(_)
                ))
            )));
        }
    }
}
