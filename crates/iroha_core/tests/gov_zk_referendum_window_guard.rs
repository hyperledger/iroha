//! Authorized ZK ballots require an open referendum within its voting window.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{
        ElectionState, GovernanceReferendumMode, GovernanceReferendumRecord,
        GovernanceReferendumStatus, State, World, WorldReadOnly,
    },
};
use iroha_data_model::{
    Registrable,
    block::BlockHeader,
    isi::{error::InstructionExecutionError, governance::CastZkBallot},
    permission::Permission,
    prelude::{Account, Domain, Grant},
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;

#[test]
fn zk_ballot_rejected_when_referendum_absent_or_out_of_window() {
    use GovernanceReferendumStatus::{Closed, Open, Proposed};

    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id).build(&ALICE_ID);
    let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let state = State::new_for_testing(
        World::with([domain], [account], []),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    for (id, height, status, expected) in [
        ("missing", 5_u64, None, "referendum not found"),
        (
            "closed",
            5,
            Some(Closed),
            "referendum has not passed the Parliament gate",
        ),
        (
            "proposed",
            5,
            Some(Proposed),
            "referendum has not passed the Parliament gate",
        ),
        ("early", 4, Some(Open), "referendum not active"),
        ("late", 7, Some(Open), "referendum not active"),
    ] {
        let header = BlockHeader::new(height.try_into().unwrap(), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        // Authorization is exact even when the referenced referendum is absent.
        let permission: Permission = CanSubmitGovernanceBallot {
            referendum_id: id.to_owned(),
        }
        .into();
        Grant::account_permission(permission, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut tx)
            .expect("grant exact ballot permission");
        tx.world.elections_mut().insert(
            id.to_owned(),
            ElectionState {
                options: 2,
                tally: vec![0, 0],
                domain_tag: "gov:ballot:v1".to_owned(),
                ..Default::default()
            },
        );
        let referendum = status.map(|status| GovernanceReferendumRecord {
            h_start: 5,
            h_end: 6,
            status,
            mode: GovernanceReferendumMode::Zk,
            plain_context:
                iroha_data_model::governance::conviction::PlainVotingContextV1::NotApplicable,
            plain_result:
                iroha_data_model::governance::conviction::PlainVotingResultV1::NotApplicable,
        });
        if let Some(record) = &referendum {
            tx.world
                .governance_referenda_mut()
                .insert(id.to_owned(), record.clone());
        }
        let error = CastZkBallot {
            election_id: id.to_owned(),
            proof_b64: "AA==".to_owned(),
            public_inputs_json: "{}".to_owned(),
        }
        .execute(&ALICE_ID, &mut tx)
        .expect_err("referendum guard must reject before proof verification");
        assert_eq!(
            error,
            InstructionExecutionError::InvariantViolation(expected.into()),
            "case {id} at height {height}",
        );
        assert_eq!(
            tx.world.governance_referenda().get(&id.to_owned()).cloned(),
            referendum,
            "rejected ballot must not change referendum status",
        );
        let election = tx.world.elections().get(&id.to_owned()).unwrap();
        assert!(election.accepted_ballots.is_empty());
        assert_eq!(election.tally, [0, 0]);
    }
}
