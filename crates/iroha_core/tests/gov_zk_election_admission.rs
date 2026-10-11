//! Governance election bounds, rollback, and the closed production proof registry.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{ElectionState, StandaloneBallotCorpusEntryV1, State, World, WorldReadOnly},
};
use iroha_core_zk::{hash_vk, native_pipa_r::BACKEND as NATIVE_BACKEND};
use iroha_data_model::{
    Registrable,
    account::Account,
    block::BlockHeader,
    confidential::ConfidentialStatus,
    domain::Domain,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        verifying_keys::RegisterVerifyingKey,
        zk::{CreateElection, FinalizeElection, MAX_ELECTION_OPTIONS_V1, MIN_ELECTION_OPTIONS_V1},
    },
    permission::Permission,
    prelude::Grant,
    proof::{ProofAttachment, ProofBox, VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};
use iroha_executor_data_model::permission::governance::{CanEnactGovernance, CanManageParliament};
use iroha_model_base::domain::DomainId;
use iroha_primitives::json::Json;
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;

fn election_state() -> State {
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain");
    let domain = Domain::new(domain_id).build(&ALICE_ID);
    let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    State::new_for_testing(
        World::with([domain], [account], []),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn election_request(options: u32) -> CreateElection {
    CreateElection {
        election_id: "ref-bounded".to_owned(),
        options,
        eligible_root: [0; 32],
        start_ts: 0,
        end_ts: 0,
        vk_ballot: VerifyingKeyId::new(NATIVE_BACKEND, "ballot"),
        vk_tally: VerifyingKeyId::new(NATIVE_BACKEND, "tally"),
        domain_tag: "gov:ballot:v1".to_owned(),
    }
}

#[test]
fn retained_election_tally_roundtrips_exact_u128_weight() {
    let large_weight = u128::from(u64::MAX) + 1;
    let first = StandaloneBallotCorpusEntryV1 {
        nullifier: [0x11; 32],
        commitment: [0x21; 32],
    };
    let second = StandaloneBallotCorpusEntryV1 {
        nullifier: [0x12; 32],
        commitment: [0x22; 32],
    };
    let original = ElectionState {
        options: 2,
        tally: vec![large_weight, 1],
        accepted_ballots: vec![first, second],
        ..ElectionState::default()
    };
    let encoded = norito::encode_canonical(&original).expect("encode retained election");
    let decoded: ElectionState =
        norito::decode_canonical(&encoded).expect("decode exact retained election");
    assert_eq!(decoded.options, original.options);
    assert_eq!(decoded.tally, original.tally);
    assert_eq!(decoded.accepted_ballots, [first, second]);
    assert_eq!(norito::encode_canonical(&decoded).unwrap(), encoded);
    let mut reordered = decoded;
    reordered.accepted_ballots.reverse();
    assert_ne!(
        norito::encode_canonical(&reordered).unwrap(),
        encoded,
        "the canonical state must bind admission order"
    );
}

#[test]
fn election_option_bounds_and_failed_key_lookup_preserve_state() {
    let state = election_state();
    let mut block = state.block(BlockHeader::new(nonzero!(10_u64), None, None, 0, 0));
    for options in [
        0,
        1,
        MIN_ELECTION_OPTIONS_V1,
        MAX_ELECTION_OPTIONS_V1 + 1,
        MAX_ELECTION_OPTIONS_V1,
    ] {
        let mut transaction = block.transaction();
        let permission: Permission = CanManageParliament.into();
        Grant::account_permission(permission, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut transaction)
            .expect("grant parliament permission");
        let error = election_request(options)
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("no election may be created without qualified verifying keys");
        if options == MIN_ELECTION_OPTIONS_V1 || options == MAX_ELECTION_OPTIONS_V1 {
            assert!(
                error.to_string().contains("ballot verifying key not found"),
                "valid option counts must pass the bounds gate: {error}"
            );
        } else {
            assert!(
                matches!(
                    error,
                    InstructionExecutionError::InvalidParameter(
                        InvalidParameterError::SmartContract(_)
                    )
                ),
                "out-of-range options must be an invalid parameter: {error}"
            );
            assert!(
                transaction
                    .world
                    .governance_referenda()
                    .get("ref-bounded")
                    .is_none()
            );
            assert!(transaction.world.elections().get("ref-bounded").is_none());
        }
        // Instruction execution belongs to the transaction overlay. A rejected
        // instruction must never commit its provisional referendum or election.
        drop(transaction);
        assert_eq!(block.world.governance_referenda().iter().count(), 0);
        assert_eq!(block.world.elections().iter().count(), 0);
    }
}

#[test]
fn unqualified_vote_circuits_cannot_enter_the_production_registry() {
    let state = election_state();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut transaction = block.transaction();
    let permission = Permission::new("CanManageVerifyingKeys".to_owned(), Json::new(()));
    Grant::account_permission(permission, ALICE_ID.clone())
        .execute(&ALICE_ID, &mut transaction)
        .expect("grant verifying-key permission");

    // Governance ballot and tally circuits remain unqualified. The retired
    // vote-bool fixture is not a substitute for either semantic relation.
    for circuit_id in [
        "halo2/pasta/ipa/vote-ballot",
        "halo2/pasta/ipa/vote-tally",
        "halo2/pasta/ipa/vote-bool-commit-merkle8",
    ] {
        let id = VerifyingKeyId::new(NATIVE_BACKEND, "unqualified");
        let key = VerifyingKeyBox::new(NATIVE_BACKEND.into(), vec![1, 2, 3, 4]);
        let mut record = VerifyingKeyRecord::new(
            1,
            circuit_id,
            BackendTag::NativePipaRPasta,
            "vesta",
            [0x11; 32],
            hash_vk(&key),
        );
        record.status = ConfidentialStatus::Active;
        record.vk_len = u32::try_from(key.bytes.len()).expect("key length");
        record.key = Some(key);
        record.max_proof_bytes = 1024;
        record.gas_schedule_id = Some("native_pipa_r_default".to_owned());
        let error = RegisterVerifyingKey {
            id: id.clone(),
            record,
        }
        .execute(&ALICE_ID, &mut transaction)
        .expect_err("unqualified governance circuits must be rejected");
        // Assert the typed cause: the outer Display only describes the error category.
        assert_eq!(
            error,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                "native PIPA-R circuit_id is not in the compiled circuit registry".to_owned(),
            )),
            "unexpected rejection for {circuit_id}"
        );
        assert!(transaction.world.verifying_keys().get(&id).is_none());
    }
    transaction.apply();
    assert_eq!(block.world.verifying_keys().iter().count(), 0);
    assert_eq!(block.world.elections().iter().count(), 0);
    assert_eq!(block.world.governance_referenda().iter().count(), 0);
}

#[test]
fn finalize_rejects_invalid_stored_and_submitted_tally_shapes() {
    let state = election_state();
    let mut block = state.block(BlockHeader::new(nonzero!(10_u64), None, None, 0, 0));
    let mut transaction = block.transaction();
    let permission: Permission = CanEnactGovernance.into();
    Grant::account_permission(permission, ALICE_ID.clone())
        .execute(&ALICE_ID, &mut transaction)
        .expect("grant enact permission");
    let vk_id = VerifyingKeyId::new(NATIVE_BACKEND, "tally");
    for (stored_len, submitted_len, expected_error) in [
        (0, 64, "invalid stored election shape"),
        (65, 64, "invalid stored election shape"),
        (64, 63, "tally length does not match options"),
        (64, 64, "verifying key for tally not found"),
    ] {
        // Seed the state shape under test directly; this is not evidence that
        // an unqualified governance proof can create or finalize an election.
        transaction.world.elections_mut().insert(
            "ref-bounded".to_owned(),
            ElectionState {
                options: MAX_ELECTION_OPTIONS_V1,
                tally: vec![7; stored_len],
                vk_tally: Some(vk_id.clone()),
                ..ElectionState::default()
            },
        );
        let error = FinalizeElection {
            election_id: "ref-bounded".to_owned(),
            tally: vec![0; submitted_len],
            tally_proof: ProofAttachment::new_ref(
                NATIVE_BACKEND.into(),
                ProofBox::new(NATIVE_BACKEND.into(), Vec::new()),
                vk_id.clone(),
            ),
        }
        .execute(&ALICE_ID, &mut transaction)
        .expect_err("malformed or unproved tally must not finalize");
        assert!(
            error.to_string().contains(expected_error),
            "stored={stored_len}, submitted={submitted_len}: {error}"
        );
        let election = transaction
            .world
            .elections()
            .get("ref-bounded")
            .expect("retained election");
        assert!(!election.finalized);
        assert_eq!(election.tally, vec![7; stored_len]);
    }
}
