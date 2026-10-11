#![doc = "Pre-proof ballot admission and rejection of development-only retained keys."]
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]
//! Pre-proof ballot admission and rejection of development-only retained keys.
#[path = "zk_testkit.rs"]
mod zk_testkit;
use base64::Engine as _;
use core::num::NonZeroU64;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, StateTransaction, World, WorldReadOnly},
};
use iroha_data_model::{
    Registrable,
    account::Account,
    asset::AssetDefinition,
    block::BlockHeader,
    domain::Domain,
    events::data::{DataEvent, governance::GovernanceEvent},
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        governance::CastZkBallot,
    },
    permission::Permission,
    prelude::Grant,
};
use iroha_executor_data_model::permission::governance::{
    CanManageParliament, CanSubmitGovernanceBallot,
};
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::StorageReadOnly;
use std::time::Duration;
fn derive_ballot_nullifier(
    domain_tag: &str,
    network_id: &iroha_data_model::NetworkId,
    election_id: &str,
    commit: &[u8; 32],
) -> [u8; 32] {
    use blake2::{Blake2b512, Digest as _};
    let mut input = Vec::with_capacity(
        domain_tag.len() + network_id.as_bytes().len() + election_id.len() + commit.len() + 24,
    );
    let push_len = |buf: &mut Vec<u8>, len: usize| {
        let len_u64 = len as u64;
        buf.extend_from_slice(&len_u64.to_le_bytes());
    };
    push_len(&mut input, domain_tag.len());
    input.extend_from_slice(domain_tag.as_bytes());
    push_len(&mut input, network_id.as_bytes().len());
    input.extend_from_slice(network_id.as_bytes());
    push_len(&mut input, election_id.len());
    input.extend_from_slice(election_id.as_bytes());
    input.extend_from_slice(commit);
    let digest = Blake2b512::digest(&input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}
fn new_state() -> State {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let alice_id = (*ALICE_ID).clone();
    let bob_id = (*BOB_ID).clone();
    let domain_id: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain");
    let domain = Domain::new(domain_id.clone()).build(&alice_id);
    let alice = Account::new(alice_id.clone()).build(&alice_id);
    let bob = Account::new(bob_id.clone()).build(&bob_id);
    let world = World::with([domain], [alice, bob], Vec::<AssetDefinition>::new());
    let mut state = State::new_for_testing(world, kura, query_handle);
    state.gov.citizenship_bond_amount = 0_u64.into();
    state
        .edit_zk_for_testing(|zk| zk.pipa_r.enabled = true)
        .expect("fixture ZK settings install");
    state
        .edit_zk_for_testing(|zk| zk.verify_timeout = Duration::ZERO)
        .expect("fixture ZK settings install");
    state
}
fn assert_instruction_error_contains(err: &InstructionExecutionError, expected: &str) {
    let msg = match err {
        InstructionExecutionError::InvariantViolation(reason) => reason.as_ref(),
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            reason,
        )) => reason.as_str(),
        _ => "",
    };
    if !msg.is_empty() {
        assert!(
            msg.contains(expected),
            "expected error containing \"{expected}\", got \"{msg}\""
        );
        return;
    }
    let rendered = format!("{err}");
    assert!(
        rendered.contains(expected),
        "expected error containing \"{expected}\", got \"{rendered}\""
    );
}
fn seed_rejected_retained_election(
    stx: &mut StateTransaction<'_, '_>,
    election_id: &str,
) -> zk_testkit::UnqualifiedNativeBallotBundle {
    let bundle = zk_testkit::unqualified_native_ballot_bundle();
    let vk_id = bundle.vk_id.clone();
    let perm = Permission::new("CanManageVerifyingKeys".to_string(), Json::new(()));
    Grant::account_permission(perm, ALICE_ID.clone())
        .execute(&ALICE_ID, stx)
        .expect("grant VK management");
    // Adversarial retained state only: this key cannot be registered in production.
    stx.world
        .verifying_keys_mut_for_testing()
        .insert(vk_id.clone(), bundle.vk_record.clone());
    let parliament_perm: Permission = CanManageParliament.into();
    Grant::account_permission(parliament_perm, ALICE_ID.clone())
        .execute(&ALICE_ID, stx)
        .expect("grant CanManageParliament");
    let ballot_perm: Permission = CanSubmitGovernanceBallot {
        referendum_id: election_id.to_string(),
    }
    .into();
    Grant::account_permission(ballot_perm, ALICE_ID.clone())
        .execute(&ALICE_ID, stx)
        .expect("grant CanSubmitGovernanceBallot");
    stx.world.elections_mut().insert(
        election_id.to_owned(),
        iroha_core::state::ElectionState {
            options: 2,
            tally: vec![0, 0],
            eligible_root: bundle.root_bytes(),
            vk_ballot: Some(vk_id.clone()),
            vk_ballot_commitment: Some(bundle.vk_record.commitment),
            vk_tally: Some(vk_id),
            vk_tally_commitment: Some(bundle.vk_record.commitment),
            domain_tag: "gov:ballot:v1".into(),
            ..Default::default()
        },
    );
    stx.world.governance_referenda_mut().insert(
        election_id.to_string(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 0,
            h_end: 100,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Zk,
            plain_context:
                iroha_data_model::governance::conviction::PlainVotingContextV1::NotApplicable,
            plain_result:
                iroha_data_model::governance::conviction::PlainVotingResultV1::NotApplicable,
        },
    );
    bundle
}
#[test]
fn development_ballot_retries_never_consume_a_nullifier() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    let mut block = state.block(BlockHeader::new(
        NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    ));
    let mut stx = block.transaction();
    let election_id = "referendum-1".to_owned();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let ballot = CastZkBallot {
        election_id: election_id.clone(),
        proof_b64: bundle.proof_b64(),
        public_inputs_json: "{}".into(),
    };
    for _ in 0..2 {
        let error = ballot.clone().execute(&ALICE_ID, &mut stx).unwrap_err();
        assert_instruction_error_contains(&error, "ballot verifying key circuit mismatch");
        assert_no_ballot_mutation(&mut stx, &election_id);
    }
}
fn assert_no_ballot_mutation(stx: &mut StateTransaction<'_, '_>, election_id: &str) {
    let election = stx.world.elections().get(election_id).unwrap();
    assert!(election.accepted_ballots.is_empty());
    assert!(stx.world.governance_locks().get(election_id).is_none());
    assert!(
        !stx.world
            .take_external_events()
            .iter()
            .any(|event| matches!(
                event.as_data_event(),
                Some(DataEvent::Governance(
                    GovernanceEvent::BallotAccepted(_)
                        | GovernanceEvent::LockCreated(_)
                        | GovernanceEvent::LockExtended(_)
                ))
            ))
    );
}
#[test]
fn zk_ballot_rejects_missing_lock_hints_when_bond_required() {
    let state = new_state();
    assert!(
        !state.gov.min_bond_amount.is_zero(),
        "bond must be required by default"
    );
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "referendum-bond-required".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let err = CastZkBallot {
        election_id,
        proof_b64: bundle.proof_b64(),
        public_inputs_json: "{}".to_string(),
    }
    .execute(&ALICE_ID, &mut stx)
    .unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("lock hints required"));
    let events = stx.world.take_external_events();
    assert!(events.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::BallotRejected(rej)))
            if rej.reason.contains("lock hints required")
    )));
}
#[test]
fn direction_hint_does_not_admit_a_development_ballot() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "referendum-direction-only".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let error = CastZkBallot {
        election_id: election_id.clone(),
        proof_b64: bundle.proof_b64(),
        public_inputs_json: r#"{"direction":"Aye"}"#.to_string(),
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("direction hints cannot admit the development relation");
    assert_instruction_error_contains(&error, "ballot verifying key circuit mismatch");
    assert_no_ballot_mutation(&mut stx, &election_id);
}
#[test]
fn commit_nullifier_hint_does_not_admit_a_development_ballot() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "referendum-commit-nullifier".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let commit_bytes = bundle.commit_bytes();
    let expected_nullifier = derive_ballot_nullifier(
        "gov:ballot:v1",
        &state.network_id,
        &election_id,
        &commit_bytes,
    );
    let public_inputs = norito::json::object([
        (
            "nullifier",
            norito::json::to_value(&hex::encode(expected_nullifier)).expect("serialize nullifier"),
        ),
        (
            "root_hint",
            norito::json::to_value(&hex::encode(bundle.root_bytes())).expect("serialize root_hint"),
        ),
    ])
    .expect("serialize public inputs");
    let public_inputs = norito::json::to_json(&public_inputs).expect("serialize public inputs");
    let instr = CastZkBallot {
        election_id: election_id.clone(),
        proof_b64: bundle.proof_b64(),
        public_inputs_json: public_inputs.clone(),
    };
    for _ in 0..2 {
        let error = instr.clone().execute(&ALICE_ID, &mut stx).unwrap_err();
        assert_instruction_error_contains(&error, "ballot verifying key circuit mismatch");
        assert_no_ballot_mutation(&mut stx, &election_id);
    }
}
#[test]
fn corrupted_development_envelope_is_rejected_before_proof_dispatch() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "ref-invalid-proof".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let mut corrupted_proof = bundle.proof_bytes.clone();
    if let Some(last) = corrupted_proof.last_mut() {
        *last ^= 0x01;
    }
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(corrupted_proof);
    let public_inputs = "{}".to_string();
    let err = CastZkBallot {
        election_id: election_id.clone(),
        proof_b64,
        public_inputs_json: public_inputs,
    }
    .execute(&ALICE_ID, &mut stx)
    .unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("ballot verifying key circuit mismatch"));
    let events = stx.world.take_external_events();
    assert!(events.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::BallotRejected(rej)))
            if rej.reason.contains("ballot verifying key circuit mismatch")
    )));
}
#[test]
fn development_ballot_with_wrong_owner_never_records() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "referendum-owner-mismatch".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let amount = stx.gov.min_bond_amount.clone().max(Quantity::one());
    let duration = stx.gov.conviction_step_blocks.max(100u64);
    let public_inputs = format!(
        "{{\"owner\":\"{}\",\"amount\":\"{}\",\"duration_blocks\":{}}}",
        &*BOB_ID, amount, duration
    );
    let err = CastZkBallot {
        election_id: election_id.clone(),
        proof_b64: bundle.proof_b64(),
        public_inputs_json: public_inputs,
    }
    .execute(&ALICE_ID, &mut stx)
    .unwrap_err();
    assert_instruction_error_contains(&err, "ballot verifying key circuit mismatch");
    let st_after = stx
        .world
        .elections()
        .get(&election_id)
        .expect("election exists");
    assert!(st_after.accepted_ballots.is_empty());
    let events = stx.world.take_external_events();
    assert!(events.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::BallotRejected(rej)))
            if rej.reason.contains("ballot verifying key circuit mismatch")
    )));
    assert!(!events.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::BallotAccepted(_)))
    )));
}
#[test]
fn zk_ballot_rejects_malformed_public_inputs() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "ref-public-inputs".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let malformed_public_inputs = "{\"owner\": \"alice#wonderland\"".to_string();
    let err = CastZkBallot {
        election_id,
        proof_b64: bundle.proof_b64(),
        public_inputs_json: malformed_public_inputs,
    }
    .execute(&ALICE_ID, &mut stx)
    .unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("public inputs must be valid JSON"));
    let events = stx.world.take_external_events();
    assert!(events.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::BallotRejected(rej)))
            if rej.reason.contains("public inputs must be valid JSON")
    )));
}
#[test]
fn zk_ballot_rejects_non_object_public_inputs() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "ref-public-inputs-object".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let non_object_public_inputs = "[1,2,3]".to_string();
    let err = CastZkBallot {
        election_id,
        proof_b64: bundle.proof_b64(),
        public_inputs_json: non_object_public_inputs,
    }
    .execute(&ALICE_ID, &mut stx)
    .unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("public inputs must be a JSON object"));
    let events = stx.world.take_external_events();
    assert!(events.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::BallotRejected(rej)))
            if rej.reason.contains("public inputs must be a JSON object")
    )));
}
#[test]
fn zk_ballot_rejects_public_input_aliases() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    state
        .edit_zk_for_testing(|zk| zk.max_verify_calls_per_tx = 0)
        .expect("fixture ZK settings install");
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "ref-public-inputs-alias".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let hex = "aa".repeat(32);
    let cases = [
        (
            format!(r#"{{"rootHintHex":"{hex}"}}"#),
            "public inputs contain unknown field `rootHintHex`",
        ),
        (
            format!(r#"{{"rootHint":"{hex}"}}"#),
            "public inputs contain unknown field `rootHint`",
        ),
        (
            format!(r#"{{"root_hint_hex":"{hex}"}}"#),
            "public inputs contain unknown field `root_hint_hex`",
        ),
        (
            format!(r#"{{"nullifierHex":"{hex}"}}"#),
            "public inputs contain unknown field `nullifierHex`",
        ),
        (
            format!(r#"{{"nullifier_hex":"{hex}"}}"#),
            "public inputs contain unknown field `nullifier_hex`",
        ),
        (
            r#"{"durationBlocks": 10}"#.to_string(),
            "public inputs contain unknown field `durationBlocks`",
        ),
    ];
    for (public_inputs, expected) in cases {
        let err = CastZkBallot {
            election_id: election_id.clone(),
            proof_b64: bundle.proof_b64(),
            public_inputs_json: public_inputs,
        }
        .execute(&ALICE_ID, &mut stx)
        .unwrap_err();
        assert_instruction_error_contains(&err, expected);
    }
}
#[test]
fn null_input_hints_do_not_admit_a_development_ballot() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "ref-public-inputs-null".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let public_inputs = r#"{"root_hint":null,"owner":null,"amount":null,"duration_blocks":null,"direction":null,"nullifier":null}"#.to_string();
    let error = CastZkBallot {
        election_id: election_id.clone(),
        proof_b64: bundle.proof_b64(),
        public_inputs_json: public_inputs,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("null hints cannot admit the development relation");
    assert_instruction_error_contains(&error, "ballot verifying key circuit mismatch");
    assert_no_ballot_mutation(&mut stx, &election_id);
}
#[test]
fn zk_ballot_rejects_owner_non_string() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "ref-owner-hint-type".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let owner_non_string = "{\"owner\": 5}".to_string();
    let err = CastZkBallot {
        election_id,
        proof_b64: bundle.proof_b64(),
        public_inputs_json: owner_non_string,
    }
    .execute(&ALICE_ID, &mut stx)
    .unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("owner must be a canonical I105 account id"));
    let events = stx.world.take_external_events();
    assert!(events.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::BallotRejected(rej)))
            if rej.reason.contains("owner must be a canonical I105 account id")
    )));
}
#[test]
fn zk_ballot_rejects_when_vk_commitment_mismatched() {
    let mut state = new_state();
    state.gov.min_bond_amount = 0_u64.into();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let election_id = "ref-vk-commitment".to_string();
    let bundle = seed_rejected_retained_election(&mut stx, &election_id);
    let vk_id = bundle.vk_id.clone();
    // Corrupt the stored commitment while keeping the verifying key bytes intact.
    let mut corrupted = stx
        .world
        .verifying_keys_mut_for_testing()
        .get(&vk_id)
        .cloned()
        .expect("vk present");
    corrupted.commitment[0] ^= 0x01;
    stx.world
        .verifying_keys_mut_for_testing()
        .insert(vk_id.clone(), corrupted);
    let public_inputs = "{}".to_string();
    let err = CastZkBallot {
        election_id,
        proof_b64: bundle.proof_b64(),
        public_inputs_json: public_inputs,
    }
    .execute(&ALICE_ID, &mut stx)
    .unwrap_err();
    assert_instruction_error_contains(&err, "verifying key commitment mismatch");
}
