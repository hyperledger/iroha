//! Query fixture writes publish World records without inventing finalized history.

use iroha_crypto::{Algorithm, Hash, KeyPair, Signature};
use iroha_data_model::{
    block::consensus::{
        Evidence, EvidenceAttribution, EvidenceOffender, EvidencePenaltyStatus, EvidenceRecord,
    },
    confidential::ConfidentialStatus,
    governance::types::{
        AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal, ProposalKind,
    },
    proof::{
        ProofId, ProofRecord, ProofStatus, VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord,
    },
    smart_contract::ContractAddress,
    zk::BackendTag,
};
use iroha_model_base::peer::PeerId;
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        GovernanceLockCustody, GovernanceLockRecord, GovernanceLocksForReferendum,
        GovernanceProposalRecord, GovernanceProposalStatus, GovernanceReferendumMode,
        GovernanceReferendumRecord, GovernanceReferendumStatus, State, World,
    },
};

fn state() -> State {
    State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn assert_no_finality(state: &State) {
    let view = state.view();
    assert_eq!(view.height(), 0);
    assert!(view.block_hashes().is_empty());
    assert_eq!(state.transactions.latest_height(), 0);
    assert_eq!(state.transactions.view().latest_height_for_tests(), 0);
}

fn contract_address() -> ContractAddress {
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
        .parse()
        .expect("fixture contract address")
}

fn proof_id(seed: u8) -> ProofId {
    ProofId {
        backend: "halo2/ipa".into(),
        proof_hash: [seed; 32],
    }
}

#[test]
fn verifying_key_fixture_publishes_record_and_circuit_index_without_finality() {
    let mut state = state();
    let id = VerifyingKeyId::new("halo2/ipa", "fixture-key");
    let key = VerifyingKeyBox::new("halo2/ipa".into(), vec![1, 2, 3, 4, 5]);
    let mut record = VerifyingKeyRecord::new(
        1,
        "fixture-circuit",
        BackendTag::NativePipaRPasta,
        "pallas",
        [0x11; 32],
        crate::zk::hash_vk(&key),
    );
    record.vk_len = 5;
    record.key = Some(key);
    record.status = ConfidentialStatus::Active;
    insert_verifying_key_record_for_test(&mut state, id.clone(), record.clone());
    assert_no_finality(&state);
    let view = state.view();
    assert_eq!(view.world().verifying_keys().get(&id), Some(&record));
    assert_eq!(
        view.world()
            .verifying_keys_by_circuit()
            .get(&(record.circuit_id.clone(), record.version)),
        Some(&id),
    );
}

#[test]
fn evidence_fixture_publishes_signed_record_without_finality() {
    let mut state = state();
    let record = EvidenceRecord {
        evidence: phase_vote_evidence(),
        attribution: fixture_attribution(),
        recorded_at_height: 1,
        recorded_at_view: 0,
        recorded_at_ms: 10,
        penalty_status: EvidencePenaltyStatus::Pending,
    };
    let key = crate::sumeragi::evidence::evidence_key(&record.evidence);
    insert_evidence_record_for_test(&mut state, record.clone());
    assert_no_finality(&state);
    let view = state.view();
    assert_eq!(
        view.world()
            .consensus_evidence()
            .get(&key)
            .map(crate::state::RetainedEvidenceRecord::canonical_projection),
        Some(record.clone())
    );
    assert_eq!(evidence_count(&view), 1);
    assert_eq!(evidence_list_snapshot(&view), vec![record]);
}

#[test]
fn contract_fixture_replaces_code_without_finality() {
    let mut state = state();
    let address = contract_address();
    for code_hash in [Hash::new(b"initial code"), Hash::new(b"replacement code")] {
        insert_contract_instance_for_test(&mut state, address.clone(), code_hash);
        assert_no_finality(&state);
        assert_eq!(
            state.view().world().contract_instances().get(&address),
            Some(&code_hash),
        );
    }
}

#[test]
fn proof_fixture_uses_supplied_id_and_updates_status_index_without_finality() {
    let mut state = state();
    let id = proof_id(0x31);
    let other = proof_id(0x32);
    for status in [ProofStatus::Verified, ProofStatus::Rejected] {
        let record = ProofRecord {
            id: other.clone(),
            vk_ref: Some(VerifyingKeyId::new("halo2/ipa", "fixture-key")),
            vk_commitment: Some([0x11; 32]),
            status,
            verified_at_height: Some(1),
            bridge: None,
        };
        insert_proof_record_for_test(&mut state, id.clone(), record.clone());
        assert_no_finality(&state);
        let view = state.view();
        assert_eq!(
            view.world().proofs().get(&id),
            Some(&ProofRecord {
                id: id.clone(),
                ..record
            }),
        );
        assert!(view.world().proofs().get(&other).is_none());
        assert!(
            view.world()
                .proofs_by_status()
                .get(&status)
                .expect("status row")
                .contains(&id)
        );
    }
    let view = state.view();
    assert!(
        !view
            .world()
            .proofs_by_status()
            .get(&ProofStatus::Verified)
            .is_some_and(|ids| ids.contains(&id))
    );
}

#[test]
fn proof_tag_fixture_deduplicates_both_indexes_without_finality() {
    let mut state = state();
    let id = proof_id(0x41);
    for _ in 0..2 {
        insert_proof_tags_for_test(&mut state, id.clone(), vec![*b"ZZZZ", *b"AAAA", *b"ZZZZ"]);
        assert_no_finality(&state);
    }
    let view = state.view();
    assert_eq!(
        view.world().proof_tags().get(&id),
        Some(&vec![*b"AAAA", *b"ZZZZ"])
    );
    for tag in [*b"AAAA", *b"ZZZZ"] {
        assert_eq!(
            view.world().proofs_by_tag().get(&tag),
            Some(&vec![id.clone()])
        );
    }
}

#[test]
fn governance_proposal_fixture_publishes_typed_record_without_finality() {
    let mut state = state();
    let id = [0x51; 32];
    let record = GovernanceProposalRecord {
        proposer: ALICE_ID.clone(),
        kind: ProposalKind::DeployContract(DeployContractProposal {
            proposal_operator: ALICE_ID.clone(),
            contract_address: contract_address(),
            code_hash: ContractCodeHash::from_hex_str(&"11".repeat(32)).expect("code hash"),
            abi_hash: ContractAbiHash::from_hex_str(&"22".repeat(32)).expect("ABI hash"),
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        }),
        created_height: 0,
        status: GovernanceProposalStatus::Proposed,
    };
    insert_gov_proposal_for_test(&mut state, id, record.clone());
    assert_no_finality(&state);
    let view = state.view();
    let stored = view
        .world()
        .governance_proposals()
        .get(&id)
        .expect("proposal");
    assert_eq!(stored.proposer, record.proposer);
    assert_eq!(stored.kind, record.kind);
    assert_eq!(stored.created_height, record.created_height);
    assert_eq!(stored.status, record.status);
}

#[test]
fn governance_referendum_fixture_publishes_schedule_without_finality() {
    let mut state = state();
    let id = "fixture-referendum".to_owned();
    let record = GovernanceReferendumRecord {
        h_start: 0,
        h_end: 100,
        status: GovernanceReferendumStatus::Open,
        mode: GovernanceReferendumMode::Plain,
        plain_context: standalone_plain_test_fixture::context(&state.gov, 0),
        plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
    };
    record
        .validate_context()
        .expect("valid frozen PLAIN context");
    insert_gov_referendum_for_test(&mut state, id.clone(), record.clone());
    assert_no_finality(&state);
    assert_eq!(
        state.view().world().governance_referenda().get(&id),
        Some(&record)
    );
}

#[test]
fn governance_lock_fixture_publishes_original_custody_without_finality() {
    let mut state = state();
    let id = "fixture-locks".to_owned();
    let record = GovernanceLockRecord {
        owner: ALICE_ID.clone(),
        amount: 10_000_u64.into(),
        slashed: 0_u64.into(),
        expiry_height: 1_000,
        direction: 0,
        duration_blocks: state.gov.conviction_step_blocks.max(1),
        custody: GovernanceLockCustody {
            escrowed: !state.gov.min_bond_amount.is_zero(),
            asset_definition_id: state.gov.voting_asset_id.clone(),
            bond_escrow_account: state.gov.bond_escrow_account.clone(),
            slash_receiver_account: state.gov.slash_receiver_account.clone(),
        },
    };
    let mut locks = GovernanceLocksForReferendum::default();
    locks.locks.insert(ALICE_ID.clone(), record.clone());
    insert_gov_locks_for_test(&mut state, id.clone(), locks);
    assert_no_finality(&state);
    let view = state.view();
    let stored = view.world().governance_locks().get(&id).expect("locks");
    assert_eq!(stored.locks.len(), 1);
    let stored = stored.locks.get(&*ALICE_ID).expect("original owner lock");
    assert_eq!(stored.owner, record.owner);
    assert_eq!(stored.amount, record.amount);
    assert_eq!(stored.slashed, record.slashed);
    assert_eq!(stored.expiry_height, record.expiry_height);
    assert_eq!(stored.direction, record.direction);
    assert_eq!(stored.duration_blocks, record.duration_blocks);
    assert_eq!(stored.custody, record.custody);
}

fn phase_vote_evidence() -> Evidence {
    use iroha_sumeragi::{
        message::{Evidence as NativeEvidence, Vote, VoteKind},
        types::{EpochId, Hash32, SIGNATURE_LEN, Signature as NativeSignature},
    };
    let key =
        KeyPair::try_from_seed(vec![0xA1; 32], Algorithm::BlsNormal).expect("fixture BLS key");
    let vote = |subject| {
        let mut vote = Vote {
            kind: VoteKind::Prepare,
            instance: Hash32([1; 32]),
            epoch: EpochId {
                epoch: 0,
                context: Hash32([2; 32]),
            },
            height: 1,
            view: 0,
            block_hash: Hash32([subject; 32]),
            result: Hash32([4; 32]),
            signer: 0,
            sig: NativeSignature([0; SIGNATURE_LEN]),
        };
        vote.sig = NativeSignature(
            Signature::new(key.private_key(), &vote.preimage())
                .payload()
                .try_into()
                .expect("signature width"),
        );
        vote
    };
    Evidence::from_native(&NativeEvidence::VoteEquivocation(vote(0xA1), vote(0xA2)))
        .expect("native signed pair")
}
fn fixture_attribution() -> EvidenceAttribution {
    let key =
        KeyPair::try_from_seed(vec![0xA1; 32], Algorithm::BlsNormal).expect("fixture BLS key");
    EvidenceAttribution {
        scope: iroha_data_model::block::consensus::EvidenceScope::Root,
        instance: [1; 32],
        height: 1,
        epoch: 0,
        context_id: [2; 32],
        authority_generation: [3; 32],
        offenders: vec![EvidenceOffender {
            lane_stake: None,
            signer: 0,
            peer_id: PeerId::new(key.public_key().clone()),
        }],
        safety_violation: false,
    }
}
