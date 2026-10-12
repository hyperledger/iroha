//! Real original-pool graph, lifecycle and canonical projection tests.

use super::*;
use iroha_crypto::{Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::{MultisigMember, MultisigPolicy},
    block::BlockHeader,
    nexus::PublicLaneValidatorStatus,
    parameter::system::ConsensusMode,
    sccp::committee::SccpGenerationCauseV1,
    sumeragi::epoch::{
        ValidatorCommitteeMemberV1, ValidatorEpochAuthorizationV1, ValidatorGenerationV1,
    },
};
use iroha_model_base::{metadata::Metadata, peer::PeerId};
use iroha_primitives::numeric::Quantity;

fn epoch() -> ValidatorEpochContextV1 {
    let mut keys = (1..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let committee = keys
        .iter()
        .map(|key| ValidatorCommitteeMemberV1 {
            validator: PeerId::new(key.public_key().clone()),
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
        })
        .collect::<Vec<_>>();
    let network_id = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"sccp owner component"),
    ));
    let generation = ValidatorGenerationV1::from_committee(network_id, 0, &committee);
    ValidatorEpochContextV1 {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        version: 1,
        network_id,
        mode: ConsensusMode::Npos,
        authorization: ValidatorEpochAuthorizationV1::genesis(&generation, 10).unwrap(),
        committee,
        leader_seed: [0x31; 32],
    }
}

fn start() -> SccpGenerationStartV1 {
    SccpGenerationStartV1 {
        generation: 1,
        cause: SccpGenerationCauseV1::Genesis,
        height: 1,
        timestamp_ms: 1_000,
        liability_clock: 1_000,
    }
}

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn claim() -> SccpCommitteeGenerationV1 {
    let multisig = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(account(2).try_signatory().unwrap().clone(), 1).unwrap(),
                MultisigMember::new(account(3).try_signatory().unwrap().clone(), 1).unwrap(),
            ],
        )
        .unwrap(),
    );
    SccpCommitteeGenerationV1::from_epoch(
        start(),
        &SccpParametersV1::taira_default(),
        &epoch(),
        vec![
            Some(SccpGenerationMemberV1 {
                lane_id: LaneId::SINGLE,
                validator: account(1),
                activation_height: 0,
            }),
            Some(SccpGenerationMemberV1 {
                lane_id: LaneId::SINGLE,
                validator: multisig,
                activation_height: 1,
            }),
            None,
            None,
        ],
    )
    .unwrap()
}

fn end(source: &SccpCommitteeGenerationV1) -> SccpGenerationEndV1 {
    SccpGenerationEndV1 {
        end_height: 10,
        end_timestamp_ms: 2_000,
        next_committee_root: source.committee_root,
        successor_validity_ms: source.validity_ms,
    }
}

#[test]
fn complete_graph_and_shared_shell_obey_exact_original_pool_boundaries() {
    let source = claim();
    let probe = AllocationBudget::new(1 << 20);
    let owner = RetainedSccpCommitteeGeneration::admit_claim(&source, &probe).unwrap();
    let bytes = owner.allocation_bytes().unwrap();
    assert_eq!(bytes, probe.reserved_bytes());
    assert_eq!(owner.record(), &source);
    assert_ne!(owner.keys.as_ptr(), source.keys.as_ptr());
    assert_ne!(owner.members.as_ptr(), source.members.as_ptr());
    let clone = owner.clone();
    assert!(std::ptr::eq(owner.record(), clone.record()));
    assert_eq!(probe.reserved_bytes(), bytes);
    assert!(clone.belongs_to(&probe.clone()));
    assert!(!clone.belongs_to(&AllocationBudget::new(probe.limit_bytes())));
    drop(owner);
    assert_eq!(probe.reserved_bytes(), bytes);
    assert_eq!(clone.record(), &source);
    drop(clone);
    assert_eq!(probe.reserved_bytes(), 0);
    for limit in [0, bytes - 1] {
        let pool = AllocationBudget::new(limit);
        assert!(matches!(
            RetainedSccpCommitteeGeneration::admit_claim(&source, &pool),
            Err(CommitteeOwnerError::Admission(_))
        ));
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let exact = AllocationBudget::new(bytes);
    let owner = RetainedSccpCommitteeGeneration::admit_claim(&source, &exact).unwrap();
    assert_eq!(exact.reserved_bytes(), bytes);
    drop(owner);
    assert_eq!(exact.reserved_bytes(), 0);
}

#[test]
fn lifecycle_admission_preserves_current_and_undo_on_refusal_and_success() {
    let source = claim();
    let pool = AllocationBudget::new(1 << 20);
    let current = RetainedSccpCommitteeGeneration::admit_claim(&source, &pool).unwrap();
    let undo = current.clone();
    let bytes = pool.reserved_bytes();
    pool.set_limit_bytes(bytes);
    let repeated = current.with_lifecycle(None, None, &pool).unwrap();
    assert!(std::ptr::eq(current.record(), repeated.record()));
    assert!(matches!(
        current.with_lifecycle(Some(end(&source)), None, &pool),
        Err(CommitteeOwnerError::Admission(_))
    ));
    assert_eq!(current.record(), &source);
    assert_eq!(undo.record(), &source);
    assert_eq!(pool.reserved_bytes(), bytes);
    pool.set_limit_bytes(bytes * 2);
    let ended = current
        .with_lifecycle(Some(end(&source)), None, &pool)
        .unwrap();
    assert_eq!(pool.reserved_bytes(), bytes * 2);
    assert_eq!(ended.keys, source.keys);
    assert_eq!(ended.members, source.members);
    assert_eq!(ended.deadline_ms, source.deadline_ms);
    assert!(ended.with_lifecycle(None, None, &pool).is_err());
    let mut changed = end(&source);
    changed.end_height += 1;
    assert!(ended.with_lifecycle(Some(changed), None, &pool).is_err());
    assert!(matches!(
        current.with_lifecycle(None, None, &AllocationBudget::new(bytes)),
        Err(CommitteeOwnerError::Invariant("foreign lifecycle pool"))
    ));
    drop((current, repeated, undo));
    assert_eq!(pool.reserved_bytes(), bytes);
    pool.set_limit_bytes(bytes * 2);
    let cleared = ended
        .with_lifecycle(ended.end, Some(ended.start_lc), &pool)
        .unwrap();
    assert!(cleared.with_lifecycle(cleared.end, None, &pool).is_err());
    assert!(
        cleared
            .with_lifecycle(cleared.end, Some(cleared.start_lc + 1), &pool)
            .is_err()
    );
    drop((ended, cleared));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn retained_projection_matches_dto_and_invalid_claim_refunds_every_charge() {
    let source = claim();
    let pool = AllocationBudget::new(1 << 20);
    let owner = RetainedSccpCommitteeGeneration::admit_claim(&source, &pool).unwrap();
    let canonical = norito::encode_canonical(&source).unwrap();
    assert_eq!(norito::encode_canonical(&owner).unwrap(), canonical);
    assert_eq!(
        norito::canonical_frame_len(&owner).unwrap(),
        canonical.len()
    );
    assert_eq!(
        norito::json::to_json(&owner).unwrap(),
        norito::json::to_json(&source).unwrap()
    );
    let decoded: SccpCommitteeGenerationV1 = norito::decode_canonical(&canonical).unwrap();
    assert_eq!(decoded, *owner.record());
    let bytes = pool.reserved_bytes();
    let mut bad = source.clone();
    bad.committee_root[0] ^= 1;
    assert!(matches!(
        RetainedSccpCommitteeGeneration::admit_claim(&bad, &pool),
        Err(CommitteeOwnerError::Invalid(_))
    ));
    assert_eq!(pool.reserved_bytes(), bytes);
    assert!(matches!(
        owner.with_lifecycle(None, Some(source.start_lc), &pool),
        Err(CommitteeOwnerError::Invalid(_))
    ));
    assert_eq!(
        pool.reserved_bytes(),
        bytes,
        "failure after copying the complete graph refunds it"
    );
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn account_decode_resource_refusal_preserves_error_and_releases_prepaid_graph() {
    let source = claim();
    let pool = AllocationBudget::new(1 << 20);
    let refused = norito::core::with_decode_limits_scope(
        norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || RetainedSccpCommitteeGeneration::admit_claim(&source, &pool),
    );
    let Err(CommitteeOwnerError::DecodeResource(error)) = refused else {
        panic!("the nested account clone must preserve its original decode resource error");
    };
    assert!(error.is_decode_resource_limit());
    assert_eq!(pool.reserved_bytes(), 0);
    let retried = RetainedSccpCommitteeGeneration::admit_claim(&source, &pool).unwrap();
    assert_eq!(retried.record(), &source);
    assert_eq!(pool.reserved_bytes(), retried.allocation_bytes().unwrap());
    drop(retried);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn creation_moves_funded_seats_without_accepting_reordered_peer_bindings() {
    let epoch = epoch();
    let validator = account(8);
    let mut record = PublicLaneValidatorRecord {
        lane_id: LaneId::SINGLE,
        validator: validator.clone(),
        peer_id: epoch.committee[0].validator.clone(),
        stake_account: validator,
        total_stake: Quantity::from(10_u32),
        self_stake: Quantity::from(10_u32),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::Active,
        activation_height: 0,
        election_exit_height: None,
        deactivation_height: None,
    };
    let pool = AllocationBudget::new(1 << 20);
    let owner = RetainedSccpCommitteeGeneration::admit_new(
        start(),
        &SccpParametersV1::taira_default(),
        &epoch,
        &[Some(&record), None, None, None],
        &pool,
    )
    .unwrap();
    assert_eq!(
        owner.members[0].as_ref().unwrap().validator,
        record.validator
    );
    assert_eq!(
        owner.keys[0].as_slice(),
        record.peer_id.public_key().to_bytes().1
    );
    let bytes = pool.reserved_bytes();
    record.peer_id = epoch.committee[1].validator.clone();
    assert!(matches!(
        RetainedSccpCommitteeGeneration::admit_new(
            start(),
            &SccpParametersV1::taira_default(),
            &epoch,
            &[Some(&record), None, None, None],
            &pool
        ),
        Err(CommitteeOwnerError::Invalid(SccpGenerationError::Field(
            "original_member_peer"
        )))
    ));
    assert_eq!(pool.reserved_bytes(), bytes);
    let mut bad_epoch = epoch;
    bad_epoch.committee[0].proof_of_possession[0] ^= 1;
    assert!(matches!(
        RetainedSccpCommitteeGeneration::admit_new(
            start(),
            &SccpParametersV1::taira_default(),
            &bad_epoch,
            &[None; 4],
            &pool
        ),
        Err(CommitteeOwnerError::Invalid(SccpGenerationError::Epoch(_)))
    ));
    assert_eq!(pool.reserved_bytes(), bytes);
}
