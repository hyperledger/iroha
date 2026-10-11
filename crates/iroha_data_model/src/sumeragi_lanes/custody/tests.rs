//! Boundary and canonical identity tests for original lane custody obligations.
use super::*;
use crate::nexus::PublicLaneValidatorStatus;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::{metadata::Metadata, peer::PeerId};

fn fixture() -> (PublicLaneValidatorRecord, AssetId) {
    let key = KeyPair::from_seed(vec![7; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let record = PublicLaneValidatorRecord {
        lane_id: LaneId::SINGLE,
        validator: account.clone(),
        peer_id: PeerId::new(key.public_key().clone()),
        stake_account: account.clone(),
        total_stake: 100_u32.into(),
        self_stake: 100_u32.into(),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::Active,
        activation_height: 2,
        election_exit_height: None,
        deactivation_height: None,
    };
    let definition = crate::asset::AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("custody", "test").unwrap(),
        "xor".parse().unwrap(),
    );
    (record, AssetId::new(definition, account))
}
fn obligation() -> SumeragiLaneCustody {
    let (record, asset) = fixture();
    let signers = vec![SumeragiLaneSignerCustody {
        signer: 0,
        binding: SumeragiLaneStakeBinding::from_record(&record, &asset).unwrap(),
    }]
    .try_into()
    .unwrap();
    SumeragiLaneCustody {
        lane: LaneId::new(1),
        incarnation: [1; 32],
        instance: [2; 32],
        created_at: 10,
        merged: crate::sumeragi_lanes::SumeragiLaneFrontier::default(),
        signer_count: 4,
        signers,
        evidence_horizon: 7,
        slashing_delay: 3,
        retired_at: None,
    }
}
#[test]
fn lane_custody_keeps_native_height_out_of_global_fences() {
    let mut value = obligation();
    value.validate().unwrap();
    assert!(!value.admits_at(10).unwrap());
    assert!(value.admits_at(u64::MAX).unwrap());
    assert!(value.retains_at(u64::MAX).unwrap());
    value.retired_at = Some(20);
    assert_eq!(value.admission_deadline().unwrap(), Some(27));
    assert_eq!(value.release_height().unwrap(), Some(30));
    assert!(value.admits_at(27).unwrap());
    assert!(!value.admits_at(28).unwrap());
    assert!(value.retains_at(29).unwrap());
    assert!(!value.retains_at(30).unwrap());
}
#[test]
fn lane_custody_rejects_overflow_bad_geometry_and_unused_signer_slots() {
    let mut value = obligation();
    value.retired_at = Some(u64::MAX - 7);
    assert!(value.validate().is_err());
    value.retired_at = Some(u64::MAX);
    assert!(value.admission_deadline().is_err());
    value.retired_at = None;
    value.signer_count = 0;
    assert!(value.validate().is_err());
    value.signer_count = 4;
    let original = value.signers.as_slice()[0];
    value.signers = vec![SumeragiLaneSignerCustody {
        signer: 4,
        ..original
    }]
    .try_into()
    .unwrap();
    assert!(value.validate().is_err());
    value.signers = vec![original].try_into().unwrap();
    value.slashing_delay = 0;
    assert!(value.validate().is_err());
}
#[test]
fn lane_custody_roundtrip_includes_forensic_only_signers_and_every_fence() {
    let mut value = obligation();
    value.retired_at = Some(20);
    let bytes = norito::encode_canonical(&value).unwrap();
    assert_eq!(
        norito::decode_canonical::<SumeragiLaneCustody>(&bytes).unwrap(),
        value
    );
    let json = norito::json::to_vec(&value).unwrap();
    assert_eq!(
        norito::json::from_slice::<SumeragiLaneCustody>(&json).unwrap(),
        value
    );
    assert_eq!(value.signers.as_slice().len(), 1);
}
#[test]
fn original_tenure_commitment_excludes_balances_but_rejects_reused_keys_and_assets() {
    let (mut record, asset) = fixture();
    let original = SumeragiLaneStakeBinding::from_record(&record, &asset).unwrap();
    assert!(
        original
            .names_account(record.lane_id, &record.validator)
            .unwrap()
    );
    assert!(
        !original
            .names_account(LaneId::new(7), &record.validator)
            .unwrap()
    );
    record.total_stake = 2_u32.into();
    record.status = PublicLaneValidatorStatus::Exited;
    record.deactivation_height = Some(11);
    assert_eq!(
        SumeragiLaneStakeBinding::from_record(&record, &asset).unwrap(),
        original
    );
    record.activation_height = 7;
    assert_ne!(
        SumeragiLaneStakeBinding::from_record(&record, &asset).unwrap(),
        original
    );
    record.activation_height = 2;
    let definition = crate::asset::AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("custody", "test").unwrap(),
        "other".parse().unwrap(),
    );
    let other = AssetId::new(definition, record.validator.clone());
    assert_ne!(
        SumeragiLaneStakeBinding::from_record(&record, &other).unwrap(),
        original
    );
    record.deactivation_height = Some(1);
    assert!(SumeragiLaneStakeBinding::from_record(&record, &asset).is_err());
}

#[test]
fn sparse_custody_preserves_native_committee_geometry_and_exact_index() {
    let mut value = obligation();
    let binding = value.signers.as_slice()[0].binding;
    for count in [1_u32, 2, 4, 7, 32, 1024] {
        value.signer_count = count;
        value.signers = vec![SumeragiLaneSignerCustody {
            signer: count - 1,
            binding,
        }]
        .try_into()
        .unwrap();
        value.validate().unwrap();
        let bytes = norito::encode_canonical(&value).unwrap();
        assert_eq!(
            norito::decode_canonical::<SumeragiLaneCustody>(&bytes).unwrap(),
            value
        );
    }
    value.signer_count = 1025;
    assert!(value.validate().is_err());
    value.signer_count = 1024;
    value.signers = SumeragiLaneCustodySigners::default();
    value.validate().unwrap();
}

#[test]
fn sparse_custody_rejects_duplicate_reordered_and_outside_native_signers() {
    let binding = obligation().signers.as_slice()[0].binding;
    for indices in [vec![1, 1], vec![2, 1], vec![1024]] {
        let rows = indices
            .into_iter()
            .map(|signer| SumeragiLaneSignerCustody { signer, binding })
            .collect::<Vec<_>>();
        assert!(SumeragiLaneCustodySigners::try_from(rows).is_err());
    }
    let json = norito::json::to_json(&vec![
        SumeragiLaneSignerCustody { signer: 0, binding };
        MAX_LANE_CUSTODY_SIGNERS + 1
    ])
    .unwrap();
    assert!(norito::json::from_str::<SumeragiLaneCustodySigners>(&json).is_err());
    let mut value = obligation();
    let future = SumeragiLaneStakeBinding {
        activation_height: value.created_at + 1,
        ..binding
    };
    value.signers = vec![SumeragiLaneSignerCustody {
        signer: 0,
        binding: future,
    }]
    .try_into()
    .unwrap();
    assert!(value.validate().is_err());
}

#[test]
fn sparse_custody_binary_count_is_rejected_before_decoding_rows() {
    use norito::core::{self as ncore, DecodeFromSlice};
    // Explicit layout for this bare-payload preflight test; there are deliberately no rows.
    // The hostile count alone must be refused, without trying to build its backing vector.
    let _flags = ncore::DecodeFlagsGuard::enter(0);
    let mut field = Vec::new();
    ncore::write_seq_len(
        &mut field,
        u64::try_from(MAX_LANE_CUSTODY_SIGNERS).unwrap() + 1,
    )
    .unwrap();
    let mut bytes = Vec::new();
    ncore::write_len_with_flags(&mut bytes, u64::try_from(field.len()).unwrap(), 0).unwrap();
    bytes.extend(field);
    assert!(matches!(
        SumeragiLaneCustodySigners::decode_from_slice(&bytes),
        Err(norito::Error::LengthMismatch)
    ));
}

#[test]
fn custody_json_requires_the_complete_current_state_layout() {
    let value = obligation();
    let mut json = norito::json::to_value(&value).unwrap();
    json.as_object_mut().unwrap().remove("signers");
    assert!(norito::json::from_value::<SumeragiLaneCustody>(json).is_err());
    let mut json = norito::json::to_value(&super::super::SumeragiLaneState::default()).unwrap();
    json.as_object_mut().unwrap().remove("custody");
    assert!(norito::json::from_value::<super::super::SumeragiLaneState>(json).is_err());
}

#[test]
fn native_parent_coverage_uses_only_the_globally_anchored_native_frontier() {
    let mut value = obligation();
    assert!(!value.covers_native_subject(0).unwrap());
    assert!(value.covers_native_subject(1).unwrap());
    assert!(!value.covers_native_subject(2).unwrap());
    value.merged.height = 1_000_000;
    assert!(value.covers_native_subject(1_000_001).unwrap());
    assert!(!value.covers_native_subject(1_000_002).unwrap());
    assert!(
        value.admits_at(11).unwrap(),
        "global admission clock remains independent"
    );
    value.merged.height = u64::MAX;
    assert!(value.covers_native_subject(u64::MAX).unwrap());
}

#[test]
fn sparse_custody_clone_retains_the_original_immutable_signer_backing() {
    let original = obligation();
    let pointer = original.signers.as_slice().as_ptr();
    let canonical = norito::encode_canonical(&original).unwrap();
    let retained = original.clone();
    assert_eq!(retained, original);
    assert_eq!(norito::encode_canonical(&retained).unwrap(), canonical);
    assert_eq!(
        retained.signers.as_slice().as_ptr(),
        pointer,
        "World and rollback clones must retain the original immutable signer allocation"
    );
    drop(original);
    assert_eq!(retained.signers.as_slice().as_ptr(), pointer);
    assert_eq!(norito::encode_canonical(&retained).unwrap(), canonical);
}

#[test]
fn sparse_custody_charged_owner_preserves_exact_pool_refusal_retry_and_last_drop() {
    use iroha_allocation::{AllocationBudget, ChargedBuffer};
    let source = obligation().signers;
    let backing_bytes = std::mem::size_of::<SumeragiLaneSignerCustody>();
    let demand = backing_bytes + SumeragiLaneCustodySigners::control_layout().size();
    let budget = AllocationBudget::new(demand - 1);
    let foreign = AllocationBudget::new(demand);
    let mut rows = ChargedBuffer::new(1, &budget).unwrap();
    rows.append(source.as_slice()).unwrap();
    let pointer = rows.as_slice().as_ptr();
    let (rows, error) = SumeragiLaneCustodySigners::from_charged(rows, &foreign).unwrap_err();
    assert!(matches!(error, CustodySignersAdmissionError::ForeignBudget));
    assert_eq!(rows.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), backing_bytes);
    assert_eq!(foreign.reserved_bytes(), 0);
    let (rows, error) = SumeragiLaneCustodySigners::from_charged(rows, &budget).unwrap_err();
    assert!(matches!(
        error,
        CustodySignersAdmissionError::ControlAdmission(_)
    ));
    assert_eq!(rows.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), backing_bytes);
    budget.set_limit_bytes(demand);
    let admitted = SumeragiLaneCustodySigners::from_charged(rows, &budget)
        .unwrap_or_else(|(_rows, error)| panic!("same original owner retry: {error:?}"));
    assert_eq!(admitted.as_slice().as_ptr(), pointer);
    assert!(admitted.admitted_to(&budget));
    assert!(!admitted.admitted_to(&foreign));
    assert_eq!(budget.reserved_bytes(), demand);
    assert!(matches!(
        admitted.admit(&foreign),
        Err(CustodySignersAdmissionError::ForeignBudget)
    ));
    let same_pool = admitted.admit(&budget).unwrap();
    let retained = admitted.clone();
    assert_eq!(same_pool.as_slice().as_ptr(), pointer);
    assert_eq!(retained.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), demand);
    drop((admitted, same_pool));
    assert_eq!(budget.reserved_bytes(), demand);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn sparse_custody_decoded_admission_refunds_partial_copies_and_retries_original() {
    use iroha_allocation::AllocationBudget;
    let source = obligation().signers;
    let pointer = source.as_slice().as_ptr();
    let demand = std::mem::size_of::<SumeragiLaneSignerCustody>()
        + SumeragiLaneCustodySigners::control_layout().size();
    let budget = AllocationBudget::new(demand - 1);
    assert!(!source.admitted_to(&budget));
    assert!(matches!(
        source.admit(&budget),
        Err(CustodySignersAdmissionError::ControlAdmission(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(source.as_slice().as_ptr(), pointer);
    budget.set_limit_bytes(demand);
    let admitted = source.admit(&budget).unwrap();
    assert_eq!(admitted, source);
    assert_ne!(admitted.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), demand);
    drop(admitted);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(source.as_slice().as_ptr(), pointer);
}

#[test]
fn sparse_custody_immutable_storage_keeps_the_existing_binary_and_json_shape() {
    #[derive(norito::Encode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::sumeragi_lanes::SumeragiLaneCustodySigners")]
    struct OriginalShape(Vec<SumeragiLaneSignerCustody>);
    use iroha_allocation::AllocationBudget;
    let source = obligation().signers;
    for rows in [Vec::new(), source.as_slice().to_vec()] {
        let canonical = norito::encode_canonical(&OriginalShape(rows.clone())).unwrap();
        let json = norito::json::to_json(&rows).unwrap();
        let value = SumeragiLaneCustodySigners::try_from(rows).unwrap();
        let budget = AllocationBudget::new(4096);
        let admitted = value.admit(&budget).unwrap();
        for owner in [&value, &admitted] {
            assert_eq!(norito::encode_canonical(owner).unwrap(), canonical);
            assert_eq!(norito::json::to_json(owner).unwrap(), json);
        }
        let binary = norito::decode_canonical::<SumeragiLaneCustodySigners>(&canonical).unwrap();
        let json: SumeragiLaneCustodySigners = norito::json::from_str(&json).unwrap();
        assert_eq!(binary, value);
        assert_eq!(json, value);
    }
}

#[test]
fn sparse_custody_untrusted_control_refusal_preserves_the_decode_category() {
    let source = obligation().signers;
    let rows = source.as_slice().to_vec();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let error =
        norito::with_decode_limits_scope(limits, || SumeragiLaneCustodySigners::try_from(rows))
            .unwrap_err();
    assert!(
        matches!(
            error,
            norito::Error::TotalAllocationExceeded { limit: 0, .. }
        ),
        "{error:?}"
    );
    let retried = SumeragiLaneCustodySigners::try_from(source.as_slice().to_vec()).unwrap();
    assert_eq!(retried, source);
}

#[test]
fn original_charged_lane_signers_checked_container_retains_exact_pool_backing_and_depth() {
    use iroha_allocation::{AllocationBudget, ChargedBuffer};
    let source = obligation().signers;
    let demand = std::mem::size_of::<SumeragiLaneSignerCustody>()
        + SumeragiLaneCustodySigners::control_layout().size();
    let pool = AllocationBudget::new(demand);
    let mut rows = ChargedBuffer::new(1, &pool).unwrap();
    rows.append(source.as_slice()).unwrap();
    let pointer = rows.as_slice().as_ptr();
    let owner = SumeragiLaneCustodySigners::from_charged(rows, &pool)
        .unwrap_or_else(|(_, error)| panic!("original custody: {error:?}"));
    let charged = pool.reserved_bytes();
    pool.set_limit_bytes(0);
    crate::checked_container_refusal_controls::audit(&owner);
    assert_eq!(owner.as_slice().as_ptr(), pointer);
    assert!(owner.admitted_to(&pool));
    assert_eq!(pool.reserved_bytes(), charged);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}
