//! Synthetic certified World controls for exact capacity/pricing originals, not native eligibility.

use super::*;
use sorafs_manifest::{
    capacity::{
        CAPACITY_DECLARATION_VERSION_V1, CapacityDeclarationV1, CapacityMetadataEntry,
        ChunkerCommitmentV1,
    },
    provider_advert::{CapabilityType, StakePointer},
};

fn capacity() -> CapacityDeclarationRecord {
    let declaration = CapacityDeclarationV1 {
        version: CAPACITY_DECLARATION_VERSION_V1,
        provider_id: *provider().as_bytes(),
        stake: StakePointer {
            pool_id: [0x52; 32],
            stake_amount: "1".parse().unwrap(),
        },
        committed_capacity_gib: 1,
        chunker_commitments: vec![ChunkerCommitmentV1 {
            profile_id: "sorafs.sf1@1.0.0".into(),
            profile_aliases: None,
            committed_gib: 1,
            capability_refs: vec![CapabilityType::ToriiGateway],
        }],
        lane_commitments: Vec::new(),
        pricing: None,
        valid_from: 9_000,
        valid_until: 10_000,
        metadata: vec![
            CapacityMetadataEntry {
                key: "sorafs.owner_account_id".into(),
                value: account(6).to_string(),
            },
            CapacityMetadataEntry {
                key: "sorafs.storage_class".into(),
                value: "hot".into(),
            },
            CapacityMetadataEntry {
                key: "note_a".into(),
                value: "a".repeat(3_000),
            },
            CapacityMetadataEntry {
                key: "note_b".into(),
                value: "b".repeat(3_000),
            },
        ],
    };
    declaration.validate().unwrap();
    let bytes = norito::encode_canonical(&declaration).unwrap();
    assert!(
        bytes.len() > 4_096,
        "exercise an actual canonical declaration byte sequence"
    );
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    for entry in &declaration.metadata {
        metadata.insert(
            entry.key.parse().unwrap(),
            iroha_primitives::json::Json::new(entry.value.clone()),
        );
    }
    CapacityDeclarationRecord::new(provider(), bytes, 1, 8_999, 9_000, 10_000, metadata)
}

fn all_facts() -> (
    NativeFinalityFixture,
    ReserveAccountProofV1,
    ReserveAuthorityPolicyV1,
    VerifiedSumeragiBlock,
) {
    let (mut native, mut proof, policy, _) = fixture_with_credit();
    proof.capacity = Some(norito::encode_canonical(&capacity()).unwrap());
    rebuild(&mut proof, &policy);
    let block = certify(&mut native, &proof);
    (native, proof, policy, block)
}

#[test]
fn capacity_and_pricing_share_exact_borrowed_layout_and_preserve_future_facts() {
    let (_, proof, policy, block) = all_facts();
    let verified = verify(&proof, &policy, &block).unwrap();
    assert_eq!(verified.capacity(), Some(&capacity()));
    assert_eq!(verified.pricing(), &PricingScheduleRecord::launch_default());
    assert!(verified.capacity().unwrap().valid_from_epoch > verified.block_time_ms() / 1_000);
    assert_eq!(verified.credit(), Some(&credit()));
    let borrowed = ReserveAccountProofRefV1::new(
        &proof.world,
        &proof.owner,
        &proof.policy,
        proof.current.as_ref(),
        proof.credit.as_ref(),
        proof.capacity.as_ref(),
        &proof.pricing,
    );
    let bytes = norito::encode_canonical(&proof).unwrap();
    assert_eq!(norito::encode_canonical(&borrowed).unwrap(), bytes);
    assert_eq!(ReserveAccountProofV1::decode_frame(&bytes).unwrap(), proof);
    assert_eq!(
        norito::json::to_vec(&borrowed).unwrap(),
        norito::json::to_vec(&proof).unwrap()
    );
    for name in ["capacity", "pricing"] {
        let mut json = norito::json::to_value(&proof).unwrap();
        assert!(json.as_object_mut().unwrap().remove(name).is_some());
        assert!(norito::json::from_value::<ReserveAccountProofV1>(json).is_err());
    }
    let (_, absent, policy, block) = fixture(false);
    let verified = verify(&absent, &policy, &block).unwrap();
    assert!(verified.capacity().is_none());
    assert_eq!(verified.pricing(), &PricingScheduleRecord::launch_default());
}

#[test]
fn every_capacity_original_field_and_hidden_row_refuse_substitution() {
    let (_, proof, policy, block) = all_facts();
    let mut hidden = proof.clone();
    hidden.capacity = None;
    assert!(verify(&hidden, &policy, &block).is_err());
    let (_, mut absent, absent_policy, absent_block) = fixture(true);
    absent.capacity = proof.capacity.clone();
    assert!(verify(&absent, &absent_policy, &absent_block).is_err());
    let original = capacity();
    let mut changes = Vec::new();
    macro_rules! candidate {
        ($field:ident, $value:expr) => {{
            let mut value = original.clone();
            value.$field = $value;
            changes.push(value);
        }};
    }
    candidate!(provider_id, ProviderId::new([0x53; 32]));
    candidate!(declaration, vec![1, 2, 3]);
    candidate!(committed_capacity_gib, 2);
    candidate!(registered_epoch, 1);
    candidate!(valid_from_epoch, 1);
    candidate!(valid_until_epoch, 2);
    candidate!(metadata, iroha_model_base::metadata::Metadata::default());
    for value in changes {
        let mut candidate = proof.clone();
        candidate.capacity = Some(norito::encode_canonical(&value).unwrap());
        assert!(verify(&candidate, &policy, &block).is_err());
    }
}

#[test]
fn capacity_key_kind_and_typed_value_are_bound_to_selected_provider() {
    let (mut native, proof, policy, _) = all_facts();
    for variant in 0..4 {
        let mut changed = proof.clone();
        let entry = changed
            .world
            .entries
            .iter_mut()
            .find(|e| e.field_id == "world.capacity_declarations")
            .unwrap();
        match variant {
            0 => entry.field_id = "world.other_capacity".into(),
            1 => {
                entry.kind = WorldStateElementKindV1::Cell;
                entry.key_hash = None;
            }
            2 => {
                entry.key_hash =
                    Some(world_state_value_hash_v1(&ProviderId::new([0x53; 32])).unwrap())
            }
            _ => {
                entry.value_hash =
                    world_state_value_hash_v1(proof.capacity.as_ref().unwrap()).unwrap()
            }
        }
        sort(&mut changed);
        let block = certify(&mut native, &changed);
        assert!(verify(&changed, &policy, &block).is_err());
        if variant == 1 {
            changed.capacity = None;
            assert!(verify(&changed, &policy, &block).is_err());
        }
    }
    let mut changed = proof;
    let mut wrong = capacity();
    wrong.provider_id = ProviderId::new([0x53; 32]);
    changed.capacity = Some(norito::encode_canonical(&wrong).unwrap());
    rebuild(&mut changed, &policy);
    let block = certify(&mut native, &changed);
    assert!(verify(&changed, &policy, &block).is_err());
}

#[test]
fn pricing_is_required_exact_cell_data_without_hidden_arithmetic_eligibility() {
    let (mut native, proof, policy, block) = all_facts();
    let mut schedule = PricingScheduleRecord::launch_default();
    schedule.version += 1;
    assert!(schedule.validate().is_err());
    let mut changed = proof.clone();
    changed.pricing = norito::encode_canonical(&schedule).unwrap();
    assert!(verify(&changed, &policy, &block).is_err());
    // Explicit synthetic commitment to invalid economics: the evidence reader authenticates
    // data, while the existing arithmetic/validation owner still refuses to use it.
    rebuild(&mut changed, &policy);
    let changed_block = certify(&mut native, &changed);
    let verified = verify(&changed, &policy, &changed_block).unwrap();
    assert_eq!(verified.pricing(), &schedule);
    assert!(verified.pricing().validate().is_err());
    for variant in 0..4 {
        let mut changed = proof.clone();
        let index = changed
            .world
            .entries
            .iter()
            .position(|e| e.field_id == "world.sorafs_pricing")
            .unwrap();
        match variant {
            0 => {
                changed.world.entries.remove(index);
            }
            1 => changed.world.entries[index].field_id = "world.other_pricing".into(),
            2 => {
                changed.world.entries[index].kind = WorldStateElementKindV1::Table;
                changed.world.entries[index].key_hash =
                    Some(world_state_value_hash_v1(&provider()).unwrap());
            }
            _ => {
                changed.world.entries[index].value_hash =
                    world_state_value_hash_v1(&proof.pricing).unwrap()
            }
        }
        sort(&mut changed);
        let block = certify(&mut native, &changed);
        assert!(verify(&changed, &policy, &block).is_err());
    }
}

#[test]
fn capacity_pricing_bounds_and_full_decode_share_one_cumulative_allowance() {
    let (_, proof, policy, block) = all_facts();
    for capacity_field in [true, false] {
        let original = if capacity_field {
            proof.capacity.as_ref().unwrap()
        } else {
            &proof.pricing
        };
        let mut trailing = original.clone();
        trailing.push(0);
        let maximum = if capacity_field {
            MAX_RESERVE_ACCOUNT_CAPACITY_BYTES_V1
        } else {
            MAX_RESERVE_ACCOUNT_PRICING_BYTES_V1
        };
        for bytes in [Vec::new(), vec![0], trailing, vec![0; maximum + 1]] {
            let mut changed = proof.clone();
            if capacity_field {
                changed.capacity = Some(bytes);
            } else {
                changed.pricing = bytes;
            }
            assert!(verify(&changed, &policy, &block).is_err());
        }
    }
    let bytes = norito::encode_canonical(&proof).unwrap();
    let attempt = || {
        let decoded = ReserveAccountProofV1::decode_frame(&bytes).map_err(map_invalid)?;
        verify(&decoded, &policy, &block)
    };
    let (result, usage) =
        norito::core::with_decode_limits_measured(RESERVE_ACCOUNT_PROOF_LIMITS_V1, attempt);
    result.unwrap();
    let short = norito::DecodeLimits::new(
        MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1,
        MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1,
        MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1,
        usage.total_allocated_bytes() - 1,
        64,
    );
    assert!(norito::core::with_decode_limits_scope(short, attempt).is_err());
    assert_eq!(
        norito::core::with_decode_limits_scope(RESERVE_ACCOUNT_PROOF_LIMITS_V1, attempt)
            .unwrap()
            .capacity(),
        Some(&capacity())
    );
}

#[test]
fn incomplete_current_wire_cannot_default_capacity_or_pricing() {
    #[derive(norito::derive::NoritoSerialize)]
    struct MissingPricing<'a> {
        world: borrowed::Value<'a, WorldStateSnapshotV1>,
        owner: borrowed::Value<'a, AccountId>,
        policy: borrowed::Vec<'a, u8>,
        current: Option<borrowed::Vec<'a, u8>>,
        credit: Option<borrowed::Vec<'a, u8>>,
        capacity: Option<borrowed::Vec<'a, u8>>,
    }
    impl norito::NoritoSchema for MissingPricing<'_> {
        fn nominal_name() -> String {
            <ReserveAccountProofV1 as norito::NoritoSchema>::nominal_name()
        }
        fn frame_name() -> String {
            <ReserveAccountProofV1 as norito::NoritoSchema>::frame_name()
        }
    }
    let (_, proof, _, _) = all_facts();
    let incomplete = MissingPricing {
        world: borrowed::Value(&proof.world),
        owner: borrowed::Value(&proof.owner),
        policy: borrowed::Vec(&proof.policy),
        current: proof.current.as_ref().map(borrowed::Vec),
        credit: proof.credit.as_ref().map(borrowed::Vec),
        capacity: proof.capacity.as_ref().map(borrowed::Vec),
    };
    assert!(
        ReserveAccountProofV1::decode_frame(&norito::encode_canonical(&incomplete).unwrap())
            .is_err()
    );
}

#[test]
fn former_five_field_payload_cannot_omit_both_new_originals() {
    #[derive(norito::derive::NoritoSerialize)]
    struct Incomplete<'a> {
        world: borrowed::Value<'a, WorldStateSnapshotV1>,
        owner: borrowed::Value<'a, AccountId>,
        policy: borrowed::Vec<'a, u8>,
        current: Option<borrowed::Vec<'a, u8>>,
        credit: Option<borrowed::Vec<'a, u8>>,
    }
    impl norito::NoritoSchema for Incomplete<'_> {
        fn nominal_name() -> String {
            <ReserveAccountProofV1 as norito::NoritoSchema>::nominal_name()
        }
        fn frame_name() -> String {
            <ReserveAccountProofV1 as norito::NoritoSchema>::frame_name()
        }
    }
    let (_, proof, _, _) = all_facts();
    let incomplete = Incomplete {
        world: borrowed::Value(&proof.world),
        owner: borrowed::Value(&proof.owner),
        policy: borrowed::Vec(&proof.policy),
        current: proof.current.as_ref().map(borrowed::Vec),
        credit: proof.credit.as_ref().map(borrowed::Vec),
    };
    assert!(
        ReserveAccountProofV1::decode_frame(&norito::encode_canonical(&incomplete).unwrap())
            .is_err()
    );
}
