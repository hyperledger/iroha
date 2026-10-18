//! Genuine finality over explicit public fixture preimages; no native execution claim.
use super::*;
use crate::{
    consensus::ConsensusKeyStatus,
    sumeragi_finality::{
        WorldStateElementKindV1, WorldStateSnapshotEntryV1, test_fixtures::NativeFinalityFixture,
        world_state_value_hash_v1,
    },
    sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::peer::PeerId;

// NativeFinalityFixture::new authenticates H2; certify below extends it to H3.
const FIXTURE_CONTEXT_HEIGHT: u64 = 3;

fn entry<K: norito::codec::Encode, V: norito::codec::Encode>(
    field: &str,
    key: &K,
    value: &V,
) -> WorldStateSnapshotEntryV1 {
    WorldStateSnapshotEntryV1 {
        field_id: field.into(),
        kind: WorldStateElementKindV1::Table,
        key_hash: Some(world_state_value_hash_v1(key).unwrap()),
        value_hash: world_state_value_hash_v1(value).unwrap(),
    }
}
fn fixture() -> (PrivateSettlementPoolKeyV1, PrivateSettlementContextProofV1) {
    let (key, pool) = super::super::proof::tests::fixture();
    let keys: [_; 4] = std::array::from_fn(|index| {
        KeyPair::from_seed(vec![70 + index as u8; 32], Algorithm::BlsNormal)
    });
    let members: Vec<_> = keys
        .iter()
        .map(|key| SumeragiLaneMember {
            peer: PeerId::new(key.public_key().clone()),
            pop: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
        })
        .collect();
    let committee_keys = std::array::from_fn(|index| {
        let id = ConsensusKeyId::new(
            ConsensusKeyRole::Committee,
            format!("context-member-{index}")
                .parse::<iroha_schema::Ident>()
                .unwrap(),
        );
        PrivateSettlementCommitteeKeyProofV1 {
            index: vec![id.clone()],
            record: ConsensusKeyRecord {
                id,
                public_key: keys[index].public_key().clone(),
                pop: Some(members[index].pop.clone()),
                activation_height: FIXTURE_CONTEXT_HEIGHT,
                expiry_height: Some(10),
                replaces: None,
                status: ConsensusKeyStatus::Pending,
            },
        }
    });
    let mut lanes = SumeragiLaneState::default();
    lanes.upsert(SumeragiLaneRecord {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        lane: key.route.lane_id,
        dataspace: key.route.dataspace_id,
        incarnation: *key.route.lane_incarnation.as_ref(),
        params: crate::parameter::system::SumeragiParameters::default(),
        committee: members,
        created_at: 0,
        active_from: FIXTURE_CONTEXT_HEIGHT,
        closing: None,
        anchor_freshness: 16,
        merged: SumeragiLaneFrontier::default(),
        merged_at: FIXTURE_CONTEXT_HEIGHT,
        rescued: 0,
    });
    let mut proof = PrivateSettlementContextProofV1 {
        pool,
        lanes,
        committee_keys,
    };
    refresh(&mut proof);
    (key, proof)
}
fn refresh(proof: &mut PrivateSettlementContextProofV1) {
    proof.pool.world.entries.retain(|entry| {
        ![
            "world.sumeragi_lanes",
            "world.consensus_keys",
            "world.consensus_keys_by_pk",
        ]
        .contains(&entry.field_id.as_str())
    });
    proof.pool.world.entries.push(WorldStateSnapshotEntryV1 {
        field_id: "world.sumeragi_lanes".into(),
        kind: WorldStateElementKindV1::Cell,
        key_hash: None,
        value_hash: world_state_value_hash_v1(&proof.lanes).unwrap(),
    });
    for original in &proof.committee_keys {
        proof.pool.world.entries.push(entry(
            "world.consensus_keys_by_pk",
            &original.record.public_key.to_string(),
            &original.index,
        ));
        proof.pool.world.entries.push(entry(
            "world.consensus_keys",
            &original.record.id,
            &original.record,
        ));
    }
    proof
        .pool
        .world
        .entries
        .sort_by(|a, b| (&a.field_id, a.kind, a.key_hash).cmp(&(&b.field_id, b.kind, b.key_hash)));
}
fn certify(proof: &PrivateSettlementContextProofV1) -> (NetworkId, VerifiedSumeragiBlock) {
    let mut native = NativeFinalityFixture::new();
    let header = native.next_header();
    assert_eq!(header.height().get(), FIXTURE_CONTEXT_HEIGHT);
    let block = native.block_with_submitted_work(header);
    let certificate = native.certify_with_world_root(block, proof.pool.world.root().unwrap());
    (
        native.network_id(),
        native
            .verifier()
            .verify_retained_decision(&certificate)
            .unwrap(),
    )
}
#[test]
fn private_context_authenticates_same_cut_assignment_pending_activation_and_exact_borrowed_wire() {
    let (key, proof) = fixture();
    let (network, block) = certify(&proof);
    let selected = proof
        .verify(network, proof.pool.world.schema_hash, key, &block)
        .unwrap();
    assert_eq!(selected.pool_cut().height(), FIXTURE_CONTEXT_HEIGHT);
    assert_eq!(
        selected.authority().validators[0],
        proof.lanes.lanes[0].committee[0].peer
    );
    let borrowed = PrivateSettlementContextProofRefV1::new(
        PrivateSettlementPoolCutProofRefV1::new(
            &proof.pool.world,
            &proof.pool.governance,
            &proof.pool.pool,
        ),
        &proof.lanes,
        std::array::from_fn(|i| {
            PrivateSettlementCommitteeKeyProofRefV1::new(
                &proof.committee_keys[i].index,
                &proof.committee_keys[i].record,
            )
        }),
    );
    let bytes = norito::encode_canonical(&proof).unwrap();
    assert_eq!(norito::encode_canonical(&borrowed).unwrap(), bytes);
    assert_eq!(
        norito::json::to_vec(&borrowed).unwrap(),
        norito::json::to_vec(&proof).unwrap()
    );
    assert_eq!(
        PrivateSettlementContextProofV1::decode_frame(&bytes).unwrap(),
        proof
    );
}
#[test]
fn private_context_rejects_committed_disabled_expired_future_wrong_role_and_missing_index() {
    for mutation in 0..5 {
        let (key, mut proof) = fixture();
        match mutation {
            0 => proof.committee_keys[0].record.status = ConsensusKeyStatus::Disabled,
            1 => proof.committee_keys[0].record.expiry_height = Some(FIXTURE_CONTEXT_HEIGHT),
            2 => proof.committee_keys[0].record.activation_height = FIXTURE_CONTEXT_HEIGHT + 1,
            3 => {
                proof.committee_keys[0].record.id.role = ConsensusKeyRole::Validator;
                proof.committee_keys[0].index[0].role = ConsensusKeyRole::Validator;
            }
            _ => proof.committee_keys[0].index.clear(),
        }
        refresh(&mut proof);
        let (network, block) = certify(&proof);
        assert!(
            proof
                .verify(network, proof.pool.world.schema_hash, key, &block)
                .is_err(),
            "lifecycle/role/index mutation {mutation}"
        );
    }
}
#[test]
fn private_context_rejects_cross_cut_roster_record_and_lane_lifecycle() {
    let (key, proof) = fixture();
    let (network, block) = certify(&proof);
    let mut changed = proof.clone();
    changed.committee_keys[0].record.expiry_height = None;
    assert!(
        changed
            .verify(network, proof.pool.world.schema_hash, key, &block)
            .is_err()
    );
    let mut changed = proof.clone();
    changed.lanes.lanes[0].committee.swap(0, 1);
    assert!(
        changed
            .verify(network, proof.pool.world.schema_hash, key, &block)
            .is_err()
    );
    for close in [false, true] {
        let mut changed = proof.clone();
        if close {
            changed.lanes.lanes[0].closing = Some(FIXTURE_CONTEXT_HEIGHT);
        } else {
            changed.lanes.lanes[0].active_from = FIXTURE_CONTEXT_HEIGHT + 1;
        }
        refresh(&mut changed);
        let (network, block) = certify(&changed);
        assert!(
            changed
                .verify(network, changed.pool.world.schema_hash, key, &block)
                .is_err()
        );
    }
}

#[test]
fn private_context_batch_preserves_one_cut_all_selectors_and_borrowed_codec() {
    let (key, mut first) = fixture();
    let mut second = first.clone();
    second.pool.pool.pool_id = crate::privacy::PrivacyPoolIdV1::new([93; 32]);
    second.pool.governance.pool_id = second.pool.pool.pool_id;
    let second_key = PrivateSettlementPoolKeyV1 {
        route: key.route,
        pool_id: second.pool.pool.pool_id,
    };
    first.pool.world.entries.push(entry(
        "world.private_settlement_governance",
        &second_key,
        &second.pool.governance,
    ));
    first.pool.world.entries.push(entry(
        "world.private_settlement_pools",
        &second_key,
        &second.pool.pool,
    ));
    refresh(&mut first);
    second.pool.world = first.pool.world.clone();
    let (network, block) = certify(&first);
    let schema = first.pool.world.schema_hash;
    let request = PrivateSettlementContextRequestV1 {
        pools: vec![key, second_key],
    };
    let batch = PrivateSettlementContextsProofV1 {
        contexts: vec![first, second],
    };
    batch.verify(network, schema, &request, &block).unwrap();
    let borrowed = PrivateSettlementContextsProofRefV1::new(
        batch
            .contexts
            .iter()
            .map(|proof| {
                PrivateSettlementContextProofRefV1::new(
                    PrivateSettlementPoolCutProofRefV1::new(
                        &proof.pool.world,
                        &proof.pool.governance,
                        &proof.pool.pool,
                    ),
                    &proof.lanes,
                    std::array::from_fn(|i| {
                        PrivateSettlementCommitteeKeyProofRefV1::new(
                            &proof.committee_keys[i].index,
                            &proof.committee_keys[i].record,
                        )
                    }),
                )
            })
            .collect(),
    );
    let bytes = norito::encode_canonical(&batch).unwrap();
    assert_eq!(bytes, norito::encode_canonical(&borrowed).unwrap());
    assert_eq!(
        norito::json::to_vec(&batch).unwrap(),
        norito::json::to_vec(&borrowed).unwrap()
    );
    assert_eq!(
        PrivateSettlementContextsProofV1::decode_frame(&bytes).unwrap(),
        batch
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(PrivateSettlementContextsProofV1::decode_frame(&trailing).is_err());
    assert_eq!(
        norito::decode_canonical::<PrivateSettlementContextRequestV1>(
            &norito::encode_canonical(&request).unwrap()
        )
        .unwrap(),
        request
    );
    for mutation in 0..5 {
        let mut changed = batch.clone();
        match mutation {
            0 => {
                changed.contexts.pop();
            }
            1 => changed.contexts.swap(0, 1),
            2 => changed.contexts.push(batch.contexts[0].clone()),
            3 => changed.contexts[1].pool.world.schema_hash = Hash::new(b"another cut"),
            _ => changed.contexts[1].pool.pool.epoch += 1,
        }
        assert!(
            changed.verify(network, schema, &request, &block).is_err(),
            "every exact same-cut member must authenticate before the first wallet call: {mutation}"
        );
    }
}

#[test]
fn private_context_request_rejects_duplicate_empty_and_one_over_protocol_leg_bound() {
    let (key, _) = fixture();
    assert!(
        PrivateSettlementContextRequestV1 { pools: Vec::new() }
            .validate()
            .is_err()
    );
    assert!(
        PrivateSettlementContextRequestV1 {
            pools: vec![key, key]
        }
        .validate()
        .is_err()
    );
    let keys = (0..255)
        .map(|i| PrivateSettlementPoolKeyV1 {
            pool_id: crate::privacy::PrivacyPoolIdV1::new([i as u8 + 1; 32]),
            ..key
        })
        .collect();
    let mut request = PrivateSettlementContextRequestV1 { pools: keys };
    request.validate().unwrap();
    assert!(
        norito::canonical_frame_len(&request).unwrap()
            <= PRIVATE_SETTLEMENT_CONTEXT_REQUEST_MAX_BYTES_V1
    );
    request.pools.push(key);
    assert!(request.validate().is_err());
}

#[test]
fn private_context_public_intent_join_rejects_rederived_foreign_commitments() {
    use crate::{
        nexus::{PrivateSettlementBundleLegMaterialV1, PrivateSettlementProofIntentV1},
        transaction::FeePaymentIntent,
    };
    let (key, proof) = fixture();
    let (network, block) = certify(&proof);
    let selected = proof
        .verify(network, proof.pool.world.schema_hash, key, &block)
        .unwrap();
    let first = PrivateSettlementBundleLegMaterialV1 {
        ordinal: 0,
        route: key.route,
        pool_id: key.pool_id,
        asset_binding_commitment: proof.pool.governance.asset_binding_commitment,
        audit_policy_digest: proof.pool.governance.audit_policy_digest,
    };
    let mut second = first;
    second.ordinal = 1;
    second.route.dataspace_id =
        iroha_model_base::topology::DataSpaceId::new(key.route.dataspace_id.as_u64() + 1);
    second.pool_id = crate::privacy::PrivacyPoolIdV1::new([81; 32]);
    let sponsor = crate::account::AccountId::new(
        KeyPair::from_seed(vec![31; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let make = |legs| {
        PrivateSettlementProofIntentV1::new(
            network,
            selected.pool_cut().height(),
            9,
            sponsor.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
            Hash::new(b"actual reimbursement terms"),
            0,
            legs,
        )
        .unwrap()
    };
    let good = make(vec![first, second]);
    selected.verify_intent(&good, 0).unwrap();
    assert!(selected.verify_intent(&good, 1).is_err());
    assert!(selected.verify_intent(&good, 2).is_err());
    for policy in [false, true] {
        let mut changed = first;
        if policy {
            changed.audit_policy_digest = Hash::new(b"foreign audit policy");
        } else {
            changed.asset_binding_commitment = Hash::new(b"foreign asset binding");
        }
        let foreign = make(vec![changed, second]);
        foreign.validate().unwrap();
        assert!(
            selected.verify_intent(&foreign, 0).is_err(),
            "a validly rederived intent cannot override authenticated public commitments"
        );
    }
}

#[test]
fn private_context_json_preserves_four_originals_and_bounded_borrowed_writing() {
    let (_, proof) = fixture();
    let borrowed = PrivateSettlementContextProofRefV1::new(
        PrivateSettlementPoolCutProofRefV1::new(
            &proof.pool.world,
            &proof.pool.governance,
            &proof.pool.pool,
        ),
        &proof.lanes,
        std::array::from_fn(|i| {
            PrivateSettlementCommitteeKeyProofRefV1::new(
                &proof.committee_keys[i].index,
                &proof.committee_keys[i].record,
            )
        }),
    );
    assert!(std::ptr::eq(borrowed.lanes.0, &proof.lanes));
    for (row, original) in borrowed.committee_keys.iter().zip(&proof.committee_keys) {
        assert!(std::ptr::eq(row.index.0, &original.index));
        assert!(std::ptr::eq(row.record.0, &original.record));
    }
    let actual = norito::json::to_json_bounded(&borrowed, usize::MAX).unwrap();
    let required = actual.len();
    assert_eq!(
        norito::json::to_json_bounded(&borrowed, required).unwrap(),
        actual
    );
    assert!(norito::json::to_json_bounded(&borrowed, required - 1).is_err());
    assert_eq!(actual, norito::json::to_json(&borrowed).unwrap());
    assert_eq!(actual, norito::json::to_json(&proof).unwrap());
    assert_eq!(
        norito::json::to_json_bounded(&proof, required).unwrap(),
        actual
    );
    assert!(norito::json::to_json_bounded(&proof, required - 1).is_err());
    assert_eq!(
        norito::json::from_str::<PrivateSettlementContextProofV1>(&actual).unwrap(),
        proof
    );
    let json = norito::json::parse_value(&actual).unwrap();
    assert_eq!(
        json.get("committee_keys")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1
    );
    assert_eq!(
        norito::json::from_value::<PrivateSettlementContextProofV1>(json).unwrap(),
        proof
    );
    let wire = norito::encode_canonical(&proof).unwrap();
    assert_eq!(norito::encode_canonical(&borrowed).unwrap(), wire);
    assert_eq!(
        PrivateSettlementContextProofV1::decode_frame(&wire).unwrap(),
        proof
    );
    for (row, original) in borrowed.committee_keys.iter().zip(&proof.committee_keys) {
        assert!(std::ptr::eq(row.index.0, &original.index));
        assert!(std::ptr::eq(row.record.0, &original.record));
    }
}

#[test]
fn private_context_json_rejects_nonfour_arrays_unknown_root_and_key_fields() {
    use norito::json::Value;
    let (_, proof) = fixture();
    let original = norito::json::to_value(&proof).unwrap();
    let keys = original.get("committee_keys").unwrap().as_array().unwrap();
    let rejected = |value: Value| {
        let bytes = norito::json::to_json(&value).unwrap();
        assert!(norito::json::from_str::<PrivateSettlementContextProofV1>(&bytes).is_err());
        assert!(norito::json::from_value::<PrivateSettlementContextProofV1>(value).is_err());
    };
    for count in [0, 1, 2, 3, 5, 6, 7, 8] {
        let Value::Object(mut fields) = original.clone() else {
            unreachable!()
        };
        let changed = (0..count)
            .map(|index| keys[index % keys.len()].clone())
            .collect();
        fields.insert("committee_keys".into(), Value::Array(changed));
        rejected(Value::Object(fields));
    }
    for replacement in [
        Value::Null,
        Value::String("four".into()),
        Value::Object(Default::default()),
    ] {
        let Value::Object(mut fields) = original.clone() else {
            unreachable!()
        };
        fields.insert("committee_keys".into(), replacement);
        rejected(Value::Object(fields));
    }
    let Value::Object(mut fields) = original.clone() else {
        unreachable!()
    };
    fields.insert("unexpected_context_field".into(), Value::Bool(true));
    rejected(Value::Object(fields));
    for index in 0..PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1 {
        let Value::Object(mut fields) = original.clone() else {
            unreachable!()
        };
        let mut rows = keys.clone();
        let Value::Object(ref mut row) = rows[index] else {
            unreachable!()
        };
        row.insert("unexpected_key_field".into(), Value::Bool(true));
        fields.insert("committee_keys".into(), Value::Array(rows));
        rejected(Value::Object(fields));
    }
}
