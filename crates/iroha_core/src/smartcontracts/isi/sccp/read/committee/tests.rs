//! Original graph custody, mutable lifecycle projection, strict encoding and liability.
use super::*;
use crate::smartcontracts::isi::sccp::test_support::{blank_state, header, sample_generation};
use iroha_allocation::AllocationBudget;
use norito::codec::{DecodeAll, Encode};

#[test]
fn retained_generation_view_preserves_exact_graph_lifecycle_and_wire_identity() {
    use iroha_data_model::account::{AccountId, MultisigMember, MultisigPolicy};
    let mut source = sample_generation(2);
    // Preserve a nested universal-account graph at saturation, not merely flat keys.
    let members = [0x61, 0x62].map(|seed| {
        let pair =
            iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519);
        MultisigMember::new(pair.public_key().clone(), 1).unwrap()
    });
    source.members[0].as_mut().unwrap().validator =
        AccountId::new_multisig(MultisigPolicy::new(2, members.to_vec()).unwrap());
    let budget = AllocationBudget::new(1 << 20);
    let mut original = RetainedSccpGeneration::admit(&source, &budget).unwrap();
    original.end = Some(SccpGenerationEndV1 {
        end_height: 3,
        end_timestamp_ms: 3_000,
        next_committee_root: source.committee_root,
        successor_validity_ms: source.validity_ms,
    });
    original.dest_cleared_lc = Some(3_000);
    let occupied = budget.reserved_bytes();
    let external = budget
        .try_reserve_bytes(budget.limit_bytes() - occupied)
        .unwrap();
    let response = RetainedSccpGenerationView {
        generation: original.clone(),
        liable: true,
    };
    assert_eq!(response.generation.keys.as_ptr(), original.keys.as_ptr());
    assert_eq!(
        response.generation.members.as_ptr(),
        original.members.as_ptr()
    );
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(original);
    drop(external);
    assert_eq!(budget.reserved_bytes(), occupied);
    let encoded = response.encode();
    let decoded = SccpGenerationV1::decode_all(&mut encoded.as_slice()).unwrap();
    assert_eq!(decoded.generation, source.generation);
    assert_eq!(decoded.committee_root, source.committee_root);
    assert_eq!(decoded.cause, source.cause);
    assert_eq!(decoded.start_height, source.start_height);
    assert_eq!(decoded.start_timestamp_ms, source.start_timestamp_ms);
    assert_eq!(decoded.start_lc, source.start_lc);
    assert_eq!(decoded.validity_ms, source.validity_ms);
    assert_eq!(decoded.deadline_ms, source.deadline_ms);
    assert_eq!(decoded.grace_ms, source.grace_ms);
    assert_eq!(decoded.progress_cap_ms, source.progress_cap_ms);
    assert_eq!(decoded.liable_until_lc, source.liable_until_lc);
    assert_eq!(decoded.keys, source.keys);
    assert_eq!(decoded.members, source.members);
    assert_eq!(decoded.end, response.generation.end);
    assert_eq!(decoded.dest_cleared_lc, Some(3_000));
    assert!(decoded.liable);
    assert_eq!(encoded, decoded.encode());
    let json = norito::json::to_json(&response).unwrap();
    assert_eq!(
        norito::json::from_str::<SccpGenerationV1>(&json).unwrap(),
        decoded
    );
    assert_eq!(json, norito::json::to_json(&decoded).unwrap());
    let framed = norito::to_bytes(&response).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<SccpGenerationV1>(&framed).unwrap(),
        decoded
    );
    for field in ["liable", "end", "dest_cleared_lc"] {
        let mut value = norito::json::to_value(&decoded).unwrap();
        value.as_object_mut().unwrap().remove(field);
        assert!(norito::json::from_value::<SccpGenerationV1>(value).is_err());
    }
    let mut value = norito::json::to_value(&decoded).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("roster_root".into(), norito::json::Value::from(0));
    assert!(norito::json::from_value::<SccpGenerationV1>(value).is_err());
    drop(response);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn committee_reads_distinguish_absent_pruned_and_inclusive_liability() {
    let state = blank_state();
    let budget = state.ivm_execution_budget();
    let mut block = state.block(header(30));
    let mut stx = block.transaction();
    assert!(matches!(
        current_committee(&*stx.world),
        Err(SccpReadError::NotFound(_))
    ));
    assert!(matches!(
        committee(&*stx.world, 0),
        Err(SccpReadError::Invalid(_))
    ));
    let mut source = sample_generation(2);
    source.end = Some(SccpGenerationEndV1 {
        end_height: source.start_height,
        end_timestamp_ms: source.start_timestamp_ms,
        next_committee_root: source.committee_root,
        successor_validity_ms: source.validity_ms,
    });
    source.dest_cleared_lc = Some(source.start_lc);
    let limit = source.liable_until_lc;
    store::committee_generations::insert(
        &mut stx,
        2,
        RetainedSccpGeneration::admit(&source, &budget).unwrap(),
    )
    .unwrap();
    store::committee_current::set(&mut stx, 3);
    store::liability_clock::set(&mut stx, limit);
    assert!(committee(&*stx.world, 2).unwrap().liable);
    store::liability_clock::set(&mut stx, limit + 1);
    assert!(!committee(&*stx.world, 2).unwrap().liable);
    store::committee_current::set(&mut stx, 2);
    let response = current_committee(&*stx.world).unwrap();
    assert!(response.liable, "current generation remains liable");
    assert!(matches!(
        committee(&*stx.world, 1),
        Err(SccpReadError::Pruned(_))
    ));
    assert!(matches!(
        committee(&*stx.world, 3),
        Err(SccpReadError::NotFound(_))
    ));
    drop(stx);
    drop(block);
    assert_eq!(
        response.generation.keys, source.keys,
        "response survives original view rollback"
    );
}
