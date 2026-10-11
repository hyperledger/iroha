//! Actual canonical record claims, exact original-pool backing and immutable graph retirement.
use super::*;
use crate::{
    state::WorldReadOnly as _,
    sumeragi::evidence::observe,
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use mv::storage::StorageReadOnly as _;

fn claim() -> EvidenceRecord {
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let native = super::super::tests::conflict(&chain, 2);
    let proof = Evidence::from_native(&native).unwrap();
    let key = super::super::evidence_key(&proof);
    assert!(observe(chain.state(), &native).unwrap());
    chain.commit(Vec::new());
    let record = chain
        .state()
        .view()
        .world()
        .consensus_evidence()
        .get(&key)
        .unwrap()
        .canonical_projection();
    assert!(!record.attribution.offenders.is_empty());
    record
}
fn parse(
    source: &str,
    pool: &AllocationBudget,
) -> Result<RetainedEvidenceRecord, EvidenceRecordRestoreError> {
    let mut parser = Parser::new(source);
    let record = parse_record(&mut parser, pool)?;
    parser.skip_ws();
    assert!(parser.eof());
    Ok(record)
}

#[test]
fn retained_record_restore_and_borrowed_encoding_preserve_exact_canonical_schema() {
    let mut original = claim();
    for status in [
        EvidencePenaltyStatus::Pending,
        EvidencePenaltyStatus::Applied { height: 5 },
    ] {
        original.penalty_status = status;
        let source = json::to_json(&original).unwrap();
        let pool = AllocationBudget::new(1 << 20);
        let foreign = AllocationBudget::new(pool.limit_bytes());
        let record = parse(&source, &pool).unwrap();
        assert!(record.body_belongs_to(&pool));
        assert!(record.proof_belongs_to(&pool));
        assert!(!record.body_belongs_to(&foreign));
        assert!(!record.proof_belongs_to(&foreign));
        assert_eq!(record.canonical_projection(), original);
        assert_eq!(json::to_json(&record).unwrap(), source);
        assert_eq!(
            norito::encode_canonical(&record).unwrap(),
            norito::encode_canonical(&original).unwrap()
        );
        assert_eq!(
            record.allocation_bytes_in(&pool),
            Some(pool.reserved_bytes())
        );
        assert_eq!(record.allocation_bytes_in(&foreign), Some(0));
        assert!(pool.reserved_bytes() > original.evidence.native_frame().len());
        drop(record);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn retained_record_clone_status_and_last_owner_preserve_actual_backing_and_refund() {
    let original = claim();
    let source = json::to_json(&original).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let record = parse(&source, &pool).unwrap();
    let reserved = pool.reserved_bytes();
    let mut applied = None;
    let allocations = allocations_during(|| applied = Some(record.clone()));
    let mut applied = applied.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(record, applied);
    applied.penalty_status = EvidencePenaltyStatus::Applied { height: 5 };
    assert_ne!(record, applied);
    assert!(record.shares_body(&applied));
    assert_eq!(record.penalty_status, EvidencePenaltyStatus::Pending);
    assert_eq!(
        record.evidence.native_frame().as_ptr(),
        applied.evidence.native_frame().as_ptr()
    );
    assert_eq!(
        record.attribution.offenders.as_ptr(),
        applied.attribution.offenders.as_ptr()
    );
    assert_eq!(
        record.attribution.offenders[0]
            .peer_id
            .public_key()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        applied.attribution.offenders[0]
            .peer_id
            .public_key()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr()
    );
    assert_eq!(pool.reserved_bytes(), reserved);
    drop(record);
    assert_eq!(pool.reserved_bytes(), reserved);
    drop(applied);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn retained_record_restore_proof_and_final_shell_refusals_keep_typed_original_cause() {
    let original = claim();
    let source = json::to_json(&original).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let blocker = pool.try_reserve_bytes(pool.limit_bytes()).unwrap();
    let proof_layout =
        std::alloc::Layout::array::<u8>(original.evidence.native_frame().len()).unwrap();
    let expected = pool.try_reserve(proof_layout).unwrap_err();
    let failure = parse(&source, &pool).unwrap_err();
    assert!(
        matches!(failure, EvidenceRecordRestoreError::Preparation(EvidencePreparationError::Admission(ref actual)) if actual == &expected)
    );
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(blocker);
    let shell_layout = ChargedShared::<EvidenceRecordBody>::allocation_layout();
    let (failure, refused) = refuse_one_layout_during(shell_layout, || parse(&source, &pool));
    assert!(
        refused,
        "actual final shared control allocation must be reached"
    );
    assert!(
        matches!(failure, Err(EvidenceRecordRestoreError::Preparation(EvidencePreparationError::Allocator {requested_bytes})) if requested_bytes == shell_layout.size())
    );
    assert_eq!(
        pool.reserved_bytes(),
        0,
        "partial proof/keys/vector/ledger retire before their credit"
    );
    let record = parse(&source, &pool).unwrap();
    assert!(record.body_belongs_to(&pool));
    drop(record);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn retained_record_body_rejects_equivalent_foreign_graph_pool_before_shell_allocation() {
    let original = claim();
    let source = json::to_json(&original.attribution).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(pool.limit_bytes());
    let attribution = super::super::super::evidence_history::restore_attribution(
        &mut Parser::new(&source),
        &foreign,
    )
    .unwrap();
    let mut frame = ChargedBuffer::new(original.evidence.native_frame().len(), &pool).unwrap();
    frame.append(original.evidence.native_frame()).unwrap();
    let frame_pointer = frame.as_slice().as_ptr();
    let graph_pointer = attribution.offenders.as_ptr();
    let mut frame = Some(frame);
    let mut admitted = super::super::AdmittedEvidence::from_verified(
        super::super::evidence_key(&original.evidence),
        attribution,
    );
    let mut failure = None;
    let allocations = allocations_during(|| {
        failure = Some(admitted.bind_body(&mut frame, &pool, &pool));
    });
    assert_eq!(failure.unwrap(), Err(EvidencePreparationError::Invariant));
    assert_eq!(allocations, 0);
    assert_eq!(frame.as_ref().unwrap().as_slice().as_ptr(), frame_pointer);
    assert_eq!(admitted.attribution().offenders.as_ptr(), graph_pointer);
    admitted.bind_body(&mut frame, &pool, &foreign).unwrap();
    assert!(frame.is_none());
    let mut failure = None;
    let allocations = allocations_during(|| {
        failure = Some(admitted.bind_body(&mut frame, &pool, &pool));
    });
    assert_eq!(failure.unwrap(), Err(EvidencePreparationError::Invariant));
    assert_eq!(allocations, 0);
    assert_eq!(admitted.native_frame().unwrap().as_ptr(), frame_pointer);
    let record = admitted
        .record(
            &original.evidence,
            original.recorded_at_height,
            original.recorded_at_view,
            original.recorded_at_ms,
        )
        .unwrap();
    assert!(record.proof_belongs_to(&pool));
    assert!(record.body_belongs_to(&foreign));
    assert_eq!(
        record.allocation_bytes_in(&pool),
        Some(pool.reserved_bytes())
    );
    assert_eq!(
        record.allocation_bytes_in(&foreign),
        Some(foreign.reserved_bytes())
    );
    drop(admitted);
    drop(record);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn retained_record_storage_restores_complete_current_undo_claims_without_budgetless_decode() {
    let pending = claim();
    let mut applied = pending.clone();
    applied.penalty_status = EvidencePenaltyStatus::Applied { height: 5 };
    let key = super::super::evidence_key(&pending.evidence);
    let absent = iroha_crypto::Hash::new(b"original predecessor absence");
    let ordinary = mv::storage::Storage::from_snapshot_parts(
        std::collections::BTreeMap::from([(key, applied)]),
        std::collections::BTreeMap::from([(key, Some(pending)), (absent, None)]),
    );
    let source = json::to_json(&ordinary).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let retained = restore_storage(&source, &pool).unwrap();
    let snapshot = retained.snapshot();
    let current = snapshot.current().get(&key).unwrap();
    let undo = snapshot.revert_map().get(&key).unwrap().as_ref().unwrap();
    assert_eq!(
        current.penalty_status,
        EvidencePenaltyStatus::Applied { height: 5 }
    );
    assert_eq!(undo.penalty_status, EvidencePenaltyStatus::Pending);
    assert!(current.body_belongs_to(&pool) && undo.body_belongs_to(&pool));
    assert!(current.proof_belongs_to(&pool) && undo.proof_belongs_to(&pool));
    assert_eq!(snapshot.revert_map().get(&absent), Some(&None));
    assert_eq!(json::to_json(&retained).unwrap(), source);
    drop(snapshot);
    // The enclosing original MV publication/EBR owners retain these bodies until
    // their physical readers and cursors retire; no early scratch refund is asserted.
    drop(retained);
}

#[test]
fn retained_record_restore_keeps_resource_refusal_and_canonical_negative_priority() {
    let original = claim();
    let source = json::to_json(&original).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let limits = norito::core::DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 0, 128);
    let error =
        norito::core::with_decode_limits_scope(limits, || parse(&source, &pool)).unwrap_err();
    assert!(
        matches!(error, EvidenceRecordRestoreError::Logical(ref error) if error.is_decode_resource_limit())
    );
    assert_eq!(pool.reserved_bytes(), 0);
    for source in [
        "{}",
        "{\"evidence\":{\"native\":[]}}",
        "{\"attribution\":{}}",
    ] {
        let ordinary = json::from_str::<EvidenceRecord>(source).unwrap_err();
        let restored = parse(source, &pool).unwrap_err();
        let EvidenceRecordRestoreError::Json(actual) = restored else {
            panic!("canonical failure remains syntax")
        };
        assert_eq!(actual.to_string(), ordinary.to_string());
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn retained_record_reordered_fields_preserve_canonical_values_and_first_invalid_field() {
    let original = claim();
    let evidence = json::to_json(&original.evidence).unwrap();
    let attribution = json::to_json(&original.attribution).unwrap();
    let status = json::to_json(&original.penalty_status).unwrap();
    let source = format!(
        "{{\"penalty_status\":{status},\"recorded_at_ms\":{},\"attribution\":{attribution},\"recorded_at_view\":{},\"evidence\":{evidence},\"recorded_at_height\":{}}}",
        original.recorded_at_ms, original.recorded_at_view, original.recorded_at_height,
    );
    let pool = AllocationBudget::new(1 << 20);
    let ordinary = json::from_str::<EvidenceRecord>(&source).unwrap();
    let restored = parse(&source, &pool).unwrap();
    assert_eq!(restored.canonical_projection(), ordinary);
    assert_eq!(
        json::to_json(&restored).unwrap(),
        json::to_json(&ordinary).unwrap()
    );
    drop(restored);
    assert_eq!(pool.reserved_bytes(), 0);
    // Both fields are invalid. Source order, rather than a fabricated fixed schema
    // order, selects the canonical first error and retains its failed prefix.
    for source in [
        "{\"attribution\":{},\"evidence\":{\"native\":[]}}",
        "{\"evidence\":{\"native\":[]},\"attribution\":{}}",
    ] {
        let ordinary = json::from_str::<EvidenceRecord>(source).unwrap_err();
        let restored = parse(source, &pool).unwrap_err();
        let EvidenceRecordRestoreError::Json(actual) = restored else {
            panic!("canonical first field failure remains syntax");
        };
        assert_eq!(actual.to_string(), ordinary.to_string());
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn retained_record_nested_invalid_keys_match_peer_decoder_category_and_source_order() {
    let original = claim();
    let attribution = json::to_json(&original.attribution).unwrap();
    let original_key =
        json::to_json(original.attribution.offenders[0].peer_id.public_key()).unwrap();
    let pair = iroha_crypto::KeyPair::from_seed(vec![0x91; 32], iroha_crypto::Algorithm::Secp256k1);
    let canonical = pair.public_key().to_string();
    let payload_length = pair.public_key().borrowed_parts().unwrap().1.len() * 2;
    let invalid_point = format!(
        "{}{}",
        &canonical[..canonical.len() - payload_length],
        "0".repeat(payload_length)
    );
    assert!(invalid_point.parse::<iroha_crypto::PublicKey>().is_err());
    let pool = AllocationBudget::new(1 << 20);
    for invalid in ["not-a-canonical-key", invalid_point.as_str()] {
        let invalid = json::to_json(invalid).unwrap();
        let changed = attribution.replacen(&original_key, &invalid, 1);
        assert_ne!(changed, attribution);
        for source in [
            format!("{{\"attribution\":{changed},\"evidence\":{{\"native\":[]}}}}"),
            format!("{{\"evidence\":{{\"native\":[]}},\"attribution\":{changed}}}"),
        ] {
            let ordinary = json::from_str::<EvidenceRecord>(&source).unwrap_err();
            let restored = parse(&source, &pool).unwrap_err();
            let EvidenceRecordRestoreError::Json(actual) = restored else {
                panic!("canonical invalid peer/proof remains syntax");
            };
            assert_eq!(actual.to_string(), ordinary.to_string());
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&ordinary)
            );
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
