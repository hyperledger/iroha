//! Parent-QC byte/JSON parity, exact finite-pool refusal and original full-source controls.
use super::*;
use norito::{
    SerializePayload,
    core::{DecodeFlagsGuard, Encoder, header_flags},
};
fn bytes(value: &impl SerializePayload) -> Vec<u8> {
    let mut output = Vec::new();
    value
        .serialize(&mut Encoder::for_buffer(&mut output))
        .unwrap();
    output
}
fn source(value: &[u8], pool: &AllocationBudget) -> (ChargedBuffer<u8>, SequenceSpan) {
    let encoded = bytes(&value);
    let mut input = ChargedBuffer::new(encoded.len() + 7, pool).unwrap();
    input.append(&[0xa5; 7]).unwrap();
    input.append(&encoded).unwrap();
    (
        input,
        SequenceSpan {
            start: 7,
            end: 7 + encoded.len(),
        },
    )
}
#[test]
fn parent_service_owner_keeps_vec_wire_json_and_exact_admitted_clone() {
    use iroha_schema::{IntoSchema, MetaMap, TypeId};
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for original in [vec![], vec![0, 17, 127, 255]] {
            let untrusted = NposParentServiceCommitQc::from_untrusted(original.clone());
            assert!(untrusted.admitted_source().is_none());
            assert_eq!(bytes(&untrusted), bytes(&original));
            let encoded = bytes(&untrusted);
            let (decoded, used) = NposParentServiceCommitQc::decode_from_slice(&encoded).unwrap();
            assert_eq!(used, encoded.len());
            assert_eq!(decoded.as_slice(), original);
            assert_eq!(
                <NposParentServiceCommitQc as TypeId>::id(),
                <Vec<u8> as TypeId>::id()
            );
            let mut schema = MetaMap::new();
            NposParentServiceCommitQc::update_schema_map(&mut schema);
            Vec::<u8>::update_schema_map(&mut schema);
            assert_eq!(
                schema.get::<NposParentServiceCommitQc>(),
                schema.get::<Vec<u8>>()
            );
            let pool = AllocationBudget::new(1 << 16);
            let (input, span) = source(&original, &pool);
            let floor = pool.reserved_bytes();
            let mut pending =
                PreparedParentServiceCommitQc::from_source(&input, span, &pool).unwrap();
            pending.prepare(&input).unwrap();
            let pointer = pending.initialized(&input).unwrap().unwrap().as_ptr();
            let admitted = pending
                .finish(&input)
                .unwrap_or_else(|(_, error)| panic!("{error}"));
            let clone = admitted.clone();
            assert!(
                NposParentServiceCommitQc::ptr_eq(&admitted, &clone),
                "parent-QC clone must retain the original immutable byte owner"
            );
            assert_eq!(clone.as_slice().as_ptr(), pointer);
            assert!(clone.admitted_to(&pool));
            let source = clone.admitted_source().unwrap();
            assert_eq!(source.as_slice().as_ptr(), pointer);
            assert!(source.belongs_to(&pool));
            assert!(ChargedBuffer::belongs_to(source, &pool));
            assert!(ChargedShared::ptr_eq(
                source,
                admitted.admitted_source().unwrap()
            ));
            let json = norito::json::to_json(&original).unwrap();
            assert_eq!(norito::json::to_json(&admitted).unwrap(), json);
            assert_eq!(
                norito::json::to_json_bounded(&admitted, json.len()).unwrap(),
                json
            );
            assert_eq!(
                norito::json::to_json_bounded(&admitted, json.len() - 1),
                Err(norito::json::BoundedJsonError::BodyTooLarge)
            );
            assert_eq!(
                norito::json::from_json::<NposParentServiceCommitQc>(&json)
                    .unwrap()
                    .as_slice(),
                original
            );
            let value = norito::json::to_value(&admitted).unwrap();
            assert_eq!(
                <NposParentServiceCommitQc as norito::json::JsonDeserialize>::json_from_value(
                    &value
                )
                .unwrap()
                .as_slice(),
                original
            );
            drop(admitted);
            assert_eq!(clone.as_slice().as_ptr(), pointer);
            drop(clone);
            assert_eq!(pool.reserved_bytes(), floor);
            drop(input);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
#[test]
fn parent_service_source_and_capacity_retry_preserve_original_full_frame_pool_and_layout() {
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let pool = AllocationBudget::new(1 << 16);
    let (mut input, span) = source(&[7; 31], &pool);
    let floor = pool.reserved_bytes();
    let mut owner = PreparedParentServiceCommitQc::from_source(&input, span, &pool).unwrap();
    let demanded = owner
        .allocation_layouts()
        .unwrap()
        .iter()
        .map(Layout::size)
        .sum::<usize>();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - floor - demanded + 1)
        .unwrap();
    let Err(Error::Admission(first)) = owner.prepare(&input) else {
        panic!("actual parent-QC combined admission")
    };
    assert!(
        matches!(&first, AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. } if *requested_bytes==demanded && *reserved_bytes==pool.limit_bytes()-demanded+1 && *limit_bytes==pool.limit_bytes())
    );
    assert!(owner.initialized(&input).unwrap().is_none());
    let Err(Error::Admission(repeat)) = owner.prepare(&input) else {
        panic!("same parent-QC original refusal")
    };
    assert_eq!(first, repeat);
    assert_eq!(pool.limit_bytes(), 1 << 16);
    assert!(owner.belongs_to(&pool));
    drop(blocker);
    owner.prepare(&input).unwrap();
    let pointer = owner.initialized(&input).unwrap().unwrap().as_ptr();
    let occupied = pool.reserved_bytes();
    input.as_mut_slice()[0] ^= 1;
    assert!(
        matches!(owner.prepare(&input), Err(Error::SourceChanged)),
        "parent-QC custody must bind bytes outside the selected field"
    );
    let (mut owner, cause) = owner.finish(&input).err().unwrap();
    assert!(matches!(cause, Error::SourceChanged));
    assert_eq!(pool.reserved_bytes(), occupied);
    input.as_mut_slice()[0] ^= 1;
    assert_eq!(
        owner.initialized(&input).unwrap().unwrap().as_ptr(),
        pointer
    );
    let (copy, _) = source(&[7; 31], &pool);
    assert!(matches!(owner.prepare(&copy), Err(Error::SourceChanged)));
    let foreign_pool = AllocationBudget::new(1 << 16);
    let (foreign, _) = source(&[7; 31], &foreign_pool);
    assert!(matches!(owner.prepare(&foreign), Err(Error::ForeignPool)));
    {
        let _flags = DecodeFlagsGuard::enter(0);
        assert!(matches!(owner.prepare(&input), Err(Error::LayoutChanged)));
    }
    let admitted = owner
        .finish(&input)
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    assert_eq!(admitted.as_slice(), &[7; 31]);
    assert_eq!(admitted.as_slice().as_ptr(), pointer);
    drop((admitted, copy, foreign, input));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign_pool.reserved_bytes(), 0);
}

fn native_parent(pool: &AllocationBudget) -> SharedSignedBlock {
    use crate::block::{BlockHeader, BlockSignature, CommitCertificate, SignedBlock};
    use iroha_crypto::{Signature, SignatureOf};
    let block = SignedBlock::presigned(
        BlockSignature::new(
            0,
            SignatureOf::from_signature(Signature::try_from_bytes(&[0x35; 64]).unwrap()),
        ),
        BlockHeader::new(std::num::NonZeroU64::new(2).unwrap(), None, None, 1_000, 0),
        Vec::new(),
    )
    .with_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        vec![1, 2],
        vec![0x17; 73],
        vec![3, 4],
        vec![5, 6],
    )));
    SharedSignedBlock::try_new(block, pool).unwrap()
}

#[test]
fn producer_copy_binds_actual_parent_control_pool_and_unchanged_vec_wire() {
    let pool = AllocationBudget::new(1 << 20);
    let parent = native_parent(&pool);
    let replacement = SharedSignedBlock::try_new(parent.as_ref().clone(), &pool).unwrap();
    assert_eq!(
        parent.encode_wire().unwrap(),
        replacement.encode_wire().unwrap()
    );
    let foreign = AllocationBudget::new(pool.limit_bytes());
    let baseline = pool.reserved_bytes();
    let mut pending = PreparedParentServiceCommitQc::from_parent(&parent, &pool).unwrap();
    assert_eq!(
        pool.reserved_bytes(),
        baseline,
        "initial copy shares only the original block control"
    );
    assert!(
        matches!(
            pending.prepare_parent(&replacement, &pool),
            Err(Error::SourceChanged)
        ),
        "producer copy must bind the actual original parent control"
    );
    assert!(matches!(
        pending.prepare_parent(&parent, &foreign),
        Err(Error::ForeignPool)
    ));
    assert!(matches!(
        PreparedParentServiceCommitQc::from_parent(&parent, &foreign),
        Err(Error::ForeignPool)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    let layouts = pending.allocation_layouts().unwrap();
    let demand: usize = layouts.iter().map(Layout::size).sum();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - baseline - demand + 1)
        .unwrap();
    let first = pending.prepare_parent(&parent, &pool).unwrap_err();
    let Error::Admission(original @ AllocationRefusal::Capacity { .. }) = first else {
        panic!("exact original pool capacity refusal")
    };
    assert!(
        matches!(&original, AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. }
        if *requested_bytes == demand && *reserved_bytes == pool.limit_bytes() - demand + 1 && *limit_bytes == pool.limit_bytes())
    );
    let Error::Admission(retry) = pending.prepare_parent(&parent, &pool).unwrap_err() else {
        panic!("same original capacity refusal")
    };
    assert_eq!(retry, original);
    assert!(
        pending
            .initialized_parent(&parent, &pool)
            .unwrap()
            .is_none()
    );
    assert!(pending.belongs_to(&pool));
    drop(blocker);
    pending.prepare_parent(&parent, &pool).unwrap();
    let pointer = pending
        .initialized_parent(&parent, &pool)
        .unwrap()
        .unwrap()
        .as_ptr();
    let (pending, error) = pending.finish_parent(&replacement, &pool).err().unwrap();
    assert!(matches!(error, Error::SourceChanged));
    let complete = pending
        .finish_parent(&parent, &pool)
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    assert_eq!(complete.as_slice().as_ptr(), pointer);
    let clone = complete.clone();
    assert!(NposParentServiceCommitQc::ptr_eq(&clone, &complete));
    assert!(clone.admitted_to(&pool));
    assert_eq!(pool.reserved_bytes(), baseline + demand);
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        assert_eq!(
            bytes(&complete),
            bytes(&parent.commit_certificate().unwrap().commit_qc())
        );
    }
    assert_eq!(
        norito::json::to_json(&complete).unwrap(),
        norito::json::to_json(&parent.commit_certificate().unwrap().commit_qc().to_vec()).unwrap()
    );
    drop(complete);
    assert_eq!(pool.reserved_bytes(), baseline + demand);
    drop(clone);
    assert_eq!(pool.reserved_bytes(), baseline);
    drop((parent, replacement));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn producer_input_cannot_substitute_a_canonical_field_or_missing_certificate() {
    let pool = AllocationBudget::new(1 << 20);
    let parent = native_parent(&pool);
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let (input, span) = source(parent.commit_certificate().unwrap().commit_qc(), &pool);
    let mut field = PreparedParentServiceCommitQc::from_source(&input, span, &pool).unwrap();
    let mut producer = PreparedParentServiceCommitQc::from_parent(&parent, &pool).unwrap();
    assert!(matches!(
        field.prepare_parent(&parent, &pool),
        Err(Error::SourceChanged)
    ));
    assert!(matches!(
        producer.prepare(&input),
        Err(Error::SourceChanged)
    ));
    let missing =
        SharedSignedBlock::try_new(parent.as_ref().clone().with_commit_certificate(None), &pool)
            .unwrap();
    assert!(matches!(
        PreparedParentServiceCommitQc::from_parent(&missing, &pool),
        Err(Error::SourceRange)
    ));
    // Raw parent bytes are already a field value; no inherited Norito layout is guessed.
    drop(_flags);
    producer.prepare_parent(&parent, &pool).unwrap();
    assert_eq!(
        producer
            .initialized_parent(&parent, &pool)
            .unwrap()
            .unwrap(),
        parent.commit_certificate().unwrap().commit_qc()
    );
}
