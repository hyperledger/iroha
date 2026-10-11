//! Original commitment-array, tag, signature, ledger and control allocation custody.
use super::*;
use iroha_allocation::{
    AllocationBudget, AllocationRefusal, ChargedBuffer, ChargedBufferFromChargeError,
    SharedFromChargeError,
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    da::{
        commitment::{
            DaCommitmentBundle, DaCommitmentCustodyError, DaCommitmentRecord, DaProofScheme,
            PreparedDaCommitmentBundle,
        },
        types::{BlobDigest, GovernanceTag, RetentionPolicy, StorageTicketId},
    },
    sorafs::pin_registry::ManifestDigest,
};
use iroha_model_base::topology::LaneId;
use norito::core::SequenceSpan;

fn record(lane: u32, tag: String, signature: Signature) -> DaCommitmentRecord {
    DaCommitmentRecord {
        lane_id: LaneId::new(lane),
        epoch: 13,
        sequence: 17,
        client_blob_id: BlobDigest::new([0x11; 32]),
        manifest_hash: ManifestDigest::new([0x22; 32]),
        proof_scheme: DaProofScheme::MerkleSha256,
        chunk_root: Hash::new([0x33; 32]),
        proof_digest: Some(Hash::new([0x44; 32])),
        retention_class: RetentionPolicy {
            governance_tag: GovernanceTag::new(tag),
            ..RetentionPolicy::default()
        },
        storage_ticket: StorageTicketId::new([0x55; 32]),
        acknowledgement_sig: signature,
    }
}
fn fixture() -> DaCommitmentBundle {
    // These two nonempty variable-width signatures are transport fixtures, not
    // claimed DA authorizations. The separate 64-byte positive is actually signed.
    DaCommitmentBundle::new(vec![
        record(3, "a".repeat(11), Signature::from_bytes(&[0x61; 3])),
        record(7, "é漢🙂".repeat(3), Signature::from_bytes(&[0x72; 96])),
    ])
}
fn repeated_child_layout_fixture() -> DaCommitmentBundle {
    // Adjacent tag and signature buffers deliberately make the same actual
    // allocation request; the allocator must distinguish their request order.
    DaCommitmentBundle::new(vec![
        record(3, "a".repeat(11), Signature::from_bytes(&[0x61; 11])),
        record(7, "é漢🙂".repeat(3), Signature::from_bytes(&[0x72; 96])),
    ])
}
fn source(
    value: &DaCommitmentBundle,
    pool: &AllocationBudget,
    flags: u8,
) -> (ChargedBuffer<u8>, SequenceSpan) {
    let bytes = bare_bytes(value, flags);
    let mut source = ChargedBuffer::new(bytes.len() + 9, pool).unwrap();
    source.append(&[0xa5; 9]).unwrap();
    source.append(&bytes).unwrap();
    (
        source,
        SequenceSpan {
            start: 9,
            end: 9 + bytes.len(),
        },
    )
}
fn measured<T>(run: impl FnOnce() -> T) -> (T, usize) {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            TRACKING.with(|active| active.set(false));
        }
    }
    TRACKING.with(|active| assert!(!active.replace(true)));
    ALLOCATIONS.with(|count| count.set(0));
    let guard = Restore;
    let value = run();
    let count = ALLOCATIONS.with(Cell::get);
    drop(guard);
    (value, count)
}
fn refused<T>(layout: Layout, skip_matches: usize, run: impl FnOnce() -> T) -> T {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            REFUSE.with(|next| next.set(None));
            REFUSE_SKIP_MATCHES.with(|skip| skip.set(0));
        }
    }
    REFUSE_SKIP_MATCHES.with(|skip| assert_eq!(skip.replace(skip_matches), 0));
    REFUSE.with(|next| assert!(next.replace(Some(layout)).is_none()));
    let guard = Restore;
    let value = run();
    assert!(
        REFUSE.with(|next| next.get().is_none()),
        "exact original allocator request was not reached"
    );
    assert_eq!(REFUSE_SKIP_MATCHES.with(Cell::get), 0);
    drop(guard);
    value
}
fn child_layouts(original: &DaCommitmentBundle) -> Vec<[Layout; 2]> {
    original
        .commitments()
        .iter()
        .map(|record| {
            [
                Layout::array::<u8>(record.retention_class.governance_tag.0.len()).unwrap(),
                Layout::array::<u8>(record.acknowledgement_sig.payload().len()).unwrap(),
            ]
        })
        .collect()
}
fn retained_bytes(original: &DaCommitmentBundle, payload: &[Layout; 3]) -> usize {
    payload.iter().map(Layout::size).sum::<usize>()
        + child_layouts(original)
            .iter()
            .flatten()
            .map(Layout::size)
            .sum::<usize>()
}
fn pointers(
    pending: &PreparedDaCommitmentBundle,
    source: &ChargedBuffer<u8>,
    index: usize,
) -> [Option<*const u8>; 2] {
    [
        pending
            .initialized_tag(source, index)
            .unwrap()
            .map(<[u8]>::as_ptr),
        pending
            .initialized_signature(source, index)
            .unwrap()
            .map(<[u8]>::as_ptr),
    ]
}
fn record_pointers(record: &DaCommitmentRecord) -> [*const u8; 2] {
    [
        record.retention_class.governance_tag.0.as_ptr(),
        record.acknowledgement_sig.payload().as_ptr(),
    ]
}

#[test]
fn da_commitment_array_tag_signature_ledger_and_control_are_prepaid_and_follow_last_reader() {
    const MESSAGE: &[u8] = b"actual DA acknowledgement signing witness";
    let keypair = KeyPair::try_from_seed(vec![0x91; 32], Algorithm::Ed25519).unwrap();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let signed = Signature::new(keypair.private_key(), MESSAGE);
        assert_eq!(signed.payload().len(), 64);
        signed.verify(keypair.public_key(), MESSAGE).unwrap();
        for original in [
            fixture(),
            DaCommitmentBundle::new(Vec::new()),
            DaCommitmentBundle::new(vec![record(
                1,
                String::new(),
                Signature::from_bytes(&[0x81; 3]),
            )]),
            DaCommitmentBundle::new(vec![record(17, "genuine".to_owned(), signed)]),
        ] {
            let pool = AllocationBudget::new(1 << 20);
            let (source, span) = source(&original, &pool, flags);
            let floor = pool.reserved_bytes();
            let source_pointer = source.as_slice().as_ptr();
            let source_hash = Hash::new(source.as_slice());
            let (pending, count) =
                measured(|| PreparedDaCommitmentBundle::from_source(&source, span, &pool));
            assert_eq!(count, 0);
            let mut pending = pending.unwrap();
            let planning = pending.planning_layouts().unwrap();
            let payload = pending.payload_layouts().unwrap();
            let children = child_layouts(&original);
            let scaffold = planning.iter().map(Layout::size).sum::<usize>();
            let retained = retained_bytes(&original, &payload);
            pool.set_limit_bytes(floor + scaffold);
            let (attempt, count) = measured(|| pending.prepare(&source));
            assert!(matches!(
                attempt,
                Err(DaCommitmentCustodyError::Admission(_))
            ));
            assert_eq!(
                count,
                planning.iter().filter(|layout| layout.size() != 0).count()
            );
            assert_eq!(pool.reserved_bytes(), floor + scaffold);
            pool.set_limit_bytes(floor + scaffold + retained);
            let (filled, count) = measured(|| pending.prepare(&source));
            filled.unwrap();
            assert_eq!(
                count,
                payload.iter().filter(|layout| layout.size() != 0).count()
                    + children
                        .iter()
                        .flatten()
                        .filter(|layout| layout.size() != 0)
                        .count()
            );
            assert!(pending.belongs_to(&pool));
            assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
            let original_pointers = (0..original.commitments().len())
                .map(|index| pointers(&pending, &source, index).map(Option::unwrap))
                .collect::<Vec<_>>();
            let (same, count) = measured(|| pending.prepare(&source));
            same.unwrap();
            assert_eq!(count, 0);
            let (admitted, count) = measured(|| pending.finish(&source));
            let admitted =
                admitted.unwrap_or_else(|_| panic!("complete original commitment owner"));
            assert_eq!(count, 0);
            assert!(admitted.admitted_to(&pool));
            assert_eq!(pool.reserved_bytes(), floor + retained);
            assert_eq!(admitted, original);
            assert_eq!(
                admitted
                    .commitments()
                    .iter()
                    .map(record_pointers)
                    .collect::<Vec<_>>(),
                original_pointers
            );
            assert_eq!(
                bare_bytes(&admitted, flags),
                span.get(source.as_slice()).unwrap()
            );
            assert_eq!(
                norito::to_bytes(&admitted).unwrap(),
                norito::to_bytes(&original).unwrap()
            );
            for record in admitted
                .commitments()
                .iter()
                .filter(|record| record.lane_id == LaneId::new(17))
            {
                record
                    .acknowledgement_sig
                    .verify(keypair.public_key(), MESSAGE)
                    .unwrap();
            }
            let array = admitted.commitments().as_ptr();
            let (reader, count) = measured(|| admitted.clone());
            assert_eq!(count, 0);
            assert!(DaCommitmentBundle::ptr_eq(&reader, &admitted));
            drop(admitted);
            assert_eq!(pool.reserved_bytes(), floor + retained);
            assert_eq!(reader.commitments().as_ptr(), array);
            assert_eq!(
                reader
                    .commitments()
                    .iter()
                    .map(record_pointers)
                    .collect::<Vec<_>>(),
                original_pointers
            );
            assert_eq!(source.as_slice().as_ptr(), source_pointer);
            assert_eq!(Hash::new(source.as_slice()), source_hash);
            drop(reader);
            assert_eq!(pool.reserved_bytes(), floor);
            drop(source);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn da_commitment_every_physical_refusal_retains_pending_charges_and_empty_original_siblings() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for original in [fixture(), repeated_child_layout_fixture()] {
            for selected in 0..9 {
                let pool = AllocationBudget::new(1 << 20);
                let foreign = AllocationBudget::new(1 << 20);
                let (source, span) = source(&original, &pool, flags);
                let floor = pool.reserved_bytes();
                let source_pointer = source.as_slice().as_ptr();
                let source_hash = Hash::new(source.as_slice());
                let mut pending =
                    PreparedDaCommitmentBundle::from_source(&source, span, &pool).unwrap();
                let planning = pending.planning_layouts().unwrap();
                let payload = pending.payload_layouts().unwrap();
                let children = child_layouts(&original);
                let first_signature = original.commitments()[0]
                    .acknowledgement_sig
                    .payload()
                    .len();
                assert!(matches!(first_signature, 3 | 11));
                assert_eq!(
                    children[0].map(|layout| layout.size()),
                    [11, first_signature]
                );
                if first_signature == 11 {
                    assert_eq!(children[0][0], children[0][1]);
                }
                assert_eq!(children[1].map(|layout| layout.size()), [27, 96]);
                let layouts = [
                    planning[0],
                    planning[1],
                    payload[0],
                    payload[1],
                    children[0][0],
                    children[0][1],
                    children[1][0],
                    children[1][1],
                    payload[2],
                ];
                assert!(layouts.iter().all(|layout| layout.size() != 0));
                // Refuse each preceding request first. Its successful retry advances
                // exactly one physical owner and proves every prior sibling survives.
                for index in 0..=selected {
                    // Only the immediately preceding refused owner remains pending.
                    // Its retry comes first; skip that exact layout match when the
                    // following original owner requests the same size AND alignment.
                    let skip_matches =
                        usize::from(index > 0 && layouts[index - 1] == layouts[index]);
                    let (attempt, count) = measured(|| {
                        refused(layouts[index], skip_matches, || pending.prepare(&source))
                    });
                    let error = attempt.unwrap_err();
                    assert_eq!(count, if index == 0 { 1 } else { 2 });
                    if index == 8 {
                        assert!(matches!(error, DaCommitmentCustodyError::Control(
                        SharedFromChargeError::Allocator { layout }) if layout == layouts[index]));
                    } else {
                        assert!(matches!(error, DaCommitmentCustodyError::Buffer(
                        ChargedBufferFromChargeError::Allocator { layout }) if layout == layouts[index]));
                    }
                    let expected = if index < 2 {
                        planning.iter().map(Layout::size).sum::<usize>()
                    } else {
                        layouts.iter().map(Layout::size).sum::<usize>()
                    };
                    assert_eq!(pool.reserved_bytes(), floor + expected);
                    assert!(pending.belongs_to(&pool));
                    assert!(!pending.belongs_to(&foreign));
                    for row in 0..2 {
                        for initialized in [
                            pending.initialized_tag(&source, row).unwrap(),
                            pending.initialized_signature(&source, row).unwrap(),
                        ]
                        .into_iter()
                        .flatten()
                        {
                            assert!(
                                initialized.is_empty(),
                                "no child fill before all nine original owners exist"
                            );
                        }
                    }
                    assert_eq!(source.as_slice().as_ptr(), source_pointer);
                    assert_eq!(Hash::new(source.as_slice()), source_hash);
                }
                let old_pointers: [[Option<*const u8>; 2]; 2] =
                    std::array::from_fn(|index| pointers(&pending, &source, index));
                let all_bytes = layouts.iter().map(Layout::size).sum::<usize>();
                pool.set_limit_bytes(floor + all_bytes);
                let (retry, count) = measured(|| pending.prepare(&source));
                retry.unwrap();
                assert_eq!(count, layouts.len() - selected);
                assert_eq!(pool.reserved_bytes(), floor + all_bytes);
                for (index, previous) in old_pointers.into_iter().enumerate() {
                    let now = pointers(&pending, &source, index);
                    for (old, current) in previous.into_iter().zip(now) {
                        if let Some(old) = old {
                            assert_eq!(current, Some(old));
                        }
                    }
                }
                let complete_pointers: [[*const u8; 2]; 2] = std::array::from_fn(|index| {
                    pointers(&pending, &source, index).map(Option::unwrap)
                });
                let (admitted, count) = measured(|| pending.finish(&source));
                let admitted =
                    admitted.unwrap_or_else(|_| panic!("same original commitment retry"));
                assert_eq!(count, 0);
                assert_eq!(admitted, original);
                assert!(admitted.admitted_to(&pool));
                assert_eq!(
                    admitted
                        .commitments()
                        .iter()
                        .map(record_pointers)
                        .collect::<Vec<_>>(),
                    complete_pointers
                );
                let retained = retained_bytes(&original, &payload);
                assert_eq!(pool.reserved_bytes(), floor + retained);
                assert_eq!(
                    bare_bytes(&admitted, flags),
                    span.get(source.as_slice()).unwrap()
                );
                assert_eq!(
                    norito::to_bytes(&admitted).unwrap(),
                    norito::to_bytes(&original).unwrap()
                );
                assert_eq!(source.as_slice().as_ptr(), source_pointer);
                assert_eq!(Hash::new(source.as_slice()), source_hash);
                let (reader, count) = measured(|| admitted.clone());
                assert_eq!(count, 0);
                assert!(DaCommitmentBundle::ptr_eq(&reader, &admitted));
                let array_pointer = reader.commitments().as_ptr();
                drop(admitted);
                assert_eq!(pool.reserved_bytes(), floor + retained);
                assert_eq!(reader.commitments().as_ptr(), array_pointer);
                assert_eq!(
                    reader
                        .commitments()
                        .iter()
                        .map(record_pointers)
                        .collect::<Vec<_>>(),
                    complete_pointers
                );
                drop(reader);
                assert_eq!(pool.reserved_bytes(), floor);
                drop(source);
                assert_eq!(pool.reserved_bytes(), 0);
                assert_eq!(foreign.reserved_bytes(), 0);
            }
        }
    }
}

#[test]
fn da_commitment_original_pool_source_layout_incomplete_finish_and_capacity_fail_closed() {
    let flags = header_flags::COMPACT_LEN;
    let _flags = DecodeFlagsGuard::enter(flags);
    let original = fixture();
    let pool = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let (mut source, span) = source(&original, &pool, flags);
    let (copy, _) = self::source(&original, &pool, flags);
    let (other, _) = self::source(&original, &foreign, flags);
    let floor = pool.reserved_bytes();
    let foreign_floor = foreign.reserved_bytes();
    let source_pointer = source.as_slice().as_ptr();
    let source_hash = Hash::new(source.as_slice());
    assert_eq!(copy.as_slice(), source.as_slice());
    assert_eq!(other.as_slice(), source.as_slice());
    assert_ne!(copy.as_slice().as_ptr(), source_pointer);
    let (attempt, count) =
        measured(|| PreparedDaCommitmentBundle::from_source(&other, span, &pool));
    assert_eq!(count, 0);
    assert!(matches!(
        attempt,
        Err(DaCommitmentCustodyError::ForeignPool)
    ));
    assert_eq!(pool.reserved_bytes(), floor);
    assert_eq!(foreign.reserved_bytes(), foreign_floor);
    let (attempt, count) = measured(|| {
        PreparedDaCommitmentBundle::from_source(
            &source,
            SequenceSpan {
                start: span.start,
                end: source.as_slice().len() + 1,
            },
            &pool,
        )
    });
    assert_eq!(count, 0);
    assert!(matches!(
        attempt,
        Err(DaCommitmentCustodyError::SourceRange)
    ));
    assert_eq!(pool.reserved_bytes(), floor);
    let mut pending = PreparedDaCommitmentBundle::from_source(&source, span, &pool).unwrap();
    let (attempt, count) = measured(|| pending.prepare(&other));
    assert_eq!(count, 0);
    assert!(matches!(
        attempt,
        Err(DaCommitmentCustodyError::ForeignPool)
    ));
    let (attempt, count) = measured(|| pending.prepare(&copy));
    assert_eq!(count, 0);
    assert!(matches!(
        attempt,
        Err(DaCommitmentCustodyError::SourceChanged)
    ));
    {
        let _other_flags = DecodeFlagsGuard::enter(0);
        let (attempt, count) = measured(|| pending.prepare(&source));
        assert_eq!(count, 0);
        assert!(matches!(
            attempt,
            Err(DaCommitmentCustodyError::LayoutChanged)
        ));
    }
    source.as_mut_slice()[span.start] ^= 1;
    let (attempt, count) = measured(|| pending.prepare(&source));
    assert_eq!(count, 0);
    assert!(matches!(
        attempt,
        Err(DaCommitmentCustodyError::SourceChanged)
    ));
    source.as_mut_slice()[span.start] ^= 1;
    assert_eq!(Hash::new(source.as_slice()), source_hash);
    let (attempt, count) = measured(|| pending.finish(&source));
    assert_eq!(count, 0);
    let Err((mut pending, error)) = attempt else {
        panic!("actual unfinished original owner");
    };
    assert!(matches!(error, DaCommitmentCustodyError::Incomplete));
    assert_eq!(pool.reserved_bytes(), floor);
    let scaffold = pending
        .planning_layouts()
        .unwrap()
        .iter()
        .map(Layout::size)
        .sum::<usize>();
    let payload = pending.payload_layouts().unwrap();
    let retained = retained_bytes(&original, &payload);
    let limit = floor + scaffold + retained - 1;
    pool.set_limit_bytes(limit);
    let (attempt, count) = measured(|| pending.prepare(&source));
    assert_eq!(count, 2);
    let error = attempt.unwrap_err();
    assert!(
        matches!(error, DaCommitmentCustodyError::Admission(AllocationRefusal::Capacity {
        requested_bytes, reserved_bytes, limit_bytes, ..
    }) if requested_bytes == retained && reserved_bytes == floor + scaffold && limit_bytes == limit)
    );
    assert_eq!(pool.reserved_bytes(), floor + scaffold);
    for index in 0..2 {
        assert!(pending.initialized_tag(&source, index).unwrap().is_none());
        assert!(
            pending
                .initialized_signature(&source, index)
                .unwrap()
                .is_none()
        );
    }
    let (attempt, count) = measured(|| pending.finish(&source));
    assert_eq!(count, 0);
    let Err((mut pending, error)) = attempt else {
        panic!("actual admitted planning owner remains incomplete");
    };
    assert!(matches!(error, DaCommitmentCustodyError::Incomplete));
    assert_eq!(pool.reserved_bytes(), floor + scaffold);
    pool.set_limit_bytes(floor + scaffold + retained);
    let (retry, count) = measured(|| pending.prepare(&source));
    retry.unwrap();
    assert_eq!(count, 7);
    let occupied = pool.reserved_bytes();
    let original_pointers: [[Option<*const u8>; 2]; 2] =
        std::array::from_fn(|index| pointers(&pending, &source, index));
    let (attempt, count) = measured(|| pending.finish(&copy));
    assert_eq!(count, 0);
    let Err((pending, error)) = attempt else {
        panic!("changed-owner finish returns every original child");
    };
    assert!(matches!(error, DaCommitmentCustodyError::SourceChanged));
    assert!(pending.belongs_to(&pool));
    assert_eq!(pool.reserved_bytes(), occupied);
    for (index, expected) in original_pointers.into_iter().enumerate() {
        assert_eq!(pointers(&pending, &source, index), expected);
    }
    let (admitted, count) = measured(|| pending.finish(&source));
    let admitted = admitted.unwrap_or_else(|_| panic!("original complete source retry"));
    assert_eq!(count, 0);
    assert_eq!(admitted, original);
    assert_eq!(
        admitted
            .commitments()
            .iter()
            .map(record_pointers)
            .collect::<Vec<_>>(),
        original_pointers.map(|row| row.map(Option::unwrap))
    );
    assert_eq!(
        bare_bytes(&admitted, flags),
        span.get(source.as_slice()).unwrap()
    );
    assert_eq!(pool.reserved_bytes(), floor + retained);
    assert_eq!(source.as_slice().as_ptr(), source_pointer);
    assert_eq!(Hash::new(source.as_slice()), source_hash);
    drop(admitted);
    assert_eq!(pool.reserved_bytes(), floor);
    drop((source, copy, other));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}
