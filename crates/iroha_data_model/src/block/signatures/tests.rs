//! Canonical ordered signature bytes, original source identity and retained physical custody.
use super::*;
use iroha_crypto::Signature;
use norito::{
    SerializePayload,
    core::{
        DecodeAttemptErrorKind, DecodeFlagsGuard, DecodeLimits, header_flags,
        with_decode_limits_measured, with_decode_limits_scope,
    },
};
fn signature(index: u64, width: usize) -> BlockSignature {
    BlockSignature::new(
        index,
        SignatureOf::from_signature(
            Signature::try_from_bytes(&vec![u8::try_from(index + 1).unwrap(); width]).unwrap(),
        ),
    )
}
fn sample(count: usize) -> BlockSignatures {
    BlockSignatures::try_from_iter((0..count).map(|index| signature(index as u64, 64))).unwrap()
}
fn source_for(
    values: &impl SerializePayload,
    pool: &AllocationBudget,
) -> (ChargedBuffer<u8>, SequenceSpan) {
    source_for_flags(values, pool, 0)
}
fn source_for_flags(
    values: &impl SerializePayload,
    pool: &AllocationBudget,
    flags: u8,
) -> (ChargedBuffer<u8>, SequenceSpan) {
    // Fixture payloads explicitly select the layout installed by their enclosing test.
    // Decoder plan() uses flags 0; the two-layout wire control passes its own
    // exact layout here and retains that same guard for both decode paths.
    let _flags = DecodeFlagsGuard::enter(flags);
    let mut wire = Vec::new();
    values
        .serialize(&mut Encoder::for_buffer(&mut wire))
        .unwrap();
    let mut source = ChargedBuffer::new(wire.len() + 8, pool).unwrap();
    source.append(&[0xe1; 8]).unwrap();
    source.append(&wire).unwrap();
    (
        source,
        SequenceSpan {
            start: 8,
            end: 8 + wire.len(),
        },
    )
}
fn plan(
    source: &ChargedBuffer<u8>,
    span: SequenceSpan,
    pool: &AllocationBudget,
) -> PreparedBlockSignatures {
    let _flags = DecodeFlagsGuard::enter(0);
    PreparedBlockSignatures::from_source(source, span, pool).unwrap()
}
fn finish(value: PreparedBlockSignatures, source: &ChargedBuffer<u8>) -> BlockSignatures {
    value
        .finish(source)
        .unwrap_or_else(|(_, error)| panic!("{error}"))
}
fn backing(count: usize) -> usize {
    BlockSignatures::backing_layouts(count)
        .unwrap()
        .iter()
        .map(Layout::size)
        .sum()
}
#[test]
fn bounded_signature_construction_roundtrips_the_maximum_and_rejects_an_additional_distinct_value()
{
    let maximum =
        BlockSignatures::try_from_iter((0..CAP).rev().map(|index| signature(index as u64, 64)))
            .unwrap();
    assert_eq!(maximum, sample(CAP));
    assert_eq!(maximum.len(), CAP);
    let json = norito::json::to_json(&maximum).unwrap();
    assert_eq!(
        norito::json::from_json::<BlockSignatures>(&json).unwrap(),
        maximum
    );
    let wire = norito::to_bytes(&maximum).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<BlockSignatures>(&wire).unwrap(),
        maximum
    );
    assert!(matches!(
        BlockSignatures::try_from_iter((0..=CAP).map(|index| signature(index as u64, 64))),
        Err(norito::Error::NonCanonicalEncoding)
    ));
    let oversized = (0..=CAP)
        .map(|index| signature(index as u64, 64))
        .collect::<Vec<_>>();
    assert!(
        norito::json::from_json::<BlockSignatures>(&norito::json::to_json(&oversized).unwrap())
            .is_err()
    );
}
#[test]
fn bounded_signature_construction_deduplicates_without_unbounded_reservation_or_consumption() {
    use std::cell::Cell;

    struct Input<'a> {
        consumed: &'a Cell<usize>,
        indices: std::vec::IntoIter<u64>,
    }
    impl Iterator for Input<'_> {
        type Item = BlockSignature;
        fn next(&mut self) -> Option<Self::Item> {
            let index = self.indices.next()?;
            self.consumed.set(self.consumed.get() + 1);
            Some(signature(index, 64))
        }
        fn size_hint(&self) -> (usize, Option<usize>) {
            (0, Some(usize::MAX))
        }
    }

    let consumed = Cell::new(0);
    let maximum = BlockSignatures::try_from_iter(Input {
        consumed: &consumed,
        indices: (0..CAP as u64)
            .rev()
            .chain([0, (CAP - 1) as u64])
            .collect::<Vec<_>>()
            .into_iter(),
    })
    .unwrap();
    assert_eq!(consumed.get(), CAP + 2);
    assert_eq!(maximum, sample(CAP));
    let Storage::Untrusted(values) = &maximum.storage else {
        panic!("ordinary construction must remain untrusted");
    };
    assert_eq!(values.capacity(), CAP);
    let empty = BlockSignatures::try_from_iter(std::iter::empty()).unwrap();
    let Storage::Untrusted(values) = &empty.storage else {
        panic!("empty ordinary construction must remain untrusted");
    };
    assert_eq!(values.capacity(), 0);

    consumed.set(0);
    let oversized = BlockSignatures::try_from_iter(Input {
        consumed: &consumed,
        indices: (0..CAP as u64)
            .chain([0, CAP as u64, CAP as u64 + 1])
            .collect::<Vec<_>>()
            .into_iter(),
    });
    assert!(matches!(
        oversized,
        Err(norito::Error::NonCanonicalEncoding)
    ));
    assert_eq!(consumed.get(), CAP + 2);
}
#[test]
fn ordered_signature_wire_is_the_single_canonical_sequence_for_every_global_committee() {
    for count in [0, 1, 4, 7, 31] {
        let pool = AllocationBudget::new(65536);
        let original = sample(count);
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            let (source, span) = source_for_flags(&original, &pool, flags);
            let bytes = span.get(source.as_slice()).unwrap();
            let mut expected = Vec::new();
            original
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .serialize(&mut Encoder::for_buffer(&mut expected))
                .unwrap();
            assert_eq!(bytes, expected);
            assert_eq!(
                norito::core::SerializePayload::encoded_len_exact(&original),
                Some(bytes.len())
            );
            assert_eq!(
                norito::core::SerializePayload::encoded_len_hint(&original),
                Some(bytes.len())
            );
            let (decoded, used) = BlockSignatures::decode_from_slice(bytes).unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(decoded, original);
            assert!(!decoded.admitted_to(&pool));
            let mut prepared = PreparedBlockSignatures::from_source(&source, span, &pool).unwrap();
            prepared.prepare(&source).unwrap();
            let admitted = finish(prepared, &source);
            assert_eq!(admitted, original);
            assert!(admitted.admitted_to(&pool));
            assert_eq!(
                norito::json::to_json(&admitted).unwrap(),
                norito::json::to_json(&original).unwrap()
            );
            let expected_json =
                norito::json::to_json(&original.iter().cloned().collect::<Vec<BlockSignature>>())
                    .unwrap();
            assert_eq!(norito::json::to_json(&admitted).unwrap(), expected_json);
            assert_eq!(
                norito::json::to_json_bounded(&admitted, expected_json.len()).unwrap(),
                expected_json
            );
            assert_eq!(
                norito::json::to_json_bounded_boxed(&admitted, expected_json.len())
                    .unwrap()
                    .as_ref(),
                expected_json.as_bytes()
            );
            assert!(matches!(
                norito::json::to_json_bounded(&admitted, expected_json.len() - 1),
                Err(norito::json::BoundedJsonError::BodyTooLarge)
            ));
            assert_eq!(
                norito::json::from_json::<BlockSignatures>(
                    &norito::json::to_json(&admitted).unwrap()
                )
                .unwrap(),
                original
            );
        }
    }
}
#[test]
fn retained_signature_collection_shares_every_original_byte_charge_and_rejects_downgrade() {
    let pool = AllocationBudget::new(65536);
    let original = sample(4);
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let mut prepared = plan(&source, span, &pool);
    assert_eq!(pool.reserved_bytes(), floor);
    prepared.prepare(&source).unwrap();
    let pointers = prepared
        .initialized(&source)
        .unwrap()
        .iter()
        .map(|sig| sig.signature().payload().as_ptr())
        .collect::<Vec<_>>();
    assert_eq!(pool.reserved_bytes(), floor + backing(4) + 256);
    prepared.prepare(&source).unwrap();
    let mut owner = finish(prepared, &source);
    let clone = owner.clone();
    assert_eq!(
        pool.reserved_bytes(),
        floor + backing(4) + 256 + BlockSignatures::allocation_layout().size()
    );
    assert!(owner.try_insert(signature(8, 64)).is_err());
    assert!(!owner.permits_replacement(&original));
    let foreign = AllocationBudget::new(65536);
    assert!(!owner.admitted_to(&foreign));
    assert!(owner.permits_replacement(&clone));
    assert!(BlockSignatures::ptr_eq(&owner, &clone));
    assert!(!BlockSignatures::ptr_eq(&owner, &original));
    assert_eq!(
        clone
            .iter()
            .map(|sig| sig.signature().payload().as_ptr())
            .collect::<Vec<_>>(),
        pointers
    );
    drop(owner);
    assert!(clone.admitted_to(&pool));
    drop(clone);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn signature_preparation_keeps_exact_prefix_across_byte_and_control_capacity_refusal() {
    let pool = AllocationBudget::new(65536);
    let original = sample(4);
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - floor - backing(4) - 64)
        .unwrap();
    let mut prepared = plan(&source, span, &pool);
    let error = prepared.prepare(&source).unwrap_err();
    assert!(matches!(
        error,
        BlockSignatureCustodyError::Buffer(ChargedBufferError::Admission(
            AllocationRefusal::Capacity {
                requested_bytes: 64,
                ..
            }
        ))
    ));
    let pointer = prepared.initialized(&source).unwrap()[0]
        .signature()
        .payload()
        .as_ptr();
    assert_eq!(prepared.initialized(&source).unwrap().len(), 1);
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(blocker);
    prepared.prepare(&source).unwrap();
    assert_eq!(
        prepared.initialized(&source).unwrap()[0]
            .signature()
            .payload()
            .as_ptr(),
        pointer
    );
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let (prepared, error) = match prepared.finish(&source) {
        Ok(_) => panic!("occupied control"),
        Err(value) => value,
    };
    assert!(
        matches!(error,BlockSignatureCustodyError::ControlAdmission(AllocationRefusal::Capacity{requested_bytes,..}) if requested_bytes==BlockSignatures::allocation_layout().size())
    );
    assert_eq!(
        prepared.initialized(&source).unwrap()[0]
            .signature()
            .payload()
            .as_ptr(),
        pointer
    );
    drop(blocker);
    let owner = finish(prepared, &source);
    assert_eq!(owner.as_slice()[0].signature().payload().as_ptr(), pointer);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), floor);
}
#[test]
fn signature_preparation_rejects_foreign_rebound_and_changed_whole_original_source() {
    let pool = AllocationBudget::new(65536);
    let foreign = AllocationBudget::new(65536);
    let original = sample(4);
    let (mut source, span) = source_for(&original, &pool);
    let (copy, _) = source_for(&original, &pool);
    let (other, _) = source_for(&original, &foreign);
    let _flags = DecodeFlagsGuard::enter(0);
    assert!(matches!(
        PreparedBlockSignatures::from_source(&source, span, &foreign),
        Err(BlockSignatureCustodyError::ForeignPool)
    ));
    let mut prepared = plan(&source, span, &pool);
    assert!(matches!(
        prepared.prepare(&copy),
        Err(BlockSignatureCustodyError::SourceChanged)
    ));
    assert!(matches!(
        prepared.prepare(&other),
        Err(BlockSignatureCustodyError::ForeignPool)
    ));
    source.as_mut_slice()[0] ^= 1;
    assert!(matches!(
        prepared.prepare(&source),
        Err(BlockSignatureCustodyError::SourceChanged)
    ));
    source.as_mut_slice()[0] ^= 1;
    prepared.prepare(&source).unwrap();
    source.as_mut_slice()[0] ^= 1;
    let (prepared, error) = match prepared.finish(&source) {
        Ok(_) => panic!("changed frame"),
        Err(value) => value,
    };
    assert!(matches!(error, BlockSignatureCustodyError::SourceChanged));
    source.as_mut_slice()[0] ^= 1;
    drop(finish(prepared, &source));
}
#[test]
fn signature_sequence_rejects_duplicate_reordered_oversized_and_invalid_children() {
    let pool = AllocationBudget::new(65536);
    let _flags = DecodeFlagsGuard::enter(0);
    for values in [
        vec![signature(0, 64), signature(0, 64)],
        vec![signature(1, 64), signature(0, 64)],
        (0..32).map(|i| signature(i, 64)).collect(),
    ] {
        let (source, span) = source_for(&values, &pool);
        let bytes = span.get(source.as_slice()).unwrap();
        assert!(BlockSignatures::decode_from_slice(bytes).is_err());
        assert!(
            matches!(PreparedBlockSignatures::from_source(&source,span,&pool),Err(BlockSignatureCustodyError::Decode(ref cause)) if cause.kind()==DecodeAttemptErrorKind::Invalid)
        );
    }
    for payload in [Vec::new(), vec![0; 64]] {
        let records = vec![BlockSignatureRecord { index: 0, payload }];
        let (source, span) = source_for(&records, &pool);
        assert!(BlockSignatures::decode_from_slice(span.get(source.as_slice()).unwrap()).is_err());
        assert!(PreparedBlockSignatures::from_source(&source, span, &pool).is_err());
    }
    let (source, span) = source_for(&sample(1), &pool);
    let unfinished = plan(&source, span, &pool);
    assert!(matches!(
        unfinished.finish(&source),
        Err((_, BlockSignatureCustodyError::Incomplete))
    ));
    norito::core::reset_decode_state();
    assert!(matches!(
        PreparedBlockSignatures::from_source(&source, span, &pool),
        Err(BlockSignatureCustodyError::MissingLayout)
    ));
}
#[test]
fn prepared_signature_children_preserve_aligned_owning_logical_order_and_original_enclosing_cause()
{
    let pool = AllocationBudget::new(65536);
    let _flags = DecodeFlagsGuard::enter(0);
    let original = sample(4);
    let (source, span) = source_for(&original, &pool);
    let bytes = span.get(source.as_slice()).unwrap();
    let limits = DecodeLimits::new(65536, 65536, 65536, 65536, 64);
    let (owning, usage) =
        with_decode_limits_measured(limits, || BlockSignatures::decode_from_slice(bytes));
    assert_eq!(owning.unwrap().0, original);
    let (prepared, prepared_usage) = with_decode_limits_measured(limits, || {
        PreparedBlockSignatures::from_source(&source, span, &pool)
    });
    drop(prepared.unwrap());
    assert_eq!(prepared_usage, usage);
    let narrow = DecodeLimits::new(65536, 65536, 65536, 1, 64);
    let original_source_hash = Hash::new(source.as_slice());
    let original_source_pointer = source.as_slice().as_ptr();
    let original_floor = pool.reserved_bytes();
    for (protocol, expected) in [
        (limits, DecodeAttemptErrorKind::EnclosingLimit),
        (narrow, DecodeAttemptErrorKind::Invalid),
    ] {
        // This is the real admission ownership order: caller ceiling, canonical
        // observer, then the original protocol budget. A scope installed before
        // any observer without an owned protocol budget has no attempt family.
        let owning_cause = with_decode_limits_scope(narrow, || {
            norito::core::classify_decode_attempt(|| {
                with_decode_limits_scope(protocol, || {
                    BlockSignatures::decode_from_slice(bytes).map(|_| ())
                })
            })
        })
        .unwrap_err();
        assert_eq!(owning_cause.kind(), expected);
        let owning_resource = owning_cause.into_error().decode_resource_error();
        assert_eq!(
            owning_resource,
            Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
                // The four declared children consume nominal sequence metadata
                // before either decoder admits span or typed backing.
                attempted: 4,
                limit: 1,
            }),
        );
        let original = with_decode_limits_scope(narrow, || {
            norito::core::classify_decode_attempt(|| {
                with_decode_limits_scope(protocol, || {
                    match PreparedBlockSignatures::from_source(&source, span, &pool) {
                        Ok(prepared) => {
                            drop(prepared);
                            Ok(())
                        }
                        Err(BlockSignatureCustodyError::Decode(cause)) => {
                            assert_eq!(
                                cause.kind(),
                                expected,
                                "original nested cause before scope retirement"
                            );
                            // Move the original error and its opaque family; never
                            // reconstruct a resource error from its public counts.
                            Err(cause.into_error())
                        }
                        Err(error) => panic!(
                            "valid original fixture failed outside its decode scope: {error}"
                        ),
                    }
                })
            })
        });
        let cause = original.unwrap_err();
        assert_eq!(
            cause.kind(),
            expected,
            "same original cause after both scopes retire"
        );
        assert_eq!(cause.into_error().decode_resource_error(), owning_resource,);
        assert_eq!(source.as_slice().as_ptr(), original_source_pointer);
        assert_eq!(Hash::new(source.as_slice()), original_source_hash);
        assert_eq!(pool.reserved_bytes(), original_floor);
    }
    // An actual enclosing refusal consumes neither the immutable source nor
    // physical preparation; the same original source succeeds on fresh limits.
    let mut retried = plan(&source, span, &pool);
    retried.prepare(&source).unwrap();
    let retained = finish(retried, &source);
    assert_eq!(retained, original);
    assert!(retained.admitted_to(&pool));
    drop(retained);
    assert_eq!(pool.reserved_bytes(), original_floor);
}

#[test]
fn retained_typed_signature_backing_survives_ledger_refusal_and_constructor_bounds() {
    let pool = AllocationBudget::new(65536);
    let original = sample(4);
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let layouts = BlockSignatures::backing_layouts(4).unwrap();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - floor - layouts[0].size())
        .unwrap();
    let mut prepared = plan(&source, span, &pool);
    assert!(
        matches!(prepared.prepare(&source), Err(BlockSignatureCustodyError::Buffer(ChargedBufferError::Admission(AllocationRefusal::Capacity { requested_bytes, .. }))) if requested_bytes == layouts[1].size())
    );
    let pointer = prepared.values.as_ref().unwrap().as_slice().as_ptr();
    assert!(prepared.charges.is_none());
    assert!(prepared.initialized(&source).unwrap().is_empty());
    drop(blocker);
    prepared.prepare(&source).unwrap();
    assert_eq!(
        prepared.values.as_ref().unwrap().as_slice().as_ptr(),
        pointer
    );
    drop(finish(prepared, &source));
    assert_eq!(pool.reserved_bytes(), floor);
    assert!(matches!(
        BlockSignatures::backing_layouts(usize::MAX),
        Err(AllocationRefusal::DemandOverflow)
    ));
    let mut maximum = sample(CAP);
    assert!(!maximum.try_insert(signature(0, 64)).unwrap());
    assert!(maximum.try_insert(signature(CAP as u64, 64)).is_err());
    assert_eq!(maximum.len(), CAP);
    let _flags = DecodeFlagsGuard::enter(0);
    assert!(matches!(
        PreparedBlockSignatures::from_source(
            &source,
            SequenceSpan {
                start: span.start,
                end: source.capacity() + 1
            },
            &pool
        ),
        Err(BlockSignatureCustodyError::SourceRange)
    ));
}

#[test]
fn signature_json_streams_the_canonical_sequence_with_exact_bounded_output() {
    for count in [0, 1, 4, 7, CAP] {
        let values = sample(count);
        let independent = values.iter().cloned().collect::<Vec<_>>();
        let expected = norito::json::to_json(&independent).unwrap();
        assert_eq!(norito::json::to_json(&values).unwrap(), expected);
        assert_eq!(
            norito::json::to_json_bounded(&values, expected.len()).unwrap(),
            expected
        );
        assert!(norito::json::to_json_bounded(&values, expected.len() - 1).is_err());
        assert_eq!(
            norito::json::from_json::<BlockSignatures>(&expected).unwrap(),
            values
        );
    }
}

#[test]
fn stored_original_pool_must_match_actual_signature_backing_custody() {
    let pool = AllocationBudget::new(65536);
    let foreign = AllocationBudget::new(65536);
    let original = sample(4);
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    for (stored_budget, matches_original) in [(pool.clone(), true), (foreign.clone(), false)] {
        let mut prepared = plan(&source, span, &pool);
        prepared.prepare(&source).unwrap();
        let funded = Funded {
            values: prepared.values.take().unwrap(),
            charges: prepared.charges.take().unwrap(),
            budget: stored_budget,
        };
        assert_eq!(funded.values.as_slice(), original.as_slice());
        assert!(funded.values.belongs_to(&pool));
        assert!(funded.charges.belongs_to(&pool));
        assert_eq!(funded.charges.as_slice().len(), original.len());
        let mut signature_bytes = 0;
        for (value, charge) in funded
            .values
            .as_slice()
            .iter()
            .zip(funded.charges.as_slice())
        {
            let actual = Layout::array::<u8>(value.signature().payload().len()).unwrap();
            assert_eq!(charge.layout(), actual);
            assert!(charge.belongs_to(&pool));
            signature_bytes += actual.size();
        }
        let actual = Layout::array::<BlockSignature>(funded.values.capacity())
            .unwrap()
            .size()
            + Layout::array::<AllocationCharge>(funded.charges.capacity())
                .unwrap()
                .size()
            + signature_bytes;
        assert_eq!(pool.reserved_bytes(), floor + actual);
        assert_eq!(funded.belongs_to(&pool), matches_original);
        assert!(!funded.belongs_to(&foreign));
        assert_eq!(pool.reserved_bytes(), floor + actual);
        drop(funded);
        drop(prepared);
        assert_eq!(pool.reserved_bytes(), floor);
        assert_eq!(foreign.reserved_bytes(), 0);
    }
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}
