//! Canonical parity, immutable charged-source identity and unchanged prepared backing.

use super::*;
use crate::block::{
    BlockHeader, CommitCertificate, PreparedSignatureBlockError,
    PreparedSignedBlockSignaturesDecode, builder::BlockBuilder,
};
use std::{alloc::Layout, num::NonZeroU64};

fn limits() -> NativeFinalityLimits {
    NativeFinalityLimits {
        block_bytes: 65_536,
        journal_bytes: 131_072,
        block_count: 4,
        allocated_bytes: 1024 * 1024,
    }
}
fn journal() -> NativeFinalityJournal {
    // This unsigned body is a codec fixture, never an authenticated finality clock.
    let block = BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        None,
        None,
        2,
        0,
    ))
    .build(crate::block::BlockSignatures::default());
    let artifact = NativeFinalityArtifact::from_block(&block, limits()).unwrap();
    NativeFinalityJournal {
        blocks: vec![artifact.clone(), artifact],
    }
}

/// Prepare actual same-pool input backing before the fixture's first source use.
/// The independent ordinary producer is diagnostic fixture material, not a claim
/// that its own allocations or a complete production graph are physically funded.
fn charged_bytes(bytes: &[u8], pool: &AllocationBudget) -> ChargedBuffer<u8> {
    let mut original = ChargedBuffer::new(bytes.len(), pool).unwrap();
    original.append(bytes).unwrap();
    original
}
fn source_bytes(source: &ChargedBuffer<u8>) -> usize {
    Layout::array::<u8>(source.capacity()).unwrap().size()
}

#[test]
fn prepared_native_source_matches_canonical_owned_journal_and_borrows_original_frame() {
    let journal = journal();
    let producer = norito::encode_canonical(&journal).unwrap();
    let pool = AllocationBudget::new(2 * 1024 * 1024);
    let bytes = charged_bytes(&producer, &pool);
    let input_bytes = source_bytes(&bytes);
    assert_eq!(pool.reserved_bytes(), input_bytes);
    let mut prepared = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
    assert!(prepared.belongs_to(&pool));
    assert!(!prepared.belongs_to(&AllocationBudget::new(pool.limit_bytes())));
    let credits = pool.reserved_bytes();
    assert!(!prepared.is_decoded());
    assert!(matches!(
        prepared.view(&bytes),
        Err(PreparedNativeFinalityError::NotDecoded)
    ));
    prepared.decode(&bytes).unwrap();
    let view = prepared.view(&bytes).unwrap();
    assert_eq!(view.len(), 2);
    assert!(!view.is_empty());
    view.validate(limits()).unwrap();
    let mut frames = view.frames();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames.size_hint(), (2, Some(2)));
    for original in &journal.blocks {
        let frame = frames.next().unwrap();
        let wire = frame.wire();
        assert_eq!(wire, original.block_wire);
        assert_ne!(wire.as_ptr(), original.block_wire.as_ptr());
        let start = wire.as_ptr().addr() - bytes.as_slice().as_ptr().addr();
        assert!(start + wire.len() <= bytes.as_slice().len());
        assert_eq!(wire.as_ptr(), bytes.as_slice()[start..].as_ptr());
        let charged = frame.charged_source().unwrap();
        assert!(std::ptr::eq(charged.original_source(), &raw const bytes));
        assert!(charged.belongs_to(&pool));
        assert_eq!(
            charged.span(),
            SequenceSpan {
                start,
                end: start + wire.len()
            }
        );
        assert_eq!(charged.wire().as_ptr(), wire.as_ptr());
    }
    assert_eq!(frames.size_hint(), (0, Some(0)));
    assert!(frames.next().is_none());
    prepared.decode(&bytes).unwrap();
    assert_eq!(pool.reserved_bytes(), credits);
    drop(prepared);
    assert_eq!(pool.reserved_bytes(), input_bytes);
    drop(bytes);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn prepared_native_source_rejects_rebound_or_changed_bytes_until_original_consumption() {
    let journal = journal();
    let producer = norito::encode_canonical(&journal).unwrap();
    let pool = AllocationBudget::new(2 * 1024 * 1024);
    let mut bytes = charged_bytes(&producer, &pool);
    let copy = charged_bytes(&producer, &pool);
    let input_bytes = source_bytes(&bytes) + source_bytes(&copy);
    let mut prepared = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
    let spans = prepared.spans.as_slice().as_ptr();
    let blocks = prepared.blocks.as_slice().as_ptr();
    let credits = pool.reserved_bytes();
    prepared.decode(&bytes).unwrap();
    assert!(matches!(
        prepared.decode(&copy),
        Err(PreparedNativeFinalityError::SourceChanged)
    ));
    assert!(matches!(
        prepared.view(&copy),
        Err(PreparedNativeFinalityError::SourceChanged)
    ));
    let last = bytes.as_slice().len() - 1;
    bytes.as_mut_slice()[last] ^= 1;
    assert!(matches!(
        prepared.decode(&bytes),
        Err(PreparedNativeFinalityError::SourceChanged)
    ));
    bytes.as_mut_slice()[last] ^= 1;
    prepared.decode(&bytes).unwrap();
    prepared.clear_consumed();
    assert!(!prepared.is_decoded());
    prepared.decode(&copy).unwrap();
    assert_eq!(prepared.spans.as_slice().as_ptr(), spans);
    assert_eq!(prepared.blocks.as_slice().as_ptr(), blocks);
    assert_eq!(pool.reserved_bytes(), credits);
    drop(prepared);
    assert_eq!(pool.reserved_bytes(), input_bytes);
    drop(bytes);
    assert_eq!(pool.reserved_bytes(), source_bytes(&copy));
    drop(copy);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn prepared_native_source_preserves_enclosing_refusal_and_canonical_invalidity() {
    let journal = journal();
    let producer = norito::encode_canonical(&journal).unwrap();
    let pool = AllocationBudget::new(2 * 1024 * 1024);
    let bytes = charged_bytes(&producer, &pool);
    let truncated = charged_bytes(&producer[..producer.len() - 1], &pool);
    let input_bytes = source_bytes(&bytes) + source_bytes(&truncated);
    let mut prepared = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
    let credits = pool.reserved_bytes();
    let error = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || prepared.decode(&bytes),
    )
    .unwrap_err();
    let PreparedNativeFinalityError::Decode(PreparedDecodeError::Codec(original_cause)) = error
    else {
        panic!("{error:?}");
    };
    assert_eq!(
        original_cause.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(!prepared.is_decoded());
    assert_eq!(pool.reserved_bytes(), credits);
    prepared.decode(&bytes).unwrap();
    // Keep the original reader alive through unchanged-source successful retry.
    assert_eq!(
        original_cause.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    prepared.clear_consumed();
    assert!(NativeFinalityJournal::decode(truncated.as_slice(), limits()).is_err());
    let invalid_cause = prepared.decode(&truncated).unwrap_err();
    assert!(
        matches!(invalid_cause, PreparedNativeFinalityError::Decode(PreparedDecodeError::Codec(ref original)) if original.kind() == norito::core::DecodeAttemptErrorKind::Invalid)
    );
    assert!(!prepared.is_decoded());
    assert_eq!(pool.reserved_bytes(), credits);
    drop(invalid_cause);
    drop(original_cause);
    drop(prepared);
    assert_eq!(pool.reserved_bytes(), input_bytes);
    drop(bytes);
    drop(truncated);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn prepared_native_source_keeps_exact_count_empty_and_aggregate_bounds() {
    let original = journal();
    let cases = [
        NativeFinalityJournal { blocks: Vec::new() },
        NativeFinalityJournal {
            blocks: vec![NativeFinalityArtifact {
                block_wire: Vec::new(),
            }],
        },
        NativeFinalityJournal {
            blocks: vec![original.blocks[0].clone(); 5],
        },
    ];
    for journal in cases {
        let producer = norito::encode_canonical(&journal).unwrap();
        let pool = AllocationBudget::new(2 * 1024 * 1024);
        let bytes = charged_bytes(&producer, &pool);
        let input_bytes = source_bytes(&bytes);
        let mut prepared = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
        let credits = pool.reserved_bytes();
        assert!(NativeFinalityJournal::decode(bytes.as_slice(), limits()).is_err());
        assert!(prepared.decode(&bytes).is_err());
        assert!(!prepared.is_decoded());
        assert_eq!(pool.reserved_bytes(), credits);
        drop(prepared);
        assert_eq!(pool.reserved_bytes(), input_bytes);
        drop(bytes);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let source = NativeFinalitySource::from(&original);
    assert!(
        source
            .validate(NativeFinalityLimits {
                block_count: 1,
                ..limits()
            })
            .is_err()
    );
    assert!(
        source
            .validate(NativeFinalityLimits {
                block_bytes: 1,
                ..limits()
            })
            .is_err()
    );
    let length = original.blocks[0].block_wire.len();
    assert!(
        source
            .validate(NativeFinalityLimits {
                block_bytes: length,
                journal_bytes: length,
                ..limits()
            })
            .is_err()
    );
}

#[test]
fn prepared_native_source_checks_full_nominal_frame_and_keeps_original_backing_on_invalidity() {
    let journal = journal();
    let original = norito::encode_canonical(&journal).unwrap();
    let wrong_nominal = norito::encode_canonical(&journal.blocks[0]).unwrap();
    let mut bad_checksum = original.clone();
    let last = bad_checksum.len() - 1;
    bad_checksum[last] ^= 1;
    let mut trailing = original.clone();
    trailing.push(0);
    for bad in [&wrong_nominal, &bad_checksum, &trailing] {
        let pool = AllocationBudget::new(2 * 1024 * 1024);
        let bytes = charged_bytes(bad, &pool);
        let correct = charged_bytes(&original, &pool);
        let input_bytes = source_bytes(&bytes) + source_bytes(&correct);
        let mut prepared = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
        let credits = pool.reserved_bytes();
        let spans = prepared.spans.as_slice().as_ptr();
        let blocks = prepared.blocks.as_slice().as_ptr();
        assert!(NativeFinalityJournal::decode(bytes.as_slice(), limits()).is_err());
        let error = prepared.decode(&bytes).unwrap_err();
        assert!(
            matches!(error, PreparedNativeFinalityError::Decode(PreparedDecodeError::Codec(ref cause)) if cause.kind() == norito::core::DecodeAttemptErrorKind::Invalid),
            "{error:?}"
        );
        assert!(!prepared.is_decoded());
        assert_eq!(prepared.spans.as_slice().as_ptr(), spans);
        assert_eq!(prepared.blocks.as_slice().as_ptr(), blocks);
        assert_eq!(pool.reserved_bytes(), credits);
        prepared.clear_consumed();
        prepared.decode(&correct).unwrap();
        assert_eq!(prepared.view(&correct).unwrap().len(), journal.blocks.len());
        drop(error);
        drop(prepared);
        assert_eq!(pool.reserved_bytes(), input_bytes);
        drop(bytes);
        drop(correct);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn prepared_native_source_constructor_funds_both_range_arrays_before_source_consumption() {
    let range_bytes = core::mem::size_of::<SequenceSpan>() * limits().block_count;
    let control_bytes = PreparedDecodeWorkspace::allocation_layouts()
        .iter()
        .map(std::alloc::Layout::size)
        .sum::<usize>();
    let demand = 2 * range_bytes + control_bytes;
    let pool = AllocationBudget::new(demand);
    for allowed in [0, range_bytes, demand - 1] {
        let blocker = pool.try_reserve_bytes(demand - allowed).unwrap();
        let before = pool.reserved_bytes();
        let error = match PreparedNativeFinalityJournal::new(limits(), &pool) {
            Ok(_) => panic!("an unfunded range or control must refuse construction"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PreparedNativeFinalityError::Storage(ChargedBufferError::Admission(_))
        ));
        assert_eq!(pool.reserved_bytes(), before);
        drop(blocker);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let prepared = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
    assert_eq!(pool.reserved_bytes(), demand);
    assert!(!prepared.is_decoded());
    drop(prepared);
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(matches!(
        PreparedNativeFinalityJournal::new(
            NativeFinalityLimits {
                block_count: 0,
                ..limits()
            },
            &pool
        ),
        Err(PreparedNativeFinalityError::Invalid(_))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn native_owned_journal_frames_cannot_claim_charged_source_provenance() {
    let original = journal();
    let source = NativeFinalitySource::from(&original);
    source.validate(limits()).unwrap();
    let mut frames = source.frames();
    assert_eq!(frames.len(), original.blocks.len());
    for artifact in &original.blocks {
        let frame = frames.next().unwrap();
        assert!(frame.charged_source().is_none());
        assert_eq!(frame.wire(), artifact.block_wire);
        assert_eq!(frame.wire().as_ptr(), artifact.block_wire.as_ptr());
    }
    assert!(frames.next().is_none());
    assert_eq!(frames.len(), 0);
}

#[test]
fn prepared_native_source_foreign_pool_refuses_before_pin_and_keeps_same_original_owner_retry() {
    let producer = norito::encode_canonical(&journal()).unwrap();
    let pool = AllocationBudget::new(2 * 1024 * 1024);
    let foreign = AllocationBudget::new(pool.limit_bytes());
    let foreign_bytes = charged_bytes(&producer, &foreign);
    let bytes = charged_bytes(&producer, &pool);
    let copy = charged_bytes(&producer, &pool);
    let input_bytes = source_bytes(&bytes) + source_bytes(&copy);
    let mut prepared = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
    let credits = pool.reserved_bytes();
    let foreign_credits = foreign.reserved_bytes();
    let spans = prepared.spans.as_slice().as_ptr();
    let blocks = prepared.blocks.as_slice().as_ptr();
    assert!(matches!(
        prepared.view(&foreign_bytes),
        Err(PreparedNativeFinalityError::ForeignPool)
    ));
    let error =
        norito::core::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
            prepared.decode(&foreign_bytes)
        })
        .unwrap_err();
    assert!(matches!(error, PreparedNativeFinalityError::ForeignPool));
    assert!(prepared.source.is_none());
    assert!(!prepared.is_decoded());
    assert_eq!(pool.reserved_bytes(), credits);
    assert_eq!(foreign.reserved_bytes(), foreign_credits);
    prepared.decode(&bytes).unwrap();
    assert!(matches!(
        prepared.decode(&foreign_bytes),
        Err(PreparedNativeFinalityError::ForeignPool)
    ));
    assert!(matches!(
        prepared.view(&foreign_bytes),
        Err(PreparedNativeFinalityError::ForeignPool)
    ));
    assert!(matches!(
        prepared.decode(&copy),
        Err(PreparedNativeFinalityError::SourceChanged)
    ));
    assert!(matches!(
        prepared.view(&copy),
        Err(PreparedNativeFinalityError::SourceChanged)
    ));
    prepared.decode(&bytes).unwrap();
    let frame = prepared.view(&bytes).unwrap().frames().next().unwrap();
    let charged = frame.charged_source().unwrap();
    assert!(std::ptr::eq(charged.original_source(), &raw const bytes));
    assert!(charged.belongs_to(&pool));
    assert!(!charged.belongs_to(&foreign));
    assert_eq!(prepared.spans.as_slice().as_ptr(), spans);
    assert_eq!(prepared.blocks.as_slice().as_ptr(), blocks);
    assert_eq!(pool.reserved_bytes(), credits);
    assert_eq!(foreign.reserved_bytes(), foreign_credits);
    drop(prepared);
    assert_eq!(pool.reserved_bytes(), input_bytes);
    drop(bytes);
    drop(copy);
    drop(foreign_bytes);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn prepared_native_charged_frame_feeds_original_block_reader_without_source_recopy() {
    // This executes the actual canonical prepared block reader, but the unsigned
    // codec fixture establishes no authenticated native clock or finality.
    let certificate = CommitCertificate::from_untrusted_parts(
        vec![11; 11],
        vec![17; 17],
        vec![23; 23],
        vec![31; 31],
    );
    let block = BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        None,
        None,
        2,
        0,
    ))
    .build(crate::block::BlockSignatures::default())
    .with_commit_certificate(Some(certificate));
    let artifact = NativeFinalityArtifact::from_block(&block, limits()).unwrap();
    let journal = NativeFinalityJournal {
        blocks: vec![artifact.clone(), artifact],
    };
    let producer = norito::encode_canonical(&journal).unwrap();
    let pool = AllocationBudget::new(2 * 1024 * 1024);
    let bytes = charged_bytes(&producer, &pool);
    let copy = charged_bytes(&producer, &pool);
    let input_bytes = source_bytes(&bytes) + source_bytes(&copy);
    let source_pointer = bytes.as_slice().as_ptr();
    let source_hash = Hash::new(bytes.as_slice());
    let advertised = norito::core::Header::read(bytes.as_slice()).unwrap().flags;
    let mut prepared = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
    let mut reader = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    prepared.decode(&bytes).unwrap();
    let frame = prepared.view(&bytes).unwrap().frames().next().unwrap();
    let charged = frame.charged_source().unwrap();
    assert!(std::ptr::eq(charged.original_source(), &raw const bytes));
    assert!(charged.belongs_to(&pool));
    let span = charged.span();
    assert_eq!(span.get(bytes.as_slice()).unwrap(), frame.wire());
    assert_eq!(
        frame.wire().as_ptr(),
        bytes.as_slice()[span.start..].as_ptr()
    );
    let block_flags = norito::core::Header::read(&frame.wire()[1..])
        .unwrap()
        .flags;
    assert_eq!(
        block_flags,
        norito::core::Header::read(&journal.blocks[0].block_wire[1..])
            .unwrap()
            .flags
    );
    let first = reader
        .decode(
            charged.original_source(),
            span,
            limits().decode_limits().unwrap(),
        )
        .unwrap();
    assert_eq!(first.encode_wire().unwrap(), journal.blocks[0].block_wire);
    assert!(first.signatures_admitted_to(&pool));
    assert!(
        reader
            .retained_signatures(&bytes)
            .unwrap()
            .unwrap()
            .admitted_to(&pool)
    );
    let first_certificate = first.commit_certificate().unwrap();
    assert!(first_certificate.admitted_to(&pool));
    assert!(CommitCertificate::ptr_eq(
        first_certificate,
        reader.retained_certificate(&bytes).unwrap().unwrap(),
    ));
    let certificate_pointers = [
        first_certificate.consensus_header().as_ptr(),
        first_certificate.commit_qc().as_ptr(),
        first_certificate.result_preimage().as_ptr(),
        first_certificate.availability().as_ptr(),
    ];
    assert_eq!(first_certificate.consensus_header(), &[11; 11]);
    assert_eq!(first_certificate.commit_qc(), &[17; 17]);
    assert_eq!(first_certificate.result_preimage(), &[23; 23]);
    assert_eq!(first_certificate.availability(), &[31; 31]);
    let before = pool.reserved_bytes();
    let blocker = pool.try_reserve_bytes(pool.limit_bytes() - before).unwrap();
    pool.set_limit_bytes(0);
    // A genuine retry consumes the same admitted source/signature prefix. This
    // asserts no new pool credit, not an unmeasured whole-graph allocation claim.
    prepared.decode(&bytes).unwrap();
    let retry_frame = prepared.view(&bytes).unwrap().frames().next().unwrap();
    let retry_source = retry_frame.charged_source().unwrap();
    let retry = reader
        .decode(
            retry_source.original_source(),
            retry_source.span(),
            limits().decode_limits().unwrap(),
        )
        .unwrap();
    assert!(first.same_signature_custody(&retry));
    let retry_certificate = retry.commit_certificate().unwrap();
    assert!(retry_certificate.admitted_to(&pool));
    assert!(CommitCertificate::ptr_eq(
        first_certificate,
        retry_certificate
    ));
    assert!(CommitCertificate::ptr_eq(
        retry_certificate,
        reader.retained_certificate(&bytes).unwrap().unwrap(),
    ));
    assert_eq!(
        [
            retry_certificate.consensus_header().as_ptr(),
            retry_certificate.commit_qc().as_ptr(),
            retry_certificate.result_preimage().as_ptr(),
            retry_certificate.availability().as_ptr(),
        ],
        certificate_pointers,
    );
    assert!(matches!(
        reader.decode(&copy, span, limits().decode_limits().unwrap()),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    assert_eq!(retry.encode_wire().unwrap(), journal.blocks[0].block_wire);
    assert_eq!(bytes.as_slice().as_ptr(), source_pointer);
    assert_eq!(Hash::new(bytes.as_slice()), source_hash);
    assert_eq!(
        norito::core::Header::read(bytes.as_slice()).unwrap().flags,
        advertised
    );
    assert_eq!(pool.reserved_bytes(), before + blocker.remaining_bytes());
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), before);
    drop(first);
    drop(retry);
    drop(reader);
    drop(prepared);
    assert_eq!(pool.reserved_bytes(), input_bytes);
    drop(bytes);
    drop(copy);
    assert_eq!(pool.reserved_bytes(), 0);
}
