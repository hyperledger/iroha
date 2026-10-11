//! Original complete canonical frame identity and signature custody through shared block clones.
use super::*;
use crate::block::{BlockHeader, BlockSignature, BlockSignatures, SharedSignedBlock};
use iroha_crypto::{Signature, SignatureOf};
fn fixture(count: usize) -> SignedBlock {
    let header = BlockHeader::new(std::num::NonZeroU64::new(2).unwrap(), None, None, 1_000, 0);
    SignedBlock {
        signatures: BlockSignatures::try_from_iter((0..count).map(|index| {
            BlockSignature::new(
                index as u64,
                SignatureOf::from_signature(
                    Signature::try_from_bytes(&vec![index as u8 + 1; 64]).unwrap(),
                ),
            )
        }))
        .unwrap(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    }
}
fn source_for(block: &SignedBlock, pool: &AllocationBudget) -> (ChargedBuffer<u8>, SequenceSpan) {
    let wire = block.encode_wire().unwrap();
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
#[test]
fn complete_signed_block_prepared_signatures_preserve_canonical_nominal_frame_and_shared_owners() {
    for count in [0, 1, 4, 7, 31] {
        let pool = AllocationBudget::new(1024 * 1024);
        let block = fixture(count);
        let canonical_wire = block.encode_wire().unwrap();
        let ordinary = crate::block::decode_framed_signed_block(&canonical_wire).unwrap();
        assert_eq!(ordinary, block);
        assert_eq!(ordinary.encode_wire().unwrap(), canonical_wire);
        assert!(!ordinary.signatures.admitted_to(&pool));
        let (source, span) = source_for(&block, &pool);
        let source_floor = pool.reserved_bytes();
        let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        let controls = pool.reserved_bytes() - source_floor;
        assert_eq!(
            controls,
            PreparedDecodeWorkspace::allocation_layouts()
                .iter()
                .map(std::alloc::Layout::size)
                .sum::<usize>()
        );
        let admitted = decoder
            .decode(
                &source,
                span,
                norito::canonical_decode_limits(span.end - span.start),
            )
            .unwrap();
        assert_eq!(admitted, block);
        assert_eq!(
            admitted.encode_wire().unwrap(),
            block.encode_wire().unwrap()
        );
        assert!(admitted.signatures.admitted_to(&pool));
        assert!(BlockSignatures::ptr_eq(
            &admitted.signatures,
            decoder.retained_signatures(&source).unwrap().unwrap()
        ));
        let retried = decoder
            .decode(
                &source,
                span,
                norito::canonical_decode_limits(span.end - span.start),
            )
            .unwrap();
        assert!(retried.same_signature_custody(&admitted));
        drop(retried);
        let pointers = admitted
            .signatures()
            .map(|sig| sig.signature().payload().as_ptr())
            .collect::<Vec<_>>();
        let retained = SharedSignedBlock::reserve(&pool)
            .unwrap()
            .initialize(admitted);
        let shared = retained.clone();
        let candidate_clone = retained.as_ref().clone();
        assert_eq!(
            candidate_clone
                .signatures()
                .map(|sig| sig.signature().payload().as_ptr())
                .collect::<Vec<_>>(),
            pointers
        );
        drop(retained);
        drop(shared);
        assert!(candidate_clone.signatures.admitted_to(&pool));
        drop(candidate_clone);
        drop(decoder);
        assert_eq!(pool.reserved_bytes(), source_floor);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn complete_frame_signature_capacity_refusal_retains_same_source_and_partial_collection() {
    let pool = AllocationBudget::new(1024 * 1024);
    let block = fixture(4);
    let (mut source, span) = source_for(&block, &pool);
    let (copy, _) = source_for(&block, &pool);
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let backing: usize = BlockSignatures::backing_layouts(4)
        .unwrap()
        .iter()
        .map(std::alloc::Layout::size)
        .sum();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes() - backing - 64)
        .unwrap();
    let error = decoder
        .decode(
            &source,
            span,
            norito::canonical_decode_limits(span.end - span.start),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        PreparedSignatureBlockError::Decode(PreparedDecodeError::Destination(
            BlockSignatureCustodyError::Buffer(ChargedBufferError::Admission(_))
        ))
    ));
    let pointer = decoder
        .pending
        .as_ref()
        .unwrap()
        .initialized(&source)
        .unwrap()[0]
        .signature()
        .payload()
        .as_ptr();
    assert!(matches!(
        decoder.decode(
            &copy,
            span,
            norito::canonical_decode_limits(span.end - span.start)
        ),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    source.as_mut_slice()[0] ^= 1;
    assert!(matches!(
        decoder.decode(
            &source,
            span,
            norito::canonical_decode_limits(span.end - span.start)
        ),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    source.as_mut_slice()[0] ^= 1;
    drop(blocker);
    let admitted = decoder
        .decode(
            &source,
            span,
            norito::canonical_decode_limits(span.end - span.start),
        )
        .unwrap();
    assert_eq!(
        admitted
            .signatures()
            .next()
            .unwrap()
            .signature()
            .payload()
            .as_ptr(),
        pointer
    );
    assert_eq!(admitted, block);
    assert!(decoder.belongs_to(&pool));
    drop(admitted);
    decoder.clear_consumed();
    assert!(decoder.pending.is_none());
    assert!(decoder.completed.is_none());
    assert!(decoder.source.is_none());
}
#[test]
fn prepared_signature_frame_rejects_foreign_input_and_malformed_canonical_bytes() {
    let pool = AllocationBudget::new(1024 * 1024);
    let foreign = AllocationBudget::new(1024 * 1024);
    let block = fixture(4);
    let (source, span) = source_for(&block, &foreign);
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    assert!(matches!(
        decoder.decode(
            &source,
            span,
            norito::canonical_decode_limits(span.end - span.start)
        ),
        Err(PreparedSignatureBlockError::Source)
    ));
    let (mut source, span) = source_for(&block, &pool);
    source.as_mut_slice()[span.end - 1] ^= 1;
    let error = decoder
        .decode(
            &source,
            span,
            norito::canonical_decode_limits(span.end - span.start),
        )
        .unwrap_err();
    assert!(
        matches!(error,PreparedSignatureBlockError::Frame(ref cause) if cause.kind()==norito::core::DecodeAttemptErrorKind::Invalid)
    );
}

#[test]
fn ordinary_and_prepared_blocks_share_the_single_generated_canonical_record_walk() {
    for count in [0, 1, 4, 7, 31] {
        let pool = AllocationBudget::new(1024 * 1024);
        let original = fixture(count);
        let wire = original.encode_wire().unwrap();
        let ordinary = crate::block::decode_framed_signed_block(&wire).unwrap();
        assert_eq!(ordinary, original);
        assert_eq!(ordinary.encode_wire().unwrap(), wire);
        assert!(!ordinary.signatures_admitted_to(&pool));
        let (source, span) = source_for(&original, &pool);
        let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        let prepared = decoder
            .decode(
                &source,
                span,
                norito::canonical_decode_limits(span.end - span.start),
            )
            .unwrap();
        assert_eq!(prepared, ordinary);
        assert_eq!(prepared.encode_wire().unwrap(), wire);
        assert!(prepared.signatures_admitted_to(&pool));
        assert!(BlockSignatures::ptr_eq(
            &prepared.signatures,
            decoder.retained_signatures(&source).unwrap().unwrap()
        ));
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(crate::block::decode_framed_signed_block(&trailing).is_err());
        let mut wrong_version = wire;
        wrong_version[0] = 2;
        assert!(crate::block::decode_framed_signed_block(&wrong_version).is_err());
    }
}

fn certificate_fixture(count: usize, empty: bool) -> SignedBlock {
    fixture(count).with_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        if empty { Vec::new() } else { vec![11; 11] },
        if empty { Vec::new() } else { vec![17; 17] },
        if empty { Vec::new() } else { vec![23; 23] },
        if empty { Vec::new() } else { vec![31; 31] },
    )))
}
#[test]
fn original_prepared_block_retains_all_four_certificate_leaves_through_last_shared_reader() {
    for (count, empty) in [(0, true), (4, false), (7, false), (31, false)] {
        let pool = AllocationBudget::new(1024 * 1024);
        let original = certificate_fixture(count, empty);
        let wire = original.encode_wire().unwrap();
        let ordinary = crate::block::decode_framed_signed_block(&wire).unwrap();
        let (source, span) = source_for(&original, &pool);
        let floor = pool.reserved_bytes();
        let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        let prepared = decoder
            .decode(&source, span, norito::canonical_decode_limits(wire.len()))
            .unwrap();
        assert_eq!(prepared, ordinary);
        assert_eq!(prepared.encode_wire().unwrap(), wire);
        assert_eq!(
            prepared.canonical_wire_identity().unwrap(),
            original.canonical_wire_identity().unwrap()
        );
        let certificate = prepared.commit_certificate().unwrap();
        assert!(certificate.admitted_to(&pool));
        assert!(decoder.belongs_to(&pool));
        assert!(CommitCertificate::ptr_eq(
            certificate,
            decoder.retained_certificate(&source).unwrap().unwrap()
        ));
        let pointers = [
            certificate.consensus_header().as_ptr(),
            certificate.commit_qc().as_ptr(),
            certificate.result_preimage().as_ptr(),
            certificate.availability().as_ptr(),
        ];
        let replay = decoder
            .decode(&source, span, norito::canonical_decode_limits(wire.len()))
            .unwrap();
        assert!(CommitCertificate::ptr_eq(
            certificate,
            replay.commit_certificate().unwrap()
        ));
        assert!(prepared.same_signature_custody(&replay));
        drop(replay);
        let block = SharedSignedBlock::reserve(&pool)
            .unwrap()
            .initialize(prepared);
        let retained = block.clone();
        let last_certificate_reader = retained.commit_certificate().unwrap().clone();
        drop(block);
        drop(retained);
        assert_eq!(
            [
                last_certificate_reader.consensus_header().as_ptr(),
                last_certificate_reader.commit_qc().as_ptr(),
                last_certificate_reader.result_preimage().as_ptr(),
                last_certificate_reader.availability().as_ptr()
            ],
            pointers
        );
        drop(decoder);
        let certificate_bytes = last_certificate_reader.payload_len()
            + iroha_allocation::ChargedShared::<
                super::super::commit_certificate::ChargedCertificateParts,
            >::allocation_layout()
            .size();
        assert_eq!(pool.reserved_bytes(), floor + certificate_bytes);
        assert!(last_certificate_reader.admitted_to(&pool));
        assert_eq!(
            last_certificate_reader,
            original.commit_certificate().unwrap().clone()
        );
        drop(last_certificate_reader);
        assert_eq!(pool.reserved_bytes(), floor);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn complete_certificate_admission_refusal_keeps_original_block_signature_and_input_custody() {
    let pool = AllocationBudget::new(1024 * 1024);
    let original = certificate_fixture(4, false);
    let wire = original.encode_wire().unwrap();
    let (source, span) = source_for(&original, &pool);
    let pointer = source.as_slice().as_ptr();
    let hash = Hash::new(source.as_slice());
    let floor = pool.reserved_bytes();
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let controls = pool.reserved_bytes() - floor;
    let signature_bytes = BlockSignatures::backing_layouts(4)
        .unwrap()
        .iter()
        .map(std::alloc::Layout::size)
        .sum::<usize>()
        + BlockSignatures::allocation_layout().size()
        + 4 * 64;
    let certificate_bytes = original.commit_certificate().unwrap().payload_len()
        + iroha_allocation::ChargedShared::<
            super::super::commit_certificate::ChargedCertificateParts,
        >::allocation_layout()
        .size();
    pool.set_limit_bytes(floor + controls + signature_bytes + certificate_bytes - 1);
    let error = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap_err();
    assert!(matches!(
        error,
        PreparedSignatureBlockError::Certificate(CertificateCustodyError::Admission(_))
    ));
    assert_eq!(pool.reserved_bytes(), floor + controls + signature_bytes);
    assert!(decoder.retained_certificate(&source).unwrap().is_none());
    assert!(
        decoder
            .certificate_pending
            .as_ref()
            .unwrap()
            .initialized(&source)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    let signatures = decoder
        .retained_signatures(&source)
        .unwrap()
        .unwrap()
        .clone();
    pool.set_limit_bytes(floor + controls + signature_bytes + certificate_bytes);
    let retry = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert_eq!(source.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(source.as_slice()), hash);
    assert!(BlockSignatures::ptr_eq(&retry.signatures, &signatures));
    assert!(CommitCertificate::ptr_eq(
        retry.commit_certificate().unwrap(),
        decoder.retained_certificate(&source).unwrap().unwrap()
    ));
    assert_eq!(retry.encode_wire().unwrap(), wire);
    assert_eq!(
        pool.reserved_bytes(),
        floor + controls + signature_bytes + certificate_bytes
    );
    drop(retry);
    drop(signatures);
    drop(decoder);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn prepared_certificate_frame_rejects_truncation_reserved_flags_and_changed_original_source() {
    let original = certificate_fixture(4, false);
    let wire = original.encode_wire().unwrap();
    let mut malformed = Vec::new();
    for end in [0, 1, norito::core::Header::SIZE, wire.len() - 1] {
        malformed.push(wire[..end].to_vec());
    }
    let mut flags = wire.clone();
    flags[norito::core::Header::SIZE] |= 0x80; // Version prefix precedes the exact canonical header.
    malformed.push(flags);
    let mut trailing = wire.clone();
    trailing.push(0);
    malformed.push(trailing);
    for bytes in malformed {
        assert!(crate::block::decode_framed_signed_block(&bytes).is_err());
        let pool = AllocationBudget::new(1024 * 1024);
        let mut source = ChargedBuffer::new(bytes.len(), &pool).unwrap();
        source.append(&bytes).unwrap();
        let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        assert!(
            decoder
                .decode(
                    &source,
                    SequenceSpan {
                        start: 0,
                        end: bytes.len()
                    },
                    norito::canonical_decode_limits(wire.len())
                )
                .is_err()
        );
        assert!(decoder.retained_certificate(&source).unwrap().is_none());
    }
    let pool = AllocationBudget::new(1024 * 1024);
    let (mut source, span) = source_for(&original, &pool);
    let (equal_copy, _) = source_for(&original, &pool);
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let block = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert!(matches!(
        decoder.decode(
            &equal_copy,
            span,
            norito::canonical_decode_limits(wire.len())
        ),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    assert!(matches!(
        decoder.retained_certificate(&equal_copy),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    let old = source.as_slice()[span.end - 1];
    source.as_mut_slice()[span.end - 1] ^= 1;
    assert!(matches!(
        decoder.decode(&source, span, norito::canonical_decode_limits(wire.len())),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    source.as_mut_slice()[span.end - 1] = old;
    let retry = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert!(CommitCertificate::ptr_eq(
        block.commit_certificate().unwrap(),
        retry.commit_certificate().unwrap()
    ));
    assert_eq!(retry.encode_wire().unwrap(), wire);
}

#[test]
fn prepared_certificate_inner_cause_keeps_original_enclosing_reader_through_outer_frame_and_retry()
{
    use norito::core::{
        DecodeAttemptErrorKind, DecodeLimits, PreparedDecodeError, with_decode_limits_measured,
        with_decode_limits_scope,
    };
    let pool = AllocationBudget::new(1024 * 1024);
    let original = certificate_fixture(4, false);
    let wire = original.encode_wire().unwrap();
    let (source, span) = source_for(&original, &pool);
    let source_pointer = source.as_slice().as_ptr();
    let source_hash = Hash::new(source.as_slice());
    let floor = pool.reserved_bytes();
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let controls = pool.reserved_bytes() - floor;
    let signature_bytes = BlockSignatures::backing_layouts(4)
        .unwrap()
        .iter()
        .map(std::alloc::Layout::size)
        .sum::<usize>()
        + BlockSignatures::allocation_layout().size()
        + 4 * 64;
    let protocol = DecodeLimits::new(1024 * 1024, 1024 * 1024, 1024 * 1024, 1024 * 1024, 64);
    pool.set_limit_bytes(floor + controls + signature_bytes);
    // The first genuine five-layout pool refusal retains the original signatures.
    // Measure a second identical refusal with those same owners: the following
    // enclosing-limit attempt repeats this exact canonical work without running
    // the already completed signature fill again.
    let refused = with_decode_limits_scope(protocol, || decoder.decode(&source, span, protocol));
    assert!(matches!(
        refused,
        Err(PreparedSignatureBlockError::Certificate(
            CertificateCustodyError::Admission(_)
        ))
    ));
    let retained_bytes = pool.reserved_bytes();
    let (refused, usage) =
        with_decode_limits_measured(protocol, || decoder.decode(&source, span, protocol));
    assert!(matches!(
        refused,
        Err(PreparedSignatureBlockError::Certificate(
            CertificateCustodyError::Admission(_)
        ))
    ));
    assert_eq!(pool.reserved_bytes(), retained_bytes);
    let certificate = original.commit_certificate().unwrap();
    let leaves = [
        certificate.consensus_header(),
        certificate.commit_qc(),
        certificate.result_preimage(),
        certificate.availability(),
    ];
    assert_eq!(
        leaves.iter().map(|leaf| leaf.len()).sum::<usize>(),
        certificate.payload_len()
    );
    // The generated field walk charges each Vec<u8> payload length before its
    // borrowed raw-count metadata. Remove every later field's exact canonical
    // payload length and count, leaving the original first declared-count charge.
    // Borrowed &[u8] and Vec<u8> share this sole fixed-count wire payload.
    let later_work = leaves
        .iter()
        .skip(1)
        .try_fold(0usize, |total, leaf| {
            let payload_length = norito::core::SerializePayload::encoded_len_exact(leaf).unwrap();
            total.checked_add(payload_length)?.checked_add(leaf.len())
        })
        .unwrap();
    let attempted = usage
        .total_allocated_bytes()
        .checked_sub(later_work)
        .unwrap();
    let first_leaf = leaves[0].len();
    let prefix = attempted.checked_sub(first_leaf).unwrap();
    let limit = attempted.checked_sub(1).unwrap();
    assert!(prefix < limit);
    let narrow = DecodeLimits::new(1024 * 1024, 1024 * 1024, 1024 * 1024, limit, 64);
    let before = pool.reserved_bytes();
    let error =
        with_decode_limits_scope(narrow, || decoder.decode(&source, span, protocol)).unwrap_err();
    let PreparedSignatureBlockError::Decode(PreparedDecodeError::Codec(original_cause)) = error
    else {
        panic!(
            "the actual inner certificate Plan must move its canonical cause through the original outer workspace"
        );
    };
    assert_eq!(
        original_cause.kind(),
        DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(pool.reserved_bytes(), before);
    assert!(decoder.certificate_pending.is_some());
    assert!(decoder.certificate_completed.is_none());
    assert_eq!(source.as_slice().as_ptr(), source_pointer);
    assert_eq!(Hash::new(source.as_slice()), source_hash);
    let signatures = decoder
        .retained_signatures(&source)
        .unwrap()
        .unwrap()
        .clone();
    pool.set_limit_bytes(1024 * 1024);
    // Keep the original enclosing counter reader alive while the same prepared
    // workspace starts another genuine attempt with its nonrepeating identity.
    let retry = decoder.decode(&source, span, protocol).unwrap();
    assert_eq!(retry.encode_wire().unwrap(), wire);
    assert!(BlockSignatures::ptr_eq(&retry.signatures, &signatures));
    assert!(retry.commit_certificate().unwrap().admitted_to(&pool));
    assert_eq!(
        original_cause.kind(),
        DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(
        original_cause.into_error().decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: u64::try_from(attempted).unwrap(),
            limit: u64::try_from(limit).unwrap(),
        })
    );
    drop(retry);
    drop(signatures);
    drop(decoder);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[path = "tests/da_policy_tests.rs"]
mod da_policy_tests;

#[path = "tests/da_commitment_tests.rs"]
mod da_commitment_tests;

#[path = "tests/pulse_inline_tests.rs"]
mod pulse_inline_tests;

mod header_inline_tests;

#[test]
fn prepared_signature_custody_observation_rejects_equal_wire_distinct_owner() {
    for count in [0, 4] {
        let pool = AllocationBudget::new(1024 * 1024);
        let untrusted = fixture(count);
        let (source, span) = source_for(&untrusted, &pool);
        let floor = pool.reserved_bytes();
        let mut first_decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        let mut second_decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        let original = first_decoder
            .decode(
                &source,
                span,
                norito::canonical_decode_limits(span.end - span.start),
            )
            .unwrap();
        let distinct = second_decoder
            .decode(
                &source,
                span,
                norito::canonical_decode_limits(span.end - span.start),
            )
            .unwrap();
        assert_eq!(original, distinct);
        assert!(original.signatures_admitted_to(&pool));
        assert!(distinct.signatures_admitted_to(&pool));
        assert!(!original.same_signature_custody(&distinct));
        let occupied = pool.reserved_bytes();
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 0),
            || {
                assert!(
                    first_decoder
                        .retains_signature_custody(&source, &original)
                        .unwrap()
                );
                assert!(
                    !first_decoder
                        .retains_signature_custody(&source, &distinct)
                        .unwrap()
                );
                assert!(
                    second_decoder
                        .retains_signature_custody(&source, &distinct)
                        .unwrap()
                );
                assert!(
                    !second_decoder
                        .retains_signature_custody(&source, &original)
                        .unwrap()
                );
            },
        );
        assert_eq!(pool.reserved_bytes(), occupied);
        drop(original);
        drop(distinct);
        drop(first_decoder);
        drop(second_decoder);
        assert_eq!(pool.reserved_bytes(), floor);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn prepared_signature_custody_observation_requires_exact_source_and_completed_owner() {
    let pool = AllocationBudget::new(1024 * 1024);
    let foreign = AllocationBudget::new(pool.limit_bytes());
    let untrusted = fixture(4);
    let (source, span) = source_for(&untrusted, &pool);
    let (copy, _) = source_for(&untrusted, &pool);
    let (foreign_source, _) = source_for(&untrusted, &foreign);
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    assert!(
        !decoder
            .retains_signature_custody(&source, &untrusted)
            .unwrap()
    );
    assert!(matches!(
        decoder.retains_signature_custody(&foreign_source, &untrusted),
        Err(PreparedSignatureBlockError::Source)
    ));
    let original = decoder
        .decode(
            &source,
            span,
            norito::canonical_decode_limits(span.end - span.start),
        )
        .unwrap();
    assert!(
        decoder
            .retains_signature_custody(&source, &original)
            .unwrap()
    );
    assert!(
        !decoder
            .retains_signature_custody(&source, &untrusted)
            .unwrap()
    );
    assert_eq!(source.as_slice(), copy.as_slice());
    assert_ne!(source.as_slice().as_ptr(), copy.as_slice().as_ptr());
    assert!(matches!(
        decoder.retains_signature_custody(&copy, &original),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    assert!(matches!(
        decoder.retains_signature_custody(&foreign_source, &original),
        Err(PreparedSignatureBlockError::Source)
    ));
    let before_retirement = pool.reserved_bytes();
    decoder.clear_consumed();
    assert!(
        !decoder
            .retains_signature_custody(&source, &original)
            .unwrap()
    );
    assert!(
        original.signatures_admitted_to(&pool),
        "explicit decoder retirement leaves the real original block's charges alive"
    );
    assert_eq!(
        pool.reserved_bytes(),
        before_retirement,
        "the original block keeps every completed collection/leaf while controls remain"
    );
    drop(original);
    drop(decoder);
    drop(source);
    drop(copy);
    assert_eq!(pool.reserved_bytes(), 0);
    drop(foreign_source);
    assert_eq!(foreign.reserved_bytes(), 0);
}
