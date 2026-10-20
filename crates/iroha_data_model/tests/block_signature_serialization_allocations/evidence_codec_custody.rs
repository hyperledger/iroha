//! Original canonical evidence refuses locally without losing source or counter custody.
use super::*;
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::Hash;
use iroha_data_model::block::consensus::Evidence;
use iroha_sumeragi::{
    message::{CodecError, Evidence as NativeEvidence, Qc, VoteKind},
    types::{AggregateSignature, Bitmap, EpochId, Hash32, SIGNATURE_LEN},
};
use norito::core::{
    DecodeAttemptErrorKind, DecodeLimits, DecodeLocalRefusalKind, PreparedDecodeWorkspace,
    classify_decode_attempt,
};

fn proof() -> Evidence {
    // Syntax/custody fixture only: no signer, quorum, monetary or finality claim.
    let first = Qc {
        kind: VoteKind::Commit,
        instance: Hash32([1; 32]),
        epoch: EpochId {
            epoch: 3,
            context: Hash32([5; 32]),
        },
        height: 7,
        view: 11,
        block_hash: Hash32([13; 32]),
        result: Hash32([17; 32]),
        signers: Bitmap::from_bytes(vec![0x55; 97]),
        agg_sig: AggregateSignature([19; SIGNATURE_LEN]),
    };
    let second = Qc {
        block_hash: Hash32([23; 32]),
        ..first.clone()
    };
    Evidence::from_native(&NativeEvidence::ConflictingCertificates(first, second)).unwrap()
}
fn measured<T>(body: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TRACKING.with(|v| v.set(false));
        }
    }
    TRACKING.with(|v| assert!(!v.replace(true)));
    ALLOCATIONS.with(|v| v.set(0));
    let reset = Reset;
    let value = body();
    let count = ALLOCATIONS.with(Cell::get);
    drop(reset);
    (value, count)
}
fn workspace(pool: &AllocationBudget) -> PreparedDecodeWorkspace {
    let mut reserved = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    PreparedDecodeWorkspace::from_reservation(pool, &mut reserved).unwrap()
}
#[test]
fn original_evidence_real_allocator_refusal_keeps_exact_source_and_same_bytes_retry() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REFUSE.with(|v| v.set(None));
            REFUSE_SKIP_MATCHES.with(|v| v.set(0));
        }
    }
    let proof = proof();
    let expected = proof.decode_native().unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let mut source = ChargedBuffer::new(proof.native_frame().len(), &pool).unwrap();
    source.append(proof.native_frame()).unwrap();
    let pointer = source.as_slice().as_ptr();
    let hash = Hash::new(source.as_slice());
    let floor = pool.reserved_bytes();
    let NativeEvidence::ConflictingCertificates(ref first, _) = expected else {
        panic!("original QC pair")
    };
    let layout = Layout::array::<u8>(first.signers.as_bytes().len()).unwrap();
    REFUSE_SKIP_MATCHES.with(|v| assert_eq!(v.get(), 0));
    REFUSE.with(|v| assert!(v.replace(Some(layout)).is_none()));
    let reset = Reset;
    let refusal = Evidence::decode_native_frame(source.as_slice()).unwrap_err();
    assert!(
        REFUSE.with(|v| v.get().is_none()),
        "original fallible allocation was attempted"
    );
    drop(reset);
    let CodecError::Resource(original) = refusal else {
        panic!("original allocator cause lost: {refusal:?}")
    };
    assert_eq!(original.kind(), DecodeLocalRefusalKind::Allocator);
    assert_eq!(original.allocation_bytes(), Some(layout.size() as u64));
    let (cloned, count) = measured(|| original.clone());
    assert_eq!(count, 0);
    assert_eq!(cloned, original);
    let raw = norito::Error::from(CodecError::Resource(cloned));
    assert!(matches!(raw,norito::Error::AllocationFailed{bytes} if bytes==layout.size() as u64));
    assert!(
        matches!(CodecError::from(raw), CodecError::Norito(_)),
        "raw allocator diagnostics cannot manufacture a local verdict"
    );
    assert_eq!(
        Evidence::decode_native_frame(source.as_slice()).unwrap(),
        expected
    );
    assert_eq!(expected.encode().unwrap(), source.as_slice());
    assert_eq!(source.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(source.as_slice()), hash);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(original);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn original_evidence_scope_owner_clones_without_allocation_and_refunds_only_last_reader() {
    let proof = proof();
    let pointer = proof.native_frame().as_ptr();
    let hash = Hash::new(proof.native_frame());
    let pool = AllocationBudget::new(1 << 20);
    let mut caller = workspace(&pool);
    let mut decoder = workspace(&pool);
    let narrow = DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, usize::MAX);
    let protocol = norito::canonical_decode_limits(proof.native_frame().len());
    let error = caller
        .with_limits(narrow, narrow, || {
            classify_decode_attempt(|| {
                decoder
                    .with_limits(protocol, protocol, || {
                        proof.decode_native().map_err(norito::Error::from)
                    })
                    .unwrap()
            })
        })
        .unwrap()
        .unwrap_err();
    let CodecError::Resource(original) = CodecError::from(error) else {
        panic!("same actual enclosing refusal")
    };
    assert_eq!(original.kind(), DecodeLocalRefusalKind::EnclosingLimit);
    let scope = original.clone().into_error();
    let norito::Error::ScopedDecodeResource(ref expected) = scope else {
        panic!("original scoped owner")
    };
    let (last_reader, count) = measured(|| original.clone());
    assert_eq!(count, 0);
    let converted = norito::Error::from(CodecError::Resource(original));
    assert!(matches!(&converted,norito::Error::ScopedDecodeResource(actual) if actual==expected));
    drop(scope);
    drop(converted);
    let native = decoder
        .with_limits(protocol, protocol, || proof.decode_native())
        .unwrap()
        .unwrap();
    assert_eq!(native.encode().unwrap(), proof.native_frame());
    assert_eq!(proof.native_frame().as_ptr(), pointer);
    assert_eq!(Hash::new(proof.native_frame()), hash);
    drop(decoder);
    drop(caller);
    assert_eq!(
        pool.reserved_bytes(),
        PreparedDecodeWorkspace::allocation_layouts()[0].size()
    );
    drop(last_reader);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn saved_scoped_and_reconstructed_diagnostics_never_gain_a_later_evidence_verdict() {
    let pool = AllocationBudget::new(1 << 20);
    let mut caller = workspace(&pool);
    let narrow = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let old = caller
        .with_limits(narrow, narrow, || {
            classify_decode_attempt(|| norito::core::reserve_decode_allocation(1))
        })
        .unwrap()
        .unwrap_err()
        .into_local_refusal()
        .unwrap();
    let fields = old.resource_error();
    let raw = old.into_error();
    let stale = caller
        .with_limits(narrow, narrow, || {
            classify_decode_attempt(|| {
                let _fresh = norito::core::reserve_decode_allocation(1);
                Err::<(), _>(raw)
            })
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(stale.kind(), DecodeAttemptErrorKind::Invalid);
    assert!(matches!(CodecError::from(stale), CodecError::Norito(_)));
    let copied = caller
        .with_limits(narrow, narrow, || {
            classify_decode_attempt(|| Err::<(), _>(norito::Error::from(fields)))
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(copied.kind(), DecodeAttemptErrorKind::Invalid);
    assert!(matches!(CodecError::from(copied), CodecError::Norito(_)));
    drop(caller);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn malformed_protocol_evidence_never_becomes_a_local_resource_verdict() {
    let proof = proof();
    let frame = proof.native_frame();
    let mut malformed = frame.to_vec();
    *malformed.last_mut().unwrap() ^= 0x80;
    for source in [&[][..], &frame[..frame.len() - 1], malformed.as_slice()] {
        assert!(matches!(
            Evidence::decode_native_frame(source),
            Err(CodecError::Norito(_))
        ));
    }
    let raw = norito::Error::SequenceLengthExceeded {
        length: 2,
        limit: 1,
    };
    assert!(matches!(CodecError::from(raw), CodecError::Norito(_)));
    assert!(matches!(
        NativeEvidence::decode(&vec![
            0;
            iroha_sumeragi::message::MAX_EVIDENCE_FRAME_BYTES + 1
        ]),
        Err(CodecError::TooLarge { .. })
    ));
    assert_eq!(proof.decode_native().unwrap().encode().unwrap(), frame);
}

#[test]
fn complete_model_pair_order_and_json_refusal_keep_the_original_typed_boundary() {
    let proof = proof();
    let native = proof.decode_native().unwrap();
    let NativeEvidence::ConflictingCertificates(first, second) = native else {
        panic!("original complete proof pair")
    };
    let reversed = NativeEvidence::ConflictingCertificates(second, first)
        .encode()
        .unwrap();
    assert_ne!(reversed, proof.native_frame());
    let original = Evidence::decode_native_frame(&reversed).unwrap_err();
    assert!(matches!(original, CodecError::Norito(_)));
    assert!(original.to_string().contains("canonical frame order"));
    let json = norito::json::to_json(&proof).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let mut caller = workspace(&pool);
    let mut decoder = workspace(&pool);
    let narrow = DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, usize::MAX);
    let protocol = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let error = caller
        .with_limits(narrow, narrow, || {
            classify_decode_attempt(|| {
                decoder
                    .with_limits(protocol, protocol, || {
                        norito::json::from_str::<Evidence>(&json).map_err(|error| match error {
                            norito::json::Error::ScopedDecodeResource(original) => {
                                norito::Error::ScopedDecodeResource(original)
                            }
                            other => norito::Error::Message(other.to_string()),
                        })
                    })
                    .unwrap()
            })
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let original = error.into_local_refusal().unwrap();
    drop(decoder);
    drop(caller);
    assert_eq!(
        pool.reserved_bytes(),
        PreparedDecodeWorkspace::allocation_layouts()[0].size()
    );
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(norito::json::from_str::<Evidence>(&json).unwrap(), proof);
}

#[test]
fn native_protocol_sequence_ceiling_stays_terminal_with_equal_caller_limits() {
    let proof = proof();
    let original = proof.native_frame();
    let native = proof.decode_native().unwrap();
    let NativeEvidence::ConflictingCertificates(first, _) = native else {
        panic!("original proof")
    };
    let mut marker = (first.signers.as_bytes().len() as u64)
        .to_le_bytes()
        .to_vec();
    marker.extend_from_slice(first.signers.as_bytes());
    let positions: Vec<_> = original
        .windows(marker.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == marker).then_some(offset))
        .collect();
    assert_eq!(positions.len(), 2);
    let header = norito::core::Header::read(std::io::Cursor::new(original)).unwrap();
    let payload_start = original.len() - usize::try_from(header.length).unwrap();
    let defaults = norito::canonical_decode_limits(original.len());
    let count = defaults.max_sequence_elements().checked_add(1).unwrap();
    let mut invalid = original.to_vec();
    invalid[positions[0]..positions[0] + 8].copy_from_slice(&(count as u64).to_le_bytes());
    let checksum = norito::core::crc64_fallback(&invalid[payload_start..]);
    let checksum_offset = norito::core::Header::SIZE - 1 - 8;
    invalid[checksum_offset..checksum_offset + 8].copy_from_slice(&checksum.to_le_bytes());
    let reread = norito::core::Header::read(std::io::Cursor::new(&invalid)).unwrap();
    assert_eq!(reread.schema, header.schema);
    assert_eq!(reread.flags, header.flags);
    assert_eq!(reread.length, header.length);
    assert_eq!(reread.checksum, checksum);
    let error =
        norito::with_decode_limits_scope(defaults, || Evidence::decode_native_frame(&invalid))
            .unwrap_err();
    assert!(
        matches!(error, CodecError::Norito(_)),
        "own decoder protocol ceiling is terminal: {error:?}"
    );
    assert!(error.to_string().contains("sequence"));
    assert_eq!(proof.decode_native().unwrap().encode().unwrap(), original);
}

#[test]
fn completed_native_decode_precedes_real_pair_output_allocator_refusal_and_exact_retry() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REFUSE.with(|v| v.set(None));
            REFUSE_SKIP_MATCHES.with(|v| v.set(0));
        }
    }
    let proof = proof();
    let expected = proof.decode_native().unwrap();
    let NativeEvidence::ConflictingCertificates(ref first, ref second) = expected else {
        panic!("original pair")
    };
    let first_wire = norito::encode_canonical(first).unwrap();
    let second_wire = norito::encode_canonical(second).unwrap();
    assert!(
        first_wire < second_wire,
        "original complete framed pair order"
    );
    let layout = Layout::array::<u8>(norito::canonical_frame_len(first).unwrap()).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let mut source = ChargedBuffer::new(proof.native_frame().len(), &pool).unwrap();
    source.append(proof.native_frame()).unwrap();
    let pointer = source.as_slice().as_ptr();
    let hash = Hash::new(source.as_slice());
    let floor = pool.reserved_bytes();
    REFUSE_SKIP_MATCHES.with(|v| assert_eq!(v.get(), 0));
    REFUSE.with(|v| assert!(v.replace(Some(layout)).is_none()));
    let reset = Reset;
    let native = NativeEvidence::decode(source.as_slice()).unwrap();
    assert_eq!(native, expected);
    assert_eq!(
        REFUSE.with(Cell::get),
        Some(layout),
        "complete native parsing has no pair-output request"
    );
    let failure = Evidence::decode_native_frame(source.as_slice()).unwrap_err();
    assert!(
        REFUSE.with(|v| v.get().is_none()),
        "original pair output allocation was actually attempted"
    );
    drop(reset);
    let CodecError::Resource(original) = failure else {
        panic!("original pair allocator cause")
    };
    assert_eq!(original.kind(), DecodeLocalRefusalKind::Allocator);
    assert_eq!(original.allocation_bytes(), Some(layout.size() as u64));
    let (last, count) = measured(|| original.clone());
    assert_eq!(count, 0);
    assert_eq!(last, original);
    assert_eq!(source.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(source.as_slice()), hash);
    assert_eq!(pool.reserved_bytes(), floor);
    let retry = Evidence::decode_native_frame(source.as_slice()).unwrap();
    assert_eq!(retry, expected);
    assert_eq!(retry.encode().unwrap(), source.as_slice());
    let NativeEvidence::ConflictingCertificates(a, b) = retry else {
        panic!("same pair")
    };
    assert_eq!(norito::encode_canonical(&a).unwrap(), first_wire);
    assert_eq!(norito::encode_canonical(&b).unwrap(), second_wire);
    drop((original, last, source));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn completed_native_decode_precedes_exact_pair_cumulative_refusal_with_original_counter() {
    let proof = proof();
    let original = proof.native_frame();
    let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let (native, work) =
        norito::core::with_decode_limits_measured(limits, || NativeEvidence::decode(original));
    let native = native.unwrap();
    let NativeEvidence::ConflictingCertificates(ref first, ref second) = native else {
        panic!("original pair")
    };
    let first_wire = norito::encode_canonical(first).unwrap();
    let second_wire = norito::encode_canonical(second).unwrap();
    let first_len = norito::canonical_frame_len(first).unwrap();
    assert!(first_wire < second_wire);
    assert_eq!(first_len, first_wire.len());
    let budget = work.total_allocated_bytes();
    let narrow = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, budget, usize::MAX);
    assert_eq!(
        norito::with_decode_limits_scope(narrow, || NativeEvidence::decode(original)).unwrap(),
        native,
        "complete native parser and canonical authentication fit exact original work ceiling"
    );
    let pool = AllocationBudget::new(1 << 20);
    let mut caller = workspace(&pool);
    let mut decoder = workspace(&pool);
    let pointer = original.as_ptr();
    let hash = Hash::new(original);
    let failure = caller
        .with_limits(narrow, narrow, || {
            classify_decode_attempt(|| {
                decoder
                    .with_limits(limits, limits, || {
                        proof.decode_native().map_err(norito::Error::from)
                    })
                    .unwrap()
            })
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let original_cause = failure.into_local_refusal().unwrap();
    assert_eq!(
        original_cause.resource_error(),
        norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: (budget + first_len) as u64,
            limit: budget as u64
        }
    );
    assert_eq!(proof.native_frame().as_ptr(), pointer);
    assert_eq!(Hash::new(proof.native_frame()), hash);
    assert_eq!(proof.decode_native().unwrap(), native);
    let last = original_cause.clone();
    drop(original_cause);
    drop(decoder);
    drop(caller);
    assert_eq!(
        pool.reserved_bytes(),
        PreparedDecodeWorkspace::allocation_layouts()[0].size()
    );
    drop(last);
    assert_eq!(pool.reserved_bytes(), 0);
}
