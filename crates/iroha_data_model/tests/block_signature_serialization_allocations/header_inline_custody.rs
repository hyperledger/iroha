//! Actual allocation-free header transport and original enclosing-reader custody.
use super::*;
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::confidential::ConfidentialFeatureDigest;
use norito::core::{
    DecodeAttemptErrorKind, DecodeLimits, DecodeResourceError, PreparedDecodeWorkspace,
    SequenceSpan, classify_decode_attempt,
};

fn marked<T>(source: &[u8]) -> HashOf<T> {
    HashOf::from_untyped_unchecked(Hash::new(source))
}
fn fixture() -> BlockHeader {
    // Complete twelve-field transport only: original hashes/digest children
    // are not authenticated confidential policy, payload or native ancestry.
    let mut header = BlockHeader::new(
        std::num::NonZeroU64::new(7).unwrap(),
        Some(marked(b"original header parent")),
        Some(marked(b"original header merkle")),
        123_456_789,
        3,
    );
    header.set_da_proof_policies_hash(Some(marked(b"original header proof policies")));
    header.set_da_commitments_hash(Some(marked(b"original header commitments")));
    header.set_da_pin_intents_hash(Some(marked(b"original header pin intents")));
    header.set_npos_effects_hash(Some(marked(b"original header npos")));
    header.set_execution_context_hash(Some(marked(b"original header execution context")));
    header.set_global_beacon_pulse_hash(Some(marked(b"original header pulse")));
    header.set_confidential_features(Some(ConfidentialFeatureDigest::new(
        Some([17; 32]),
        Some(23),
        Some(29),
        Some(31),
        Some([37; 32]),
    )));
    header
}
fn source(
    value: &BlockHeader,
    pool: &AllocationBudget,
    prefix: usize,
    flags: u8,
) -> (ChargedBuffer<u8>, SequenceSpan) {
    let bytes = bare_bytes(value, flags);
    let mut input = ChargedBuffer::new(prefix + bytes.len(), pool).unwrap();
    input.append(&vec![0xa5; prefix]).unwrap();
    input.append(&bytes).unwrap();
    (
        input,
        SequenceSpan {
            start: prefix,
            end: prefix + bytes.len(),
        },
    )
}
fn prepaid_workspace(pool: &AllocationBudget) -> PreparedDecodeWorkspace {
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    let workspace = PreparedDecodeWorkspace::from_reservation(pool, &mut reservation).unwrap();
    assert_eq!(reservation.remaining_bytes(), 0);
    assert!(workspace.belongs_to(pool));
    workspace
}

fn measured<T>(run: impl FnOnce() -> T) -> (T, usize) {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            TRACKING.with(|tracking| tracking.set(false));
        }
    }
    TRACKING.with(|tracking| assert!(!tracking.replace(true)));
    ALLOCATIONS.with(|count| count.set(0));
    let guard = Restore;
    let value = run();
    let count = ALLOCATIONS.with(Cell::get);
    drop(guard);
    (value, count)
}

#[test]
fn header_all_inline_children_decode_with_zero_actual_allocations_at_every_source_alignment() {
    let full = fixture();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for features in [
            None,
            Some(ConfidentialFeatureDigest::new(None, None, None, None, None)),
            full.confidential_features(),
        ] {
            let mut original = full;
            original.set_confidential_features(features);
            for prefix in 0..16 {
                let pool = AllocationBudget::new(1 << 20);
                let (input, span) = source(&original, &pool, prefix, flags);
                let floor = pool.reserved_bytes();
                let pointer = input.as_slice().as_ptr();
                let hash = Hash::new(input.as_slice());
                let mut workspace = prepaid_workspace(&pool);
                let controls = PreparedDecodeWorkspace::allocation_layouts()
                    .iter()
                    .map(Layout::size)
                    .sum::<usize>();
                assert_eq!(pool.reserved_bytes(), floor + controls);
                let limits = DecodeLimits::new(0, 1 << 20, 0, 0, 64);
                let bytes = span.get(input.as_slice()).unwrap();
                let (ordinary, used) =
                    norito::core::decode_field_canonical::<BlockHeader>(bytes).unwrap();
                assert_eq!(ordinary, original);
                assert_eq!(used, bytes.len());
                let warm = workspace
                    .with_limits(limits, limits, || BlockHeader::decode_inline_payload(bytes))
                    .unwrap()
                    .unwrap();
                assert_eq!(warm, original);
                pool.set_limit_bytes(0);
                let (decoded, allocations) = measured(|| {
                    workspace
                        .with_limits(limits, limits, || BlockHeader::decode_inline_payload(bytes))
                });
                assert_eq!(
                    allocations,
                    0,
                    "flags {flags:#x}, original alignment {}",
                    bytes.as_ptr().addr() % 8
                );
                let decoded = decoded.unwrap().unwrap();
                assert_eq!(decoded, original);
                assert_eq!(decoded.hash(), original.hash());
                assert_eq!(pool.reserved_bytes(), floor + controls);
                assert_eq!(input.as_slice().as_ptr(), pointer);
                assert_eq!(Hash::new(input.as_slice()), hash);
                assert_eq!(bare_bytes(&decoded, flags), bytes);
                drop(workspace);
                assert_eq!(pool.reserved_bytes(), floor);
                drop(input);
                assert_eq!(pool.reserved_bytes(), 0);
            }
        }
    }
}

#[test]
fn header_original_nonzero_height_enclosing_cause_keeps_prepaid_counter_reader_through_retry_and_last_refund()
 {
    let flags = header_flags::COMPACT_LEN;
    let _flags = DecodeFlagsGuard::enter(flags);
    let original = fixture();
    let pool = AllocationBudget::new(1 << 20);
    let (input, span) = source(&original, &pool, 9, flags);
    let floor = pool.reserved_bytes();
    let pointer = input.as_slice().as_ptr();
    let hash = Hash::new(input.as_slice());
    let mut caller = prepaid_workspace(&pool);
    let mut decoder = prepaid_workspace(&pool);
    let controls = PreparedDecodeWorkspace::allocation_layouts();
    assert_eq!(
        pool.reserved_bytes(),
        floor + 2 * controls.iter().map(Layout::size).sum::<usize>()
    );
    let protocol = DecodeLimits::new(0, 1 << 20, 0, 0, 64);
    let narrow = DecodeLimits::new(0, 1, 0, 0, 64);
    let bytes = span.get(input.as_slice()).unwrap();
    let (failed, allocations) = measured(|| {
        caller.with_limits(narrow, narrow, || {
            classify_decode_attempt(|| {
                decoder
                    .with_limits(protocol, protocol, || {
                        BlockHeader::decode_inline_payload(bytes)
                    })
                    .unwrap()
            })
        })
    });
    assert_eq!(allocations, 0);
    let cause = failed.unwrap().unwrap_err();
    assert_eq!(cause.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        std::error::Error::source(&cause)
            .unwrap()
            .downcast_ref::<norito::Error>()
            .unwrap()
            .decode_resource_error(),
        Some(DecodeResourceError::FieldLengthExceeded {
            length: std::mem::size_of::<std::num::NonZeroU64>() as u64,
            limit: 1
        })
    );
    pool.set_limit_bytes(0);
    let (retry, allocations) = measured(|| {
        decoder.with_limits(protocol, protocol, || {
            BlockHeader::decode_inline_payload(bytes)
        })
    });
    assert_eq!(allocations, 0);
    let recovered = retry.unwrap().unwrap();
    assert_eq!(recovered, original);
    assert_eq!(recovered.hash(), original.hash());
    assert_eq!(bare_bytes(&recovered, flags), bytes);
    assert_eq!(cause.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(input.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(input.as_slice()), hash);
    drop(decoder);
    drop(caller);
    assert_eq!(pool.reserved_bytes(), floor + controls[0].size());
    assert_eq!(
        cause.into_error().decode_resource_error(),
        Some(DecodeResourceError::FieldLengthExceeded {
            length: std::mem::size_of::<std::num::NonZeroU64>() as u64,
            limit: 1
        })
    );
    assert_eq!(pool.reserved_bytes(), floor);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}

struct LocateHeaderHeight {
    base: usize,
    height: Option<std::ops::Range<usize>>,
}
impl norito::core::FieldDestination for LocateHeaderHeight {
    type Error = std::convert::Infallible;
}
impl<const INDEX: usize, T> norito::core::DecodeField<INDEX, T> for LocateHeaderHeight {
    type Value = ();
    fn decode_field(
        &mut self,
        field: norito::core::CanonicalField<'_, T>,
    ) -> Result<(), norito::core::DecodeIntoError<Self::Error>> {
        if INDEX == 0 {
            let start = field
                .bytes()
                .as_ptr()
                .addr()
                .checked_sub(self.base)
                .unwrap();
            self.height = Some(start..start.checked_add(field.bytes().len()).unwrap());
        }
        Ok(())
    }
}

#[test]
fn original_header_alignment_refusal_and_inline_nonzero_invalidity_keep_their_actual_causes_and_original_counter()
 {
    use norito::core::DecodeRecordFields;
    let flags = header_flags::COMPACT_LEN;
    let _flags = DecodeFlagsGuard::enter(flags);
    let original = fixture();
    let wire = bare_bytes(&original, flags);
    let alignment = norito::core::archived_payload_align::<BlockHeader>();
    assert!(alignment > 1);
    let pool = AllocationBudget::new(1 << 20);
    let mut input =
        ChargedBuffer::<u8>::new(wire.len().checked_add(alignment - 1).unwrap(), &pool).unwrap();
    let prefix = (1 + alignment - input.as_slice().as_ptr().addr() % alignment) % alignment;
    input.append(&vec![0xa5; prefix]).unwrap();
    input.append(&wire).unwrap();
    let span = SequenceSpan {
        start: prefix,
        end: prefix + wire.len(),
    };
    let height = {
        let bytes = span.get(input.as_slice()).unwrap();
        assert_eq!(bytes.as_ptr().addr() % alignment, 1);
        let mut fields = LocateHeaderHeight {
            base: bytes.as_ptr().addr(),
            height: None,
        };
        let (_, used) = BlockHeader::decode_fields(bytes, &mut fields).unwrap();
        assert_eq!(used, bytes.len());
        fields.height.unwrap()
    };
    assert_eq!(height.len(), std::mem::size_of::<std::num::NonZeroU64>());
    let floor = pool.reserved_bytes();
    let mut caller = prepaid_workspace(&pool);
    let mut decoder = prepaid_workspace(&pool);
    assert_eq!(
        pool.reserved_bytes(),
        floor
            + 2 * PreparedDecodeWorkspace::allocation_layouts()
                .iter()
                .map(Layout::size)
                .sum::<usize>()
    );
    let zero = DecodeLimits::new(0, wire.len(), 0, 0, 64);
    assert_eq!(
        decoder
            .with_limits(zero, zero, || BlockHeader::decode_inline_payload(
                span.get(input.as_slice()).unwrap()
            ))
            .unwrap()
            .unwrap(),
        original
    );
    input.as_mut_slice()[span.start + height.start..span.start + height.end].fill(0);

    let pointer = input.as_slice().as_ptr();
    let hash = Hash::new(input.as_slice());
    let bytes = span.get(input.as_slice()).unwrap();
    let copied_bytes = bytes.len();
    let protocol = norito::canonical_decode_limits(copied_bytes);
    pool.set_limit_bytes(0);
    let (owning, allocations) = measured(|| {
        caller.with_limits(zero, zero, || {
            classify_decode_attempt(|| {
                decoder
                    .with_limits(protocol, protocol, || {
                        norito::core::decode_field_canonical::<BlockHeader>(bytes)
                    })
                    .unwrap()
            })
        })
    });
    assert_eq!(
        allocations, 0,
        "logical copy refusal must precede the actual heap allocation"
    );
    let owning = owning.unwrap().unwrap_err();
    assert_eq!(owning.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        std::error::Error::source(&owning)
            .unwrap()
            .downcast_ref::<norito::Error>()
            .unwrap()
            .decode_resource_error(),
        Some(DecodeResourceError::TotalAllocationExceeded {
            attempted: copied_bytes as u64,
            limit: 0
        })
    );
    let (inline, allocations) = measured(|| {
        classify_decode_attempt(|| {
            decoder
                .with_limits(zero, zero, || BlockHeader::decode_inline_payload(bytes))
                .unwrap()
        })
    });
    assert_eq!(allocations, 0);
    let inline = inline.unwrap_err();
    assert_eq!(inline.kind(), DecodeAttemptErrorKind::Invalid);
    assert!(matches!(inline.into_error(), norito::Error::InvalidNonZero));
    assert_eq!(owning.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(input.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(input.as_slice()), hash);
    drop(decoder);
    drop(caller);
    assert_eq!(
        pool.reserved_bytes(),
        floor + PreparedDecodeWorkspace::allocation_layouts()[0].size()
    );
    assert_eq!(
        owning.into_error().decode_resource_error(),
        Some(DecodeResourceError::TotalAllocationExceeded {
            attempted: copied_bytes as u64,
            limit: 0
        })
    );
    assert_eq!(pool.reserved_bytes(), floor);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}
