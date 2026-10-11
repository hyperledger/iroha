//! Exact shared PeerId field framing, crypto work charges and original retry custody.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use norito::core::{
    DecodeAttemptErrorKind, DecodeFlagsGuard, DecodeLimits, OwnedFields, archived_payload_align,
    classify_decode_attempt, header_flags, with_decode_limits_measured, with_decode_limits_scope,
};

#[test]
fn prepared_peer_field_retains_complete_framing_and_crypto_logical_charges() {
    let keys = KeyPair::from_seed(vec![0x6b; 32], Algorithm::BlsNormal);
    let source = PeerId::new(keys.public_key().clone());
    let width = source.public_key().retained_allocation_layout().size();
    let pool = AllocationBudget::new(width);
    let mut destination = Peer::new(source.public_key(), &pool).unwrap();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let mut encoded = Vec::new();
        source
            .serialize(&mut Encoder::for_buffer(&mut encoded))
            .unwrap();
        let (field_bytes, prefix_bytes) = norito::core::inspect_len_from_slice(&encoded).unwrap();
        assert_eq!(prefix_bytes + field_bytes, encoded.len());
        // Pin the ordinary PublicKey child at its actual required alignment.
        // Its enclosing record walk is a slice kernel, so it need not have an
        // archived pointer. Unaligned owned child copies are separate physical
        // costs; this control compares the common logical decoding contract.
        let alignment = archived_payload_align::<PublicKey>();
        let mut storage = vec![0; encoded.len() + alignment - 1];
        let offset =
            (alignment - ((storage.as_ptr() as usize + prefix_bytes) % alignment)) % alignment;
        storage[offset..offset + encoded.len()].copy_from_slice(&encoded);
        let bytes = &storage[offset..offset + encoded.len()];
        assert_eq!((bytes.as_ptr() as usize + prefix_bytes) % alignment, 0);
        // PeerId's field framing borrows its complete PublicKey payload. The
        // child charges count + each element payload + compact backing;
        // borrowed framing contributes no allocation charge.
        let required = 3 * width;
        let protocol = DecodeLimits::new(4096, 4096, 4096, required, 32);
        let (owned, owned_usage) = with_decode_limits_measured(protocol, || {
            PeerId::decode_fields(bytes, &mut OwnedFields)
        });
        let ((key,), used) = owned.unwrap();
        assert_eq!(key, *source.public_key());
        assert_eq!(used, bytes.len());
        let (prepared, prepared_usage) =
            with_decode_limits_measured(protocol, || destination.decode(bytes));
        prepared.unwrap();
        assert_eq!(owned_usage.total_allocated_bytes(), required);
        assert_eq!(prepared_usage, owned_usage);
        assert_eq!(pool.reserved_bytes(), width);
        let pointer = destination.key.decoded_compact().unwrap().as_ptr();
        for allowed in [width - 1, width, 2 * width - 1, 2 * width, required - 1] {
            let outer = DecodeLimits::new(4096, 4096, 4096, allowed, 32);
            let owned = with_decode_limits_scope(outer, || {
                classify_decode_attempt(|| {
                    with_decode_limits_scope(protocol, || {
                        PeerId::decode_fields(bytes, &mut OwnedFields)
                            .map_err(DecodeIntoError::into_codec)
                    })
                })
            })
            .unwrap_err();
            let prepared = with_decode_limits_scope(outer, || {
                classify_decode_attempt(|| {
                    with_decode_limits_scope(protocol, || {
                        destination.decode(bytes).map_err(|error| match error {
                            DecodeIntoError::Codec(original) => original,
                            error => panic!(
                                "logical limit must preserve its original codec cause: {error:?}"
                            ),
                        })
                    })
                })
            })
            .unwrap_err();
            assert_eq!(owned.kind(), DecodeAttemptErrorKind::EnclosingLimit);
            assert_eq!(prepared.kind(), owned.kind());
            assert_eq!(prepared.to_string(), owned.to_string());
            assert_eq!(
                prepared.into_error().decode_resource_error(),
                owned.into_error().decode_resource_error()
            );
            assert!(!destination.ready);
            assert!(destination.key.decoded_compact().is_none());
            assert_eq!(pool.reserved_bytes(), width);
            with_decode_limits_scope(protocol, || destination.decode(bytes)).unwrap();
            assert_eq!(destination.key.decoded_compact().unwrap().as_ptr(), pointer);
        }
        let mut reproduced = Vec::new();
        destination
            .serialize(&mut Encoder::for_buffer(&mut reproduced))
            .unwrap();
        assert_eq!(reproduced, encoded);
    }
    drop(destination);
    assert_eq!(pool.reserved_bytes(), 0);
}
