//! Actual Norito private-byte field controls; syntax is not checkpoint authority.
use super::PrivateFoldBytes;
use iroha_plonk_recursion::{FOLD_WITNESS_BYTES, PrivateWitnessBytes};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};
#[derive(Debug, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.private_fold_owner_test.v1")]
struct Carrier {
    before: u64,
    fold: PrivateFoldBytes,
    after: u64,
}
fn private(bytes: &[u8]) -> PrivateFoldBytes {
    PrivateFoldBytes::from_owned(
        PrivateWitnessBytes::try_write::<std::io::Error>(bytes.len(), |w| w.write_all(bytes))
            .unwrap(),
    )
}
fn encoded<T: norito::SerializePayload + norito::NoritoSchema>(value: &T) -> PrivateWitnessBytes {
    PrivateWitnessBytes::try_write::<norito::Error>(
        norito::canonical_frame_len(value).unwrap(),
        |mut w| norito::core::write_canonical_to_writer(value, &mut w),
    )
    .unwrap()
}
#[test]
fn canonical_private_field_roundtrip_preserves_original_bytes_and_extent() {
    let value = Carrier {
        before: 11,
        fold: private(&[0xa5; FOLD_WITNESS_BYTES]),
        after: 17,
    };
    let bytes = encoded(&value);
    let restored: Carrier = norito::decode_from_bytes(&bytes).unwrap();
    assert_eq!(restored.before, 11);
    assert_eq!(restored.after, 17);
    assert_eq!(restored.fold.as_slice(), value.fold.as_slice());
    assert_eq!(&*encoded(&restored), &*bytes);
    assert!(format!("{restored:?}").contains("REDACTED"));
    // Public test DATA may be invalid as a fold: this codec never grants authority.
    assert!(
        iroha_plonk_recursion::FoldWitness::<iroha_pasta::Ep>::from_private_bytes(&restored.fold)
            .is_err()
    );
}
#[test]
fn non_exact_private_field_extents_are_rejected() {
    for size in [0, 32, FOLD_WITNESS_BYTES - 1, FOLD_WITNESS_BYTES + 1] {
        let malformed = Carrier {
            before: 11,
            fold: private(&vec![0xa5; size]),
            after: 17,
        };
        let bytes = encoded(&malformed);
        assert!(
            norito::decode_from_bytes::<Carrier>(&bytes).is_err(),
            "size {size}"
        );
    }
}
#[test]
fn corrupt_or_truncated_canonical_carrier_refuses() {
    let value = Carrier {
        before: 11,
        fold: private(&[0xa5; FOLD_WITNESS_BYTES]),
        after: 17,
    };
    let bytes = encoded(&value);
    for cut in [0, 1, 32, bytes.len() - 1] {
        assert!(norito::decode_from_bytes::<Carrier>(&bytes[..cut]).is_err());
    }
    let changed = PrivateWitnessBytes::try_write::<std::io::Error>(bytes.len(), |w| {
        w.write_all(&bytes[..bytes.len() - 1])?;
        w.write_all(&[bytes[bytes.len() - 1] ^ 1])
    })
    .unwrap();
    assert!(norito::decode_from_bytes::<Carrier>(&changed).is_err());
}

#[test]
fn clones_share_one_private_allocation_and_redact_diagnostics() {
    let first = private(&[0xa5; FOLD_WITNESS_BYTES]);
    let second = first.clone();
    assert_eq!(first.as_slice().as_ptr(), second.as_slice().as_ptr());
    assert_eq!(std::sync::Arc::strong_count(&first.0), 2);
    drop(first);
    assert_eq!(std::sync::Arc::strong_count(&second.0), 1);
    assert_eq!(second[0], 0xa5);
    assert_eq!(
        format!("{second:?}"),
        "PrivateFoldBytes(PrivateWitnessBytes { private: [REDACTED] })"
    );
}
