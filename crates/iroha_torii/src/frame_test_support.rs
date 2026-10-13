//! Exact current-frame assertions for non-secret Torii test fixtures.

/// Verify one literal owner and the exact payload without printing fixture contents.
///
/// Temporary buffers are not scrubbed; use only non-secret test fixtures.
pub fn assert_current_frame<T>(value: &T, owner: &str) -> Vec<u8>
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    assert!(T::nominal_name() == owner, "unexpected nominal frame owner");
    assert!(T::frame_name() == owner, "unexpected projected frame owner");
    let encoded = norito::encode_canonical(value).expect("current frame");
    assert!(encoded[6..22] == norito::schema::identity::frame_hash::<T>());
    let decoded: T = norito::decode_canonical(&encoded).expect("exact frame roundtrip");
    assert!(
        norito::codec::encode_adaptive(&decoded) == norito::codec::encode_adaptive(value),
        "roundtrip changed the payload"
    );
    let mut wrong_owner = encoded.clone();
    wrong_owner[6] ^= 1;
    assert!(matches!(
        norito::decode_canonical::<T>(&wrong_owner),
        Err(norito::Error::SchemaMismatch)
    ));
    assert!(norito::decode_canonical::<T>(&encoded[..encoded.len() - 1]).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(norito::decode_canonical::<T>(&trailing).is_err());
    encoded
}
