//! Current frame assertions with scrubbed encodings and payload-free diagnostics.

/// Check the literal owner of a real frame, including encode-only signing views.
pub fn assert_frame_encoding<T: norito::NoritoSerialize>(
    value: &T,
    nominal: &str,
    frame: &str,
) -> zeroize::Zeroizing<Vec<u8>> {
    assert!(T::nominal_name() == nominal, "unexpected nominal owner");
    assert!(T::frame_name() == frame, "unexpected frame projection");
    let encoded = zeroize::Zeroizing::new(norito::encode_canonical(value).expect("encode frame"));
    let view = norito::core::from_bytes_view(&encoded).expect("valid frame header");
    assert!(view.schema() == norito::schema::identity::frame_hash::<T>());
    assert!(view.schema() == norito::core::schema_hash_for_name(frame));
    encoded
}

/// Check exact framing and reject substituted, truncated, or suffixed frames.
pub fn assert_current_frame<T>(value: &T, nominal: &str, frame: &str) -> zeroize::Zeroizing<Vec<u8>>
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    let encoded = assert_frame_encoding(value, nominal, frame);
    let decoded: T = norito::decode_canonical(&encoded).expect("decode exact frame");
    let roundtrip =
        zeroize::Zeroizing::new(norito::encode_canonical(&decoded).expect("re-encode frame"));
    assert!(
        encoded.as_slice() == roundtrip.as_slice(),
        "frame roundtrip differs"
    );
    let mut substituted = zeroize::Zeroizing::new(encoded.to_vec());
    substituted[6] ^= 1;
    assert!(matches!(
        norito::decode_canonical::<T>(&substituted),
        Err(norito::Error::SchemaMismatch)
    ));
    assert!(norito::decode_canonical::<T>(&encoded[..encoded.len() - 1]).is_err());
    let mut trailing = zeroize::Zeroizing::new(encoded.to_vec());
    trailing.push(0);
    assert!(norito::decode_canonical::<T>(&trailing).is_err());
    encoded
}

/// Check nominal composition without requiring clone or a decoder for signing views.
pub fn assert_nominal_container_frames<T: norito::NoritoSerialize>(
    make: impl Fn() -> T,
    nominal: &str,
    frame: &str,
) {
    // This is a test of a source-derived declaration, not an identity fallback.
    assert!(
        std::any::type_name::<T>() == nominal,
        "unexpected source owner"
    );
    assert!(nominal != frame, "fixture must exercise a projected root");
    assert_frame_encoding(&make(), nominal, frame);
    let option_name = format!("core::option::Option<{nominal}>");
    let vec_name = format!("alloc::vec::Vec<{nominal}>");
    let option_hash = norito::schema::identity::frame_hash::<Option<T>>();
    let vec_hash = norito::schema::identity::frame_hash::<Vec<T>>();
    assert!(
        option_hash
            != norito::core::schema_hash_for_name(&format!("core::option::Option<{frame}>"))
    );
    assert!(vec_hash != norito::core::schema_hash_for_name(&format!("alloc::vec::Vec<{frame}>")));
    assert_frame_encoding(&None::<T>, &option_name, &option_name);
    assert_frame_encoding(&Some(make()), &option_name, &option_name);
    assert_frame_encoding(&Vec::<T>::new(), &vec_name, &vec_name);
    assert_frame_encoding(&vec![make(), make()], &vec_name, &vec_name);
}
