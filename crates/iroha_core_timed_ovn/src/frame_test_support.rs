//! Exact frame assertions for extracted public protocol owners.

/// Verify one declared owner frame, reconstruction, and strict malformed-frame rejection.
pub(super) fn assert_owner_frame_v1<T>(value: &T, nominal: &str)
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de> + PartialEq,
{
    assert_eq!(T::nominal_name(), nominal);
    assert_eq!(T::frame_name(), nominal);
    let frame = norito::encode_canonical(value).expect("declared owner frame encodes");
    assert_eq!(frame[6..22], norito::schema::identity::frame_hash::<T>());
    let decoded: T = norito::decode_canonical(&frame).expect("declared owner frame decodes");
    assert!(
        decoded == *value,
        "owner frame must preserve every payload field"
    );
    assert_eq!(
        norito::encode_canonical(&decoded).expect("owner re-encodes"),
        frame
    );
    let mut wrong_owner = frame.clone();
    wrong_owner[6] ^= 1;
    assert!(matches!(
        norito::decode_canonical::<T>(&wrong_owner),
        Err(norito::Error::SchemaMismatch)
    ));
    assert!(norito::decode_canonical::<T>(&frame[..frame.len() - 1]).is_err());
    let mut trailing = frame;
    trailing.push(0);
    assert!(norito::decode_canonical::<T>(&trailing).is_err());
}
