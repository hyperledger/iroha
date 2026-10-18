#[test]
fn string_and_str_decode_require_payload_context() {
    clear_payload_ctx();
    let mut payload = Vec::new();
    payload.extend_from_slice(&2u64.to_le_bytes());
    payload.extend_from_slice(b"ok");
    // Archived markers are byte-aligned, so the payload is used at its own address.
    let archived_string = borrowed_archived_marker::<String>(&payload);
    let error = String::try_deserialize(archived_string)
        .expect_err("a raw archived address has no payload bounds");
    assert!(matches!(error, Error::MissingPayloadContext));
    clear_payload_ctx();
    let archived_str = borrowed_archived_marker::<&str>(&payload);
    let error = <&str as DeserializePayload>::try_deserialize(archived_str)
        .expect_err("a raw archived address has no payload bounds");
    assert!(matches!(error, Error::MissingPayloadContext));
    let _payload = PayloadCtxGuard::enter_with_flags(&payload, 0);
    assert_eq!(
        String::try_deserialize(archived_string).expect("string"),
        "ok"
    );
    assert_eq!(
        <&str as DeserializePayload>::try_deserialize(archived_str).expect("str"),
        "ok"
    );
}
#[test]
fn aos_views_reject_oversize_field_len() {
    reset_decode_state();
    let _guard = DecodeFlagsGuard::enter(0);
    let overflow = (usize::MAX as u128)
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(16);
    let mut body = Vec::new();
    body.extend_from_slice(&1u64.to_le_bytes());
    body.push(crate::aos::AOS_FORMAT_VERSION);
    body.extend_from_slice(&1u64.to_le_bytes());
    body.extend_from_slice(&overflow.to_le_bytes());
    let result = crate::columnar::view_aos_u64_str_bool(&body);
    assert!(matches!(result, Err(Error::LengthMismatch)));
}
