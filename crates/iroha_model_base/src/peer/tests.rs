//! Peer identity bounded-output and public-key resource error contracts.

use super::*;

#[test]
fn peer_id_bounded_json_delegates_to_public_key_without_scratch() {
    let literal = "ed01201C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B";
    let peer_id = PeerId::new(literal.parse::<PublicKey>().expect("valid key"));
    let expected = format!("\"{literal}\"");
    assert_eq!(
        json::to_json_bounded(&peer_id, expected.len()).expect("exact checked PeerId JSON"),
        expected
    );
    assert!(matches!(
        json::to_json_bounded(&peer_id, expected.len() - 1),
        Err(json::BoundedJsonError::BodyTooLarge)
    ));
    let map = std::collections::BTreeMap::from([(&peer_id, 3_u8)]);
    let expected_map = format!("{{\"{literal}\":3}}");
    assert_eq!(
        json::to_json_bounded(&map, expected_map.len())
            .expect("serialize borrowed PeerId key at exact bound"),
        expected_map
    );
    assert!(matches!(
        json::to_json_bounded(&map, expected_map.len() - 1),
        Err(json::BoundedJsonError::BodyTooLarge)
    ));
}

#[test]
fn peer_id_json_decode_preserves_public_key_resource_errors() {
    let literal = "ed01201C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B";
    let encoded = format!("\"{literal}\"");
    let limits = norito::core::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        literal.len(),
        usize::MAX,
    );
    let (decoded, usage) =
        norito::core::with_decode_limits_measured(limits, || json::from_str::<PeerId>(&encoded));
    assert!(matches!(
        decoded,
        Err(json::Error::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        ))
    ));
    assert_eq!(
        usage.total_allocated_bytes(),
        literal.len(),
        "the JSON string allocation should be admitted before PublicKey retention is denied"
    );
}

#[test]
fn peer_id_json_wraps_only_semantic_public_key_errors() {
    let error = json::from_str::<PeerId>(r#""not-a-public-key""#)
        .expect_err("invalid public key must fail");
    assert!(matches!(
        error,
        json::Error::InvalidField { field, .. } if field == "peer_id"
    ));
}
