//! Fixed JSON schema metadata follows the same field rules as the writer.

#![cfg(feature = "json")]

use norito::json::{FastJsonWrite, JsonSerialize};

#[derive(norito::derive::JsonSerialize)]
#[norito(rename_all = "camelCase")]
struct Fixed {
    first_field: u8,
    #[norito(skip)]
    omitted: String,
    #[norito(rename = "exact_name")]
    last_field: bool,
}

#[test]
fn fixed_order_matches_emitted_keys_and_needs_no_value() {
    assert_eq!(
        Fixed::json_object_field_order(),
        Some(["firstField", "exact_name"].as_slice())
    );
    let value = Fixed {
        first_field: 7,
        omitted: "this skipped data must not appear in JSON".into(),
        last_field: true,
    };
    let mut encoded = String::new();
    value.json_serialize(&mut encoded);
    assert_eq!(encoded, r#"{"firstField":7,"exact_name":true}"#);
    assert_eq!(value.omitted, "this skipped data must not appear in JSON");
}

#[derive(norito::derive::JsonSerialize)]
struct Conditional {
    #[norito(skip_serializing_if = "Option::is_none")]
    value: Option<u8>,
}

#[derive(norito::derive::JsonSerialize)]
struct Flattened {
    #[norito(flatten)]
    values: std::collections::BTreeMap<String, u8>,
}

#[test]
fn dynamic_objects_do_not_claim_a_fixed_schema() {
    assert_eq!(Conditional::json_object_field_order(), None);
    assert_eq!(Flattened::json_object_field_order(), None);
}
