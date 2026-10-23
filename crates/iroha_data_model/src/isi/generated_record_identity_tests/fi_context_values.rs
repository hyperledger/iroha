//! Explicit first-release producer. No captured bytes or schema hashes are invented.
use super::*;

#[test]
#[ignore = "explicit maintenance command captures typed FI context assertions"]
fn print_fi_context_assertion_record_fixture_rows() {
    fn row<T>(values: impl IntoIterator<Item = T>) -> Value
    where
        T: NoritoSchema
            + NoritoSerialize
            + for<'de> NoritoDeserialize<'de>
            + Clone
            + Debug
            + PartialEq,
    {
        let values: Vec<_> = values.into_iter().map(capture).collect();
        let first = values.first().unwrap();
        for value in &values {
            assert_eq!(value.get("nominal"), first.get("nominal"));
            assert_eq!(value.get("serialize_hash"), first.get("serialize_hash"));
            assert_eq!(value.get("deserialize_hash"), first.get("deserialize_hash"));
        }
        json::object([
            ("nominal", first.get("nominal").unwrap().clone()),
            (
                "serialize_hash",
                first.get("serialize_hash").unwrap().clone(),
            ),
            (
                "deserialize_hash",
                first.get("deserialize_hash").unwrap().clone(),
            ),
            (
                "cases",
                Value::Array(values.iter().map(frame_fields).collect()),
            ),
        ])
        .unwrap()
    }
    let rows = vec![
        row([
            crate::isi::asset_fi_context::test_values::current(false),
            crate::isi::asset_fi_context::test_values::current(true),
        ]),
        row([crate::isi::asset_fi_context::test_values::historical()]),
    ];
    println!(
        "FI_CONTEXT_ASSERTION_FIXTURE_ROWS={}",
        json::to_json(&rows).unwrap()
    );
}
