//! Capture native diagnostic status DTO frames and the composed `/status` fixture.

use std::{fs, path::PathBuf};

use anyhow::{Context as _, Result, ensure};
use iroha_torii_shared::status::{CryptoStatus, DiagnosticTraceStatus, Status};
use norito::{
    NoritoSchema,
    core::{NoritoDeserialize, NoritoSerialize},
    json::{self, JsonDeserialize, JsonSerialize, Value},
};

fn capture<T>(fixtures: &mut Value, name: &str) -> Result<()>
where
    T: NoritoSchema
        + NoritoSerialize
        + for<'de> NoritoDeserialize<'de>
        + JsonSerialize
        + JsonDeserialize,
{
    let record = fixtures
        .as_object_mut()
        .and_then(|records| records.get_mut(name))
        .and_then(Value::as_object_mut)
        .with_context(|| format!("missing fixture record {name}"))?;
    let expected = record.get("json").context("missing fixture JSON")?;
    let value: T = json::from_value(expected.clone()).context("decode current typed JSON")?;
    ensure!(
        json::to_value(&value)? == *expected,
        "noncanonical JSON for {name}"
    );
    let bytes = norito::to_bytes(&value)?;
    let decoded: T = norito::decode_from_bytes(&bytes)?;
    ensure!(
        json::to_value(&decoded)? == *expected,
        "roundtrip failed for {name}"
    );
    record.insert("wire_hex".into(), Value::String(hex::encode(&bytes)));
    let hash = hex::encode(norito::schema::identity::frame_hash::<T>());
    record.insert("serialize_schema_hash".into(), Value::String(hash.clone()));
    record.insert("deserialize_schema_hash".into(), Value::String(hash));
    record.insert("schema_name".into(), Value::String(T::frame_name()));
    Ok(())
}

fn main() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let input = PathBuf::from(arguments.next().context("expected input fixture path")?);
    let output = PathBuf::from(arguments.next().context("expected output capture path")?);
    ensure!(arguments.next().is_none(), "unexpected argument");
    ensure!(
        fs::metadata(&input)?.len() <= 1_048_576,
        "fixture exceeds 1 MiB"
    );
    let mut fixtures: Value = json::from_slice(&fs::read(input)?)?;
    capture::<DiagnosticTraceStatus>(&mut fixtures, "DiagnosticTraceStatus")?;
    capture::<CryptoStatus>(&mut fixtures, "CryptoStatus")?;
    capture::<Status>(&mut fixtures, "Status")?;
    let rendered = json::to_json_pretty(&fixtures)?;
    ensure!(rendered.len() < 1_048_576, "capture exceeds 1 MiB");
    fs::write(output, format!("{rendered}\n"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_trace_frame_comes_from_the_current_typed_value() {
        let expected = json::to_value(&DiagnosticTraceStatus::default()).unwrap();
        let mut records = json::Map::new();
        let mut record = json::Map::new();
        record.insert("json".into(), expected.clone());
        records.insert("DiagnosticTraceStatus".into(), Value::Object(record));
        let mut fixtures = Value::Object(records);
        capture::<DiagnosticTraceStatus>(&mut fixtures, "DiagnosticTraceStatus").unwrap();
        let bytes = hex::decode(
            fixtures["DiagnosticTraceStatus"]["wire_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let decoded: DiagnosticTraceStatus = norito::decode_from_bytes(&bytes).unwrap();
        assert_eq!(json::to_value(&decoded).unwrap(), expected);
        assert!(
            norito::decode_from_bytes::<DiagnosticTraceStatus>(&bytes[..bytes.len() - 1]).is_err()
        );
    }
}
