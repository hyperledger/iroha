//! Effect-free deterministic owner for the two shared signed Musubi V1 fixtures.
mod musubi_fixture_values;
mod musubi_sdk_fixture_values;
use musubi_fixture_values::MUSUBI_FIXTURE_OUTPUTS;
use norito::json::{self, Value};
use std::{
    collections::BTreeSet,
    env,
    error::Error,
    ffi::OsString,
    io::{self, Write as _},
    path::{Component, Path},
};
const OWNER_ENVELOPE_SCHEMA_V1: &str = "iroha.musubi.signed_fixtures.owner.v1";
type AnyError = Box<dyn Error + 'static>;
#[derive(Debug)]
struct RenderedFixture {
    relative_path: &'static str,
    contents: String,
}
fn invalid(message: impl Into<String>) -> AnyError {
    io::Error::new(io::ErrorKind::InvalidInput, message.into()).into()
}
fn parse_options<I>(arguments: I) -> Result<(), AnyError>
where
    I: IntoIterator<Item = OsString>,
{
    if let Some(argument) = arguments.into_iter().next() {
        return Err(invalid(format!(
            "the Musubi fixture owner accepts no arguments; rejected {}",
            argument.display()
        )));
    }
    Ok(())
}
fn validate_relative_output(path: &str) -> Result<(), AnyError> {
    let path = Path::new(path);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid(format!(
            "fixture output path is not a safe relative path: {}",
            path.display()
        )));
    }
    Ok(())
}
fn reject_legacy_keys(value: &Value, location: &str) -> Result<(), AnyError> {
    if let Some(object) = value.as_object() {
        for (key, child) in object {
            if matches!(
                key.as_str(),
                "chain_id" | "genesis_hash" | "genesis_block_hash"
            ) {
                return Err(invalid(format!(
                    "legacy deployment key '{key}' at {location}"
                )));
            }
            reject_legacy_keys(child, &format!("{location}/{key}"))?;
        }
    } else if let Some(array) = value.as_array() {
        for (index, child) in array.iter().enumerate() {
            reject_legacy_keys(child, &format!("{location}/{index}"))?;
        }
    }
    Ok(())
}
fn render_fixture(relative_path: &'static str, value: &Value) -> Result<RenderedFixture, AnyError> {
    reject_legacy_keys(value, relative_path)?;
    let contents = format!("{}\n", json::to_string_pretty(value)?);
    let decoded: Value = json::from_str(&contents)?;
    if &decoded != value {
        return Err(invalid(format!(
            "{relative_path} does not round-trip through canonical Norito JSON"
        )));
    }
    let rerendered = format!("{}\n", json::to_string_pretty(&decoded)?);
    if rerendered != contents {
        return Err(invalid(format!(
            "{relative_path} has nondeterministic canonical JSON"
        )));
    }
    Ok(RenderedFixture {
        relative_path,
        contents,
    })
}
fn rendered_fixtures() -> Result<Vec<RenderedFixture>, AnyError> {
    let outputs = MUSUBI_FIXTURE_OUTPUTS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if outputs.len() != 2
        || outputs
            != BTreeSet::from([
                "fixtures/musubi/instructions_v1.json",
                "fixtures/musubi/sdk_v1.json",
            ])
    {
        return Err(invalid(
            "Musubi fixture output set is not the closed V1 pair",
        ));
    }
    for output in outputs {
        validate_relative_output(output)?;
    }
    Ok(vec![
        render_fixture(
            MUSUBI_FIXTURE_OUTPUTS[0],
            &musubi_fixture_values::instruction_document(),
        )?,
        render_fixture(
            MUSUBI_FIXTURE_OUTPUTS[1],
            &musubi_sdk_fixture_values::sdk_document(),
        )?,
    ])
}
fn rendered_envelope(fixtures: &[RenderedFixture]) -> Result<String, AnyError> {
    let outputs = fixtures
        .iter()
        .map(|fixture| {
            norito::json!({
                "path": (fixture.relative_path),
                "contents": (fixture.contents.as_str()),
            })
        })
        .collect::<Vec<_>>();
    let value = norito::json!({
        "schema": OWNER_ENVELOPE_SCHEMA_V1,
        "outputs": (outputs),
    });
    let contents = format!("{}\n", json::to_string(&value)?);
    let decoded: Value = json::from_str(&contents)?;
    if decoded != value {
        return Err(invalid(
            "Musubi fixture owner envelope does not round-trip through Norito JSON",
        ));
    }
    let rerendered = format!("{}\n", json::to_string(&decoded)?);
    if rerendered != contents {
        return Err(invalid(
            "Musubi fixture owner envelope is not deterministic",
        ));
    }
    Ok(contents)
}
fn run<I>(arguments: I) -> Result<String, AnyError>
where
    I: IntoIterator<Item = OsString>,
{
    parse_options(arguments)?;
    rendered_envelope(&rendered_fixtures()?)
}
fn main() -> Result<(), AnyError> {
    let envelope = run(env::args_os().skip(1))?;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(envelope.as_bytes())?;
    stdout.flush()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_accepts_no_pathname_or_mutation_arguments() {
        parse_options(Vec::<OsString>::new()).expect("argument-free emitter");
        for rejected in ["--write", "--check", "--output-root", "/tmp/stage"] {
            assert!(parse_options([OsString::from(rejected)]).is_err());
        }
    }
    #[test]
    fn output_paths_are_the_exact_safe_closed_pair() {
        assert_eq!(
            MUSUBI_FIXTURE_OUTPUTS,
            [
                "fixtures/musubi/instructions_v1.json",
                "fixtures/musubi/sdk_v1.json",
            ]
        );
        for output in MUSUBI_FIXTURE_OUTPUTS {
            validate_relative_output(output).expect("closed output path");
        }
        assert!(validate_relative_output("../sdk_v1.json").is_err());
        assert!(validate_relative_output("/tmp/sdk_v1.json").is_err());
    }
    #[test]
    fn legacy_deployment_keys_are_rejected_recursively() {
        for key in ["chain_id", "genesis_hash", "genesis_block_hash"] {
            let mut nested = norito::json::Map::new();
            nested.insert(key.to_owned(), norito::json!("forbidden"));
            let value = norito::json!({"nested": [(Value::Object(nested))]});
            assert!(reject_legacy_keys(&value, "fixture").is_err());
        }
        reject_legacy_keys(
            &norito::json!({"network_id": "hash:a5", "nested": []}),
            "fixture",
        )
        .expect("NetworkId-only fixture");
    }
    #[test]
    fn envelope_is_deterministic_and_contains_only_the_closed_pair() {
        let fixtures = rendered_fixtures().expect("render fixtures");
        let first = rendered_envelope(&fixtures).expect("render envelope");
        let second = rendered_envelope(&fixtures).expect("rerender envelope");
        assert_eq!(first, second);
        assert!(first.ends_with('\n'));
        let decoded: Value = json::from_str(&first).expect("decode envelope");
        assert_eq!(
            decoded
                .get("schema")
                .and_then(Value::as_str)
                .expect("schema"),
            OWNER_ENVELOPE_SCHEMA_V1
        );
        let paths = decoded
            .get("outputs")
            .and_then(Value::as_array)
            .expect("outputs")
            .iter()
            .map(|output| {
                output
                    .get("path")
                    .and_then(Value::as_str)
                    .expect("output path")
            })
            .collect::<Vec<_>>();
        assert_eq!(paths, MUSUBI_FIXTURE_OUTPUTS);
    }
}
