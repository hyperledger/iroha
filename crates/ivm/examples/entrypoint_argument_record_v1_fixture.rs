//! Generate the shared Kotodama V1 public-entrypoint argument-record fixture.
use std::{env, fs, path::Path};
#[path = "support/atomic_write.rs"]
mod fixture_io;
use iroha_primitives::json::Json;
use ivm::ProgramMetadata;
use ivm_abi::arguments::encode_argument_record_from_json;
use norito::json::{Map, Value};
const SOURCE: &str = r#"seiyaku ArgumentRecordFixture {
  view fn quote(int count, int exact_int, decimal exact_decimal, quantity exact_quantity, bool active, string memo, bytes digest) authorize(anyone) -> int {
    let Json exact = json {
      exact_int: exact_int,
      exact_decimal: exact_decimal,
      exact_quantity: exact_quantity,
    };
    let int decoded_int = match exact.get_int(Name::parse("exact_int")) {
      Option::some(value) => value,
      Option::none => { return 0; },
    };
    let decimal decoded_decimal = match exact.get_decimal(Name::parse("exact_decimal")) {
      Option::some(value) => value,
      Option::none => { return 0; },
    };
    let quantity decoded_quantity = match exact.get_quantity(Name::parse("exact_quantity")) {
      Option::some(value) => value,
      Option::none => { return 0; },
    };
    if decoded_int != exact_int || decoded_decimal != exact_decimal || decoded_quantity != exact_quantity {
      return 0;
    }
    let _active = active;
    let _memo = memo;
    let _digest = digest;
    return count;
  }
}
"#;
fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}
fn parameter(name: &'static str, ty: &'static str) -> Value {
    object([("name", Value::from(name)), ("type", Value::from(ty))])
}
/// Render the deterministic shared fixture document.
pub fn render_fixture() -> String {
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(SOURCE)
        .expect("compile argument-record fixture contract");
    let metadata = ProgramMetadata::parse(&artifact).expect("parse fixture contract metadata");
    let entrypoint = metadata
        .contract_interface
        .as_ref()
        .expect("fixture contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "quote")
        .expect("quote entrypoint");
    let schema = entrypoint
        .argument_schema
        .as_ref()
        .expect("quote argument schema");
    let payload_value = object([
        ("count", Value::from("-7")),
        (
            "exact_int",
            Value::from("1606938044258990275541962092341162602522202993782792835301376"),
        ),
        ("exact_decimal", Value::from("-12345678901234567890.125")),
        (
            "exact_quantity",
            Value::from("12345678901234567890.0000000000000000000000000001"),
        ),
        ("active", Value::from(true)),
        ("memo", Value::from("kotodama-v1")),
        ("digest", Value::from("0x000102feff")),
    ]);
    let payload = Json::from(payload_value.clone());
    let record = encode_argument_record_from_json(schema, &payload)
        .expect("encode canonical fixture argument record");
    let validated = ivm::validate_argument_record(schema, &record)
        .expect("validate canonical fixture argument record");
    let schema_bytes = norito::to_bytes(schema).expect("encode fixture argument schema");
    let document = object([
        ("fixture_version", Value::from(1_u64)),
        ("codec", Value::from("EntrypointArgumentRecordV1")),
        (
            "generator",
            Value::from("ivm_abi::arguments::encode_argument_record_from_json"),
        ),
        (
            "contract",
            object([
                ("source", Value::from(SOURCE)),
                ("entrypoint", Value::from("quote")),
                (
                    "parameters",
                    Value::Array(vec![
                        parameter("count", "int"),
                        parameter("exact_int", "int"),
                        parameter("exact_decimal", "decimal"),
                        parameter("exact_quantity", "quantity"),
                        parameter("active", "bool"),
                        parameter("memo", "string"),
                        parameter("digest", "bytes"),
                    ]),
                ),
            ]),
        ),
        (
            "torii_boundary",
            object([
                (
                    "authority",
                    Value::from("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"),
                ),
                (
                    "contract_alias",
                    Value::from("argument-record-fixture::universal"),
                ),
                ("entrypoint", Value::from("quote")),
                ("payload", payload_value),
                (
                    "fee_payment",
                    object([
                        ("payer", Value::from("authority")),
                        (
                            "value",
                            object([
                                ("charge_limits", Value::Array(vec![])),
                                ("gas_limit", Value::from(1_500_000_u64)),
                            ]),
                        ),
                    ]),
                ),
            ]),
        ),
        (
            "entrypoint_argument_schema_v1",
            object([
                ("norito_hex", Value::from(hex::encode(schema_bytes))),
                (
                    "schema_hash_hex",
                    Value::from(hex::encode(validated.schema_hash)),
                ),
            ]),
        ),
        (
            "entrypoint_argument_record_v1",
            object([("norito_hex", Value::from(hex::encode(record)))]),
        ),
    ]);
    let mut rendered =
        norito::json::to_json_pretty(&document).expect("serialize entrypoint argument fixture");
    rendered.push('\n');
    rendered
}
fn verify(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let expected = render_fixture();
    let actual = fs::read_to_string(path)?;
    if actual != expected {
        return Err(format!(
            "{} is stale; regenerate it with `cargo run -p ivm --example entrypoint_argument_record_v1_fixture -- --write {}`",
            path.display(),
            path.display()
        )
        .into());
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    if let Some(flag) = arguments.next() {
        if flag == "--check" || flag == "--write" {
            let path = arguments
                .next()
                .ok_or("--check/--write requires a fixture path")?;
            if arguments.next().is_some() {
                return Err("unexpected arguments after fixture path".into());
            }
            let path = Path::new(&path);
            if flag == "--check" {
                verify(path)?;
            } else {
                fixture_io::atomic_write(path, render_fixture().as_bytes())?;
            }
            return Ok(());
        }
        return Err("only `--check <path>` or `--write <path>` is supported".into());
    }
    print!("{}", render_fixture());
    Ok(())
}
