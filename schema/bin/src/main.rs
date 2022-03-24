//! Binary to print all types to json string

// Schemas should always be serializable to JSON
#[allow(clippy::expect_used, clippy::print_stdout)]
fn main() {
    let schemas = iroha_schema_bin::build_schemas();

    println!(
        "{}",
        serde_json::to_string_pretty(&schemas).expect("Unable to serialize schemas")
    );
}
