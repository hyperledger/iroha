//! Kotodama rejects retired source-level schema codec plumbing.
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
#[test]
fn kotodama_source_rejects_retired_schema_codec_helpers() {
    let src = r#"
        seiyaku SchemaCodecRoundtrip {
        view fn main() authorize(anyone) {
            let schema = Name::parse("Order");
            let payload = Json::parse("{\"qty\":7,\"side\":\"buy\"}");
            let bytes = codec::schema::encode(schema, payload);
            let decoded = codec::schema::decode(schema, bytes);
            let _bytes2 = codec::schema::encode(schema, decoded);
        }
        }
    "#;
    let error = KotodamaCompiler::new()
        .compile_source(src)
        .expect_err("source-level schema codec helpers are compiler-internal");
    assert!(error.contains("codec::schema::encode"), "{error}");
    assert!(error.contains("codec::schema::decode"), "{error}");
}
