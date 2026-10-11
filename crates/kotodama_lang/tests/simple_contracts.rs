//! Compiler coverage for concise constants, calls, checked reads, and record updates.

use kotodama_lang::{
    compiler::Compiler, ir, metadata::ProgramMetadata, parser::parse, semantic::analyze,
};

fn compile(source: &str) -> Vec<u8> {
    Compiler::new()
        .compile_source(source)
        .expect("compile simple contract")
}

fn code(source: &str) -> Vec<u8> {
    let artifact = compile(source);
    let metadata = ProgramMetadata::parse(&artifact).expect("artifact metadata");
    artifact[metadata.code_offset..].to_vec()
}

#[test]
fn typed_literal_constants_compile_without_wrapper_functions() {
    let source = r#"seiyaku Constants {
        error enum Failure { Missing = 1 }
        const string KEY_TEXT = "counter";
        const Name KEY = Name::parse(KEY_TEXT);
        const Failure MISSING = Failure::Missing;
        const int ACTIVE = 1;
        state StateMap<Name, int> Values;
        view fn value() authorize(anyone) -> int { Values.get(KEY).expect(MISSING) + ACTIVE }
    }"#;
    let explicit = r#"seiyaku Constants {
        error enum Failure { Missing = 1 }
        state StateMap<Name, int> Values;
        view fn value() authorize(anyone) -> int { Values.get(Name::parse("counter")).expect(Failure::Missing) + 1 }
    }"#;
    assert_eq!(code(source), code(explicit));
}

#[test]
fn typed_constants_reject_runtime_initializers_and_invalid_literals() {
    for source in [
        r#"seiyaku Invalid {
            fn key() -> string { "counter" }
            const Name KEY = Name::parse(key());
            view fn value() authorize(anyone) -> Name { KEY }
        }"#,
        r#"seiyaku Invalid {
            const Name KEY = Name::parse(1);
            view fn value() authorize(anyone) -> Name { KEY }
        }"#,
        r#"seiyaku Invalid {
            const Name KEY = Name::parse("");
            view fn value() authorize(anyone) -> Name { KEY }
        }"#,
        r#"seiyaku Invalid {
            const AccountId ACTOR = AccountId::parse("admin@universal");
            view fn value() authorize(anyone) -> AccountId { ACTOR }
        }"#,
    ] {
        Compiler::new()
            .compile_source(source)
            .expect_err("constants must have valid literal inputs");
    }
}

#[test]
fn ordinary_positional_and_named_calls_have_identical_code() {
    let positional = r#"seiyaku Calls {
        fn combine(int left, int right) -> int { left * 10 + right }
        view fn value() authorize(anyone) -> int { combine(2, 3) }
    }"#;
    let named = positional.replace("combine(2, 3)", "combine(left: 2, right: 3)");
    let mixed = positional.replace("combine(2, 3)", "combine(2, right: 3)");
    assert_eq!(code(positional), code(&named));
    assert_eq!(code(positional), code(&mixed));
}

#[test]
fn option_expect_rejects_untyped_errors_wrong_receivers_and_arity() {
    for body in [
        "let Option<int> value = Option::some(1); value.expect(1);",
        "let Option<int> value = Option::some(1); value.expect(\"missing\");",
        "let value = 1; value.expect(Failure::Missing);",
        "let Option<int> value = Option::some(1); value.expect();",
        "let Option<int> value = Option::some(1); value.expect(Failure::Missing, Failure::Missing);",
    ] {
        let source = format!(
            "seiyaku Invalid {{ error enum Failure {{ Missing = 1 }} fn check() {{ {body} }} }}"
        );
        let parsed = parse(&source).expect("parse invalid expect fixture");
        assert_eq!(
            analyze(&parsed)
                .expect_err("expect must fail closed")
                .code(),
            "K2003",
            "{source}"
        );
    }
}

#[test]
fn expect_lowers_one_nominal_abort() {
    let parsed = parse(
        r#"seiyaku Checked {
        error enum Failure { Missing = 7 }
        fn extract(Option<int> value) -> int { value.expect(Failure::Missing) }
    }"#,
    )
    .expect("parse checked extraction");
    let typed = analyze(&parsed).expect("check extraction");
    let lowered = ir::lower(&typed).expect("lower extraction");
    let aborts = lowered
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instrs)
        .filter(|instruction| matches!(instruction, ir::Instr::AbortIf { .. }))
        .count();
    assert_eq!(aborts, 1);
}

#[test]
fn sum_error_bridges_compile_identically_with_named_error_arguments() {
    let positional = r#"seiyaku Bridges {
        error enum Previous { Denied = 1 }
        error enum Failure { Missing = 7 }
        view fn convert(Option<(int, bool)> value) authorize(anyone) -> Result<(int, bool), Failure> {
            value.ok_or(Failure::Missing)
        }
        view fn replace(Result<int, Previous> value) authorize(anyone) -> Result<int, Failure> {
            value.or_err(Failure::Missing)
        }
        view fn extract(Result<int, Previous> value) authorize(anyone) -> int {
            value.expect(Failure::Missing)
        }
    }"#;
    let named = positional
        .replace(".ok_or(", ".ok_or(error: ")
        .replace(".or_err(", ".or_err(error: ")
        .replace(".expect(", ".expect(error: ");
    assert_eq!(code(positional), code(&named));
}

#[test]
fn mutable_nested_records_and_tuples_compile() {
    compile(
        r#"seiyaku Records {
        struct Inner { int amount, bytes commitment }
        struct Record { int nonce, Inner inner }
        view fn update() authorize(anyone) -> Record {
            var record = Record { nonce: 1, inner: Inner { amount: 2, commitment: b"before" } };
            record.inner.amount += 3;
            record.inner.commitment = b"after";
            record.nonce = 2;
            var pair = (record, 4);
            pair.0.nonce = 5;
            pair.1 *= 2;
            pair.0
        }
    }"#,
    );
}

#[test]
fn product_updates_preserve_mutability_type_and_root_checks() {
    for (body, error) in [
        (
            "let value = Record { count: 1 }; value.count = 2;",
            "E_IMMUTABLE_ASSIGNMENT",
        ),
        (
            "var value = Record { count: 1 }; value.count = false;",
            "E_TYPE_ANNOTATION_MISMATCH",
        ),
        (
            "var value = Record { count: 1 }; value.missing = 2;",
            "K2002",
        ),
    ] {
        let source = format!(
            "seiyaku Invalid {{ struct Record {{ int count }} fn make() -> Record {{ Record {{ count: 1 }} }} fn check() {{ {body} }} }}"
        );
        let parsed = parse(&source).expect("parse invalid product fixture");
        assert_eq!(
            analyze(&parsed)
                .expect_err("invalid field update must reject")
                .code(),
            error,
            "{source}"
        );
    }
}

#[test]
fn temporary_product_fields_cannot_be_assignment_targets() {
    let source = "seiyaku Invalid { struct Record { int count } fn make() -> Record { Record { count: 1 } } fn check() { make().count = 2; } }";
    Compiler::new()
        .compile_source(source)
        .expect_err("temporary products have no mutable binding");
}

#[test]
fn sequential_record_updates_have_no_executable_scaffolding() {
    let records = r#"seiyaku Updates {
        struct Record { int count, bytes proof, int second }
        view fn update(int count, bytes proof) authorize(anyone) -> (int, bytes, int) {
            var record = Record { count, proof: b"unused", second: 0 };
            record.count += 1;
            record.proof = proof;
            record.second = record.count + 2;
            (record.count, record.proof, record.second)
        }
    }"#;
    let scalar = r#"seiyaku Updates {
        view fn update(int count, bytes proof) authorize(anyone) -> (int, bytes, int) {
            let next = count + 1;
            let second = next + 2;
            (next, proof, second)
        }
    }"#;
    assert_eq!(code(records), code(scalar));
}
