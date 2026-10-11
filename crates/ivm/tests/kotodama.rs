//! Tests for Kotodama parsing, semantics, and compilation.
use ivm::{ProgramMetadata, encoding, instruction, syscalls};
use kotodama_lang::{
    ast as kd_ast,
    ast::{BinaryOp, Expr, Function, Item, Statement},
    compiler::{Compiler, CompilerMode, CompilerOptions},
    lexer::{TokenKind, lex},
    parser::parse as parse_source,
    semantic::{Type, analyze},
};
use std::convert::TryInto;
mod common;
fn parse_meta_offset(code: &[u8]) -> Result<(ProgramMetadata, usize), ivm::VMError> {
    ProgramMetadata::parse(code).map(|parsed| (parsed.metadata, parsed.code_offset))
}
fn test_compiler() -> Compiler {
    Compiler::new_with_options(CompilerOptions {
        mode: CompilerMode::Test,
        ..CompilerOptions::default()
    })
}
fn parse(source: &str) -> Result<kd_ast::Program, String> {
    parse_source(source)
}
#[test]
fn create_compiler() {
    let _c = Compiler::new();
}
#[test]
fn lex_simple_function() {
    let src = "fn add(int a, int b) { let c = a + b; }";
    let tokens = lex(src).expect("lex failed");
    assert!(tokens.iter().any(|t| matches!(t.kind, TokenKind::Fn)));
    assert!(
        tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Ident(ref s) if s == "add"))
    );
}
#[test]
fn parse_simple_add() {
    let src = "module SimpleAdd { fn add(int a, int b) { let c = a + b; } }";
    let prog = parse(src).expect("parse failed");
    let Item::Function(Function {
        name, params, body, ..
    }) = &prog.items[0]
    else {
        panic!("expected function item");
    };
    assert_eq!(name, "add");
    assert_eq!(params.len(), 2);
    assert_eq!(params[0].name, "a");
    assert_eq!(params[1].name, "b");
    match &body.statements[0] {
        Statement::Let { pat, value, .. } => {
            match pat {
                kd_ast::Pattern::Name(n) => assert_eq!(n, "c"),
                _ => panic!("expected name"),
            }
            match value {
                Expr::Binary {
                    op: BinaryOp::Add, ..
                } => {}
                _ => panic!("expected add expr"),
            }
        }
        _ => panic!("unexpected statement"),
    }
}
#[test]
fn lexer_accepts_v1_branded_keywords_in_both_scripts() {
    use kotodama_lang::lexer::{TokenKind, lex};
    let seiyaku = lex("seiyaku Demo { }").expect("lex seiyaku");
    assert!(matches!(seiyaku[0].kind, TokenKind::Seiyaku));
    let hajimari = lex("hajimari() {}").expect("lex");
    assert!(
        hajimari
            .iter()
            .any(|token| matches!(token.kind, TokenKind::Hajimari))
    );
    for branded in [
        "誓約 Demo { }",
        "始まり() {}",
        "言挙げ fn run() authorize(anyone) {}",
        "改善() {}",
    ] {
        lex(branded).expect("Japanese branded declaration must be accepted");
    }
}
#[test]
fn parse_and_type_tuples_and_types() {
    let src =
        "module Types { fn t(int x) -> (int, bool) { let (a, b) = (1, true); return (x, true); } }";
    let prog = parse(src).expect("parse");
    let typed = analyze(&prog).expect("type");
    let kotodama_lang::semantic::TypedItem::Function(f) = &typed.items[0];
    assert_eq!(f.name, "t");
}
#[test]
fn bytes_type_is_accepted_and_roundtrips_through_semantics() {
    let src = "module BytesDemo { fn echo(bytes b) -> bytes { let bytes tmp = b; return tmp; } }";
    let prog = parse(src).expect("parse bytes");
    let typed = analyze(&prog).expect("analyze bytes");
    let kotodama_lang::semantic::TypedItem::Function(f) = &typed.items[0];
    assert_eq!(f.ret_ty, Some(Type::Bytes));
}
#[derive(Clone, Copy)]
enum CaseSource {
    Exact(&'static str),
    Fixture(&'static str),
}

impl CaseSource {
    fn text(self, id: &str) -> &'static str {
        match self {
            Self::Exact(source) => source,
            Self::Fixture(source) => source
                .strip_suffix('\n')
                .unwrap_or_else(|| panic!("{id}: fixture sentinel newline")),
        }
    }
}

#[derive(Clone, Copy)]
enum CaseCompiler {
    Production,
    Test,
}

impl CaseCompiler {
    fn build(self) -> Compiler {
        match self {
            Self::Production => Compiler::new(),
            Self::Test => test_compiler(),
        }
    }
}

struct CompileCase {
    id: &'static str,
    source: CaseSource,
    compiler: CaseCompiler,
}
struct CompileRejectionCase {
    id: &'static str,
    source: CaseSource,
    compiler: CaseCompiler,
    required: &'static [&'static str],
    alternatives: &'static [&'static str],
}
struct SemanticRejectionCase {
    id: &'static str,
    source: CaseSource,
    code: Option<&'static str>,
    message: &'static str,
}
struct VmResultCase {
    id: &'static str,
    source: CaseSource,
    entrypoint: &'static str,
    expected: i64,
}
struct ParseRejectionCase {
    id: &'static str,
    source: CaseSource,
    required: &'static [&'static str],
}
struct SemanticSuccessCase {
    id: &'static str,
    source: CaseSource,
    require_nonempty_first_function: bool,
}

macro_rules! compile_cases {
    ($($id:literal, $compiler:ident, $source:expr;)+) => {
        const COMPILE_CASES: &[CompileCase] = &[$(
            CompileCase { id: $id, source: $source, compiler: CaseCompiler::$compiler }
        ),+];
    };
}
macro_rules! compile_rejection_cases {
    ($($id:literal, $compiler:ident, $source:expr, $required:expr, $alternatives:expr;)+) => {
        const COMPILE_REJECTION_CASES: &[CompileRejectionCase] = &[$(
            CompileRejectionCase {
                id: $id, source: $source, compiler: CaseCompiler::$compiler,
                required: $required, alternatives: $alternatives,
            }
        ),+];
    };
}
macro_rules! semantic_rejection_cases {
    ($($id:literal, $source:expr, $code:expr, $message:expr;)+) => {
        const SEMANTIC_REJECTION_CASES: &[SemanticRejectionCase] = &[$(
            SemanticRejectionCase { id: $id, source: $source, code: $code, message: $message }
        ),+];
    };
}
macro_rules! vm_result_cases {
    ($($id:literal, $source:expr, $entrypoint:literal, $expected:literal;)+) => {
        const VM_RESULT_CASES: &[VmResultCase] = &[$(
            VmResultCase { id: $id, source: $source, entrypoint: $entrypoint, expected: $expected }
        ),+];
    };
}
macro_rules! parse_rejection_cases {
    ($($id:literal, $source:expr, $required:expr;)+) => {
        const PARSE_REJECTION_CASES: &[ParseRejectionCase] = &[$(
            ParseRejectionCase { id: $id, source: $source, required: $required }
        ),+];
    };
}
macro_rules! semantic_success_cases {
    ($($id:literal, $source:expr, $nonempty:literal;)+) => {
        const SEMANTIC_SUCCESS_CASES: &[SemanticSuccessCase] = &[$(
            SemanticSuccessCase {
                id: $id, source: $source, require_nonempty_first_function: $nonempty,
            }
        ),+];
    };
}

compile_cases! {
    "for_each_map_snapshot_allows_mutation", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/030.ko"));
    "string_equality_compiles", Production,
        CaseSource::Exact("seiyaku StringEquality { view fn f() authorize(anyone) { let _x = \"hi\" == \"hi\"; } }");
    "irohaswap_sample_compiles", Test,
        CaseSource::Exact(include_str!("../../kotodama_lang/src/samples/irohaswap.ko"));
    "prediction_market_demo_compiles", Test,
        CaseSource::Exact(include_str!("../../../demo/prediction_market.ko"));
    "quantity_arithmetic_compiles_without_implicit_conversion", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/002.ko"));
    "fractional_quantity_literal_is_accepted_contextually", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/004.ko"));
    "pointer_constructors_compile", Test,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/007.ko"));
    "public_function_with_permission_is_allowed", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/012.ko"));
    "compile_unary_ops", Production,
        CaseSource::Exact("seiyaku UnaryOps { view fn f(int a, bool b) authorize(anyone) { let c = -a; let d = !b; } }");
}

compile_rejection_cases! {
    "compile_stub", Production,
        CaseSource::Exact("ADD 1, 2"),
        &[], &[];
    "negative_quantity_conversion_is_rejected", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/003.ko")),
        &["E_NEGATIVE_QUANTITY"], &[];
    "implicit_quantity_to_int_conversion_is_rejected", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/006.ko")),
        &["expected `int`, found `quantity`"], &[];
    "public_function_without_authorization_rejected", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/008.ko")),
        &["authorize"], &[];
    "register_peer_requires_permission", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/009.ko")),
        &["authorize"], &[];
    "register_account_requires_permission", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/010.ko")),
        &["authorize"], &[];
    "trigger_management_requires_permission", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/011.ko")),
        &["authorize"], &[];
    "removed_in_memory_map_type_is_rejected", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/013.ko")),
        &[], &["Map", "unknown type"];
    "raw_query_and_authority_sysvar_helpers_are_not_source_apis/query", Test,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/024.ko")),
        &["query_execute_norito"], &[];
    "raw_query_and_authority_sysvar_helpers_are_not_source_apis/authority", Test,
        CaseSource::Exact(
            r#"seiyaku RawAuthority { view fn caller() authorize(anyone) -> AccountId { return sysvar_authority(); } }"#,
        ),
        &["sysvar_authority"], &[];
    "dynamic_state_map_take_is_rejected", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/046.ko")),
        &["E_UNBOUNDED_ITERATION", "constant expression"], &[];
    "dynamic_state_map_range_is_rejected", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/047.ko")),
        &["range"], &[];
    "indirect_sensitive_calls_require_permission", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/055.ko")),
        &["authorize"], &[];
    "while_loops_are_rejected_in_v1", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/056.ko")),
        &["while"], &[];
    "compile_pubkgen_and_valcom", Production,
        CaseSource::Exact("seiyaku Commitments { view fn main() authorize(anyone) -> (int, int) { let p = crypto::pubkgen(9); let c = crypto::valcom(left: 9, right: 4); return (p, c); } }"),
        &["crypto::pubkgen"], &[];
    "raw_json_codec_aliases_are_rejected", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/059.ko")),
        &[], &["decode_json", "unknown"];
    "compile_and_run_poseidon_register_forms", Production,
        CaseSource::Exact(include_str!("../fixtures/koto_v1/kotodama/060.ko")),
        &[], &["crypto::poseidon2", "crypto::poseidon6"];
    "unbounded_state_map_iteration_is_rejected", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/061.ko")),
        &["E_UNBOUNDED_ITERATION", "for iteration requires a bounded List"], &[];
    "unbounded_state_map_iteration_cannot_infer_a_limit", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/062.ko")),
        &["E_UNBOUNDED_ITERATION", "for iteration requires a bounded List"], &[];
    "map_new_is_rejected_in_v1", Production,
        CaseSource::Exact("module RemovedMap { fn make() -> int { return Map::new(); } }"),
        &["Map"], &[];
    "raw_pointer_codec_alias_is_rejected", Production,
        CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/072.ko")),
        &[], &["pointer_to_norito", "unknown"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/account_id_bytes", Production,
        CaseSource::Exact(r#"seiyaku C { fn f(bytes value) { let _x = AccountId::parse(value); } }"#),
        &[], &["expects string", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/json_bytes", Production,
        CaseSource::Exact(r#"seiyaku C { fn f(bytes value) { let _x = Json::parse(value); } }"#),
        &[], &["expects string", "E_JSON_LITERAL_REQUIRED", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/name_bytes", Production,
        CaseSource::Exact(r#"seiyaku C { fn f(bytes value) { let _x = Name::parse(value); } }"#),
        &[], &["expects string", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/name_name", Production,
        CaseSource::Exact(r#"seiyaku C { fn f(Name value) { let _x = Name::parse(value); } }"#),
        &[], &["expects string", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/account_method", Production,
        CaseSource::Exact(r#"seiyaku C { fn f(string value) { let _x = value.account_id(); } }"#),
        &[], &["expects string", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/name_method", Production,
        CaseSource::Exact(r#"seiyaku C { fn f(string value) { let _x = value.name(); } }"#),
        &[], &["expects string", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/json_method", Production,
        CaseSource::Exact(r#"seiyaku C { fn f(string value) { let _x = value.json(); } }"#),
        &[], &["expects string", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/blob_method", Production,
        CaseSource::Exact(r#"seiyaku C { fn f(bytes value) { let _x = value.blob(); } }"#),
        &[], &["expects string", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/norito_method", Production,
        CaseSource::Exact(r#"seiyaku C { fn f(bytes value) { let _x = value.norito_bytes(); } }"#),
        &[], &["expects string", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/blob_builtin", Production,
        CaseSource::Exact(r#"seiyaku C { fn f() { let _x = blob("raw"); } }"#),
        &[], &["expects string", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
    "pointer_constructors_reject_implicit_conversions_and_method_aliases/norito_builtin", Production,
        CaseSource::Exact(r#"seiyaku C { fn f() { let _x = norito_bytes("raw"); } }"#),
        &[], &["expects string", "method aliases were removed", "compiler-internal", "unknown function or builtin"];
}

semantic_rejection_cases! {
    "decimal_literal_rejects_int_annotation", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/005.ko")),
        Some("E_TYPE_ANNOTATION_MISMATCH"), "expected `int`, found `decimal`";
    "semantic_rejects_extended_sysvar_helper_args", CaseSource::Exact(r#"module InvalidContext { fn f() { let _chain = context::chain_id(1); } }"#),
        Some("K2003"), "call `context::chain_id` expects at most 0 arguments, got 1";
    "semantic_rejects_extended_query_and_authority_sysvar_helper_args/query", CaseSource::Exact(r#"module InvalidQuery { fn f() { let _response = query_execute_norito(1); } }"#),
        None, "query_execute_norito";
    "semantic_rejects_extended_query_and_authority_sysvar_helper_args/authority", CaseSource::Exact(r#"module InvalidAuthority { fn f() { let _caller = sysvar_authority(1); } }"#),
        None, "sysvar_authority";
    "semantic_rejects_typed_query_get_helper_args/account", CaseSource::Exact(r#"module InvalidQuery { fn f() { let _account = ledger::query::account(1); } }"#),
        None, "ledger::query::account";
    "semantic_rejects_typed_query_get_helper_args/instance", CaseSource::Exact(r#"module InvalidQuery { fn f() { let _instance = ledger::query::seiyaku_instance(1); } }"#),
        None, "ledger::query::seiyaku_instance";
    "semantic_rejects_zk_vrf_read_helper_args", CaseSource::Exact(r#"module InvalidVrfRequest { fn f() { let _seed = crypto::vrf::epoch_seed(epoch: bytes("0x00")); } }"#),
        None, "crypto::vrf::epoch_seed expects (int epoch) and returns Option<bytes>";
    "semantic_rejects_state_introspection_helper_args", CaseSource::Exact(r#"seiyaku C { fn f() { let _length = state::len(1); } }"#),
        None, "state::len expects (bytes StatePath)";
    "semantic_rejects_legacy_name_state_path_carriers", CaseSource::Exact(r#"seiyaku C { fn f() { let _count = state::count(Name::parse("Orders")); } }"#),
        Some("K2003"), "state::count expects (bytes StatePath)";
    "semantic_rejects_extended_hash_non_bytes_arg", CaseSource::Exact(r#"module InvalidHash { fn f() { let digest = crypto::keccak256(1); } }"#),
        None, "crypto::keccak256 expects (bytes)";
    "semantic_type_error", CaseSource::Exact("module InvalidArithmetic { fn bad() { let a = 1 + \"hi\"; } }"),
        None, "operator `+` is not defined for `int` and `string`";
    "invalid_numeric_on_struct_reports_error", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/035.ko")),
        None, "unknown field '0' on struct A";
    "invalid_named_on_tuple_reports_error", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/036.ko")),
        None, "unknown field 'a' on tuple";
    "invalid_numeric_tuple_index_reports_error", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/037.ko")),
        None, "tuple index 3 out of bounds";
    "tuple_index_on_non_tuple_reports_type", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/038.ko")),
        None, "tuple index on non-tuple type struct A";
    "tuple_index_on_non_tuple_int_reports_type", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/039.ko")),
        None, "tuple index on non-tuple type int";
    "unknown_field_on_struct_reports_available_fields", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/040.ko")),
        None, "unknown field 'z' on struct A (available: x, y)";
    "invalid_named_on_non_struct_reports_error", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/041.ko")),
        None, "unknown field 'foo' on type int";
    "invalid_indexing_on_non_map_reports_error", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/042.ko")),
        None, "indexing not supported on this type";
    "range_end_less_than_start_rejected", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/044.ko")),
        None, "range";
    "range_non_integer_args_rejected", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/045.ko")),
        None, "range";
    "parse_register_asset_rejects_bare_name_literal", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/065.ko")),
        None, "AssetDefinitionId";
    "in_memory_map_methods_are_rejected", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/066.ko")),
        None, "Map";
    "ephemeral_keys_take2_helper_is_rejected", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/068.ko")),
        None, "Map";
    "ephemeral_keys_values_take2_helper_is_rejected", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/069.ko")),
        None, "Map";
    "semantic_return_value_without_declared_type_is_rejected", CaseSource::Exact("module ReturnMismatch { fn f() { return 1; } }"),
        Some("E_RETURN_TYPE_MISMATCH"), "expected `()`, found `int`";
    "semantic_rejects_unbounded_state_map_for_each", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/014.ko")),
        Some("E_UNBOUNDED_ITERATION"), "for iteration requires a bounded List";
}

vm_result_cases! {
    "tuple_destructure_and_field_access", CaseSource::Exact("seiyaku TupleDestructure { view fn sum() authorize(anyone) -> int { let (a,b) = (3,4); let c = (1,2).1; return a + b + c; } }"),
        "sum", 9;
    "tuple_var_member_access", CaseSource::Exact("seiyaku TupleMember { view fn f() authorize(anyone) -> int { let t = (5,6); return t.0 + t.1; } }"),
        "f", 11;
    "call_function_with_tuple_return", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/001.ko")),
        "main", 56;
    "state_allocations_do_not_clobber_params", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/031.ko")),
        "main", 42;
    "triple_nested_struct_field_access", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/033.ko")),
        "f", 5;
    "triple_nested_struct_field_mixed_named_numeric_access", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/034.ko")),
        "f", 7;
    "method_call_sugar_receiver_and_arg", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/043.ko")),
        "main", 12;
    "compile_and_run_modulo", CaseSource::Exact("seiyaku Modulo { view fn main() authorize(anyone) -> int { return 17 % 5; } }"),
        "main", 2;
}

parse_rejection_cases! {
    "c_style_for_loop_is_rejected", CaseSource::Exact("module Loops { fn f() { for var i = 0; i < 3; i = i + 1 { let x = i; } } }"),
        &[];
    "removed_bounded_attribute_is_rejected", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/016.ko")),
        &[];
    "parse_error", CaseSource::Exact("module Broken { fn bad("),
        &["identifier", "module Broken { fn bad("];
    "statement_call_sugar_is_rejected/helper", CaseSource::Exact("seiyaku C { fn f() { call helper(); } fn helper() {} }"),
        &["call"];
    "statement_call_sugar_is_rejected/expression", CaseSource::Exact("seiyaku C { fn f() { call 1; } }"),
        &["call"];
}

semantic_success_cases! {
    "literal_range_for_loop_is_bounded", CaseSource::Exact("module Loops { fn f() { for x in range(6) { let y = x; } } }"),
        false;
    "state_map_take_two_is_bounded", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/015.ko")),
        false;
    "parse_and_type_bounded_map_take_one_ok", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/017.ko")),
        true;
    "semantic_typed_pointers_and_authority", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/022.ko")),
        false;
    "parse_and_type_bounded_map_take_one", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/029.ko")),
        true;
    "lexer_block_comments_and_number_literals", CaseSource::Fixture(include_str!("../fixtures/koto_v1/kotodama/053.ko")),
        false;
    "compound_assignments_typecheck", CaseSource::Exact(r#"module Compound { fn f() { var x = 1; x += 2; x *= 3; x /= 2; x %= 2; } }"#),
        false;
}

fn run_compile_cases(cases: &[CompileCase]) {
    for case in cases {
        let code = case
            .compiler
            .build()
            .compile_source(case.source.text(case.id))
            .unwrap_or_else(|error| panic!("{} should compile: {error}", case.id));
        assert!(!code.is_empty(), "{} produced an empty artifact", case.id);
    }
}

fn run_compile_rejection_cases(cases: &[CompileRejectionCase]) {
    for case in cases {
        let error = match case
            .compiler
            .build()
            .compile_source(case.source.text(case.id))
        {
            Ok(_) => panic!("{} should be rejected", case.id),
            Err(error) => error,
        };
        for expected in case.required {
            assert!(
                error.contains(expected),
                "{}: expected `{expected}`, got {error}",
                case.id
            );
        }
        assert!(
            case.alternatives.is_empty()
                || case
                    .alternatives
                    .iter()
                    .any(|expected| error.contains(expected)),
            "{}: expected one of {:?}, got {error}",
            case.id,
            case.alternatives,
        );
    }
}

fn run_semantic_rejection_cases(cases: &[SemanticRejectionCase]) {
    for case in cases {
        let program = parse(case.source.text(case.id))
            .unwrap_or_else(|error| panic!("{} should parse: {error}", case.id));
        let error = match analyze(&program) {
            Ok(_) => panic!("{} should be rejected", case.id),
            Err(error) => error,
        };
        if let Some(code) = case.code {
            assert_eq!(error.code(), code, "{} diagnostic code", case.id);
        }
        assert!(
            error.message().contains(case.message),
            "{}: expected `{}`, got {}",
            case.id,
            case.message,
            error.message(),
        );
    }
}

fn run_vm_result_cases(cases: &[VmResultCase]) {
    for case in cases {
        let code = Compiler::new()
            .compile_source(case.source.text(case.id))
            .unwrap_or_else(|error| panic!("{} should compile: {error}", case.id));
        let mut vm = ivm::IVM::new(u64::MAX);
        vm.load_program(&code)
            .unwrap_or_else(|error| panic!("{} should load: {error:?}", case.id));
        common::select_kotodama_entrypoint(&mut vm, &code, case.entrypoint);
        vm.run()
            .unwrap_or_else(|error| panic!("{} should execute: {error:?}", case.id));
        assert_eq!(
            common::decode_i64_return_word(&vm, 0),
            case.expected,
            "{} result",
            case.id,
        );
    }
}

fn run_parse_rejection_cases(cases: &[ParseRejectionCase]) {
    for case in cases {
        let error = match parse(case.source.text(case.id)) {
            Ok(_) => panic!("{} unexpectedly parsed", case.id),
            Err(error) => error,
        };
        for expected in case.required {
            assert!(
                error.contains(expected),
                "{}: expected `{expected}`, got {error}",
                case.id
            );
        }
    }
}

fn run_semantic_success_cases(cases: &[SemanticSuccessCase]) {
    for case in cases {
        let program = parse(case.source.text(case.id))
            .unwrap_or_else(|error| panic!("{} should parse: {error}", case.id));
        let typed = analyze(&program)
            .unwrap_or_else(|error| panic!("{} should type-check: {error}", case.id));
        if case.require_nonempty_first_function {
            let kotodama_lang::semantic::TypedItem::Function(function) = &typed.items[0];
            assert!(!function.body.statements.is_empty(), "{} body", case.id);
        }
    }
}

#[test]
fn compile_case_registry() {
    run_compile_cases(COMPILE_CASES);
}

#[test]
fn compile_rejection_case_registry() {
    run_compile_rejection_cases(COMPILE_REJECTION_CASES);
}

#[test]
fn semantic_rejection_case_registry() {
    run_semantic_rejection_cases(SEMANTIC_REJECTION_CASES);
}

#[test]
fn vm_result_case_registry() {
    run_vm_result_cases(VM_RESULT_CASES);
}

#[test]
fn parse_rejection_case_registry() {
    run_parse_rejection_cases(PARSE_REJECTION_CASES);
}

#[test]
fn semantic_success_case_registry() {
    run_semantic_success_cases(SEMANTIC_SUCCESS_CASES);
}
#[test]
fn many_string_literals_load_under_wide_guard() {
    // Exercise pointer literal emission with offsets beyond the wide 8-bit range.
    let mut src =
        String::from("seiyaku Literals { permission Test;  kotoage fn main() authorize(Test) {");
    for i in 0..32 {
        src.push_str(&format!(" debug::info(\"literal_{i}\");"));
    }
    src.push_str(" return;");
    src.push_str("} }");
    let code = Compiler::new()
        .compile_source(&src)
        .expect("compile program with many literals");
    let mut vm = ivm::IVM::new(u64::MAX);
    vm.load_program(&code)
        .expect("wide guard must accept Kotodama output");
}
#[test]
fn compile_domain_literal_emits_tlv_domainid() {
    let src = include_str!("../fixtures/koto_v1/kotodama/018.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let compiler = Compiler::new();
    let bytes = compiler.compile_source(src).expect("compile ok");
    assert!(
        bytes.windows(2).any(|w| w == [0x00, 0x08]),
        "expected DomainId TLV type (0x0008) in compiled artifact"
    );
}
#[test]
fn compile_register_domain_emits_syscall_0x10() {
    use ivm::encoding;
    let src = include_str!("../fixtures/koto_v1/kotodama/019.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let compiler = Compiler::new();
    let bytes = compiler.compile_source(src).expect("compile ok");
    // Expected sys encoding for SCALL with imm8=0x10 (SYSCALL_REGISTER_DOMAIN)
    let word = encoding::wide::encode_sys(instruction::wide::system::SCALL, 0x10);
    let needle = word.to_le_bytes();
    assert!(
        bytes.windows(4).any(|w| w == needle),
        "expected SCALL imm8=0x10 (register_domain) in compiled bytecode"
    );
}
#[test]
fn compile_zk_verify_batch_emits_syscall_0x64() {
    // Ensure the Kotodama intrinsic lowers to SCALL 0x64.
    let src = include_str!("../fixtures/koto_v1/kotodama/020.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let compiler = Compiler::new();
    let bytes = compiler.compile_source(src).expect("compile ok");
    let word = encoding::wide::encode_sys(instruction::wide::system::SCALL, 0x64);
    let needle = word.to_le_bytes();
    assert!(
        bytes.windows(4).any(|w| w == needle),
        "expected SCALL imm8=0x64 (zk_verify_batch) in compiled bytecode"
    );
}
#[test]
fn compile_blob_literal_emits_tlv_blob() {
    // Ensure a bytes literal emits the canonical bytes TLV (wire type 0x0006).
    let src = include_str!("../fixtures/koto_v1/kotodama/021.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let bytes = Compiler::new().compile_source(src).expect("compile ok");
    assert!(
        bytes.windows(2).any(|w| w == [0x00, 0x06]),
        "expected bytes TLV type (0x0006) in compiled artifact"
    );
}
#[test]
fn compile_emits_get_authority_syscall() {
    let src = r#"seiyaku Authority { view fn f() authorize(anyone) -> AccountId { return context::authority(); } }"#;
    let code = Compiler::new().compile_source(src).expect("compile");
    let (_, off) = parse_meta_offset(&code).unwrap();
    let mut words = Vec::new();
    let mut i = off;
    while i + 4 <= code.len() {
        words.push(u32::from_le_bytes(code[i..i + 4].try_into().unwrap()));
        i += 4;
    }
    let scall = instruction::wide::system::SCALL;
    let want = encoding::wide::encode_sys(scall, syscalls::SYSCALL_GET_AUTHORITY as u8);
    assert!(words.contains(&want), "GET_AUTHORITY syscall not found");
}
#[test]
fn compile_emits_current_time_syscall() {
    let src = r#"seiyaku Time { view fn f() authorize(anyone) -> int { return context::transaction_time_ms(); } }"#;
    let code = Compiler::new().compile_source(src).expect("compile");
    let (_, off) = parse_meta_offset(&code).unwrap();
    let mut words = Vec::new();
    let mut i = off;
    while i + 4 <= code.len() {
        words.push(u32::from_le_bytes(code[i..i + 4].try_into().unwrap()));
        i += 4;
    }
    let scall = instruction::wide::system::SCALL;
    let want = encoding::wide::encode_sys(scall, syscalls::SYSCALL_CURRENT_TIME_MS as u8);
    assert!(words.contains(&want), "CURRENT_TIME_MS syscall not found");
}
#[test]
fn compile_emits_block_height_syscall() {
    let src = r#"seiyaku Height { view fn f() authorize(anyone) -> int { return context::block_height(); } }"#;
    let code = Compiler::new().compile_source(src).expect("compile");
    let (_, off) = parse_meta_offset(&code).unwrap();
    let code_region = &code[off..];
    let want = encoding::wide::encode_syscallx(syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT).to_le_bytes();
    assert!(
        code_region.windows(want.len()).any(|window| window == want),
        "SYSVAR_BLOCK_HEIGHT syscall not found"
    );
}
#[test]
fn compile_emits_extended_sysvar_helpers() {
    let src = include_str!("../fixtures/koto_v1/kotodama/023.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let code = Compiler::new().compile_source(src).expect("compile");
    let (_, off) = parse_meta_offset(&code).unwrap();
    let code_region = &code[off..];
    for (name, syscall) in [
        ("SYSVAR_BLOCK_HEIGHT", syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT),
        ("SYSVAR_CHAIN_ID", syscalls::SYSCALL_SYSVAR_CHAIN_ID),
        (
            "SYSVAR_CONTRACT_ADDRESS",
            syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS,
        ),
        ("SYSVAR_ENTRYPOINT", syscalls::SYSCALL_SYSVAR_ENTRYPOINT),
    ] {
        let want = encoding::wide::encode_syscallx(syscall).to_le_bytes();
        assert!(
            code_region.windows(want.len()).any(|window| window == want),
            "{name} syscall not found"
        );
    }
}
#[test]
fn compile_emits_core_query_get_helpers() {
    let src = include_str!("../fixtures/koto_v1/kotodama/025.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let code = test_compiler().compile_source(src).expect("compile");
    let (_, off) = parse_meta_offset(&code).unwrap();
    let code_region = &code[off..];
    for (name, syscall) in [
        ("CORE_QUERY_GET(account)", syscalls::SYSCALL_CORE_QUERY_GET),
        (
            "CORE_QUERY_GET(asset_definition)",
            syscalls::SYSCALL_CORE_QUERY_GET,
        ),
        ("CORE_QUERY_GET(domain)", syscalls::SYSCALL_CORE_QUERY_GET),
        ("CORE_QUERY_GET(nft)", syscalls::SYSCALL_CORE_QUERY_GET),
        ("QUERY_GET_PARAMETER", syscalls::SYSCALL_QUERY_GET_PARAMETER),
        (
            "QUERY_GET_CONTRACT_MANIFEST",
            syscalls::SYSCALL_QUERY_GET_CONTRACT_MANIFEST,
        ),
        (
            "QUERY_GET_CONTRACT_INSTANCE",
            syscalls::SYSCALL_QUERY_GET_CONTRACT_INSTANCE,
        ),
    ] {
        let want = encoding::wide::encode_syscallx(syscall).to_le_bytes();
        assert!(
            code_region.windows(want.len()).any(|window| window == want),
            "{name} syscall not found"
        );
    }
}
#[test]
fn manifest_includes_exact_access_hints_for_static_typed_query_get_helpers() {
    use iroha_data_model::{
        account::AccountId,
        asset::id::{AssetDefinitionId, AssetId},
    };
    let account = AccountId::parse_encoded("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        .expect("parse account literal");
    let asset_definition = AssetDefinitionId::parse_address_literal("62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        .expect("parse asset definition");
    let asset = AssetId::of(asset_definition.clone(), account.clone());
    let src = format!(
        r#"
        seiyaku QueryHints {{
          view fn read() authorize(anyone) -> Option<NftView> {{
            let account = ledger::query::account(context::authority());
            let asset = ledger::query::asset(AssetId::parse("{asset}"));
            let definition = ledger::query::asset_definition(AssetDefinitionId::parse("{asset_definition}"));
            let domain = ledger::query::domain(DomainId::parse("wonderland.universal"));
            let nft = ledger::query::nft(NftId::parse("n0$wonderland.universal"));
            return nft;
          }}
        }}
    "#
    );
    let (_code, manifest) = Compiler::new()
        .compile_source_with_manifest(&src)
        .expect("compile manifest with typed query hints");
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let read = entrypoints
        .iter()
        .find(|entry| entry.name == "read")
        .expect("read entrypoint");
    assert_eq!(read.access_hints_complete, Some(true));
    assert!(read.access_hints_skipped.is_empty());
    assert!(read.write_keys.is_empty());
    assert!(read.read_keys.contains(&"account:$authority".to_string()));
    assert!(read.read_keys.contains(&format!("account:{account}")));
    assert!(read.read_keys.contains(&format!("asset:{asset}")));
    assert!(
        read.read_keys
            .contains(&format!("asset_def:{asset_definition}"))
    );
    assert!(
        read.read_keys
            .contains(&"domain:wonderland.universal".to_string())
    );
    assert!(read.read_keys.contains(&"nft".to_string()));
    assert!(
        read.read_keys
            .contains(&"nft:n0$wonderland.universal".to_string())
    );
    assert!(!read.read_keys.contains(&"*".to_string()));
}
#[test]
fn compile_emits_zk_vrf_read_helpers() {
    let src = include_str!("../fixtures/koto_v1/kotodama/026.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let code = test_compiler().compile_source(src).expect("compile");
    let (_, off) = parse_meta_offset(&code).unwrap();
    let code_region = &code[off..];
    for (name, syscall) in [
        ("ZK_ROOTS_GET", syscalls::SYSCALL_ZK_ROOTS_GET),
        ("ZK_VOTE_GET_TALLY", syscalls::SYSCALL_ZK_VOTE_GET_TALLY),
        ("VRF_EPOCH_SEED", syscalls::SYSCALL_VRF_EPOCH_SEED),
    ] {
        let want = encoding::wide::encode_sys(instruction::wide::system::SCALL, syscall as u8)
            .to_le_bytes();
        assert!(
            code_region.windows(want.len()).any(|window| window == want),
            "{name} syscall not found"
        );
    }
}
#[test]
fn manifest_includes_exact_access_hints_for_static_zk_read_requests() {
    use iroha_data_model::asset::id::AssetDefinitionId;
    use ivm::zk_verify::{RootsGetRequest, VoteGetTallyRequest};
    let asset_definition = AssetDefinitionId::parse_address_literal("62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        .expect("parse asset definition");
    let roots_payload = norito::to_bytes(&RootsGetRequest {
        asset_id: asset_definition.to_string(),
        max: 4,
    })
    .expect("encode roots request");
    let tally_payload = norito::to_bytes(&VoteGetTallyRequest {
        election_id: "election-1".to_string(),
    })
    .expect("encode tally request");
    let roots_literal = roots_payload
        .iter()
        .map(|byte| format!("\\x{byte:02x}"))
        .collect::<String>();
    let tally_literal = tally_payload
        .iter()
        .map(|byte| format!("\\x{byte:02x}"))
        .collect::<String>();
    let src = format!(
        r#"
        seiyaku StaticReadHints {{
          view fn read() authorize(anyone) -> bytes {{
            let roots = crypto::zk::roots(value: b"{}");
            let tally = ledger::governance::tally(value: b"{}");
            return tally;
          }}
        }}
    "#,
        roots_literal, tally_literal
    );
    let (_code, manifest) = Compiler::new()
        .compile_source_with_manifest(&src)
        .expect("compile manifest with ZK read hints");
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let read = entrypoints
        .iter()
        .find(|entry| entry.name == "read")
        .expect("read entrypoint");
    assert_eq!(read.access_hints_complete, Some(true));
    assert!(read.access_hints_skipped.is_empty());
    assert!(read.write_keys.is_empty());
    assert!(
        read.read_keys
            .contains(&format!("zk_asset:{asset_definition}"))
    );
    assert!(
        read.read_keys
            .contains(&"zk:election:election-1:tally".to_string())
    );
    assert!(!read.read_keys.contains(&"*".to_string()));
}
#[test]
fn compile_emits_state_introspection_helpers() {
    let src = include_str!("../fixtures/koto_v1/kotodama/027.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let code = Compiler::new().compile_source(src).expect("compile");
    let (_, off) = parse_meta_offset(&code).unwrap();
    let code_region = &code[off..];
    for (name, syscall) in [
        ("STATE_SCAN", syscalls::SYSCALL_STATE_SCAN),
        ("STATE_HAS", syscalls::SYSCALL_STATE_HAS),
        ("STATE_LEN", syscalls::SYSCALL_STATE_LEN),
        ("STATE_COUNT", syscalls::SYSCALL_STATE_COUNT),
    ] {
        let want = encoding::wide::encode_syscallx(syscall).to_le_bytes();
        assert!(
            code_region.windows(want.len()).any(|window| window == want),
            "{name} syscall not found"
        );
    }
}
#[test]
fn compile_emits_extended_hash_syscalls() {
    let src = include_str!("../fixtures/koto_v1/kotodama/028.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let code = Compiler::new().compile_source(src).expect("compile");
    let (_, off) = parse_meta_offset(&code).unwrap();
    let mut words = Vec::new();
    let mut i = off;
    while i + 4 <= code.len() {
        words.push(u32::from_le_bytes(code[i..i + 4].try_into().unwrap()));
        i += 4;
    }
    let scall = instruction::wide::system::SCALL;
    for (name, syscall) in [
        ("BLAKE2B256_HASH", syscalls::SYSCALL_BLAKE2B256_HASH),
        ("KECCAK256_HASH", syscalls::SYSCALL_KECCAK256_HASH),
        ("IROHA_HASH", syscalls::SYSCALL_IROHA_HASH),
    ] {
        let want = encoding::wide::encode_sys(scall, syscall as u8);
        assert!(words.contains(&want), "{name} syscall not found");
    }
}
#[test]
fn compile_emits_resolve_account_alias_syscall() {
    let src = r#"seiyaku ResolveAlias { view fn f() authorize(anyone) { let a = ledger::account::resolve_alias(alias: "banking@centralbank"); } }"#;
    let code = Compiler::new().compile_source(src).expect("compile");
    let (_, off) = parse_meta_offset(&code).unwrap();
    let mut words = Vec::new();
    let mut i = off;
    while i + 4 <= code.len() {
        words.push(u32::from_le_bytes(code[i..i + 4].try_into().unwrap()));
        i += 4;
    }
    let scall = instruction::wide::system::SCALL;
    let want = encoding::wide::encode_sys(scall, syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS as u8);
    assert!(
        words.contains(&want),
        "RESOLVE_ACCOUNT_ALIAS syscall not found"
    );
}
#[test]
fn semantic_simple_add() {
    let src = "module Arithmetic { fn add(int a, int b) { let c = a + b; } }";
    let prog = parse(src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let kotodama_lang::semantic::TypedItem::Function(func) = &typed.items[0];
    if let kotodama_lang::semantic::TypedStatement::Let { name, value } = &func.body.statements[0] {
        assert_eq!(name, "c");
        assert_eq!(value.ty, Type::Int);
    } else {
        panic!("expected let statement");
    }
}
#[test]
fn encode_helpers() {
    use kotodama_lang::compiler::{encode_add, encode_addi};
    let add = encode_add(3, 1, 2);
    assert_eq!(add, 0x0103_0102);
    let addi = encode_addi(1, 1, 7).expect("encode addi");
    assert_eq!(addi, 0x2001_0107);
}
#[test]
fn compile_and_run_add() {
    let src = "seiyaku Add { fn add(int a, int b) -> int { return a + b; } view fn main() authorize(anyone) -> int { return add(a: 4, b: 7); } }";
    let compiler = Compiler::new();
    let code = compiler.compile_source(src).expect("compile failed");
    let (meta, off) = parse_meta_offset(&code).unwrap();
    assert_eq!(meta.mode, 0);
    assert_eq!(meta.version_minor, 1);
    assert!(
        off > 17,
        "self-describing artifacts must prefix code with CNTR"
    );
    let mut vm = ivm::IVM::new(u64::MAX);
    // Decode trace left disabled by default; first-words dump is printed above.
    vm.load_program(&code).unwrap();
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("execution failed");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 11);
}
#[test]
fn compile_builtin_create_nfts_and_set_detail() {
    let src = "seiyaku CanonicalHostCalls { permission Admin;  kotoage fn main() authorize(Admin) { ledger::nft::create_for_all_users(); ledger::account::set_metadata(account: context::authority(), key: Name::parse(\"cursor\"), value: Json::parse(\"{\\\"cursor\\\":1,\\\"query\\\":\\\"sc_dummy\\\"}\")); } }";
    let code = test_compiler().compile_source(src).expect("compile failed");
    // Sanity: code contains at least three syscalls (order preserved)
    // Byte-pattern search for SCALL encodings (LE): [imm8, 0x00, 0x00, 0x60]
    let (_meta, off) = parse_meta_offset(&code).unwrap();
    let code_bytes = &code[off..];
    // Expect SCALL encodings for our helper syscalls present
    let scall = instruction::wide::system::SCALL;
    let _want = [
        encoding::wide::encode_sys(scall, syscalls::SYSCALL_CREATE_NFTS_FOR_ALL_USERS as u8),
        encoding::wide::encode_sys(scall, syscalls::SYSCALL_SET_ACCOUNT_DETAIL as u8),
    ];
    let imm_create = syscalls::SYSCALL_CREATE_NFTS_FOR_ALL_USERS as u8;
    let imm_detail = syscalls::SYSCALL_SET_ACCOUNT_DETAIL as u8;
    let pat = |imm: u8| [imm, 0x00, 0x00, instruction::wide::system::SCALL];
    let has = |imm: u8| code_bytes.windows(4).any(|w| w == pat(imm));
    assert!(has(imm_create) && has(imm_detail));
}
#[test]
fn non_json_pointer_constructors_accept_string_variables() {
    // Non-JSON constructors accept string variables; Json::parse remains literal-only.
    let src = include_str!("../fixtures/koto_v1/kotodama/032.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile pointer from vars");
    // Expect SCALLs present for set detail and transfer domain
    let (_m, off) = parse_meta_offset(&code).unwrap();
    let bytes = &code[off..];
    let scall = instruction::wide::system::SCALL;
    let has = |imm: u8| {
        bytes
            .windows(4)
            .any(|w| w == encoding::wide::encode_sys(scall, imm).to_le_bytes())
    };
    assert!(
        has(syscalls::SYSCALL_SET_ACCOUNT_DETAIL as u8)
            && has(syscalls::SYSCALL_TRANSFER_DOMAIN as u8),
        "expected set detail and transfer domain syscalls"
    );
}
#[test]
fn semantic_type_enforcement_for_typed_syscalls() {
    use kotodama_lang::parser::parse;
    // Wrong types should fail
    let bad = parse(
        "module InvalidMint { fn f() { ledger::asset::mint(account: Name::parse(\"x\"), asset_definition: AssetDefinitionId::parse(\"62Fk4FPcMuLvW5QjDGNF2a4jAmjM\"), amount: 1); } }",
    )
    .unwrap();
    assert!(analyze(&bad).is_err());
    let bad2 = parse("module InvalidDetail { fn f() { ledger::account::set_metadata(account: AccountId::parse(\"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV\"), key: Json::parse(\"1\"), value: Name::parse(\"k\")); } }").unwrap();
    assert!(analyze(&bad2).is_err());
}
#[test]
fn compile_typed_nft_syscalls() {
    let src = "seiyaku NftCalls { permission ManageNfts;  kotoage fn main() authorize(ManageNfts) { ledger::nft::mint(nft: NftId::parse(\"n0$wonderland.universal\"), owner: AccountId::parse(\"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV\")); ledger::nft::transfer(source: AccountId::parse(\"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV\"), nft: NftId::parse(\"n0$wonderland.universal\"), destination: AccountId::parse(\"sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76\")); } }";
    let code = Compiler::new()
        .compile_source(src)
        .expect("compile typed NFT");
    let (_meta, off) = parse_meta_offset(&code).unwrap();
    let code_bytes = &code[off..];
    let pat = |imm: u8| [imm, 0x00, 0x00, instruction::wide::system::SCALL];
    let has = |imm: u8| code_bytes.windows(4).any(|w| w == pat(imm));
    assert!(has(syscalls::SYSCALL_NFT_MINT_ASSET as u8));
    assert!(has(syscalls::SYSCALL_NFT_TRANSFER_ASSET as u8));
}
#[test]
fn compiler_owns_first_release_abi_metadata() {
    let code = Compiler::new()
        .compile_source("seiyaku FixedAbi { view fn f() authorize(anyone) -> int { return 3; } }")
        .expect("compile");
    let (meta, _off) = parse_meta_offset(&code).unwrap();
    assert_eq!(meta.abi_version, 1);
    assert_eq!(meta.vector_length, 0);
}
#[test]
fn compile_emits_manifest_hashes() {
    use ivm::{SyscallPolicy, syscalls::compute_abi_hash};
    let src = "seiyaku ManifestHash { view fn f() authorize(anyone) { let x = 1 + 2; } }";
    let (code, manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("compile with manifest");
    let parsed = ProgramMetadata::parse(&code).expect("parse header");
    let meta = parsed.metadata;
    let expected_code_hash = ivm::contract_code_hash(&code);
    assert_eq!(manifest.code_hash, Some(expected_code_hash));
    let policy = match meta.abi_version {
        1 => SyscallPolicy::AbiV1,
        _ => unreachable!("compiler emits ABI v1 only"),
    };
    let expected_abi = iroha_crypto::Hash::prehashed(compute_abi_hash(policy));
    assert_eq!(manifest.abi_hash, Some(expected_abi));
}
#[test]
fn manifest_code_hash_reflects_literals() {
    let compiler = Compiler::new();
    let (_, manifest_a) = compiler
        .compile_source_with_manifest(
            "seiyaku LiteralAlpha { view fn f() authorize(anyone) -> string { return \"alpha\"; } }",
        )
        .expect("compile alpha");
    let (_, manifest_b) = compiler
        .compile_source_with_manifest(
            "seiyaku LiteralBeta { view fn f() authorize(anyone) -> string { return \"beta\"; } }",
        )
        .expect("compile beta");
    let hash_a = manifest_a.code_hash.expect("alpha code hash");
    let hash_b = manifest_b.code_hash.expect("beta code hash");
    assert_ne!(hash_a, hash_b, "literals must influence code_hash");
}
#[test]
fn manifest_includes_entrypoints_and_features() {
    use iroha_data_model::smart_contract::manifest::EntryPointKind;
    let src = include_str!("../fixtures/koto_v1/kotodama/048.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (code, manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("compile manifest with entrypoints");
    let parsed = ProgramMetadata::parse(&code).expect("parse compiled artifact");
    assert_eq!(parsed.metadata.version_minor, 1);
    let contract_interface = parsed
        .contract_interface
        .expect("compiled contract must embed a CNTR section");
    assert_eq!(contract_interface.entrypoints.len(), 2);
    assert_eq!(contract_interface.entrypoints[0].name, "hajimari");
    assert_eq!(contract_interface.entrypoints[1].name, "run");
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    assert_eq!(entrypoints.len(), 2);
    assert_eq!(entrypoints[0].name, "hajimari");
    assert!(matches!(entrypoints[0].kind, EntryPointKind::Hajimari));
    assert_eq!(
        entrypoints[0].authorization,
        iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::RuntimeLifecycle
    );
    assert_eq!(entrypoints[0].read_keys, Vec::<String>::new());
    assert_eq!(entrypoints[0].write_keys, vec!["state:counter"]);
    assert_eq!(entrypoints[1].name, "run");
    assert!(matches!(entrypoints[1].kind, EntryPointKind::Kotoage));
    assert_eq!(
        entrypoints[1].authorization,
        iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
            "Admin".parse().unwrap()
        )
    );
    assert_eq!(entrypoints[1].read_keys, vec!["state:counter"]);
    assert_eq!(entrypoints[1].write_keys, Vec::<String>::new());
    assert_eq!(manifest.features_bitmap, Some(0));
}
#[test]
fn manifest_includes_trigger_descriptors() {
    use iroha_data_model::{events::EventFilterBox, trigger::action::Repeats};
    let src = include_str!("../fixtures/koto_v1/kotodama/049.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (_code, manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("compile manifest with triggers");
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let run = entrypoints
        .iter()
        .find(|entry| entry.name == "run")
        .expect("run entrypoint");
    assert_eq!(run.triggers.len(), 1);
    let trigger = &run.triggers[0];
    assert_eq!(trigger.id.to_string(), "wake");
    assert!(matches!(trigger.filter, EventFilterBox::Time(_)));
    assert_eq!(trigger.repeats, Repeats::Exactly(2));
    assert_eq!(trigger.callback.entrypoint, "run");
}
#[test]
fn manifest_includes_isi_access_hints_for_static_targets() {
    use iroha_data_model::{
        account::AccountId,
        asset::id::{AssetDefinitionId, AssetId},
    };
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let src = include_str!("../fixtures/koto_v1/kotodama/050.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (_code, manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("compile manifest with ISI hints");
    let hints = manifest
        .access_set_hints
        .expect("access_set_hints must be present");
    let account: AccountId =
        AccountId::parse_encoded("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
            .expect("parse encoded account literal");
    let asset_def =
        AssetDefinitionId::parse_address_literal(asset_literal).expect("parse canonical asset");
    let asset_id = AssetId::of(asset_def.clone(), account.clone());
    assert!(hints.read_keys.contains(&format!("account:{account}")));
    assert!(hints.read_keys.contains(&format!("asset_def:{asset_def}")));
    assert!(hints.read_keys.contains(&format!("asset:{asset_id}")));
    assert!(hints.write_keys.contains(&format!("asset_def:{asset_def}")));
    assert!(hints.write_keys.contains(&format!("asset:{asset_id}")));
    assert!(
        !hints.read_keys.iter().any(|key| key.starts_with("domain:")),
        "canonical asset-definition ids must not synthesize domain hints",
    );
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let main = entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    assert!(main.read_keys.contains(&format!("account:{account}")));
    assert!(main.read_keys.contains(&format!("asset_def:{asset_def}")));
    assert!(main.read_keys.contains(&format!("asset:{asset_id}")));
    assert!(main.write_keys.contains(&format!("asset_def:{asset_def}")));
    assert!(main.write_keys.contains(&format!("asset:{asset_id}")));
    assert!(
        !main.read_keys.iter().any(|key| key.starts_with("domain:")),
        "opaque canonical asset definitions should not synthesize domain hints",
    );
}
#[test]
fn production_manifest_accepts_authority_placeholder_isi_access() {
    let src = include_str!("../fixtures/koto_v1/kotodama/051.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (_code, manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("production compile must accept authority placeholder access");
    let hints = manifest
        .access_set_hints
        .expect("access_set_hints must be present");
    assert!(hints.read_keys.contains(&"account:$authority".to_string()));
    assert!(
        hints
            .read_keys
            .contains(&"domain:wonderland.universal".to_string())
    );
    assert!(
        hints
            .write_keys
            .contains(&"domain:wonderland.universal".to_string())
    );
    assert!(!hints.read_keys.contains(&"*".to_string()));
    assert!(!hints.write_keys.contains(&"*".to_string()));
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let main = entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    assert_eq!(main.access_hints_complete, Some(true));
    assert!(main.read_keys.contains(&"account:$authority".to_string()));
    assert!(
        main.read_keys
            .contains(&"domain:wonderland.universal".to_string())
    );
    assert!(
        main.write_keys
            .contains(&"domain:wonderland.universal".to_string())
    );
}
#[test]
fn production_manifest_accepts_parameter_dependent_isi_access_with_coarse_hints() {
    let src = include_str!("../fixtures/koto_v1/kotodama/052.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (_code, manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("parameter-dependent asset transfers have bounded coarse hints");
    let hints = manifest
        .access_set_hints
        .expect("production manifest must include access hints");
    for key in ["account:*", "asset:*", "asset_def:*"] {
        assert!(hints.read_keys.iter().any(|actual| actual == key));
    }
    for key in ["asset:*", "asset_def:*"] {
        assert!(hints.write_keys.iter().any(|actual| actual == key));
    }
    assert!(!hints.read_keys.iter().any(|key| key == "*"));
    assert!(!hints.write_keys.iter().any(|key| key == "*"));
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let move_entry = entrypoints
        .iter()
        .find(|entry| entry.name == "move")
        .expect("move entrypoint");
    assert_eq!(move_entry.access_hints_complete, Some(true));
    assert!(move_entry.access_hints_skipped.is_empty());
    for key in ["account:*", "asset:*", "asset_def:*"] {
        assert!(move_entry.read_keys.iter().any(|actual| actual == key));
    }
    for key in ["asset:*", "asset_def:*"] {
        assert!(move_entry.write_keys.iter().any(|actual| actual == key));
    }
}
#[test]
fn source_localization_blocks_are_rejected() {
    for spelling in ["messages", "kotoba"] {
        let src = format!(
            r#"
            seiyaku C {{
                {spelling} {{
                    "E0001": {{ en: "Invalid assets", ja: "無効な資産" }}
                }}
                view fn main() authorize(anyone) {{}}
            }}
            "#
        );
        let error = Compiler::new()
            .compile_source_with_manifest(&src)
            .expect_err("source localization tables are not part of V1");
        assert!(error.contains("source-unit item"), "{error}");
    }
}
#[test]
fn canonical_host_calls_typecheck_and_removed_map_does_not() {
    let src = include_str!("../fixtures/koto_v1/kotodama/054.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let prog = parse(src).expect("parse ledger::asset::transfer");
    analyze(&prog).expect("analyze ledger::asset::transfer");
    let src2 = "module RemovedMap { fn make() -> int { return std::map::new(); } }";
    let prog2 = parse(src2).expect("parse std::map::new");
    analyze(&prog2).expect_err("in-memory map constructors are removed from V1");
}
#[test]
fn ternary_parses_and_types() {
    let src = "module Ternary { fn f(int a, int b) -> int { let x = (1 < 2) ? a : b; return x; } }";
    let prog = parse(src).expect("parse ternary");
    let typed = analyze(&prog).expect("type ternary");
    let kotodama_lang::semantic::TypedItem::Function(f) = &typed.items[0];
    assert_eq!(f.name, "f");
}
#[test]
fn ternary_min_types() {
    let src = "module Ternary { fn choose_min(int a, int b) -> int { return (a < b) ? a : b; } }";
    let typed = analyze(&parse(src).expect("parse ternary")).expect("type ternary");
    assert!(typed.items.iter().any(|item| {
        matches!(item, kotodama_lang::semantic::TypedItem::Function(function) if function.name == "choose_min")
    }));
}
#[test]
fn nested_ternary_types() {
    let src =
        "module Ternary { fn f(int a, int b, int c) -> int { return a < b ? b < c ? b : c : a; } }";
    analyze(&parse(src).expect("parse nested ternary")).expect("type nested ternary");
}
#[test]
fn build_options_control_header_and_source_meta_is_unavailable() {
    let src = include_str!("../fixtures/koto_v1/kotodama/057.ko");
    let code = Compiler::new_with_options(kotodama_lang::compiler::CompilerOptions {
        max_cycles: 1234,
        ..Default::default()
    })
    .compile_source(src)
    .expect("compile build-selected metadata");
    let (meta, _off) = parse_meta_offset(&code).unwrap();
    assert_eq!(meta.abi_version, 1);
    assert_eq!(meta.vector_length, 0);
    assert_eq!(meta.max_cycles, 1234);
    assert_eq!(meta.mode & ivm::ivm_mode::ZK, 0);
    assert_eq!(meta.mode & ivm::ivm_mode::VECTOR, 0);
}
#[test]
fn removed_in_memory_map_indexing_is_rejected() {
    let src = "module RemovedMap { fn f(Map<int, int> m, int k) -> int { return m[k]; } }";
    let error = Compiler::new()
        .compile_source(src)
        .expect_err("in-memory Map must not compile in V1");
    assert!(error.contains("Map"), "unexpected error: {error}");
}
#[test]
fn branch_lowering_uses_compact_conditional_and_one_relaxed_transfer() {
    let src = include_str!("../fixtures/koto_v1/kotodama/058.ko");
    let (code, _manifest, report) = Compiler::new()
        .compile_source_with_manifest_and_report(src)
        .expect("compile simple branch");
    let metadata = ProgramMetadata::parse(&code).expect("parse metadata");
    let branch = report
        .budget_report
        .iter()
        .find(|entry| entry.function_name == "branch")
        .expect("branch budget report");
    let words = code[metadata.code_offset + branch.pc_start as usize
        ..metadata.code_offset + branch.pc_end as usize]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("word chunk")))
        .collect::<Vec<_>>();
    let branch_index = words
        .iter()
        .position(|word| {
            matches!(
                instruction::wide::opcode(*word),
                instruction::wide::control::BEQ | instruction::wide::control::BNE
            )
        })
        .expect("expected compact conditional branch");
    let branch_word = words[branch_index];
    let imm = instruction::wide::imm8(branch_word);
    assert_eq!(
        imm, 2,
        "BNE should skip the one-word else transfer and land on the one-word then transfer"
    );
    let relaxed_else_transfer = words[branch_index + 1];
    let then_block_index =
        branch_index + usize::try_from(imm).expect("positive branch displacement");
    assert!(
        words.len() > then_block_index,
        "BNE target should land directly in the then block"
    );
    assert!(
        matches!(
            instruction::wide::opcode(relaxed_else_transfer),
            instruction::wide::control::JAL | instruction::wide::control::JMP
        ),
        "fallthrough path must transfer to the non-adjacent block"
    );
    assert!(
        !matches!(
            instruction::wide::opcode(words[then_block_index]),
            instruction::wide::control::JAL | instruction::wide::control::JMP
        ),
        "taken path must fall through into the adjacent block without a second jump"
    );
}
#[test]
fn truncated_poseidon2_is_not_a_source_api() {
    // Truncated scalar proof gadgets are internal VM operations.
    let src =
        "module Poseidon { fn f(int a, int b) { let h = crypto::poseidon2(left: a, right: b); } }";
    let error = Compiler::new()
        .compile_source(src)
        .expect_err("truncated Poseidon must not be a source API");
    assert!(error.contains("crypto::poseidon2"));
}
#[test]
fn public_scalar_valcom_is_rejected_even_without_pubkgen() {
    let src = "module Commitment { fn main(int a, int b) -> int { return crypto::valcom(left: a, right: b); } }";
    let error = Compiler::new_with_options(CompilerOptions {
        force_zk: true,
        ..CompilerOptions::default()
    })
    .compile_source(src)
    .expect_err("public valcom operands must not select the truncated opcode");
    assert!(error.contains("Secret<int|decimal|quantity>"));
}
#[test]
fn typed_json_access_spills_are_handled() {
    use kotodama_lang::ir::Instr;
    use kotodama_lang::regalloc;
    std::thread::Builder::new()
        .name("typed_json_access_spills".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let build_src = |count: usize| {
                let mut src =
                    String::from("seiyaku JsonSpills {\nview fn main(Json j) authorize(anyone) -> int {\n");
                for i in 0..count {
                    let value = (i + 1) as i64;
                    src.push_str(&format!("  let v{i} = {value};\n"));
                }
                src.push_str("  let val = match j.get_int(Name::parse(\"value\")) { Option::some(value) => value, Option::none => 0 };\n");
                src.push_str("  let sum = ");
                for i in 0..count {
                    if i > 0 {
                        src.push_str(" + ");
                    }
                    src.push_str(&format!("v{i}"));
                }
                src.push_str(" + val;\n  return sum;\n}\n}\n");
                src
            };
            let src = build_src(32);
            let prog = parse(&src).expect("parse typed Json spill");
            let typed = analyze(&prog).expect("analyze typed Json spill");
            let ir = kotodama_lang::ir::lower(&typed).expect("lower");
            let func = ir
                .functions
                .iter()
                .find(|f| f.name == "main")
                .expect("main function lowered");
            assert!(func.blocks.iter().any(|block| {
                block.instrs.iter().any(|instruction| {
                    matches!(
                        instruction,
                        Instr::JsonGetNumeric {
                            kind: kotodama_lang::ir::WideNumericKind::Int,
                            ..
                        }
                    )
                })
            }));
            let alloc = regalloc::allocate(func);
            assert!(
                !alloc.stack.is_empty(),
                "fixture must compile typed Json access in a spilled stack frame"
            );
            Compiler::new()
                .compile_source(&src)
                .expect("compile typed Json spill");
        })
        .expect("spawn typed Json spill test")
        .join()
        .expect("typed Json spill test thread");
}
#[test]
fn compile_from_file() {
    let path = std::path::Path::new("tests/data/add.ko");
    let code = Compiler::new().compile_file(path).expect("compile failed");
    assert!(!code.is_empty());
}
#[test]
fn compile_complex_program() {
    let path = std::path::Path::new("tests/data/complex.ko");
    let code = Compiler::new().compile_file(path).expect("compile failed");
    let (meta, _) = parse_meta_offset(&code).unwrap();
    assert_eq!(meta.mode & ivm::ivm_mode::ZK, 0);
}
#[test]
fn parse_control_flow() {
    let path = std::path::Path::new("tests/data/control.ko");
    let src = std::fs::read_to_string(path).expect("read failed");
    let prog = parse(&src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    assert!(ir.functions[0].blocks.len() > 2);
}
#[test]
fn parse_amm_dex() {
    use kotodama_lang::ir::{Instr, WideNumericKind};
    use std::path::Path;
    let path = Path::new("tests/data/amm.ko");
    let src = std::fs::read_to_string(path).expect("read failed");
    let prog = parse(&src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let mut has_mul = false;
    let mut has_div = false;
    for function in &ir.functions {
        for block in &function.blocks {
            for instruction in &block.instrs {
                match instruction {
                    Instr::NumericBinary {
                        op: BinaryOp::Mul,
                        left_kind: WideNumericKind::Int,
                        right_kind: WideNumericKind::Int,
                        result_kind: WideNumericKind::Int,
                        ..
                    } => has_mul = true,
                    Instr::NumericBinary {
                        op: BinaryOp::Div,
                        left_kind: WideNumericKind::Int,
                        right_kind: WideNumericKind::Int,
                        result_kind: WideNumericKind::Int,
                        ..
                    } => has_div = true,
                    _ => {}
                }
            }
        }
    }
    assert!(has_mul && has_div);
}
#[test]
fn parse_dai_clone() {
    use kotodama_lang::ir::{Instr, WideNumericKind};
    use std::path::Path;
    let path = Path::new("tests/data/dai.ko");
    let src = std::fs::read_to_string(path).expect("read failed");
    let prog = parse(&src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let mut has_add = false;
    let mut has_sub = false;
    for function in &ir.functions {
        for block in &function.blocks {
            for instruction in &block.instrs {
                match instruction {
                    Instr::NumericBinary {
                        op: BinaryOp::Add,
                        left_kind: WideNumericKind::Quantity,
                        right_kind: WideNumericKind::Quantity,
                        result_kind: WideNumericKind::Quantity,
                        ..
                    } => has_add = true,
                    Instr::NumericBinary {
                        op: BinaryOp::Sub,
                        left_kind: WideNumericKind::Quantity,
                        right_kind: WideNumericKind::Quantity,
                        result_kind: WideNumericKind::Quantity,
                        ..
                    } => has_sub = true,
                    _ => {}
                }
            }
        }
    }
    assert!(has_add && has_sub);
}
#[test]
fn parse_mint_asset_builtin() {
    use kotodama_lang::ir::Instr;
    let src = "module MintHelpers { fn f(AccountId a, AssetDefinitionId b, quantity c) { ledger::asset::mint(account: a, asset_definition: b, amount: c); } }";
    let prog = parse(src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let instrs = &ir.functions[0].blocks[0].instrs;
    assert!(instrs.iter().any(|i| matches!(i, Instr::MintAsset { .. })));
}
#[test]
fn parse_transfer_asset_builtin() {
    use kotodama_lang::ir::Instr;
    let src = "module TransferHelpers { fn f(AccountId a, AccountId b, AssetDefinitionId c, quantity d, DataSpaceId e) { ledger::asset::transfer(source: a, destination: b, asset_definition: c, amount: d, dataspace: e); } }";
    let prog = parse(src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let instrs = &ir.functions[0].blocks[0].instrs;
    assert!(
        instrs
            .iter()
            .any(|i| matches!(i, Instr::TransferAsset { .. }))
    );
}
#[test]
fn parse_transfer_batch_builtin() {
    use kotodama_lang::ir::{Instr, Terminator};
    let src = "module BatchHelpers { fn f(AccountId a, AccountId b, AssetDefinitionId c, quantity d) { ledger::asset::transfer_batch(transfers: [(a, b, c, d), (b, a, c, d)]); } }";
    let prog = parse(src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let instrs = ir.functions[0]
        .blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .collect::<Vec<_>>();
    assert_eq!(
        instrs
            .iter()
            .filter(|i| matches!(i, Instr::TransferBatchBegin))
            .count(),
        1,
        "one high-level transfer_batch call must open one atomic batch"
    );
    let transfer_count = instrs
        .iter()
        .filter(|i| matches!(i, Instr::TransferBatchAsset { .. }))
        .count();
    assert_eq!(
        transfer_count, 1,
        "one bounded loop body applies each active transfer entry"
    );
    let body = ir.functions[0]
        .blocks
        .iter()
        .find(|block| {
            block
                .instrs
                .iter()
                .any(|instruction| matches!(instruction, Instr::TransferBatchAsset { .. }))
        })
        .expect("transfer loop body");
    let Terminator::Jump(condition) = body.terminator else {
        panic!("transfer loop must return to its active-length condition");
    };
    let condition = ir.functions[0]
        .blocks
        .iter()
        .find(|block| block.label == condition)
        .expect("bounded transfer condition");
    assert!(matches!(
        condition.terminator,
        Terminator::Branch { then_bb, .. } if then_bb == body.label
    ));
    assert_eq!(
        instrs
            .iter()
            .filter(|i| matches!(i, Instr::TransferBatchEnd))
            .count(),
        1,
        "one high-level transfer_batch call must close one atomic batch"
    );
}
#[test]
fn transfer_batch_requires_entries() {
    let src = "module EmptyBatch { fn f() { ledger::asset::transfer_batch(); } }";
    let prog = parse(src).expect("parse failed");
    assert!(
        analyze(&prog).is_err(),
        "an empty transfer_batch call must be rejected"
    );
}
#[test]
fn transfer_batch_requires_tuple_entries() {
    let src = "module InvalidBatch { fn f(AccountId a) { ledger::asset::transfer_batch(transfers: [a]); } }";
    let prog = parse(src).expect("parse failed");
    assert!(
        analyze(&prog).is_err(),
        "non-tuple transfer_batch entries must be rejected"
    );
}
#[test]
fn parse_burn_asset_builtin() {
    use kotodama_lang::ir::Instr;
    let src = "module BurnHelpers { fn f(AccountId a, AssetDefinitionId b, quantity c) { ledger::asset::burn(account: a, asset_definition: b, amount: c); } }";
    let prog = parse(src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let instrs = &ir.functions[0].blocks[0].instrs;
    assert!(instrs.iter().any(|i| matches!(i, Instr::BurnAsset { .. })));
}
#[test]
fn parse_register_asset_builtin() {
    use kotodama_lang::ir::Instr;
    let src = include_str!("../fixtures/koto_v1/kotodama/063.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let prog = parse(src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let instrs = &ir.functions[0].blocks[0].instrs;
    assert!(
        instrs
            .iter()
            .any(|i| matches!(i, Instr::RegisterAsset { .. }))
    );
}
#[test]
fn parse_register_then_mint_builtins() {
    use kotodama_lang::ir::Instr;
    let src = include_str!("../fixtures/koto_v1/kotodama/064.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let prog = parse(src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let instrs = &ir.functions[0].blocks[0].instrs;
    assert!(
        instrs
            .iter()
            .any(|i| matches!(i, Instr::RegisterAsset { .. }))
    );
    assert!(instrs.iter().any(|i| matches!(i, Instr::MintAsset { .. })));
}
#[test]
fn parse_mfc_example() {
    use kotodama_lang::ir::{Instr, Terminator};
    use std::path::Path;
    let path = Path::new("tests/data/mfc.ko");
    let src = std::fs::read_to_string(path).expect("read failed");
    let prog = parse(&src).expect("parse failed");
    let typed = analyze(&prog).expect("semantic analysis failed");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let mut has_transfer = false;
    let mut has_branch = false;
    for block in &ir.functions[1].blocks {
        for instr in &block.instrs {
            if matches!(instr, Instr::TransferAsset { .. }) {
                has_transfer = true;
            }
        }
        if matches!(block.terminator, Terminator::Branch { .. }) {
            has_branch = true;
        }
    }
    let mut has_mint = false;
    let mut has_register = false;
    for instr in &ir.functions[2].blocks[0].instrs {
        if matches!(instr, Instr::MintAsset { .. }) {
            has_mint = true;
        }
        if matches!(instr, Instr::RegisterAsset { .. }) {
            has_register = true;
        }
    }
    assert!(has_transfer && has_branch && has_mint && has_register);
}
#[test]
fn compile_kotodama_samples_supported() {
    use std::path::Path;
    let compiler = test_compiler();
    let samples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../kotodama_lang/src/samples");
    // Compile a curated subset of samples supported by the current compiler
    let files = [
        "asset_ops.ko",
        "mint_rose_trigger.ko",
        "query_assets_and_save_cursor.ko",
        "smart_contract_can_filter_queries.ko",
        "threshold_escrow.ko",
    ];
    for file in files {
        let src = std::fs::read_to_string(samples_dir.join(file)).expect("read failed");
        compiler
            .compile_source(&src)
            .unwrap_or_else(|e| panic!("compile failed for {file}: {e}"));
    }
}
#[test]
fn ir_lower_contains_method_state_map() {
    use kotodama_lang::ir::Instr;
    let src = include_str!("../fixtures/koto_v1/kotodama/067.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let prog = parse(src).expect("parse contains");
    let typed = analyze(&prog).expect("analyze contains");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let f = &ir.functions[0];
    let mut saw_state_get = false;
    let mut saw_ne = false;
    for block in &f.blocks {
        for ins in &block.instrs {
            match ins {
                Instr::StateGet { .. } => saw_state_get = true,
                Instr::Binary { op, .. } if *op == kotodama_lang::ast::BinaryOp::Ne => {
                    saw_ne = true;
                }
                _ => {}
            }
        }
    }
    assert!(saw_state_get && saw_ne);
}
#[test]
fn ir_tuple_pack_and_get_general() {
    use kotodama_lang::ir::Instr;
    let src = include_str!("../fixtures/koto_v1/kotodama/070.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let prog = parse(src).expect("parse tuple pack/get");
    let typed = analyze(&prog).expect("analyze tuple pack/get");
    let ir = kotodama_lang::ir::lower(&typed).expect("lower");
    let f = &ir.functions[0];
    let mut saw_pack = false;
    let mut saw_get = false;
    for block in &f.blocks {
        for ins in &block.instrs {
            match ins {
                Instr::TuplePack { .. } => saw_pack = true,
                Instr::TupleGet { .. } => saw_get = true,
                _ => {}
            }
        }
    }
    let flattened = typed.items.iter().any(|item| {
        let kotodama_lang::semantic::TypedItem::Function(func) = item;
        func.body.statements.iter().any(|stmt| {
            if let kotodama_lang::semantic::TypedStatement::Let { name, value } = stmt {
                name.contains('#')
                    && matches!(value.expr, kotodama_lang::semantic::ExprKind::Ident(_))
            } else {
                false
            }
        })
    });
    assert!(saw_pack, "tuple literals should lower to TuplePack");
    assert!(
        saw_get || flattened,
        "tuple field access should lower via TupleGet or reuse flattened bindings"
    );
}
#[test]
fn typed_vrf_syscalls_are_present() {
    let src = include_str!("../fixtures/koto_v1/kotodama/071.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile vrf intrinsic");
    let (_meta, off) = parse_meta_offset(&code).unwrap();
    let bytes = &code[off..];
    let scall = instruction::wide::system::SCALL;
    let has = |imm: u8| {
        bytes
            .windows(4)
            .any(|w| w == encoding::wide::encode_sys(scall, imm).to_le_bytes())
    };
    assert!(has(syscalls::SYSCALL_VRF_VERIFY as u8));
    assert!(has(syscalls::SYSCALL_VRF_VERIFY_BATCH as u8));
}
#[test]
fn retired_axt_handle_intrinsics_are_rejected() {
    for (retired, source) in [
        (
            "asset_handle",
            r#"seiyaku RemovedAxtSurface { permission UseAxt;
                 kotoage fn main() authorize(UseAxt) {
                   let handle = asset_handle("0x00");
                 }
               }"#,
        ),
        (
            "axt::use_asset_handle",
            r#"seiyaku RemovedAxtSurface { permission UseAxt;
                 kotoage fn main() authorize(UseAxt) {
                   axt::use_asset_handle(handle: norito_bytes("h"), operation: norito_bytes("i"), proof: norito_bytes("p"));
                 }
               }"#,
        ),
    ] {
        let error = test_compiler()
            .compile_source(source)
            .expect_err("retired AXT pointer operation is not in V1");
        assert!(
            error.contains("unknown")
                || error.contains("not supported")
                || error.contains("undefined"),
            "{retired} unexpectedly failed for a different reason: {error}"
        );
    }
}
