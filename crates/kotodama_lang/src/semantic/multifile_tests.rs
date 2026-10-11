//! Shared-unit semantic regressions retaining independently resolved source arenas.
use super::*;
use crate::{
    parser::{parse_fragment_source_spanned, parse_source_spanned},
    resolved::{ExternalResolutionEnvironment, ResolvedProgram, resolve_with_external_environment},
    source::{FrontendBudget, SourceFile},
};

fn shared_program(root: &str, fragment: &str) -> ResolvedProgram {
    let root_file = SourceFile::new(SourceId(11), "root.ko", root);
    let fragment_file = SourceFile::new(SourceId(29), "shared.ko", fragment);
    let (root, _) = parse_source_spanned(&root_file, FrontendBudget::v1()).expect("root syntax");
    let (mut fragment, _) = parse_fragment_source_spanned(&fragment_file, FrontendBudget::v1())
        .expect("fragment syntax");
    fragment.program.unit = root.program.unit.clone();
    let mut environment = ExternalResolutionEnvironment::default();
    for item in root.program.items.iter().chain(&fragment.program.items) {
        match item {
            Item::Function(value) => {
                environment.functions.insert(value.name.clone());
            }
            Item::State(value) => {
                environment.states.insert(value.name.clone());
            }
            Item::Const(value) => {
                environment.consts.insert(value.name.clone());
            }
            Item::Struct(value) | Item::Event(value) => {
                environment.structs.insert(value.name.clone());
            }
            Item::Enum(value) => {
                environment.structs.insert(value.name.clone());
                environment.variant_codes.extend(
                    value
                        .variants
                        .iter()
                        .map(|variant| (format!("{}::{}", value.name, variant.name), variant.code)),
                );
            }
            Item::Trigger(_) => {}
        }
    }
    let order = (0..fragment.program.items.len())
        .map(|index| (fragment_file.id(), index))
        .chain((0..root.program.items.len()).map(|index| (root_file.id(), index)))
        .collect::<Vec<_>>();
    let root =
        resolve_with_external_environment(root, &root_file, &environment).expect("root resolution");
    let fragment = resolve_with_external_environment(fragment, &fragment_file, &environment)
        .expect("fragment resolution");
    root.with_included_sources(vec![fragment], &order)
}

#[test]
fn sibling_bindings_and_hir_nodes_keep_distinct_source_authority() {
    let program = shared_program(
        "seiyaku Shared { view fn answer(bool ready) authorize(anyone) -> int { if ready { twice(21) } else { 0 } } }",
        "fn twice(int _ value) -> int { value + value }",
    );
    let typed = SemanticContext::new()
        .analyze_resolved(&program)
        .expect("independent binding identities with different types");
    assert_eq!(program.program().items.len(), 2);
    assert_eq!(
        program
            .source_program(SourceId(11))
            .unwrap()
            .program()
            .items
            .len(),
        1
    );
    assert_eq!(
        program
            .source_program(SourceId(29))
            .unwrap()
            .program()
            .items
            .len(),
        1
    );
    assert_eq!(typed.source_files.len(), 2);
    assert!(typed.hir_nodes.keys().any(|id| id.source == SourceId(11)));
    assert!(typed.hir_nodes.keys().any(|id| id.source == SourceId(29)));
    let sources = typed
        .items
        .iter()
        .map(|item| {
            let TypedItem::Function(function) = item;
            (
                function.name.as_str(),
                function.source.expect("source-backed function").source,
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(sources["answer"], SourceId(11));
    assert_eq!(sources["twice"], SourceId(29));
}

#[test]
fn included_types_constants_and_error_messages_share_the_root_identity() {
    let program = shared_program(
        "seiyaku Shared { view fn size(Receipt receipt) authorize(anyone) -> int { receipt.amount + SIZE } fn failure() -> Fault { Fault::Denied } }",
        "const int SIZE = 7; struct Receipt { int amount; } error enum Fault { #[message(\"Permission required\")] Denied = 3; }",
    );
    let typed = SemanticContext::new()
        .analyze_resolved(&program)
        .expect("cross-file declarations");
    assert!(
        typed
            .error_types
            .iter()
            .any(|error| error.identity == "Shared::Fault")
    );
    assert_eq!(typed.error_messages.len(), 1);
}

#[test]
fn sibling_arena_cannot_authorize_forged_source_identity() {
    let program = shared_program(
        "seiyaku Shared { view fn answer() authorize(anyone) -> int { value() } }",
        "fn value() -> int { 42 }",
    );
    let context = SemanticContext::new();
    context.resolved_arenas.replace(
        program
            .arenas()
            .map(|arena| (arena.source(), arena))
            .collect(),
    );
    let unknown = SourceRange::new(SourceId(99), crate::source::TextRange::empty(0));
    let error = context
        .resolved_node(
            Some(HirId(0)),
            crate::resolved::ResolvedNodeKind::Expression,
            Some(unknown),
        )
        .expect_err("unknown arena cannot borrow another file's node id");
    assert_eq!(error.code, "E_INTERNAL_RESOLUTION");
}

#[test]
fn exported_constant_interfaces_prepare_qualified_list_capacities() {
    let file = SourceFile::new(
        SourceId(7),
        "consumer.ko",
        "module Consumer { fn length(List<int, math::SCALE> values) -> int { 0 } const string LABEL = \"bounded\"; const bool READY = true; }",
    );
    let (parsed, _) = parse_source_spanned(&file, FrontendBudget::v1()).expect("consumer syntax");
    let mut names = ExternalResolutionEnvironment::default();
    names.consts.insert("math::SCALE".into());
    let resolved =
        resolve_with_external_environment(parsed, &file, &names).expect("constant resolution");
    let mut environment = TestTargetEnvironment::default();
    environment.consts.insert(
        "math::SCALE".into(),
        TypedExpr {
            expr: ExprKind::IntLiteral(BigInt::from(4)),
            ty: Type::Int,
        },
    );
    let context = SemanticContext::new();
    let signatures = context
        .resolve_resolved_function_signatures_with_environment(&resolved, &environment)
        .expect("capacity supplied by module export");
    assert_eq!(
        signatures["length"].params[0].ty,
        Type::List(Box::new(Type::Int), 4)
    );
    let constants = context
        .declared_constants(&resolved)
        .expect("all explicit constant types");
    assert_eq!(constants.len(), 2);
    assert_eq!(constants["LABEL"].ty, Type::String);
    assert_eq!(constants["READY"].ty, Type::Bool);
    assert!(
        !constants.contains_key("math::SCALE"),
        "imports are not implicitly re-exported"
    );
}

#[test]
fn exported_constant_interfaces_keep_declaration_before_use() {
    let file = SourceFile::new(
        SourceId(17),
        "constants.ko",
        "module Constants { const string BEFORE = AFTER; const string AFTER = \"later\"; }",
    );
    let (parsed, _) = parse_source_spanned(&file, FrontendBudget::v1()).expect("constant syntax");
    let resolved = crate::resolved::resolve(parsed, &file).expect("declarations resolve");
    let context = SemanticContext::new();
    context
        .resolve_resolved_function_signatures(&resolved)
        .expect("no signature dependency");
    let error = context
        .declared_constants(&resolved)
        .expect_err("value use must follow declaration");
    assert_eq!(error.failures[0].error.code, "K2002");
}

#[test]
fn included_semantic_diagnostics_keep_native_ranges_and_source_text() {
    for fragment in ["fn value() -> int { true }", "fn value() -> int {}"] {
        let program = shared_program(
            "seiyaku Shared { view fn answer() authorize(anyone) -> int { value() } }",
            fragment,
        );
        let failures = SemanticContext::new()
            .analyze_resolved(&program)
            .expect_err("invalid fragment body");
        let diagnostics = crate::semantic_diagnostics::from_semantic_failures(
            failures,
            Some("root.ko"),
            Some(program.source_file()),
            Some(&program),
        );
        let primary = diagnostics.diagnostics[0]
            .primary_span
            .as_ref()
            .expect("native diagnostic");
        assert_eq!(primary.source.as_deref(), Some("shared.ko"));
        let rendered = diagnostics.render_human();
        assert!(rendered.contains(fragment), "{rendered}");
    }
}
