//! Native event declaration, payload, effect and resource invariants.
use super::*;
use crate::parser::parse;

fn checked(source: &str) -> TypedProgram {
    analyze(&parse(source).expect("parse event source")).expect("type checked event source")
}

#[test]
fn native_events_share_record_types_and_evaluate_fields_in_source_order() {
    let typed = checked(
        r#"seiyaku Events {
        enum Status { Active = 1, Paused = 2 }
        struct Details { Status status; List<int, 4> history; }
        event Transfer { int first; int second; Option<Details> details; }
        event Empty {}
        fn first() -> int { 1 }
        fn second() -> int { 2 }
        fn notify() { emit Transfer { second: second(), first: first(), details: Option::some(Details { status: Status::Active, history: [1, 2] }) }; }
        kotoage fn run() authorize(anyone) { notify(); }
        hajimari() { emit Empty {}; }
        kaizen() { emit Empty {}; }
    }"#,
    );
    assert_eq!(
        typed
            .events
            .iter()
            .map(|event| event.name.as_ref())
            .collect::<Vec<_>>(),
        ["Empty", "Transfer"]
    );
    assert!(typed.events.iter().all(|event| event.validate()));
    assert_eq!(typed.events[0].payload_type.word_count(), Some(1));
    assert!(typed.events[1].payload_type.nodes.iter().any(|node| matches!(node, iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Enum(descriptor) if descriptor.identity == "Events::Status")));
    let notify = typed
        .items
        .iter()
        .find_map(|item| {
            let TypedItem::Function(function) = item;
            (function.name == "notify").then_some(function)
        })
        .unwrap();
    let TypedStatement::Expr(emission) = &notify.body.statements[0] else {
        panic!("typed event emission")
    };
    let ExprKind::Call {
        target: CallTarget::Intrinsic(CompilerIntrinsic::EmitEvent),
        args,
    } = emission.kind()
    else {
        panic!("event intrinsic")
    };
    let ExprKind::StructLiteral { fields, .. } = args[1].kind() else {
        panic!("typed event record")
    };
    assert_eq!(
        fields
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["second", "first", "details"]
    );
    assert_eq!(typed.clone(), typed);
}

#[test]
fn native_event_boundaries_reject_values_invalid_fields_and_view_effects() {
    for (source, code) in [
        (
            "seiyaku Demo { event Note { int value; } fn bad() { let x = Note { value: 1 }; } }",
            "E_EVENT_VALUE",
        ),
        (
            "seiyaku Demo { event Note { int value; } fn bad(Note note) {} }",
            "E_EVENT_VALUE",
        ),
        (
            "seiyaku Demo { event Note { int value; } fn bad() { emit Note {}; } }",
            "E_MISSING_STRUCT_FIELD",
        ),
        (
            "seiyaku Demo { event Note { int value; } fn bad() { emit Note { other: 1 }; } }",
            "E_UNKNOWN_STRUCT_FIELD",
        ),
        (
            "seiyaku Demo { event Note { int value; } fn bad() { emit Note { value: true }; } }",
            "E_TYPE_ANNOTATION_MISMATCH",
        ),
        (
            "seiyaku Demo { struct Note { int value; } fn bad() { emit Note { value: 1 }; } }",
            "E_UNKNOWN_EVENT",
        ),
        (
            "seiyaku Demo { event Note { Json data; } }",
            "E_EVENT_SCHEMA",
        ),
        (
            "seiyaku Demo { struct Nested { StateCursor<int> cursor; } event Note { Option<Nested> data; } }",
            "E_EVENT_SCHEMA",
        ),
        (
            "seiyaku Demo { event Note {} fn helper() { emit Note {}; } view fn bad() authorize(anyone) { helper(); } }",
            "K2004",
        ),
    ] {
        let ast = parse(source).unwrap_or_else(|error| panic!("{source}: {error:?}"));
        let error = analyze(&ast).expect_err(source);
        assert_eq!(error.code, code, "{source}: {error:?}");
    }
}

#[test]
fn native_event_tables_enforce_count_and_aggregate_byte_bounds() {
    let empty = (0..257)
        .map(|index| format!("event E{index:03} {{}} "))
        .collect::<String>();
    let source = format!("seiyaku Events {{ {empty} }}");
    assert_eq!(
        analyze(&parse(&source).unwrap()).unwrap_err().code,
        "E_EVENT_SCHEMA"
    );
    let field = "f".repeat(80);
    let fields = (0..100)
        .map(|index| format!("int {field}{index}; "))
        .collect::<String>();
    let declarations = (0..12)
        .map(|index| format!("event E{index:03} {{ {fields} }} "))
        .collect::<String>();
    let source = format!("seiyaku Events {{ {declarations} }}");
    assert_eq!(
        analyze(&parse(&source).unwrap()).unwrap_err().code,
        "E_EVENT_SCHEMA"
    );
    checked("seiyaku Events { event Empty {} event Note { int value; } }");
}

#[test]
fn semantic_context_does_not_retain_event_or_enum_declarations() {
    let context = SemanticContext::new();
    context
        .analyze(
            &parse("seiyaku First { enum Status { Active = 1 } event Note { Status status; } }")
                .unwrap(),
        )
        .unwrap();
    let second = context
        .analyze(
            &parse("seiyaku Second { view fn read() authorize(anyone) -> int { 1 } }").unwrap(),
        )
        .unwrap();
    assert!(second.events.is_empty());
    assert!(second.enum_types.is_empty());
}
