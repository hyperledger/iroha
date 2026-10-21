//! Typed UID quote regressions; register with the coherent native quote surface.
use super::*;

const QUOTE_ARGUMENTS: &str =
    "asset_definition: asset_definition, account: account, incoming: incoming";
const QUOTE_SOURCE: &str = r#"seiyaku HoldingPolicy {
    view fn quote(
        AssetDefinitionId asset_definition, AccountId account, quantity incoming
    ) authorize(anyone) -> AssetUidHoldingQuote {
        ledger::asset::uid_holding_quote(asset_definition: asset_definition, account: account, incoming: incoming)
    }
}"#;

fn quote_field_source(field: &str, value_type: &str) -> String {
    QUOTE_SOURCE
        .replace("-> AssetUidHoldingQuote", &format!("-> {value_type}"))
        .replace(
            &format!("ledger::asset::uid_holding_quote({QUOTE_ARGUMENTS})"),
            &format!("let quote = ledger::asset::uid_holding_quote({QUOTE_ARGUMENTS});\n        quote.{field}"),
        )
}

#[test]
fn typed_uid_quote_compiles_as_one_native_read() {
    for source in [
        QUOTE_SOURCE.to_owned(),
        QUOTE_SOURCE.replace("view fn", "kotoage fn"),
    ] {
        let bytes = test_mode_compiler()
            .compile_source(&source)
            .expect("typed native quote compiles in views and transactions");
        let parsed = ProgramMetadata::parse(&bytes).unwrap();
        let quote_calls = bytes[parsed.code_offset..]
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .filter(|word| {
                instruction::wide::opcode(*word) == instruction::wide::system::SYSTEM
                    && encoding::wide::decode_syscallx(*word)
                        == syscalls::SYSCALL_ASSET_UID_HOLDING_QUOTE
            })
            .count();
        assert_eq!(quote_calls, 1);
    }
}

#[test]
fn uid_quote_is_pure_for_views_but_has_native_ledger_read_access() {
    use kotodama_surface::builtins::{Builtin, BuiltinEffects};
    let spec = Builtin::AssetUidHoldingQuote.spec();
    assert_eq!(spec.effects, BuiltinEffects::NONE);
    assert_eq!(spec.access, BuiltinAccess::LedgerRead);
    assert_eq!(
        classify_ir_access(&ir::Instr::DirectHelperSyscall {
            dest: ir::Temp(3),
            syscall: syscalls::SYSCALL_ASSET_UID_HOLDING_QUOTE,
            args: vec![ir::Temp(0), ir::Temp(1), ir::Temp(2)],
        }),
        IrAccessClass::Ledger(BuiltinAccess::LedgerRead),
    );
    assert!(
        kotodama_surface::source_policy::V1_SOURCE_TYPE_NAMES.contains(&"AssetUidHoldingQuote")
    );
    assert!(
        kotodama_surface::source_policy::is_reserved_source_type_declaration(
            "AssetUidHoldingQuote"
        )
    );
}

#[test]
fn uid_quote_manifest_has_exact_nominal_six_field_product() {
    use ivm_abi::entrypoint::{
        EntrypointStructTypeNodeV1 as Struct, EntrypointValueKindV1 as Kind,
        EntrypointValueTypeNodeV1 as Node,
    };
    let output = test_mode_compiler()
        .compile_source_output(QUOTE_SOURCE, None)
        .unwrap();
    let entry = output.manifest.entrypoints.unwrap().remove(0);
    assert_eq!(entry.return_type.as_deref(), Some("AssetUidHoldingQuote"));
    let schema = entry.return_schema.unwrap();
    assert_eq!(
        schema.nodes,
        vec![
            Node::Struct(Struct {
                name: "kotodama::AssetUidHoldingQuote".into(),
                fields: [
                    "asset_definition_id",
                    "account_id",
                    "policy_revision",
                    "beneficial_holdings",
                    "holding_limit",
                    "required_overflow"
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            }),
            Node::Leaf(Kind::AssetDefinitionId),
            Node::Leaf(Kind::AccountId),
            Node::Leaf(Kind::Int),
            Node::Leaf(Kind::Quantity),
            Node::Option,
            Node::Leaf(Kind::Quantity),
            Node::Leaf(Kind::Quantity),
        ]
    );
    assert_eq!(schema.word_count(), Some(6));
    assert!(schema.validate());
}

#[test]
fn uid_quote_fields_keep_exact_value_types() {
    for (field, value_type) in [
        ("asset_definition_id", "AssetDefinitionId"),
        ("account_id", "AccountId"),
        ("policy_revision", "int"),
        ("beneficial_holdings", "quantity"),
        ("holding_limit", "Option<quantity>"),
        ("required_overflow", "quantity"),
    ] {
        test_mode_compiler()
            .compile_source(&quote_field_source(field, value_type))
            .unwrap_or_else(|error| panic!("typed quote field {field}: {error:?}"));
    }
}

#[test]
fn uid_quote_rejects_wrong_identity_and_amount_types() {
    for arguments in [
        "asset_definition: account, account: account, incoming: incoming",
        "asset_definition: asset_definition, account: asset_definition, incoming: incoming",
        "asset_definition: asset_definition, account: account, incoming: true",
    ] {
        let source = QUOTE_SOURCE.replace(QUOTE_ARGUMENTS, arguments);
        let parsed = parse(&source).expect("well-formed negative source");
        let error = analyze(&parsed).expect_err("invalid quote type must fail");
        assert_eq!(error.code, "K2003", "{arguments}: {error:?}");
        assert_eq!(
            error.message,
            "ledger::asset::uid_holding_quote expects (AssetDefinitionId, AccountId, quantity)"
        );
    }
}

#[test]
fn uid_quote_rejects_missing_incoming_by_exact_label() {
    let source = QUOTE_SOURCE.replace(
        QUOTE_ARGUMENTS,
        "asset_definition: asset_definition, account: account",
    );
    let parsed = parse(&source).expect("well-formed missing-argument source");
    let error = analyze(&parsed).expect_err("incoming is required");
    assert_eq!(error.code, "E_MISSING_NAMED_ARGUMENT");
    assert_eq!(
        error.message,
        "call `ledger::asset::uid_holding_quote` is missing required argument `incoming`"
    );
}

#[test]
fn uid_quote_does_not_expose_identity_roster_or_transfer_authority() {
    for field in ["uid", "accounts", "controller", "fi_account"] {
        let parsed =
            parse(&quote_field_source(field, "bytes")).expect("well-formed negative source");
        let error = analyze(&parsed).expect_err("private or authority field is absent");
        assert_eq!(error.code, "K2002", "{field}: {error:?}");
        assert_eq!(
            error.message,
            format!(
                "unknown field '{field}' on struct kotodama::AssetUidHoldingQuote (available: asset_definition_id, account_id, policy_revision, beneficial_holdings, holding_limit, required_overflow)"
            )
        );
    }
}

#[test]
fn uid_quote_source_type_rendering_roundtrips_exact_nominal_type() {
    let program = analyze(&parse(QUOTE_SOURCE).unwrap()).unwrap();
    let quote = program
        .items
        .iter()
        .find_map(|item| match item {
            semantic::TypedItem::Function(function) if function.name == "quote" => {
                function.ret_ty.as_ref()
            }
            _ => None,
        })
        .expect("typed quote return");
    assert_eq!(semantic::type_name(quote), "AssetUidHoldingQuote");
    assert_eq!(semantic::render_type_name(quote), "AssetUidHoldingQuote");
    let optional = semantic::Type::Option(Box::new(quote.clone()));
    assert_eq!(
        semantic::render_type_name(&optional),
        "Option<AssetUidHoldingQuote>"
    );
    let mut forged = quote.clone();
    let semantic::Type::Struct { fields, .. } = &mut forged else {
        panic!("quote product")
    };
    std::sync::Arc::make_mut(fields)[0].1 = semantic::Type::Bool;
    assert_ne!(semantic::type_name(&forged), "AssetUidHoldingQuote");
    assert_ne!(semantic::render_type_name(&forged), "AssetUidHoldingQuote");
}
