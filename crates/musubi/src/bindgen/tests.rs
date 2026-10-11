//! Admission, nominal identity, language coverage and source-generation checks.
use super::*;

const SOURCE: &str = r#"
誓約 BindingSample {
    enum Status { Ready = 1, Complete = 2 }
    error enum Failure { Invalid = 7 }
    struct Payload {
        int amount;
        decimal price;
        quantity total;
        bool enabled;
        string note;
        bytes data;
        Json metadata;
        DataSpaceId space;
        Option<Option<int>> optional;
        Result<int, Failure> outcome;
        List<int, 4> items;
        Status status;
        (int, bool) pair;
        StateCursor<(AccountId, int)> cursor;
    }
    始まり() {}
    改善() {}
    view fn inspect(Payload input) authorize(anyone) -> Payload { input }
    言挙げ fn update(Payload input) authorize(anyone) -> Payload { input }
}
"#;

#[test]
fn admitted_artifact_generates_deterministic_kind_specific_bindings() {
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(SOURCE)
        .expect("binding source compiles");
    for (language, extension) in [
        (Language::Typescript, "ts"),
        (Language::Swift, "swift"),
        (Language::Kotlin, "kt"),
    ] {
        let text = generate(&artifact, language, "sample").expect("admitted generator");
        assert_eq!(text, generate(&artifact, language, "sample").unwrap());
        for kind in [
            "ViewRequest",
            "KotoageRequest",
            "HajimariRequest",
            "KaizenRequest",
        ] {
            assert!(text.contains(kind), "{kind}");
        }
        assert!(text.contains("BindingSample::Payload"));
        assert!(text.contains("BindingSample::Status"));
        assert!(text.contains("Complete"));
        assert!(text.contains("update"));
        assert!(text.contains("KotodamaInt"));
        assert!(text.contains("KotodamaDecimal"));
        assert!(text.contains("KotodamaQuantity"));
        assert!(!text.contains("as unknown as"));
        if matches!(language, Language::Kotlin) {
            assert!(
                text.contains("private fun encode6(value: String): Any? { return string(value) }")
            );
        }
        // Explicit local qualification aid: tests remain independent of SDK tool installations.
        if let Some(directory) = std::env::var_os("MUSUBI_BINDGEN_CAPTURE_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(format!("Sample.{extension}")), text).unwrap();
        }
    }
}

#[test]
fn generator_rejects_non_artifact_input_before_emitting_source() {
    for input in [
        b"".as_slice(),
        b"{\"entrypoints\":[]}".as_slice(),
        b"seiyaku Sample {}".as_slice(),
    ] {
        for language in [Language::Typescript, Language::Swift, Language::Kotlin] {
            assert!(generate(input, language, "sample").is_err());
        }
    }
}

#[test]
fn identifiers_are_injective_across_escapes_keywords_and_unicode() {
    let names = [
        "class", "1st", "更新", "k更新", "_u66f4_", "a-b", "a_b", "A::Type", "A_Type", "é",
        "e\u{301}",
    ];
    let encoded = names
        .iter()
        .map(|name| identifier(name))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(encoded.len(), names.len());
    for name in encoded {
        assert!(name.starts_with('k'));
        assert!(
            name.bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
        );
    }
}

#[test]
fn equal_shapes_from_distinct_nominal_owners_remain_distinct() {
    use iroha_data_model::smart_contract::entrypoint::EntrypointStructTypeNodeV1;
    let schema = |owner: &str| EntrypointValueTypeV1 {
        nodes: vec![
            EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                name: format!("{owner}::Payload"),
                fields: vec!["value".into()],
            }),
            EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
        ],
    };
    let mut model = Model {
        namespace: "Bindings".into(),
        code_hash: String::new(),
        types: Vec::new(),
        entries: Vec::new(),
    };
    let mut interned = BTreeMap::new();
    let left = model.intern(&schema("pkg/left@1.0.0::Left"), &mut interned);
    let right = model.intern(&schema("pkg/right@1.0.0::Right"), &mut interned);
    assert_ne!(left, right);
    assert_ne!(model.ty(left), model.ty(right));
    assert_eq!(
        model.intern(&schema("pkg/left@1.0.0::Left"), &mut interned),
        left
    );
    assert_eq!(
        model.types.len(),
        3,
        "only the identical primitive leaf is shared"
    );
}
