//! Nominal enum navigation and atomic rename use exact declaring identities.
use super::*;
use crate::linker::{SourceModuleUnit, SourcePackageUnit};

#[test]
fn local_enum_references_cover_values_and_patterns_without_merging_equal_codes() {
    let source = r#"module Errors {
        error enum Failure { Missing = 1 }
        error enum Other { Missing = 1 }
        fn fail() -> Failure { (Failure /* enum name */ :: Missing) }
        fn describe(Failure value) -> int { match value { Failure::Missing => 1 } }
        fn inspect(Failure value) -> int { if let Failure::Missing = value { 1 } else { 2 } }
        fn other() -> Other { Other::Missing }
        // Failure::Missing is documentation, not a reference.
    }"#;
    let snapshot = EditorSnapshot::single("errors.ko", source, false);
    assert!(snapshot.is_complete());
    let offset = source.find("Failure /*").unwrap() as u32;
    let definition = snapshot.definition(SourceId(0), offset).unwrap();
    assert_eq!(
        definition.source.range.start,
        source.find("Failure {").unwrap() as u32
    );
    let references = snapshot.references(SourceId(0), offset, true);
    assert_eq!(references.len(), 7);
    assert!(
        references.iter().all(
            |range| snapshot.source(range.source).unwrap().slice(range.range) == Some("Failure")
        )
    );
    let other = snapshot
        .definition(SourceId(0), source.find("Other::").unwrap() as u32)
        .unwrap();
    assert_ne!(
        definition.identity, other.identity,
        "enum-local code 1 does not merge nominal owners"
    );
    let variant = source.find(":: Missing").unwrap() as u32 + 3;
    assert!(
        snapshot.definition(SourceId(0), variant).is_none(),
        "the enum reference excludes the variant token"
    );
    let rename = snapshot
        .rename(SourceId(0), offset, "Problem")
        .expect("enum values and patterns rename together");
    assert_eq!(rename.sources, references);
    assert!(rename.exports.is_empty());
}

#[test]
fn imported_enum_references_rename_only_the_exact_locked_owner_and_enum_segment() {
    let request = SourceLinkRequest { artifacts: Vec::new(), sources: Vec::new(),
        root: SourceModuleUnit {
            source_name: "app.ko".into(),
            source: r#"seiyaku App {
                view fn run() authorize(anyone) -> errors::Failure { errors /* alias */ :: Failure :: Missing }
                view fn describe(errors::Failure value) authorize(anyone) -> int { match value { errors::Failure::Missing => 1 } }
                view fn other() authorize(anyone) -> alternate::Failure { alternate::Failure::Missing }
            }"#.into(),
        },
        imports: vec![
            ImportBinding { alias: "errors".into(), package: "local/errors@1".into() },
            ImportBinding { alias: "alternate".into(), package: "local/alternate@1".into() },
        ],
        packages: ["local/errors@1", "local/alternate@1"].into_iter().map(|identity| SourcePackageUnit { artifacts: Vec::new(), sources: Vec::new(),
            identity: identity.into(),
            modules: vec![SourceModuleUnit {
                source_name: "errors.ko".into(),
                source: "module Errors { export error enum Failure { Missing = 1 } fn fail() -> Failure { Failure::Missing } }".into(),
            }],
            exports: BTreeSet::from(["Failure".into()]),
            imports: vec![],
        }).collect(),
    };
    let snapshot = EditorSnapshot::project(&request, false);
    assert!(
        snapshot.is_complete(),
        "{:#?}",
        ModuleBuildGraph::default().link(request.clone(), LinkerOptions::default())
    );
    let root = snapshot
        .sources()
        .find(|file| file.name() == "app.ko")
        .unwrap();
    let offset = root.text().find("Failure :: Missing").unwrap() as u32;
    let definition = snapshot.definition(root.id(), offset).unwrap();
    assert_eq!(
        snapshot
            .source(definition.source.source)
            .unwrap()
            .package_identity(),
        Some("local/errors@1")
    );
    let alternate = snapshot
        .definition(
            root.id(),
            root.text().find("alternate::Failure::").unwrap() as u32 + "alternate::".len() as u32,
        )
        .unwrap();
    assert_ne!(definition.identity, alternate.identity);
    let references = snapshot.references(root.id(), offset, true);
    assert_eq!(references.len(), 7);
    for range in &references {
        let file = snapshot.source(range.source).unwrap();
        assert_eq!(file.slice(range.range), Some("Failure"));
        assert_ne!(file.package_identity(), Some("local/alternate@1"));
    }
    let rename = snapshot
        .rename(root.id(), offset, "Problem")
        .expect("locked enum source and export rename");
    assert_eq!(rename.sources, references);
    assert_eq!(
        rename.exports,
        vec![EditorExportRename {
            package: "local/errors@1".into(),
            old_name: "Failure".into(),
            new_name: "Problem".into(),
        }]
    );
    assert!(
        snapshot
            .definition(root.id(), offset + "Failure :: ".len() as u32)
            .is_none()
    );
}
