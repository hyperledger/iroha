//! Repository-wide ownership and freshness guard for checked-in IVM artifacts.
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};
const INVENTORY: &str = include_str!("../../../scripts/ivm_artifacts.tsv");
#[derive(Debug)]
struct Artifact<'a> {
    owner: &'a str,
    source_or_tag: &'a str,
    path: &'a str,
}
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("IVM crate belongs to the workspace")
        .to_path_buf()
}
fn safe_relative_path(raw: &str, extension: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    assert!(
        !path.is_absolute()
            && path.extension().is_some_and(|value| value == extension)
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "invalid repository artifact path {raw:?}"
    );
    path
}
fn inventory() -> Vec<Artifact<'static>> {
    let mut artifacts = Vec::new();
    let mut paths = BTreeSet::new();
    for (index, line) in INVENTORY.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(
            fields.len(),
            3,
            "invalid IVM artifact inventory row {}",
            index + 1
        );
        assert!(
            matches!(
                fields[0],
                "kotodama-standard" | "kotodama-zk" | "predecoder" | "default"
            ),
            "unknown artifact owner {:?} on row {}",
            fields[0],
            index + 1
        );
        let path = safe_relative_path(fields[2], "to");
        assert!(
            paths.insert(path),
            "duplicate artifact inventory path on row {}",
            index + 1
        );
        artifacts.push(Artifact {
            owner: fields[0],
            source_or_tag: fields[1],
            path: fields[2],
        });
    }
    assert!(!artifacts.is_empty(), "the IVM artifact inventory is empty");
    artifacts
}
fn tracked_ivm_artifacts(root: &Path) -> BTreeSet<PathBuf> {
    let output = Command::new("git")
        .args(["-C", root.to_str().expect("UTF-8 repository root")])
        .args(["ls-files", "-z", "--", "*.to"])
        .output()
        .expect("run git artifact inventory");
    assert!(
        output.status.success(),
        "git artifact inventory failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .filter_map(|raw| {
            let relative = PathBuf::from(std::str::from_utf8(raw).expect("tracked path is UTF-8"));
            let bytes = fs::read(root.join(&relative)).expect("tracked artifact remains readable");
            bytes.starts_with(ivm::METADATA_MAGIC).then_some(relative)
        })
        .collect()
}
#[test]
fn every_checked_in_ivm_artifact_is_owned_authenticated_and_fresh() {
    let root = repository_root();
    let inventory = inventory();
    let declared: BTreeSet<_> = inventory
        .iter()
        .map(|artifact| safe_relative_path(artifact.path, "to"))
        .collect();
    assert_eq!(
        tracked_ivm_artifacts(&root),
        declared,
        "tracked IVM artifacts and scripts/ivm_artifacts.tsv must match exactly"
    );
    assert!(
        inventory
            .iter()
            .any(|artifact| matches!(artifact.owner, "kotodama-standard" | "kotodama-zk")),
        "the inventory must include deployable contracts"
    );
    // The reviewed map owns contract membership. Generator-owned raw fixtures
    // have exact path sets; historical row counts cannot establish ownership.
    let predecoder = ivm::predecoder_fixtures::generated_predecoder_mixed_artifacts();
    let predecoder_root = Path::new("crates/ivm/tests/fixtures/predecoder/mixed/artifacts");
    assert_eq!(
        inventory
            .iter()
            .filter(|artifact| artifact.owner == "predecoder")
            .map(|artifact| safe_relative_path(artifact.path, "to"))
            .collect::<BTreeSet<_>>(),
        predecoder
            .iter()
            .map(|(name, _)| predecoder_root.join(name))
            .collect(),
        "predecoder fixture ownership must match its canonical generator"
    );
    assert_eq!(
        inventory
            .iter()
            .filter(|artifact| artifact.owner == "default")
            .map(|artifact| safe_relative_path(artifact.path, "to"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([PathBuf::from("defaults/executor.to")]),
        "the default executor must retain its exact owner"
    );
    let expected_abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    let compiler = kotodama_lang::compiler::Compiler::new();
    let zk_compiler = kotodama_lang::compiler::Compiler::new_with_options(
        kotodama_lang::compiler::CompilerOptions {
            force_zk: true,
            ..kotodama_lang::compiler::CompilerOptions::default()
        },
    );
    for artifact in inventory {
        let relative = safe_relative_path(artifact.path, "to");
        let path = root.join(&relative);
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("read owned artifact {}: {error}", path.display()));
        let parsed = ivm::ProgramMetadata::parse(&bytes)
            .unwrap_or_else(|error| panic!("{} has invalid metadata: {error}", path.display()));
        assert_eq!(
            parsed.header_len,
            ivm::HEADER_SIZE,
            "{} header",
            path.display()
        );
        assert_eq!(parsed.metadata.abi_version, 1, "{} ABI", path.display());
        assert_eq!(
            bytes.get(17..ivm::HEADER_SIZE),
            Some(expected_abi_hash.as_slice()),
            "{} does not authenticate the canonical ABI descriptor",
            path.display()
        );
        ivm::IVM::new(parsed.metadata.max_cycles.max(1))
            .load_program(&bytes)
            .unwrap_or_else(|error| panic!("{} does not load: {error}", path.display()));
        match artifact.owner {
            "kotodama-standard" | "kotodama-zk" => {
                assert_eq!(
                    (parsed.metadata.version_major, parsed.metadata.version_minor),
                    (1, 1),
                    "{} must use the deployable contract version",
                    path.display()
                );
                assert!(
                    parsed.contract_interface.is_some(),
                    "{} must embed its CNTR interface",
                    path.display()
                );
                ivm::verify_contract_artifact(&bytes).unwrap_or_else(|error| {
                    panic!(
                        "{} does not pass contract admission: {error}",
                        path.display()
                    )
                });
            }
            "predecoder" => {
                assert_eq!(
                    (parsed.metadata.version_major, parsed.metadata.version_minor),
                    (1, 1),
                    "{} must exercise the V1 predecoder header",
                    path.display()
                );
                assert!(
                    parsed.contract_interface.is_none() && parsed.literal_section.is_none(),
                    "{} must remain a raw non-contract predecoder fixture",
                    path.display()
                );
                ivm::IvmCache::decode_artifact(&bytes).unwrap_or_else(|error| {
                    panic!(
                        "{} does not pass predecoder admission: {error}",
                        path.display()
                    )
                });
                assert!(
                    ivm::verify_contract_artifact(&bytes).is_err(),
                    "{} must not enter deployable contract admission",
                    path.display()
                );
            }
            "default" => {
                assert_eq!(
                    (parsed.metadata.version_major, parsed.metadata.version_minor),
                    (1, 1),
                    "{} is a generic executor, not a deployable contract",
                    path.display()
                );
                assert!(
                    parsed.contract_interface.is_none() && parsed.literal_section.is_some(),
                    "{} must remain a generic executor with authenticated literals",
                    path.display()
                );
                assert!(
                    ivm::verify_contract_artifact(&bytes).is_err(),
                    "{} must not enter deployable contract admission",
                    path.display()
                );
            }
            _ => unreachable!("inventory parser rejects unknown owners"),
        }
        let rebuilt = match artifact.owner {
            "kotodama-standard" | "kotodama-zk" => {
                let source = safe_relative_path(artifact.source_or_tag, "ko");
                let source_path = root.join(&source);
                let source_text = fs::read_to_string(&source_path).unwrap_or_else(|error| {
                    panic!("read owned source {}: {error}", source_path.display())
                });
                let expected_zk = artifact.owner == "kotodama-zk";
                assert_eq!(
                    parsed.metadata.mode & 1 != 0,
                    expected_zk,
                    "{} has the wrong declared execution mode",
                    path.display()
                );
                let compiler = if expected_zk { &zk_compiler } else { &compiler };
                compiler
                    .compile_source(&source_text)
                    .unwrap_or_else(|error| {
                        panic!(
                            "compile {} for artifact parity: {error}",
                            source_path.display()
                        )
                    })
            }
            "predecoder" => {
                let tag: usize = artifact
                    .source_or_tag
                    .parse()
                    .expect("predecoder tag is usize");
                let (name, generated) = predecoder.get(tag).expect("known predecoder tag");
                assert_eq!(
                    relative.file_name().and_then(|value| value.to_str()),
                    Some(name.as_str()),
                    "predecoder inventory tag names the wrong file"
                );
                generated.clone()
            }
            "default" => {
                assert_eq!(artifact.source_or_tag, "v1");
                ivm::prebuilt_fixtures::build_default_executor_program()
            }
            _ => unreachable!("inventory parser rejects unknown owners"),
        };
        assert_eq!(
            bytes,
            rebuilt,
            "{} is stale relative to owner {} ({})",
            path.display(),
            artifact.owner,
            artifact.source_or_tag
        );
    }
}
