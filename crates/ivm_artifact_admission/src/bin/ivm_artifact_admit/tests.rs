//! Admission-tool argument, exact-manifest, and protected-publication regressions.

use super::*;

fn fixture() -> (tempfile::TempDir, Inputs, Vec<u8>) {
    let directory = tempfile::tempdir().expect("private fixture directory");
    let inputs = Inputs {
        code_file: directory.path().join("contract.to"),
        out: directory.path().join("manifest.json"),
    };
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            "seiyaku Admission { view fn inspect() authorize(anyone) -> int { return 7; } }",
        )
        .expect("compile current V1 artifact");
    std::fs::write(&inputs.code_file, &artifact).expect("write source fixture");
    (directory, inputs, artifact)
}

#[test]
fn arguments_require_one_input_and_one_output_without_retired_options() {
    let parsed =
        parse_args(["--code-file", "contract.to", "--out", "manifest.json"].map(Into::into))
            .expect("valid arguments");
    assert_eq!(
        parsed,
        Some(Inputs {
            code_file: "contract.to".into(),
            out: "manifest.json".into(),
        })
    );
    assert_eq!(parse_args(["--help".into()]), Ok(None));
    for args in [
        vec![],
        vec!["--code-file"],
        vec!["--code-file", "", "--out", "manifest.json"],
        vec!["--code-file", "--out", "manifest.json"],
        vec!["--code-file", "a", "--code-file", "b", "--out", "c"],
        vec!["--code-file", "a", "--out", "b", "--out", "c"],
        vec!["--help", "--out", "a"],
        vec!["--code-file", "a", "--out", "b", "--help"],
        vec!["--machine", "contract", "manifest", "build"],
        vec!["--code-file", "a", "--out", "b", "--sign-with", "key"],
    ] {
        assert!(parse_args(args.into_iter().map(Into::into)).is_err());
    }
}

#[test]
fn admitted_output_is_the_exact_canonical_norito_manifest() {
    let (_directory, inputs, artifact) = fixture();
    admit(&inputs).expect("native admission");
    let expected = norito::json::to_json_pretty(
        &verify_contract_artifact(&artifact)
            .expect("canonical admission")
            .manifest,
    )
    .expect("canonical Norito JSON");
    assert_eq!(std::fs::read(&inputs.out).unwrap(), expected.as_bytes());
    assert_eq!(std::fs::read(&inputs.code_file).unwrap(), artifact);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&inputs.out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn malformed_and_oversized_artifacts_never_publish_a_manifest() {
    let (_directory, inputs, _) = fixture();
    for artifact in [b"".as_slice(), b"IVM\0retired or malformed"] {
        std::fs::write(&inputs.code_file, artifact).unwrap();
        assert!(admit(&inputs).unwrap_err().contains("admission failed"));
        assert!(!inputs.out.exists());
    }
    let file = std::fs::File::create(&inputs.code_file).unwrap();
    file.set_len(MAX_CONTRACT_IMAGE_BYTES + ivm_abi::metadata::HEADER_SIZE as u64 + 1)
        .unwrap();
    assert!(
        admit(&inputs)
            .unwrap_err()
            .contains("cannot retain contract input")
    );
    assert!(!inputs.out.exists());
}

#[test]
fn full_artifact_bound_includes_the_fixed_header() {
    let (_directory, inputs, mut artifact) = fixture();
    let maximum = ivm_abi::metadata::HEADER_SIZE + ivm_abi::metadata::MAX_PROGRAM_IMAGE_BYTES_V1;
    let halt = (u32::from(ivm_abi::instruction::wide::control::HALT) << 24).to_le_bytes();
    // Extend the unused executable tail with admitted instructions, keeping all
    // compiler-owned interface and entrypoint bindings intact and word-aligned.
    while artifact.len() + halt.len() <= maximum {
        artifact.extend_from_slice(&halt);
    }
    assert!(artifact.len() > MAX_CONTRACT_IMAGE_BYTES as usize);
    assert!(maximum - artifact.len() < halt.len());
    let expected = norito::json::to_json_pretty(
        &verify_contract_artifact(&artifact)
            .expect("near-cap artifact satisfies canonical admission")
            .manifest,
    )
    .unwrap();
    std::fs::write(&inputs.code_file, artifact).unwrap();
    admit(&inputs).expect("tool admits the same near-cap complete artifact");
    assert_eq!(std::fs::read(&inputs.out).unwrap(), expected.as_bytes());
}

#[test]
fn publication_is_create_only_and_never_replaces_the_input() {
    let (_directory, inputs, artifact) = fixture();
    std::fs::write(&inputs.out, b"retained output").unwrap();
    assert!(
        admit(&inputs)
            .unwrap_err()
            .contains("cannot create manifest")
    );
    assert_eq!(std::fs::read(&inputs.out).unwrap(), b"retained output");
    let same_path = Inputs {
        code_file: inputs.code_file.clone(),
        out: inputs.code_file.clone(),
    };
    assert!(admit(&same_path).is_err());
    assert_eq!(std::fs::read(&inputs.code_file).unwrap(), artifact);
}

#[cfg(unix)]
#[test]
fn links_and_unsafe_output_parents_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let (directory, inputs, _) = fixture();
    let linked = directory.path().join("linked.to");
    symlink(&inputs.code_file, &linked).unwrap();
    assert!(
        admit(&Inputs {
            code_file: linked.clone(),
            out: inputs.out.clone()
        })
        .is_err()
    );
    std::fs::remove_file(&linked).unwrap();
    std::fs::hard_link(&inputs.code_file, &linked).unwrap();
    assert!(admit(&inputs).is_err());
    std::fs::remove_file(&linked).unwrap();
    symlink(&inputs.code_file, &inputs.out).unwrap();
    assert!(admit(&inputs).is_err());
    std::fs::remove_file(&inputs.out).unwrap();
    let unsafe_parent = directory.path().join("unsafe");
    std::fs::create_dir(&unsafe_parent).unwrap();
    std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        admit(&Inputs {
            code_file: inputs.code_file,
            out: unsafe_parent.join("manifest.json")
        })
        .is_err()
    );
    assert!(!unsafe_parent.join("manifest.json").exists());
}
