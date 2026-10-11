//! Bounded artifact input and atomic output adapter for SDK binding generation.
use super::*;
use crate::bindgen::{self, Language};

#[derive(Args, Debug)]
pub(super) struct BindgenArgs {
    /// Complete compiler-produced .to artifact; loose manifests are not accepted.
    #[arg(value_name = "ARTIFACT.to")]
    artifact: PathBuf,
    /// SDK source language.
    #[arg(long, value_enum)]
    language: Language,
    /// Output source file in an existing directory.
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// Source namespace seed (defaults to the artifact filename stem).
    #[arg(long)]
    name: Option<String>,
}

pub(super) fn run_bindgen(manifest_path: Option<&Path>, args: &BindgenArgs) -> CommandResult {
    if manifest_path.is_some() {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "bindgen takes one complete artifact and does not select a project manifest",
        ));
    }
    let bytes = read_bounded_single_link_regular_file_v1(
        &args.artifact,
        iroha_contract_deploy::MAX_DEPLOYMENT_ARTIFACT_BYTES as u64,
    )
    .map_err(|error| io_diagnostic("read bounded contract artifact", &args.artifact, &error))?;
    let name = args
        .name
        .as_deref()
        .or_else(|| args.artifact.file_stem().and_then(|name| name.to_str()))
        .unwrap_or("Contract");
    let generated = bindgen::generate(&bytes, args.language, name).map_err(|error| {
        Diagnostic::new(ErrorCode::Compiler, error)
            .with_context("artifact", args.artifact.display().to_string())
    })?;
    let parent = args
        .out
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let filename = args
        .out
        .file_name()
        .ok_or_else(|| Diagnostic::new(ErrorCode::Usage, "--out must name a source file"))?;
    let root = fs::canonicalize(parent)
        .map_err(|error| io_diagnostic("resolve output directory", parent, &error))?;
    let source = fs::canonicalize(&args.artifact)
        .map_err(|error| io_diagnostic("resolve input artifact", &args.artifact, &error))?;
    if root.join(filename) == source {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "binding output must not replace the input artifact",
        ));
    }
    AtomicWriteRoot::new(&root)
        .map_err(atomic_diagnostic)?
        .replace(Path::new(filename), generated.as_bytes())
        .map_err(atomic_diagnostic)?;
    let output = args.out.display().to_string();
    let length = generated.len();
    Ok(Success {
        message: format!(
            "Generated {:?} bindings at {}\n",
            args.language,
            args.out.display()
        ),
        data: norito::json!({"output": output, "bytes": length}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindgen_requires_an_artifact_language_and_output() {
        for args in [
            vec!["musubi", "bindgen"],
            vec![
                "musubi",
                "bindgen",
                "contract.to",
                "--language",
                "typescript",
            ],
            vec!["musubi", "bindgen", "contract.to", "--out", "contract.ts"],
            vec![
                "musubi",
                "bindgen",
                "contract.to",
                "--language",
                "java",
                "--out",
                "Contract.java",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "musubi",
                "bindgen",
                "contract.to",
                "--language",
                "kotlin",
                "--out",
                "Contract.kt"
            ])
            .is_ok()
        );
    }

    #[test]
    fn bindgen_installs_admitted_output_and_cannot_replace_its_input() {
        let directory = tempfile::tempdir().unwrap();
        let artifact = directory.path().join("contract.to");
        let bytes = kotodama_lang::compiler::Compiler::new()
            .compile_source("seiyaku C { view fn read() authorize(anyone) -> int { 1 } }")
            .unwrap();
        fs::write(&artifact, &bytes).unwrap();
        let mut args = BindgenArgs {
            artifact: artifact.clone(),
            language: Language::Typescript,
            out: directory.path().join("Contract.ts"),
            name: None,
        };
        assert!(run_bindgen(None, &args).is_ok());
        assert!(
            fs::read_to_string(&args.out)
                .unwrap()
                .contains("ViewRequest")
        );
        assert!(run_bindgen(Some(Path::new("Musubi.toml")), &args).is_err());
        args.out = artifact.clone();
        assert!(run_bindgen(None, &args).is_err());
        assert_eq!(fs::read(artifact).unwrap(), bytes);
    }
}
