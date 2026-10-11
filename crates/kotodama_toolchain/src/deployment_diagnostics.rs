//! Deployment limitations derived from canonical artifact admission.

use kotodama_lang::diagnostic::{Diagnostic, DiagnosticBundle, DiagnosticPhase};

/// Warn when a public entrypoint can request raw private witnesses from a local host.
///
/// The verifier supplies transitive control-flow reachability, including private helpers.
/// ZK capability without this syscall does not produce a warning.
///
/// # Errors
/// Returns the original admission failure for an invalid artifact.
pub fn artifact_deployment_warnings(
    artifact: &[u8],
) -> Result<DiagnosticBundle, ivm::ContractArtifactError> {
    let verified = ivm::verify_contract_artifact(artifact)?;
    let entrypoints = verified.private_input_entrypoints();
    Ok(DiagnosticBundle::new(if entrypoints.is_empty() {
        Vec::new()
    } else {
        vec![Diagnostic::warning(
                "W_PROVER_PRIVATE_INPUT",
                DiagnosticPhase::Artifact,
                format!(
                    "entrypoints {} require a prover or local test host for raw private inputs; production consensus hosts cannot execute them",
                    entrypoints.join(", ")
                ),
                None,
            )
            .with_help("Generate proofs in a prover environment and submit public proofs to a deployable verifier contract. --zk alone does not provide private witnesses on-chain.")]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotodama_lang::compiler::{Compiler, CompilerOptions};

    #[test]
    fn warning_tracks_reachable_private_inputs_instead_of_the_zk_bit() {
        let compiler = Compiler::new_with_options(CompilerOptions {
            force_zk: true,
            ..CompilerOptions::default()
        });
        let public = compiler
            .compile_source("seiyaku Public { view fn read() authorize(anyone) -> int { 1 } }")
            .unwrap();
        assert!(
            artifact_deployment_warnings(&public)
                .unwrap()
                .diagnostics
                .is_empty()
        );
        let private = compiler.compile_source("seiyaku Prover { fn witness() -> Secret<int> { crypto::private_input(0) } kotoage fn commitment() authorize(anyone) -> int { let value = witness(); crypto::valcom(left: value, right: value) } }").unwrap();
        let warnings = artifact_deployment_warnings(&private).unwrap();
        assert_eq!(warnings.diagnostics.len(), 1);
        assert_eq!(warnings.diagnostics[0].code, "W_PROVER_PRIVATE_INPUT");
        assert!(warnings.diagnostics[0].message.contains("commitment"));
        assert!(
            warnings
                .render_json()
                .unwrap()
                .contains("W_PROVER_PRIVATE_INPUT")
        );
        assert!(artifact_deployment_warnings(b"invalid artifact").is_err());
    }
}
