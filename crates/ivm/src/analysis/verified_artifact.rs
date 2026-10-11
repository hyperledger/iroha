//! Funded inspection reuses the original native artifact's admitted executable range.
//!
//! The caller keeps the shared admission result and its actual memory owner alive through
//! final writing.

use super::{ProgramAnalysis, ProgramAnalysisError, aggregate};
use crate::{VerifiedContractArtifact, ivm_cache::ValidatedInstructions};
use iroha_allocation::AllocationBudget;

/// Analyze exact already verified immutable bytes under the original native allocation pool.
///
/// No discarded CNTR/DBG1 tree or decoded instruction vector is materialized. Only fixed scalar
/// metadata is copied; syscall scratch and its returned histogram retain the actual caller pool.
/// This grants no compilation, deployment, query-admission or source-allocation authority.
///
/// # Errors
/// Refuses source/range substitution before allocation and preserves original capacity refusal.
pub fn analyze_verified_artifact_with_memory_budget(
    bytes: &[u8],
    verified: &VerifiedContractArtifact,
    budget: &AllocationBudget,
) -> Result<ProgramAnalysis, ProgramAnalysisError> {
    let source = verified
        .borrow_admitted_program(bytes)
        .map_err(ProgramAnalysisError::Metadata)?;
    let stream = ValidatedInstructions::new(source.code()).map_err(ProgramAnalysisError::Decode)?;
    aggregate::analyze(source.metadata().clone(), || stream.iter(), Some(budget))
        .map_err(ProgramAnalysisError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VMError, analysis::analyze_program_with_memory_budget};

    fn actual() -> (Vec<u8>, VerifiedContractArtifact) {
        let bytes = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                "seiyaku VerifiedAnalysis { state int count; hajimari() { count = 0; } view fn main() authorize(anyone) -> int { return count; } }",
            )
            .unwrap();
        let verified = crate::verify_contract_artifact(&bytes).unwrap();
        (bytes, verified)
    }

    #[test]
    fn verified_analysis_preserves_output_without_decoding_metadata_again() {
        let (bytes, verified) = actual();
        let expected =
            analyze_program_with_memory_budget(&bytes, &AllocationBudget::new(1024 * 1024))
                .unwrap();
        let owner = AllocationBudget::new(1024 * 1024);
        let actual =
            norito::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
                analyze_verified_artifact_with_memory_budget(&bytes, &verified, &owner)
            })
            .unwrap();
        assert_eq!(actual.metadata.encode(), expected.metadata.encode());
        assert_eq!(actual.instruction_count, expected.instruction_count);
        assert_eq!(actual.registers, expected.registers);
        assert_eq!(actual.memory, expected.memory);
        assert_eq!(actual.syscalls, expected.syscalls);
        assert!(
            owner.reserved_bytes() > 0,
            "returned native syscall result retains custody"
        );
        let cloned = actual.clone();
        drop(actual);
        assert!(owner.reserved_bytes() > 0);
        drop(cloned);
        assert_eq!(owner.reserved_bytes(), 0);
    }

    #[test]
    fn verified_analysis_source_substitution_precedes_actual_pool_admission() {
        let (mut bytes, verified) = actual();
        bytes[8] ^= 1;
        let owner = AllocationBudget::new(0);
        let error =
            analyze_verified_artifact_with_memory_budget(&bytes, &verified, &owner).unwrap_err();
        assert_eq!(error.into_vm_error(), VMError::InvalidMetadata);
        assert_eq!(owner.reserved_bytes(), 0);
    }

    #[test]
    fn verified_analysis_preserves_actual_capacity_refusal_and_retry_identity() {
        let (bytes, verified) = actual();
        let owner = AllocationBudget::new(0);
        let error =
            analyze_verified_artifact_with_memory_budget(&bytes, &verified, &owner).unwrap_err();
        assert!(matches!(
            error.into_vm_error(),
            VMError::AllocationDeferred(_)
        ));
        assert_eq!(owner.reserved_bytes(), 0);
        owner.set_limit_bytes(1024 * 1024);
        let output =
            analyze_verified_artifact_with_memory_budget(&bytes, &verified, &owner).unwrap();
        assert!(output.instruction_count > 0);
        drop(output);
        assert_eq!(owner.reserved_bytes(), 0);
    }
}
