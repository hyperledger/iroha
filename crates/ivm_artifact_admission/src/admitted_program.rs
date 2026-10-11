//! Borrow the original executable range from actual native artifact admission.
//!
//! Public admission summary fields are not a mutable replacement for their original range.
//! This fixed-size seal is created by the sole verifier constructor and authenticates the exact
//! same borrowed image without decoding CNTR/DBG1 or copying the artifact again.
//!
//! The private seal is populated only in the native `verified_from_parts` constructor.

use super::VerifiedContractArtifact;
use iroha_crypto::Hash;
use ivm_abi::{VMError, metadata::ProgramMetadata};

/// Fixed scalar identity derived only by the native admission owner.
#[derive(Clone, Debug)]
pub struct AdmittedProgramSeal {
    metadata: ProgramMetadata,
    header_len: usize,
    code_offset: usize,
    code_hash: Hash,
}

impl AdmittedProgramSeal {
    /// The native verifier calls this after policy/literal/interface checks have completed.
    pub(super) fn new(
        metadata: &ProgramMetadata,
        header_len: usize,
        code_offset: usize,
        code_hash: Hash,
    ) -> Self {
        Self {
            metadata: metadata.clone(),
            header_len,
            code_offset,
            code_hash,
        }
    }
}

fn same_metadata(left: &ProgramMetadata, right: &ProgramMetadata) -> bool {
    left.version_major == right.version_major
        && left.version_minor == right.version_minor
        && left.mode == right.mode
        && left.vector_length == right.vector_length
        && left.max_cycles == right.max_cycles
        && left.abi_version == right.abi_version
}

/// Immutable executable borrow joined to one actual admission result.
///
/// This has no public constructor or wire codec. It adds no source allocation or physical
/// capacity, and does not itself retain an HTTP/execution permit. Its caller retains the actual
/// admission result and request owner throughout inspection and final response writing.
#[derive(Clone, Copy)]
pub struct AdmittedProgram<'a> {
    metadata: &'a ProgramMetadata,
    code: &'a [u8],
}
impl AdmittedProgram<'_> {
    /// Borrow the admission owner's fixed scalar execution header.
    pub fn metadata(&self) -> &ProgramMetadata {
        self.metadata
    }

    /// Borrow the unchanged executable stream, with no artifact-prefix payloads.
    pub fn code(&self) -> &[u8] {
        self.code
    }
}

impl VerifiedContractArtifact {
    /// Borrow executable input from the exact artifact admitted by this native result.
    ///
    /// Summary mutation, replacement bytes and invalid coordinates are refused before analysis
    /// scratch allocation. The complete artifact identity includes its header and all sections.
    ///
    /// # Errors
    /// Returns a canonical metadata error if the original source/range identity no longer joins.
    pub fn borrow_admitted_program<'a>(
        &'a self,
        artifact: &'a [u8],
    ) -> Result<AdmittedProgram<'a>, VMError> {
        let seal = &self.admitted_program;
        if self.code_hash != seal.code_hash
            || self.header_len != seal.header_len
            || self.code_offset != seal.code_offset
            || !same_metadata(&self.metadata, &seal.metadata)
            || seal.header_len != ivm_abi::metadata::HEADER_SIZE
            || seal.code_offset < seal.header_len
            || ivm_abi::metadata::contract_code_hash(artifact) != seal.code_hash
        {
            return Err(VMError::InvalidMetadata);
        }
        let code = artifact
            .get(seal.code_offset..)
            .ok_or(VMError::InvalidMetadata)?;
        Ok(AdmittedProgram {
            metadata: &seal.metadata,
            code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actual() -> (Vec<u8>, VerifiedContractArtifact) {
        let bytes = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                "seiyaku AdmittedRange { view fn value() authorize(anyone) -> int { return 7; } }",
            )
            .unwrap();
        let verified = crate::verify_contract_artifact(&bytes).unwrap();
        (bytes, verified)
    }

    #[test]
    fn admitted_range_borrows_original_image_without_second_metadata_decode() {
        let (bytes, verified) = actual();
        let range =
            norito::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
                verified.borrow_admitted_program(&bytes)
            })
            .unwrap();
        assert_eq!(range.code(), &bytes[verified.code_offset..]);
        assert!(core::ptr::eq(
            range.code().as_ptr(),
            bytes[verified.code_offset..].as_ptr()
        ));
        assert!(same_metadata(range.metadata(), &verified.metadata));
    }

    #[test]
    fn mutable_summary_and_complete_artifact_substitutions_do_not_change_native_range() {
        let (bytes, verified) = actual();
        for changed in [
            {
                let mut changed = crate::verify_contract_artifact(&bytes).unwrap();
                changed.code_offset += 4;
                changed
            },
            {
                let mut changed = crate::verify_contract_artifact(&bytes).unwrap();
                changed.metadata.max_cycles ^= 1;
                changed
            },
            {
                let mut changed = crate::verify_contract_artifact(&bytes).unwrap();
                changed.code_hash = Hash::new(b"different source");
                changed
            },
        ] {
            assert!(matches!(
                changed.borrow_admitted_program(&bytes),
                Err(VMError::InvalidMetadata)
            ));
        }
        let mut changed_bytes = bytes.clone();
        changed_bytes[8] ^= 1;
        assert!(matches!(
            verified.borrow_admitted_program(&changed_bytes),
            Err(VMError::InvalidMetadata)
        ));
    }
}
