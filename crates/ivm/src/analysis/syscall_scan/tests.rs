//! Classifiers preserve executable order and the canonical decoder boundary.

use super::*;
use crate::{encoding::wide as enc, instruction::wide};

#[test]
fn borrowed_scan_preserves_repeated_full_width_ids_and_sorted_first_selection() {
    let mut bytes = ProgramMetadata::default().encode();
    for word in [
        enc::encode_syscallx(0x00ff_ffff),
        enc::encode_halt(),
        enc::encode_sys(wide::system::SCALL, 17),
        enc::encode_syscallx(256),
        enc::encode_sys(wide::system::SCALL, 17),
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    assert!(
        program_syscall_numbers(&bytes)
            .unwrap()
            .eq([0x00ff_ffff, 17, 256, 17])
    );
    assert_eq!(
        program_syscall_numbers(&bytes)
            .unwrap()
            .filter(|number| *number >= 256)
            .min(),
        Some(256)
    );
    bytes.pop();
    assert!(matches!(
        program_syscall_numbers(&bytes),
        Err(ProgramAnalysisError::Decode(
            crate::VMError::MemoryAccessViolation { .. }
        ))
    ));
}

#[test]
fn prepared_scan_matches_original_artifact_and_keeps_canonical_metadata_refusal() {
    let bytes = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku SyscallScan { view fn main() authorize(anyone) -> bool { true } }")
        .unwrap();
    let prepared = crate::prepare_contract(std::sync::Arc::from(bytes.as_slice())).unwrap();
    assert!(prepared_syscall_numbers(&prepared).eq(program_syscall_numbers(&bytes).unwrap()));
    let failure = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || {
            program_syscall_numbers(&bytes)
                .err()
                .expect("actual metadata allocation refusal")
        },
    );
    assert_eq!(
        failure.into_vm_error().execution_deferral(),
        Some(crate::error::ExecutionDeferral::ActiveMemoryCapacity)
    );
    assert!(program_syscall_numbers(&bytes).is_ok());
}
