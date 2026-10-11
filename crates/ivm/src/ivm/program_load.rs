//! Shared static loader admission, independent of mutable VM allocation.

use super::*;

pub(super) enum PreparedLoadImage<'a> {
    Contract(crate::PreparedContract),
    Generic(ProgramLoadImage<'a>),
}

pub(super) fn prepare<'a>(
    program: &'a [u8],
    budget: Option<&AllocationBudget>,
) -> Result<PreparedLoadImage<'a>, VMError> {
    let header = ProgramMetadata::parse_header(program)?;
    if header.declares_contract_interface() {
        let contract = match budget {
            Some(budget) => crate::prepare_contract_with_memory_budget(program, budget),
            None => crate::prepare_contract(Arc::<[u8]>::from(program)),
        }
        .map_err(crate::ContractArtifactError::into_vm_error)?;
        return Ok(PreparedLoadImage::Contract(contract));
    }
    let parsed = header.parse_sections()?;
    let strict_return_integrity = false;
    let header_len = parsed.header_len;
    let literal_prefix = parsed.prefix_len();
    let literal_table = decode_literal_table(
        program,
        header_len,
        parsed.literal_section,
        SyscallPolicy::AbiV1,
        budget,
    )?;
    let code_region = &program[header_len..];
    let code_len = u64::try_from(code_region.len()).map_err(|_| VMError::InvalidMetadata)?;
    if code_len > Memory::HEAP_START {
        return Err(VMError::InvalidMetadata);
    }
    if literal_prefix > code_region.len() {
        return Err(VMError::InvalidMetadata);
    }
    let instruction_region = &code_region[literal_prefix..];
    let entry_pc = u64::try_from(literal_prefix).map_err(|_| VMError::InvalidMetadata)?;
    let meta = parsed.metadata;
    let (predecoded, prepared) = if instruction_region.is_empty() {
        (None, None)
    } else {
        let decoded = match budget {
            Some(budget) => crate::ivm_cache::IvmCache::decode_stream_with_memory_budget(
                instruction_region,
                budget,
            )?,
            None => crate::ivm_cache::global_get(instruction_region)?,
        };
        validate_generic_program_syscalls(decoded.as_ref())?;
        let prepared = prepare_instruction_stream(
            instruction_region,
            decoded.as_ref(),
            entry_pc,
            literal_table.entries(),
            budget,
        )?;
        (Some(decoded), Some(prepared))
    };
    Ok(PreparedLoadImage::Generic(ProgramLoadImage {
        code_region,
        metadata: meta,
        contract_interface: parsed.contract_interface.map(|interface| {
            let exclusively_owned = interface
                .entrypoints
                .iter()
                .all(|entry| entry.triggers.is_empty());
            crate::prepared::shared_metadata(interface, exclusively_owned)
        }),
        contract_debug: parsed.contract_debug,
        literal_table,
        predecoded,
        prepared,
        code_hash: crate::metadata::contract_code_hash(program).into(),
        entry_pc,
        strict_return_integrity,
        allow_koto_test_syscalls: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generic(instructions: &[u8]) -> Vec<u8> {
        let mut program = ProgramMetadata::default().encode();
        program.extend_from_slice(instructions);
        program
    }

    fn same_static_verdict(program: &[u8], valid: bool) {
        let admitted = IVM::validate_program(program);
        let loaded = IVM::new(100_000).load_program(program);
        assert_eq!(admitted, loaded, "static and mutable loaders disagree");
        assert_eq!(admitted.is_ok(), valid);
    }

    #[test]
    fn static_admission_and_loading_share_generic_instruction_and_header_policy() {
        same_static_verdict(
            &generic(&crate::encoding::wide::encode_halt().to_le_bytes()),
            true,
        );
        same_static_verdict(&generic(&[]), true);
        same_static_verdict(&generic(&[0xff; 4]), false);
        same_static_verdict(&generic(&[0; 3]), false);
        for metadata in [
            ProgramMetadata {
                abi_version: 2,
                ..ProgramMetadata::default()
            },
            ProgramMetadata {
                mode: 0x80,
                ..ProgramMetadata::default()
            },
        ] {
            same_static_verdict(&metadata.encode(), false);
        }
        let number = crate::syscalls::abi_syscall_list()
            .iter()
            .copied()
            .find(|number| {
                !crate::syscalls::is_generic_program_syscall_allowed(SyscallPolicy::AbiV1, *number)
            })
            .expect("contract-only syscall exists");
        same_static_verdict(
            &generic(&crate::encoding::wide::encode_syscallx(number).to_le_bytes()),
            false,
        );
    }

    #[test]
    fn static_admission_rejects_malformed_literal_and_authenticated_contract_images() {
        let mut truncated = generic(b"LTLB");
        truncated.extend_from_slice(&1_u32.to_le_bytes());
        same_static_verdict(&truncated, false);
        let mut contract = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                "seiyaku Admission { view fn main() authorize(anyone) -> bool { true } }",
            )
            .unwrap();
        same_static_verdict(&contract, true);
        let code = ProgramMetadata::parse(&contract).unwrap().code_offset;
        contract[code..code + 4].copy_from_slice(&[0xff; 4]);
        same_static_verdict(&contract, false);
    }

    #[test]
    fn static_admission_preserves_local_preparation_refusal_and_retry() {
        let contract = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                "seiyaku Admission { view fn main() authorize(anyone) -> bool { true } }",
            )
            .unwrap();
        let _limits = crate::ivm_cache::CacheLimitsGuard::new(crate::ivm_cache::CacheLimits {
            capacity: 0,
            max_bytes: 0,
            max_decoded_ops: 0,
        });
        let refused = crate::cache_memory::with_refused_shared_allocation_for_test(|| {
            IVM::validate_program(&contract)
        });
        assert_eq!(
            refused,
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable,
            ))
        );
        IVM::validate_program(&contract).unwrap();
    }
}
