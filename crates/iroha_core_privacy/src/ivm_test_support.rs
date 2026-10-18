//! Authenticated V1 Unit-call fixtures for native execution-relation tests.

/// Descriptor for a zero-argument function returning one initialized Unit word.
pub fn unit_callable(entry_pc: u64) -> ivm::call::EmbeddedCallableV1 {
    ivm::call::EmbeddedCallableV1 {
        entry_pc,
        frame_bytes: 0,
        arguments: ivm::call::CallSchemaV1::empty(),
        results: ivm::call::CallSchemaV1::unit(),
    }
}

/// Unit return through the caller-owned result table and protected return address.
pub fn unit_return() -> [u8; 16] {
    use ivm::{
        encoding::wide,
        instruction::wide::{arithmetic, control, memory},
    };
    let instructions = [
        wide::encode_store(memory::STORE64, 12, 0, 0),
        wide::encode_ri(arithmetic::ADDI, 10, 12, 0),
        wide::encode_ri(arithmetic::ADDI, 11, 0, 1),
        wide::encode_rr(control::JALR, 0, 1, 0),
    ];
    let mut code = [0; 16];
    for (slot, instruction) in code.chunks_exact_mut(4).zip(instructions) {
        slot.copy_from_slice(&instruction.to_le_bytes());
    }
    code
}
