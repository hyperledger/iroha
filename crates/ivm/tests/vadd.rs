//! Canonical VADD32 privacy enforcement regression.

use ivm::{IVM, ProgramMetadata, VMError, encoding, instruction, ivm_mode};

#[test]
fn vadd32_rejects_mismatched_lane_tags() {
    let metadata = ProgramMetadata {
        mode: ivm_mode::ZK | ivm_mode::VECTOR,
        vector_length: 2,
        max_cycles: 32,
        ..ProgramMetadata::default()
    };
    let mut program = metadata.encode();
    program.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::crypto::VADD32, 2, 0, 1).to_le_bytes(),
    );
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());

    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program)
        .expect("load canonical VADD32 privacy fixture");
    for (register, value, private) in [(32, 1, true), (33, 2, false), (34, 3, true), (35, 4, true)]
    {
        vm.set_register(register, value);
        vm.registers.set_tag(register, private);
    }

    assert!(matches!(vm.run(), Err(VMError::PrivacyViolation)));
}
