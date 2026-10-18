//! CoreHost canonical `Name` frame decoding and rejection coverage.
use crate::common;
use ivm::{CoreHost, IVM, PointerType, encoding, syscalls};
fn tlv(pty: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + payload.len() + 32);
    v.extend_from_slice(&(pty as u16).to_be_bytes());
    v.push(1);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    v.extend_from_slice(&h);
    v
}
#[test]
fn name_decode_rejects_invalid_utf8() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    // Build NoritoBytes TLV with an invalid UTF-8 byte inside a Norito string payload.
    let mut bad = norito::to_bytes(&"ok").expect("encode string");
    if let Some(last) = bad.last_mut() {
        *last = 0xFF;
    }
    let p_nb = vm
        .alloc_input_tlv(&tlv(PointerType::NoritoBytes, &bad))
        .unwrap();
    // Program: publish TLV; NAME_DECODE; HALT
    let prog = common::assemble(
        &[
            encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                syscalls::SYSCALL_NAME_DECODE as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_nb);
    vm.load_program(&prog).unwrap();
    let err = vm.run().expect_err("expected invalid UTF-8 to be rejected");
    assert!(matches!(err, ivm::VMError::DecodeError));
}
#[test]
fn name_decode_rejects_invalid_name_utf8_valid() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    // Valid UTF-8 but invalid Name (contains space)
    let bad = norito::to_bytes(&"bad name").expect("encode string");
    let p_nb = vm
        .alloc_input_tlv(&tlv(PointerType::NoritoBytes, &bad))
        .unwrap();
    let prog = common::assemble(
        &[
            encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                syscalls::SYSCALL_NAME_DECODE as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_nb);
    vm.load_program(&prog).unwrap();
    let err = vm.run().expect_err("expected invalid Name to be rejected");
    assert!(matches!(err, ivm::VMError::DecodeError));
}
#[test]
fn name_decode_rejects_reserved_chars() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    // Valid UTF-8 but invalid Name (reserved delimiter `@`)
    let bad = norito::to_bytes(&"alice@banka").expect("encode string");
    let p_nb = vm
        .alloc_input_tlv(&tlv(PointerType::NoritoBytes, &bad))
        .unwrap();
    let prog = common::assemble(
        &[
            encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                syscalls::SYSCALL_NAME_DECODE as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_nb);
    vm.load_program(&prog).unwrap();
    let err = vm
        .run()
        .expect_err("expected reserved chars to be rejected");
    assert!(matches!(err, ivm::VMError::DecodeError));
}
#[test]
fn name_decode_accepts_valid_utf8() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let name: iroha_model_base::name::Name = "wonderland".parse().expect("name");
    let good = norito::to_bytes(&name).expect("encode name");
    let p_nb = vm
        .alloc_input_tlv(&tlv(PointerType::NoritoBytes, &good))
        .unwrap();
    let prog = common::assemble(
        &[
            encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                syscalls::SYSCALL_NAME_DECODE as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_nb);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    let p = vm.register(10);
    let tlv_name = vm.memory.validate_tlv(p).unwrap();
    assert_eq!(tlv_name.type_id, PointerType::Name);
    let decoded: iroha_model_base::name::Name =
        norito::decode_from_bytes(tlv_name.payload).expect("decode name");
    assert_eq!(decoded.as_ref(), "wonderland");
}
