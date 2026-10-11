//! Exact utility values, gas/refusal ordering and original allocation ownership.
use super::*;
use crate::host::{DefaultHost, IVMHost};

fn input(vm: &mut IVM, kind: PointerType, bytes: &[u8]) -> u64 {
    let mut envelope = blob_envelope(bytes, None).unwrap();
    envelope.bytes[..2].copy_from_slice(&(kind as u16).to_be_bytes());
    vm.alloc_host_tlv(&envelope.bytes).unwrap()
}
fn encoding_input(vm: &mut IVM, schema: &EntrypointValueTypeV1, words: &[u64]) {
    let schema = input(
        vm,
        PointerType::NoritoBytes,
        &norito::encode_canonical(schema).unwrap(),
    );
    let base = vm.alloc_heap((words.len() * 8) as u64).unwrap();
    for (i, word) in words.iter().enumerate() {
        vm.store_u64(base + i as u64 * 8, *word).unwrap();
    }
    vm.set_register(10, schema);
    vm.set_register(11, base);
    vm.set_register(12, words.len() as u64);
}
#[test]
fn concat_preserves_bytes_and_utf8_validation_never_normalizes() {
    let mut vm = IVM::new(100_000);
    let left = input(&mut vm, PointerType::Blob, "言".as_bytes());
    let right = input(&mut vm, PointerType::Blob, "葉".as_bytes());
    vm.set_register(10, left);
    vm.set_register(11, right);
    assert_eq!(
        DefaultHost::default()
            .syscall(syscalls::SYSCALL_BLOB_CONCAT, &mut vm)
            .unwrap(),
        44
    );
    assert_eq!(
        payload(&vm, vm.register(10), PointerType::Blob).unwrap(),
        "言葉".as_bytes()
    );
    let pointer = vm.register(10);
    assert_eq!(
        execute(syscalls::SYSCALL_UTF8_VALIDATE, &mut vm).unwrap(),
        38
    );
    assert_eq!(vm.register(10), pointer);
    let bad = input(&mut vm, PointerType::Blob, &[0xff]);
    vm.set_register(10, bad);
    assert_eq!(
        execute(syscalls::SYSCALL_UTF8_VALIDATE, &mut vm).unwrap(),
        33
    );
    assert_eq!(vm.register(10), 0);
}
#[test]
fn unaffordable_concat_precedes_digest_validation_and_output_allocation() {
    let mut vm = IVM::new(1);
    let pointer = input(&mut vm, PointerType::Blob, b"abcdef");
    vm.set_register(10, pointer);
    vm.set_register(11, pointer);
    assert_eq!(
        execute(syscalls::SYSCALL_BLOB_CONCAT, &mut vm)
            .unwrap_err()
            .into_unmetered(),
        VMError::OutOfGas
    );
    assert_eq!(vm.register(10), pointer);
}
#[test]
fn typed_encoding_matches_the_canonical_schema_bound_record() {
    let mut vm = IVM::new(100_000);
    let schema = EntrypointValueTypeV1 {
        nodes: vec![
            Node::Tuple(2),
            Node::Leaf(Kind::Bool),
            Node::Leaf(Kind::String),
        ],
    };
    let string = input(&mut vm, PointerType::Blob, "誓約".as_bytes());
    encoding_input(&mut vm, &schema, &[1, string]);
    let expected = value_record::capture_value_record(&vm, &schema, vm.register(11), 2).unwrap();
    execute(syscalls::SYSCALL_VALUE_ENCODE, &mut vm).unwrap();
    assert_eq!(
        payload(&vm, vm.register(10), PointerType::Blob).unwrap(),
        norito::encode_canonical(&expected).unwrap()
    );
}
#[test]
fn typed_encoding_rejects_bad_words_without_publishing() {
    let mut vm = IVM::new(100_000);
    let schema = EntrypointValueTypeV1 {
        nodes: vec![Node::Leaf(Kind::Bool)],
    };
    encoding_input(&mut vm, &schema, &[2]);
    let before = vm.register(10);
    assert!(execute(syscalls::SYSCALL_VALUE_ENCODE, &mut vm).is_err());
    assert_eq!(vm.register(10), before);
}
#[test]
fn scalar_formatting_preserves_full_width_numbers_and_unicode() {
    use iroha_primitives::numeric_abi::IntValueV1;
    let mut vm = IVM::new(100_000);
    let number = "123456789012345678901234567890123456789012345678901234567890";
    let frame = IntValueV1::try_new(number.parse().unwrap())
        .unwrap()
        .encode_frame()
        .unwrap();
    let pointer = input(&mut vm, PointerType::Int, &frame);
    let schema = EntrypointValueTypeV1 {
        nodes: vec![Node::Leaf(Kind::Int)],
    };
    encoding_input(&mut vm, &schema, &[pointer]);
    execute(syscalls::SYSCALL_VALUE_TO_STRING, &mut vm).unwrap();
    assert_eq!(
        payload(&vm, vm.register(10), PointerType::Blob).unwrap(),
        number.as_bytes()
    );
    let string = input(&mut vm, PointerType::Blob, "e\u{301}言".as_bytes());
    let schema = EntrypointValueTypeV1 {
        nodes: vec![Node::Leaf(Kind::String)],
    };
    encoding_input(&mut vm, &schema, &[string]);
    execute(syscalls::SYSCALL_VALUE_TO_STRING, &mut vm).unwrap();
    assert_eq!(
        payload(&vm, vm.register(10), PointerType::Blob).unwrap(),
        "e\u{301}言".as_bytes()
    );
}
#[test]
fn funded_refusal_preserves_original_pool_and_retries() {
    let pool = AllocationBudget::new(256 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(100_000, &pool).unwrap();
    let schema = EntrypointValueTypeV1 {
        nodes: vec![Node::Leaf(Kind::Bool)],
    };
    encoding_input(&mut vm, &schema, &[1]);
    let before = vm.register(10);
    let baseline = pool.reserved_bytes();
    pool.set_limit_bytes(baseline);
    assert!(matches!(
        execute(syscalls::SYSCALL_VALUE_ENCODE, &mut vm),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(vm.register(10), before);
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(256 * 1024 * 1024);
    execute(syscalls::SYSCALL_VALUE_ENCODE, &mut vm).unwrap();
    drop(vm);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn small_schema_does_not_limit_large_valid_scalar_payloads() {
    let mut vm = IVM::new(1_000_000);
    let name = "x".repeat(255);
    let value: iroha_model_base::name::Name = name.parse().unwrap();
    let pointer = input(
        &mut vm,
        PointerType::Name,
        &norito::encode_canonical(&value).unwrap(),
    );
    let schema = EntrypointValueTypeV1 {
        nodes: vec![Node::Leaf(Kind::Name)],
    };
    encoding_input(&mut vm, &schema, &[pointer]);
    execute(syscalls::SYSCALL_VALUE_TO_STRING, &mut vm).unwrap();
    assert_eq!(
        payload(&vm, vm.register(10), PointerType::Blob).unwrap(),
        name.as_bytes()
    );
}

#[test]
fn scalar_name_payload_is_not_limited_by_its_smaller_schema_frame() {
    let name: iroha_model_base::name::Name = "long_name_".repeat(25).parse().unwrap();
    let schema = EntrypointValueTypeV1 {
        nodes: vec![Node::Leaf(Kind::Name)],
    };
    assert!(name.as_ref().len() > norito::encode_canonical(&schema).unwrap().len());
    for number in [
        syscalls::SYSCALL_VALUE_ENCODE,
        syscalls::SYSCALL_VALUE_TO_STRING,
    ] {
        let mut vm = IVM::new(1_000_000);
        let pointer = input(
            &mut vm,
            PointerType::Name,
            &norito::encode_canonical(&name).unwrap(),
        );
        encoding_input(&mut vm, &schema, &[pointer]);
        let expected =
            value_record::capture_value_record(&vm, &schema, vm.register(11), 1).unwrap();
        execute(number, &mut vm).unwrap();
        let bytes = payload(&vm, vm.register(10), PointerType::Blob).unwrap();
        if number == syscalls::SYSCALL_VALUE_TO_STRING {
            assert_eq!(bytes, name.as_ref().as_bytes());
        } else {
            assert_eq!(bytes, norito::encode_canonical(&expected).unwrap());
        }
    }
}

#[test]
fn fixed_stack_int_formatting_covers_zero_sign_and_signed_512_bit_edges() {
    use iroha_primitives::{bigint::BigInt, numeric_abi::IntValueV1};
    let mut maximum = [0xff; 64];
    maximum[0] = 0x7f;
    let mut minimum = [0; 64];
    minimum[0] = 0x80;
    for value in [
        BigInt::from(0),
        BigInt::from(1),
        BigInt::from(-1),
        BigInt::from_twos_bytes(&maximum).unwrap(),
        BigInt::from_twos_bytes(&minimum).unwrap(),
    ] {
        let expected = value.to_string();
        assert_eq!(format!("{}", StackInt(&value)), expected);
        let frame = IntValueV1::try_new(value).unwrap().encode_frame().unwrap();
        let mut vm = IVM::new(1_000_000);
        let pointer = input(&mut vm, PointerType::Int, &frame);
        let schema = EntrypointValueTypeV1 {
            nodes: vec![Node::Leaf(Kind::Int)],
        };
        encoding_input(&mut vm, &schema, &[pointer]);
        execute(syscalls::SYSCALL_VALUE_TO_STRING, &mut vm).unwrap();
        assert_eq!(
            payload(&vm, vm.register(10), PointerType::Blob).unwrap(),
            expected.as_bytes()
        );
    }
}
