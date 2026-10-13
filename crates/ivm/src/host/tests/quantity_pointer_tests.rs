//! Pointer-ABI provenance and canonical quantity admission tests for the default IVM host.
use super::*;
#[test]
fn default_host_pointer_decoders_enforce_owned_provenance_and_integrity() {
    let blob = test_tlv(PointerType::Blob, b"owned-heap-input");
    let mut heap_vm = IVM::new(u64::MAX);
    let heap_pointer = heap_vm
        .alloc_heap(u64::try_from(blob.len()).expect("TLV length fits u64"))
        .expect("allocate complete HEAP envelope");
    heap_vm
        .store_bytes(heap_pointer, &blob)
        .expect("store complete HEAP envelope");
    heap_vm.set_register(10, heap_pointer);
    DefaultHost::new()
        .syscall(syscalls::SYSCALL_SHA256_HASH, &mut heap_vm)
        .expect("allocated HEAP must be a valid pointer-ABI source");
    let digest = heap_vm
        .validate_tlv(heap_vm.register(10))
        .expect("validate hash result");
    assert_eq!(digest.type_id, PointerType::Blob);
    assert_eq!(digest.payload.len(), 32);
    for (label, pointer) in [
        ("unallocated HEAP", Memory::HEAP_START),
        ("OUTPUT", Memory::OUTPUT_START),
        ("stack", Memory::STACK_START),
    ] {
        let mut vm = IVM::new(u64::MAX);
        vm.store_bytes(pointer, &blob)
            .unwrap_or_else(|error| panic!("store {label} envelope: {error:?}"));
        vm.set_register(10, pointer);
        assert!(
            matches!(
                DefaultHost::new().syscall(syscalls::SYSCALL_SHA256_HASH, &mut vm),
                Err(VMError::NoritoInvalid)
            ),
            "{label} bytes must not acquire pointer provenance"
        );
        assert_eq!(vm.register(10), pointer);
    }
    let mut partial_vm = IVM::new(u64::MAX);
    let owned_blob_bytes = blob
        .len()
        .checked_sub(8)
        .expect("Blob envelope exceeds one HEAP alignment unit");
    let partial_pointer = partial_vm
        .alloc_heap(u64::try_from(owned_blob_bytes).expect("partial length fits u64"))
        .expect("allocate truncated HEAP ownership");
    partial_vm
        .store_bytes(partial_pointer, &blob)
        .expect("write across the unowned HEAP boundary");
    partial_vm.set_register(10, partial_pointer);
    assert!(matches!(
        DefaultHost::new().syscall(syscalls::SYSCALL_SHA256_HASH, &mut partial_vm),
        Err(VMError::NoritoInvalid)
    ));
    for malformed in [test_tlv(PointerType::Name, b"wrong-type"), {
        let mut corrupted = blob.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        corrupted
    }] {
        let mut vm = IVM::new(u64::MAX);
        let pointer = vm
            .alloc_host_tlv(&malformed)
            .expect("allocate malformed adversarial envelope");
        vm.set_register(10, pointer);
        assert!(matches!(
            DefaultHost::new().syscall(syscalls::SYSCALL_SHA256_HASH, &mut vm),
            Err(VMError::NoritoInvalid)
        ));
    }
    let mut code_vm = IVM::new(u64::MAX);
    let mut code = crate::encoding::wide::encode_halt().to_le_bytes().to_vec();
    let code_pointer = u64::try_from(code.len()).expect("code offset fits u64");
    code.extend_from_slice(&blob);
    code_vm.load_code(&code).expect("load arbitrary code bytes");
    code_vm.set_register(10, code_pointer);
    assert!(matches!(
        DefaultHost::new().syscall(syscalls::SYSCALL_SHA256_HASH, &mut code_vm),
        Err(VMError::NoritoInvalid)
    ));
}
#[test]
fn expect_tlv_enforces_pointer_policy() {
    crate::set_banner_enabled(false);
    let mut vm = IVM::new(u64::MAX);
    let program = ProgramMetadata::default_for(1, 1, 1).encode();
    vm.load_program(&program).expect("load program");
    // The first release only supports ABI v1; installing any other
    // annotated ABI version must fail closed during pointer validation.
    let _guard = crate::pointer_abi::PointerPolicyGuard::install(crate::SyscallPolicy::AbiV1, 2);
    let mut tlv = Vec::new();
    tlv.extend_from_slice(&(PointerType::AccountId as u16).to_be_bytes());
    tlv.push(1);
    tlv.extend_from_slice(&0u32.to_be_bytes());
    let hash: [u8; 32] = iroha_crypto::Hash::new([]).into();
    tlv.extend_from_slice(&hash);
    let ptr = vm.alloc_input_tlv(&tlv).expect("allocate TLV");
    vm.set_register(10, ptr);
    let err = DefaultHost::expect_tlv(&vm, 10, PointerType::AccountId).unwrap_err();
    assert!(matches!(
        err,
        VMError::AbiTypeNotAllowed { abi: 2, type_id } if type_id == PointerType::AccountId as u16
    ));
}
#[test]
fn quantity_arguments_require_canonical_quantity_pointer() {
    crate::set_banner_enabled(false);
    let mut vm = IVM::new(u64::MAX);
    let canonical = "1.25".parse::<Quantity>().expect("canonical quantity");
    let canonical_payload = QuantityValueV1::new(canonical.clone())
        .encode_frame()
        .expect("encode canonical quantity frame");
    let canonical_ptr = vm
        .alloc_input_tlv(&test_tlv(PointerType::Quantity, &canonical_payload))
        .expect("allocate canonical quantity");
    vm.set_register(13, canonical_ptr);
    assert_eq!(
        (DefaultHost::expect_quantity(&vm, 13)).expect("expected successful fixture result"),
        canonical_payload.len()
    );
    let account_ptr = vm
        .alloc_input_tlv(&test_tlv(PointerType::AccountId, &[]))
        .expect("allocate account fixture");
    let definition_ptr = vm
        .alloc_input_tlv(&test_tlv(PointerType::AssetDefinitionId, &[]))
        .expect("allocate asset definition fixture");
    let dataspace_ptr = vm
        .alloc_input_tlv(&test_tlv(PointerType::DataSpaceId, &[]))
        .expect("allocate dataspace fixture");
    vm.set_register(10, account_ptr);
    vm.set_register(11, account_ptr);
    vm.set_register(12, definition_ptr);
    vm.set_register(14, dataspace_ptr);
    let expected_gas = DefaultHost::mutation_gas(canonical_payload.len());
    let mut scoped_host = DefaultHost::new();
    assert_eq!(
        (scoped_host.prepare_syscall(syscalls::SYSCALL_TRANSFER_ASSET_SCOPED, &vm))
            .expect("expected successful fixture result"),
        expected_gas
    );
    assert_eq!(
        (scoped_host.syscall(syscalls::SYSCALL_TRANSFER_ASSET_SCOPED, &mut vm))
            .expect("expected successful fixture result"),
        expected_gas
    );
    let mut batch_host = DefaultHost::new();
    assert_eq!(
        (batch_host.syscall(syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN, &mut vm))
            .expect("expected successful fixture result"),
        gas::G_FASTPQ_BATCH
    );
    assert_eq!(
        (batch_host.syscall(syscalls::SYSCALL_TRANSFER_V1, &mut vm))
            .expect("expected successful fixture result"),
        expected_gas
    );
    assert!(batch_host.fastpq_batch_has_entries);
    let legacy_payload =
        norito::to_bytes(&canonical.into_numeric()).expect("encode legacy Numeric");
    let legacy_ptr = vm
        .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &legacy_payload))
        .expect("allocate legacy Numeric pointer");
    vm.set_register(13, legacy_ptr);
    assert!(matches!(
        DefaultHost::expect_quantity(&vm, 13),
        Err(VMError::NoritoInvalid)
    ));
    let noncanonical = Numeric::new(1_250_u32, 3);
    let noncanonical_ptr = vm
        .alloc_input_tlv(&test_tlv(
            PointerType::Quantity,
            &norito::to_bytes(&noncanonical).expect("encode noncanonical quantity"),
        ))
        .expect("allocate noncanonical quantity");
    vm.set_register(13, noncanonical_ptr);
    assert!(matches!(
        DefaultHost::expect_quantity(&vm, 13),
        Err(VMError::DecodeError)
    ));
}
#[test]
fn oversized_quantity_fails_from_bounded_header_before_hash_or_mutation() {
    crate::set_banner_enabled(false);
    let mut vm = IVM::new(u64::MAX);
    let account_ptr = vm
        .alloc_input_tlv(&test_tlv(PointerType::AccountId, &[]))
        .expect("allocate account fixture");
    let definition_ptr = vm
        .alloc_input_tlv(&test_tlv(PointerType::AssetDefinitionId, &[]))
        .expect("allocate asset definition fixture");
    let dataspace_ptr = vm
        .alloc_input_tlv(&test_tlv(PointerType::DataSpaceId, &[]))
        .expect("allocate dataspace fixture");
    let oversized = test_tlv(
        PointerType::Quantity,
        &[0xa5; MAX_QUANTITY_FRAME_BYTES_V1 + 1],
    );
    let valid_oversized_ptr = vm
        .alloc_input_tlv(&oversized)
        .expect("allocate oversized quantity with a valid digest");
    let mut corrupted_oversized = oversized;
    *corrupted_oversized
        .last_mut()
        .expect("quantity envelope has a digest") ^= 1;
    let quantity_ptr = vm
        .alloc_input_tlv(&corrupted_oversized)
        .expect("allocate oversized quantity with a corrupt digest");
    let mut impossible_length = test_tlv(PointerType::Quantity, &[]);
    impossible_length[3..7].copy_from_slice(&u32::MAX.to_be_bytes());
    let impossible_length_ptr = vm
        .alloc_input_tlv(&impossible_length)
        .expect("allocate quantity with an impossible declared length");
    let maximum_sized_noncanonical_ptr = vm
        .alloc_input_tlv(&test_tlv(
            PointerType::Quantity,
            &[0x5a; MAX_QUANTITY_FRAME_BYTES_V1],
        ))
        .expect("allocate maximum-sized noncanonical quantity");
    vm.set_register(13, maximum_sized_noncanonical_ptr);
    assert_eq!(
        (read_bounded_tlv_payload_len_at(
            &vm,
            maximum_sized_noncanonical_ptr,
            PointerType::Quantity,
            MAX_QUANTITY_FRAME_BYTES_V1,
        ))
        .expect("expected successful fixture result"),
        MAX_QUANTITY_FRAME_BYTES_V1,
        "the exact V1 maximum must reach canonical frame validation"
    );
    assert!(
        matches!(
            DefaultHost::expect_quantity(&vm, 13),
            Err(VMError::DecodeError)
        ),
        "size admission must not replace canonical frame validation"
    );
    for (label, pointer) in [
        ("valid digest", valid_oversized_ptr),
        ("corrupt digest", quantity_ptr),
        ("impossible declared length", impossible_length_ptr),
    ] {
        vm.set_register(13, pointer);
        vm.memory.clear_tracking();
        assert!(
            matches!(
                DefaultHost::expect_quantity(&vm, 13),
                Err(VMError::NoritoInvalid)
            ),
            "{label}"
        );
        assert_eq!(
            vm.memory
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot")[..],
            vec![crate::memory::AccessRange {
                addr: pointer,
                len: 7,
            }],
            "{label} must be rejected after the fixed header only"
        );
        assert!(
            vm.memory
                .try_write_log_snapshot()
                .expect("allocate write-log snapshot")
                .is_empty(),
            "{label}"
        );
    }
    vm.set_register(10, account_ptr);
    vm.set_register(11, account_ptr);
    vm.set_register(12, definition_ptr);
    vm.set_register(13, quantity_ptr);
    vm.set_register(14, dataspace_ptr);
    let registers_before = [
        vm.register(10),
        vm.register(11),
        vm.register(12),
        vm.register(13),
        vm.register(14),
    ];
    let mut scoped_host = DefaultHost::new();
    vm.memory.clear_tracking();
    assert!(matches!(
        scoped_host.prepare_syscall(syscalls::SYSCALL_TRANSFER_ASSET_SCOPED, &vm),
        Err(VMError::NoritoInvalid)
    ));
    assert!(
        vm.memory
            .try_read_log_snapshot()
            .expect("allocate read-log snapshot")
            .is_empty(),
        "header-only preparation must reject the oversized frame before reading its payload"
    );
    assert!(
        vm.memory
            .try_write_log_snapshot()
            .expect("allocate write-log snapshot")
            .is_empty()
    );
    vm.memory.clear_tracking();
    assert!(matches!(
        scoped_host.syscall(syscalls::SYSCALL_TRANSFER_ASSET_SCOPED, &mut vm),
        Err(VMError::NoritoInvalid)
    ));
    assert_eq!(
        vm.memory
            .try_read_log_snapshot()
            .expect("allocate read-log snapshot")[..],
        vec![crate::memory::AccessRange {
            addr: quantity_ptr,
            len: 7,
        }],
        "scoped transfer must read only the bounded header before rejecting the payload"
    );
    assert!(
        vm.memory
            .try_write_log_snapshot()
            .expect("allocate write-log snapshot")
            .is_empty()
    );
    assert_eq!(
        [
            vm.register(10),
            vm.register(11),
            vm.register(12),
            vm.register(13),
            vm.register(14),
        ],
        registers_before
    );
    let mut batch_host = DefaultHost::new();
    assert_eq!(
        (batch_host.syscall(syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN, &mut vm))
            .expect("expected successful fixture result"),
        gas::G_FASTPQ_BATCH
    );
    vm.memory.clear_tracking();
    assert!(matches!(
        batch_host.syscall(syscalls::SYSCALL_TRANSFER_V1, &mut vm),
        Err(VMError::NoritoInvalid)
    ));
    assert_eq!(
        vm.memory
            .try_read_log_snapshot()
            .expect("allocate read-log snapshot")[..],
        vec![crate::memory::AccessRange {
            addr: quantity_ptr,
            len: 7,
        }],
        "batch transfer must read only the bounded header before rejecting the payload"
    );
    assert!(
        vm.memory
            .try_write_log_snapshot()
            .expect("allocate write-log snapshot")
            .is_empty()
    );
    assert!(batch_host.fastpq_batch_active);
    assert!(!batch_host.fastpq_batch_has_entries);
}
