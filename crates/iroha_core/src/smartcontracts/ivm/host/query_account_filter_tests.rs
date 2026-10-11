// Account-filter scratch is retained through query input use and refuses locally.
#[test]
fn core_query_account_filter_retains_original_vm_pool_until_input_is_dropped() {
    let pool = iroha_allocation::AllocationBudget::new(256 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(1_000_000, &pool).unwrap();
    let account = fixture_account("alice");
    let pointer = store_tlv(
        &mut vm,
        PointerType::AccountId,
        &norito::encode_canonical(&account).unwrap(),
    );
    // Warm the VM-owned memory-read log separately from decoded filter custody.
    drop(CoreQueryAccountFilter::decode(&vm, pointer).unwrap());
    vm.memory.clear_tracking();
    let baseline = pool.reserved_bytes();
    pool.set_limit_bytes(baseline);
    let error = CoreQueryAccountFilter::decode(&vm, pointer)
        .err()
        .expect("local refusal");
    assert!(matches!(error, ivm::VMError::AllocationDeferred(_)));
    assert_eq!(error.metered_gas(), None);
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(256 * 1024 * 1024);
    vm.memory.clear_tracking();
    let mut filter = CoreQueryAccountFilter::decode(&vm, pointer).unwrap();
    assert!(pool.reserved_bytes() > baseline);
    let decoded = filter.account.take().unwrap();
    assert_eq!(decoded, account);
    assert!(
        pool.reserved_bytes() > baseline,
        "input remains covered after transfer into query"
    );
    drop(decoded);
    drop(filter);
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(vm);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn core_query_account_filter_rejects_wrong_pointer_and_noncanonical_account() {
    let mut vm = IVM::new(1_000_000);
    for (pointer_type, bytes) in [
        (
            PointerType::Blob,
            norito::encode_canonical(&fixture_account("alice")).unwrap(),
        ),
        (PointerType::AccountId, b"not an AccountId".to_vec()),
    ] {
        let pointer = store_tlv(&mut vm, pointer_type, &bytes);
        assert!(matches!(
            CoreQueryAccountFilter::decode(&vm, pointer),
            Err(ivm::VMError::DecodeError)
        ));
    }
}
