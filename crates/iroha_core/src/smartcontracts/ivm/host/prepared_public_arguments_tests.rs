#[test]
#[cfg(debug_assertions)]
fn prepared_public_arguments_decode_once_ignore_guest_descriptors_and_require_precharge() {
    let compiler = kotodama_lang::compiler::Compiler::new_with_options(
        kotodama_lang::compiler::CompilerOptions {
            mode: kotodama_lang::compiler::CompilerMode::Production,
            ..kotodama_lang::compiler::CompilerOptions::default()
        },
    );
    let (program, _) = compiler
        .compile_source_with_manifest(
            r"
seiyaku PreparedArguments { permission Invoke;
  kotoage fn invoke(int count, Name label) authorize(Invoke) {
  }
}
",
        )
        .expect("compile parameterized contract");
    let metadata = ivm::ProgramMetadata::parse(&program).expect("parse contract metadata");
    let schema = metadata
        .contract_interface
        .as_ref()
        .expect("contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "invoke")
        .and_then(|entrypoint| entrypoint.argument_schema.as_ref())
        .expect("argument schema");
    let canonical = ivm_abi::arguments::encode_argument_record_from_json(
        schema,
        &Json::from(norito::json!({"count": "7", "label": "ready"})),
    )
    .expect("encode arguments");
    ivm::reset_argument_record_decode_count();
    let prepared =
        ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), u64::MAX)
            .expect("prepare arguments");
    let authority: AccountId = fixture_account("alice");
    let mut host = CoreHost::with_accounts_and_argument_record(
        authority.clone(),
        Arc::new(vec![authority.clone()]),
        Some(prepared.clone()),
    );
    let mut vm = IVM::new(100_000);
    vm.load_program(&program).expect("load table ABI contract");
    let descriptor = metadata
        .contract_interface
        .as_ref()
        .unwrap()
        .entrypoints
        .iter()
        .find(|entry| entry.name == "invoke")
        .unwrap();
    let entry_pc = metadata.prefix_len() as u64 + descriptor.entry_pc;
    vm.set_program_counter(entry_pc).unwrap();
    // Arbitrary guest-facing descriptors cannot substitute for the signed host record.
    vm.set_register(10, u64::MAX);
    vm.set_register(11, 8193);
    vm.set_register(12, 1);
    vm.set_register(13, 0);
    prepared
        .precharge_vm(&mut vm)
        .expect("precharge prepared arguments");
    vm.run_with_host(&mut host)
        .expect("host prepares the authenticated root tables");
    assert_eq!(ivm::argument_record_decode_count(), 1);
    assert_eq!(vm.call_result_word_count().unwrap(), 1);
    assert_eq!(vm.public_call_result_word(0).unwrap(), 0);

    let mut unpaid = IVM::new(100_000);
    unpaid.load_program(&program).unwrap();
    unpaid.set_program_counter(entry_pc).unwrap();
    assert_eq!(unpaid.run_with_host(&mut host), Err(VMError::DecodeError));
    assert!(unpaid.call_result_word_count().is_err());
    assert_eq!(ivm::argument_record_decode_count(), 1);
}

#[test]
#[cfg(debug_assertions)]
fn prepared_root_arguments_and_trigger_event_json_remain_distinct() {
    let (program, _) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(
            r"
seiyaku PreparedArgumentEventProbe {
  error enum ProbeError { WrongCount = 1 }
  kotoage fn invoke(int count) authorize(anyone) {
    require(count == 7, ProbeError::WrongCount);
  }
}
",
        )
        .expect("compile parameter-consuming root probe");
    let metadata = ivm::ProgramMetadata::parse(&program).expect("parse root probe");
    let descriptor = metadata
        .contract_interface
        .as_ref()
        .expect("probe contract interface")
        .entrypoints
        .iter()
        .find(|entry| entry.name == "invoke")
        .expect("probe entrypoint");
    let schema = descriptor.argument_schema.as_ref().expect("probe schema");
    let args = Json::from(norito::json!({"count": "7"}));
    let original_json = args.get().as_ptr();
    let canonical = ivm_abi::arguments::encode_argument_record_from_json(schema, &args)
        .expect("encode canonical probe arguments");
    ivm::reset_argument_record_decode_count();
    let prepared =
        ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), u64::MAX)
            .expect("prepare original root arguments");
    let original_record = prepared.canonical_bytes().as_ptr();
    let authority: AccountId = fixture_account("alice");
    let mut host = CoreHost::with_accounts_and_args(
        authority.clone(),
        Arc::new(vec![authority.clone()]),
        args.clone(),
    );
    host.set_entrypoint_argument_record(Some(prepared.clone()));
    assert_eq!(
        host.prepared_entrypoint_arguments()
            .expect("host retains prepared root arguments")
            .canonical_bytes()
            .as_ptr(),
        original_record,
        "the event context must not replace the original prepared argument owner"
    );
    let mut vm = IVM::new(100_000);
    vm.load_program(&program)
        .expect("load parameter-consuming root");
    vm.set_program_counter(metadata.prefix_len() as u64 + descriptor.entry_pc)
        .expect("seek actual root entrypoint");
    prepared
        .precharge_vm(&mut vm)
        .expect("precharge original arguments");
    vm.run_with_host(&mut host)
        .expect("canonical root tables supply the original typed parameter");
    assert_eq!(ivm::argument_record_decode_count(), 1);
    assert_eq!(vm.call_result_word_count().unwrap(), 1);
    assert_eq!(vm.public_call_result_word(0).unwrap(), 0);

    let mut event_vm = IVM::new(10_000);
    let name: Name = TRIGGER_EVENT_PUBLIC_INPUT_KEY.parse().unwrap();
    let name_ptr = store_tlv(&mut event_vm, PointerType::Name, &norito_blob(&name));
    event_vm.set_register(10, name_ptr);
    let quote = host
        .prepare_syscall(ivm_sys::SYSCALL_GET_PUBLIC_INPUT, &event_vm)
        .expect("quote actual firing event");
    let gas = host
        .syscall(ivm_sys::SYSCALL_GET_PUBLIC_INPUT, &mut event_vm)
        .expect("prepared arguments must not hide the firing JSON");
    let event_tlv = event_vm
        .memory
        .validate_tlv(event_vm.register(10))
        .expect("authenticated event TLV");
    assert_eq!(event_tlv.type_id, PointerType::Json);
    let decoded: Json = norito::decode_from_bytes(event_tlv.payload).expect("decode event JSON");
    assert_eq!(decoded, args);
    assert_eq!(
        host.args
            .as_ref()
            .expect("original event remains owned")
            .get()
            .as_ptr(),
        original_json,
        "installing prepared arguments must retain the original firing JSON backing"
    );
    let expected_tlv = make_tlv(PointerType::Json as u16, &norito_blob(&args));
    assert_eq!(
        gas,
        PUBLIC_INPUT_GAS_BASE_DEFAULT.saturating_add(
            PUBLIC_INPUT_GAS_PER_BYTE_DEFAULT
                .saturating_mul(u64::try_from(expected_tlv.len()).unwrap()),
        )
    );
    assert_eq!(quote, event_vm.remaining_gas());
    assert!(gas <= quote);
    assert_eq!(ivm::argument_record_decode_count(), 1);

    // A prepared record alone is not an event; the event API must not expose it.
    let mut record_only_host = CoreHost::with_accounts_and_argument_record(
        authority.clone(),
        Arc::new(vec![authority]),
        Some(prepared),
    );
    let mut absent_vm = IVM::new(10_000);
    let name_ptr = store_tlv(&mut absent_vm, PointerType::Name, &norito_blob(&name));
    absent_vm.set_register(10, name_ptr);
    record_only_host
        .prepare_syscall(ivm_sys::SYSCALL_GET_PUBLIC_INPUT, &absent_vm)
        .expect("quote missing event");
    assert_eq!(
        record_only_host.syscall(ivm_sys::SYSCALL_GET_PUBLIC_INPUT, &mut absent_vm),
        Err(VMError::PermissionDenied)
    );
    assert_eq!(ivm::argument_record_decode_count(), 1);
}
