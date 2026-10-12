// ZK envelope and batch-verification regression tests for the CoreHost.
#[test]
fn enforce_zk_envelope_maps_errors_and_ok() {
    let mut host = CoreHost::new(fixture_account("alice"));
    host.set_chain_id_bytes(b"chain".to_vec());
    host.set_current_manifest_id(Some("core".to_string()));
    let backend = "pipa-r/pasta";
    let circuit_id = crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID;
    let vk_bytes = canonical_confidential_transfer_vk_bytes();
    let commitment = CoreHost::hash_vk_bytes(backend, &vk_bytes);
    let public_inputs =
        crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1.to_vec();
    let schema_hash = schema_hash(&public_inputs);
    let rec = active_vk_record(
        commitment,
        schema_hash,
        backend,
        circuit_id,
        "transfer",
        vk_bytes.clone(),
    );
    let mut map = BTreeMap::new();
    map.insert(VerifyingKeyId::new(backend, "vk"), rec);
    host.set_verifying_keys(map).expect("set registry");
    let ok_env = dummy_env(
        circuit_id,
        commitment,
        public_inputs.clone(),
        vec![0xAA; 16],
    );
    assert!(host.enforce_zk_envelope(&ok_env, "transfer").is_ok());
    let bad_circuit_env = dummy_env(
        "halo2/ipa:wrong-circuit",
        commitment,
        public_inputs,
        vec![0xAA; 16],
    );
    assert_eq!(
        host.enforce_zk_envelope(&bad_circuit_env, "transfer"),
        Err(ivm::host::ERR_VK_MISMATCH)
    );
}
#[test]
fn enforce_zk_envelope_rejects_shared_open_verify_shape_failures() {
    let mut host = CoreHost::new(fixture_account("alice"));
    host.set_chain_id_bytes(b"chain".to_vec());
    host.set_current_manifest_id(Some("core".to_string()));
    host.pipa_r_config.max_envelope_bytes = usize::MAX;
    host.pipa_r_config.max_proof_bytes = usize::MAX;
    let backend = "pipa-r/pasta";
    let circuit_id = crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID;
    let vk_bytes = canonical_confidential_transfer_vk_bytes();
    let commitment = CoreHost::hash_vk_bytes(backend, &vk_bytes);
    let public_inputs =
        crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1.to_vec();
    let schema_hash = schema_hash(&public_inputs);
    let rec = active_vk_record(
        commitment,
        schema_hash,
        backend,
        circuit_id,
        "transfer",
        vk_bytes,
    );
    let mut map = BTreeMap::new();
    map.insert(VerifyingKeyId::new(backend, "vk"), rec);
    host.set_verifying_keys(map).expect("set registry");
    let invalid_cases: [(&str, fn(&mut iroha_data_model::zk::OpenVerifyEnvelope), u64); 10] = [
        (
            "empty circuit id",
            |env| env.circuit_id.clear(),
            ivm::host::ERR_DECODE,
        ),
        (
            "malformed circuit id",
            |env| env.circuit_id = "halo2/ipa:transfer-check\nforged".to_owned(),
            ivm::host::ERR_DECODE,
        ),
        (
            "oversized circuit id",
            |env| {
                env.circuit_id =
                    "a".repeat(iroha_data_model::zk::OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES + 1);
            },
            ivm::host::ERR_ENVELOPE_SIZE,
        ),
        (
            "zero verifier-key hash",
            |env| env.vk_hash = [0u8; 32],
            ivm::host::ERR_VK_MISSING,
        ),
        (
            "empty public inputs",
            |env| env.public_inputs.clear(),
            ivm::host::ERR_DECODE,
        ),
        (
            "all-zero public inputs",
            |env| env.public_inputs = vec![0u8; 16],
            ivm::host::ERR_DECODE,
        ),
        (
            "oversized public inputs",
            |env| {
                env.public_inputs = vec![
                    0xA5;
                    iroha_data_model::zk::OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES
                        + 1
                ];
            },
            ivm::host::ERR_ENVELOPE_SIZE,
        ),
        (
            "empty proof bytes",
            |env| env.proof_bytes.clear(),
            ivm::host::ERR_DECODE,
        ),
        (
            "all-zero proof bytes",
            |env| env.proof_bytes = vec![0u8; 16],
            ivm::host::ERR_DECODE,
        ),
        (
            "auxiliary bytes",
            |env| env.aux = b"ignored-hint".to_vec(),
            ivm::host::ERR_VK_MISMATCH,
        ),
    ];
    for (label, mutate, expected_code) in invalid_cases {
        let payload = mutated_dummy_env(
            circuit_id,
            commitment,
            public_inputs.clone(),
            vec![0xAA; 16],
            mutate,
        );
        assert_eq!(
            host.enforce_zk_envelope(&payload, "transfer"),
            Err(expected_code),
            "{label} should map to the shared validation error code"
        );
    }
    host.pipa_r_config.max_proof_bytes = 8;
    let too_large_proof = dummy_env(
        circuit_id,
        commitment,
        public_inputs,
        vec![0xAA; host.pipa_r_config.max_proof_bytes + 1],
    );
    assert_eq!(
        host.enforce_zk_envelope(&too_large_proof, "transfer"),
        Err(ivm::host::ERR_PROOF_LEN)
    );
}
#[test]
fn enforce_zk_envelope_rejects_namespace_and_manifest_replays() {
    let mut host = CoreHost::new(fixture_account("alice"));
    host.set_chain_id_bytes(b"chain".to_vec());
    host.set_current_manifest_id(Some("core".to_string()));
    let backend = "pipa-r/pasta";
    let circuit_id = crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID;
    let vk_bytes = canonical_confidential_transfer_vk_bytes();
    let commitment = CoreHost::hash_vk_bytes(backend, &vk_bytes);
    let public_inputs =
        crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1.to_vec();
    let schema_hash = schema_hash(&public_inputs);
    let rec = active_vk_record(
        commitment,
        schema_hash,
        backend,
        circuit_id,
        "ballot",
        vk_bytes.clone(),
    );
    let mut map = BTreeMap::new();
    map.insert(VerifyingKeyId::new(backend, "vk"), rec);
    host.set_verifying_keys(map).expect("set registry");
    let env = dummy_env(
        circuit_id,
        commitment,
        public_inputs.clone(),
        vec![0xAA; 16],
    );
    assert_eq!(
        host.enforce_zk_envelope(&env, "transfer"),
        Err(ivm::host::ERR_NAMESPACE)
    );
    // Switching the caller manifest also trips the manifest binding.
    let rec = active_vk_record(
        commitment,
        schema_hash,
        backend,
        circuit_id,
        "transfer",
        vk_bytes,
    );
    let mut map = BTreeMap::new();
    map.insert(VerifyingKeyId::new(backend, "vk"), rec);
    host.set_verifying_keys(map).expect("set registry");
    host.set_current_manifest_id(Some("other".to_string()));
    assert_eq!(
        host.enforce_zk_envelope(&env, "transfer"),
        Err(ivm::host::ERR_NAMESPACE)
    );
}
#[test]
fn enforce_zk_envelope_rejects_vk_metadata_mismatch() {
    let mut host = CoreHost::new(fixture_account("alice"));
    host.set_chain_id_bytes(b"chain".to_vec());
    host.set_current_manifest_id(Some("core".to_string()));
    let backend = "pipa-r/pasta";
    let circuit_id = crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID;
    let vk_bytes = canonical_confidential_transfer_vk_bytes();
    let commitment = CoreHost::hash_vk_bytes(backend, &vk_bytes);
    let public_inputs =
        crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1.to_vec();
    let schema_hash = schema_hash(&public_inputs);
    let rec = active_vk_record(
        commitment,
        schema_hash,
        backend,
        circuit_id,
        "transfer",
        vk_bytes.clone(),
    );
    let mut map = BTreeMap::new();
    map.insert(VerifyingKeyId::new(backend, "vk"), rec);
    host.set_verifying_keys(map).expect("set registry");
    // Schema hash mismatch is rejected.
    let env = dummy_env(circuit_id, commitment, vec![5u8, 6, 7, 8], vec![0xAA; 16]);
    assert_eq!(
        host.enforce_zk_envelope(&env, "transfer"),
        Err(ivm::host::ERR_VK_MISMATCH)
    );
    // Unknown vk hash is rejected explicitly.
    let env_bad_vk = dummy_env(
        circuit_id,
        [0xAA; 32],
        public_inputs.clone(),
        vec![0xAA; 16],
    );
    assert_eq!(
        host.enforce_zk_envelope(&env_bad_vk, "transfer"),
        Err(ivm::host::ERR_VK_MISSING)
    );
    host.stark_config.enabled = true;
    let env_bad_backend = mutated_dummy_env(
        circuit_id,
        commitment,
        public_inputs.clone(),
        vec![0xAA; 16],
        |env| env.backend = BackendTag::Stark,
    );
    assert_eq!(
        host.enforce_zk_envelope(&env_bad_backend, "transfer"),
        Err(ivm::host::ERR_BACKEND)
    );
    // Opaque auxiliary metadata is not admitted by the registered-key guard.
    let mut env_aux = ivm::host::decode_canonical_zk_envelope(&dummy_env(
        circuit_id,
        commitment,
        public_inputs.clone(),
        vec![0xAA; 16],
    ))
    .expect("decode dummy envelope");
    env_aux.aux = b"ignored-hint".to_vec();
    let env_aux = norito::to_bytes(&env_aux).expect("encode aux envelope");
    assert_eq!(
        host.enforce_zk_envelope(&env_aux, "transfer"),
        Err(ivm::host::ERR_VK_MISMATCH)
    );
    // Happy-path still succeeds.
    let env_ok = dummy_env(circuit_id, commitment, public_inputs, vec![0xAA; 16]);
    assert!(host.enforce_zk_envelope(&env_ok, "transfer").is_ok());
}
#[test]
fn generic_verify_proof_syscall_reports_registry_precheck_errors() {
    let mut host = CoreHost::new(fixture_account("alice"));
    host.set_chain_id_bytes(b"chain".to_vec());
    host.set_current_manifest_id(Some("core".to_string()));
    let payload = dummy_env(
        "halo2/ipa:missing-vk",
        [1u8; 32],
        vec![1u8, 2, 3, 4],
        vec![0xAA; 16],
    );
    let mut vm = IVM::new(1_000_000);
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &payload);
    vm.set_register(10, ptr);
    let gas = host
        .syscall(ivm_sys::SYSCALL_VERIFY_PROOF, &mut vm)
        .expect("generic verify proof syscall");
    assert!(gas > 0, "verification prechecks still charge proof gas");
    assert_eq!(vm.register(10), 0);
    assert_eq!(vm.register(11), ivm::host::ERR_VK_MISSING);
}
#[test]
fn unaffordable_zk_verification_stops_before_verifier_or_latch_mutation() {
    let mut host = CoreHost::new(fixture_account("alice"));
    let code = [
        ivm::encoding::wide::encode_sys(
            ivm::instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_ZK_VOTE_VERIFY_BALLOT).expect("syscall fits"),
        )
        .to_le_bytes(),
        ivm::encoding::wide::encode_halt().to_le_bytes(),
    ]
    .concat();
    let mut vm = IVM::new(20);
    vm.load_program(&build_program(&code, 0))
        .expect("load verifier program");
    let payload_ptr = store_tlv(
        &mut vm,
        PointerType::NoritoBytes,
        b"intentionally malformed proof envelope",
    );
    vm.set_register(10, payload_ptr);
    vm.set_register(11, 0xfeed);
    let error = vm
        .run_with_host(&mut host)
        .expect_err("proof gas exceeds the pre-debited reserve");
    assert_eq!(error, ivm::VMError::OutOfGas);
    assert_eq!(
        vm.remaining_gas(),
        15,
        "an unaffordable proof reserve must not be partially debited"
    );
    assert_eq!(vm.register(10), payload_ptr);
    assert_eq!(vm.register(11), 0xfeed);
    assert!(host.zk_verified_ballot.is_empty());
    assert!(host.zk_last_env_hash_ballot.is_empty());
}
#[test]
fn zk_verify_batch_quote_and_actual_scale_with_every_proof() {
    let envelope = ivm::host::decode_canonical_zk_envelope(&dummy_env(
        "halo2/ipa:metering",
        [1u8; 32],
        vec![1, 2, 3, 4],
        vec![0xAA; 16],
    ))
    .expect("decode metering envelope");
    for count in [1_usize, 3] {
        let payload =
            norito::to_bytes(&vec![envelope.clone(); count]).expect("encode metered ZK batch");
        let mut vm = IVM::new(u64::MAX);
        let pointer = store_tlv(&mut vm, PointerType::NoritoBytes, &payload);
        vm.set_register(10, pointer);
        let mut host = CoreHost::new(fixture_account("alice"));
        let expected_quote = host
            .zk_gas_schedule
            .conservative_batch_gas(count, payload.len());
        let expected_actual = host.zk_gas_schedule.actual_batch_gas(
            count,
            payload.len(),
            u64::try_from(count).expect("bounded count"),
        );
        assert_eq!(
            host.prepare_syscall(ivm_sys::SYSCALL_ZK_VERIFY_BATCH, &vm),
            Ok(expected_quote)
        );
        assert_eq!(
            host.syscall(ivm_sys::SYSCALL_ZK_VERIFY_BATCH, &mut vm),
            Ok(expected_actual)
        );
        assert!(expected_actual < expected_quote);
        assert_eq!(vm.register(11), ivm::host::ERR_VK_MISSING);
    }
}
#[test]
fn unaffordable_zk_batch_stops_before_decode_allocation_or_backend_work() {
    let envelope = ivm::host::decode_canonical_zk_envelope(&dummy_env(
        "halo2/ipa:metering",
        [1u8; 32],
        vec![1, 2, 3, 4],
        vec![0xAA; 16],
    ))
    .expect("decode metering envelope");
    let payload = norito::to_bytes(&vec![envelope.clone(), envelope]).expect("encode ZK batch");
    let code = [
        ivm::encoding::wide::encode_sys(
            ivm::instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_ZK_VERIFY_BATCH).expect("syscall fits"),
        )
        .to_le_bytes(),
        ivm::encoding::wide::encode_halt().to_le_bytes(),
    ]
    .concat();
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&build_program(&code, 0))
        .expect("load batch verifier program");
    let pointer = store_tlv(&mut vm, PointerType::NoritoBytes, &payload);
    vm.set_register(10, pointer);
    vm.set_register(11, 0xfeed);
    vm.set_register(12, 0xbeef);
    let mut host = CoreHost::new(fixture_account("alice"));
    let quote = host
        .prepare_syscall(ivm_sys::SYSCALL_ZK_VERIFY_BATCH, &vm)
        .expect("quote bounded ZK batch");
    vm.set_gas_limit(quote);
    assert_eq!(vm.run_with_host(&mut host), Err(ivm::VMError::OutOfGas));
    assert_eq!(vm.register(10), pointer);
    assert_eq!(vm.register(11), 0xfeed);
    assert_eq!(vm.register(12), 0xbeef);
}
#[test]
fn zk_verify_batch_rejects_configured_count_cap_after_metered_prepare() {
    let envelope = ivm::host::decode_canonical_zk_envelope(&dummy_env(
        "halo2/ipa:metering",
        [1u8; 32],
        vec![1, 2, 3, 4],
        vec![0xAA; 16],
    ))
    .expect("decode metering envelope");
    let payload =
        norito::to_bytes(&vec![envelope.clone(), envelope]).expect("encode over-limit ZK batch");
    let mut vm = IVM::new(u64::MAX);
    let pointer = store_tlv(&mut vm, PointerType::NoritoBytes, &payload);
    vm.set_register(10, pointer);
    let mut host = CoreHost::new(fixture_account("alice"));
    host.zk_verify_limits.max_verify_batch = 1;
    let quote = host
        .prepare_syscall(ivm_sys::SYSCALL_ZK_VERIFY_BATCH, &vm)
        .expect("count rejection must still reserve gas");
    assert_eq!(
        quote,
        host.zk_gas_schedule
            .conservative_batch_gas(2, payload.len())
    );
    assert_eq!(vm.register(10), pointer);
    assert_eq!(
        host.syscall(ivm_sys::SYSCALL_ZK_VERIFY_BATCH, &mut vm),
        Ok(quote)
    );
    assert_eq!(vm.register(10), 0);
    assert_eq!(vm.register(11), ivm::host::ERR_BATCH);
    assert_eq!(vm.register(12), u64::MAX);
}
#[test]
fn generic_verify_proof_syscall_rejects_injected_non_production_vk_snapshot() {
    for backend in [
        "halo2/mock",
        "halo2/ipa:production-ready",
        "halo2/unknown-native-v1",
    ] {
        let mut host = CoreHost::new(fixture_account("alice"));
        host.set_chain_id_bytes(b"chain".to_vec());
        host.set_current_manifest_id(Some("core".to_string()));
        let circuit_id = format!("{backend}:rejected-circuit");
        let public_inputs = vec![1u8, 2, 3, 4];
        let vk_bytes = vec![4, 3, 2, 1];
        let commitment = CoreHost::hash_vk_bytes(backend, &vk_bytes);
        let rec = active_vk_record(
            commitment,
            schema_hash(&public_inputs),
            backend,
            &circuit_id,
            "core",
            vk_bytes,
        );
        let record = Arc::new(rec);
        host.verifying_keys
            .insert(VerifyingKeyId::new(backend, "vk"), Arc::clone(&record));
        host.prepared_verifying_keys.insert(
            commitment,
            PreparedVerifyingKey {
                record,
                backend_label: Arc::from(backend),
                material: None,
            },
        );
        let payload = dummy_env(&circuit_id, commitment, public_inputs, vec![0xAA; 16]);
        let mut vm = IVM::new(1_000_000);
        let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &payload);
        vm.set_register(10, ptr);
        let gas = host
            .syscall(ivm_sys::SYSCALL_VERIFY_PROOF, &mut vm)
            .expect("generic verify proof syscall");
        assert!(
            gas > 0,
            "verification prechecks still charge proof gas for {backend}"
        );
        assert_eq!(vm.register(10), 0, "case {backend} must fail");
        assert_eq!(
            vm.register(11),
            ivm::host::ERR_BACKEND,
            "case {backend} must fail as backend admission"
        );
    }
}
#[test]
fn generic_verify_proof_revalidates_injected_native_material_at_dispatch() {
    let backend = "pipa-r/pasta";
    let circuit_id = crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID;
    let public_inputs = vec![1_u8, 2, 3, 4];
    let mut vk_bytes = b"ZK1\0H2VK".to_vec();
    vk_bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    let commitment = CoreHost::hash_vk_bytes(backend, &vk_bytes);
    let record = Arc::new(active_vk_record(
        commitment,
        schema_hash(&public_inputs),
        backend,
        circuit_id,
        "core",
        vk_bytes,
    ));
    let mut host = CoreHost::new(fixture_account("alice"));
    host.set_chain_id_bytes(b"chain".to_vec());
    host.set_current_manifest_id(Some("core".to_owned()));
    // Simulate a corrupt in-memory snapshot that bypassed installation.
    // Dispatch must still invoke the shared strict material validator.
    host.verifying_keys.insert(
        VerifyingKeyId::new(backend, "forged-inline-key"),
        Arc::clone(&record),
    );
    host.prepared_verifying_keys.insert(
        commitment,
        PreparedVerifyingKey {
            record,
            backend_label: Arc::from(backend),
            material: Some(
                crate::zk::PreparedVerifyingKeyMaterialV1::NativePipaRPasta {
                    ipa_k: crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_IPA_K,
                },
            ),
        },
    );
    let payload = dummy_env(circuit_id, commitment, public_inputs, vec![0xAA; 16]);
    let mut vm = IVM::new(1_000_000);
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &payload);
    vm.set_register(10, ptr);
    host.syscall(ivm_sys::SYSCALL_VERIFY_PROOF, &mut vm)
        .expect("malformed key is a reported verification failure");
    assert_eq!(vm.register(10), 0);
    assert_eq!(vm.register(11), ivm::host::ERR_VERIFY);
}
#[cfg(feature = "zk-stark")]
#[test]
fn zk_verify_batch_accepts_stark_registry_bound_envelope() {
    let mut host = CoreHost::new(fixture_account("alice"));
    host.set_chain_id_bytes(b"chain".to_vec());
    host.set_current_manifest_id(Some("core".to_string()));
    let mut stark_cfg = iroha_config::parameters::actual::Stark::default();
    stark_cfg.enabled = true;
    host.set_stark_config(&stark_cfg);
    let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
    // This checks generic proof dispatch through a host syscall, not an IVM
    // execution relation. The unavailable IVM namespace must remain reserved.
    assert!(!crate::zk::stark_open_verify_circuit_id_matches_backend(
        backend,
        "stark/fri/poseidon-x7-goldilocks-6x64-v1:ivm-syscall",
    ));
    let circuit_id = "stark/fri/poseidon-x7-goldilocks-6x64-v1:host-syscall-batch-v1";
    assert!(crate::zk::stark_open_verify_circuit_id_matches_backend(
        backend, circuit_id,
    ));
    let vk_payload = crate::zk_stark::StarkFriVerifyingKeyV1 {
        version: 1,
        circuit_id: circuit_id.to_string(),
        n_log2: crate::zk_stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
        blowup_log2: crate::zk_stark::STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
        fold_arity: 2,
        queries: crate::zk_stark::STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
    };
    let vk_bytes = norito::encode_canonical(&vk_payload).expect("encode canonical STARK vk");
    let vk_box = VerifyingKeyBox::new(backend.into(), vk_bytes.clone());
    let schema_descriptor = b"host-syscall-batch-schema-v1";
    let proof = crate::zk::prove_stark_fri_open_verify_envelope(
        backend,
        circuit_id,
        &vk_box,
        schema_descriptor,
        vec![vec![[7u8; 32]]],
    )
    .expect("prove STARK envelope");
    let env =
        ivm::host::decode_canonical_zk_envelope(&proof.bytes).expect("decode OpenVerifyEnvelope");
    let commitment = crate::zk::hash_vk(&vk_box);
    let rec = active_vk_record(
        commitment,
        schema_hash(schema_descriptor),
        backend,
        circuit_id,
        "transfer",
        vk_bytes,
    );
    let mut map = BTreeMap::new();
    map.insert(VerifyingKeyId::new(backend, "vk_stark"), rec);
    host.set_verifying_keys(map).expect("set registry");
    let payload = norito::to_bytes(&vec![env]).expect("encode batch");
    let mut vm = IVM::new(50_000_000);
    let tlv = make_tlv(PointerType::NoritoBytes as u16, &payload);
    let ptr = vm
        .alloc_heap(tlv.len() as u64)
        .expect("allocate STARK batch TLV");
    vm.store_bytes(ptr, &tlv).expect("store STARK batch TLV");
    vm.set_register(10, ptr);
    host.syscall(ivm_sys::SYSCALL_ZK_VERIFY_BATCH, &mut vm)
        .expect("batch verify");
    let out_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("output tlv");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    let statuses: Vec<u8> = norito::decode_from_bytes(tlv.payload).expect("decode statuses");
    assert_eq!(statuses, vec![1]);
    assert_eq!(vm.register(11), 0);
    assert_eq!(vm.register(12), u64::MAX);
}
#[cfg(feature = "zk-stark")]
#[test]
fn zk_verify_batch_returns_statuses_with_registry_binding() {
    let mut host = CoreHost::new(fixture_account("alice"));
    host.set_chain_id_bytes(b"chain".to_vec());
    host.set_current_manifest_id(Some("core".to_string()));
    let mut stark_cfg = iroha_config::parameters::actual::Stark::default();
    stark_cfg.enabled = true;
    host.set_stark_config(&stark_cfg);
    let env_ok = registered_stark_batch_fixture(&mut host, "transfer");
    assert!(
        !env_ok.public_inputs.is_empty(),
        "fixture circuit must expose public inputs for schema mismatch coverage"
    );
    let mut env_bad = env_ok.clone();
    env_bad.public_inputs[0] ^= 0x01;
    env_bad.proof_bytes = vec![0x01];
    let payload = norito::to_bytes(&vec![env_ok, env_bad]).expect("encode batch");
    let mut vm = IVM::new(50_000_000);
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &payload);
    vm.set_register(10, ptr);
    host.syscall(ivm_sys::SYSCALL_ZK_VERIFY_BATCH, &mut vm)
        .expect("batch verify");
    let out_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("output tlv");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    let statuses: Vec<u8> = norito::decode_from_bytes(tlv.payload).expect("decode statuses");
    assert_eq!(statuses, vec![1, 0]);
    assert_eq!(vm.register(11), ivm::host::ERR_VK_MISMATCH);
    assert_eq!(vm.register(12), 1);
}
#[cfg(feature = "zk-stark")]
#[test]
fn zk_verify_batch_reports_backend_verifier_failure_after_prechecks() {
    let mut host = CoreHost::new(fixture_account("alice"));
    host.set_chain_id_bytes(b"chain".to_vec());
    host.set_current_manifest_id(Some("core".to_string()));
    let mut stark_cfg = iroha_config::parameters::actual::Stark::default();
    stark_cfg.enabled = true;
    host.set_stark_config(&stark_cfg);
    let env_ok = registered_stark_batch_fixture(&mut host, "transfer");
    let mut env_bad = env_ok.clone();
    let mut malformed: iroha_data_model::zk::StarkFriOpenProofV1 =
        norito::decode_canonical(&env_ok.proof_bytes).expect("decode native STARK wrapper");
    malformed.envelope_bytes = vec![0x01];
    env_bad.proof_bytes = norito::encode_canonical(&malformed).expect("encode malformed wrapper");
    let payload = norito::to_bytes(&vec![env_ok, env_bad]).expect("encode batch");
    let mut vm = IVM::new(50_000_000);
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &payload);
    vm.set_register(10, ptr);
    host.syscall(ivm_sys::SYSCALL_ZK_VERIFY_BATCH, &mut vm)
        .expect("batch verify");
    let out_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("output tlv");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    let statuses: Vec<u8> = norito::decode_from_bytes(tlv.payload).expect("decode statuses");
    assert_eq!(statuses, vec![1, 0]);
    assert_eq!(vm.register(11), ivm::host::ERR_VERIFY);
    assert_eq!(vm.register(12), 1);
}
#[test]
fn zk_verify_batch_reports_first_error_for_dummy_payloads() {
    let mut host = CoreHost::new(fixture_account("alice"));
    host.set_chain_id_bytes(b"chain".to_vec());
    host.set_current_manifest_id(Some("core".to_string()));
    let backend = "pipa-r/pasta";
    let circuit_id = crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID;
    let vk_bytes = canonical_confidential_transfer_vk_bytes();
    let commitment = CoreHost::hash_vk_bytes(backend, &vk_bytes);
    let public_inputs =
        crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1.to_vec();
    let schema_hash = schema_hash(&public_inputs);
    let rec = active_vk_record(
        commitment,
        schema_hash,
        backend,
        circuit_id,
        "transfer",
        vk_bytes.clone(),
    );
    let mut map = BTreeMap::new();
    map.insert(VerifyingKeyId::new(backend, "vk"), rec);
    host.set_verifying_keys(map).expect("set registry");
    let env_bytes = dummy_env(circuit_id, commitment, public_inputs, vec![0xAA; 16]);
    let env = ivm::host::decode_canonical_zk_envelope(&env_bytes).expect("decode envelope");
    let payload = norito::to_bytes(&vec![env]).expect("encode batch");
    let mut vm = IVM::new(1_000_000);
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &payload);
    vm.set_register(10, ptr);
    host.syscall(ivm_sys::SYSCALL_ZK_VERIFY_BATCH, &mut vm)
        .expect("batch verify");
    let out_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("output tlv");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    let statuses: Vec<u8> = norito::decode_from_bytes(tlv.payload).expect("decode statuses");
    assert_eq!(statuses, vec![0]);
    assert_eq!(vm.register(11), ivm::host::ERR_VERIFY);
    assert_eq!(vm.register(12), 0);
}

#[test]
fn queued_ballot_and_tally_require_their_distinct_verification_latches() {
    let attachment = || {
        iroha_data_model::proof::ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            iroha_data_model::proof::ProofBox::new("pipa-r/pasta".into(), vec![0xAB; 32]),
            VerifyingKeyId::new("pipa-r/pasta", "fixture"),
        )
    };
    let ballot: InstructionBox = DMZk::SubmitBallot {
        election_id: "election1".into(),
        ciphertext: vec![0; 32],
        ballot_proof: attachment(),
        nullifier: [1; 32],
    }
    .into();
    let tally: InstructionBox = DMZk::FinalizeElection {
        election_id: "election1".into(),
        tally: vec![1, 0, 0],
        tally_proof: attachment(),
    }
    .into();
    for (instruction, expected) in [
        (
            ballot,
            "missing ZK_VOTE_VERIFY_BALLOT prior to SubmitBallot",
        ),
        (
            tally,
            "missing ZK_VOTE_VERIFY_TALLY prior to FinalizeElection",
        ),
    ] {
        let mut host = CoreHost::new(fixture_account("alice"));
        assert_eq!(
            host.validate_queued_for_zk(&[instruction]),
            Err(ValidationFail::NotPermitted(expected.into()))
        );
    }
}

/// The host reads native proof-size limits from the committed policy, independently of node limits.
#[test]
fn committed_native_proof_limit_accepts_exact_bound_and_rejects_one_more() {
    use iroha_data_model::{parameter::Parameter, zk_validity_policy::ZkValidityPolicyV1};

    let backend = "pipa-r/pasta";
    let circuit_id = crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID;
    let vk_bytes = canonical_confidential_transfer_vk_bytes();
    let commitment = CoreHost::hash_vk_bytes(backend, &vk_bytes);
    let public_inputs =
        crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1.to_vec();
    for node_limit in [1, 16, 1_000] {
        let mut policy = ZkValidityPolicyV1::protocol_default();
        policy.pipa_r.max_proof_bytes = 16;
        let world = crate::state::World::default();
        {
            let mut block = world.block();
            block
                .parameters
                .get_mut()
                .set_parameter(Parameter::Custom(policy.into_custom_parameter()))
                .expect("valid fixture parameters");
            block.commit();
        }
        let mut state = crate::state::State::new_for_testing(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut node = crate::state::default_zk_config();
        node.pipa_r.max_proof_bytes = node_limit;
        state.install_node_zk(node).expect("install node resources");
        let block = state.block(iroha_data_model::block::BlockHeader::new(
            core::num::NonZeroU64::new(2).expect("nonzero"),
            None,
            None,
            0,
            0,
        ));
        assert_eq!(block.zk.pipa_r.max_proof_bytes, 16);
        let mut host = CoreHost::new(fixture_account("alice"));
        host.set_chain_id_bytes(b"chain".to_vec());
        host.set_current_manifest_id(Some("core".to_owned()));
        let record = active_vk_record(
            commitment,
            schema_hash(&public_inputs),
            backend,
            circuit_id,
            "transfer",
            vk_bytes.clone(),
        );
        host.set_verifying_keys(BTreeMap::from([(
            VerifyingKeyId::new(backend, "vk"),
            record,
        )]))
        .expect("install registry");
        host.set_zk_config(&block.zk);
        let at_limit = dummy_env(
            circuit_id,
            commitment,
            public_inputs.clone(),
            vec![0xAA; 16],
        );
        assert!(host.enforce_zk_envelope(&at_limit, "transfer").is_ok());
        let above_limit = dummy_env(
            circuit_id,
            commitment,
            public_inputs.clone(),
            vec![0xAA; 17],
        );
        assert_eq!(
            host.enforce_zk_envelope(&above_limit, "transfer").err(),
            Some(ivm::host::ERR_PROOF_LEN)
        );
    }
}
