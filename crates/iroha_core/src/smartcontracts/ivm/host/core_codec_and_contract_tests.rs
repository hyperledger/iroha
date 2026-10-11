// Same-scope regression coverage extracted to keep the parent source budget bounded.
#[test]
fn host_codec_bytes_hash_gas_and_lengths_ignore_ambient_layout() {
    let value = vec!["first".to_owned(), "second".to_owned()];
    let canonical = CoreHost::encode_norito_payload(&value).expect("encode canonical host payload");
    let canonical_hash = Hash::new(&canonical);
    let canonical_gas = CoreHost::state_query_gas(canonical.len());
    assert_eq!(
        CoreHost::norito_encoded_len_exact(&value),
        Some(u64::try_from(canonical.len()).expect("fixture length fits u64"))
    );
    let canonical_retained_bytes = {
        let mut host = CoreHost::new(ALICE_ID.clone());
        host.restrict_output_limits(HostOutputLimits::new(1, u64::MAX));
        assert!(host.try_reserve_serialized_output(&value, 1));
        host.retained_output_bytes()
    };
    let name: Name = "state_input".parse().expect("valid public-input name");
    let canonical_name = CoreHost::encode_norito_payload(&name).expect("encode canonical Name");
    let path: StatePath = "state/first".parse().expect("valid state path");
    let canonical_path =
        CoreHost::encode_norito_payload(&path).expect("encode canonical StatePath");
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    let ambient_before = norito::to_bytes(&value).expect("encode payload under ambient layout");
    assert_ne!(ambient_before, canonical);
    let alternate_name = norito::to_bytes(&name).expect("encode Name under alternate layout");
    assert_ne!(alternate_name, canonical_name);
    let alternate_path = norito::to_bytes(&path).expect("encode StatePath under alternate layout");
    assert_ne!(alternate_path, canonical_path);
    let encoded_under_ambient =
        CoreHost::encode_norito_payload(&value).expect("encode host payload canonically");
    assert_eq!(encoded_under_ambient, canonical);
    assert_eq!(Hash::new(&encoded_under_ambient), canonical_hash);
    assert_eq!(
        CoreHost::state_query_gas(encoded_under_ambient.len()),
        canonical_gas
    );
    assert_eq!(
        CoreHost::norito_encoded_len_exact(&value),
        Some(u64::try_from(canonical.len()).expect("fixture length fits u64"))
    );
    let retained_under_ambient = {
        let mut host = CoreHost::new(ALICE_ID.clone());
        host.restrict_output_limits(HostOutputLimits::new(1, u64::MAX));
        assert!(host.try_reserve_serialized_output(&value, 1));
        host.retained_output_bytes()
    };
    assert_eq!(retained_under_ambient, canonical_retained_bytes);
    assert_eq!(
        CoreHost::decode_name_payload(&canonical_name)
            .expect("decode canonical Name under ambient layout"),
        name
    );
    assert_eq!(
        CoreHost::decode_name_payload(&alternate_name),
        Err(ivm::VMError::DecodeError)
    );
    assert_eq!(
        decode_canonical_norito::<StatePath>(&canonical_path)
            .expect("decode canonical StatePath under ambient layout"),
        path
    );
    assert!(
        decode_canonical_norito::<StatePath>(&alternate_path).is_err(),
        "ambient StatePath framing must not pass canonical decoding"
    );
    assert_eq!(
        norito::to_bytes(&value).expect("re-encode payload under ambient layout"),
        ambient_before,
        "canonical helpers must restore the caller's ambient layout"
    );
    drop(ambient);
    assert_eq!(
        norito::to_bytes(&value).expect("encode payload after ambient guard"),
        canonical
    );
}
fn exact_return_type(
    kind: iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1,
) -> iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
        nodes: vec![
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(kind),
        ],
    }
}
pub(super) fn store_tlv(vm: &mut IVM, ty: PointerType, payload: &[u8]) -> u64 {
    let tlv = make_tlv(ty as u16, payload);
    vm.alloc_host_tlv(&tlv)
        .expect("allocate VM-owned TLV input")
}
pub(super) fn quantity_frame(value: &Quantity) -> Vec<u8> {
    QuantityValueV1::new(value.clone())
        .encode_frame()
        .expect("encode quantity frame")
}
pub(super) fn store_quantity(vm: &mut IVM, value: &Quantity) -> u64 {
    store_tlv(vm, PointerType::Quantity, &quantity_frame(value))
}
fn read_option_words(vm: &IVM, handle: u64, some_words: u64) -> (bool, Vec<u64>) {
    let layout = ivm::sum::SumLayoutV1::option(some_words).expect("option layout");
    ivm::sum::read_words(vm, handle, layout).expect("read option handle")
}
fn read_option_int(vm: &IVM, handle: u64) -> Option<i64> {
    let (present, words) = read_option_words(vm, handle, 1);
    if !present {
        assert!(words.is_empty(), "Option::none cannot carry inactive words");
        return None;
    }
    let [pointer] = words.as_slice() else {
        panic!("Option<int>::some must carry exactly one pointer")
    };
    let tlv = vm
        .memory
        .validate_tlv(*pointer)
        .expect("next-offset int TLV");
    assert_eq!(tlv.type_id, PointerType::Int);
    Some(
        IntValueV1::decode_frame(tlv.payload)
            .expect("decode next-offset int")
            .into_int()
            .try_to_i64()
            .expect("query next offset fits i64"),
    )
}
fn decode_typed_leaf<T>(vm: &IVM, pointer: u64, expected: PointerType) -> T
where
    for<'de> T: NoritoDeserialize<'de> + norito::NoritoSerialize,
{
    let tlv = vm.memory.validate_tlv(pointer).expect("typed leaf TLV");
    assert_eq!(tlv.type_id, expected);
    norito::decode_from_bytes(tlv.payload).expect("decode typed leaf")
}
fn decode_quantity_leaf(vm: &IVM, pointer: u64) -> Quantity {
    let tlv = vm.memory.validate_tlv(pointer).expect("quantity leaf TLV");
    assert_eq!(tlv.type_id, PointerType::Quantity);
    QuantityValueV1::decode_frame(tlv.payload)
        .expect("decode quantity leaf")
        .into_quantity()
}
fn seed_test_call_hash(tx: &mut StateTransaction<'_, '_>, byte: u8) {
    tx.tx_call_hash = Some(Hash::prehashed([byte; Hash::LENGTH]));
}
fn fixture_domain_id() -> DomainId {
    DomainId::try_new("wonderland", "universal").expect("fixture domain id")
}
fn fixture_account(label: &str) -> AccountId {
    match label {
        "alice" => ALICE_ID.clone(),
        "bob" => BOB_ID.clone(),
        "carol" | "charlie" => {
            let seed: Vec<u8> = label.as_bytes().iter().copied().cycle().take(32).collect();
            AccountId::new(fixture_public_key_from_seed(seed))
        }
        other => panic!("unsupported fixture account label: {other}"),
    }
}
fn local_contract_host(authority: AccountId) -> CoreHost {
    let mut host = CoreHost::new(authority);
    host.set_local_contract_debug_execution();
    host
}
fn authenticated_test_probe_prologue() -> [u32; 6] {
    use ivm::{
        encoding::wide,
        instruction::wide::{arithmetic, memory},
    };
    [
        wide::encode_ri(arithmetic::ADDI, 31, 31, -16),
        wide::encode_store(memory::STORE64, 31, 12, 0),
        wide::encode_store(memory::STORE64, 31, 1, 8),
        wide::encode_ri(arithmetic::ADDI, 10, 14, 0),
        wide::encode_ri(arithmetic::ADDI, 11, 15, 0),
        wide::encode_ri(arithmetic::ADDI, 12, 16, 0),
    ]
}
fn authenticated_test_probe_setup_gas() -> u64 {
    // Eight root result bytes and three frame/result initialization-bitmap words.
    8 + 3
        + authenticated_test_probe_prologue()
            .into_iter()
            .map(|instruction| ivm::gas::cost_of(instruction).unwrap())
            .sum::<u64>()
}
fn authenticated_test_probe_result(vm: &IVM) -> u64 {
    assert_eq!(vm.call_result_word_count().unwrap(), 1);
    assert_eq!(vm.public_call_result_word(0).unwrap(), 0);
    // The probe snapshots the syscall's r10 before returning its separate Unit table.
    vm.register(17)
}
fn build_authenticated_test_contract_program(
    code: &[u8],
    vector_length: u8,
    zk_mode: bool,
) -> Vec<u8> {
    build_authenticated_test_contract_program_with_states(code, vector_length, zk_mode, Vec::new())
}
fn build_authenticated_test_contract_program_with_states(
    code: &[u8],
    vector_length: u8,
    zk_mode: bool,
    states: Vec<ivm::EmbeddedStateDescriptor>,
) -> Vec<u8> {
    assert!(code.len().is_multiple_of(4));
    assert!(
        code.chunks_exact(4)
            .all(|word| u32::from_le_bytes(word.try_into().unwrap())
                != ivm::encoding::wide::encode_halt())
    );
    let contract_interface = ivm::EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: Vec::new(),
        callables: vec![ivm::call::EmbeddedCallableV1 {
            entry_pc: 0,
            frame_bytes: 16,
            arguments: ivm::call::CallSchemaV1::empty(),
            results: ivm::call::CallSchemaV1::unit(),
        }],
        seiyaku_name: "CoreHostHarness".to_owned(),
        compiler_fingerprint: "iroha-core-host-tests".to_owned(),
        abi_hash: ivm_sys::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: if zk_mode {
            ivm::CONTRACT_FEATURE_BIT_ZK
        } else {
            0
        },
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: "main".to_owned(),
            kind: iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: EntrypointAuthorizationV1::Anyone,
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: None,
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
        states,
        error_messages: Vec::new(),
        error_types: Vec::new(),
    };
    let mut program = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: if zk_mode { ivm::ivm_mode::ZK } else { 0 },
        vector_length,
        max_cycles: 1_000_000,
        abi_version: 1,
    }
    .encode();
    program.extend_from_slice(&contract_interface.encode_section());
    // These raw syscall probes have no language arguments. The test owner stages
    // syscall operands in r14-r16; fixture bytecode copies them only after the VM
    // establishes authenticated root tables and saves their result descriptor.
    for instruction in authenticated_test_probe_prologue() {
        program.extend_from_slice(&instruction.to_le_bytes());
    }
    program.extend_from_slice(code);
    use ivm::{
        encoding::wide,
        instruction::wide::{arithmetic, control, memory},
    };
    for instruction in [
        wide::encode_ri(arithmetic::ADDI, 17, 10, 0),
        wide::encode_load(memory::LOAD64, 25, 31, 0),
        wide::encode_load(memory::LOAD64, 1, 31, 8),
        wide::encode_store(memory::STORE64, 25, 0, 0),
        wide::encode_ri(arithmetic::ADDI, 10, 25, 0),
        wide::encode_ri(arithmetic::ADDI, 11, 0, 1),
        wide::encode_ri(arithmetic::ADDI, 31, 31, 16),
        wide::encode_rr(control::JALR, 0, 1, 0),
    ] {
        program.extend_from_slice(&instruction.to_le_bytes());
    }
    program
}
#[test]
fn authenticated_test_probe_completes_unit_and_preserves_syscall_observation() {
    let mut vm = IVM::new(10_000);
    vm.load_program(&build_authenticated_test_contract_program(&[], 0, false))
        .expect("authenticated probe fixture");
    vm.set_register(14, 42);
    vm.run().expect("probe completes protected return");
    assert_eq!(authenticated_test_probe_result(&vm), 42);
    assert_ne!(vm.register(10), 42, "r10 owns the completed result table");
}
#[test]
fn authenticated_test_probe_setup_gas_matches_real_root_and_staging_work() {
    struct ObserveGas(Option<u64>);
    impl ivm::IVMHost for ObserveGas {
        fn as_any(&mut self) -> &mut dyn std::any::Any {
            self
        }
        fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, ivm::VMError> {
            Ok(0)
        }
        fn syscall(&mut self, _number: u32, vm: &mut IVM) -> Result<u64, ivm::VMError> {
            self.0 = Some(vm.remaining_gas());
            Ok(0)
        }
    }
    let instruction = ivm::encoding::wide::encode_sys(
        ivm::instruction::wide::system::SCALL,
        u8::try_from(ivm_sys::SYSCALL_DEBUG_PRINT).expect("syscall fits byte"),
    );
    let mut vm = IVM::new(10_000);
    vm.load_program(&build_authenticated_test_contract_program(
        &instruction.to_le_bytes(),
        0,
        false,
    ))
    .expect("authenticated probe fixture");
    let mut host = ObserveGas(None);
    vm.run_with_host(&mut host)
        .expect("probe completes protected return");
    assert_eq!(
        host.0,
        Some(
            10_000 - authenticated_test_probe_setup_gas() - ivm::gas::cost_of(instruction).unwrap()
        )
    );
    assert_eq!(authenticated_test_probe_result(&vm), 0);
}
fn fixture_account_in_domain(label: &str, domain_label: &str) -> AccountId {
    let seed: Vec<u8> = format!("{label}@{domain_label}")
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    AccountId::new(fixture_public_key_from_seed(seed))
}
pub(super) fn fixture_public_key_from_seed(seed: Vec<u8>) -> iroha_crypto::PublicKey {
    let (public_key, _) = KeyPair::try_from_seed(seed, Algorithm::Ed25519)
        .expect("fixture seed must derive a valid keypair")
        .into_parts();
    public_key
}
#[test]
fn fixture_public_key_from_seed_uses_checked_seed_derivation() {
    assert_eq!(
        fixture_public_key_from_seed(vec![0x61; 32])
            .try_algorithm()
            .expect("fixture public key algorithm"),
        Algorithm::Ed25519
    );
    assert!(
        KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
        "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
    );
}
#[test]
fn contract_subject_sysvar_returns_bound_subject_and_fails_outside_contract_scope() {
    let authority = fixture_account("alice");
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &authority,
        7,
        DataSpaceId::UNIVERSAL,
    )
    .expect("derive contract address");
    let subject = contract_address.subject_id();
    let mut host = CoreHost::new(authority.clone());
    host.set_contract_runtime_context(Some(ContractRuntimeExecutionContext {
        contract_address,
        contract_subject: subject.clone(),
        contract_alias: None,
        entrypoint: "main".to_owned(),
    }));
    let mut vm = IVM::new(100_000);
    host.syscall(ivm_sys::SYSCALL_SYSVAR_CONTRACT_SUBJECT, &mut vm)
        .expect("read contract subject");
    let observed: AccountId =
        CoreHost::decode_tlv_typed(&vm, vm.register(10), PointerType::AccountId)
            .expect("decode contract subject");
    assert_eq!(observed, subject);
    let mut host = local_contract_host(authority);
    assert_eq!(
        host.syscall(ivm_sys::SYSCALL_SYSVAR_CONTRACT_SUBJECT, &mut vm),
        Err(ivm::VMError::PermissionDenied)
    );
}
fn build_fixture_account(id: &AccountId, authority: &AccountId) -> Account {
    Account::new(id.clone()).build(authority)
}
fn retail_dataspace_catalog() -> (
    iroha_model_base::topology::DataSpaceId,
    iroha_data_model::nexus::DataSpaceCatalog,
) {
    let paynet = iroha_model_base::topology::DataSpaceId::new(12);
    let catalog = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: paynet,
            alias: "paynet".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("retail dataspace catalog");
    (paynet, catalog)
}
fn resolved_test_account_alias(
    tx: &StateTransaction<'_, '_>,
    alias: &AccountAlias,
) -> iroha_data_model::alias_setup::ResolvedAccountAliasV1 {
    iroha_data_model::alias_setup::ResolvedAccountAliasV1::new(
        alias
            .to_literal(&tx.nexus.dataspace_catalog)
            .expect("fixture alias must resolve through the live catalog")
            .parse()
            .expect("fixture alias literal must be canonical"),
        alias.dataspace,
    )
}
fn seed_test_account_alias_lease_record(
    tx: &mut StateTransaction<'_, '_>,
    alias: &AccountAlias,
    owner: &AccountId,
) {
    let dataspace_name = tx
        .nexus
        .dataspace_catalog
        .by_id(alias.dataspace)
        .expect("fixture alias dataspace must be catalogued")
        .alias
        .clone();
    let dataspace_selector =
        crate::sns::selector_for_dataspace_alias(&dataspace_name).expect("dataspace selector");
    let dataspace_key = crate::sns::record_storage_key(&dataspace_selector);
    if tx.world.smart_contract_state.get(&dataspace_key).is_none() {
        let address = AccountAddress::from_account_id(owner).expect("fixture owner address");
        let mut metadata = Metadata::default();
        metadata.insert(
            crate::sns::SNS_DATASPACE_ID_METADATA_KEY
                .parse()
                .expect("dataspace metadata key"),
            iroha_primitives::json::Json::new(alias.dataspace.as_u64()),
        );
        let record = iroha_data_model::sns::NameRecordV1::new(
            dataspace_selector,
            owner.clone(),
            vec![iroha_data_model::sns::NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            metadata,
        );
        tx.world
            .smart_contract_state
            .insert(dataspace_key, norito::codec::Encode::encode(&record));
    }
    if let Some(domain_id) = alias
        .domain_id(&tx.nexus.dataspace_catalog)
        .expect("fixture alias domain")
    {
        let domain_owner = tx
            .world
            .domains
            .get(&domain_id)
            .map(|domain| domain.owned_by().clone())
            .unwrap_or_else(|| owner.clone());
        if tx.world.domains.get(&domain_id).is_none() {
            let domain = Domain::new(domain_id.clone()).build(&domain_owner);
            tx.world.insert_domain_entry(domain_id.clone(), domain);
            tx.world.track_domain_owner(&domain_id, &domain_owner);
        }
        let selector = crate::sns::selector_for_domain(&domain_id).expect("SNS domain selector");
        let storage_key = crate::sns::record_storage_key(&selector);
        if tx.world.smart_contract_state.get(&storage_key).is_none() {
            let address =
                AccountAddress::from_account_id(&domain_owner).expect("domain owner address");
            let record = iroha_data_model::sns::NameRecordV1::new(
                selector,
                domain_owner,
                vec![iroha_data_model::sns::NameControllerV1::account(&address)],
                0,
                0,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                Metadata::default(),
            );
            tx.world
                .smart_contract_state
                .insert(storage_key, norito::codec::Encode::encode(&record));
        }
    }
    let selector = crate::sns::selector_for_account_alias(alias, &tx.nexus.dataspace_catalog)
        .expect("fixture alias selector");
    let storage_key = crate::sns::record_storage_key(&selector);
    if tx.world.smart_contract_state.get(&storage_key).is_some() {
        return;
    }
    let address = AccountAddress::from_account_id(owner).expect("fixture owner address");
    let record = iroha_data_model::sns::NameRecordV1::new(
        selector,
        owner.clone(),
        vec![iroha_data_model::sns::NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    tx.world
        .smart_contract_state
        .insert(storage_key, norito::codec::Encode::encode(&record));
}
/// Lease-only state fixture for alias-resolution tests.
struct SeedTestAccountAliasLease {
    alias: AccountAlias,
    owner: AccountId,
}
impl SeedTestAccountAliasLease {
    fn new(
        alias: AccountAlias,
        owner: AccountId,
        _payer: AccountId,
        _term_years: u8,
        _pricing_class_hint: Option<u8>,
    ) -> Self {
        Self { alias, owner }
    }
}
impl Execute for SeedTestAccountAliasLease {
    fn execute(
        self,
        _authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), iroha_data_model::isi::error::InstructionExecutionError> {
        seed_test_account_alias_lease_record(tx, &self.alias, &self.owner);
        Ok(())
    }
}
/// Declarative repair/CAS adapter used to build alias-resolution fixtures.
struct EnsureTestAccountAliasBinding {
    account: AccountId,
    alias: AccountAlias,
}
impl EnsureTestAccountAliasBinding {
    fn bind(account: AccountId, alias: AccountAlias, _lease_expiry_ms: Option<u64>) -> Self {
        Self { account, alias }
    }
}
impl Execute for EnsureTestAccountAliasBinding {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), iroha_data_model::isi::error::InstructionExecutionError> {
        let resolved = resolved_test_account_alias(tx, &self.alias);
        if let Some(expected_target) = tx.world.account_aliases.get(&self.alias).cloned()
            && expected_target != self.account
        {
            // Alias resolution deliberately fails closed unless the SNS lease,
            // forward binding, and rekey record agree. Model the lease transfer
            // that accompanies this test-only cross-account rebind before
            // applying the binding CAS.
            let selector =
                crate::sns::selector_for_account_alias(&self.alias, &tx.nexus.dataspace_catalog)
                    .expect("fixture alias selector");
            tx.world
                .smart_contract_state
                .remove(crate::sns::record_storage_key(&selector));
            seed_test_account_alias_lease_record(tx, &self.alias, &self.account);
            return iroha_data_model::isi::alias_setup::RebindAccountAlias::new(
                resolved,
                expected_target,
                self.account,
            )
            .execute(authority, tx);
        }
        seed_test_account_alias_lease_record(tx, &self.alias, &self.account);
        iroha_data_model::isi::alias_setup::EnsureAlias::new(
            iroha_data_model::alias_setup::AliasIntentV1::AccountAlias(
                iroha_data_model::alias_setup::AliasAccountIntentV1 {
                    alias: resolved,
                    target_account: self.account,
                    provision: iroha_data_model::alias_setup::AccountProvisionV1::Existing,
                    role: iroha_data_model::alias_setup::AccountAliasRoleV1::Additional,
                },
            ),
            iroha_data_model::alias_setup::AliasLeaseAcquisitionV1::new(1, None),
            iroha_data_model::alias_setup::AliasQuoteGuardV1 {
                expected_policy_version: 0,
                expected_payment_asset: AssetDefinitionId::derive_from_components(
                    DomainId::try_new("assets", "universal").expect("fixture asset domain"),
                    "xor".parse().expect("fixture asset name"),
                ),
                max_amount: Quantity::zero(),
                valid_until_ms: 0,
            },
        )
        .execute(authority, tx)
    }
}
fn fixture_signing_keypair(authority: &AccountId) -> KeyPair {
    if authority == &*ALICE_ID {
        return (*ALICE_KEYPAIR).clone();
    }
    if authority == &*BOB_ID {
        return (*BOB_KEYPAIR).clone();
    }
    panic!("unsupported fixture signing authority: {authority}");
}
/// Execute the configured signed genesis while retaining its original State and Kura.
fn signed_contract_host_state(config: crate::sumeragi::test_chain::TestChainConfig) -> State {
    use crate::sumeragi::{startup, test_chain::CertifiedTestChain};

    let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
    let consensus_mode = config.consensus_mode;
    let prepared = CertifiedTestChain::prepare(config).expect("prepare signed host genesis");
    let state = Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("unpublished host fixture State is unique"));
    startup::apply_genesis(
        &state,
        prepared.genesis.block().clone(),
        &genesis_account,
        consensus_mode.into(),
        None,
    )
    .expect("apply signed host genesis");
    state
}
pub(super) fn contract_test_state(authority: &AccountId) -> State {
    let domain = Domain::new(fixture_domain_id()).build(authority);
    let account = build_fixture_account(authority, authority);
    let world = World::with([domain], [account], []);
    contract_test_state_with_world(authority, world)
}
/// Authenticate the supplied World and grant the fixture authority its deployment permissions.
pub(super) fn contract_test_state_with_world(authority: &AccountId, world: World) -> State {
    let state =
        signed_contract_host_state(crate::sumeragi::test_chain::TestChainConfig::new(world, 0));
    grant_named_permission_to_account(
        &state,
        authority,
        authority.clone(),
        "CanManageSmartContractCode",
    );
    state
}
#[test]
fn deployed_host_fixture_retains_original_genesis_and_artifact_scope() {
    let authority = ALICE_ID.clone();
    let world = World::with(
        [Domain::new(fixture_domain_id()).build(&authority)],
        [build_fixture_account(&authority, &authority)],
        [],
    );
    let unprepared = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    assert!(
        crate::sumeragi::lanes::routing::committed_root_scope(unprepared.view().world()).is_none()
    );
    let state = contract_test_state(&authority);
    let parent = state
        .view()
        .latest_block_hash()
        .expect("original signed genesis");
    assert_eq!(state.committed_height(), 1);
    assert!(crate::sumeragi::lanes::routing::committed_root_scope(state.view().world()).is_some());
    assert!(state.view().world().account(&authority).is_ok());
    assert!(
        !state
            .view()
            .world()
            .account_permissions
            .get(&authority)
            .is_some_and(|permissions| permissions
                .iter()
                .any(|permission| permission.name() == "CanInvokeContractEntrypoint")),
        "fixture deployment does not grant unrequested contract entrypoints"
    );
    let address = install_contract(
        &state,
        &authority,
        "seiyaku OriginalHostFixture { view fn inspect() authorize(anyone) -> int { return 8; } }",
        73,
    );
    assert_eq!(
        address,
        ContractAddress::derive(
            state.network_id_ref(),
            &authority,
            73,
            DataSpaceId::UNIVERSAL
        )
        .expect("original network-derived contract address")
    );
    assert!(
        crate::smartcontracts::code::fetch_bound_contract_record(&state.view(), &address)
            .expect("registry read completes")
            .is_some()
    );
    assert_eq!(state.committed_height(), 1);
    assert_eq!(state.view().latest_block_hash(), Some(parent));
    assert!(
        !state
            .view()
            .world()
            .account_permissions
            .get(&authority)
            .is_some_and(|permissions| permissions
                .iter()
                .any(|permission| permission.name() == "CanInvokeContractEntrypoint")),
        "fixture deployment does not grant unrequested contract entrypoints"
    );
}

#[test]
fn deployed_host_fixture_entrypoint_grants_keep_exact_caller_contract_and_selector_scope() {
    let authority = ALICE_ID.clone();
    let state = contract_test_state(&authority);
    let caller = install_contract(
        &state,
        &authority,
        "seiyaku ScopedFixtureCaller { view fn main() authorize(anyone) -> int { return 0; } }",
        90,
    );
    let source = r#"
seiyaku ScopedFixtureCallee { permission Inspect; permission InspectOther;
  view fn inspect() authorize(Inspect) -> int { return 8; }
  view fn inspect_other() authorize(InspectOther) -> int { return 9; }
}
"#;
    let callee = install_contract(&state, &authority, source, 91);
    let other_callee = install_contract(&state, &authority, source, 92);
    let caller_subject = caller.subject_id();
    let check = |holder: &AccountId, contract: &ContractAddress, selector: &str| {
        let view = state.view();
        crate::executor::enforce_named_contract_entrypoint_authorization(
            view.world(),
            holder,
            contract,
            selector,
            &EntrypointAuthorizationV1::Permission(
                match selector {
                    "inspect" => "Inspect",
                    "inspect_other" => "InspectOther",
                    _ => panic!("fixture selector"),
                }
                .parse()
                .unwrap(),
            ),
        )
        .map_err(crate::execution_attempt::expect_completed_rejection)
    };
    assert!(matches!(
        check(&authority, &callee, "inspect"),
        Err(ValidationFail::NotPermitted(_))
    ));
    assert!(matches!(
        check(&caller_subject, &callee, "inspect"),
        Err(ValidationFail::NotPermitted(_))
    ));
    grant_contract_entrypoint_to_account(
        &state,
        &authority,
        caller_subject.clone(),
        &callee,
        "inspect",
    );
    assert!(check(&caller_subject, &callee, "inspect").is_ok());
    for (holder, contract, selector) in [
        (&authority, &callee, "inspect"),
        (&caller_subject, &other_callee, "inspect"),
        (&caller_subject, &callee, "inspect_other"),
    ] {
        assert!(matches!(
            check(holder, contract, selector),
            Err(ValidationFail::NotPermitted(_))
        ));
    }
    for _ in 0..2 {
        grant_contract_entrypoint_to_account(
            &state,
            &authority,
            caller_subject.clone(),
            &callee,
            "inspect_other",
        );
    }
    assert!(check(&caller_subject, &callee, "inspect_other").is_ok());
    assert_eq!(
        state
            .view()
            .world()
            .account_permissions
            .get(&caller_subject)
            .expect("exact entrypoint permission holder")
            .iter()
            .filter(|permission| permission.name() == "CanUseContractPermission")
            .count(),
        2,
        "distinct selectors coexist and identical grants remain idempotent"
    );
    grant_contract_entrypoint_to_account(
        &state,
        &authority,
        authority.clone(),
        &callee,
        "inspect_other",
    );
    assert!(check(&authority, &callee, "inspect_other").is_ok());
    assert!(matches!(
        check(&authority, &callee, "inspect"),
        Err(ValidationFail::NotPermitted(_))
    ));
    let next_height = u64::try_from((state.view().height() + 1).max(2))
        .ok()
        .and_then(core::num::NonZeroU64::new)
        .expect("next exact entrypoint revocation height");
    let mut block = state.block(BlockHeader::new(
        next_height,
        state.view().latest_block_hash(),
        None,
        0,
        0,
    ));
    let mut tx = block.transaction();
    Revoke::account_permission(
        CanUseContractPermission {
            contract: callee.clone(),
            permission: "Inspect".parse().unwrap(),
        },
        caller_subject.clone(),
    )
    .execute(&authority, &mut tx)
    .expect("revoke the exact caller's inspect permission");
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit exact entrypoint permission revocation");
    assert!(matches!(
        check(&caller_subject, &callee, "inspect"),
        Err(ValidationFail::NotPermitted(_))
    ));
    assert!(check(&caller_subject, &callee, "inspect_other").is_ok());
    assert!(check(&authority, &callee, "inspect_other").is_ok());
}

#[test]
#[should_panic(
    expected = "scoped contract permissions require an exact deployed address and selector"
)]
fn named_permission_fixture_rejects_scoped_entrypoint_marker() {
    let authority = ALICE_ID.clone();
    let state = contract_test_state(&authority);
    grant_named_permission_to_account(
        &state,
        &authority,
        authority.clone(),
        "CanInvokeContractEntrypoint",
    );
}

pub(super) fn install_contract(
    state: &State,
    authority: &AccountId,
    source: &str,
    nonce: u64,
) -> ContractAddress {
    install_contract_with_interface_and_lifecycle(state, authority, source, nonce, false, |_| {})
}
fn install_contract_with_pending_lifecycle(
    state: &State,
    authority: &AccountId,
    source: &str,
    nonce: u64,
) -> ContractAddress {
    install_contract_with_interface_and_lifecycle(state, authority, source, nonce, true, |_| {})
}
fn install_contract_with_interface(
    state: &State,
    authority: &AccountId,
    source: &str,
    nonce: u64,
    customize_interface: impl FnOnce(&mut ivm::EmbeddedContractInterfaceV1),
) -> ContractAddress {
    install_contract_with_interface_and_lifecycle(
        state,
        authority,
        source,
        nonce,
        false,
        customize_interface,
    )
}
fn install_contract_with_interface_and_lifecycle(
    state: &State,
    authority: &AccountId,
    source: &str,
    nonce: u64,
    leave_lifecycle_pending: bool,
    customize_interface: impl FnOnce(&mut ivm::EmbeddedContractInterfaceV1),
) -> ContractAddress {
    let compiler = kotodama_lang::compiler::Compiler::new_with_options(
        kotodama_lang::compiler::CompilerOptions {
            mode: kotodama_lang::compiler::CompilerMode::Production,
            ..kotodama_lang::compiler::CompilerOptions::default()
        },
    );
    let (code, _manifest) = compiler
        .compile_source_with_manifest(source)
        .expect("compile contract with manifest");
    install_contract_artifact_with_interface_and_lifecycle(
        state,
        authority,
        code,
        nonce,
        leave_lifecycle_pending,
        customize_interface,
    )
}
fn install_contract_artifact_with_interface_and_lifecycle(
    state: &State,
    authority: &AccountId,
    mut code: Vec<u8>,
    nonce: u64,
    leave_lifecycle_pending: bool,
    customize_interface: impl FnOnce(&mut ivm::EmbeddedContractInterfaceV1),
) -> ContractAddress {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    sanitize_test_contract_artifact_wildcards(&mut code);
    rewrite_test_contract_interface(&mut code, customize_interface);
    let mut manifest = ivm::verify_contract_artifact(&code)
        .expect("test contract artifact must verify after wildcard sanitization")
        .manifest;
    let next_height = u64::try_from((state.view().height() + 1).max(2))
        .ok()
        .and_then(core::num::NonZeroU64::new)
        .expect("next block height must fit in u64 and be non-zero");
    let mut block = state.block(BlockHeader::new(
        next_height,
        state.view().latest_block_hash(),
        None,
        0,
        0,
    ));
    let mut tx = block.transaction();
    tx.world.add_account_permission(
        authority,
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into(),
    );
    let code_hash = register_code_bytes(authority, DataSpaceId::UNIVERSAL, code, &mut tx)
        .expect("register contract bytecode");
    manifest.code_hash = Some(code_hash);
    manifest = manifest
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &fixture_signing_keypair(authority),
        )
        .expect("sign bounded fixture manifest");
    register_manifest(authority, DataSpaceId::UNIVERSAL, manifest, &mut tx)
        .expect("register contract manifest");
    let contract_address = ContractAddress::derive(
        state.network_id_ref(),
        authority,
        nonce,
        DataSpaceId::UNIVERSAL,
    )
    .expect("derive contract address");
    tx.world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), authority.clone());
    activate_instance(authority, contract_address.clone(), 1, code_hash, &mut tx)
        .expect("activate contract");
    // Most host tests exercise an isolated syscall and use a fixture that represents a
    // contract after its lifecycle transition. Lifecycle-specific tests opt into retaining
    // the real pending marker through `install_contract_with_pending_lifecycle`.
    if !leave_lifecycle_pending {
        crate::smartcontracts::code::set_pending_contract_lifecycle(
            &mut tx,
            &contract_address,
            None,
        );
    }
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit contract registration block");
    contract_address
}
#[test]
fn call_contract_syscall_cursor_cannot_authorize_other_or_revoked_caller() {
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointValueKindV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
    };

    let authority: AccountId = fixture_account("alice");
    let state = contract_test_state(&authority);
    let caller_source =
        "seiyaku CursorCaller { view fn main() authorize(anyone) -> int { return 0; } }";
    let reader = install_contract(&state, &authority, caller_source, 0);
    let other = install_contract(&state, &authority, caller_source, 1);
    let callee = install_contract(
        &state,
        &authority,
        r#"
seiyaku ProtectedPages { permission ReadState; permission WriteState;
  state StateMap<int, int> Entries;

  kotoage fn seed() authorize(WriteState) {
    Entries[1] = 10;
    Entries[2] = 20;
  }

  view fn first() authorize(ReadState) -> Option<StateCursor<int>> {
    let page = Entries.page(after: Option::none, limit: 1);
    return page.next;
  }

  view fn resume(Option<StateCursor<int>> after) authorize(ReadState) -> int {
    let page = Entries.page(after: after, limit: 1);
    return page.items.len();
  }
}
"#,
        2,
    );
    grant_named_permission_to_account(&state, &authority, authority.clone(), "WriteState");
    // A grant to the outer transaction authority does not authorize a different
    // calling contract subject at the nested boundary.
    grant_named_permission_to_account(&state, &authority, authority.clone(), "ReadState");
    grant_named_permission_to_account(&state, &authority, reader.subject_id(), "ReadState");
    grant_named_permission_to_account(&state, &authority, other.subject_id(), "OtherOps");
    let mut cache = crate::smartcontracts::ivm::cache::IvmCache::new();
    execute_contract_call_transaction(
        &state,
        &authority,
        &fixture_signing_keypair(&authority),
        contract_invocation_from_json(&state, callee.clone(), "seed", &Json::new(())),
        &mut cache,
    );

    let (result, vm, overlay, _) = dispatch_call_contract_syscall(
        &state,
        &authority,
        &reader,
        &callee,
        "first",
        Json::new(()),
        1_000_000,
    );
    result.expect("authorized first page should produce a live continuation");
    assert!(
        overlay.is_empty(),
        "reading the first page must not write state"
    );
    let schema = EntrypointValueTypeV1 {
        nodes: vec![
            EntrypointValueTypeNodeV1::Option,
            EntrypointValueTypeNodeV1::StateCursor(EntrypointValueTypeV1 {
                nodes: vec![EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)],
            }),
        ],
    };
    let record = captured_nested_result(&vm, &schema);
    let after = super::super::return_value::render_entrypoint_return_record(&schema, &record)
        .expect("render actual cursor for public arguments");
    let cursor_hex = after
        .get("some")
        .and_then(norito::json::Value::as_str)
        .expect("two stored positions and limit one must yield a continuation");
    let cursor_frame = hex::decode(cursor_hex.strip_prefix("0x").expect("cursor hex prefix"))
        .expect("canonical cursor frame hex");
    let cursor =
        iroha_data_model::smart_contract::state_cursor::StateCursorV1::decode_frame(&cursor_frame)
            .expect("cursor came from the production page implementation");
    assert_eq!(cursor.map.as_ref(), "Entries");
    assert_eq!(
        cursor.key_schema_hash,
        iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(
            &EntrypointValueTypeV1 {
                nodes: vec![EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)]
            },
        )
        .expect("scalar key schema")
    );
    let payload = Json::from(
        norito::json::object([("after", after)]).expect("unchanged continuation argument"),
    );

    let assert_can_resume = |caller: &ContractAddress| {
        let (result, vm, overlay, _) = dispatch_call_contract_syscall(
            &state,
            &authority,
            caller,
            &callee,
            "resume",
            payload.clone(),
            1_000_000,
        );
        result
            .expect("same cursor, instance, map and schema must remain valid with read permission");
        assert!(overlay.is_empty(), "resuming a page must not write state");
        assert_eq!(
            render_nested_result(&vm, EntrypointValueKindV1::Int),
            norito::json!("1")
        );
    };
    let assert_cannot_resume = |caller: &ContractAddress| {
        let (result, vm, overlay, target_ptr) = dispatch_call_contract_syscall(
            &state,
            &authority,
            caller,
            &callee,
            "resume",
            payload.clone(),
            1_000_000,
        );
        let error = result.expect_err("cursor possession cannot grant ReadState");
        assert!(matches!(
            error.as_unmetered(),
            ivm::VMError::PermissionDenied
        ));
        assert_eq!(
            vm.register(10),
            target_ptr,
            "denied admission must not publish a page"
        );
        assert!(overlay.is_empty(), "denied admission must not change state");
    };
    assert_can_resume(&reader);
    assert_cannot_resume(&other);
    grant_named_permission_to_account(&state, &authority, other.subject_id(), "ReadState");
    assert_can_resume(&other);

    let next_height = u64::try_from((state.view().height() + 1).max(2))
        .ok()
        .and_then(core::num::NonZeroU64::new)
        .expect("next permission block height");
    let mut block = state.block(BlockHeader::new(next_height, None, None, 0, 0));
    let mut tx = block.transaction();
    assert!(
        tx.world.remove_account_permission(
            &other.subject_id(),
            &CanUseContractPermission {
                contract: callee.clone(),
                permission: "ReadState".parse().unwrap()
            }
            .into(),
        )
    );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit ReadState revocation");
    assert_cannot_resume(&other);
    assert_can_resume(&reader);
    grant_named_permission_to_account(&state, &authority, other.subject_id(), "ReadState");
    assert_can_resume(&other);
}

#[test]
fn contract_permission_syscalls_use_declared_instance_names_and_exact_address() {
    let (artifact, _) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(
            r#"
seiyaku GrantPolicy {
  permission Admin;
  import permission "GlobalAdmin" as Shared;
  kotoage fn main() authorize(anyone) {}
}
"#,
        )
        .expect("compile syscall permission catalog");
    for syscall in [
        ivm::syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION,
        ivm::syscalls::SYSCALL_REVOKE_CONTRACT_PERMISSION,
    ] {
        for declaration in ["Admin", "Shared", "Typo"] {
            let mut vm = ivm::IVM::new(1_000_000);
            vm.load_program(&artifact).unwrap();
            let mut host = CoreHost::new(ALICE_ID.clone());
            bind_test_contract_runtime(&mut host, 911);
            let address = host
                .current_contract_runtime_context
                .as_ref()
                .unwrap()
                .contract_address
                .clone();
            let account_ptr = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&*BOB_ID));
            let name: Name = declaration.parse().unwrap();
            let name_ptr = store_tlv(&mut vm, PointerType::Name, &norito_blob(&name));
            vm.set_register(10, account_ptr);
            vm.set_register(11, name_ptr);
            let result = host.syscall(syscall, &mut vm);
            if declaration != "Admin" {
                assert_eq!(result, Err(ivm::VMError::PermissionDenied));
                assert!(host.queued.is_empty());
                continue;
            }
            result.expect("declared instance role queues an exact token mutation");
            let permission: Permission = CanUseContractPermission {
                contract: address,
                permission: name,
            }
            .into();
            let expected = if syscall == ivm::syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION {
                InstructionBox::from(Grant::account_permission(permission, BOB_ID.clone()))
            } else {
                InstructionBox::from(Revoke::account_permission(permission, BOB_ID.clone()))
            };
            assert_eq!(
                host.queued
                    .iter()
                    .filter_map(QueuedEffect::instruction)
                    .collect::<Vec<_>>(),
                vec![&expected]
            );
        }
    }
}
