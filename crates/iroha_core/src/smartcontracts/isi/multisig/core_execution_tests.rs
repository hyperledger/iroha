// Same-scope regression coverage extracted to keep the parent source budget bounded.
#[test]
fn multisig_executes_fi_registration_alias_batch_as_multisig_authority() {
    assert_multisig_executes_fi_registration_alias_batch(false);
}
#[test]
fn multisig_executes_fi_registration_alias_batch_with_uaid_account() {
    assert_multisig_executes_fi_registration_alias_batch(true);
}
#[test]
fn checked_keypair_helper_preserves_default_algorithm() {
    assert_eq!(checked_keypair().algorithm(), Algorithm::default());
}
fn register_account_in_domain(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    _domain_id: &iroha_model_base::domain::DomainId,
    account_id: &AccountId,
    label: &str,
) {
    Register::account(iroha_data_model::account::NewAccount::new(
        account_id.clone(),
    ))
    .execute(authority, state_transaction)
    .expect(label);
}
fn register_multisig_account(
    state_transaction: &mut StateTransaction<'_, '_>,
    owner_id: &AccountId,
    domain_id: &iroha_model_base::domain::DomainId,
    spec: &MultisigSpec,
    label: &str,
) -> AccountId {
    let multisig_key = checked_keypair();
    let multisig_id = new_account_id(&multisig_key);
    let mut metadata = Metadata::default();
    metadata.insert(spec_key(), Json::new(spec.clone()));
    metadata.insert(
        (*MULTISIG_HOME_DOMAIN_KEY).clone(),
        Json::new(Some(domain_id.clone())),
    );
    Register::account(
        iroha_data_model::account::NewAccount::new(multisig_id.clone()).with_metadata(metadata),
    )
    .execute(owner_id, state_transaction)
    .expect(label);
    let updated_account =
        rekey_multisig_account(state_transaction, &multisig_id, Some(domain_id), spec)
            .expect("rekey multisig account");
    persist_multisig_account_state(
        state_transaction,
        None,
        &MultisigAccountState::new(updated_account.clone(), domain_id.clone(), spec.clone()),
    )
    .expect("persist multisig account state");
    materialize_missing_signatory_accounts(
        state_transaction,
        Some(domain_id),
        &updated_account,
        spec,
    )
    .expect("materialize signatory accounts");
    configure_roles(
        state_transaction,
        owner_id,
        Some(domain_id),
        &updated_account,
        spec,
    )
    .expect("configure multisig roles");
    updated_account
}
fn install_trigger_contract(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    signing_keypair: &KeyPair,
    code: Vec<u8>,
    mut manifest: iroha_data_model::smart_contract::manifest::ContractManifest,
    nonce: u64,
) -> (
    IvmBytecode,
    iroha_data_model::smart_contract::ContractAddress,
) {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let code_hash = ivm::contract_code_hash(&code);
    let bytecode = IvmBytecode::from_compiled(code.clone());
    let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        state_transaction.network_id(),
        authority,
        nonce,
        DataSpaceId::UNIVERSAL,
    )
    .expect("derive trigger contract address");
    Register::account(iroha_data_model::account::NewAccount::new(
        contract_address.subject_id(),
    ))
    .execute(authority, state_transaction)
    .expect("register trigger contract subject");
    let deployment_permission: Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(deployment_permission, authority.clone())
        .execute(authority, state_transaction)
        .expect("grant trigger contract deployment permission");
    let registered_hash = crate::smartcontracts::code::register_code_bytes(
        authority,
        contract_address
            .dataspace_id()
            .expect("test contract dataspace"),
        code,
        state_transaction,
    )
    .expect("register trigger contract bytecode");
    assert_eq!(registered_hash, code_hash);
    manifest.code_hash = Some(code_hash);
    crate::smartcontracts::code::register_manifest(
        authority,
        contract_address
            .dataspace_id()
            .expect("test contract dataspace"),
        manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                signing_keypair,
            )
            .expect("sign bounded fixture manifest"),
        state_transaction,
    )
    .expect("register trigger contract manifest");
    state_transaction
        .world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), authority.clone());
    crate::smartcontracts::code::activate_instance(
        authority,
        contract_address.clone(),
        1,
        code_hash,
        state_transaction,
    )
    .expect("activate trigger contract");
    (bytecode, contract_address)
}
fn bind_account_label(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    account_id: &AccountId,
    domain_id: &iroha_model_base::domain::DomainId,
    label: &str,
) -> AccountAlias {
    bind_account_label_in_dataspace(
        state_transaction,
        authority,
        account_id,
        domain_id,
        DataSpaceId::UNIVERSAL,
        label,
    )
}
fn bind_account_label_in_dataspace(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    account_id: &AccountId,
    domain_id: &iroha_model_base::domain::DomainId,
    dataspace: DataSpaceId,
    label: &str,
) -> AccountAlias {
    let _ = authority;
    let label = AccountAlias::new(
        label.parse().expect("account label name"),
        Some(AccountAliasDomain::new(domain_id.name().clone())),
        dataspace,
    );
    let selector =
        crate::sns::selector_for_account_alias(&label, &state_transaction.nexus.dataspace_catalog)
            .expect("account alias selector");
    let address = iroha_data_model::account::AccountAddress::from_account_id(account_id)
        .expect("account address");
    let lease = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        account_id.clone(),
        vec![iroha_data_model::sns::NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    state_transaction.world.smart_contract_state.insert(
        crate::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&lease),
    );
    state_transaction
        .world
        .account_mut(account_id)
        .expect("registered account")
        .set_label(Some(label.clone()));
    state_transaction
        .world
        .insert_account_alias_binding(label.clone(), account_id.clone());
    state_transaction.world.replace_account_rekey_record(
        iroha_data_model::account::rekey::AccountRekeyRecord::new(
            label.clone(),
            account_id.clone(),
        ),
    );
    label
}
fn account_alias_lease_record(
    state_transaction: &StateTransaction<'_, '_>,
    alias: &AccountAlias,
) -> iroha_data_model::sns::NameRecordV1 {
    let selector =
        crate::sns::selector_for_account_alias(alias, &state_transaction.nexus.dataspace_catalog)
            .expect("account alias selector");
    let bytes = state_transaction
        .world
        .smart_contract_state
        .get(&crate::sns::record_storage_key(&selector))
        .expect("account alias lease");
    let mut slice = bytes.as_slice();
    let record = norito::codec::Decode::decode(&mut slice).expect("decode account alias lease");
    assert!(slice.is_empty(), "account alias lease must be canonical");
    record
}
fn assert_account_rekey_not_applied(
    state_transaction: &StateTransaction<'_, '_>,
    old_account: &AccountId,
    new_account: &AccountId,
    aliases: &[AccountAlias],
) {
    assert!(
        state_transaction.world.account(old_account).is_ok(),
        "failed rekey must retain the old account"
    );
    assert!(
        state_transaction.world.account(new_account).is_err(),
        "failed rekey must not materialize the new account"
    );
    for alias in aliases {
        assert_eq!(
            state_transaction.world.account_aliases.get(alias),
            Some(old_account),
            "failed rekey must preserve alias target"
        );
        assert_eq!(
            state_transaction
                .world
                .account_rekey_records
                .get(alias)
                .expect("account rekey record")
                .active_account_id,
            *old_account,
            "failed rekey must preserve the active rekey-record account"
        );
    }
}
fn load_signatory_memberships(
    state_transaction: &StateTransaction<'_, '_>,
    signatory: &AccountId,
) -> BTreeSet<AccountId> {
    load_multisig_signatory_memberships(state_transaction, signatory)
        .expect("load signatory memberships")
}
fn multisig_policy_for_members(members: &[(&KeyPair, u16)]) -> MultisigPolicy {
    MultisigPolicy::new(
        u16::try_from(members.len()).expect("member count fits u16"),
        members
            .iter()
            .map(|(key_pair, weight)| {
                MultisigMember::new(key_pair.public_key().clone(), *weight)
                    .expect("valid multisig member")
            })
            .collect(),
    )
    .expect("valid multisig policy")
}
fn seed_domain_name_lease(
    world: &mut World,
    owner: &AccountId,
    domain_id: &iroha_model_base::domain::DomainId,
) {
    let selector = crate::sns::selector_for_domain(domain_id).expect("selector");
    let address =
        iroha_data_model::account::AccountAddress::from_account_id(owner).expect("address");
    let record = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![iroha_data_model::sns::NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    world.smart_contract_state_mut_for_testing().insert(
        crate::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&record),
    );
}
fn seed_domain_name_lease_tx(
    state_transaction: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    domain_id: &iroha_model_base::domain::DomainId,
) {
    let selector = crate::sns::selector_for_domain(domain_id).expect("selector");
    let address =
        iroha_data_model::account::AccountAddress::from_account_id(owner).expect("address");
    let record = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![iroha_data_model::sns::NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    state_transaction.world.smart_contract_state.insert(
        crate::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&record),
    );
}
fn durable_int_value(bytes: &[u8]) -> i64 {
    use ivm::state_value::{
        StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1,
        StateValueSchemaV1, state_value_schema_hash_v1,
    };
    // Typed durable state stores a schema-bound Norito record. The authenticated
    // pointer-ABI envelope is the record's leaf atom, not the outer storage bytes.
    let schema = StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Int)],
    };
    let schema_bytes = norito::to_bytes(&schema).expect("encode durable int schema");
    let record: StateValueRecordV1 =
        norito::decode_from_bytes(bytes).expect("decode durable int state record");
    assert_eq!(
        norito::to_bytes(&record).expect("re-encode durable int state record"),
        bytes,
        "durable int state record must use canonical Norito encoding"
    );
    assert_eq!(
        record.schema_hash,
        state_value_schema_hash_v1(&schema_bytes),
        "durable int state record must bind the exact Int schema"
    );
    assert!(
        schema.validate_atoms(&record.atoms),
        "durable int state record must match the Int atom stream"
    );
    let [StateValueAtomV1::Pointer(envelope)] = record.atoms.as_slice() else {
        panic!("durable int state record must contain one pointer atom");
    };
    ivm::numeric_tlv::decode_int_bytes(envelope)
        .expect("decode canonical durable int pointer")
        .try_to_i64()
        .expect("test durable int value fits i64")
}
fn durable_state_values_under_contract_prefix(
    state_transaction: &StateTransaction<'_, '_>,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    prefix: &str,
) -> Vec<Vec<u8>> {
    let scope_digest = hex::encode(Hash::new(contract_address.to_string().as_bytes()).as_ref());
    let physical_prefix = format!("sc/{scope_digest}/{prefix}");
    let prefix_with_child = format!("{physical_prefix}/");
    state_transaction
        .world
        .smart_contract_state
        .iter()
        .filter_map(|(key, value)| {
            let key = key.as_ref();
            (key == physical_prefix || key.starts_with(prefix_with_child.as_str()))
                .then(|| value.clone())
        })
        .collect()
}
fn register_domain_with_name_lease(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    domain_id: &iroha_model_base::domain::DomainId,
    label: &str,
) {
    seed_domain_name_lease_tx(state_transaction, authority, domain_id);
    Register::domain(Domain::new(domain_id.clone()))
        .execute(authority, state_transaction)
        .expect(label);
}
#[test]
fn initial_executor_runs_multisig_flow() {
    let domain_id: iroha_model_base::domain::DomainId =
        DomainId::try_new("acme", "universal").unwrap();
    let signer1 = checked_keypair();
    let signer2 = checked_keypair();
    let signer1_id = new_account_id(&signer1);
    let signer2_id = new_account_id(&signer2);
    let spec = MultisigSpec {
        signatories: BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
        quorum: NonZeroU16::new(2).unwrap(),
        transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS).unwrap(),
    };
    let multisig_account_key = checked_keypair();
    let multisig_id = new_account_id(&multisig_account_key);
    let register =
        MultisigRegister::with_account(multisig_id.clone(), domain_id.clone(), spec.clone());
    let instruction: InstructionBox = register.into();
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(
        World::with(
            [Domain::new(domain_id).build(&signer1_id)],
            [&signer1_id, &signer2_id]
                .map(|account| Account::new(account.clone()).build(&signer1_id)),
            [],
        ),
        0,
    );
    config.chain_id = ChainId::from("multisig-test-chain");
    config.genesis_key = signer1;
    config.genesis_instructions.push(instruction.clone());
    let prepared = crate::sumeragi::test_chain::CertifiedTestChain::prepare(config)
        .expect("prepare exact signed multisig registration genesis");
    let source = prepared.genesis.block();
    let index = source
        .external_transactions()
        .position(|signed| {
            matches!(signed.instructions(),
            Executable::Instructions(instructions)
                if instructions.iter().eq(core::iter::once(&instruction)))
        })
        .expect("original singleton multisig registration input");
    let mut block = prepared
        .state
        .block_with_pristine_carrier_stage(source, |_| Ok::<_, String>(()))
        .expect("capture original multisig bootstrap carrier");
    let mut state_transaction = block
        .transaction_for_original_genesis_testing(source, index, &signer1_id, &instruction)
        .expect("authenticate original multisig bootstrap instruction");
    let executor = Executor::Initial;
    executor
        .execute_instruction(&mut state_transaction, &signer1_id, instruction)
        .expect("multisig register");
    let policy = multisig_policy_from_spec(&spec).expect("policy");
    let expected_id = AccountId::new_multisig(policy);
    state_transaction
        .world
        .account(&expected_id)
        .expect("multisig account registered");
    assert!(
        state_transaction
            .world
            .smart_contract_state
            .get(&multisig_account_state_key(&expected_id))
            .is_some(),
        "multisig account state must be stored on registration"
    );
    assert!(
        matches!(
            state_transaction.world.account(&multisig_id),
            Err(FindError::Account(_))
        ),
        "initial controller id should be rekeyed"
    );
    let stored_spec = multisig_spec(&state_transaction, &expected_id).expect("spec must decode");
    assert_eq!(
        stored_spec.quorum, spec.quorum,
        "spec quorum must roundtrip through metadata"
    );
    assert_eq!(
        stored_spec.transaction_ttl_ms, spec.transaction_ttl_ms,
        "spec ttl must roundtrip through metadata"
    );
    assert_eq!(
        stored_spec.signatories.len(),
        spec.signatories.len(),
        "stored spec must preserve signatory cardinality"
    );
    for (expected_signatory, expected_weight) in &spec.signatories {
        let actual_weight = stored_spec
            .signatories
            .iter()
            .find_map(|(stored_signatory, stored_weight)| {
                (stored_signatory.subject_id() == expected_signatory.subject_id())
                    .then_some(*stored_weight)
            })
            .expect("stored spec must include expected signatory subject");
        assert_eq!(actual_weight, *expected_weight);
    }
}
