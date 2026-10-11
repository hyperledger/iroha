fn checked_signature(
    private_key: &iroha_crypto::PrivateKey,
    payload: &[u8],
) -> iroha_crypto::Signature {
    iroha_crypto::Signature::try_new(private_key, payload)
        .expect("test fixture signing should succeed")
}
const SMALL_ORDER_ED25519_R: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const NONCANONICAL_ED25519_R: [u8; 32] = [
    0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
fn signature_with_malformed_ed25519_r(
    signature: &iroha_crypto::Signature,
    replacement_r: &[u8; 32],
) -> iroha_crypto::Signature {
    let mut payload = signature.payload().to_vec();
    payload[..replacement_r.len()].copy_from_slice(replacement_r);
    iroha_crypto::Signature::from_bytes(&payload)
}
#[test]
fn soracloud_provenance_signature_admission_rejects_malformed_ed25519_signature_r() {
    let key_pair = KeyPair::try_from_seed(vec![0x61; 32], iroha_crypto::Algorithm::Ed25519)
        .expect("derive checked Soracloud Ed25519 provenance keypair");
    let payload = b"soracloud-provenance-ed25519-admission";
    let signature = checked_signature(key_pair.private_key(), payload);
    for (label, replacement_r) in [
        ("small-order", SMALL_ORDER_ED25519_R),
        ("noncanonical", NONCANONICAL_ED25519_R),
    ] {
        let malformed_signature = signature_with_malformed_ed25519_r(&signature, &replacement_r);
        assert!(
            verify_signature_for_signer(&malformed_signature, key_pair.public_key(), payload)
                .is_err(),
            "{label} Soracloud provenance Ed25519 admission must reject malformed R before backend verification"
        );
    }
}
#[test]
fn soracloud_provenance_signature_admission_rejects_malformed_mldsa_signature_lengths() {
    let key_pair = KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::MlDsa)
        .expect("generate checked Soracloud ML-DSA provenance keypair");
    let payload = b"soracloud-provenance-mldsa-admission";
    let signature = checked_signature(key_pair.private_key(), payload);
    verify_signature_for_signer(&signature, key_pair.public_key(), payload)
        .expect("valid Soracloud ML-DSA provenance signature verifies");
    let valid_signature = signature.payload().to_vec();
    for (label, replacement_signature) in [
        (
            "short",
            valid_signature[..valid_signature.len() - 1].to_vec(),
        ),
        ("overlong", {
            let mut payload = valid_signature.clone();
            payload.push(0x64);
            payload
        }),
    ] {
        let malformed_signature = iroha_crypto::Signature::from_bytes(&replacement_signature);
        assert_eq!(
            verify_signature_for_signer(&malformed_signature, key_pair.public_key(), payload)
                .expect_err("malformed Soracloud ML-DSA signature length must fail admission"),
            iroha_crypto::Error::BadSignature,
            "{label} Soracloud ML-DSA signature length was not rejected"
        );
    }
}
#[track_caller]
fn checked_keypair() -> KeyPair {
    let caller = std::panic::Location::caller();
    let mut seed = Sha256::new();
    seed.update(b"iroha-core-soracloud-test-keypair-v1");
    seed.update(caller.file().as_bytes());
    seed.update(caller.line().to_le_bytes());
    seed.update(caller.column().to_le_bytes());
    KeyPair::try_from_seed(seed.finalize().to_vec(), iroha_crypto::Algorithm::default())
        .expect("derive Soracloud fixture key from call site")
}
#[test]
fn checked_keypair_helper_preserves_default_algorithm() {
    assert_eq!(
        checked_keypair().algorithm(),
        iroha_crypto::Algorithm::default()
    );
}
#[test]
fn checked_keypair_helper_is_deterministic_per_call_site() {
    let fixture = || checked_keypair();
    let first = fixture();
    let second = fixture();
    assert_eq!(first.public_key(), second.public_key());
    let other_call_site = checked_keypair();
    assert_ne!(first.public_key(), other_call_site.public_key());
}
#[test]
fn soracloud_provenance_rejects_multisig_authority_without_panicking() {
    let member_key = checked_keypair();
    let member = iroha_data_model::account::MultisigMember::new(member_key.public_key().clone(), 1)
        .expect("multisig member");
    let policy =
        iroha_data_model::account::MultisigPolicy::new(1, vec![member]).expect("multisig policy");
    let authority = AccountId::new_multisig(policy);
    let error = single_signatory_authority(&authority)
        .expect_err("multisig authority must fail provenance admission");
    assert!(
        matches!(
            &error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains("single-signatory transaction authority")
        ),
        "unexpected multisig provenance rejection: {error:?}"
    );
}
fn seed_domain_name_lease_tx(
    state_transaction: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    domain_id: &DomainId,
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
fn state_with_soracloud_permission(kura: &Arc<Kura>) -> Result<State, eyre::Report> {
    state_with_soracloud_permission_on_chain(
        kura,
        iroha_model_base::chain::ChainId::from("00000000-0000-0000-0000-000000000000"),
    )
}
fn state_with_soracloud_permission_on_chain(
    kura: &Arc<Kura>,
    chain_id: iroha_model_base::chain::ChainId,
) -> Result<State, eyre::Report> {
    let world = World::with([], [], []);
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_with_chain(world, kura.clone(), query_handle, chain_id);
    let block_header = ValidBlock::new_dummy(&checked_keypair().into_parts().1)
        .as_ref()
        .header();
    let mut state_block = state.block(block_header);
    let mut state_transaction = state_block.transaction();
    let wonderland: iroha_model_base::domain::DomainId =
        DomainId::try_new("wonderland", "universal")?;
    seed_domain_name_lease_tx(
        &mut state_transaction,
        &SAMPLE_GENESIS_ACCOUNT_ID,
        &wonderland,
    );
    Register::domain(Domain::new(wonderland.clone()))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
    Register::account(Account::new(ALICE_ID.clone()))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
    Grant::account_permission(
        Permission::new(CAN_MANAGE_SORACLOUD_PERMISSION.into(), Json::new(())),
        ALICE_ID.clone(),
    )
    .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
    insert_active_public_lane_validator(&mut state_transaction, ALICE_ID.clone(), 1_000);
    state_transaction.apply();
    state_block.commit_world_overlay_for_testing()?;
    Ok(state)
}
// Ordinary Initial-executor scenarios require an original authenticated genesis root.
// The component fixture still owns the same seeded permissions and validator rows; its World
// enters the canonical chain constructor before any ordinary execution or proof admission.
fn state_with_initial_soracloud_permission(kura: &Arc<Kura>) -> Result<State, eyre::Report> {
    use crate::sumeragi::{
        startup,
        test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let component = state_with_soracloud_permission(kura)?;
    let mut config = TestChainConfig::new(component.world, 0);
    config.chain_id = component.chain_id;
    let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
    let mode = config.consensus_mode;
    let prepared = CertifiedTestChain::prepare(config).map_err(|failure| failure.error)?;
    let state = Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("unpublished SoraCloud State is unique"));
    startup::apply_genesis(
        &state,
        prepared.genesis.block().clone(),
        &genesis_account,
        mode.into(),
        None,
    )?;
    Ok(state)
}

fn initial_soracloud_header(state: &State, height: u64) -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(height).expect("ordinary SoraCloud execution height"),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    )
}

#[test]
fn initial_soracloud_fixture_owns_original_genesis_and_preserves_exact_permission()
-> Result<(), eyre::Report> {
    let kura = Kura::blank_kura_for_testing();
    let state = state_with_initial_soracloud_permission(&kura)?;
    let parent = state
        .view()
        .latest_block_hash()
        .expect("committed original genesis");
    assert_eq!(state.network_id_ref().into_genesis_hash(), parent);
    let header = initial_soracloud_header(&state, 2);
    assert_eq!(header.prev_block_hash(), Some(parent));
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    assert!(crate::executor::root_scope::execution_root_scope(&mut transaction).is_ok());
    require_soracloud_permission(&ALICE_ID, &transaction)?;
    assert_eq!(
        transaction
            .world
            .public_lane_validators
            .get(&(LaneId::SINGLE, ALICE_ID.clone()))
            .expect("original seeded validator")
            .status,
        PublicLaneValidatorStatus::Active,
    );
    let bonded = &transaction
        .world
        .public_lane_stake_shares
        .get(&(LaneId::SINGLE, ALICE_ID.clone(), ALICE_ID.clone()))
        .expect("original matching self-bonded share")
        .bonded;
    let validator = transaction
        .world
        .public_lane_validators
        .get(&(LaneId::SINGLE, ALICE_ID.clone()))
        .expect("original seeded validator");
    assert_eq!(bonded, &validator.total_stake);
    assert_eq!(bonded, &validator.self_stake);
    drop(transaction);
    drop(block);
    let component = state_with_soracloud_permission(&kura)?;
    let mut block = component.block(initial_soracloud_header(&component, 2));
    let mut transaction = block.transaction();
    require_soracloud_permission(&ALICE_ID, &transaction)?;
    assert!(crate::executor::root_scope::execution_root_scope(&mut transaction).is_err());
    Ok(())
}

#[test]
fn soracloud_permission_allows_granted_authority() -> Result<(), eyre::Report> {
    let kura = Kura::blank_kura_for_testing();
    let state = state_with_soracloud_permission(&kura)?;
    let block_header = ValidBlock::new_dummy(&checked_keypair().into_parts().1)
        .as_ref()
        .header();
    let mut state_block = state.block(block_header);
    let state_transaction = state_block.transaction();
    require_soracloud_permission(&ALICE_ID, &state_transaction)?;
    Ok(())
}
#[test]
fn soracloud_permission_rejects_ungranted_taira_testnet_authority() -> Result<(), eyre::Report> {
    let kura = Kura::blank_kura_for_testing();
    let state = state_with_soracloud_permission_on_chain(
        &kura,
        iroha_model_base::chain::ChainId::from(TAIRA_TESTNET_CHAIN_ID),
    )?;
    let block_header = ValidBlock::new_dummy(&checked_keypair().into_parts().1)
        .as_ref()
        .header();
    let mut state_block = state.block(block_header);
    let mut state_transaction = state_block.transaction();
    Register::account(Account::new(BOB_ID.clone()))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
    let err = require_soracloud_permission(&BOB_ID, &state_transaction)
        .expect_err("Taira must enforce the same Soracloud permission as every other chain");
    assert!(matches!(
        err,
        InstructionExecutionError::InvariantViolation(message)
            if message.as_ref() == "not permitted: CanManageSoracloud"
    ));
    Ok(())
}
#[test]
fn soracloud_permission_rejects_ungranted_authority() -> Result<(), eyre::Report> {
    let kura = Kura::blank_kura_for_testing();
    let state = state_with_soracloud_permission(&kura)?;
    let block_header = ValidBlock::new_dummy(&checked_keypair().into_parts().1)
        .as_ref()
        .header();
    let mut state_block = state.block(block_header);
    let mut state_transaction = state_block.transaction();
    Register::account(Account::new(BOB_ID.clone()))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
    let err = require_soracloud_permission(&BOB_ID, &state_transaction)
        .expect_err("authority without Soracloud permission must be rejected");
    assert!(matches!(
        err,
        InstructionExecutionError::InvariantViolation(message)
            if message.as_ref() == "not permitted: CanManageSoracloud"
    ));
    Ok(())
}
#[test]
fn soracloud_permission_accepts_exact_assigned_role() -> Result<(), eyre::Report> {
    let kura = Kura::blank_kura_for_testing();
    let state = state_with_soracloud_permission(&kura)?;
    let block_header = ValidBlock::new_dummy(&checked_keypair().into_parts().1)
        .as_ref()
        .header();
    let mut state_block = state.block(block_header);
    let mut state_transaction = state_block.transaction();
    Register::account(Account::new(BOB_ID.clone()))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
    let role_id: RoleId = "soracloud_operator".parse().expect("valid role id");
    let role = Role::new(role_id.clone(), BOB_ID.clone())
        .add_permission(Permission::new(
            CAN_MANAGE_SORACLOUD_PERMISSION.into(),
            Json::new(()),
        ))
        .build(&BOB_ID);
    state_transaction.world.roles.insert(role_id.clone(), role);
    state_transaction.world.account_roles.insert(
        crate::role::RoleIdWithOwner::new(BOB_ID.clone(), role_id),
        (),
    );
    require_soracloud_permission(&BOB_ID, &state_transaction)?;
    Ok(())
}
#[test]
fn soracloud_permission_rejects_same_name_wrong_payload_direct_and_role() -> Result<(), eyre::Report>
{
    let kura = Kura::blank_kura_for_testing();
    let state = state_with_soracloud_permission(&kura)?;
    let block_header = ValidBlock::new_dummy(&checked_keypair().into_parts().1)
        .as_ref()
        .header();
    let mut state_block = state.block(block_header);
    let mut state_transaction = state_block.transaction();
    Register::account(Account::new(BOB_ID.clone()))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
    state_transaction.world.add_account_permission(
        &BOB_ID,
        Permission::new(CAN_MANAGE_SORACLOUD_PERMISSION.into(), Json::new("all")),
    );
    let role_id: RoleId = "malformed_soracloud_operator"
        .parse()
        .expect("valid role id");
    let role = Role::new(role_id.clone(), BOB_ID.clone())
        .add_permission(Permission::new(
            CAN_MANAGE_SORACLOUD_PERMISSION.into(),
            Json::new(true),
        ))
        .build(&BOB_ID);
    state_transaction.world.roles.insert(role_id.clone(), role);
    state_transaction.world.account_roles.insert(
        crate::role::RoleIdWithOwner::new(BOB_ID.clone(), role_id),
        (),
    );
    let error = require_soracloud_permission(&BOB_ID, &state_transaction)
        .expect_err("same-name permissions with non-unit payloads must not authorize");
    assert!(matches!(
        error,
        InstructionExecutionError::InvariantViolation(message)
            if message.as_ref() == "not permitted: CanManageSoracloud"
    ));
    Ok(())
}
#[test]
fn soracloud_active_validator_authority_rejects_mismatched_public_lane_validator_rows()
-> Result<(), eyre::Report> {
    let kura = Kura::blank_kura_for_testing();
    let state = state_with_soracloud_permission(&kura)?;
    let block_header = ValidBlock::new_dummy(&checked_keypair().into_parts().1)
        .as_ref()
        .header();
    let mut state_block = state.block(block_header);
    let mut state_transaction = state_block.transaction();
    Register::account(Account::new(BOB_ID.clone()))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
    state_transaction.world.public_lane_validators.insert(
        (LaneId::SINGLE, BOB_ID.clone()),
        PublicLaneValidatorRecord {
            lane_id: LaneId::new(8),
            validator: BOB_ID.clone(),
            peer_id: PeerId::from(BOB_ID.expect_single_signatory().clone()),
            stake_account: BOB_ID.clone(),
            total_stake: Quantity::from(9_000_u64),
            self_stake: Quantity::from(9_000_u64),
            metadata: Metadata::default(),
            status: PublicLaneValidatorStatus::Active,
            activation_height: 1,
            election_exit_height: None,
            deactivation_height: None,
        },
    );
    assert!(
        require_active_public_lane_validator(&BOB_ID, &state_transaction).is_err(),
        "a row whose storage-key lane disagrees with the embedded record lane must not grant Soracloud runtime authority"
    );
    state_transaction.world.public_lane_validators.insert(
        (LaneId::SINGLE, BOB_ID.clone()),
        PublicLaneValidatorRecord {
            lane_id: LaneId::SINGLE,
            validator: ALICE_ID.clone(),
            peer_id: PeerId::from(BOB_ID.expect_single_signatory().clone()),
            stake_account: BOB_ID.clone(),
            total_stake: Quantity::from(8_000_u64),
            self_stake: Quantity::from(8_000_u64),
            metadata: Metadata::default(),
            status: PublicLaneValidatorStatus::Active,
            activation_height: 1,
            election_exit_height: None,
            deactivation_height: None,
        },
    );
    assert!(
        require_active_public_lane_validator(&BOB_ID, &state_transaction).is_err(),
        "a row whose storage-key validator disagrees with the embedded record validator must not grant Soracloud runtime authority"
    );
    Ok(())
}
fn insert_active_public_lane_validator(
    state_transaction: &mut StateTransaction<'_, '_>,
    validator: AccountId,
    total_stake: u64,
) {
    let bonded = Quantity::from(total_stake);
    state_transaction.world.public_lane_validators.insert(
        (LaneId::SINGLE, validator.clone()),
        PublicLaneValidatorRecord {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            peer_id: PeerId::from(validator.expect_single_signatory().clone()),
            stake_account: validator.clone(),
            total_stake: bonded.clone(),
            self_stake: bonded.clone(),
            metadata: Metadata::default(),
            status: PublicLaneValidatorStatus::Active,
            activation_height: 1,
            election_exit_height: None,
            deactivation_height: None,
        },
    );
    state_transaction.world.public_lane_stake_shares.insert(
        (LaneId::SINGLE, validator.clone(), validator.clone()),
        PublicLaneStakeShare {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            staker: validator,
            bonded,
            pending_unbonds: BTreeMap::new(),
            metadata: Metadata::default(),
        },
    );
}
fn install_future_created_autoscale_lane(
    state_transaction: &mut StateTransaction<'_, '_>,
    lane_id: LaneId,
    created_height: u64,
) {
    let mut lane = LaneConfig {
        id: lane_id,
        alias: format!("elastic-lane-{}", lane_id.as_u32()),
        dataspace_id: DataSpaceId::UNIVERSAL,
        visibility: LaneVisibility::Public,
        ..LaneConfig::default()
    };
    lane.metadata
        .insert(AUTOSCALE_META_MANAGED.to_owned(), "true".to_owned());
    lane.metadata.insert(
        AUTOSCALE_META_CREATED_HEIGHT.to_owned(),
        created_height.to_string(),
    );
    crate::state::attach_synthetic_autoscale_committee_for_test(&mut lane);
    let lane_count = NonZeroU32::new(lane_id.as_u32().saturating_add(1))
        .expect("future-created lane count must be nonzero");

    state_transaction.nexus.autoscale.enabled = true;
    state_transaction.nexus.autoscale.min_lane_id = NonZeroU32::new(1).expect("nonzero min");
    state_transaction.nexus.autoscale.max_lane_id_exclusive = lane_count;
    state_transaction.nexus.lane_catalog =
        LaneCatalog::new(lane_count, vec![LaneConfig::default(), lane])
            .expect("future-created autoscale lane catalog");
    state_transaction.nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(
            &state_transaction.nexus.lane_catalog,
        );
}
fn insert_active_public_lane_validator_on_lane(
    state_transaction: &mut StateTransaction<'_, '_>,
    lane_id: LaneId,
    validator: AccountId,
    total_stake: u64,
) {
    let bonded = Quantity::from(total_stake);
    state_transaction.world.public_lane_validators.insert(
        (lane_id, validator.clone()),
        PublicLaneValidatorRecord {
            lane_id,
            validator: validator.clone(),
            peer_id: PeerId::from(validator.expect_single_signatory().clone()),
            stake_account: validator.clone(),
            total_stake: bonded.clone(),
            self_stake: bonded.clone(),
            metadata: Metadata::default(),
            status: PublicLaneValidatorStatus::Active,
            activation_height: 1,
            election_exit_height: None,
            deactivation_height: None,
        },
    );
    state_transaction.world.public_lane_stake_shares.insert(
        (lane_id, validator.clone(), validator.clone()),
        PublicLaneStakeShare {
            lane_id,
            validator: validator.clone(),
            staker: validator,
            bonded,
            pending_unbonds: BTreeMap::new(),
            metadata: Metadata::default(),
        },
    );
}
#[test]
fn soracloud_active_validator_authority_rejects_future_created_autoscale_lane_record()
-> Result<(), eyre::Report> {
    let kura = Kura::blank_kura_for_testing();
    let state = state_with_soracloud_permission(&kura)?;
    let block_header = ValidBlock::new_dummy(&checked_keypair().into_parts().1)
        .as_ref()
        .header();
    let mut state_block = state.block(block_header);
    let mut state_transaction = state_block.transaction();
    Register::account(Account::new(BOB_ID.clone()))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
    let future_lane = LaneId::new(1);
    install_future_created_autoscale_lane(&mut state_transaction, future_lane, 7);
    insert_active_public_lane_validator_on_lane(
        &mut state_transaction,
        future_lane,
        BOB_ID.clone(),
        9_000,
    );
    assert!(
        require_active_public_lane_validator(&BOB_ID, &state_transaction).is_err(),
        "active validator rows on future-created autoscale lanes must not grant Soracloud runtime authority before activation"
    );
    Ok(())
}
fn sample_bundle(
    service_name: &str,
    service_version: &str,
    canary_percent: u8,
) -> SoraDeploymentBundleV1 {
    let container = SoraContainerManifestV1 {
        schema_version: iroha_data_model::soracloud::SORA_CONTAINER_MANIFEST_VERSION_V1,
        runtime: SoraContainerRuntimeV1::Ivm,
        bundle_hash: Hash::new(format!("bundle:{service_name}:{service_version}").as_bytes()),
        bundle_path: "/bundles/service.ivm".to_string(),
        entrypoint: "main".to_string(),
        args: Vec::new(),
        env: std::collections::BTreeMap::new(),
        inrou: None,
        required_config_names: Vec::new(),
        required_secret_names: Vec::new(),
        config_exports: Vec::new(),
        capabilities: SoraCapabilityPolicyV1 {
            network: SoraNetworkPolicyV1::Allowlist(vec![SoraNetworkAllowlistEntryV1::new(
                "api.example.test",
                [443],
            )]),
            allow_state_writes: false,
            allow_model_inference: false,
            allow_model_training: false,
        },
        resources: SoraResourceLimitsV1 {
            cpu_millis: NonZeroU32::new(500).expect("nonzero"),
            memory_bytes: NonZeroU64::new(128 * 1024 * 1024).expect("nonzero"),
            ephemeral_storage_bytes: NonZeroU64::new(64 * 1024 * 1024).expect("nonzero"),
            max_open_files_per_process: NonZeroU32::new(1024).expect("nonzero"),
            max_tasks: NonZeroU16::new(32).expect("nonzero"),
        },
        lifecycle: SoraLifecycleHooksV1 {
            start_grace_secs: NonZeroU32::new(10).expect("nonzero"),
            stop_grace_secs: NonZeroU32::new(10).expect("nonzero"),
            healthcheck_path: Some("/health".to_string()),
        },
    };
    let container_manifest_hash = Hash::new(Encode::encode(&container));
    SoraDeploymentBundleV1 {
        schema_version: iroha_data_model::soracloud::SORA_DEPLOYMENT_BUNDLE_VERSION_V1,
        container,
        service: SoraServiceManifestV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_MANIFEST_VERSION_V1,
            service_name: service_name.parse().expect("valid name"),
            service_version: service_version.to_string(),
            execution_plane:
                iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::DeterministicService,
            container: SoraContainerManifestRefV1 {
                manifest_hash: container_manifest_hash,
                expected_schema_version:
                    iroha_data_model::soracloud::SORA_CONTAINER_MANIFEST_VERSION_V1,
            },
            replicas: NonZeroU16::new(2).expect("nonzero"),
            placement_targets: BTreeSet::new(),
            route: Some(SoraRouteTargetV1 {
                host: format!("{service_name}.example.test"),
                path_prefix: "/".to_string(),
                service_port: NonZeroU16::new(8080).expect("nonzero"),
                visibility: SoraRouteVisibilityV1::Public,
                tls_mode: SoraTlsModeV1::Required,
            }),
            rollout: SoraRolloutPolicyV1 {
                canary_percent,
                max_unavailable_replicas: 0,
                health_window_secs: NonZeroU32::new(30).expect("nonzero"),
                automatic_rollback_failures: NonZeroU32::new(2).expect("nonzero"),
            },
            economics: Default::default(),
            state_bindings: vec![SoraStateBindingV1 {
                schema_version: iroha_data_model::soracloud::SORA_STATE_BINDING_VERSION_V1,
                binding_name: "session".parse().expect("valid name"),
                key_prefix: "/state/session".to_string(),
                scope: SoraStateScopeV1::ServiceState,
                encryption: SoraStateEncryptionV1::Plaintext,
                mutability: SoraStateMutabilityV1::ReadOnly,
                max_item_bytes: NonZeroU64::new(1024).expect("nonzero"),
                max_total_bytes: NonZeroU64::new(2048).expect("nonzero"),
            }],
            lease_volumes: Vec::new(),
            handlers: vec![SoraServiceHandlerV1 {
                handler_name: "query".parse().expect("valid name"),
                class: SoraServiceHandlerClassV1::Query,
                entrypoint: "serve_query".to_string(),
                route_path: Some("/query".to_string()),
                certified_response: SoraCertifiedResponsePolicyV1::AuditReceipt,
                mailbox: None,
            }],
            artifacts: vec![SoraArtifactRefV1 {
                kind: SoraArtifactKindV1::StaticAsset,
                artifact_hash: Hash::new(
                    format!("asset:{service_name}:{service_version}").as_bytes(),
                ),
                artifact_path: "/public/index.html".to_string(),
                handler_name: Some("query".parse().expect("valid name")),
            }],
        },
    }
}
fn sample_inrou_manifest() -> SoraInrouManifestV1 {
    SoraInrouManifestV1 {
        schema_version: iroha_data_model::soracloud::SORA_INROU_MANIFEST_VERSION_V1,
        guest_images: std::collections::BTreeMap::from([
            (
                iroha_data_model::soracloud::SoraInrouGuestIsaV1::X8664,
                iroha_data_model::soracloud::SoraInrouGuestImageV1 {
                    kernel_image_path: "/inrou/x86_64/vmlinux".to_string(),
                    rootfs_image_path: "/inrou/x86_64/rootfs.ext4".to_string(),
                    initrd_image_path: None,
                    published_artifact: sample_inrou_published_artifact(),
                },
            ),
            (
                iroha_data_model::soracloud::SoraInrouGuestIsaV1::Aarch64,
                iroha_data_model::soracloud::SoraInrouGuestImageV1 {
                    kernel_image_path: "/inrou/aarch64/vmlinux".to_string(),
                    rootfs_image_path: "/inrou/aarch64/rootfs.ext4".to_string(),
                    initrd_image_path: None,
                    published_artifact: sample_inrou_published_artifact(),
                },
            ),
        ]),
    }
}
fn sample_inrou_lease_volumes() -> Vec<SoraLeaseVolumeBindingV1> {
    vec![
        SoraLeaseVolumeBindingV1 {
            volume_name: "root_disk".parse().expect("valid name"),
            kind: SoraLeaseVolumeKindV1::PersistentRootLeaseVolume,
            storage_class: StorageClass::Warm,
            mount_path: "/".to_string(),
            max_total_bytes: NonZeroU64::new(8 * 1024 * 1024 * 1024).expect("nonzero"),
        },
        SoraLeaseVolumeBindingV1 {
            volume_name: "service_state".parse().expect("valid name"),
            kind: SoraLeaseVolumeKindV1::ServiceLeaseVolume,
            storage_class: StorageClass::Warm,
            mount_path: "/var/lib/soracloud/volumes/service_state".to_string(),
            max_total_bytes: NonZeroU64::new(1024 * 1024).expect("nonzero"),
        },
    ]
}
fn sample_inrou_replica_runtime_state_for(
    service_name: iroha_model_base::name::Name,
    service_version: &str,
    replica_slot: u16,
    validator_account_id: AccountId,
) -> SoraInrouReplicaRuntimeStateV1 {
    let peer_id = PeerId::from(validator_account_id.expect_single_signatory().clone()).to_string();
    SoraInrouReplicaRuntimeStateV1 {
        schema_version: SORA_INROU_REPLICA_RUNTIME_STATE_VERSION_V1,
        service_name,
        service_version: service_version.to_string(),
        replica_slot,
        placement_incarnation: Hash::new(b"placement-1"),
        validator_account_id,
        peer_id,
        selected_guest_isa: SoraInrouGuestIsaV1::Aarch64,
        health_status: iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        load_factor_bps: 250,
        materialized_bundle_hash: Hash::new(b"inrou-runtime-state-test-bundle"),
        reporting_epoch: 1,
        accounted_egress_bytes: 0,
        updated_at_ms: 1_000,
        last_error: None,
    }
}
fn sample_inrou_service_placement_record_for(
    service_name: iroha_model_base::name::Name,
    service_version: &str,
    runtime_state: &SoraInrouReplicaRuntimeStateV1,
) -> SoraInrouServicePlacementRecordV1 {
    SoraInrouServicePlacementRecordV1 {
        schema_version: SORA_INROU_SERVICE_PLACEMENT_RECORD_VERSION_V1,
        service_name,
        service_version: service_version.to_string(),
        desired_replica_count: runtime_state.replica_slot,
        eligible_validator_count: 1,
        placements: vec![SoraInrouReplicaPlacementV1 {
            replica_slot: runtime_state.replica_slot,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            lease_started_height: 1,
            placement_incarnation: Hash::new(b"placement-1"),
            host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
            validator_account_id: runtime_state.validator_account_id.clone(),
            peer_id: runtime_state.peer_id.clone(),
            selected_guest_isa: runtime_state.selected_guest_isa,
        }],
        reconciled_at_ms: 1_000,
        last_error: None,
    }
}
#[test]
fn service_runtime_mutations_require_exact_validator_placement() -> Result<(), eyre::Report> {
    let kura = Kura::blank_kura_for_testing();
    let state = state_with_initial_soracloud_permission(&kura)?;
    let block_header = initial_soracloud_header(&state, 2);
    let mut state_block = state.block(block_header);
    let mut stx = state_block.transaction();
    Register::account(Account::new(BOB_ID.clone()))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut stx)?;
    insert_active_public_lane_validator(&mut stx, BOB_ID.clone(), 500);
    let mut bundle = sample_bundle("victim_runtime", "1.0.0", 0);
    bundle.service.handlers.push(SoraServiceHandlerV1 {
        handler_name: "update".parse().expect("valid name"),
        class: SoraServiceHandlerClassV1::Update,
        entrypoint: "apply_update".to_string(),
        route_path: Some("/update".to_string()),
        certified_response: SoraCertifiedResponsePolicyV1::None,
        mailbox: Some(SoraMailboxContractV1 {
            queue_name: "updates".parse().expect("valid queue"),
            max_pending_messages: NonZeroU32::new(1).expect("nonzero"),
            max_message_bytes: NonZeroU64::new(16).expect("nonzero"),
            retention_blocks: NonZeroU32::new(3).expect("nonzero"),
        }),
    });
    bundle.container.capabilities.allow_state_writes = true;
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    isi::DeploySoracloudService {
        bundle: bundle.clone(),
        initial_service_configs: BTreeMap::new(),
        initial_service_secrets: BTreeMap::new(),
        precondition: SoraServiceMutationPreconditionV1::ServiceAbsent,
        provenance: bundle_provenance(&bundle),
    }
    .execute(&ALICE_ID, &mut stx)?;
    let victim_name = bundle.service.service_name.clone();
    let victim_version = bundle.service.service_version.as_str();
    let mut other_bundle = sample_hosted_http_service_bundle("assigned_elsewhere", "2.0.0", 0);
    other_bundle.service.replicas = NonZeroU16::new(1).expect("nonzero replicas");
    isi::DeploySoracloudService {
        bundle: other_bundle.clone(),
        initial_service_configs: BTreeMap::new(),
        initial_service_secrets: BTreeMap::new(),
        precondition: SoraServiceMutationPreconditionV1::ServiceAbsent,
        provenance: bundle_provenance(&other_bundle),
    }
    .execute(&ALICE_ID, &mut stx)?;
    let other_name = other_bundle.service.service_name.clone();
    let other_version = other_bundle.service.service_version.as_str();
    let mut lease_victim_bundle =
        sample_hosted_http_service_bundle("unassigned_hosted", "1.0.0", 0);
    lease_victim_bundle.service.replicas = NonZeroU16::new(1).expect("nonzero replicas");
    isi::DeploySoracloudService {
        bundle: lease_victim_bundle.clone(),
        initial_service_configs: BTreeMap::new(),
        initial_service_secrets: BTreeMap::new(),
        precondition: SoraServiceMutationPreconditionV1::ServiceAbsent,
        provenance: bundle_provenance(&lease_victim_bundle),
    }
    .execute(&ALICE_ID, &mut stx)?;
    let lease_victim_name = lease_victim_bundle.service.service_name.clone();
    let lease_victim_version = lease_victim_bundle.service.service_version.as_str();
    stx.world.soracloud_inrou_host_capabilities.insert(
        BOB_ID.clone(),
        SoraInrouHostCapabilityRecordV1 {
            schema_version:
                iroha_data_model::soracloud::SORA_INROU_HOST_CAPABILITY_RECORD_VERSION_V1,
            validator_account_id: BOB_ID.clone(),
            peer_id: PeerId::from(BOB_ID.expect_single_signatory().clone()).to_string(),
            supported_guest_isas: BTreeSet::from([SoraInrouGuestIsaV1::Aarch64]),
            trusted_guest_artifact: sample_inrou_published_artifact(),
            max_hosted_replica_capacity: 1,
            max_cpu_millis: 1_000,
            max_memory_bytes: 1_073_741_824,
            max_storage_bytes: 16 * 1_073_741_824,
            advertised_at_ms: 1,
            heartbeat_expires_at_ms: u64::MAX,
        },
    );
    let bob_other_runtime = sample_inrou_replica_runtime_state_for(
        other_name.clone(),
        other_version,
        1,
        BOB_ID.clone(),
    );
    let bob_other_placement = sample_inrou_service_placement_record_for(
        other_name.clone(),
        other_version,
        &bob_other_runtime,
    );
    stx.world.soracloud_inrou_service_placements.insert(
        (
            bob_other_placement.service_name.as_ref().to_owned(),
            bob_other_placement.service_version.clone(),
        ),
        bob_other_placement,
    );
    assert_eq!(
        require_soracloud_service_runtime_authority(&ALICE_ID, &victim_name, victim_version, &stx,)?,
        SoracloudServiceRuntimeAuthority::Manager
    );
    assert_eq!(
        require_soracloud_service_runtime_authority(&BOB_ID, &other_name, other_version, &stx,)?,
        SoracloudServiceRuntimeAuthority::AssignedValidator
    );
    let bob_placement_key = (other_name.as_ref().to_owned(), other_version.to_owned());
    stx.world
        .soracloud_inrou_service_placements
        .get_mut(&bob_placement_key)
        .expect("Bob placement")
        .placements[0]
        .host_availability = SoraInrouReplicaHostAvailabilityV1::Unavailable;
    require_soracloud_service_runtime_authority(&BOB_ID, &other_name, other_version, &stx)
        .expect_err("an unavailable assignment must not grant runtime or receipt authority");
    stx.world
        .soracloud_inrou_service_placements
        .get_mut(&bob_placement_key)
        .expect("Bob placement")
        .placements[0]
        .host_availability = SoraInrouReplicaHostAvailabilityV1::Available;
    let cross_service_error =
        require_soracloud_service_runtime_authority(&BOB_ID, &victim_name, victim_version, &stx)
            .expect_err("a placement for another service must not grant runtime authority");
    assert!(matches!(
        cross_service_error,
        InstructionExecutionError::InvariantViolation(message)
            if message.contains("is not assigned to service")
    ));
    let stale_runtime =
        sample_inrou_replica_runtime_state_for(victim_name.clone(), "0.9.0", 1, BOB_ID.clone());
    let stale_placement =
        sample_inrou_service_placement_record_for(victim_name.clone(), "0.9.0", &stale_runtime);
    stx.world.soracloud_inrou_service_placements.insert(
        (
            stale_placement.service_name.as_ref().to_owned(),
            stale_placement.service_version.clone(),
        ),
        stale_placement,
    );
    let stale_placement_error =
        require_soracloud_service_runtime_authority(&BOB_ID, &victim_name, "0.9.0", &stx)
            .expect_err("a stale placement must not grant runtime authority");
    assert!(matches!(
        stale_placement_error,
        InstructionExecutionError::InvariantViolation(message)
            if message.contains("is not assigned to service")
    ));
    let runtime_state = SoraServiceRuntimeStateV1 {
        schema_version: iroha_data_model::soracloud::SORA_SERVICE_RUNTIME_STATE_VERSION_V1,
        service_name: victim_name.clone(),
        active_service_version: victim_version.to_owned(),
        health_status: iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        load_factor_bps: 125,
        materialized_bundle_hash: bundle.container.bundle_hash,
    };
    let runtime_state_error = execute_initial_soracloud(
        isi::SetSoracloudRuntimeState {
            state: runtime_state.clone(),
        },
        &BOB_ID,
        &mut stx,
    )
    .expect_err("a validator assigned elsewhere must not replace runtime state");
    assert_initial_soracloud_core_denial(runtime_state_error, "is not assigned to service");
    assert!(
        stx.world
            .soracloud_service_runtime
            .get(&victim_name)
            .is_none()
    );
    let deployment_before_usage = stx
        .world
        .soracloud_service_deployments
        .get(&lease_victim_name)
        .cloned()
        .expect("unassigned hosted-service deployment");
    let reporting_epoch = deployment_before_usage
        .service_lease
        .as_ref()
        .expect("unassigned hosted-service lease")
        .reporting_epoch;
    let lease_started_height = deployment_before_usage
        .service_lease
        .as_ref()
        .expect("unassigned hosted-service lease")
        .lease_started_height;
    let lease_error = execute_initial_soracloud(
        isi::ReportSoracloudServiceLeaseUsage {
            service_name: lease_victim_name.clone(),
            lease_started_height,
            reporting_epoch,
            active_service_version: lease_victim_version.to_owned(),
            replica_slot: 1,
            placement_incarnation: Hash::new(b"placement-1"),
            replica_accounted_egress_bytes: u64::MAX,
            finalize_reporter: false,
        },
        &BOB_ID,
        &mut stx,
    )
    .expect_err("a validator assigned elsewhere must not inflate lease usage");
    assert_initial_soracloud_core_denial(lease_error, "is not assigned to service");
    assert_eq!(
        stx.world
            .soracloud_service_deployments
            .get(&lease_victim_name),
        Some(&deployment_before_usage)
    );
    let mailbox_message = SoraServiceMailboxMessageV1 {
        schema_version: iroha_data_model::soracloud::SORA_SERVICE_MAILBOX_MESSAGE_VERSION_V1,
        message_id: Hash::prehashed([0; Hash::LENGTH]),
        from_service: victim_name.clone(),
        from_service_version: String::new(),
        from_handler: "update".parse().expect("valid handler"),
        to_service: victim_name.clone(),
        to_service_version: String::new(),
        to_handler: "update".parse().expect("valid handler"),
        payload_bytes: b"payload".to_vec(),
        payload_commitment: Hash::new(b"payload"),
        delivery_delay_blocks: 2,
        enqueue_sequence: 0,
        enqueue_height: 0,
        available_after_height: 0,
        expires_at_height: 0,
    };
    let sequence_before_mailbox = *stx.world.soracloud_sequence_watermark.get();
    let mailbox_error = isi::RecordSoracloudMailboxMessage {
        message: mailbox_message.clone(),
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("a validator assigned elsewhere must not forge source-service messages");
    assert!(matches!(
        mailbox_error,
        InstructionExecutionError::InvariantViolation(message)
            if message.contains("is not assigned to service")
    ));
    assert!(stx.world.soracloud_mailbox_messages.is_empty());
    let mut undeployed_source_message = mailbox_message.clone();
    undeployed_source_message.from_service =
        "undeployed_source".parse().expect("valid service name");
    let undeployed_source_error = isi::RecordSoracloudMailboxMessage {
        message: undeployed_source_message.clone(),
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("even a manager must not forge messages from an undeployed service");
    assert!(matches!(
        undeployed_source_error,
        InstructionExecutionError::InvariantViolation(message)
            if message.contains("source service")
    ));
    assert!(stx.world.soracloud_mailbox_messages.is_empty());
    let closed_mailbox = isi::RecordSoracloudMailboxMessage {
        message: mailbox_message.clone(),
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("ordered mailbox admission remains disabled even for a manager");
    assert_invariant_contains(
        closed_mailbox,
        "disabled until consensus can re-execute the exact admitted IVM bundle",
    );
    assert!(stx.world.soracloud_mailbox_messages.is_empty());
    let closed_initial_mailbox = execute_initial_soracloud(
        isi::RecordSoracloudMailboxMessage {
            message: mailbox_message.clone(),
        },
        &ALICE_ID,
        &mut stx,
    )
    .expect_err("Initial executor must explicitly close unfinished mailbox admission");
    assert!(
        matches!(closed_initial_mailbox, ValidationFail::NotPermitted(message)
        if message.contains("explicitly closed"))
    );
    assert!(stx.world.soracloud_mailbox_messages.is_empty());
    assert_eq!(
        *stx.world.soracloud_sequence_watermark.get(),
        sequence_before_mailbox
    );
    let mut runtime_receipt = SoraRuntimeReceiptV1 {
        schema_version: iroha_data_model::soracloud::SORA_RUNTIME_RECEIPT_VERSION_V1,
        receipt_id: Hash::new(b"cross-service-runtime-receipt"),
        service_name: victim_name.clone(),
        service_version: victim_version.to_owned(),
        handler_name: "query".parse().expect("valid handler"),
        handler_class: SoraServiceHandlerClassV1::Query,
        request_commitment: Hash::new(b"request"),
        result_commitment: Hash::new(b"result"),
        certified_by: SoraCertifiedResponsePolicyV1::AuditReceipt,
        emitted_sequence: 0,
        execution_host: None,
        mailbox_message_id: None,
        journal_artifact_hash: None,
        checkpoint_artifact_hash: None,
    };
    runtime_receipt.receipt_id =
        iroha_data_model::soracloud::derive_soracloud_local_read_receipt_id_v1(&runtime_receipt);
    let mailbox_receipt = SoraRuntimeReceiptV1 {
        schema_version: iroha_data_model::soracloud::SORA_RUNTIME_RECEIPT_VERSION_V1,
        receipt_id: Hash::new(b"mailbox-runtime-receipt"),
        service_name: victim_name.clone(),
        service_version: victim_version.to_owned(),
        handler_name: "update".parse().expect("valid handler"),
        handler_class: SoraServiceHandlerClassV1::Update,
        request_commitment: mailbox_message.payload_commitment,
        result_commitment: Hash::new(b"mailbox-result"),
        certified_by: SoraCertifiedResponsePolicyV1::None,
        emitted_sequence: 0,
        execution_host: None,
        mailbox_message_id: Some(Hash::new(b"unadmitted-mailbox-message")),
        journal_artifact_hash: None,
        checkpoint_artifact_hash: None,
    };
    let closed_result = isi::ApplySoracloudOrderedMailboxResult {
        result: iroha_data_model::soracloud::SoraOrderedMailboxResultV1 {
            schema_version: iroha_data_model::soracloud::SORA_ORDERED_MAILBOX_RESULT_VERSION_V1,
            observed_height: 1,
            observed_block_hash: None,
            observed_sequence: 1,
            state_mutations: Vec::new(),
            outbound_mailbox_messages: Vec::new(),
            response_commitment: Hash::new(b"closed-mailbox-response"),
            runtime_execution_commitment: Hash::new(b"closed-mailbox-execution"),
            content_type: None,
            observed_runtime_state: None,
            runtime_state: None,
            runtime_receipt: mailbox_receipt.clone(),
        },
    };
    let initial_error = execute_initial_soracloud(closed_result.clone(), &ALICE_ID, &mut stx)
        .expect_err(
            "Initial must close atomic mailbox results until consensus re-execution exists",
        );
    assert!(
        matches!(initial_error, ValidationFail::NotPermitted(message)
        if message.contains("explicitly closed"))
    );
    let core_error = closed_result
        .execute(&ALICE_ID, &mut stx)
        .expect_err("Core must independently keep ordered mailbox execution disabled");
    assert_invariant_contains(
        core_error,
        "disabled until consensus can re-execute the exact admitted IVM bundle",
    );
    assert!(stx.world.soracloud_mailbox_messages.is_empty());
    assert!(stx.world.soracloud_runtime_receipts.is_empty());
    assert_eq!(
        *stx.world.soracloud_sequence_watermark.get(),
        sequence_before_mailbox
    );
    let direct_mailbox_receipt_error = execute_initial_soracloud(
        isi::RecordSoracloudRuntimeReceipt {
            receipt: mailbox_receipt.clone(),
        },
        &ALICE_ID,
        &mut stx,
    )
    .expect_err("ordered mailbox work must be consumed through its atomic result instruction");
    assert_initial_soracloud_core_denial(
        direct_mailbox_receipt_error,
        "ordered-mailbox runtime receipts must use ApplySoracloudOrderedMailboxResult",
    );
    assert!(
        stx.world
            .soracloud_runtime_receipts
            .get(&mailbox_receipt.receipt_id)
            .is_none()
    );
    let receipt_error = execute_initial_soracloud(
        isi::RecordSoracloudRuntimeReceipt {
            receipt: runtime_receipt.clone(),
        },
        &BOB_ID,
        &mut stx,
    )
    .expect_err("a validator assigned elsewhere must not forge runtime receipts");
    assert_initial_soracloud_core_denial(
        receipt_error,
        "validator-attributed runtime receipts must use ApplySoracloudOrderedMailboxResult",
    );
    assert!(
        stx.world
            .soracloud_runtime_receipts
            .get(&runtime_receipt.receipt_id)
            .is_none()
    );
    execute_initial_soracloud(
        isi::RecordSoracloudRuntimeReceipt {
            receipt: runtime_receipt.clone(),
        },
        &ALICE_ID,
        &mut stx,
    )?;
    let persisted_runtime_receipt = stx
        .world
        .soracloud_runtime_receipts
        .get(&runtime_receipt.receipt_id)
        .cloned()
        .expect("runtime receipt persisted with a ledger-assigned sequence");
    assert!(persisted_runtime_receipt.emitted_sequence > 0);
    let receipt_collision_error = execute_initial_soracloud(
        isi::RecordSoracloudRuntimeReceipt {
            receipt: runtime_receipt.clone(),
        },
        &ALICE_ID,
        &mut stx,
    )
    .expect_err("an exact runtime receipt must not be recorded twice");
    assert_initial_soracloud_core_denial(receipt_collision_error, "has already been recorded");
    assert_eq!(
        stx.world
            .soracloud_runtime_receipts
            .get(&runtime_receipt.receipt_id),
        Some(&persisted_runtime_receipt)
    );
    assert_eq!(
        require_soracloud_service_runtime_authority(&BOB_ID, &other_name, other_version, &stx,)?,
        SoracloudServiceRuntimeAuthority::AssignedValidator
    );
    let mut falsely_attributed_receipt = runtime_receipt;
    falsely_attributed_receipt.receipt_id = Hash::new(b"falsely-attributed-runtime-receipt");
    falsely_attributed_receipt.service_name = other_name.clone();
    falsely_attributed_receipt.service_version = other_version.to_owned();
    falsely_attributed_receipt.execution_host = Some(SoraRuntimeDeterministicValidatorHostV1 {
        lane_id: LaneId::SINGLE,
        validator_account_id: ALICE_ID.clone(),
        peer_id: PeerId::from(ALICE_ID.expect_single_signatory().clone()).to_string(),
    });
    let attribution_error = execute_initial_soracloud(
        isi::RecordSoracloudRuntimeReceipt {
            receipt: falsely_attributed_receipt.clone(),
        },
        &BOB_ID,
        &mut stx,
    )
    .expect_err("an assigned validator must identify itself in its runtime receipt");
    assert_initial_soracloud_core_denial(
        attribution_error,
        "validator-attributed runtime receipts must use ApplySoracloudOrderedMailboxResult",
    );
    assert!(
        stx.world
            .soracloud_runtime_receipts
            .get(&falsely_attributed_receipt.receipt_id)
            .is_none()
    );
    let other_runtime_state = SoraServiceRuntimeStateV1 {
        schema_version: iroha_data_model::soracloud::SORA_SERVICE_RUNTIME_STATE_VERSION_V1,
        service_name: other_name.clone(),
        active_service_version: other_version.to_owned(),
        health_status: iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        load_factor_bps: 125,
        materialized_bundle_hash: other_bundle.container.bundle_hash,
    };
    execute_initial_soracloud(
        isi::SetSoracloudRuntimeState {
            state: other_runtime_state.clone(),
        },
        &BOB_ID,
        &mut stx,
    )?;
    assert_eq!(
        stx.world.soracloud_service_runtime.get(&other_name),
        Some(&other_runtime_state)
    );
    Ok(())
}
fn bundle_provenance(bundle: &SoraDeploymentBundleV1) -> ManifestProvenance {
    bundle_provenance_with_precondition(bundle, &SoraServiceMutationPreconditionV1::ServiceAbsent)
}
fn bundle_provenance_with_precondition(
    bundle: &SoraDeploymentBundleV1,
    precondition: &SoraServiceMutationPreconditionV1,
) -> ManifestProvenance {
    let payload = iroha_data_model::soracloud::encode_bundle_with_materials_provenance_payload(
        bundle,
        &BTreeMap::new(),
        &BTreeMap::new(),
        precondition,
    )
    .expect("bundle payload");
    ManifestProvenance {
        signer: ALICE_KEYPAIR.public_key().clone(),
        signature: checked_signature(ALICE_KEYPAIR.private_key(), &payload),
    }
}
fn app_infra_provenance_with_precondition(
    manifest: &SoraAppInfraManifestV1,
    precondition: &SoraAppInfraMutationPreconditionV1,
) -> ManifestProvenance {
    let payload = encode_app_infra_provenance_payload(manifest, precondition)
        .expect("app infra provenance payload");
    ManifestProvenance {
        signer: ALICE_KEYPAIR.public_key().clone(),
        signature: checked_signature(ALICE_KEYPAIR.private_key(), &payload),
    }
}
fn exact_app_infra_precondition(
    manifest: &SoraAppInfraManifestV1,
    revision_count: u32,
) -> SoraAppInfraMutationPreconditionV1 {
    SoraAppInfraMutationPreconditionV1::ExactCurrentRevision(
        SoraAppInfraExactCurrentRevisionPreconditionV1 {
            app_version: manifest.app_version.clone(),
            manifest_hash: manifest.manifest_hash(),
            revision_count,
        },
    )
}
fn exact_service_revision_precondition(
    bundle: &SoraDeploymentBundleV1,
    process_generation: u64,
) -> SoraServiceMutationPreconditionV1 {
    SoraServiceMutationPreconditionV1::ExactCurrentRevision(
        SoraServiceExactCurrentRevisionPreconditionV1 {
            service_version: bundle.service.service_version.clone(),
            service_manifest_hash: bundle.service_manifest_hash(),
            container_manifest_hash: bundle.container_manifest_hash(),
            process_generation,
            config_generation: 0,
            secret_generation: 0,
        },
    )
}
fn rollback_provenance(
    service_name: &iroha_model_base::name::Name,
    target_version: &str,
) -> ManifestProvenance {
    let payload = encode_rollback_provenance_payload(service_name.as_ref(), target_version)
        .expect("rollback payload");
    ManifestProvenance {
        signer: ALICE_KEYPAIR.public_key().clone(),
        signature: checked_signature(ALICE_KEYPAIR.private_key(), &payload),
    }
}
fn rollout_provenance(
    service_name: &iroha_model_base::name::Name,
    rollout_handle: &str,
    healthy: bool,
    promote_to_percent: Option<u8>,
    governance_tx_hash: Hash,
) -> ManifestProvenance {
    let payload = encode_rollout_provenance_payload(
        service_name.as_ref(),
        rollout_handle,
        healthy,
        promote_to_percent,
        governance_tx_hash,
    )
    .expect("rollout payload");
    ManifestProvenance {
        signer: ALICE_KEYPAIR.public_key().clone(),
        signature: checked_signature(ALICE_KEYPAIR.private_key(), &payload),
    }
}
fn sample_bundle_with_state_binding(
    service_name: &str,
    service_version: &str,
    canary_percent: u8,
    binding_name: &str,
    key_prefix: &str,
    encryption: SoraStateEncryptionV1,
    mutability: SoraStateMutabilityV1,
    max_item_bytes: u64,
    max_total_bytes: u64,
) -> SoraDeploymentBundleV1 {
    let mut bundle = sample_bundle(service_name, service_version, canary_percent);
    bundle.container.capabilities.allow_state_writes = true;
    bundle.service.state_bindings = vec![SoraStateBindingV1 {
        schema_version: iroha_data_model::soracloud::SORA_STATE_BINDING_VERSION_V1,
        binding_name: binding_name.parse().expect("valid name"),
        key_prefix: key_prefix.to_string(),
        scope: SoraStateScopeV1::ServiceState,
        encryption,
        mutability,
        max_item_bytes: NonZeroU64::new(max_item_bytes).expect("nonzero"),
        max_total_bytes: NonZeroU64::new(max_total_bytes).expect("nonzero"),
    }];
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    bundle
}
fn state_mutation_provenance(
    service_name: &iroha_model_base::name::Name,
    binding_name: &iroha_model_base::name::Name,
    state_key: &str,
    operation: SoraStateMutationOperationV1,
    value_size_bytes: Option<u64>,
    payload_commitment: Option<Hash>,
    encryption: SoraStateEncryptionV1,
    governance_tx_hash: Hash,
    fhe_input_admission_proof: Option<SoracloudFheInputAdmissionProofV1>,
) -> ManifestProvenance {
    let operation_label = match operation {
        SoraStateMutationOperationV1::Upsert => "upsert",
        SoraStateMutationOperationV1::Delete => "delete",
    };
    let payload = encode_state_mutation_provenance_payload(
        service_name.as_ref(),
        binding_name.as_ref(),
        state_key,
        operation_label,
        value_size_bytes,
        payload_commitment,
        encryption,
        governance_tx_hash,
        fhe_input_admission_proof,
    )
    .expect("state mutation payload");
    ManifestProvenance {
        signer: ALICE_KEYPAIR.public_key().clone(),
        signature: checked_signature(ALICE_KEYPAIR.private_key(), &payload),
    }
}
fn sample_fhe_param_set() -> FheParamSetV1 {
    let registered_params = ram_lfe_bfv_parameters_v1();
    let parameter_digest = registered_bfv_parameter_digest(&registered_params)
        .expect("registered BFV parameter digest");
    let rns_modulus_chain_digest = registered_bfv_rns_modulus_chain_digest(&registered_params)
        .expect("registered BFV RNS modulus-chain digest");
    let key_switch_decomposition_chain_digest =
        registered_bfv_key_switch_decomposition_chain_digest(&registered_params)
            .expect("registered BFV key-switch decomposition-chain digest");
    FheParamSetV1 {
        schema_version: iroha_data_model::soracloud::FHE_PARAM_SET_VERSION_V1,
        param_set: "bfv-default".parse().expect("valid name"),
        version: NonZeroU32::new(1).expect("nonzero"),
        backend: "fhe/bfv-rns/v1".to_string(),
        scheme: FheSchemeV1::Bfv,
        ciphertext_modulus_bits: vec![
            NonZeroU16::new(53).expect("nonzero"),
            NonZeroU16::new(52).expect("nonzero"),
        ],
        plaintext_modulus_bits: NonZeroU16::new(9).expect("nonzero"),
        polynomial_modulus_degree: NonZeroU32::new(u32::from(registered_params.polynomial_degree))
            .expect("nonzero"),
        slot_count: NonZeroU32::new(u32::from(registered_params.polynomial_degree))
            .expect("nonzero"),
        security_level_bits: NonZeroU16::new(128).expect("nonzero"),
        max_multiplicative_depth: NonZeroU16::new(1).expect("nonzero"),
        lifecycle: FheParamLifecycleV1::Active,
        activation_height: Some(1),
        withdraw_height: None,
        parameter_digest,
        rns_modulus_chain_digest,
        key_switch_decomposition_chain_digest,
    }
}
fn sample_bfv_evaluation_key_bundle() -> BfvEvaluationKeyBundle {
    let params = ram_lfe_bfv_parameters_v1();
    let (secret_key, public_key, relinearization_key) =
        keygen_from_seed(&params, b"soracloud-fhe-test-keygen").expect("keygen");
    let packed_half_rotation = u32::from(params.polynomial_degree) / 2;
    let packed_half_rotation_power =
        packed_left_rotation_galois_automorphism_power(&params, packed_half_rotation)
            .expect("registered packed half-rotation must be one Galois automorphism");
    BfvEvaluationKeyBundle {
        relinearization_key,
        rotation_keys: vec![
            rotation_key_from_seed(&params, &public_key, 1, b"soracloud-fhe-rotation-key")
                .expect("rotation key"),
        ],
        galois_keys: vec![
            galois_key_from_seed(&params, &secret_key, 3, b"soracloud-fhe-galois-key")
                .expect("Galois key"),
            galois_key_from_seed(
                &params,
                &secret_key,
                packed_half_rotation_power,
                b"soracloud-fhe-packed-rotate-galois-key",
            )
            .expect("packed rotation Galois key"),
        ],
        bootstrap_key: Some(
            bootstrap_key_with_max_refresh_rounds_from_seed(
                &params,
                &public_key,
                "bootstrap-test-key",
                1,
                b"soracloud-fhe-bootstrap-key",
            )
            .expect("bootstrap key"),
        ),
    }
}
fn install_full_bootstrap_material(
    evaluation_keys: &mut BfvEvaluationKeyBundle,
    params: &BfvParameters,
    public_key: &BfvPublicKey,
    material: BfvFullBootstrapCircuitMaterialV1,
) {
    let key_id = evaluation_keys
        .bootstrap_key
        .as_ref()
        .expect("sample bundle carries a bootstrap key")
        .key_id
        .clone();
    evaluation_keys.bootstrap_key = Some(
        full_bootstrap_key_from_material_v1(params, public_key, key_id, material)
            .expect("construct sample full-bootstrap key"),
    );
}
fn sample_full_bootstrap_material(params: &BfvParameters) -> BfvFullBootstrapCircuitMaterialV1 {
    sample_full_bootstrap_material_and_artifacts(params).0
}
fn sample_full_bootstrap_linear_transform_artifact_payload(
    params: &BfvParameters,
    role: BfvFullBootstrapCircuitArtifactRoleV1,
) -> Vec<u8> {
    let transform = BfvFullBootstrapLinearTransformV1 {
        input_slot_count: params.polynomial_degree,
        output_slot_count: params.polynomial_degree,
        diagonals: vec![BfvFullBootstrapLinearTransformDiagonalV1 {
            rotation_steps: 0,
            plaintext: encode_packed_plaintext_slots(
                params,
                &vec![1; usize::from(params.polynomial_degree)],
            )
            .expect("encode identity packed-slot mask"),
        }],
    };
    encode_bfv_full_bootstrap_linear_transform_artifact_v1(params, 1, role, &transform)
        .expect("encode sample full-bootstrap linear transform artifact")
}
fn sample_full_bootstrap_accumulator_artifact_payload(params: &BfvParameters) -> Vec<u8> {
    let accumulator = BfvFullBootstrapAccumulatorV1 {
        slot_count: params.polynomial_degree,
        test_vector: encode_packed_plaintext_slots(
            params,
            &vec![1; usize::from(params.polynomial_degree)],
        )
        .expect("encode sample full-bootstrap accumulator test vector"),
    };
    encode_bfv_full_bootstrap_accumulator_artifact_v1(params, 1, &accumulator)
        .expect("encode sample full-bootstrap accumulator artifact")
}
fn sample_full_bootstrap_sample_extraction_switch_key_artifact_payload(
    params: &BfvParameters,
    secret_key: &BfvSecretKey,
) -> Vec<u8> {
    let sample_extraction = BfvFullBootstrapSampleExtractionV1 {
        source_slot_count: params.polynomial_degree,
        source_ciphertext_component_count: 2,
        extracted_coefficient_index: 0,
        output_ciphertext_component_count: 2,
    };
    let switch_key = bfv_full_bootstrap_sample_extraction_switch_key_from_seed_v1(
        params,
        secret_key,
        sample_extraction,
        b"soracloud-full-bootstrap-sample-switch-artifact",
    )
    .expect("build sample full-bootstrap sample switch key");
    encode_bfv_full_bootstrap_sample_extraction_switch_key_artifact_v1(params, 1, &switch_key)
        .expect("encode sample full-bootstrap sample switch-key artifact")
}
fn sample_full_bootstrap_bounded_noise_sample_extraction_switch_key_artifact_payload(
    params: &BfvParameters,
    secret_key: &BfvSecretKey,
) -> Vec<u8> {
    let sample_extraction = BfvFullBootstrapSampleExtractionV1 {
        source_slot_count: params.polynomial_degree,
        source_ciphertext_component_count: 2,
        extracted_coefficient_index: 0,
        output_ciphertext_component_count: 2,
    };
    let switch_key = bfv_full_bootstrap_sample_extraction_bounded_noise_switch_key_from_seed_v1(
        params,
        secret_key,
        sample_extraction,
        b"soracloud-full-bootstrap-bounded-sample-switch-artifact",
    )
    .expect("build sample bounded full-bootstrap sample switch key");
    encode_bfv_full_bootstrap_sample_extraction_switch_key_artifact_v1(params, 1, &switch_key)
        .expect("encode sample bounded full-bootstrap sample switch-key artifact")
}
fn sample_full_bootstrap_blind_rotation_artifact_payload(
    params: &BfvParameters,
    accumulator_digest: Hash,
) -> Vec<u8> {
    let blind_rotation_key = bfv_full_bootstrap_blind_rotation_key_for_packed_left_rotation_v1(
        params,
        accumulator_digest,
        1,
    )
    .expect("build sample full-bootstrap blind-rotation key");
    encode_bfv_full_bootstrap_blind_rotation_artifact_v1(params, 1, &blind_rotation_key)
        .expect("encode sample full-bootstrap blind-rotation artifact")
}
fn sample_full_bootstrap_proof_public_input_schema_artifact_payload(
    params: &BfvParameters,
) -> Vec<u8> {
    encode_bfv_full_bootstrap_proof_public_input_schema_artifact_v1(
        params,
        1,
        &bfv_full_bootstrap_proof_public_input_schema_v1(),
    )
    .expect("encode sample full-bootstrap proof public-input schema artifact")
}
fn sample_full_bootstrap_proof_key_artifact_payloads(
    params: &BfvParameters,
    public_input_schema_digest: Hash,
    evaluator_artifact_set_digest: Hash,
    prover_key_material: &[u8],
    verifier_key_material: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let (prover_key, verifier_key) = bfv_full_bootstrap_proof_key_pair_from_key_material_v1(
        params,
        1,
        public_input_schema_digest,
        evaluator_artifact_set_digest,
        prover_key_material,
        verifier_key_material,
    )
    .expect("build sample full-bootstrap proof-key pair");
    let prover_key = encode_bfv_full_bootstrap_proof_key_artifact_v1(
        params,
        1,
        BfvFullBootstrapCircuitArtifactRoleV1::ProverKey,
        &prover_key,
    )
    .expect("encode sample full-bootstrap prover-key artifact");
    let verifier_key = encode_bfv_full_bootstrap_proof_key_artifact_v1(
        params,
        1,
        BfvFullBootstrapCircuitArtifactRoleV1::VerifierKey,
        &verifier_key,
    )
    .expect("encode sample full-bootstrap verifier-key artifact");
    (prover_key, verifier_key)
}
fn sample_full_bootstrap_circuit_artifacts(
    params: &BfvParameters,
) -> BfvFullBootstrapCircuitArtifactBundleV1 {
    let (secret_key, _public_key, _relinearization_key) =
        keygen_from_seed(params, b"soracloud-fhe-test-keygen")
            .expect("sample full-bootstrap artifact keygen");
    sample_full_bootstrap_circuit_artifacts_for_secret(params, &secret_key)
}
fn sample_full_bootstrap_circuit_artifacts_for_secret(
    params: &BfvParameters,
    secret_key: &BfvSecretKey,
) -> BfvFullBootstrapCircuitArtifactBundleV1 {
    #[cfg(feature = "zk-stark")]
    {
        let verifier_key = sample_fhe_full_bootstrap_execution_vk_box();
        let prover_key_material =
            encode_bfv_full_bootstrap_native_stark_fri_prover_key_material_v1(
                SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
            )
            .expect("sample native full-bootstrap prover-key material");
        let verifier_key_material =
            sample_full_bootstrap_native_verifier_material_for_core_vk(&verifier_key);
        sample_full_bootstrap_circuit_artifacts_for_secret_and_proof_keys(
            params,
            secret_key,
            &prover_key_material,
            &verifier_key_material,
        )
    }
    #[cfg(not(feature = "zk-stark"))]
    {
        let prover_key_material =
            encode_bfv_full_bootstrap_native_stark_fri_prover_key_material_v1(
                SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
            )
            .expect("sample native full-bootstrap prover-key material");
        let verifier_key_material =
            iroha_crypto::fhe_bfv::encode_bfv_full_bootstrap_native_stark_fri_verifier_key_material_v1(
                SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
            )
            .expect("sample native full-bootstrap verifier-key material");
        sample_full_bootstrap_circuit_artifacts_for_secret_and_proof_keys(
            params,
            secret_key,
            &prover_key_material,
            &verifier_key_material,
        )
    }
}
fn sample_full_bootstrap_circuit_artifacts_for_secret_and_proof_keys(
    params: &BfvParameters,
    secret_key: &BfvSecretKey,
    prover_key_material: &[u8],
    verifier_key_material: &[u8],
) -> BfvFullBootstrapCircuitArtifactBundleV1 {
    let accumulator = sample_full_bootstrap_accumulator_artifact_payload(params);
    let accumulator_digest = Hash::new(&accumulator);
    let proof_public_input_schema =
        sample_full_bootstrap_proof_public_input_schema_artifact_payload(params);
    let proof_public_input_schema_digest = Hash::new(&proof_public_input_schema);
    let arithmetic_air_constraint_system =
        encode_bfv_full_bootstrap_arithmetic_air_constraint_system_artifact_v1(
            params,
            1,
            &bfv_full_bootstrap_arithmetic_air_constraint_system_material_v1(),
        )
        .expect("encode sample full-bootstrap arithmetic AIR constraint-system artifact");
    let coefficient_to_slot_key = sample_full_bootstrap_linear_transform_artifact_payload(
        params,
        BfvFullBootstrapCircuitArtifactRoleV1::CoefficientToSlotKey,
    );
    let slot_to_coefficient_key = sample_full_bootstrap_linear_transform_artifact_payload(
        params,
        BfvFullBootstrapCircuitArtifactRoleV1::SlotToCoefficientKey,
    );
    let blind_rotation_key =
        sample_full_bootstrap_blind_rotation_artifact_payload(params, accumulator_digest);
    let sample_extraction_key =
        sample_full_bootstrap_sample_extraction_switch_key_artifact_payload(params, secret_key);
    let evaluator_artifact_set_digest = bfv_full_bootstrap_evaluator_artifact_set_digest_v1(
        params,
        1,
        &coefficient_to_slot_key,
        &slot_to_coefficient_key,
        &blind_rotation_key,
        &sample_extraction_key,
        &accumulator,
        &proof_public_input_schema,
        &arithmetic_air_constraint_system,
    )
    .expect("sample full-bootstrap evaluator artifact-set digest");
    let (prover_key, verifier_key) = sample_full_bootstrap_proof_key_artifact_payloads(
        params,
        proof_public_input_schema_digest,
        evaluator_artifact_set_digest,
        prover_key_material,
        verifier_key_material,
    );
    BfvFullBootstrapCircuitArtifactBundleV1 {
        coefficient_to_slot_key,
        slot_to_coefficient_key,
        blind_rotation_key,
        sample_extraction_key,
        accumulator,
        proof_public_input_schema,
        arithmetic_air_constraint_system,
        prover_key,
        verifier_key,
    }
}
