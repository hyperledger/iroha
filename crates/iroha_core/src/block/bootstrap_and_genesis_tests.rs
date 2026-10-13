#[test]
#[allow(clippy::too_many_lines)]
fn manager_sponsored_contract_registration_survives_block_and_committed_replay() {
    for parallel_apply in [false, true] {
        let chain_id = ChainId::try_from(format!(
            "contract-code-management-grant-block-{parallel_apply}"
        ))
        .expect("canonical contract-deployment test chain id");
        let (manager, manager_keypair) = gen_account_in("code-management-granter");
        let (authority, authority_keypair) = gen_account_in("builder");
        let (adversary, adversary_keypair) = gen_account_in("adversary");
        let (missing, missing_keypair) = gen_account_in("missing-self-grant");
        let (malformed, malformed_keypair) = gen_account_in("malformed-self-grant");
        let manager_permission: Permission = iroha_executor_data_model::permission::smart_contract::CanGrantSmartContractCodeManagement.into();
        let permission: Permission =
            iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode
                .into();
        let accepted_hash = Hash::new(b"manager-sponsored builder upload");
        let existing_replay_hash = Hash::new(b"existing authority bootstrap replay");
        let decorated_hash = Hash::new(b"decorated authority bootstrap");
        let missing_hash = Hash::new(b"missing self-grant bootstrap");
        let malformed_hash = Hash::new(b"malformed self-grant bootstrap");
        let genesis_world = || {
            let mut world = World::with([], [Account::new(manager.clone()).build(&manager)], []);
            world.account_permissions.insert(
                manager.clone(),
                std::collections::BTreeSet::from([manager_permission.clone()]),
            );
            world
        };
        let make_chain = || {
            let mut config = crate::sumeragi::test_chain::TestChainConfig::new(genesis_world(), 1);
            config.chain_id = chain_id.clone();
            config.pipeline.parallel_overlay = true;
            config.pipeline.parallel_apply = parallel_apply;
            config.pipeline.workers = 2;
            crate::sumeragi::test_chain::CertifiedTestChain::start(config)
                .expect("original manager World and native genesis")
        };
        let mut chain = make_chain();
        let state = Arc::clone(chain.state());
        let network_id = chain.network_id();
        let make_bootstrap_transaction =
            |authority: &AccountId,
             keypair: &KeyPair,
             code_hash: Hash,
             decorated: bool,
             grant: &Permission,
             creation_time_ms: u64| {
                let mut account = Account::new(authority.clone());
                if decorated {
                    let mut metadata = Metadata::default();
                    metadata.insert(
                        "bootstrap-note".parse().expect("metadata name"),
                        Json::new("decorated"),
                    );
                    account = account.with_metadata(metadata);
                }
                let instructions: Vec<InstructionBox> = vec![
                    Register::account(account).into(),
                    Grant::account_permission(grant.clone(), authority.clone()).into(),
                    iroha_data_model::isi::smart_contract_code::UploadSmartContractCodeChunk {
                        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                            code_hash,
                        ),
                        total_size: 1,
                        chunk_index: 0,
                        chunk_count: 1,
                        chunk: vec![0xA5],
                    }
                    .into(),
                ];
                let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
                    &network_id,
                    authority,
                    0,
                    DataSpaceId::UNIVERSAL,
                )
                .expect("bootstrap contract address");
                let mut transaction_metadata = Metadata::default();
                for key in ["gov_contract_address", "contract_address"] {
                    transaction_metadata.insert(
                        key.parse().expect("deployment metadata name"),
                        Json::new(contract_address.to_string()),
                    );
                }
                let (_time_handle, time_source) =
                    TimeSource::new_mock(Duration::from_millis(creation_time_ms));
                TransactionBuilder::new_with_time_source(
                    network_id,
                    authority.clone(),
                    &time_source,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .with_metadata(transaction_metadata)
                .with_instructions(instructions)
                .sign(keypair.private_key())
            };
        let (_registration_handle, registration_time) =
            TimeSource::new_mock(Duration::from_millis(10));
        let registration = TransactionBuilder::new_with_time_source(
            network_id,
            manager.clone(),
            &registration_time,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(vec![
            InstructionBox::from(Register::account(Account::new(authority.clone()))),
            InstructionBox::from(Grant::account_permission(
                permission.clone(),
                authority.clone(),
            )),
        ])
        .sign(manager_keypair.private_key());
        assert_eq!(
            chain.commit_at(20, vec![registration]),
            vec![true],
            "genesis-seeded manager sponsors registration and the exact code-management grant"
        );
        state
            .view()
            .world()
            .account(&authority)
            .expect("manager registered builder");
        assert!(
            state
                .view()
                .world()
                .account_permissions_iter(&authority)
                .expect("registered builder permissions")
                .any(|stored| stored == &permission)
        );
        assert!(
            !state
                .view()
                .world()
                .account_permissions_iter(&authority)
                .expect("builder permissions")
                .any(|stored| stored == &manager_permission)
        );
        let (_upload_handle, upload_time) = TimeSource::new_mock(Duration::from_millis(30));
        let accepted = TransactionBuilder::new_with_time_source(
            network_id,
            authority.clone(),
            &upload_time,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([
            iroha_data_model::isi::smart_contract_code::UploadSmartContractCodeChunk {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    accepted_hash,
                ),
                total_size: 1,
                chunk_index: 0,
                chunk_count: 1,
                chunk: vec![0xA5],
            },
        ])
        .sign(authority_keypair.private_key());
        assert_eq!(
            chain.commit_at(40, vec![accepted]),
            vec![true],
            "registered builder upload must execute after genesis"
        );
        assert_eq!(chain.height(), 3);
        state
            .view()
            .world()
            .account(&authority)
            .expect("registered builder exists in validated block");
        assert!(
            state
                .view()
                .world()
                .account_permissions_iter(&authority)
                .expect("builder code-management permissions")
                .any(|stored| stored == &permission)
        );
        assert!(
            state
                .view()
                .world()
                .contract_code_upload_progress(
                    &authority,
                    &iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        accepted_hash
                    )
                )
                .is_some()
        );
        let existing_replay = make_bootstrap_transaction(
            &authority,
            &authority_keypair,
            existing_replay_hash.clone(),
            false,
            &permission,
            50,
        );
        let decorated = make_bootstrap_transaction(
            &adversary,
            &adversary_keypair,
            decorated_hash.clone(),
            true,
            &permission,
            51,
        );
        let missing_self_grant = make_bootstrap_transaction(
            &missing,
            &missing_keypair,
            missing_hash,
            false,
            &permission,
            52,
        );
        let malformed_permission = Permission::new(
            "CanManageSmartContractCode".to_owned(),
            Json::new("not-the-unit-payload"),
        );
        let malformed_self_grant = make_bootstrap_transaction(
            &malformed,
            &malformed_keypair,
            malformed_hash,
            false,
            &malformed_permission,
            53,
        );
        assert_eq!(
            chain.commit_at(
                60,
                vec![
                    existing_replay,
                    decorated,
                    missing_self_grant,
                    malformed_self_grant
                ]
            ),
            vec![false; 4],
            "existing-authority replay, decorated, missing, and malformed self-grants must all reject"
        );
        assert_eq!(chain.height(), 4);
        assert!(state.view().world().account(&adversary).is_err());
        for (account, hash) in [(&missing, &missing_hash), (&malformed, &malformed_hash)] {
            assert!(
                state.view().world().account(account).is_err(),
                "rejected self-grant must roll back account registration"
            );
            assert!(
                state
                    .view()
                    .world()
                    .contract_code_upload_progress(
                        account,
                        &iroha_data_model::smart_contract::ContractArtifactId::new(
                            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                            *hash
                        )
                    )
                    .is_none(),
                "rejected self-grant must not stage contract bytes"
            );
        }
        assert!(
            state
                .view()
                .world()
                .contract_code_upload_progress(
                    &authority,
                    &iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        existing_replay_hash
                    )
                )
                .is_none()
        );
        assert!(
            state
                .view()
                .world()
                .contract_code_upload_progress(
                    &adversary,
                    &iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        decorated_hash
                    )
                )
                .is_none()
        );
        let mut replay = make_chain();
        replay
            .replay_from(&chain)
            .expect("original certified blocks replay through native executor");
        let replay_state = replay.state();
        let replay_view = replay_state.view();
        let replay_world = replay_view.world();
        replay_world
            .account(&authority)
            .expect("registered builder survives committed replay");
        assert!(replay_world.account(&adversary).is_err());
        assert!(
            replay_world
                .account_permissions_iter(&manager)
                .expect("replayed manager permissions")
                .any(|stored| stored == &manager_permission)
        );
        assert!(
            !replay_world
                .account_permissions_iter(&authority)
                .expect("replayed builder permissions")
                .any(|stored| stored == &manager_permission)
        );
        for (account, hash) in [(&missing, &missing_hash), (&malformed, &malformed_hash)] {
            assert!(
                replay_world.account(account).is_err(),
                "replay must preserve rejected self-grant atomicity"
            );
            assert!(
                replay_world
                    .contract_code_upload_progress(
                        account,
                        &iroha_data_model::smart_contract::ContractArtifactId::new(
                            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                            *hash
                        )
                    )
                    .is_none()
            );
        }
        assert!(
            replay_world
                .account_permissions_iter(&authority)
                .expect("replayed builder code-management permissions")
                .any(|stored| stored == &permission)
        );
        assert!(
            replay_world
                .contract_code_upload_progress(
                    &authority,
                    &iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        accepted_hash
                    )
                )
                .is_some()
        );
        assert!(
            replay_world
                .contract_code_upload_progress(
                    &authority,
                    &iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        existing_replay_hash
                    )
                )
                .is_none()
        );
        assert!(
            replay_world
                .contract_code_upload_progress(
                    &adversary,
                    &iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        decorated_hash
                    )
                )
                .is_none()
        );
    }
}
#[tokio::test]
async fn genesis_public_key_is_checked() {
    // Predefined world state
    let genesis_correct_key = crate::block::checked_keypair();
    let genesis_wrong_key = crate::block::checked_keypair();
    let genesis_correct_account_id = AccountId::new(genesis_correct_key.public_key().clone());
    let genesis_wrong_account_id = AccountId::new(genesis_wrong_key.public_key().clone());
    let genesis_domain = Domain::new(GENESIS_DOMAIN_ID.clone()).build(&genesis_correct_account_id);
    let genesis_wrong_account =
        Account::new(genesis_wrong_account_id.clone()).build(&genesis_wrong_account_id);
    let world = World::with([genesis_domain], [genesis_wrong_account], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_handle);
    // Creating an instruction
    let isi = Log::new(
        iroha_data_model::Level::DEBUG,
        "instruction itself doesn't matter here".to_string(),
    );
    // Create genesis transaction
    // Sign with `genesis_wrong_key` as peer which has incorrect genesis key pair
    // Bypass `accept_genesis` check to allow signing with wrong key
    let tx = TransactionBuilder::new_genesis(
        genesis_wrong_account_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([isi])
    .sign(genesis_wrong_key.private_key());
    let tx = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    // Create genesis block
    let transactions = vec![tx];
    let topology =
        crate::sumeragi::network_topology::test_topology_with_keys([&genesis_correct_key]);
    let unverified_block = BlockBuilder::new(transactions)
        .chain(
            0,
            state
                .view()
                .latest_block()
                .expect("original block read attempt")
                .as_deref(),
        )
        .with_confidential_features({
            let view = state.view();
            let digest =
                crate::state::compute_confidential_feature_digest(view.world(), view.zk(), 1);
            (!digest.is_empty()).then_some(digest)
        })
        .sign(genesis_correct_key.private_key())
        .unpack(|_| {});
    // Invalid genesis authority must be rejected before any execution or commit.
    let block: SignedBlock = unverified_block.into();
    let (_handle, time_source) = TimeSource::new_mock(block.header().creation_time());
    let (_, error) = {
        let selected_genesis = block;
        let selected_scope =
            iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture::new()
                .root_scope();
        ValidBlock::validate_signed_genesis(
            selected_genesis,
            &topology,
            &genesis_correct_account_id,
            &time_source,
            &state,
            iroha_data_model::block::consensus::ConsensusMode::Permissioned,
            selected_scope,
        )
    }
    .unpack(|_| {})
    .err()
    .expect("genesis with an unexpected authority must fail validation");
    // The first transaction should be rejected
    assert!(matches!(
        error.as_ref(),
        BlockValidationError::InvalidGenesis(InvalidGenesisError::UnexpectedAuthority)
    ));
}
#[tokio::test]
async fn genesis_asset_definition_registration_is_not_domain_gated() {
    let genesis_key_pair = crate::block::checked_keypair();
    let genesis_account_id = AccountId::new(genesis_key_pair.public_key().clone());
    let alice_key_pair = crate::block::checked_keypair();
    let wonderland_domain_id: DomainId =
        DomainId::try_new("wonderland", "universal").expect("Valid domain id");
    let alice_account_id = AccountId::new(alice_key_pair.public_key().clone());
    let genesis_domain = Domain::new(GENESIS_DOMAIN_ID.clone()).build(&genesis_account_id);
    let wonderland_domain = Domain::new(wonderland_domain_id.clone()).build(&alice_account_id);
    let genesis_account = Account::new(genesis_account_id.clone()).build(&genesis_account_id);
    let alice_account = Account::new(alice_account_id.clone()).build(&alice_account_id);
    let world = World::with(
        [genesis_domain, wonderland_domain],
        [genesis_account, alice_account],
        [],
    );
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("valid domain id"),
        "xor".parse().expect("valid asset name"),
    );
    let instruction = Register::asset_definition(AssetDefinition::numeric(
        asset_definition_id.clone(),
        "xor",
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    ));
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
    config.genesis_key = genesis_key_pair;
    config.genesis_instructions.push(instruction.into());
    let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
        .expect("genesis asset-definition registration is not domain-owner gated");
    assert!(
        chain
            .state()
            .view()
            .world()
            .asset_definitions()
            .get(&asset_definition_id)
            .is_some()
    );
}

#[tokio::test]
async fn genesis_domain_registration_bootstraps_domain_name_lease() {
    let genesis_key_pair = crate::block::checked_keypair();
    let genesis_account_id = AccountId::new(genesis_key_pair.public_key().clone());
    let wonderland_domain_id: DomainId =
        DomainId::try_new("wonderland", "universal").expect("valid domain id");
    let genesis_domain = Domain::new(GENESIS_DOMAIN_ID.clone()).build(&genesis_account_id);
    let genesis_account = Account::new(genesis_account_id.clone()).build(&genesis_account_id);
    let world = World::with([genesis_domain], [genesis_account], []);
    let instruction = Register::domain(Domain::new(wonderland_domain_id.clone()));
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
    config.genesis_key = genesis_key_pair;
    config.genesis_instructions.push(instruction.into());
    let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
        .expect("original genesis registers its domain-name lease");
    let state = chain.state();
    let view = state.view();
    assert_eq!(
        (crate::sns::active_domain_owner(view.world(), &wonderland_domain_id, 0))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(Some(genesis_account_id)),
        "genesis registration should leave an active domain-name record behind"
    );
}
