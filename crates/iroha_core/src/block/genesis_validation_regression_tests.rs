#[cfg(feature = "bls")]
#[test]
fn block_authenticated_genesis_rejects_invalid_per_transaction_bls_proof() {
    use iroha_data_model::prelude::*;
    let chain_id = ChainId::from("block-authenticated-bls-genesis");
    let genesis_keypair = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let unrelated_keypair = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let genesis_account = AccountId::new(genesis_keypair.public_key().clone());
    let pop = iroha_crypto::bls_normal_pop_prove(genesis_keypair.private_key())
        .expect("valid BLS proof of possession");
    let mut metadata = Metadata::default();
    metadata.insert(
        "bls_pop".parse().expect("valid BLS PoP metadata key"),
        iroha_primitives::json::Json::new(hex::encode_upper(pop)),
    );
    let mut transaction = TransactionBuilder::new_genesis(
        genesis_account.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "genesis".to_owned())])
    .with_metadata(metadata)
    .sign(genesis_keypair.private_key());
    transaction.set_signature(iroha_data_model::transaction::TransactionSignature(
        SignatureOf::try_new(unrelated_keypair.private_key(), transaction.payload())
            .expect("unrelated BLS key can sign the fixture payload"),
    ));
    transaction
        .verify_signature()
        .expect_err("fixture transaction proof must not authorize the genesis account");
    let block = SignedBlock::genesis(vec![transaction], genesis_keypair.private_key(), None, None);
    let world = World::with(
        [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&genesis_account)],
        [Account::new(genesis_account.clone()).build(&genesis_account)],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let state = State::new_with_chain_for_testing(
        world,
        Arc::clone(&kura),
        LiveQueryStore::start_test(),
        chain_id.clone(),
    );
    install_test_lane_manifests_for_keypairs(&state, std::slice::from_ref(&genesis_keypair));
    let mut crypto = iroha_config::parameters::actual::Crypto::default();
    if !crypto.allowed_signing.contains(&Algorithm::BlsNormal) {
        crypto.allowed_signing.push(Algorithm::BlsNormal);
    }
    state.set_crypto(crypto);
    let block = with_current_state_confidential_features(
        block,
        &state,
        &[(0, genesis_keypair.private_key())],
    );
    let topology = Topology::new(vec![PeerId::new(genesis_keypair.public_key().clone())]);
    let result = {
        let selected_genesis = block;
        let selected_scope =
            iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture::new()
                .root_scope();
        ValidBlock::validate_signed_genesis(
            selected_genesis,
            &topology,
            &genesis_account,
            &TimeSource::new_system(),
            &state,
            iroha_data_model::block::consensus::ConsensusMode::Permissioned,
            selected_scope,
        )
    }
    .unpack(|_| {});
    let Err(error) = result else {
        panic!(
            "a valid genesis block signature must not replace each transaction's authorization proof"
        );
    };
    assert!(matches!(
        *error.1,
        BlockValidationError::InvalidGenesis(InvalidGenesisError::InvalidTransactionSignature)
    ));
}
#[test]
fn check_genesis_block_rejects_multisig_authority_without_unwinding() {
    use iroha_data_model::{
        account::{MultisigMember, MultisigPolicy},
        prelude::*,
    };
    use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
    let transaction = TransactionBuilder::new_genesis(
        SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "genesis".to_owned())])
    .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
    let block = SignedBlock::genesis(
        vec![transaction],
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
        None,
        None,
    );
    let member = MultisigMember::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone(), 1)
        .expect("valid member");
    let multisig_genesis =
        AccountId::new_multisig(MultisigPolicy::new(1, vec![member]).expect("valid policy"));
    assert_eq!(
        check_genesis_block(&block, &multisig_genesis),
        Err(InvalidGenesisError::GenesisAuthorityNotSingleKey)
    );
}
#[test]
fn genesis_block_with_da_commitments_uses_header_tree_commitment() {
    use iroha_data_model::prelude::*;
    use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
    let genesis_account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
    let tx = TransactionBuilder::new_genesis(
        genesis_account.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "genesis".to_owned())])
    .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
    let record = DaCommitmentRecord::new(
        LaneId::new(0),
        1,
        1,
        BlobDigest::new([0xAA; 32]),
        ManifestDigest::new([0xBB; 32]),
        DaProofScheme::MerkleSha256,
        Hash::prehashed([0xCC; 32]),
        None,
        RetentionClass::default(),
        StorageTicketId::new([0xDD; 32]),
        checked_da_ack_signature(0xEE),
    );
    let bundle = DaCommitmentBundle::new(vec![record]);
    let tree_commitment = bundle
        .merkle_commitment()
        .expect("non-empty bundle must have a tree commitment");
    let block = SignedBlock::genesis(
        vec![tx],
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
        None,
        Some(bundle),
    );
    assert_eq!(block.header().da_commitments_hash(), Some(tree_commitment));
    assert!(authenticate_genesis_block_intents(&block, &genesis_account).is_ok());
}
#[test]
fn genesis_asset_definition_in_genesis_domain_is_authorized() {
    use iroha_data_model::prelude::*;
    use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
    let genesis_account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("genesis", "universal").expect("valid domain id"),
        "xor".parse().expect("valid asset name"),
    );
    let asset_name = "xor".to_owned();
    let tx = TransactionBuilder::new_genesis(
        genesis_account.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Register::asset_definition(AssetDefinition::numeric(
        asset_definition_id,
        asset_name,
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    ))])
    .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
    let block = SignedBlock::genesis(
        vec![tx],
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
        None,
        None,
    );
    assert!(authenticate_genesis_block_intents(&block, &genesis_account).is_ok());
}
#[test]
fn signed_genesis_validation_rejects_a_non_genesis_header() {
    let kura = Kura::blank_kura_for_testing();
    let state = State::new_for_testing(World::new(), kura, LiveQueryStore::start_test());
    let leader = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let topology = Topology::new(vec![PeerId::new(leader.public_key().clone())]);
    let block: SignedBlock = ValidBlock::new_dummy(leader.private_key()).into();
    let result = {
        let selected_genesis = block;
        let selected_scope =
            iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture::new()
                .root_scope();
        ValidBlock::validate_signed_genesis(
            selected_genesis,
            &topology,
            &ALICE_ID,
            &TimeSource::new_system(),
            &state,
            iroha_data_model::block::consensus::ConsensusMode::Permissioned,
            selected_scope,
        )
    }
    .unpack(|_| {});
    assert!(matches!(
        result,
        Err(error)
            if matches!(
                *error.1,
                BlockValidationError::InvalidGenesis(InvalidGenesisError::InvalidHeader)
            )
    ));
}
