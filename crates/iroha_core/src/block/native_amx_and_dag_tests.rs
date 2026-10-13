#[test]
fn map_overlay_error_labels_amx_budget() {
    let err =
        crate::pipeline::overlay::OverlayBuildError::IvmRun(ivm::VMError::AmxBudgetExceeded {
            dataspace: DataSpaceId::new(5),
            stage: AmxStage::Commit,
            elapsed_ms: 42,
            budget_ms: 30,
        });
    match super::map_overlay_error(&err) {
        TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::NotPermitted(
            message,
        )) => {
            assert!(
                message.contains("AMX_TIMEOUT"),
                "message missing AMX_TIMEOUT label: {message}"
            );
            assert!(
                message.contains("dataspace=5"),
                "message missing dataspace label: {message}"
            );
            assert!(
                message.contains(
                    &iroha_data_model::errors::CanonicalErrorKind::AMX_TIMEOUT_CODE.to_string()
                ),
                "message missing canonical code: {message}"
            );
        }
        other => panic!("unexpected rejection: {other:?}"),
    }
}
#[test]
fn map_overlay_error_labels_amx_violation_variant() {
    let err = crate::pipeline::overlay::OverlayBuildError::AmxBudgetViolation(
        crate::smartcontracts::ivm::host::AmxBudgetViolation {
            dataspace: DataSpaceId::new(7),
            stage: AmxStage::Prepare,
            elapsed_ms: 99,
            budget_ms: 10,
        },
    );
    match super::map_overlay_error(&err) {
        TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::NotPermitted(
            message,
        )) => {
            assert!(
                message.contains("AMX_TIMEOUT"),
                "message missing AMX_TIMEOUT label: {message}"
            );
            assert!(
                message.contains("dataspace=7"),
                "message missing dataspace label: {message}"
            );
            assert!(
                message.contains(
                    &iroha_data_model::errors::CanonicalErrorKind::AMX_TIMEOUT_CODE.to_string()
                ),
                "message missing canonical code: {message}"
            );
        }
        other => panic!("unexpected rejection: {other:?}"),
    }
}
#[test]
pub fn committed_and_valid_block_hashes_are_equal() {
    let peer_key_pair =
        crate::block::checked_keypair_with_algorithm(iroha_crypto::Algorithm::BlsNormal);
    let peer_id = PeerId::new(peer_key_pair.public_key().clone());
    let topology = Topology::new(vec![peer_id]);
    let valid_block = ValidBlock::new_dummy(peer_key_pair.private_key());
    let committed_block = valid_block
        .clone()
        .commit(&topology, crate::block::reserve_block_for_tests())
        .unpack(|_| {})
        .unwrap();
    assert_eq!(valid_block.as_ref().hash(), committed_block.as_ref().hash())
}
#[test]
fn merkle_root_matches_header() {
    use std::borrow::Cow;
    let network_id = deterministic_test_network_id(0x0A);
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let log = Log::new(Level::INFO, "test".to_string());
    let tx1 = Box::new(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([log.clone()])
        .sign(alice_keypair.private_key()),
    );
    let tx1: &'static SignedTransaction = Box::leak(tx1);
    let tx1 = AcceptedTransaction::new_unchecked(Cow::Borrowed(tx1));
    let tx2 = Box::new(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([log])
        .sign(alice_keypair.private_key()),
    );
    let tx2: &'static SignedTransaction = Box::leak(tx2);
    let tx2 = AcceptedTransaction::new_unchecked(Cow::Borrowed(tx2));
    let block = BlockBuilder::new(vec![tx1, tx2])
        .chain(0, None)
        .sign(alice_keypair.private_key())
        .unpack(|_| {});
    let block: Box<SignedBlock> = Box::new(block.into());
    let mut tree: Box<MerkleTree<TransactionEntrypoint>> = Box::default();
    for tx in block.external_transactions() {
        tree.add(tx.hash_as_entrypoint());
    }
    assert_eq!(tree.root(), block.header().merkle_root());
}
#[test]
fn entrypoint_merkle_bottom_up_matches_incremental_root_shapes() {
    fn sample_leaf(idx: u8) -> HashOf<TransactionEntrypoint> {
        let mut bytes = [0_u8; Hash::LENGTH];
        bytes[0] = idx;
        bytes[Hash::LENGTH - 1] = idx.wrapping_mul(17);
        HashOf::from_untyped_unchecked(Hash::prehashed(bytes))
    }
    fn incremental_root(
        leaves: &[HashOf<TransactionEntrypoint>],
    ) -> Option<HashOf<MerkleTree<TransactionEntrypoint>>> {
        let mut tree = MerkleTree::default();
        for leaf in leaves {
            tree.add(*leaf);
        }
        tree.root()
    }
    fn bottom_up_root(
        leaves: Vec<HashOf<TransactionEntrypoint>>,
    ) -> Option<HashOf<MerkleTree<TransactionEntrypoint>>> {
        let tree = MerkleTree::from_typed_leaves_parallel(leaves);
        tree.root()
    }
    for count in [1_usize, 2, 3, 4, 5, 8] {
        let leaves = (0..count)
            .map(|idx| sample_leaf(u8::try_from(idx + 1).expect("small test index")))
            .collect::<Vec<_>>();
        assert_eq!(
            bottom_up_root(leaves.clone()),
            incremental_root(&leaves),
            "bottom-up Merkle root must match incremental insertion for {count} leaves"
        );
    }
}
#[test]
fn canonical_output_repeat_validation_is_deterministic() {
    // Build a small world and a block with two independent txs to exercise access-set derivation
    let (alice_id, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
    let (bob_id, bob_keypair) = iroha_test_samples::gen_account_in("wonderland");
    let domain_id: DomainId =
        DomainId::try_new("wonderland", "universal").expect("wonderland domain");
    let domain: Domain = Domain::new(domain_id.clone()).build(&alice_id);
    let ad: AssetDefinition = {
        let __asset_definition_id =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "coin".parse().unwrap(),
            );
        AssetDefinition::new(
            __asset_definition_id.clone(),
            "coin".to_owned(),
            NumericSpec::default(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    }
    .build(&alice_id);
    let acc_a = Account::new(alice_id.clone()).build(&alice_id);
    let acc_b = Account::new(bob_id.clone()).build(&alice_id);
    let world = crate::state::World::with([domain], [acc_a, acc_b], [ad]);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new(world, kura, query);
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let rose: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let a_coin = AssetId::of(rose.clone(), alice_id.clone());
    let tx1 = TransactionBuilder::new(
        state.network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Mint::asset_quantity(5_u32, a_coin.clone())])
    .sign(alice_keypair.private_key());
    let tx2 = TransactionBuilder::new(
        state.network_id,
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([SetKeyValue::account(
        bob_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )])
    .sign(bob_keypair.private_key());
    let acc: Vec<_> = vec![tx1, tx2]
        .into_iter()
        .map(|t| crate::tx::AcceptedTransaction::new_unchecked(Cow::Owned(t)))
        .collect();
    // Replay the same signed inputs against an unchanged predecessor and compare
    // the complete canonical outputs, including each transaction result.
    let new_block = BlockBuilder::new(acc.clone())
        .chain(
            0,
            state
                .view()
                .latest_block()
                .expect("original block read attempt")
                .as_deref(),
        )
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key())
        .unpack(|_| {});
    assert!(
        new_block.execution_context.as_ref().is_some_and(|context| {
            context.external.len() == acc.len()
                && context.external.iter().all(|entry| {
                    entry.lane_id == LaneId::SINGLE && entry.dataspace_id == DataSpaceId::UNIVERSAL
                })
        }),
        "the state-free fixture binds one exact ordinary route per input"
    );
    let source: SignedBlock = new_block.into();
    let (mut sb, sb_recorder) = ValidBlock::start_component_execution(&source, state)
        .expect("original recorder before execution");
    let vb = ValidBlock::validate_unchecked(source, &mut sb, sb_recorder).unpack(|_| {});
    let first_outputs = vb.as_ref().execution_outputs().to_vec();
    assert!(
        first_outputs.iter().all(|output| output.result().is_ok()),
        "both independent transaction effects must execute successfully"
    );
    drop(sb);
    let new_block2 = BlockBuilder::new(acc)
        .chain(
            0,
            state
                .view()
                .latest_block()
                .expect("original block read attempt")
                .as_deref(),
        )
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key())
        .unpack(|_| {});
    let replay: SignedBlock = new_block2.into();
    let (mut sb2, replay_recorder) = ValidBlock::start_component_execution(&replay, state)
        .expect("original recorder before replay");
    let vb2 = ValidBlock::validate_unchecked(replay, &mut sb2, replay_recorder).unpack(|_| {});
    assert_eq!(
        vb2.as_ref().execution_outputs(),
        first_outputs.as_slice(),
        "canonical execution output bytes must be deterministic for the same predecessor and inputs"
    );
}
