/// Original configured native State, optionally applied through genuine H2 execution and Kura.
/// The missing-parent variant keeps the prepared signed genesis unapplied; it does not fabricate
/// a committed journal entry or omit a second finality sidecar.
pub fn app_with_finalized_block_for_test(
    has_parent: bool,
) -> (
    SharedAppState,
    Option<iroha_data_model::sumeragi_finality::SumeragiFinalityProof>,
    Vec<KeyPair>,
) {
    use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let authority_key = checked_torii_test_ed25519_keypair(0x39, "lifecycle ingress authority");
    let authority = AccountId::new(authority_key.public_key().clone());
    let prepared =
        CertifiedTestChain::prepare(TestChainConfig::new(world_with_account(&authority), 1_000))
            .unwrap();
    let validators = prepared.validator_keys.clone();
    let mut app = mk_app_state_for_tests();
    let unique = Arc::get_mut(&mut app).unwrap();
    let proof = if has_parent {
        let mut chain = CertifiedTestChain::from_prepared(prepared).unwrap();
        chain.commit(Vec::new());
        let proof = iroha_core::sumeragi::finality::build_proof(&chain.state().view(), 2).unwrap();
        unique.state = chain.state().clone();
        unique.kura = chain.kura().clone();
        Some(proof)
    } else {
        unique.state = prepared.state;
        unique.kura = prepared.kura;
        None
    };
    (app, proof, validators)
}

#[test]
fn finalized_block_fixture_commits_one_ordinary_block_with_durable_finality() {
    run_executed_block_wire_handler_test("lifecycle-native-parent", || async {
        let (app, proof, validators) = app_with_finalized_block_for_test(true);
        let proof = proof.unwrap();
        assert_ne!(
            *app.state.network_id_ref(),
            *mk_app_state_for_tests().state.network_id_ref()
        );
        assert_eq!(proof.height(), 2);
        assert_eq!(proof.committee.len(), 4);
        assert_eq!(
            proof
                .committee
                .iter()
                .map(|member| &member.public_key)
                .collect::<Vec<_>>(),
            validators
                .iter()
                .map(KeyPair::public_key)
                .collect::<Vec<_>>()
        );
        let block = app
            .state
            .block_by_height(NonZeroUsize::new(2).unwrap())
            .expect("funded canonical history read")
            .unwrap();
        assert_eq!(block.header(), proof.block_header);
        assert_eq!(block.execution_outputs().len(), 1);
        assert!(block.commit_certificate().is_some());
        assert_eq!(block.encode_wire().unwrap(), proof.block_wire);
        assert_eq!(app.state.exact_durable_block_count().unwrap(), 2);
        let (unapplied, absent, _) = app_with_finalized_block_for_test(false);
        assert!(absent.is_none());
        assert_eq!(unapplied.state.committed_height(), 0);
        assert_eq!(unapplied.state.exact_durable_block_count().unwrap(), 0);
    });
}
