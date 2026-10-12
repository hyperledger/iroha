#[test]
fn transaction_height_expiry_is_exclusive_when_height_expiry_is_optional() {
    use iroha_data_model::{isi::Log, transaction::TransactionBuilder};
    use iroha_logger::Level;
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::json::Json;
    use std::time::Duration;
    for (expires_at_height, should_accept) in [(2_u64, false), (3, true)] {
        let (mut world, authority_id, kp) = world_with_authority("wonderland");
        let mut params = iroha_data_model::parameter::system::Parameters::default();
        params.transaction = params.transaction.with_ingress_enforcement(false, false);
        world.parameters = mv::cell::Cell::new(
            crate::state::StateParameters::try_from(params).expect("valid fixture parameters"),
        );
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query_handle = crate::query::store::LiveQueryStore::start_test();
        let chain: ChainId = "ttl-check-chain".parse().unwrap();
        let state = State::new_with_chain(world, kura, query_handle, chain);
        let chain = crate::block::tests::component_chain(state);
        let state = chain.state();
        assert!(
            !state
                .view()
                .world()
                .parameters()
                .transaction()
                .require_height_ttl
        );
        let header = original_component_successor_header(state);
        let mut block = state.block(header);
        let mut metadata = Metadata::default();
        metadata.insert(
            iroha_model_base::name::Name::from_str("expires_at_height").unwrap(),
            Json::from(expires_at_height),
        );
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority_id,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "ttl".into())])
        .with_metadata(metadata)
        .sign(kp.private_key());
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            default_limits.max_signatures(),
            default_limits.max_instructions(),
            default_limits.ivm_bytecode_size(),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        )
        .with_ingress_enforcement(false, false);
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let time_source = TimeSource::new_fixed(tx.creation_time());
        let accepted = AcceptedTransaction::accept_with_time_source(
            tx,
            &chain.network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("stateless checks accept optional but present height expiry");
        let mut ivm_cache = IvmCache::new();
        let result =
            execute_component_transaction_for_testing(&mut block, accepted, &mut ivm_cache, None);
        if should_accept {
            assert!(
                result.is_ok(),
                "expiry one height after current height must remain valid: {result:?}"
            );
        } else {
            match result {
                Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg))) => {
                    assert!(
                        msg.contains("expired at height 2; current height is 2"),
                        "expected equality-boundary expiry rejection, got {msg}"
                    );
                }
                other => panic!("expected expired Validation::NotPermitted, got {other:?}"),
            }
        }
    }
}
