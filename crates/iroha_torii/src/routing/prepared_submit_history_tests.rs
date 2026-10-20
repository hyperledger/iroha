//! Prepared-submit replay of an exact committed receipt past the full-prefix fetch budget.
use super::*;

#[tokio::test]
async fn faucet_prepared_submit_replays_committed_outcome_past_fetch_budget() {
    use crate::tests_runtime_handlers::{
        checked_torii_test_ed25519_keypair, past_fetch_budget_history_fixture,
    };
    use iroha_data_model::{
        account::Account,
        asset::{Asset, AssetDefinition, AssetDefinitionId, AssetId},
        domain::Domain,
    };

    let faucet_key = checked_torii_test_ed25519_keypair(0x61, "past-budget faucet signer");
    let faucet_authority = AccountId::new(faucet_key.public_key().clone());
    let claimant = AccountId::new(
        checked_torii_test_ed25519_keypair(0x62, "past-budget faucet claimant")
            .public_key()
            .clone(),
    );
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("xor").expect("asset name"),
    );
    let source = AssetId::new(definition_id.clone(), faucet_authority.clone());
    let amount = Quantity::from(5_u32);
    let world = iroha_core::state::World::with_assets(
        [Domain::new(domain_id).build(&faucet_authority)],
        [
            Account::new(faucet_authority.clone()).build(&faucet_authority),
            Account::new(claimant.clone()).build(&faucet_authority),
        ],
        [AssetDefinition::numeric(
            definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&faucet_authority)],
        [Asset::new(source.clone(), Quantity::from(100_u32))],
        [],
    );
    let claim = AccountFaucetRequestDto {
        account_id: claimant.to_string(),
        pow_anchor_height: 42,
        pow_nonce_hex: "0001020304050607".to_owned(),
    };
    let semantic_hash_hex = hex::encode(faucet_claim_hash(&claim).as_ref());
    let binding = PreparedOperationBindingV1 {
        schema: PreparedOperationBindingV1::SCHEMA.to_owned(),
        semantic_hash_hex: semantic_hash_hex.clone(),
        kind: AccountFaucetPreparedTransactionDto::OPERATION.to_owned(),
        request_id: "61".repeat(32),
        execution_expires_at_unix_ms: 4_102_444_800_000,
    };
    let metadata = prepared_transaction_metadata(
        &binding,
        AccountFaucetPreparedTransactionDto::OPERATION,
        &semantic_hash_hex,
    )
    .expect("prepared faucet metadata");
    // The genuine faucet transfer commits at 501, past the shipped full-prefix fetch budget.
    let (mut app, transactions, _chain) = past_fetch_budget_history_fixture(
        iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 1_000),
        |network| {
            let fee = iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None);
            let transfer =
                Transfer::asset_quantity(source.clone(), amount.clone(), claimant.clone());
            let mut builder = TransactionBuilder::new(network, faucet_authority.clone(), fee)
                .with_metadata(metadata)
                .with_instructions([InstructionBox::from(transfer)]);
            builder.set_creation_time(Duration::from_millis(1_001));
            vec![builder.sign(faucet_key.private_key())]
        },
        &[true],
    );
    Arc::get_mut(&mut app)
        .expect("unique faucet replay app")
        .account_faucet = Some(iroha_config::parameters::actual::ToriiFaucet {
        authority: faucet_authority.clone(),
        private_key_file: "/runtime-only/past-budget-faucet.key".into(),
        signer: faucet_key.clone(),
        asset_definition_id: definition_id.to_string(),
        amount: amount.clone(),
        pow_difficulty_bits: std::num::NonZeroU8::new(1).expect("nonzero"),
        pow_scrypt_log_n: 1,
        pow_scrypt_r: 1,
        pow_scrypt_p: 1,
        pow_max_anchor_age_blocks: std::num::NonZeroU64::new(1).expect("nonzero"),
        pow_adaptive_lookback_blocks: 1,
        pow_adaptive_claims_per_extra_bit: 1,
        pow_adaptive_max_extra_bits: 1,
        pow_beacon_seed_enabled: false,
    });
    let transaction = &transactions[0];
    let refused = crate::canonical_transaction_outcome(&app.state, &transaction.hash())
        .expect_err("the full-prefix outcome reader keeps its fetch budget");
    assert!(matches!(
        refused,
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
        ))
    ));
    let (transaction_hash_hex, signed_transaction_wire_hex, signed_transaction_wire_sha256) =
        canonical_prepared_transaction_wire(transaction).expect("canonical faucet wire");
    let payload = AccountFaucetPreparedSignaturePayloadV1 {
        schema: AccountFaucetPreparedTransactionDto::SCHEMA.to_owned(),
        binding: binding.clone(),
        operation: AccountFaucetPreparedTransactionDto::OPERATION.to_owned(),
        claim,
        semantic_hash_hex,
        account_id: claimant.to_string(),
        asset_definition_id: definition_id.to_string(),
        asset_id: AssetId::new(definition_id, claimant).to_string(),
        amount,
        transaction_hash_hex: transaction_hash_hex.clone(),
        signed_transaction_wire_hex,
        signed_transaction_wire_sha256,
        fee_payment: transaction.payload().fee_payment.clone(),
    };
    let server_signature = sign_prepared_transaction_payload(&payload, faucet_key.private_key())
        .expect("sign prepared faucet envelope");
    let prepared = AccountFaucetPreparedTransactionDto {
        schema: payload.schema,
        binding: payload.binding,
        operation: payload.operation,
        claim: payload.claim,
        semantic_hash_hex: payload.semantic_hash_hex,
        account_id: payload.account_id,
        asset_definition_id: payload.asset_definition_id,
        asset_id: payload.asset_id,
        amount: payload.amount,
        transaction_hash_hex: payload.transaction_hash_hex,
        signed_transaction_wire_hex: payload.signed_transaction_wire_hex,
        signed_transaction_wire_sha256: payload.signed_transaction_wire_sha256,
        fee_payment: payload.fee_payment,
        server_signature,
    };
    let available = app.query_fanout_inflight.available_bytes();
    let response = handle_v1_accounts_faucet_submit_prepared(
        app.clone(),
        crate::JsonOnly(prepared),
        app.telemetry.clone(),
    )
    .await
    .expect("the exact committed faucet transaction replays its canonical outcome")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("replay response body");
    let replay: PreparedTransactionSubmitResponseDto =
        norito::json::from_slice(&body).expect("prepared submit response");
    assert_eq!(replay.outcome, "Applied");
    assert_eq!(
        replay.operation,
        AccountFaucetPreparedTransactionDto::OPERATION
    );
    assert_eq!(replay.transaction_hash_hex, transaction_hash_hex);
    assert_eq!(replay.binding, binding);
    assert_eq!(
        app.queue.active_len(),
        0,
        "a replay must not resubmit the committed faucet transaction"
    );
    assert_eq!(app.query_fanout_inflight.available_bytes(), available);
}
