//! Smart contract query behaviour checks.
use eyre::{Result, WrapErr};
use integration_tests::sandbox;
use iroha::{client::QueryError, data_model::prelude::*};
use iroha_core::smartcontracts::ivm::gas_limit_for_meta;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_test_network::*;
use iroha_test_samples::load_sample_ivm;
use std::num::NonZeroU64;
fn fee_payment_with_gas_limit(bytecode: &IvmBytecode) -> Result<FeePaymentIntent> {
    let parsed =
        ivm::ProgramMetadata::parse(bytecode.as_ref()).wrap_err("parse IVM program metadata")?;
    let gas_limit = gas_limit_for_meta(&parsed.metadata)
        .map_err(|error| eyre::eyre!("invalid IVM cycle limit: {error:?}"))?;
    Ok(FeePaymentIntent::authority(
        Vec::new(),
        NonZeroU64::new(gas_limit),
    ))
}
#[test]
fn smart_contract_query_scenarios() -> Result<()> {
    let Some((network, _rt)) = sandbox::start_network_blocking_or_skip(
        NetworkBuilder::new().with_config_layer(|layer| {
            layer.write(["pipeline", "query_default_cursor_mode"], "stored");
        }),
        stringify!(smart_contract_query_scenarios),
    )?
    else {
        return Ok(());
    };
    let client = network.client();
    let torii = client.client().endpoint().clone();
    let env_dir = network.env_dir().to_path_buf();
    // The contract writes a synthetic cursor that has no server-owned stored query.
    // Continuing it must fail before executor validation or cursor advancement.
    {
        let bytecode = load_sample_ivm("query_assets_and_save_cursor");
        let fee_payment = fee_payment_with_gas_limit(&bytecode)?;
        let transaction = {
            let account = client.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    bytecode,
                    fee_payment,
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build integration-test transaction");
        client.submit_transaction_and_wait(&transaction)?;
        let cursor_key: Name = "cursor".parse().unwrap();
        let asset_cursor = client
            .client()
            .query(FindAccounts)
            .execute_all()? // lightweight DSL: filter/select on client
            .into_iter()
            .find(|account| account.id() == client.client().account())
            .and_then(|account| account.metadata().get(&cursor_key).cloned())
            .expect("account metadata must contain cursor")
            .try_into_any_norito()?;
        let err = client
            .client()
            .raw_continue_iterable_query(asset_cursor)
            .expect_err("a contract-supplied synthetic cursor must not resume a stored query");
        assert!(matches!(err, QueryError::Other(_)));
        assert!(
            err.to_string()
                .starts_with("query failed; HTTP 410 Gone; query_validation_failed: "),
            "expected the decoded Torii envelope for a contract-supplied cursor absent from the store: {err:?}"
        );
    }
    // smart_contract_can_filter_queries
    {
        let bytecode = load_sample_ivm("smart_contract_can_filter_queries");
        let fee_payment = fee_payment_with_gas_limit(&bytecode)?;
        let transaction = {
            let account = client.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    bytecode,
                    fee_payment,
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build integration-test transaction");
        client
            .submit_transaction_and_wait(&transaction)
            .wrap_err_with(|| {
                format!(
                    "submit smart_contract_can_filter_queries failed; torii={torii}, env_dir={}",
                    env_dir.display()
                )
            })?;
    }
    Ok(())
}
