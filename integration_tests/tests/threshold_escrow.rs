#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! End-to-end coverage for the canonical threshold escrow Kotodama sample.
use eyre::{Result, WrapErr, eyre};
use integration_tests::sandbox;
use iroha::query::QueryError;
use iroha::{
    blocking::Client,
    data_model::{
        account::Account,
        asset::{AssetDefinition, AssetId},
        prelude::*,
    },
};
use iroha_data_model::query::dsl::IntoPredicate as _;
use iroha_data_model::{
    ValidationFail,
    query::error::{FindError, QueryExecutionFail},
};
use iroha_executor_data_model::permission::{
    asset::CanTransferAsset, smart_contract::CanManageSmartContractCode,
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use iroha_test_network::{NetworkBuilder, read_on_dedicated_thread};
use iroha_test_samples::{
    ALICE_ID, ALICE_KEYPAIR, BOB_ID, BOB_KEYPAIR, CARPENTER_ID, load_sample_ivm,
};
use std::{
    num::NonZeroU64,
    time::{Duration, Instant},
};
const TX_TIMEOUT: Duration = Duration::from_secs(60);
const CONTRACT_GAS_LIMIT: u64 = 100_000;
const SAMPLE_ASSET_DEFINITION_LITERAL: &str = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
fn sample_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(SAMPLE_ASSET_DEFINITION_LITERAL)
        .expect("sample asset definition literal must parse")
}
fn amount_args(amount: u64) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    map.insert("amount".to_owned(), norito::json!(amount.to_string()));
    norito::json::Value::Object(map)
}
fn open_escrow_args(target_amount: u64) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    map.insert(
        "target_amount".to_owned(),
        norito::json!(target_amount.to_string()),
    );
    norito::json::Value::Object(map)
}
async fn wait_for_tx_terminal_status(
    client: &Client,
    tx_hash_hex: &str,
    timeout: Duration,
    stage: &str,
) -> Result<(String, String)> {
    let hash = tx_hash_hex.parse::<iroha_crypto::HashOf<SignedTransaction>>()?;
    let deadline = Instant::now() + timeout;
    let mut last = String::from("not found");
    loop {
        if let Some(status) = client
            .client()
            .fetch_transaction_status_response_global(hash)
            .await?
        {
            last = format!("{status:?}");
            let kind = status.status.kind.as_str();
            if kind == "Applied" {
                if status.resolved_from != "state"
                    || status.status.block_height.is_none_or(|height| height == 0)
                {
                    return Err(eyre!(
                        "{stage}: Applied lacks exact committed-state evidence: {status:?}"
                    ));
                }
                return Ok((kind.to_owned(), last));
            }
            if matches!(kind, "Rejected" | "Expired") {
                return Ok((kind.to_owned(), last));
            }
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{stage}: timed out waiting for exact transaction `{tx_hash_hex}`; last={last}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
async fn deploy_threshold_escrow(
    client: &Client,
) -> Result<iroha_data_model::smart_contract::ContractAddress> {
    let artifact = load_sample_ivm("threshold_escrow");
    let contract_alias = iroha_data_model::smart_contract::ContractAlias::from_components(
        "threshold_escrow",
        None,
        "universal",
    )
    .expect("threshold escrow alias");
    let (contract_address, _, _, _) = read_on_dedicated_thread({
        let client = client.clone();
        move || {
            super::contracts::deploy_contract_locally_signed(
                &client,
                artifact.as_ref(),
                contract_alias,
            )
        }
    })
    .await
    .wrap_err("deploy threshold escrow task")?;
    read_on_dedicated_thread({
        let client = client.clone();
        let address = contract_address.clone();
        move || {
            client.submit_all(
                [
                    Grant::account_permission(
                        Permission::from(iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
                            contract: address.clone(),
                            entrypoint: "hajimari".to_owned(),
                        }),
                        client.client().account().clone(),
                    ),
                    Grant::account_permission(
                        Permission::from(iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                            contract: address,
                            permission: "Admin".parse().expect("declared escrow role"),
                        }),
                        client.client().account().clone(),
                    ),
                ],
                FeePaymentIntent::authority(Vec::new(), None),
            )
        }
    }).await.wrap_err("grant exact constructor and scoped escrow role task")?;
    call_contract_expect_status(
        client,
        client.client().account(),
        client.client().key_pair().private_key(),
        &contract_address,
        "hajimari",
        None,
        "Applied",
        "initialize threshold escrow",
    )
    .await?;
    Ok(contract_address)
}
async fn call_contract_expect_status(
    client: &Client,
    authority: &AccountId,
    private_key: &iroha_crypto::PrivateKey,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    entrypoint: &str,
    payload: Option<norito::json::Value>,
    expected_status: &str,
    stage: &str,
) -> Result<()> {
    let hash = submit_contract_call_once(
        client,
        authority,
        private_key,
        contract_address,
        entrypoint,
        payload.as_ref(),
        stage,
    )
    .await?;
    let tx_hash_hex = hex::encode(hash.as_ref());
    let observed = wait_for_tx_terminal_status(client, &tx_hash_hex, TX_TIMEOUT, stage).await?;
    if observed.0 != expected_status {
        return Err(eyre!(
            "{stage}: expected `{expected_status}`, observed `{}` for tx `{tx_hash_hex}`; payload={}",
            observed.0,
            observed.1,
        ));
    }
    Ok(())
}
fn threshold_contract_call_intent(
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    entrypoint: &str,
    payload: Option<&norito::json::Value>,
) -> Result<iroha::client::ContractCallDraftIntent> {
    use iroha_data_model::transaction::executable::{ContractArgumentRecord, ContractInvocation};
    let artifact = load_sample_ivm("threshold_escrow");
    let verified = ivm::verify_contract_artifact(artifact.as_ref()).map_err(|error| {
        eyre!("verify independently trusted threshold escrow artifact: {error}")
    })?;
    let descriptor = verified
        .contract_interface
        .entrypoints
        .iter()
        .find(|descriptor| descriptor.name == entrypoint)
        .ok_or_else(|| eyre!("threshold escrow entrypoint `{entrypoint}` is missing"))?;
    let canonical_payload = payload
        .map(Json::from_norito_value_ref)
        .transpose()
        .map_err(|error| eyre!("canonical contract payload: {error}"))?;
    let arguments = match (
        descriptor.argument_schema.as_ref(),
        canonical_payload.as_ref(),
    ) {
        (None, None) if descriptor.params.is_empty() => None,
        (Some(schema), Some(payload)) => Some(
            ContractArgumentRecord::try_new(
                ivm_abi::arguments::encode_argument_record_from_json(schema, payload)
                    .map_err(|error| eyre!("encode trusted threshold escrow arguments: {error}"))?,
            )
            .map_err(|error| eyre!("bound trusted argument record: {error}"))?,
        ),
        _ => {
            return Err(eyre!(
                "threshold escrow payload does not match `{entrypoint}` argument schema"
            ));
        }
    };
    let mut metadata = Metadata::default();
    for (key, value) in [
        ("contract_address", contract_address.to_string()),
        ("contract_code_hash", verified.code_hash.to_string()),
        ("contract_entrypoint", entrypoint.to_owned()),
    ] {
        metadata.insert(key.parse::<Name>()?, Json::new(value));
    }
    if let Some(payload) = canonical_payload {
        metadata.insert("contract_payload".parse::<Name>()?, payload);
    }
    Ok(iroha::client::ContractCallDraftIntent {
        invocation: ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: verified.code_hash,
            entrypoint: entrypoint.to_owned(),
            arguments,
        },
        metadata,
    })
}
async fn submit_contract_call_once(
    client: &Client,
    authority: &AccountId,
    private_key: &iroha_crypto::PrivateKey,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    entrypoint: &str,
    payload: Option<&norito::json::Value>,
    stage: &str,
) -> Result<iroha_crypto::HashOf<SignedTransaction>> {
    let intent = threshold_contract_call_intent(contract_address, entrypoint, payload)?;
    let mut signing_client = client.client().to_builder();
    signing_client.account = authority.clone();
    signing_client.key_pair = iroha_crypto::KeyPair::from_private_key(private_key.clone())?;
    let account = signing_client.build()?.account_client()?;
    // The SDK authenticates prepare, verifies it against the local artifact, signs the exact
    // transaction payload, and submits once. An ambiguous outcome must never restart preparation.
    let result = account
        .post_contract_call_json(
            authority,
            Some(private_key),
            Some(contract_address),
            None,
            entrypoint,
            payload,
            None,
            None,
            None,
            &FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(CONTRACT_GAS_LIMIT)),
            &intent,
        )
        .await;
    match result {
        Ok(response) => response
            .get("tx_hash_hex")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre!("{stage}: submitted response has no exact transaction hash"))?
            .parse()
            .wrap_err_with(|| format!("{stage}: decode exact submitted transaction hash")),
        Err(error) => {
            Err(error).wrap_err_with(|| format!("{stage}: exact public contract submission"))
        }
    }
}
fn signed_contract_state_request(
    client: &Client,
    http: &reqwest::Client,
    url: reqwest::Url,
) -> Result<reqwest::RequestBuilder> {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    static NONCE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let timestamp: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let nonce = format!(
        "threshold-{}-{timestamp}-{}",
        std::process::id(),
        NONCE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let context = client.client();
    let message = iroha::client::canonical_network_request_signature_message(
        context.network_id(),
        &iroha::http::Method::GET,
        &url,
        &[],
        timestamp,
        &nonce,
    )?;
    let signature = iroha_crypto::Signature::try_new(context.key_pair().private_key(), &message)?;
    Ok(http
        .get(url)
        .header("Accept", "application/json")
        .header(
            "x-iroha-account",
            iroha::client::canonical_request_account_header_value(context.account())?,
        )
        .header(
            "x-iroha-signature",
            iroha::client::canonical_request_signature_header_value(&signature)?,
        )
        .header(
            "x-iroha-timestamp-ms",
            iroha::client::canonical_request_timestamp_header_value(timestamp)?,
        )
        .header("x-iroha-nonce", nonce))
}
async fn contract_state_values(
    http: &reqwest::Client,
    client: &Client,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    paths: &[&str],
) -> Result<std::collections::BTreeMap<String, norito::json::Value>> {
    let mut url = client.client().endpoint().join("v1/contracts/state")?;
    let contract_address = contract_address.to_string();
    url.query_pairs_mut()
        .append_pair("contract_address", contract_address.as_str())
        .append_pair("paths", &paths.join(","))
        .append_pair("decode", "json");
    let response = signed_contract_state_request(client, http, url)?
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(eyre!("contract state request returned {status}: {body}"));
    }
    let payload: norito::json::Value = norito::json::from_str(&response.text().await?)?;
    let entries = payload
        .get("entries")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre!("contract state response missing entries: {payload:?}"))?;
    let mut out = std::collections::BTreeMap::new();
    for entry in entries {
        let found = entry
            .get("found")
            .and_then(norito::json::Value::as_bool)
            .unwrap_or(false);
        if !found {
            return Err(eyre!("contract state entry not found: {entry:?}"));
        }
        let path = entry
            .get("path")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre!("contract state entry missing path: {entry:?}"))?;
        let value = decode_contract_state_entry_json(entry)?;
        out.insert(path.to_owned(), value);
    }
    Ok(out)
}
fn decode_contract_state_entry_json(entry: &norito::json::Value) -> Result<norito::json::Value> {
    if entry
        .get("decode_error")
        .is_some_and(|value| !value.is_null())
    {
        return Err(eyre!("contract state decoding failed: {entry:?}"));
    }
    entry
        .get("value_json")
        .cloned()
        .ok_or_else(|| eyre!("canonical decode=json state response omitted value_json: {entry:?}"))
}
async fn asset_value(client: &Client, asset_id: &AssetId) -> Result<Option<Quantity>> {
    let client = client.clone();
    let asset_id = asset_id.clone();
    read_on_dedicated_thread(move || {
        match client
            .client()
            .query_single(FindAssetById::new(asset_id.clone()))
        {
            Ok(asset) if asset.id() == &asset_id => Ok(Some(asset.value().clone())),
            Ok(_) => Err(eyre!("exact asset query returned a different asset")),
            Err(QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::Find(
                FindError::Asset(missing),
            )))) if missing.as_ref() == &asset_id => Ok(None),
            Err(error) => Err(eyre!(error)),
        }
    })
    .await
    .wrap_err("asset query worker failed")
}
async fn account_exists(client: &Client, account_id: &AccountId) -> Result<bool> {
    let client = client.clone();
    let account_id = account_id.clone();
    read_on_dedicated_thread(move || {
        let found = client
            .client()
            .query(FindAccounts)
            .filter_with(|item| item.equals("id", account_id.clone()).into_predicate())
            .execute_single_opt()?;
        match found {
            Some(account) if account.id() == &account_id => Ok(true),
            Some(_) => Err(eyre!("exact account query returned a different account")),
            None => Ok(false),
        }
    })
    .await
    .wrap_err("account query worker failed")
}
async fn asset_definition_exists(
    client: &Client,
    asset_definition_id: &AssetDefinitionId,
) -> Result<bool> {
    let client = client.clone();
    let asset_definition_id = asset_definition_id.clone();
    read_on_dedicated_thread(move || {
        let found = client
            .client()
            .query(FindAssetDefinitions)
            .filter_with(|item| {
                item.equals("id", asset_definition_id.clone())
                    .into_predicate()
            })
            .execute_single_opt()?;
        match found {
            Some(definition) if definition.id() == &asset_definition_id => Ok(true),
            Some(_) => Err(eyre!(
                "exact definition query returned a different asset definition"
            )),
            None => Ok(false),
        }
    })
    .await
    .wrap_err("asset definition query worker failed")
}
async fn setup_ledger_for_sample(
    client: &Client,
    asset_definition_id: &AssetDefinitionId,
    initial_amount: u32,
) -> Result<()> {
    let mut instructions: Vec<InstructionBox> = Vec::new();
    if !account_exists(client, &BOB_ID).await? {
        instructions.push(Register::account(Account::new(BOB_ID.clone())).into());
    }
    if !account_exists(client, &CARPENTER_ID).await? {
        instructions.push(Register::account(Account::new(CARPENTER_ID.clone())).into());
    }
    if !asset_definition_exists(client, asset_definition_id).await? {
        instructions.push(
            Register::asset_definition(AssetDefinition::numeric(
                asset_definition_id.clone(),
                "threshold_escrow_asset".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ))
            .into(),
        );
    }
    instructions.push(
        Mint::asset_quantity(
            initial_amount,
            AssetId::new(asset_definition_id.clone(), ALICE_ID.clone()),
        )
        .into(),
    );
    read_on_dedicated_thread({
        let client = client.clone();
        move || {
            client.submit_all(
                instructions,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
        }
    })
    .await
    .wrap_err("setup ledger task")?;
    let escrow_asset = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    read_on_dedicated_thread({
        let client = client.clone();
        move || {
            let grant_transfer = Grant::account_permission(
                CanTransferAsset {
                    asset: escrow_asset,
                },
                ALICE_ID.clone(),
            );
            let mut bob = client.client().to_builder();
            bob.account = BOB_ID.clone();
            bob.key_pair = BOB_KEYPAIR.clone();
            Client::from_client(bob.build()?)?.submit_all(
                [grant_transfer],
                FeePaymentIntent::authority(Vec::new(), None),
            )
        }
    })
    .await
    .wrap_err("grant escrow transfer permission task")?;
    Ok(())
}
fn threshold_state_paths() -> [&'static str; 9] {
    [
        "payer_account",
        "recipient_account",
        "escrow_account_id",
        "escrow_asset_definition",
        "target_amount_value",
        "funded_amount_value",
        "is_open",
        "is_released",
        "is_refunded",
    ]
}
#[tokio::test]
async fn threshold_escrow_releases_when_fully_funded() -> Result<()> {
    let register_permission: Permission = CanManageSmartContractCode.into();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_block_cadence(Duration::from_secs(4))
        .with_genesis_instruction(Grant::account_permission(
            register_permission,
            ALICE_ID.clone(),
        ));
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(threshold_escrow_releases_when_fully_funded),
    )
    .await?
    else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let client = network.client();
    let http = integration_tests::http::client();
    let asset_definition_id = sample_asset_definition_id();
    setup_ledger_for_sample(&client, &asset_definition_id, 20).await?;
    let contract_address = deploy_threshold_escrow(&client).await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "open_escrow",
        Some(open_escrow_args(10)),
        "Applied",
        "open_escrow",
    )
    .await?;
    let opened_state =
        contract_state_values(&http, &client, &contract_address, &threshold_state_paths()).await?;
    assert_eq!(
        opened_state["payer_account"],
        norito::json::Value::from(ALICE_ID.to_string())
    );
    assert_eq!(
        opened_state["recipient_account"],
        norito::json::Value::from(CARPENTER_ID.to_string())
    );
    assert_eq!(
        opened_state["escrow_account_id"],
        norito::json::Value::from(BOB_ID.to_string())
    );
    assert_eq!(
        opened_state["escrow_asset_definition"],
        norito::json::Value::from(asset_definition_id.to_string())
    );
    assert_eq!(
        opened_state["target_amount_value"],
        norito::json::Value::from("10")
    );
    assert_eq!(
        opened_state["funded_amount_value"],
        norito::json::Value::from("0")
    );
    assert_eq!(opened_state["is_open"], norito::json::Value::from(true));
    assert_eq!(
        opened_state["is_released"],
        norito::json::Value::from(false)
    );
    assert_eq!(
        opened_state["is_refunded"],
        norito::json::Value::from(false)
    );
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "deposit",
        Some(amount_args(4)),
        "Applied",
        "deposit_partial",
    )
    .await?;
    let alice_asset = AssetId::new(asset_definition_id.clone(), ALICE_ID.clone());
    let recipient_asset = AssetId::new(asset_definition_id.clone(), CARPENTER_ID.clone());
    let escrow_asset = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    assert_eq!(
        asset_value(&client, &alice_asset).await?,
        Some(Quantity::from(16_u32))
    );
    assert_eq!(
        asset_value(&client, &escrow_asset).await?,
        Some(Quantity::from(4_u32))
    );
    assert_eq!(asset_value(&client, &recipient_asset).await?, None);
    let partial_state = contract_state_values(
        &http,
        &client,
        &contract_address,
        &[
            "funded_amount_value",
            "is_open",
            "is_released",
            "is_refunded",
        ],
    )
    .await?;
    assert_eq!(
        partial_state["funded_amount_value"],
        norito::json::Value::from("4")
    );
    assert_eq!(partial_state["is_open"], norito::json::Value::from(true));
    assert_eq!(
        partial_state["is_released"],
        norito::json::Value::from(false)
    );
    assert_eq!(
        partial_state["is_refunded"],
        norito::json::Value::from(false)
    );
    call_contract_expect_status(
        &client,
        &BOB_ID.clone(),
        BOB_KEYPAIR.private_key(),
        &contract_address,
        "deposit",
        Some(amount_args(1)),
        "Rejected",
        "deposit_by_non_payer",
    )
    .await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "deposit",
        Some(amount_args(7)),
        "Rejected",
        "deposit_over_target",
    )
    .await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "release_if_ready",
        None,
        "Rejected",
        "release_too_early",
    )
    .await?;
    let early_release_state = contract_state_values(
        &http,
        &client,
        &contract_address,
        &["funded_amount_value", "is_open", "is_released"],
    )
    .await?;
    assert_eq!(
        early_release_state["funded_amount_value"],
        norito::json::Value::from("4")
    );
    assert_eq!(
        asset_value(&client, &escrow_asset).await?,
        Some(Quantity::from(4_u32))
    );
    assert_eq!(asset_value(&client, &recipient_asset).await?, None);
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "deposit",
        Some(amount_args(6)),
        "Applied",
        "deposit_remainder",
    )
    .await?;
    let funded_state = contract_state_values(
        &http,
        &client,
        &contract_address,
        &["funded_amount_value", "is_open"],
    )
    .await?;
    assert_eq!(
        funded_state["funded_amount_value"],
        norito::json::Value::from("10")
    );
    assert_eq!(funded_state["is_open"], norito::json::Value::from(true));
    assert_eq!(
        asset_value(&client, &alice_asset).await?,
        Some(Quantity::from(10_u32))
    );
    assert_eq!(
        asset_value(&client, &escrow_asset).await?,
        Some(Quantity::from(10_u32))
    );
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "release_if_ready",
        None,
        "Applied",
        "release_if_ready",
    )
    .await?;
    let released_state = contract_state_values(
        &http,
        &client,
        &contract_address,
        &[
            "funded_amount_value",
            "is_open",
            "is_released",
            "is_refunded",
        ],
    )
    .await?;
    assert_eq!(
        released_state["funded_amount_value"],
        norito::json::Value::from("10")
    );
    assert_eq!(released_state["is_open"], norito::json::Value::from(false));
    assert_eq!(
        released_state["is_released"],
        norito::json::Value::from(true)
    );
    assert_eq!(
        released_state["is_refunded"],
        norito::json::Value::from(false)
    );
    assert_eq!(
        asset_value(&client, &alice_asset).await?,
        Some(Quantity::from(10_u32))
    );
    assert_eq!(
        asset_value(&client, &recipient_asset).await?,
        Some(Quantity::from(10_u32))
    );
    assert_eq!(asset_value(&client, &escrow_asset).await?, None);
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "deposit",
        Some(amount_args(1)),
        "Rejected",
        "deposit_after_release",
    )
    .await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "release_if_ready",
        None,
        "Rejected",
        "release_after_release",
    )
    .await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "refund",
        None,
        "Rejected",
        "refund_after_release",
    )
    .await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "open_escrow",
        Some(open_escrow_args(10)),
        "Rejected",
        "reopen_after_release",
    )
    .await?;
    Ok(())
}
#[tokio::test]
async fn threshold_escrow_refunds_when_unresolved() -> Result<()> {
    let register_permission: Permission = CanManageSmartContractCode.into();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_block_cadence(Duration::from_secs(4))
        .with_genesis_instruction(Grant::account_permission(
            register_permission,
            ALICE_ID.clone(),
        ));
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(threshold_escrow_refunds_when_unresolved),
    )
    .await?
    else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let client = network.client();
    let http = integration_tests::http::client();
    let asset_definition_id = sample_asset_definition_id();
    setup_ledger_for_sample(&client, &asset_definition_id, 20).await?;
    let contract_address = deploy_threshold_escrow(&client).await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "open_escrow",
        Some(open_escrow_args(9)),
        "Applied",
        "open_escrow",
    )
    .await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "deposit",
        Some(amount_args(3)),
        "Applied",
        "deposit_partial",
    )
    .await?;
    let alice_asset = AssetId::new(asset_definition_id.clone(), ALICE_ID.clone());
    let escrow_asset = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    assert_eq!(
        asset_value(&client, &alice_asset).await?,
        Some(Quantity::from(17_u32))
    );
    assert_eq!(
        asset_value(&client, &escrow_asset).await?,
        Some(Quantity::from(3_u32))
    );
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "refund",
        None,
        "Applied",
        "refund",
    )
    .await?;
    let refunded_state = contract_state_values(
        &http,
        &client,
        &contract_address,
        &[
            "funded_amount_value",
            "is_open",
            "is_released",
            "is_refunded",
        ],
    )
    .await?;
    assert_eq!(
        refunded_state["funded_amount_value"],
        norito::json::Value::from("3")
    );
    assert_eq!(refunded_state["is_open"], norito::json::Value::from(false));
    assert_eq!(
        refunded_state["is_released"],
        norito::json::Value::from(false)
    );
    assert_eq!(
        refunded_state["is_refunded"],
        norito::json::Value::from(true)
    );
    assert_eq!(
        asset_value(&client, &alice_asset).await?,
        Some(Quantity::from(20_u32))
    );
    assert_eq!(asset_value(&client, &escrow_asset).await?, None);
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "deposit",
        Some(amount_args(1)),
        "Rejected",
        "deposit_after_refund",
    )
    .await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "release_if_ready",
        None,
        "Rejected",
        "release_after_refund",
    )
    .await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "refund",
        None,
        "Rejected",
        "refund_after_refund",
    )
    .await?;
    call_contract_expect_status(
        &client,
        &ALICE_ID.clone(),
        ALICE_KEYPAIR.private_key(),
        &contract_address,
        "open_escrow",
        Some(open_escrow_args(9)),
        "Rejected",
        "reopen_after_refund",
    )
    .await?;
    Ok(())
}

#[test]
fn threshold_call_intent_uses_canonical_arguments_from_the_trusted_artifact() {
    let network = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"threshold-intent-test",
        )),
    );
    let address = iroha_data_model::smart_contract::ContractAddress::derive(
        &network,
        &ALICE_ID,
        0,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("fixture address");
    let payload = open_escrow_args(10);
    assert_eq!(payload["target_amount"].as_str(), Some("10"));
    let intent = threshold_contract_call_intent(&address, "open_escrow", Some(&payload))
        .expect("canonical threshold argument record");
    assert!(intent.invocation.arguments.is_some());
    assert_eq!(intent.invocation.contract_address, address);
    assert!(
        threshold_contract_call_intent(&address, "hajimari", None)
            .expect("constructor has no arguments")
            .invocation
            .arguments
            .is_none()
    );
    assert!(
        threshold_contract_call_intent(
            &address,
            "open_escrow",
            Some(&norito::json!({"target_amount": 10}))
        )
        .is_err(),
        "numeric JSON alias cannot replace the canonical quantity string"
    );
    assert!(threshold_contract_call_intent(&address, "open_escrow", None).is_err());
}
