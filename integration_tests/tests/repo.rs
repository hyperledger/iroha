//! Integration coverage for repo and reverse-repo instructions.
use eyre::{Result, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    data_model::{
        prelude::*,
        query::repo::prelude::FindRepoAgreements,
        repo::{RepoAgreement, RepoAgreementId, RepoCashLeg, RepoCollateralLeg, RepoGovernance},
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::isi::RepoMarginCallIsi;
use iroha_executor_data_model::permission::settlement::CanExecuteSettlement;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, BOB_ID, BOB_KEYPAIR};
use std::{
    convert::TryFrom,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
static GENESIS_STATUS: OnceLock<std::result::Result<(), ()>> = OnceLock::new();
static START_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
fn install_quiet_tracing() {
    static QUIET_TRACE: OnceLock<()> = OnceLock::new();
    QUIET_TRACE.get_or_init(|| {});
}
fn ivm_build_profile_exists() -> bool {
    iroha_test_samples::ivm_build_profile_path().is_file()
}
fn quiet_network_builder() -> NetworkBuilder {
    install_quiet_tracing();
    init_instruction_registry();
    NetworkBuilder::new()
        .with_auto_populated_trusted_peers()
        .with_peers(4)
}
fn loopback_bind_allowed() -> bool {
    static LOOPBACK_BIND_ALLOWED: OnceLock<bool> = OnceLock::new();
    *LOOPBACK_BIND_ALLOWED.get_or_init(|| std::net::TcpListener::bind(("127.0.0.1", 0)).is_ok())
}
fn start_test_network() -> Option<(sandbox::SerializedNetwork, tokio::runtime::Runtime)> {
    if !ivm_build_profile_exists() {
        eprintln!("Skipping test: missing IVM build profile");
        return None;
    }
    if !loopback_bind_allowed() {
        eprintln!("Skipping test: environment denies binding TCP sockets on 127.0.0.1");
        return None;
    }
    if matches!(GENESIS_STATUS.get(), Some(Err(()))) {
        eprintln!("Skipping test: failed to start network (cached)");
        return None;
    }
    let serial_guard = sandbox::serial_guard();
    let guard = START_MUTEX.get_or_init(|| Mutex::new(())).lock().unwrap();
    if matches!(GENESIS_STATUS.get(), Some(Err(()))) {
        eprintln!("Skipping test: failed to start network (cached)");
        drop(guard);
        return None;
    }
    let builder = quiet_network_builder();
    let (network, runtime) = builder.build_blocking();
    if let Err(err) = runtime.block_on(async { network.start_all().await }) {
        eprintln!("Skipping test: failed to start network: {err}");
        let _ = GENESIS_STATUS.set(Err(()));
        drop(guard);
        return None;
    }
    let _ = GENESIS_STATUS.set(Ok(()));
    drop(guard);
    Some((
        sandbox::SerializedNetwork::new(network, serial_guard),
        runtime,
    ))
}
fn repo_outsider_key_pair() -> KeyPair {
    KeyPair::try_from_seed(vec![42; 32], Algorithm::Ed25519).expect("fixture repo outsider key")
}
#[test]
fn repo_outsider_fixture_uses_checked_seed_derivation() {
    let key_pair = repo_outsider_key_pair();
    let expected = KeyPair::try_from_seed(vec![42; 32], Algorithm::Ed25519)
        .expect("fixture repo outsider key");
    assert_eq!(key_pair.public_key(), expected.public_key());
}
fn repo_instr_box<T>(instruction: T) -> InstructionBox
where
    RepoInstructionBox: From<T>,
{
    InstructionBox::from(RepoInstructionBox::from(instruction))
}
fn grant_repo_consents(
    base_client: &Client,
    instruction: &RepoIsi,
    collateral_holder: (&AccountId, &KeyPair),
) -> Result<()> {
    let settlement_id = instruction.settlement_id();
    let cash_consent = Permission::from(CanExecuteSettlement {
        debited_asset: AssetId::new(
            instruction.cash_leg().asset_definition_id().clone(),
            instruction.counterparty().clone(),
        ),
        settlement_id: settlement_id.clone(),
        intent_hash: instruction.initiation_intent_hash(),
    });
    let maturity_consent = Permission::from(CanExecuteSettlement {
        debited_asset: AssetId::new(
            instruction.collateral_leg().asset_definition_id().clone(),
            collateral_holder.0.clone(),
        ),
        settlement_id,
        intent_hash: instruction.maturity_intent_hash(),
    });
    let bob_client = alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), base_client);
    bob_client.submit(
        Grant::account_permission(cash_consent, instruction.initiator().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let holder_client = if collateral_holder.0 == &*BOB_ID {
        bob_client
    } else {
        alt_client(
            (collateral_holder.0.clone(), collateral_holder.1.clone()),
            base_client,
        )
    };
    holder_client.submit(
        Grant::account_permission(maturity_consent, instruction.initiator().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    Ok(())
}
fn error_chain_contains(err: &eyre::Report, needle: &str) -> bool {
    err.chain().any(|cause| cause.to_string().contains(needle))
}
fn asset_value(assets: &[Asset], asset_id: &AssetId) -> Option<Quantity> {
    assets
        .iter()
        .find(|asset| asset.id() == asset_id)
        .map(|asset| asset.value().clone())
}
fn wait_for_assets(
    client: &Client,
    expected: &[(&AssetId, Option<Quantity>)],
    context: &str,
) -> Result<Vec<Asset>> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "assets were not queried".to_owned();
    while Instant::now() < deadline {
        match client.client().query(FindAssets::new()).execute_all() {
            Ok(assets) => {
                let all_match = expected.iter().all(|(asset_id, expected_value)| {
                    let observed = asset_value(&assets, asset_id);
                    match expected_value {
                        Some(value) => observed.as_ref() == Some(value),
                        None => observed.is_none(),
                    }
                });
                last_observed = expected
                    .iter()
                    .map(|(asset_id, _)| format!("{asset_id}={:?}", asset_value(&assets, asset_id)))
                    .collect::<Vec<_>>()
                    .join(", ");
                if all_match {
                    return Ok(assets);
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(eyre!(
        "timed out waiting for assets after {context}; last_observed={last_observed}"
    ))
}
fn wait_for_repo_agreement(
    client: &Client,
    agreement_id: &RepoAgreementId,
    context: &str,
) -> Result<RepoAgreement> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "repo agreements were not queried".to_owned();
    while Instant::now() < deadline {
        match client
            .client()
            .query(FindRepoAgreements::new())
            .execute_all()
        {
            Ok(agreements) => {
                last_observed = agreements
                    .iter()
                    .map(|agreement| agreement.id().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                if let Some(agreement) = agreements
                    .into_iter()
                    .find(|agreement| agreement.id() == agreement_id)
                {
                    return Ok(agreement);
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(eyre!(
        "timed out waiting for repo agreement after {context}; id={agreement_id}; last_observed={last_observed}"
    ))
}
#[test]
#[allow(clippy::too_many_lines)]
fn repo_roundtrip_transfers_balances_and_seals_agreement() -> Result<()> {
    let Some((network, _rt)) = start_test_network() else {
        return Ok(());
    };
    let client = network.client();
    let metadata = Metadata::default();
    let cash_def_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal")?,
        "usd".parse()?,
    );
    let collateral_def_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal")?,
        "bond".parse()?,
    );
    // Prepare cash/collateral assets and balances.
    let setup_instructions: Vec<InstructionBox> = vec![
        Register::asset_definition({
            let __asset_definition_id = cash_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "usd".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .into(),
        Register::asset_definition({
            let __asset_definition_id = collateral_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "bond".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .into(),
        Mint::asset_quantity(
            Quantity::from(2000_u64),
            AssetId::new(cash_def_id.clone(), BOB_ID.clone()),
        )
        .into(),
        Mint::asset_quantity(
            Quantity::from(1500_u64),
            AssetId::new(collateral_def_id.clone(), ALICE_ID.clone()),
        )
        .into(),
    ];
    let setup_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                setup_instructions,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    client.submit_transaction_and_wait(&setup_tx)?;
    // Initiate the repo: Alice borrows cash, pledging collateral.
    let agreement_id: RepoAgreementId = "daily_repo".parse()?;
    let repo_instruction_template = || -> Result<RepoIsi> {
        let maturity_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .checked_add(Duration::from_secs(3))
                .ok_or_else(|| eyre!("maturity timestamp overflow"))?
                .as_millis(),
        )
        .expect("repo maturity timestamp fits in u64");
        Ok(RepoIsi::new(
            agreement_id.clone(),
            ALICE_ID.clone(),
            BOB_ID.clone(),
            None,
            RepoCashLeg {
                asset_definition_id: cash_def_id.clone(),
                quantity: Quantity::from(1000_u64),
            },
            RepoCollateralLeg::new(collateral_def_id.clone(), Quantity::from(1100_u64)),
            0,
            maturity_ms,
            RepoGovernance::new(1_500, 86_400, false),
        ))
    };
    let repo_instruction = repo_instruction_template()?;
    grant_repo_consents(&client, &repo_instruction, (&BOB_ID, &BOB_KEYPAIR))?;
    let repo_instruction_box = repo_instr_box(repo_instruction);
    let repo_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                vec![repo_instruction_box],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    client.submit_transaction_and_wait(&repo_tx)?;
    // Ensure duplicate agreement IDs are rejected while active.
    let duplicate_repo = repo_instruction_template()?;
    let duplicate_instruction_box = repo_instr_box(duplicate_repo);
    let duplicate_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                vec![duplicate_instruction_box],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    let duplicate_err = client
        .submit_transaction_and_wait(&duplicate_tx)
        .unwrap_err();
    assert!(
        error_chain_contains(&duplicate_err, "already exists"),
        "expected duplicate repo to be rejected, got {duplicate_err:?}"
    );
    let alice_cash_id = AssetId::new(cash_def_id.clone(), ALICE_ID.clone());
    let bob_cash_id = AssetId::new(cash_def_id.clone(), BOB_ID.clone());
    let alice_collateral_id = AssetId::new(collateral_def_id.clone(), ALICE_ID.clone());
    let bob_collateral_id = AssetId::new(collateral_def_id.clone(), BOB_ID.clone());
    let assets_after_repo = wait_for_assets(
        &client,
        &[
            (&alice_cash_id, Some(Quantity::from(1000_u64))),
            (&bob_cash_id, Some(Quantity::from(1000_u64))),
            (&alice_collateral_id, Some(Quantity::from(400_u64))),
            (&bob_collateral_id, Some(Quantity::from(1100_u64))),
        ],
        "repo initiation",
    )?;
    let alice_cash = assets_after_repo
        .iter()
        .find(|asset| asset.id() == &alice_cash_id)
        .expect("alice cash after repo");
    assert_eq!(*alice_cash.value(), Quantity::from(1000_u64));
    let bob_cash = assets_after_repo
        .iter()
        .find(|asset| asset.id() == &bob_cash_id)
        .expect("bob cash after repo");
    assert_eq!(*bob_cash.value(), Quantity::from(1000_u64));
    let alice_collateral = assets_after_repo
        .iter()
        .find(|asset| asset.id() == &alice_collateral_id)
        .expect("alice collateral after repo");
    assert_eq!(*alice_collateral.value(), Quantity::from(400_u64));
    let bob_collateral = assets_after_repo
        .iter()
        .find(|asset| asset.id() == &bob_collateral_id)
        .expect("bob collateral after repo");
    assert_eq!(*bob_collateral.value(), Quantity::from(1100_u64));
    let repo_snapshot = wait_for_repo_agreement(&client, &agreement_id, "repo maturity lookup")?;
    let future_reverse = ReverseRepoIsi::new(agreement_id.clone());
    let future_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                vec![repo_instr_box(future_reverse)],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    let future_err = client.submit_transaction_and_wait(&future_tx).unwrap_err();
    assert!(
        error_chain_contains(&future_err, "before its recorded maturity"),
        "expected pre-maturity repo settlement to be rejected, got {future_err:?}"
    );
    let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .expect("current timestamp fits in u64");
    if *repo_snapshot.maturity_timestamp_ms() >= now_ms {
        std::thread::sleep(Duration::from_millis(
            repo_snapshot
                .maturity_timestamp_ms()
                .saturating_sub(now_ms)
                .saturating_add(500),
        ));
    }
    let reverse_repo_instruction = ReverseRepoIsi::new(agreement_id.clone());
    let counterparty_client = alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &client);
    let reverse_tx = {
        let account = counterparty_client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                vec![repo_instr_box(reverse_repo_instruction)],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    counterparty_client.submit_transaction_and_wait(&reverse_tx)?;
    let assets_after_reverse = wait_for_assets(
        &client,
        &[
            (&alice_cash_id, None),
            (&bob_cash_id, Some(Quantity::from(2000_u64))),
            (&alice_collateral_id, Some(Quantity::from(1500_u64))),
            (&bob_collateral_id, None),
        ],
        "reverse repo",
    )?;
    let alice_cash_post = assets_after_reverse
        .iter()
        .find(|asset| asset.id() == &alice_cash_id);
    assert!(
        alice_cash_post.is_none(),
        "alice cash asset should be pruned when returning to zero balance"
    );
    let bob_cash_post = assets_after_reverse
        .iter()
        .find(|asset| asset.id() == &bob_cash_id)
        .expect("bob cash after reverse repo");
    assert_eq!(*bob_cash_post.value(), Quantity::from(2000_u64));
    let alice_collateral_post = assets_after_reverse
        .iter()
        .find(|asset| asset.id() == &alice_collateral_id)
        .expect("alice collateral after reverse repo");
    assert_eq!(*alice_collateral_post.value(), Quantity::from(1500_u64));
    let bob_collateral_post = assets_after_reverse
        .iter()
        .find(|asset| asset.id() == &bob_collateral_id);
    assert!(
        bob_collateral_post.is_none(),
        "bob collateral asset should be pruned on unwind"
    );
    // A settled identifier remains on-chain and cannot be reused.
    let reopened_repo = RepoIsi::new(
        agreement_id.clone(),
        ALICE_ID.clone(),
        BOB_ID.clone(),
        None,
        RepoCashLeg {
            asset_definition_id: cash_def_id.clone(),
            quantity: Quantity::from(1000_u64),
        },
        RepoCollateralLeg::new(collateral_def_id.clone(), Quantity::from(1100_u64)),
        0,
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .checked_add(Duration::from_secs(3))
                .expect("maturity arithmetic")
                .as_millis(),
        )
        .expect("reverse maturity timestamp fits in u64"),
        RepoGovernance::new(1_500, 3, false),
    );
    grant_repo_consents(&client, &reopened_repo, (&BOB_ID, &BOB_KEYPAIR))?;
    let reopened_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                vec![repo_instr_box(reopened_repo)],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    let reopened_err = client
        .submit_transaction_and_wait(&reopened_tx)
        .expect_err("settled repo identifier must remain consumed");
    assert!(
        error_chain_contains(&reopened_err, "already exists"),
        "expected one-shot identifier rejection, got {reopened_err:?}"
    );
    let settled = wait_for_repo_agreement(&client, &agreement_id, "settled tombstone")?;
    assert_eq!(
        settled.settlement_timestamp_ms(),
        &Some(*settled.maturity_timestamp_ms())
    );
    Ok(())
}
#[test]
#[allow(clippy::too_many_lines)]
fn repo_margin_call_enforces_cadence_and_participant_rules() -> Result<()> {
    let Some((network, _rt)) = start_test_network() else {
        return Ok(());
    };
    let client = network.client();
    let metadata = Metadata::default();
    let cash_def_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal")?,
        "usd".parse()?,
    );
    let collateral_def_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal")?,
        "bond".parse()?,
    );
    let outsider_keypair = repo_outsider_key_pair();
    let outsider_id = AccountId::new(outsider_keypair.public_key().clone());
    let setup_instructions: Vec<InstructionBox> = vec![
        Register::account(Account::new(outsider_id.clone())).into(),
        Register::asset_definition({
            let __asset_definition_id = cash_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "usd".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .into(),
        Register::asset_definition({
            let __asset_definition_id = collateral_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "bond".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .into(),
        Mint::asset_quantity(
            Quantity::from(2000_u64),
            AssetId::new(cash_def_id.clone(), BOB_ID.clone()),
        )
        .into(),
        Mint::asset_quantity(
            Quantity::from(1500_u64),
            AssetId::new(collateral_def_id.clone(), ALICE_ID.clone()),
        )
        .into(),
    ];
    let setup_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                setup_instructions,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    client.submit_transaction_and_wait(&setup_tx)?;
    let agreement_id: RepoAgreementId = "margin_repo".parse()?;
    let maturity_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .checked_add(Duration::from_secs(3_600))
            .ok_or_else(|| eyre!("maturity timestamp overflow"))?
            .as_millis(),
    )
    .expect("repo maturity timestamp fits in u64");
    let repo_instruction = RepoIsi::new(
        agreement_id.clone(),
        ALICE_ID.clone(),
        BOB_ID.clone(),
        None,
        RepoCashLeg {
            asset_definition_id: cash_def_id.clone(),
            quantity: Quantity::from(1000_u64),
        },
        RepoCollateralLeg::new(collateral_def_id.clone(), Quantity::from(1100_u64)),
        0,
        maturity_ms,
        // Use a generous margin cadence to avoid wall-clock flakiness in the
        // integration test network.
        RepoGovernance::new(1_500, 300, false),
    );
    grant_repo_consents(&client, &repo_instruction, (&BOB_ID, &BOB_KEYPAIR))?;
    let repo_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                vec![repo_instr_box(repo_instruction)],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    client.submit_transaction_and_wait(&repo_tx)?;
    let repo_snapshot = wait_for_repo_agreement(&client, &agreement_id, "margin repo initiation")?;
    let initial_last_margin_ms = *repo_snapshot.last_margin_check_timestamp_ms();
    let expected_first_due = repo_snapshot
        .next_margin_check_after(initial_last_margin_ms)
        .expect("margin cadence configured");
    assert!(
        expected_first_due > initial_last_margin_ms,
        "margin cadence should advance beyond the initiation timestamp"
    );
    let premature_err = client
        .submit_transaction_and_wait(&{
            let account = client.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    vec![repo_instr_box(RepoMarginCallIsi::new(agreement_id.clone()))],
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                    metadata.clone(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
                .expect("build integration-test transaction")
        })
        .unwrap_err();
    assert!(
        error_chain_contains(&premature_err, "margin check is not yet due"),
        "expected cadence enforcement error, got {premature_err:?}"
    );
    let after_reject = wait_for_repo_agreement(&client, &agreement_id, "rejected margin call")?;
    assert_eq!(
        *after_reject.last_margin_check_timestamp_ms(),
        initial_last_margin_ms,
        "rejected margin call should not advance the schedule"
    );
    let unauthorized_client = alt_client((outsider_id.clone(), outsider_keypair), &client);
    let unauthorized_err = unauthorized_client
        .submit_transaction_and_wait(&{
            let account = unauthorized_client.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    vec![repo_instr_box(RepoMarginCallIsi::new(agreement_id))],
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                    metadata,
                ))
                .and_then(|payload| account.sign_transaction(payload))
                .expect("build integration-test transaction")
        })
        .unwrap_err();
    assert!(
        error_chain_contains(
            &unauthorized_err,
            "margin call must be initiated by a repo participant",
        ),
        "expected participant check failure, got {unauthorized_err:?}"
    );
    Ok(())
}
#[test]
#[allow(clippy::too_many_lines)]
fn repo_roundtrip_with_custodian_routes_collateral() -> Result<()> {
    let Some((network, _rt)) = start_test_network() else {
        return Ok(());
    };
    let client = network.client();
    let metadata = Metadata::default();
    let custodian_keypair = KeyPair::random();
    let custodian_id = AccountId::new(custodian_keypair.public_key().clone());
    let cash_def_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal")?,
        "usd".parse()?,
    );
    let collateral_def_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal")?,
        "bond".parse()?,
    );
    let setup_instructions: Vec<InstructionBox> = vec![
        Register::account(Account::new(custodian_id.clone())).into(),
        Register::asset_definition({
            let __asset_definition_id = cash_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "usd".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .into(),
        Register::asset_definition({
            let __asset_definition_id = collateral_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "bond".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .into(),
        Mint::asset_quantity(
            Quantity::from(2000_u64),
            AssetId::new(cash_def_id.clone(), BOB_ID.clone()),
        )
        .into(),
        Mint::asset_quantity(
            Quantity::from(1500_u64),
            AssetId::new(collateral_def_id.clone(), ALICE_ID.clone()),
        )
        .into(),
    ];
    let setup_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                setup_instructions,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    client.submit_transaction_and_wait(&setup_tx)?;
    let agreement_id: RepoAgreementId = "tri_party_repo".parse()?;
    let maturity_timestamp_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .checked_add(Duration::from_secs(3))
            .ok_or_else(|| eyre!("maturity timestamp overflow"))?
            .as_millis(),
    )
    .expect("repo maturity timestamp fits in u64");
    let repo_instruction = RepoIsi::new(
        agreement_id.clone(),
        ALICE_ID.clone(),
        BOB_ID.clone(),
        Some(custodian_id.clone()),
        RepoCashLeg {
            asset_definition_id: cash_def_id.clone(),
            quantity: Quantity::from(1000_u64),
        },
        RepoCollateralLeg::new(collateral_def_id.clone(), Quantity::from(1100_u64)),
        0,
        maturity_timestamp_ms,
        RepoGovernance::new(1_500, 3, false),
    );
    grant_repo_consents(
        &client,
        &repo_instruction,
        (&custodian_id, &custodian_keypair),
    )?;
    let repo_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                vec![repo_instr_box(repo_instruction)],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    client.submit_transaction_and_wait(&repo_tx)?;
    let alice_cash_id = AssetId::new(cash_def_id.clone(), ALICE_ID.clone());
    let bob_cash_id = AssetId::new(cash_def_id.clone(), BOB_ID.clone());
    let alice_collateral_id = AssetId::new(collateral_def_id.clone(), ALICE_ID.clone());
    let custodian_collateral_id = AssetId::new(collateral_def_id.clone(), custodian_id.clone());
    let bob_collateral_id = AssetId::new(collateral_def_id.clone(), BOB_ID.clone());
    let assets_after_repo = wait_for_assets(
        &client,
        &[
            (&alice_cash_id, Some(Quantity::from(1000_u64))),
            (&bob_cash_id, Some(Quantity::from(1000_u64))),
            (&alice_collateral_id, Some(Quantity::from(400_u64))),
            (&bob_collateral_id, None),
            (&custodian_collateral_id, Some(Quantity::from(1100_u64))),
        ],
        "tri-party repo initiation",
    )?;
    let alice_cash = assets_after_repo
        .iter()
        .find(|asset| asset.id() == &alice_cash_id)
        .expect("alice cash after repo");
    assert_eq!(*alice_cash.value(), Quantity::from(1000_u64));
    let bob_cash = assets_after_repo
        .iter()
        .find(|asset| asset.id() == &bob_cash_id)
        .expect("bob cash after repo");
    assert_eq!(*bob_cash.value(), Quantity::from(1000_u64));
    let alice_collateral = assets_after_repo
        .iter()
        .find(|asset| asset.id() == &alice_collateral_id)
        .expect("alice collateral after repo");
    assert_eq!(*alice_collateral.value(), Quantity::from(400_u64));
    assert!(
        !assets_after_repo
            .iter()
            .any(|asset| asset.id() == &bob_collateral_id),
        "counterparty should not hold collateral when custodian participates"
    );
    let custodian_collateral = assets_after_repo
        .iter()
        .find(|asset| asset.id() == &custodian_collateral_id)
        .expect("custodian collateral after repo");
    assert_eq!(*custodian_collateral.value(), Quantity::from(1100_u64));
    let stored_agreement =
        wait_for_repo_agreement(&client, &agreement_id, "tri-party repo initiation")?;
    assert_eq!(
        stored_agreement.custodian(),
        &Some(custodian_id.clone()),
        "custodian id should be persisted in repo agreement"
    );
    let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .expect("current timestamp fits in u64");
    if *stored_agreement.maturity_timestamp_ms() >= now_ms {
        std::thread::sleep(Duration::from_millis(
            stored_agreement
                .maturity_timestamp_ms()
                .saturating_sub(now_ms)
                .saturating_add(500),
        ));
    }
    let reverse_repo_instruction = ReverseRepoIsi::new(agreement_id.clone());
    let custodian_client = alt_client((custodian_id.clone(), custodian_keypair), &client);
    let reverse_tx = {
        let account = custodian_client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                vec![repo_instr_box(reverse_repo_instruction)],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    custodian_client.submit_transaction_and_wait(&reverse_tx)?;
    let assets_after_reverse = wait_for_assets(
        &client,
        &[
            (&alice_cash_id, None),
            (&bob_cash_id, Some(Quantity::from(2000_u64))),
            (&alice_collateral_id, Some(Quantity::from(1500_u64))),
            (&custodian_collateral_id, None),
        ],
        "tri-party reverse repo",
    )?;
    let alice_cash_after_reverse = assets_after_reverse
        .iter()
        .find(|asset| asset.id() == &alice_cash_id);
    assert!(
        alice_cash_after_reverse.is_none(),
        "alice cash should be pruned after returning to zero"
    );
    let bob_cash_after_reverse = assets_after_reverse
        .iter()
        .find(|asset| asset.id() == &bob_cash_id)
        .expect("bob cash after reverse");
    assert_eq!(*bob_cash_after_reverse.value(), Quantity::from(2000_u64));
    let alice_collateral_after_reverse = assets_after_reverse
        .iter()
        .find(|asset| asset.id() == &alice_collateral_id)
        .expect("alice collateral after reverse");
    assert_eq!(
        *alice_collateral_after_reverse.value(),
        Quantity::from(1500_u64)
    );
    assert!(
        !assets_after_reverse
            .iter()
            .any(|asset| asset.id() == &custodian_collateral_id),
        "custodian collateral asset should be pruned after unwind"
    );
    let settled = wait_for_repo_agreement(&client, &agreement_id, "tri-party reverse repo")?;
    assert_eq!(
        settled.settlement_timestamp_ms(),
        &Some(*settled.maturity_timestamp_ms())
    );
    Ok(())
}
fn alt_client(signatory: (AccountId, KeyPair), base_client: &Client) -> Client {
    integration_tests::sync::rebind_blocking_client(base_client, |client| {
        client.account = signatory.0;
        client.key_pair = signatory.1;
    })
}
