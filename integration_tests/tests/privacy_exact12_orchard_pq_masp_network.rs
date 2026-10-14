#![cfg(feature = "privacy-release-evidence")]

//! Four-peer DA/RBC, lifecycle, atomicity, nullifier replay, and restart gate
//! for the retained native Orchard and PQ-MASP production actions.
use eyre::{Result, WrapErr as _, ensure, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    data_model::{
        account::Account,
        asset::AssetDefinition,
        domain::Domain,
        isi::{
            Grant, InstructionBox, Mint, Register, SetParameter,
            privacy::{
                BootstrapPrivacyOrchardPoolV1, BootstrapPrivacyProofManagedPoolV1,
                RegisterPrivacyProtocolActivationV1, SubmitPrivacyProofV1,
                TransitionPrivacyProtocolLifecycleV1,
            },
        },
        parameter::{Parameter, TransactionParameter},
        permission::Permission,
        prelude::{
            AssetDefinitionId, AssetId, FindAssets, Identifiable, Quantity, QueryBuilderExt,
        },
        privacy::{
            PrivacyActiveLifecycleV1, PrivacyCompiledProfileResultV1,
            PrivacyCompiledProfileSnapshotV1, PrivacyConsensusLimitsV1,
            PrivacyExact12CapabilityManifestV1, PrivacyExact12CapabilityRowV1, PrivacyPoolIdV1,
            PrivacyProofV1, PrivacyProposedLifecycleV1, PrivacyProtocolActivationRecordV1,
            PrivacyProtocolIdV1, PrivacyProtocolLifecycleV1,
        },
        query::{block::prelude::FindBlocks, transaction::prelude::FindTransactions},
        transaction::{
            FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionEntrypoint,
        },
    },
};
use iroha_core::privacy_release_evidence::{
    PrivacyReleaseOrchardNetworkActionV1, PrivacyReleasePqMaspNetworkActionsV1,
    PrivacyReleaseTransactionContextV1, build_privacy_release_orchard_network_action_v1,
    build_privacy_release_pq_masp_network_actions_v1,
};
use iroha_core_privacy::privacy_profiles::{CompiledPrivacyProfileV1, compiled_privacy_profile_v1};
use iroha_executor_data_model::permission::governance::CanEnactGovernance;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_test_network::{NetworkBuilder, init_instruction_registry, read_on_dedicated_thread};
use iroha_test_samples::{ALICE_ID, gen_account_in};
use std::{
    num::{NonZeroU32, NonZeroU64},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, sleep, timeout};
const ORCHARD_PROTOCOL: PrivacyProtocolIdV1 = PrivacyProtocolIdV1::OrchardHalo2ActionsV1;
const PQ_MASP_PROTOCOL: PrivacyProtocolIdV1 = PrivacyProtocolIdV1::PqMaspStarkV1;
const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(180);
const PROVER_TIMEOUT: Duration = Duration::from_secs(900);
const PEER_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);
const RESTART_TIMEOUT: Duration = Duration::from_secs(120);
const TEST_BLOCK_CADENCE: Duration = Duration::from_millis(100);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const ACTION_TTL: Duration = Duration::from_secs(7_200);
const TRANSACTION_BUDGET_BYTES: u64 = 32 * 1024 * 1024;
const TORII_CONTENT_BUDGET_BYTES: i64 = 128 * 1024 * 1024;
const NETWORK_FRAME_BUDGET_BYTES: i64 = 128 * 1024 * 1024;
#[derive(Clone, Copy)]
struct ProtocolExpectationV1 {
    protocol: PrivacyProtocolIdV1,
    compiled: PrivacyCompiledProfileSnapshotV1,
    activation: Option<PrivacyProtocolActivationRecordV1>,
}
fn bounded_client(client: Client) -> Client {
    integration_tests::sync::rebind_blocking_client(&client, |configured| {
        configured.transaction_status_timeout = SUBMISSION_TIMEOUT;
        configured.torii_request_timeout = Duration::from_secs(45);
    })
}
async fn read_privacy_capabilities(client: &Client) -> Result<PrivacyExact12CapabilityManifestV1> {
    let client = client.clone();
    read_on_dedicated_thread(move || client.client().get_privacy_capabilities()).await
}
fn no_fee() -> FeePaymentIntent {
    FeePaymentIntent::authority(Vec::new(), None)
}
fn error_chain_contains(error: &eyre::Report, needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    error
        .chain()
        .any(|cause| cause.to_string().to_ascii_lowercase().contains(&needle))
}
fn error_chain_contains_any(error: &eyre::Report, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| error_chain_contains(error, needle))
}
fn is_exact_transaction_replay(error: &eyre::Report) -> bool {
    error_chain_contains_any(
        error,
        &[
            "prtry:already_committed",
            "prtry:already_enqueued",
            "already_committed",
            "already_enqueued",
            "transaction already committed",
            "transaction already present in the queue",
        ],
    )
}
fn protocol_row(
    snapshot: &PrivacyExact12CapabilityManifestV1,
    protocol: PrivacyProtocolIdV1,
) -> Result<PrivacyExact12CapabilityRowV1> {
    snapshot
        .protocols
        .iter()
        .copied()
        .find(|row| row.protocol_id == protocol)
        .ok_or_else(|| eyre!("canonical capability snapshot omitted {protocol:?}"))
}
fn assert_protocol_expectations(
    snapshot: &PrivacyExact12CapabilityManifestV1,
    expectations: &[ProtocolExpectationV1],
    context: &str,
) -> Result<()> {
    snapshot
        .validate()
        .wrap_err_with(|| format!("{context}: invalid capability snapshot"))?;
    for expected in expectations {
        let row = protocol_row(snapshot, expected.protocol)?;
        ensure!(
            row.compiled_profile == PrivacyCompiledProfileResultV1::Available(expected.compiled),
            "{context}: {:?} compiled profile drifted: {:?}",
            expected.protocol,
            row.compiled_profile
        );
        ensure!(
            row.activation == expected.activation,
            "{context}: {:?} lifecycle mismatch: expected {:?}, got {:?}",
            expected.protocol,
            expected.activation,
            row.activation
        );
    }
    Ok(())
}
async fn wait_for_all_peer_protocols(
    network: &sandbox::SerializedNetwork,
    minimum_height: u64,
    expectations: &[ProtocolExpectationV1],
    context: &str,
) -> Result<Vec<PrivacyExact12CapabilityManifestV1>> {
    let deadline = Instant::now() + PEER_CONVERGENCE_TIMEOUT;
    let mut last_observed = Vec::new();
    loop {
        let mut snapshots = Vec::with_capacity(network.peers().len());
        last_observed.clear();
        for (index, peer) in network.peers().iter().enumerate() {
            let client = bounded_client(peer.client());
            match read_privacy_capabilities(&client).await {
                Ok(snapshot) if snapshot.committed_height >= minimum_height => {
                    match assert_protocol_expectations(&snapshot, expectations, context) {
                        Ok(()) => {
                            last_observed.push(format!(
                                "peer {index}: exact rows at height {}",
                                snapshot.committed_height
                            ));
                            snapshots.push(snapshot);
                        }
                        Err(error) => last_observed.push(format!(
                            "peer {index}: height={}, row mismatch: {error}",
                            snapshot.committed_height
                        )),
                    }
                }
                Ok(snapshot) => last_observed.push(format!(
                    "peer {index}: height={} below {minimum_height}",
                    snapshot.committed_height
                )),
                Err(error) => last_observed.push(format!("peer {index}: query failed: {error}")),
            }
        }
        if snapshots.len() == network.peers().len() {
            return Ok(snapshots);
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{context}: peers did not converge within {PEER_CONVERGENCE_TIMEOUT:?}; {}",
                last_observed.join("; ")
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}
async fn canonical_genesis_hash(client: &Client) -> Result<[u8; 32]> {
    let query_client = client.clone();
    let blocks = read_on_dedicated_thread(move || {
        Ok(query_client.client().query(FindBlocks).execute_all()?)
    })
    .await
    .wrap_err("query committed blocks for canonical genesis binding")?;
    let genesis = blocks
        .iter()
        .filter(|block| block.header().prev_block_hash().is_none())
        .collect::<Vec<_>>();
    ensure!(
        genesis.len() == 1,
        "FindBlocks must contain exactly one canonical genesis block, got {}",
        genesis.len()
    );
    let hash = *genesis[0].header().hash().as_ref();
    ensure!(hash != [0; 32], "canonical genesis hash must be nonzero");
    Ok(hash)
}
// Each isolated ordinary submission executes in the next native certified global carrier.
async fn next_governed_execution_height(client: &Client) -> Result<u64> {
    read_privacy_capabilities(client)
        .await
        .wrap_err("query committed height before governed transaction")?
        .committed_height
        .checked_add(1)
        .ok_or_else(|| eyre!("governed privacy execution height overflowed"))
}
fn proposed_activation(
    compiled: CompiledPrivacyProfileV1,
    proposed_at_height: u64,
) -> PrivacyProtocolActivationRecordV1 {
    compiled.activation_record(PrivacyProtocolLifecycleV1::Proposed(
        PrivacyProposedLifecycleV1 { proposed_at_height },
    ))
}
fn active_activation(
    compiled: CompiledPrivacyProfileV1,
    proposed_at_height: u64,
    activated_at_height: u64,
) -> PrivacyProtocolActivationRecordV1 {
    compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
        PrivacyActiveLifecycleV1 {
            proposed_at_height,
            activated_at_height,
            state_since_height: activated_at_height,
        },
    ))
}
async fn submit_instructions(
    client: &Client,
    instructions: Vec<InstructionBox>,
    context: &str,
) -> Result<iroha_crypto::HashOf<SignedTransaction>> {
    let client = client.clone();
    timeout(
        SUBMISSION_TIMEOUT,
        read_on_dedicated_thread(move || client.submit_all(instructions, no_fee())),
    )
    .await
    .map_err(|_| eyre!("{context}: submission exceeded {SUBMISSION_TIMEOUT:?}"))?
    .wrap_err_with(|| context.to_owned())
}
async fn submit_signed_transaction(
    client: &Client,
    transaction: &SignedTransaction,
    context: &str,
) -> Result<iroha_crypto::HashOf<SignedTransaction>> {
    timeout(
        SUBMISSION_TIMEOUT,
        client
            .account_client()
            .submit_transaction_and_wait(transaction),
    )
    .await
    .map_err(|_| eyre!("{context}: signed transaction exceeded {SUBMISSION_TIMEOUT:?}"))?
    .wrap_err_with(|| context.to_owned())
}
async fn exact_transaction_result(
    client: &Client,
    transaction: &SignedTransaction,
) -> Result<Option<bool>> {
    let expected_hash = transaction.hash_as_entrypoint();
    let expected_entrypoint = TransactionEntrypoint::External(transaction.clone());
    let query_client = client.clone();
    let transactions = read_on_dedicated_thread(move || {
        Ok(query_client
            .client()
            .query(FindTransactions::new())
            .execute_all()?)
    })
    .await
    .wrap_err("query finalized transactions")?;
    let Some(committed) = transactions
        .iter()
        .find(|committed| committed.entrypoint_hash() == &expected_hash)
    else {
        return Ok(None);
    };
    ensure!(
        committed.entrypoint() == &expected_entrypoint,
        "entrypoint hash matched different transaction bytes"
    );
    Ok(Some(committed.result().0.is_ok()))
}
async fn wait_for_transaction_result_on_peers(
    clients: &[Client],
    transaction: &SignedTransaction,
    expected_success: bool,
    context: &str,
) -> Result<()> {
    let deadline = Instant::now() + PEER_CONVERGENCE_TIMEOUT;
    let mut last_observed = Vec::new();
    loop {
        let mut matching = 0_usize;
        last_observed.clear();
        for (index, client) in clients.iter().enumerate() {
            match exact_transaction_result(client, transaction).await {
                Ok(Some(success)) if success == expected_success => {
                    matching += 1;
                    last_observed.push(format!("peer {index}: expected result visible"));
                }
                Ok(Some(success)) => last_observed.push(format!(
                    "peer {index}: result success={success}, expected {expected_success}"
                )),
                Ok(None) => last_observed.push(format!("peer {index}: transaction absent")),
                Err(error) => last_observed.push(format!("peer {index}: {error}")),
            }
        }
        if matching == clients.len() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{context}: transaction result did not converge within \
                 {PEER_CONVERGENCE_TIMEOUT:?}; {}",
                last_observed.join("; ")
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}
async fn asset_quantities(client: &Client, asset_ids: &[AssetId]) -> Result<Vec<Option<Quantity>>> {
    let query_client = client.clone();
    let assets = read_on_dedicated_thread(move || {
        Ok(query_client
            .client()
            .query(FindAssets::new())
            .execute_all()?)
    })
    .await
    .wrap_err("query exact asset snapshot")?;
    Ok(asset_ids
        .iter()
        .map(|asset_id| {
            assets
                .iter()
                .find(|asset| asset.id() == asset_id)
                .map(|asset| asset.value().clone())
        })
        .collect())
}
async fn wait_for_asset_quantities(
    clients: &[Client],
    asset_ids: &[AssetId],
    expected: &[Option<Quantity>],
    context: &str,
) -> Result<()> {
    let deadline = Instant::now() + PEER_CONVERGENCE_TIMEOUT;
    let mut last_observed = Vec::new();
    loop {
        let mut matching = 0_usize;
        last_observed.clear();
        for (index, client) in clients.iter().enumerate() {
            match asset_quantities(client, asset_ids).await {
                Ok(observed) if observed == expected => {
                    matching += 1;
                    last_observed.push(format!("peer {index}: {observed:?}"));
                }
                Ok(observed) => last_observed.push(format!(
                    "peer {index}: observed {observed:?}, expected {expected:?}"
                )),
                Err(error) => last_observed.push(format!("peer {index}: {error}")),
            }
        }
        if matching == clients.len() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{context}: asset state did not converge within {PEER_CONVERGENCE_TIMEOUT:?}; {}",
                last_observed.join("; ")
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}
fn independently_resign_corrupted_proof(
    client: &Client,
    valid: &SignedTransaction,
) -> Result<SignedTransaction> {
    let (valid_intent, submission) = valid
        .privacy_transaction_intent_binding_if_present_v1()
        .wrap_err("scan canonical retained-native action before corruption")?
        .ok_or_else(|| eyre!("canonical action omitted its privacy submission"))?;
    let mut envelope = submission.envelope.clone();
    let proof = match &mut envelope.proof {
        PrivacyProofV1::OrchardHalo2ActionsV1(proof) | PrivacyProofV1::PqMaspStarkV1(proof) => {
            proof
        }
        _ => return Err(eyre!("canonical action carried a different proof variant")),
    };
    ensure!(
        proof.bytes.len() > 8,
        "canonical proof is too short to corrupt"
    );
    let interior = proof.bytes.len() / 2;
    proof.bytes[interior] ^= 0x01;
    envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .wrap_err("proof corruption must preserve the generic envelope contract")?;
    let corrupted = TransactionBuilder::from_payload(valid.payload().clone())
        .wrap_err("re-open canonical retained-native payload")?
        .with_instructions([SubmitPrivacyProofV1::new(envelope)])
        .try_sign(client.client().key_pair().private_key())
        .wrap_err("independently sign corrupted retained-native proof")?;
    corrupted
        .verify_signature()
        .wrap_err("verify independently signed corrupted transaction")?;
    let (corrupted_intent, _) = corrupted
        .privacy_transaction_intent_binding_if_present_v1()
        .wrap_err("corrupted action lost its transaction-intent binding")?
        .ok_or_else(|| eyre!("corrupted action omitted its privacy submission"))?;
    ensure!(
        corrupted_intent == valid_intent,
        "proof-only corruption changed the proof-independent transaction intent"
    );
    ensure!(
        corrupted.hash() != valid.hash(),
        "proof corruption did not change the signed transaction hash"
    );
    Ok(corrupted)
}
async fn wait_for_common_commit_subject(
    clients: &[Client],
    minimum_height: u64,
    context: &str,
) -> Result<()> {
    let deadline = Instant::now() + PEER_CONVERGENCE_TIMEOUT;
    let mut last_observed = Vec::new();
    loop {
        let mut subjects = Vec::with_capacity(clients.len());
        last_observed.clear();
        for (index, client) in clients.iter().enumerate() {
            let status_client = client.clone();
            match read_on_dedicated_thread(move || status_client.client().get_sumeragi_status())
                .await
            {
                Ok(status) => {
                    if let Some(halted) = status.halted {
                        last_observed.push(format!("peer {index}: halted: {halted:?}"));
                    } else if status.committed_height < minimum_height {
                        last_observed.push(format!(
                            "peer {index}: committed height {} below {minimum_height}",
                            status.committed_height
                        ));
                    } else {
                        subjects.push(status.committed_height);
                        last_observed.push(format!(
                            "peer {index}: committed height {}",
                            status.committed_height
                        ));
                    }
                }
                Err(error) => last_observed.push(format!("peer {index}: status failed: {error}")),
            }
        }
        if subjects.len() == clients.len() && subjects.iter().all(|subject| *subject == subjects[0])
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{context}: DA/RBC committed subject did not converge within \
                 {PEER_CONVERGENCE_TIMEOUT:?}; {}",
                last_observed.join("; ")
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}
fn action_context(
    client: &Client,
    genesis_hash: [u8; 32],
    creation_time: Duration,
    nonce: u32,
) -> PrivacyReleaseTransactionContextV1 {
    PrivacyReleaseTransactionContextV1 {
        network_id: *client.client().network_id(),
        authority: client.client().account().clone(),
        creation_time,
        time_to_live: Some(ACTION_TTL),
        nonce: NonZeroU32::new(nonce),
        fee_payment: no_fee(),
        metadata: Metadata::default(),
        genesis_hash,
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_orchard_and_pq_masp_actions_survive_four_peer_da_replay_and_restart()
-> Result<()> {
    init_instruction_registry();
    let context =
        stringify!(canonical_orchard_and_pq_masp_actions_survive_four_peer_da_replay_and_restart);
    let privacy_domain = DomainId::try_new("privacy", "universal")?;
    let (reserve_account, _) = gen_account_in("privacy");
    let orchard_asset = AssetDefinitionId::derive_from_components(
        privacy_domain.clone(),
        "orchard_note".parse::<Name>()?,
    );
    let pq_asset = AssetDefinitionId::derive_from_components(
        privacy_domain.clone(),
        "pq_note".parse::<Name>()?,
    );
    let orchard_asset_at_alice = AssetId::new(orchard_asset.clone(), ALICE_ID.clone());
    let orchard_asset_at_reserve = AssetId::new(orchard_asset.clone(), reserve_account.clone());
    let transaction_budget =
        NonZeroU64::new(TRANSACTION_BUDGET_BYTES).expect("fixed transaction budget is nonzero");
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_block_cadence(TEST_BLOCK_CADENCE)
        .with_permissioned_consensus()
        .with_config_layer(|layer| {
            layer
                .write(["torii", "max_content_len"], TORII_CONTENT_BUDGET_BYTES)
                .write(
                    ["torii", "query_fanout_max_retained_bytes"],
                    TORII_CONTENT_BUDGET_BYTES,
                )
                .write(["network", "max_frame_bytes"], NETWORK_FRAME_BUDGET_BYTES)
                .write(
                    ["network", "max_frame_bytes_consensus"],
                    NETWORK_FRAME_BUDGET_BYTES,
                )
                .write(
                    ["network", "max_frame_bytes_control"],
                    NETWORK_FRAME_BUDGET_BYTES,
                )
                .write(
                    ["network", "max_frame_bytes_block_sync"],
                    NETWORK_FRAME_BUDGET_BYTES,
                )
                .write(
                    ["network", "max_frame_bytes_other"],
                    NETWORK_FRAME_BUDGET_BYTES,
                )
                .write(
                    ["network", "max_frame_bytes_tx_gossip"],
                    NETWORK_FRAME_BUDGET_BYTES,
                );
        })
        .with_genesis_instruction(SetParameter::new(Parameter::Transaction(
            TransactionParameter::MaxTxBytes(transaction_budget),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Transaction(
            TransactionParameter::MaxDecompressedBytes(transaction_budget),
        )))
        .with_genesis_instruction(Register::domain(Domain::new(privacy_domain.clone())))
        .with_genesis_instruction(Register::account(Account::new(reserve_account.clone())))
        .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
            orchard_asset.clone(),
            "orchard_note".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )))
        .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
            pq_asset.clone(),
            "pq_note".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )))
        .with_genesis_instruction(Mint::asset_quantity(
            100_u32,
            orchard_asset_at_alice.clone(),
        ));
    let Some(network) = sandbox::start_network_async_or_skip(builder, context).await? else {
        return Ok(());
    };
    let result: Result<()> = async {
        ensure!(
            network.peers().len() == 4,
            "retained-native DA gate requires exactly four peers"
        );
        network
            .ensure_blocks_with(|height| height.total >= 1)
            .await?;
        let client = bounded_client(network.client());
        let all_clients = network
            .peers()
            .iter()
            .map(|peer| bounded_client(peer.client()))
            .collect::<Vec<_>>();
        let genesis_hash = canonical_genesis_hash(&client).await?;
        let orchard_compiled = compiled_privacy_profile_v1(ORCHARD_PROTOCOL)
            .wrap_err("load canonical Orchard compiled profile")?;
        let pq_compiled = compiled_privacy_profile_v1(PQ_MASP_PROTOCOL)
            .wrap_err("load canonical PQ-MASP compiled profile")?;
        let orchard_snapshot: PrivacyCompiledProfileSnapshotV1 = orchard_compiled.into();
        let pq_snapshot: PrivacyCompiledProfileSnapshotV1 = pq_compiled.into();
        submit_instructions(
            &client,
            vec![
                Grant::account_permission(
                    Permission::from(CanEnactGovernance),
                    client.client().account().clone(),
                )
                .into(),
            ],
            "grant CanEnactGovernance",
        )
        .await?;
        let registration_height = next_governed_execution_height(&client).await?;
        let orchard_proposed =
            proposed_activation(orchard_compiled, registration_height);
        let pq_proposed = proposed_activation(pq_compiled, registration_height);
        submit_instructions(
            &client,
            vec![
                RegisterPrivacyProtocolActivationV1::new(orchard_proposed).into(),
                RegisterPrivacyProtocolActivationV1::new(pq_proposed).into(),
            ],
            "register exact Orchard and PQ-MASP activations",
        )
        .await?;
        let proposed_expectations = [
            ProtocolExpectationV1 {
                protocol: ORCHARD_PROTOCOL,
                compiled: orchard_snapshot,
                activation: Some(orchard_proposed),
            },
            ProtocolExpectationV1 {
                protocol: PQ_MASP_PROTOCOL,
                compiled: pq_snapshot,
                activation: Some(pq_proposed),
            },
        ];
        wait_for_all_peer_protocols(
            &network,
            registration_height,
            &proposed_expectations,
            "exact proposed retained-native lifecycles",
        )
        .await?;
        let creation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .wrap_err("system clock is before the Unix epoch")?;
        let signing_key = client.client().key_pair().private_key().clone();
        let pre_orchard_context = action_context(
            &client,
            genesis_hash,
            creation_time + Duration::from_millis(1),
            101,
        );
        let final_orchard_context = action_context(
            &client,
            genesis_hash,
            creation_time + Duration::from_millis(2),
            102,
        );
        let pre_pq_context = action_context(
            &client,
            genesis_hash,
            creation_time + Duration::from_millis(3),
            103,
        );
        let final_pq_context = action_context(
            &client,
            genesis_hash,
            creation_time + Duration::from_millis(4),
            104,
        );
        let replay_pq_context = action_context(
            &client,
            genesis_hash,
            creation_time + Duration::from_millis(5),
            105,
        );
        let post_restart_replay_pq_context = action_context(
            &client,
            genesis_hash,
            creation_time + Duration::from_millis(6),
            106,
        );
        let orchard_pool = PrivacyPoolIdV1::new([0x41; 32]);
        let reserve_for_builder = reserve_account.clone();
        let orchard_asset_for_builder = orchard_asset.clone();
        let build_actions = tokio::task::spawn_blocking(move || {
            let pre_orchard = build_privacy_release_orchard_network_action_v1(
                pre_orchard_context,
                orchard_pool,
                orchard_asset_for_builder.clone(),
                reserve_for_builder.clone(),
                registration_height.saturating_add(1_000),
                [0x31; 32],
                &signing_key,
            )
            .map_err(|error| eyre!("build pre-activation Orchard action: {error:?}"))?;
            let final_orchard = build_privacy_release_orchard_network_action_v1(
                final_orchard_context,
                orchard_pool,
                orchard_asset_for_builder,
                reserve_for_builder,
                registration_height.saturating_add(1_000),
                [0x32; 32],
                &signing_key,
            )
            .map_err(|error| eyre!("build final Orchard action: {error:?}"))?;
            let pq_actions = build_privacy_release_pq_masp_network_actions_v1(
                pre_pq_context,
                final_pq_context,
                replay_pq_context,
                post_restart_replay_pq_context,
                [0x50; 32],
                &signing_key,
            )
            .map_err(|error| eyre!("build PQ-MASP network actions: {error:?}"))?;
            Ok::<_, eyre::Report>((pre_orchard, final_orchard, pq_actions))
        });
        let (pre_orchard, final_orchard, pq_actions): (
            PrivacyReleaseOrchardNetworkActionV1,
            PrivacyReleaseOrchardNetworkActionV1,
            PrivacyReleasePqMaspNetworkActionsV1,
        ) = timeout(PROVER_TIMEOUT, build_actions)
            .await
            .map_err(|_| eyre!("retained-native action proving exceeded {PROVER_TIMEOUT:?}"))?
            .map_err(|error| eyre!("retained-native prover task failed: {error}"))??;
        ensure!(
            pre_orchard.bootstrap == final_orchard.bootstrap,
            "Orchard fixtures disagree on the governed pool bootstrap"
        );
        ensure!(
            pq_actions.bootstrap.asset_definition_id() == &pq_asset,
            "PQ-MASP fixture asset differs from the genesis asset"
        );
        ensure!(
            pre_orchard.transaction.hash() != final_orchard.transaction.hash(),
            "pre-activation and final Orchard actions must be distinct"
        );
        let pre_orchard_error = submit_signed_transaction(
            &client,
            &pre_orchard.transaction,
            "valid Orchard action before activation must reject",
        )
        .await
        .expect_err("valid Orchard action was admitted before activation");
        ensure!(
            error_chain_contains(&pre_orchard_error, "activation is not active"),
            "pre-activation Orchard rejection had wrong reason: {pre_orchard_error:?}"
        );
        let pre_pq_error = submit_signed_transaction(
            &client,
            &pq_actions.preactivation_transaction,
            "valid PQ-MASP action before activation must reject",
        )
        .await
        .expect_err("valid PQ-MASP action was admitted before activation");
        ensure!(
            error_chain_contains(&pre_pq_error, "activation is not active"),
            "pre-activation PQ-MASP rejection had wrong reason: {pre_pq_error:?}"
        );
        wait_for_transaction_result_on_peers(
            &all_clients,
            &pre_orchard.transaction,
            false,
            "pre-activation Orchard rejection convergence",
        )
        .await?;
        wait_for_transaction_result_on_peers(
            &all_clients,
            &pq_actions.preactivation_transaction,
            false,
            "pre-activation PQ-MASP rejection convergence",
        )
        .await?;
        wait_for_asset_quantities(
            &all_clients,
            &[
                orchard_asset_at_alice.clone(),
                orchard_asset_at_reserve.clone(),
            ],
            &[Some(Quantity::from(100_u32)), None],
            "pre-activation rejections must preserve public bridge balances",
        )
        .await?;
        let activation_height = next_governed_execution_height(&client).await?;
        let orchard_active = active_activation(orchard_compiled, registration_height, activation_height);
        let pq_active = active_activation(pq_compiled, registration_height, activation_height);
        submit_instructions(&client, vec![
            TransitionPrivacyProtocolLifecycleV1::new(ORCHARD_PROTOCOL, orchard_active.lifecycle).into(),
            TransitionPrivacyProtocolLifecycleV1::new(PQ_MASP_PROTOCOL, pq_active.lifecycle).into(),
        ], "explicitly activate exact Orchard and PQ-MASP profiles").await?;
        let active_expectations = [
            ProtocolExpectationV1 {
                protocol: ORCHARD_PROTOCOL,
                compiled: orchard_snapshot,
                activation: Some(orchard_active),
            },
            ProtocolExpectationV1 {
                protocol: PQ_MASP_PROTOCOL,
                compiled: pq_snapshot,
                activation: Some(pq_active),
            },
        ];
        wait_for_all_peer_protocols(
            &network,
            activation_height,
            &active_expectations,
            "exact active retained-native lifecycles",
        )
        .await?;
        submit_instructions(
            &client,
            vec![
                BootstrapPrivacyOrchardPoolV1::new(final_orchard.bootstrap.clone()).into(),
                BootstrapPrivacyProofManagedPoolV1::new(pq_actions.bootstrap.clone()).into(),
            ],
            "bootstrap authoritative Orchard and PQ-MASP pools",
        )
        .await?;
        let bootstrap_height = read_privacy_capabilities(&client).await
            .wrap_err("query height after retained-native bootstraps")?
            .committed_height;
        wait_for_asset_quantities(
            &all_clients,
            &[
                orchard_asset_at_alice.clone(),
                orchard_asset_at_reserve.clone(),
            ],
            &[Some(Quantity::from(100_u32)), None],
            "pool bootstrap must preserve public bridge balances",
        )
        .await?;
        let corrupted_orchard =
            independently_resign_corrupted_proof(&client, &final_orchard.transaction)?;
        let corrupted_pq =
            independently_resign_corrupted_proof(&client, &pq_actions.canonical_transaction)?;
        let corrupted_orchard_error = submit_signed_transaction(
            &client,
            &corrupted_orchard,
            "independently signed Orchard proof corruption must reject",
        )
        .await
        .expect_err("corrupted Orchard proof was accepted");
        ensure!(
            error_chain_contains(
                &corrupted_orchard_error,
                "native orchard verification failed"
            ),
            "corrupted Orchard proof rejected for wrong reason: {corrupted_orchard_error:?}"
        );
        let corrupted_pq_error = submit_signed_transaction(
            &client,
            &corrupted_pq,
            "independently signed PQ-MASP proof corruption must reject",
        )
        .await
        .expect_err("corrupted PQ-MASP proof was accepted");
        ensure!(
            error_chain_contains(&corrupted_pq_error, "native pq-masp verification failed"),
            "corrupted PQ-MASP proof rejected for wrong reason: {corrupted_pq_error:?}"
        );
        wait_for_transaction_result_on_peers(
            &all_clients,
            &corrupted_orchard,
            false,
            "corrupted Orchard rejection convergence",
        )
        .await?;
        wait_for_transaction_result_on_peers(
            &all_clients,
            &corrupted_pq,
            false,
            "corrupted PQ-MASP rejection convergence",
        )
        .await?;
        wait_for_asset_quantities(
            &all_clients,
            &[
                orchard_asset_at_alice.clone(),
                orchard_asset_at_reserve.clone(),
            ],
            &[Some(Quantity::from(100_u32)), None],
            "proof failures must preserve every public bridge balance",
        )
        .await?;
        ensure!(
            read_privacy_capabilities(&client).await
                .wrap_err("query height after corruption rejections")?
                .committed_height
                >= bootstrap_height.saturating_add(2),
            "both rejected proof transactions must reach canonical finality"
        );
        let restart_index = network.peers().len() - 1;
        let restart_peer = network.peers()[restart_index].clone();
        let config_layers = network.config_layers().collect::<Vec<_>>();
        ensure!(
            restart_peer.shutdown_if_started().await,
            "selected retained-native peer was not running before restart coverage"
        );
        let healthy_clients = network
            .peers()
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != restart_index)
            .map(|(_, peer)| bounded_client(peer.client()))
            .collect::<Vec<_>>();
        submit_signed_transaction(
            &client,
            &final_orchard.transaction,
            "submit canonical active Orchard action through DA/RBC",
        )
        .await?;
        wait_for_transaction_result_on_peers(
            &healthy_clients,
            &final_orchard.transaction,
            true,
            "healthy-peer Orchard finality",
        )
        .await?;
        submit_signed_transaction(
            &client,
            &pq_actions.canonical_transaction,
            "submit canonical active PQ-MASP action through DA/RBC",
        )
        .await?;
        wait_for_transaction_result_on_peers(
            &healthy_clients,
            &pq_actions.canonical_transaction,
            true,
            "healthy-peer PQ-MASP finality",
        )
        .await?;
        wait_for_asset_quantities(
            &healthy_clients,
            &[
                orchard_asset_at_alice.clone(),
                orchard_asset_at_reserve.clone(),
            ],
            &[Some(Quantity::from(83_u32)), Some(Quantity::from(17_u32))],
            "canonical Orchard deposit must apply atomically",
        )
        .await?;
        let pq_replay_error = submit_signed_transaction(
            &client,
            &pq_actions.replay_transaction,
            "independently proved stable-nullifier replay must reject",
        )
        .await
        .expect_err("independently proved PQ-MASP nullifier replay was accepted");
        ensure!(
            error_chain_contains(
                &pq_replay_error,
                "proof-managed nullifier was already consumed"
            ),
            "PQ-MASP nullifier replay rejected for wrong reason: {pq_replay_error:?}"
        );
        wait_for_transaction_result_on_peers(
            &healthy_clients,
            &pq_actions.replay_transaction,
            false,
            "stable-nullifier replay rejection convergence",
        )
        .await?;
        wait_for_asset_quantities(
            &healthy_clients,
            &[
                orchard_asset_at_alice.clone(),
                orchard_asset_at_reserve.clone(),
            ],
            &[Some(Quantity::from(83_u32)), Some(Quantity::from(17_u32))],
            "nullifier replay must preserve post-Orchard state",
        )
        .await?;
        let finalized_height = read_privacy_capabilities(&client).await
            .wrap_err("query height before exact retained-native replays")?
            .committed_height;
        for (label, transaction) in [
            ("Orchard", &final_orchard.transaction),
            ("PQ-MASP", &pq_actions.canonical_transaction),
        ] {
            let replay_error = timeout(
                SUBMISSION_TIMEOUT,
                client.account_client().submit_transaction(transaction),
            )
            .await
            .map_err(|_| eyre!("exact {label} replay submission exceeded {SUBMISSION_TIMEOUT:?}"))?
            .expect_err("exact retained-native transaction replay was accepted");
            ensure!(
                is_exact_transaction_replay(&replay_error),
                "exact {label} replay rejected for wrong reason: {replay_error:?}"
            );
            let observed_height = read_privacy_capabilities(&client).await
                .wrap_err_with(|| format!("query height after exact {label} replay"))?
                .committed_height;
            ensure!(
                observed_height == finalized_height,
                "exact {label} replay committed height {observed_height}, expected unchanged \
                 height {finalized_height}"
            );
        }
        wait_for_common_commit_subject(
            &healthy_clients,
            finalized_height,
            "healthy-peer retained-native DA/RBC subject",
        )
        .await?;
        timeout(
            RESTART_TIMEOUT,
            restart_peer.start_checked(config_layers.iter(), None),
        )
        .await
        .map_err(|_| eyre!("retained-native peer restart exceeded {RESTART_TIMEOUT:?}"))?
        .wrap_err("restart retained-native peer")?;
        wait_for_all_peer_protocols(
            &network,
            finalized_height,
            &active_expectations,
            "post-restart active retained-native lifecycles",
        )
        .await?;
        let recovered_clients = network
            .peers()
            .iter()
            .map(|peer| bounded_client(peer.client()))
            .collect::<Vec<_>>();
        let restarted_client = bounded_client(restart_peer.client());
        let post_restart_replay_error = submit_signed_transaction(
            &restarted_client,
            &pq_actions.post_restart_replay_transaction,
            "fresh stable-nullifier replay through restarted peer must reject",
        )
        .await
        .expect_err("fresh post-restart PQ-MASP nullifier replay was accepted");
        ensure!(
            error_chain_contains(
                &post_restart_replay_error,
                "proof-managed nullifier was already consumed"
            ),
            "post-restart PQ-MASP replay rejected for wrong reason: \
             {post_restart_replay_error:?}"
        );
        wait_for_transaction_result_on_peers(
            &recovered_clients,
            &pq_actions.post_restart_replay_transaction,
            false,
            "fresh post-restart PQ-MASP replay convergence",
        )
        .await?;
        let post_restart_replay_height = read_privacy_capabilities(&restarted_client).await
            .wrap_err("query height after fresh post-restart PQ-MASP replay")?
            .committed_height;
        ensure!(
            post_restart_replay_height > finalized_height,
            "fresh post-restart PQ-MASP replay was not finalized: height remained \
             {post_restart_replay_height}"
        );
        for (transaction, expected_success, label) in [
            (&final_orchard.transaction, true, "canonical Orchard"),
            (&pq_actions.canonical_transaction, true, "canonical PQ-MASP"),
            (
                &pq_actions.replay_transaction,
                false,
                "PQ-MASP nullifier replay",
            ),
            (&corrupted_orchard, false, "corrupted Orchard"),
            (&corrupted_pq, false, "corrupted PQ-MASP"),
        ] {
            wait_for_transaction_result_on_peers(
                &recovered_clients,
                transaction,
                expected_success,
                &format!("post-restart {label} visibility"),
            )
            .await?;
        }
        wait_for_asset_quantities(
            &recovered_clients,
            &[orchard_asset_at_alice, orchard_asset_at_reserve],
            &[Some(Quantity::from(83_u32)), Some(Quantity::from(17_u32))],
            "post-restart authoritative Orchard state",
        )
        .await?;
        wait_for_common_commit_subject(
            &recovered_clients,
            post_restart_replay_height,
            "post-restart retained-native DA/RBC subject",
        )
        .await?;
        ensure!(
            canonical_genesis_hash(&bounded_client(restart_peer.client())).await? == genesis_hash,
            "restarted peer derived a different canonical genesis hash"
        );
        println!(
            "TAIRA_PRIVACY_PROTOCOL_FOUR_PEER_CASE_V1:privacy_exact12_orchard_pq_masp_network::canonical_orchard_and_pq_masp_actions_survive_four_peer_da_replay_and_restart:passed"
        );
        Ok(())
    }
    .await;
    network.shutdown().await;
    result
}
