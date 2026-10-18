//! Four-validator activation, adversarial intent/governance, replay, and
//! restart coverage for the canonical native ZK-AMS and Vega action APIs.
//!
//! This release gate intentionally leaves the network's DA/RBC configuration untouched. A validator
//! is stopped only after all negative probes converge, then both protocol lineages are finalized by
//! the remaining quorum and recovered byte-for-byte by the restarted validator. The ZK-AMS lineage
//! includes the two canonical eight-member admissions required for a minimum ring, successor-root
//! account provisioning, and persisted key-image replay.
use eyre::{Result, WrapErr as _, ensure, eyre};
use futures_util::TryStreamExt as _;
use integration_tests::{sandbox, sync::rebind_blocking_client};
use iroha::blocking::Client;
use iroha_core_privacy::{
    privacy_engines::{
        p256::TranscriptBindingV1,
        vega::{
            VegaPrivacyActionPublicInputV1, VegaPrivacyActionTransactionContextV1,
            VegaPrivacyActionWitnessMaterialV1, build_signed_vega_privacy_action_with_rng_v1,
        },
        zk_ams::{
            ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1, ZkAmsBatchCredentialWitnessV1,
            ZkAmsMaskedProverConfigV1, ZkAmsPrivacyActionGovernanceV1,
            ZkAmsPrivacyActionTransactionContextV1, ZkAmsSeedSecretV1,
            prepare_zk_ams_batch_admission_transaction_intent_v1,
            prepare_zk_ams_provision_account_transaction_intent_v1,
            prove_zk_ams_batch_admission_v1, sign_zk_ams_provision_statement_v1,
            validate_zk_ams_privacy_action_transaction_intent_v1, verify_zk_ams_batch_admission_v1,
            verify_zk_ams_provision_statement_v1, zk_ams_generator_digest_v1, zk_ams_key_image_v1,
            zk_ams_registry_transition_root_v1, zk_ams_seed_public_key_v1,
        },
    },
    privacy_profiles::{CompiledPrivacyProfileV1, compiled_privacy_profile_v1},
};
use iroha_data_model::{
    isi::{
        Grant, InstructionBox,
        privacy::{
            BootstrapPrivacyZkAmsRegistryV1, RegisterPrivacyProtocolActivationV1,
            RegisterPrivacyVegaIssuerV1, SubmitPrivacyProofV1,
            TransitionPrivacyProtocolLifecycleV1,
        },
    },
    permission::Permission,
    prelude::{AccountId, QueryBuilderExt},
    privacy::{
        IrohaZkAmsProofV1, IrohaZkAmsStatementV1, PrivacyActiveLifecycleV1, PrivacyChallengeV1,
        PrivacyCompiledProfileResultV1, PrivacyCompiledProfileSnapshotV1,
        PrivacyCredentialDocumentTypeV1, PrivacyExact12CapabilityManifestV1,
        PrivacyExact12CapabilityRowV1, PrivacyIssuerIdV1, PrivacyP256PointV1,
        PrivacyParameterDigestV1, PrivacyPolicyDigestV1, PrivacyPolicyIdV1, PrivacyProofBytesV1,
        PrivacyProofEnvelopeV1, PrivacyProofV1, PrivacyProposedLifecycleV1,
        PrivacyProtocolActivationRecordV1, PrivacyProtocolIdV1, PrivacyProtocolLifecycleV1,
        PrivacyRootV1, PrivacySessionTranscriptDigestV1, PrivacyStatementDigestV1,
        PrivacyStatementV1, PrivacyTransactionIntentDigestV1, PrivacyVegaIssuerRecordDigestV1,
        PrivacyVegaIssuerRecordLifecycleV1, PrivacyVegaIssuerRecordV1, PrivacyVegaMdlDateV1,
        PrivacyVegaMdlDigestAlgorithmV1, PrivacyVegaMdlNamespaceV1,
        PrivacyVegaMdlSignatureAlgorithmV1, PrivacyZkAmsAdmissionAnchorV1,
        PrivacyZkAmsBatchAdmissionV1, PrivacyZkAmsCredentialNonceV1, PrivacyZkAmsKeyImageV1,
        PrivacyZkAmsPersonhoodCredentialV1, PrivacyZkAmsProvisionAccountV1,
        PrivacyZkAmsRegistryBootstrapV1, PrivacyZkAmsRegistryRecordDigestV1,
        PrivacyZkAmsSeedPublicKeyV1, PrivacyZkAmsSubjectCommitmentV1,
        VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1,
        VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1, VEGA_MDL_MSO_PAYLOAD_BYTES_V1,
        ZK_AMS_PHC_VERSION_V1, ZK_AMS_REGISTRY_BOOTSTRAP_INITIAL_EPOCH_V1,
        zk_ams_registry_record_digest_v1,
    },
    query::account::prelude::FindAccounts,
    transaction::{
        Executable, FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionEntrypoint,
        TransactionPayload,
    },
};
use iroha_executor_data_model::permission::governance::CanEnactGovernance;
use iroha_model_base::metadata::Metadata;
use iroha_test_network::{NetworkBuilder, init_instruction_registry, read_on_dedicated_thread};
use iroha_test_samples::gen_account_in;
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, signature::hazmat::PrehashSigner as _,
};
use rand_core_06::{CryptoRng, Error as RngError, RngCore};
use sha2::{Digest, Sha256};
use std::{
    num::{NonZeroU32, NonZeroU64},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, sleep, timeout};
const ZK_AMS_PROTOCOL: PrivacyProtocolIdV1 = PrivacyProtocolIdV1::IrohaZkAmsV1;
const VEGA_PROTOCOL: PrivacyProtocolIdV1 = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
const TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES: i64 = 1024 * 1024 * 1024;
const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(120);
const PEER_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(90);
const RESTART_TIMEOUT: Duration = Duration::from_secs(90);
// This release-evidence fixture exercises instrumented four-validator body
// reconstruction, validation, replay, and restart rather than throughput. Use
// the released one-second signed cadence so the deterministic Sumeragi view
// backoff can cover that work without changing the production timer policy.
const TEST_BLOCK_CADENCE: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
// Each isolated ordinary submission executes in the next native certified global carrier.
const EXECUTION_CARRIER_BLOCKS: u64 = 1;
const CANONICAL_GENESIS_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const ACTION_TTL: Duration = Duration::from_secs(7_200);
struct DeterministicCryptoRng {
    seed: [u8; 32],
    counter: u64,
    buffered: [u8; 32],
    offset: usize,
}
impl DeterministicCryptoRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buffered: [0; 32],
            offset: 32,
        }
    }
    fn refill(&mut self) {
        let mut hash = Sha256::new();
        hash.update(b"iroha.integration.privacy.zk-ams-vega.rng.v1");
        hash.update(self.seed);
        hash.update(self.counter.to_be_bytes());
        self.buffered = hash.finalize().into();
        self.counter = self
            .counter
            .checked_add(1)
            .expect("test RNG counter cannot exhaust");
        self.offset = 0;
    }
}
impl RngCore for DeterministicCryptoRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, destination: &mut [u8]) {
        let mut written = 0;
        while written < destination.len() {
            if self.offset == self.buffered.len() {
                self.refill();
            }
            let available = self.buffered.len() - self.offset;
            let take = available.min(destination.len() - written);
            destination[written..written + take]
                .copy_from_slice(&self.buffered[self.offset..self.offset + take]);
            self.offset += take;
            written += take;
        }
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(destination);
        Ok(())
    }
}
impl CryptoRng for DeterministicCryptoRng {}
#[derive(Clone)]
struct ZkAmsCredentialFixture {
    credential: PrivacyZkAmsPersonhoodCredentialV1,
    issuer_signature: [u8; 64],
    seed_secret_bytes: [u8; 32],
}
#[derive(Clone)]
struct ZkAmsFixture {
    bootstrap: PrivacyZkAmsRegistryBootstrapV1,
    credentials: Vec<ZkAmsCredentialFixture>,
}
#[derive(Clone, Copy)]
struct ZkAmsRegistryStateV1 {
    root: PrivacyRootV1,
    epoch: u64,
    record_digest: PrivacyZkAmsRegistryRecordDigestV1,
}
struct ZkAmsBatchActionV1 {
    transaction: SignedTransaction,
    next_state: ZkAmsRegistryStateV1,
}
struct ZkAmsProvisionActionV1 {
    transaction: SignedTransaction,
    account_id: AccountId,
    key_image: PrivacyZkAmsKeyImageV1,
}
struct VegaFixture {
    issuer_record: PrivacyVegaIssuerRecordV1,
    public_input: VegaPrivacyActionPublicInputV1,
    witness_material: VegaPrivacyActionWitnessMaterialV1,
    device_signing_key: P256SigningKey,
}
fn bounded_client(client: Client) -> Client {
    rebind_blocking_client(&client, |client| {
        client.transaction_status_timeout = SUBMISSION_TIMEOUT;
        client.torii_request_timeout = Duration::from_secs(30);
    })
}
async fn privacy_capabilities(client: &Client) -> Result<PrivacyExact12CapabilityManifestV1> {
    let client = client.clone();
    read_on_dedicated_thread(move || client.client().get_privacy_capabilities()).await
}
fn no_fee() -> FeePaymentIntent {
    FeePaymentIntent::authority(Vec::new(), None)
}
fn now_duration() -> Result<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock is before the Unix epoch")
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
fn is_exact_replay_error(error: &eyre::Report) -> bool {
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
fn assert_exact_protocol_row(
    snapshot: &PrivacyExact12CapabilityManifestV1,
    protocol: PrivacyProtocolIdV1,
    compiled: PrivacyCompiledProfileSnapshotV1,
    activation: Option<PrivacyProtocolActivationRecordV1>,
    context: &str,
) -> Result<()> {
    snapshot
        .validate()
        .wrap_err_with(|| format!("{context}: invalid capability snapshot"))?;
    let row = protocol_row(snapshot, protocol)?;
    ensure!(
        row.compiled_profile == PrivacyCompiledProfileResultV1::Available(compiled),
        "{context}: {protocol:?} compiled binding drifted: {:?}",
        row.compiled_profile
    );
    ensure!(
        row.activation == activation,
        "{context}: {protocol:?} activation mismatch: expected {activation:?}, got {:?}",
        row.activation
    );
    Ok(())
}
async fn canonical_genesis_hash(client: &Client) -> Result<[u8; 32]> {
    let genesis = timeout(CANONICAL_GENESIS_FETCH_TIMEOUT, async {
        let mut blocks = client
            .account_client()
            .blocks()
            .subscribe(NonZeroU64::MIN)
            .await
            .wrap_err("subscribe to canonical block replay from genesis")?;
        blocks
            .try_next()
            .await
            .wrap_err("read canonical genesis block replay")?
            .ok_or_else(|| eyre!("canonical block replay ended before genesis"))
    })
    .await
    .map_err(|_| {
        eyre!("canonical genesis block replay exceeded {CANONICAL_GENESIS_FETCH_TIMEOUT:?}")
    })??;
    ensure!(
        genesis.header().height().get() == 1 && genesis.header().prev_block_hash().is_none(),
        "canonical block replay returned a non-genesis block at height {}",
        genesis.header().height()
    );
    let hash = *genesis.header().hash().as_ref();
    ensure!(hash != [0; 32], "canonical genesis hash must be non-zero");
    Ok(hash)
}
async fn next_execution_height(client: &Client) -> Result<u64> {
    privacy_capabilities(&client)
        .await
        .wrap_err("query committed height before native transaction governed transaction")?
        .committed_height
        .checked_add(EXECUTION_CARRIER_BLOCKS)
        .ok_or_else(|| eyre!("native transaction privacy-governance execution height overflowed"))
}
fn proposed_activation(
    compiled: CompiledPrivacyProfileV1,
    proposed_at_height: u64,
) -> PrivacyProtocolActivationRecordV1 {
    compiled.activation_record(PrivacyProtocolLifecycleV1::Proposed(
        PrivacyProposedLifecycleV1 { proposed_at_height },
    ))
}
async fn submit_instruction(
    client: &Client,
    instruction: impl Into<InstructionBox>,
    context: &str,
) -> Result<iroha_crypto::HashOf<SignedTransaction>> {
    let client = client.clone();
    let instruction = instruction.into();
    timeout(
        SUBMISSION_TIMEOUT,
        read_on_dedicated_thread(move || client.submit(instruction, no_fee())),
    )
    .await
    .map_err(|_| eyre!("{context}: instruction submission exceeded {SUBMISSION_TIMEOUT:?}"))?
    .wrap_err_with(|| context.to_owned())
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
    .map_err(|_| eyre!("{context}: instruction submission exceeded {SUBMISSION_TIMEOUT:?}"))?
    .wrap_err_with(|| context.to_owned())
}
async fn submit_signed_transaction(
    client: &Client,
    transaction: &SignedTransaction,
    context: &str,
) -> Result<iroha_crypto::HashOf<SignedTransaction>> {
    let client = client.clone();
    let transaction = transaction.clone();
    timeout(
        SUBMISSION_TIMEOUT,
        client
            .account_client()
            .submit_transaction_and_wait(&transaction),
    )
    .await
    .map_err(|_| eyre!("{context}: signed transaction exceeded {SUBMISSION_TIMEOUT:?}"))?
    .wrap_err_with(|| context.to_owned())
}
async fn wait_for_all_peer_activations(
    network: &sandbox::SerializedNetwork,
    minimum_height: u64,
    rows: &[(
        PrivacyProtocolIdV1,
        PrivacyCompiledProfileSnapshotV1,
        Option<PrivacyProtocolActivationRecordV1>,
    )],
    context: &str,
) -> Result<Vec<PrivacyExact12CapabilityManifestV1>> {
    let deadline = Instant::now() + PEER_CONVERGENCE_TIMEOUT;
    let mut last_observed = Vec::new();
    loop {
        let mut snapshots = Vec::with_capacity(network.peers().len());
        last_observed.clear();
        for (index, peer) in network.peers().iter().enumerate() {
            let client = bounded_client(peer.client());
            match privacy_capabilities(&client).await {
                Ok(snapshot) => {
                    if snapshot.committed_height < minimum_height {
                        last_observed.push(format!(
                            "peer {index}: height={} below {minimum_height}",
                            snapshot.committed_height
                        ));
                        continue;
                    }
                    let exact = rows
                        .iter()
                        .try_for_each(|(protocol, compiled, activation)| {
                            assert_exact_protocol_row(
                                &snapshot,
                                *protocol,
                                *compiled,
                                *activation,
                                context,
                            )
                        });
                    match exact {
                        Ok(()) => {
                            last_observed.push(format!(
                                "peer {index}: exact rows at height {}",
                                snapshot.committed_height
                            ));
                            snapshots.push(snapshot);
                        }
                        Err(error) => last_observed.push(format!(
                            "peer {index}: height={}, exact-row mismatch: {error}",
                            snapshot.committed_height
                        )),
                    }
                }
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
async fn exact_applied_transaction_visible(
    client: &Client,
    transaction: &SignedTransaction,
) -> Result<bool> {
    let client = client.clone();
    let transaction = transaction.clone();
    read_on_dedicated_thread(move || {
        let signed_hash = transaction.hash();
        let Some(status) = client
            .client()
            .get_transaction_status_response_local(signed_hash)
            .wrap_err("query exact peer-local transaction status")?
        else {
            return Ok(false);
        };
        match (status.status.kind.as_str(), status.resolved_from.as_str()) {
            ("Applied", "state") => {}
            ("Rejected" | "Expired", "state") => {
                return Err(eyre!(
                    "canonical privacy transaction reached terminal {} status",
                    status.status.kind
                ));
            }
            _ => return Ok(false),
        }
        let expected_hash = transaction.hash_as_entrypoint();
        let expected_entrypoint = TransactionEntrypoint::External(transaction.clone());
        let details = client
            .client()
            .get_successful_transaction_details(expected_hash)
            .wrap_err("query exact successful transaction details")?;
        let committed = &details.transaction;
        ensure!(
            committed.entrypoint() == &expected_entrypoint,
            "entrypoint hash matched different transaction bytes"
        );
        ensure!(
            committed.result().0.is_ok(),
            "canonical privacy transaction is visible but finalized as rejected"
        );
        Ok(true)
    })
    .await
}
async fn wait_for_transactions_on_peers(
    clients: &[Client],
    transactions: &[(&str, &SignedTransaction)],
    context: &str,
) -> Result<()> {
    let deadline = Instant::now() + PEER_CONVERGENCE_TIMEOUT;
    let mut last_observed = Vec::new();
    loop {
        let mut visible = 0_usize;
        last_observed.clear();
        for (peer_index, client) in clients.iter().enumerate() {
            for (label, transaction) in transactions {
                match exact_applied_transaction_visible(client, transaction).await {
                    Ok(true) => {
                        visible += 1;
                        last_observed.push(format!(
                            "peer {peer_index}: exact applied {label} transaction visible"
                        ));
                    }
                    Ok(false) => {
                        last_observed.push(format!("peer {peer_index}: {label} transaction absent"))
                    }
                    Err(error) => {
                        last_observed.push(format!("peer {peer_index}: {label}: {error}"))
                    }
                }
            }
        }
        if visible == clients.len() * transactions.len() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{context}: finalized transactions did not converge within \
                 {PEER_CONVERGENCE_TIMEOUT:?}; {}",
                last_observed.join("; ")
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}
async fn assert_zk_ams_account_state(
    client: &Client,
    provisioned_account: &AccountId,
    rejected_accounts: &[&AccountId],
    context: &str,
) -> Result<()> {
    let read_client = client.clone();
    let accounts = read_on_dedicated_thread(move || {
        Ok(read_client.client().query(FindAccounts).execute_all()?)
    })
    .await
    .wrap_err_with(|| format!("{context}: query accounts"))?;
    let provisioned = accounts
        .iter()
        .filter(|account| &account.id == provisioned_account)
        .collect::<Vec<_>>();
    ensure!(
        provisioned.len() == 1,
        "{context}: expected exactly one provisioned ZK-AMS account, found {}",
        provisioned.len()
    );
    let provisioned = provisioned[0];
    ensure!(
        provisioned.metadata == Metadata::default()
            && provisioned.label.is_none()
            && provisioned.uaid.is_none()
            && provisioned.opaque_ids.is_empty(),
        "{context}: provisioned ZK-AMS account carries unexpected mutable state"
    );
    for rejected_account in rejected_accounts {
        ensure!(
            accounts
                .iter()
                .all(|account| &account.id != *rejected_account),
            "{context}: key-image replay unexpectedly created account {rejected_account}"
        );
    }
    Ok(())
}
async fn wait_for_zk_ams_account_state_on_peers(
    clients: &[Client],
    provisioned_account: &AccountId,
    rejected_accounts: &[&AccountId],
    context: &str,
) -> Result<()> {
    let deadline = Instant::now() + PEER_CONVERGENCE_TIMEOUT;
    let mut last_observed = Vec::new();
    loop {
        last_observed.clear();
        let mut exact = 0_usize;
        for (peer_index, client) in clients.iter().enumerate() {
            match assert_zk_ams_account_state(
                client,
                provisioned_account,
                rejected_accounts,
                context,
            )
            .await
            {
                Ok(()) => {
                    exact += 1;
                    last_observed.push(format!("peer {peer_index}: exact ZK-AMS account state"));
                }
                Err(error) => last_observed.push(format!("peer {peer_index}: {error}")),
            }
        }
        if exact == clients.len() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{context}: ZK-AMS account state did not converge within \
                 {PEER_CONVERGENCE_TIMEOUT:?}; {}",
                last_observed.join("; ")
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}
fn p256_public_key(signing_key: &P256SigningKey) -> Result<PrivacyP256PointV1> {
    let encoded = signing_key.verifying_key().to_encoded_point(true);
    let bytes: [u8; 33] = encoded
        .as_bytes()
        .try_into()
        .map_err(|_| eyre!("compressed P-256 point did not contain 33 bytes"))?;
    Ok(PrivacyP256PointV1::new(bytes))
}
fn zk_ams_seed_secret(seed: u64) -> Result<ZkAmsSeedSecretV1> {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    ZkAmsSeedSecretV1::from_bytes(bytes)
        .map_err(|error| eyre!("construct canonical ZK-AMS seed secret: {error}"))
}
fn zk_ams_fixture() -> Result<ZkAmsFixture> {
    let issuer_signing_key = P256SigningKey::from_bytes((&[7_u8; 32]).into())
        .map_err(|_| eyre!("construct fixed ZK-AMS issuer key"))?;
    let issuer_id = PrivacyIssuerIdV1::new([0x31; 32]);
    let registry_id = iroha_data_model::privacy::PrivacyZkAmsRegistryIdV1::new([0x33; 32]);
    let policy_id = PrivacyPolicyIdV1::new([0x35; 32]);
    let bootstrap = PrivacyZkAmsRegistryBootstrapV1 {
        issuer_id,
        registry_id,
        policy_id,
        issuer_public_key: p256_public_key(&issuer_signing_key)?,
        policy_digest: PrivacyPolicyDigestV1::new([0x36; 32]),
        initial_registry_root: PrivacyRootV1::new([0x37; 32]),
        initial_registry_epoch: ZK_AMS_REGISTRY_BOOTSTRAP_INITIAL_EPOCH_V1,
    };
    bootstrap
        .validate()
        .map_err(|error| eyre!("validate ZK-AMS bootstrap fixture: {error}"))?;
    let mut seed_material = (0..16_usize)
        .map(|index| {
            let seed = 41_u64
                .checked_add(u64::try_from(index).expect("sixteen fixture indices fit u64"))
                .ok_or_else(|| eyre!("ZK-AMS fixture seed overflowed"))?;
            let mut seed_secret_bytes = [0_u8; 32];
            seed_secret_bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let seed_secret = zk_ams_seed_secret(seed)?;
            Ok((zk_ams_seed_public_key_v1(&seed_secret), seed_secret_bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    seed_material.sort_by_key(|(public_key, _)| *public_key);
    ensure!(
        seed_material.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "ZK-AMS fixture ring must be strictly increasing"
    );
    let credentials = seed_material
        .into_iter()
        .enumerate()
        .map(|(index, (seed_public_key, seed_secret_bytes))| {
            let index = u8::try_from(index).expect("sixteen fixture indices fit u8");
            let credential = PrivacyZkAmsPersonhoodCredentialV1 {
                version: ZK_AMS_PHC_VERSION_V1,
                issuer_id,
                policy_id,
                subject_commitment: PrivacyZkAmsSubjectCommitmentV1::new(
                    [0x41_u8
                        .checked_add(index)
                        .expect("sixteen subject fixtures fit u8"); 32],
                ),
                seed_public_key: PrivacyZkAmsSeedPublicKeyV1::new(seed_public_key),
                credential_nonce: PrivacyZkAmsCredentialNonceV1::new(
                    [0x51_u8
                        .checked_add(index)
                        .expect("sixteen nonce fixtures fit u8"); 32],
                ),
            };
            let signature: P256Signature = issuer_signing_key
                .sign_prehash(credential.digest().as_bytes())
                .map_err(|_| eyre!("sign fixed ZK-AMS credential"))?;
            let signature = signature.normalize_s().unwrap_or(signature);
            Ok(ZkAmsCredentialFixture {
                credential,
                issuer_signature: signature.to_bytes().into(),
                seed_secret_bytes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        credentials.len() == 16,
        "ZK-AMS minimum-ring fixture must contain sixteen credentials"
    );
    Ok(ZkAmsFixture {
        bootstrap,
        credentials,
    })
}
fn zk_ams_initial_registry_state(fixture: &ZkAmsFixture) -> ZkAmsRegistryStateV1 {
    ZkAmsRegistryStateV1 {
        root: fixture.bootstrap.initial_registry_root,
        epoch: fixture.bootstrap.initial_registry_epoch,
        record_digest: fixture.bootstrap.registry_record_digest(),
    }
}
fn zk_ams_transaction_context(
    client: &Client,
    creation_time: Duration,
    nonce: u32,
) -> ZkAmsPrivacyActionTransactionContextV1 {
    ZkAmsPrivacyActionTransactionContextV1 {
        network_id: *client.client().network_id(),
        authority: client.client().account().clone(),
        creation_time,
        time_to_live: Some(ACTION_TTL),
        nonce: NonZeroU32::new(nonce),
        fee_payment: no_fee(),
        metadata: Metadata::default(),
    }
}
fn build_transaction_from_envelope(
    context: &ZkAmsPrivacyActionTransactionContextV1,
    envelope: PrivacyProofEnvelopeV1,
    client: &Client,
) -> Result<SignedTransaction> {
    let mut builder = TransactionBuilder::new(
        context.network_id,
        context.authority.clone(),
        context.fee_payment.clone(),
    )
    .with_instructions([SubmitPrivacyProofV1::new(envelope)])
    .with_metadata(context.metadata.clone());
    builder.set_creation_time(context.creation_time);
    if let Some(ttl) = context.time_to_live {
        builder.set_ttl(ttl);
    }
    if let Some(nonce) = context.nonce {
        builder.set_nonce(nonce);
    }
    let payload = builder
        .into_payload()
        .wrap_err("construct final ZK-AMS transaction payload")?;
    payload
        .validate_privacy_transaction_intent_binding_v1()
        .wrap_err("validate final ZK-AMS transaction intent")?;
    let signed = TransactionBuilder::from_payload(payload)
        .wrap_err("re-open final ZK-AMS payload for signing")?
        .try_sign(client.client().key_pair().private_key())
        .wrap_err("sign final ZK-AMS transaction")?;
    signed
        .verify_signature()
        .wrap_err("verify final ZK-AMS transaction signature")?;
    Ok(signed)
}
fn zk_ams_binding_v1<'a>(
    statement: &'a IrohaZkAmsStatementV1,
    canonical_genesis_hash: [u8; 32],
) -> Result<TranscriptBindingV1<'a>> {
    let statement_digest = PrivacyStatementV1::IrohaZkAmsV1(statement.clone())
        .digest()
        .wrap_err("derive canonical ZK-AMS statement digest")?;
    Ok(TranscriptBindingV1 {
        network_id: statement.context.network_id.as_bytes(),
        genesis_hash: canonical_genesis_hash,
        action_index: statement.context.action_index,
        statement_digest: *statement_digest.as_bytes(),
        parameter_id: *statement.context.parameter_id.as_bytes(),
        parameter_digest: *statement.context.parameter_digest.as_bytes(),
        verifier_digest: *statement.context.verifier_digest.as_bytes(),
        statement_schema_digest: *statement.context.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *statement.context.engine_manifest_digest.as_bytes(),
        generator_digest: zk_ams_generator_digest_v1(),
    })
}
fn build_zk_ams_batch_action(
    client: &Client,
    fixture: &ZkAmsFixture,
    credentials: &[ZkAmsCredentialFixture],
    current_state: ZkAmsRegistryStateV1,
    canonical_genesis_hash: [u8; 32],
    nonce: u32,
    proof_seed: [u8; 32],
) -> Result<ZkAmsBatchActionV1> {
    ensure!(
        !credentials.is_empty() && credentials.len() <= ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1,
        "ZK-AMS admission fixture must contain between one and eight credentials"
    );
    let context = zk_ams_transaction_context(client, now_duration()?, nonce);
    let anchors = credentials
        .iter()
        .map(|fixture| PrivacyZkAmsAdmissionAnchorV1 {
            phc_hash: fixture.credential.digest(),
            seed_public_key: fixture.credential.seed_public_key,
        })
        .collect::<Vec<_>>();
    let next_epoch = current_state
        .epoch
        .checked_add(1)
        .ok_or_else(|| eyre!("ZK-AMS registry epoch overflowed"))?;
    let batch_size = u32::try_from(anchors.len())
        .map_err(|_| eyre!("ZK-AMS admission batch length exceeded u32"))?;
    let next_root = anchors.iter().copied().enumerate().fold(
        current_state.root,
        |prior_root, (index, anchor)| {
            zk_ams_registry_transition_root_v1(
                fixture.bootstrap.registry_id,
                prior_root,
                current_state.epoch,
                next_epoch,
                batch_size,
                u32::try_from(index).expect("ZK-AMS admission batch is bounded to eight"),
                anchor,
            )
        },
    );
    let action = PrivacyZkAmsBatchAdmissionV1 {
        account_registry_root: current_state.root,
        account_registry_root_epoch: current_state.epoch,
        next_account_registry_root: next_root,
        next_account_registry_root_epoch: next_epoch,
        anchors: anchors.clone(),
    };
    let governance = ZkAmsPrivacyActionGovernanceV1 {
        issuer_id: fixture.bootstrap.issuer_id,
        issuer_public_key: fixture.bootstrap.issuer_public_key,
        issuer_policy_record_digest: fixture.bootstrap.issuer_policy_record_digest(),
        registry_id: fixture.bootstrap.registry_id,
        registry_record_digest: current_state.record_digest,
        policy_id: fixture.bootstrap.policy_id,
        policy_digest: fixture.bootstrap.policy_digest,
    };
    let statement =
        prepare_zk_ams_batch_admission_transaction_intent_v1(&context, governance, action)
            .map_err(|error| eyre!("prepare canonical ZK-AMS action intent: {error}"))?;
    let intent = validate_zk_ams_privacy_action_transaction_intent_v1(&context, &statement)
        .map_err(|error| eyre!("revalidate canonical ZK-AMS action intent: {error}"))?;
    ensure!(
        intent == statement.context.transaction_intent_digest,
        "ZK-AMS prepared intent differs from the statement"
    );
    let typed_statement = PrivacyStatementV1::IrohaZkAmsV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .wrap_err("derive canonical ZK-AMS statement digest")?;
    let binding = zk_ams_binding_v1(&statement, canonical_genesis_hash)?;
    let seed_secrets = credentials
        .iter()
        .map(|fixture| {
            ZkAmsSeedSecretV1::from_bytes(fixture.seed_secret_bytes)
                .map_err(|error| eyre!("restore canonical ZK-AMS seed secret: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let witnesses = credentials
        .iter()
        .zip(&seed_secrets)
        .map(|(fixture, secret)| {
            ZkAmsBatchCredentialWitnessV1::new(
                &fixture.credential,
                &fixture.issuer_signature,
                secret,
            )
        })
        .collect::<Vec<_>>();
    let mut rng = DeterministicCryptoRng::new(proof_seed);
    let proof = prove_zk_ams_batch_admission_v1(
        &statement,
        &binding,
        &witnesses,
        ZkAmsMaskedProverConfigV1::new(1)
            .map_err(|error| eyre!("construct deterministic ZK-AMS prover config: {error}"))?,
        &mut rng,
    )
    .map_err(|error| eyre!("prove canonical ZK-AMS batch admission: {error}"))?;
    let effect = verify_zk_ams_batch_admission_v1(&statement, &binding, &proof)
        .map_err(|error| eyre!("verify locally produced ZK-AMS proof: {error}"))?;
    ensure!(
        effect.current_root == current_state.root
            && effect.current_epoch == current_state.epoch
            && effect.registry_record_digest == current_state.record_digest
            && effect.next_root == next_root
            && effect.next_epoch == next_epoch
            && effect.anchors == anchors,
        "locally verified ZK-AMS state effect drifted"
    );
    let profile = compiled_privacy_profile_v1(ZK_AMS_PROTOCOL)
        .wrap_err("load canonical compiled ZK-AMS profile for envelope")?;
    let envelope = PrivacyProofEnvelopeV1 {
        wire_magic: Default::default(),
        catalog_commitment: Default::default(),
        protocol_id: profile.protocol_id,
        proof_system_id: profile.proof_system_id,
        engine_id: profile.engine_id,
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
        statement_digest,
        statement: typed_statement,
        proof: PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(
            PrivacyProofBytesV1::new(proof),
        )),
    };
    let transaction = build_transaction_from_envelope(&context, envelope, client)?;
    let next_state = ZkAmsRegistryStateV1 {
        root: next_root,
        epoch: next_epoch,
        record_digest: zk_ams_registry_record_digest_v1(
            fixture.bootstrap.issuer_id,
            fixture.bootstrap.registry_id,
            fixture.bootstrap.policy_id,
            fixture.bootstrap.issuer_policy_record_digest(),
            fixture.bootstrap.policy_digest,
            next_root,
            next_epoch,
        ),
    };
    Ok(ZkAmsBatchActionV1 {
        transaction,
        next_state,
    })
}
fn build_zk_ams_provision_action(
    client: &Client,
    fixture: &ZkAmsFixture,
    current_state: ZkAmsRegistryStateV1,
    account_id: AccountId,
    canonical_genesis_hash: [u8; 32],
    nonce: u32,
    proof_seed: [u8; 32],
) -> Result<ZkAmsProvisionActionV1> {
    ensure!(
        fixture.credentials.len() == 16,
        "ZK-AMS provisioning fixture must use the canonical minimum ring"
    );
    let context = zk_ams_transaction_context(client, now_duration()?, nonce);
    let ring = fixture
        .credentials
        .iter()
        .map(|fixture| fixture.credential.seed_public_key)
        .collect::<Vec<_>>();
    ensure!(
        ring.windows(2).all(|pair| pair[0] < pair[1]),
        "ZK-AMS provisioning ring must be strictly increasing"
    );
    let signer_index = 5_usize;
    let signer_secret = ZkAmsSeedSecretV1::from_bytes(
        fixture
            .credentials
            .get(signer_index)
            .ok_or_else(|| eyre!("ZK-AMS provisioning signer is outside the ring"))?
            .seed_secret_bytes,
    )
    .map_err(|error| eyre!("restore ZK-AMS provisioning signer secret: {error}"))?;
    let key_image = PrivacyZkAmsKeyImageV1::new(
        zk_ams_key_image_v1(&signer_secret)
            .map_err(|error| eyre!("derive canonical ZK-AMS key image: {error}"))?,
    );
    let governance = ZkAmsPrivacyActionGovernanceV1 {
        issuer_id: fixture.bootstrap.issuer_id,
        issuer_public_key: fixture.bootstrap.issuer_public_key,
        issuer_policy_record_digest: fixture.bootstrap.issuer_policy_record_digest(),
        registry_id: fixture.bootstrap.registry_id,
        registry_record_digest: current_state.record_digest,
        policy_id: fixture.bootstrap.policy_id,
        policy_digest: fixture.bootstrap.policy_digest,
    };
    let action = PrivacyZkAmsProvisionAccountV1 {
        account_registry_root: current_state.root,
        account_registry_root_epoch: current_state.epoch,
        admitted_seed_key_ring: ring.clone(),
        account_id: account_id.clone(),
        key_image,
    };
    let statement =
        prepare_zk_ams_provision_account_transaction_intent_v1(&context, governance, action)
            .map_err(|error| eyre!("prepare canonical ZK-AMS provisioning intent: {error}"))?;
    let intent = validate_zk_ams_privacy_action_transaction_intent_v1(&context, &statement)
        .map_err(|error| eyre!("revalidate canonical ZK-AMS provisioning intent: {error}"))?;
    ensure!(
        intent == statement.context.transaction_intent_digest,
        "ZK-AMS provisioning intent differs from the statement"
    );
    let typed_statement = PrivacyStatementV1::IrohaZkAmsV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .wrap_err("derive canonical ZK-AMS provisioning statement digest")?;
    let binding = zk_ams_binding_v1(&statement, canonical_genesis_hash)?;
    let mut rng = DeterministicCryptoRng::new(proof_seed);
    let proof = sign_zk_ams_provision_statement_v1(
        &statement,
        &binding,
        signer_index,
        &signer_secret,
        &mut rng,
    )
    .map_err(|error| eyre!("prove canonical ZK-AMS account provisioning: {error}"))?;
    let effect = verify_zk_ams_provision_statement_v1(&statement, &binding, &proof)
        .map_err(|error| eyre!("verify locally produced ZK-AMS provisioning proof: {error}"))?;
    ensure!(
        effect.current_root == current_state.root
            && effect.current_epoch == current_state.epoch
            && effect.registry_record_digest == current_state.record_digest
            && effect.ring == ring
            && effect.account_id == account_id
            && effect.key_image == key_image,
        "locally verified ZK-AMS provisioning effect drifted"
    );
    let profile = compiled_privacy_profile_v1(ZK_AMS_PROTOCOL)
        .wrap_err("load canonical compiled ZK-AMS profile for provisioning envelope")?;
    let envelope = PrivacyProofEnvelopeV1 {
        wire_magic: Default::default(),
        catalog_commitment: Default::default(),
        protocol_id: profile.protocol_id,
        proof_system_id: profile.proof_system_id,
        engine_id: profile.engine_id,
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
        statement_digest,
        statement: typed_statement,
        proof: PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(
            PrivacyProofBytesV1::new(proof),
        )),
    };
    let transaction = build_transaction_from_envelope(&context, envelope, client)?;
    Ok(ZkAmsProvisionActionV1 {
        transaction,
        account_id,
        key_image,
    })
}
fn cbor_head(major: u8, argument: u64) -> Vec<u8> {
    let argument_bytes = argument.to_be_bytes();
    match argument {
        0..=23 => vec![
            (major << 5) | u8::try_from(argument).expect("CBOR immediate argument is at most 23"),
        ],
        24..=0xff => vec![
            (major << 5) | 24,
            u8::try_from(argument).expect("CBOR one-byte argument is at most 255"),
        ],
        0x100..=0xffff => vec![(major << 5) | 25, argument_bytes[6], argument_bytes[7]],
        0x1_0000..=0xffff_ffff => vec![
            (major << 5) | 26,
            argument_bytes[4],
            argument_bytes[5],
            argument_bytes[6],
            argument_bytes[7],
        ],
        _ => {
            let mut encoded = vec![(major << 5) | 27];
            encoded.extend_from_slice(&argument_bytes);
            encoded
        }
    }
}
fn cbor_unsigned(value: u64) -> Vec<u8> {
    cbor_head(0, value)
}
fn cbor_negative(value: i64) -> Vec<u8> {
    debug_assert!(value < 0);
    let argument = u64::try_from(-(i128::from(value)) - 1)
        .expect("negative i64 has a non-negative CBOR argument fitting u64");
    cbor_head(1, argument)
}
fn cbor_bytes(value: &[u8]) -> Vec<u8> {
    let mut encoded = cbor_head(
        2,
        u64::try_from(value.len()).expect("slice length fits CBOR u64"),
    );
    encoded.extend_from_slice(value);
    encoded
}
fn cbor_text(value: &str) -> Vec<u8> {
    let mut encoded = cbor_head(
        3,
        u64::try_from(value.len()).expect("string length fits CBOR u64"),
    );
    encoded.extend_from_slice(value.as_bytes());
    encoded
}
fn cbor_array(values: Vec<Vec<u8>>) -> Vec<u8> {
    let mut encoded = cbor_head(
        4,
        u64::try_from(values.len()).expect("array length fits CBOR u64"),
    );
    for value in values {
        encoded.extend_from_slice(&value);
    }
    encoded
}
fn cbor_map(mut entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    entries.sort_by(|left, right| {
        left.0
            .len()
            .cmp(&right.0.len())
            .then_with(|| left.0.cmp(&right.0))
    });
    let mut encoded = cbor_head(
        5,
        u64::try_from(entries.len()).expect("map length fits CBOR u64"),
    );
    for (key, value) in entries {
        encoded.extend_from_slice(&key);
        encoded.extend_from_slice(&value);
    }
    encoded
}
fn cbor_tag(tag: u64, value: Vec<u8>) -> Vec<u8> {
    let mut encoded = cbor_head(6, tag);
    encoded.extend_from_slice(&value);
    encoded
}
fn utc_date_from_timestamp_ms(timestamp_ms: u64) -> Result<PrivacyVegaMdlDateV1> {
    let days = i64::try_from(timestamp_ms / 86_400_000)
        .map_err(|_| eyre!("trusted timestamp day count exceeded i64"))?;
    let shifted = days
        .checked_add(719_468)
        .ok_or_else(|| eyre!("UTC civil-date conversion overflowed"))?;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Ok(PrivacyVegaMdlDateV1 {
        year: u16::try_from(year).map_err(|_| eyre!("UTC year is outside u16"))?,
        month: u8::try_from(month).map_err(|_| eyre!("UTC month is outside u8"))?,
        day: u8::try_from(day).map_err(|_| eyre!("UTC day is outside u8"))?,
    })
}
fn vega_fixture(trusted_timestamp_ms: u64, challenge_byte: u8) -> Result<VegaFixture> {
    let issuer_signing_key = P256SigningKey::from_bytes((&[1_u8; 32]).into())
        .map_err(|_| eyre!("construct fixed Vega issuer key"))?;
    let device_signing_key = P256SigningKey::from_bytes((&[2_u8; 32]).into())
        .map_err(|_| eyre!("construct fixed Vega device key"))?;
    let issuer_record = PrivacyVegaIssuerRecordV1::new(
        PrivacyIssuerIdV1::new([0x40; 32]),
        1,
        p256_public_key(&issuer_signing_key)?,
        PrivacyCredentialDocumentTypeV1::Iso18013_5Mdl,
        PrivacyVegaMdlNamespaceV1::OrgIso18013_5_1,
        PrivacyVegaMdlDigestAlgorithmV1::Sha256,
        PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
        PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
        None,
        PrivacyVegaIssuerRecordLifecycleV1::Active,
    )
    .map_err(|error| eyre!("construct canonical Vega issuer record: {error}"))?;
    let device_uncompressed = device_signing_key.verifying_key().to_encoded_point(false);
    let device_x = device_uncompressed
        .x()
        .ok_or_else(|| eyre!("uncompressed Vega device key omitted x"))?;
    let device_y = device_uncompressed
        .y()
        .ok_or_else(|| eyre!("uncompressed Vega device key omitted y"))?;
    let birth_inner = cbor_map(vec![
        (cbor_text("digestID"), cbor_unsigned(1)),
        (cbor_text("random"), cbor_bytes(&[0x42; 16])),
        (cbor_text("elementIdentifier"), cbor_text("birth_date")),
        (cbor_text("elementValue"), cbor_text("1980-06-15")),
    ]);
    let birth_item = cbor_tag(24, cbor_bytes(&birth_inner));
    let birth_digest: [u8; 32] = Sha256::digest(&birth_item).into();
    let device_key = cbor_map(vec![
        (cbor_unsigned(1), cbor_unsigned(2)),
        (cbor_negative(-1), cbor_unsigned(1)),
        (cbor_negative(-2), cbor_bytes(device_x)),
        (cbor_negative(-3), cbor_bytes(device_y)),
    ]);
    let validity_info = cbor_map(vec![
        (
            cbor_text("signed"),
            cbor_tag(0, cbor_text("2020-01-01T00:00:00Z")),
        ),
        (
            cbor_text("validFrom"),
            cbor_tag(0, cbor_text("2020-01-01T00:00:00Z")),
        ),
        (
            cbor_text("validUntil"),
            cbor_tag(0, cbor_text("2099-12-31T23:59:59Z")),
        ),
    ]);
    let value_digests = cbor_map(vec![(
        cbor_text("org.iso.18013.5.1"),
        cbor_map(vec![(cbor_unsigned(1), cbor_bytes(&birth_digest))]),
    )]);
    let mso_inner = cbor_map(vec![
        (cbor_text("version"), cbor_text("1.0")),
        (cbor_text("digestAlgorithm"), cbor_text("SHA-256")),
        (cbor_text("valueDigests"), value_digests),
        (
            cbor_text("deviceKeyInfo"),
            cbor_map(vec![(cbor_text("deviceKey"), device_key)]),
        ),
        (cbor_text("docType"), cbor_text("org.iso.18013.5.1.mDL")),
        (cbor_text("validityInfo"), validity_info),
    ]);
    let mso_payload = cbor_tag(24, cbor_bytes(&mso_inner));
    let signature_structure = cbor_array(vec![
        cbor_text("Signature1"),
        cbor_bytes(&[0xa1, 0x01, 0x26]),
        cbor_bytes(&[]),
        cbor_bytes(&mso_payload),
    ]);
    ensure!(
        signature_structure.len() == VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1,
        "Vega Sig_structure fixture length drifted: got {}, expected {}",
        signature_structure.len(),
        VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1
    );
    ensure!(
        mso_payload.len() == VEGA_MDL_MSO_PAYLOAD_BYTES_V1,
        "Vega MSO fixture length drifted: got {}, expected {}",
        mso_payload.len(),
        VEGA_MDL_MSO_PAYLOAD_BYTES_V1
    );
    ensure!(
        birth_item.len() == VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1,
        "Vega birth item fixture length drifted: got {}, expected {}",
        birth_item.len(),
        VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1
    );
    let issuer_digest: [u8; 32] = Sha256::digest(&signature_structure).into();
    let issuer_signature: P256Signature = issuer_signing_key
        .sign_prehash(&issuer_digest)
        .map_err(|_| eyre!("sign fixed Vega MSO"))?;
    let issuer_signature = issuer_signature.normalize_s().unwrap_or(issuer_signature);
    let witness_material = VegaPrivacyActionWitnessMaterialV1::new(
        signature_structure,
        mso_payload,
        birth_item,
        &issuer_signature.to_bytes(),
    )
    .map_err(|error| eyre!("construct canonical Vega witness material: {error}"))?;
    Ok(VegaFixture {
        issuer_record,
        public_input: VegaPrivacyActionPublicInputV1 {
            issuer_record,
            presentation_date: utc_date_from_timestamp_ms(trusted_timestamp_ms)?,
            minimum_age_years: 18,
            reader_challenge: PrivacyChallengeV1::new([challenge_byte; 32]),
            session_transcript_digest: PrivacySessionTranscriptDigestV1::new([0x32; 32]),
        },
        witness_material,
        device_signing_key,
    })
}
fn build_vega_action(
    client: &Client,
    canonical_genesis_hash: [u8; 32],
    nonce: u32,
    challenge_byte: u8,
    proof_seed: [u8; 32],
) -> Result<(PrivacyVegaIssuerRecordV1, SignedTransaction)> {
    let creation_time = now_duration()?;
    let trusted_timestamp_ms = u64::try_from(creation_time.as_millis())
        .map_err(|_| eyre!("Vega trusted timestamp exceeded u64"))?;
    let fixture = vega_fixture(trusted_timestamp_ms, challenge_byte)?;
    let context = VegaPrivacyActionTransactionContextV1 {
        network_id: *client.client().network_id(),
        authority: client.client().account().clone(),
        creation_time,
        time_to_live: Some(ACTION_TTL),
        nonce: NonZeroU32::new(nonce),
        fee_payment: no_fee(),
        metadata: Metadata::default(),
    };
    let mut rng = DeterministicCryptoRng::new(proof_seed);
    let signed = build_signed_vega_privacy_action_with_rng_v1(
        context,
        fixture.public_input,
        fixture.witness_material,
        &fixture.device_signing_key,
        canonical_genesis_hash,
        trusted_timestamp_ms,
        client.client().key_pair().private_key(),
        &mut rng,
    )
    .map_err(|error| eyre!("build canonical signed Vega action: {error}"))?;
    signed
        .signed_transaction()
        .verify_signature()
        .wrap_err("verify canonical Vega transaction signature")?;
    ensure!(
        signed.transaction_hash() == *signed.signed_transaction().hash().as_ref(),
        "Vega builder-reported hash differs from the canonical transaction hash"
    );
    Ok((fixture.issuer_record, signed.into_signed_transaction()))
}
fn independently_resigned_stale_intent(
    transaction: &SignedTransaction,
    nonce: u32,
    client: &Client,
) -> Result<SignedTransaction> {
    transaction
        .privacy_transaction_intent_binding_if_present_v1()
        .wrap_err("scan canonical transaction before stale-intent mutation")?
        .ok_or_else(|| eyre!("canonical privacy transaction omitted its direct submission"))?;
    let mut payload = transaction.payload().clone();
    payload.nonce =
        Some(NonZeroU32::new(nonce).ok_or_else(|| eyre!("stale-intent nonce must be non-zero"))?);
    let stale = TransactionBuilder::from_payload(payload)
        .wrap_err("re-open stale-intent payload")?
        .try_sign(client.client().key_pair().private_key())
        .wrap_err("independently sign stale-intent payload")?;
    stale
        .verify_signature()
        .wrap_err("verify independently signed stale-intent transaction")?;
    ensure!(
        stale
            .privacy_transaction_intent_binding_if_present_v1()
            .is_err(),
        "independent transaction signature unexpectedly redeemed a stale privacy intent"
    );
    Ok(stale)
}
#[derive(Clone, Copy)]
enum GovernanceTamper {
    ZkAmsRegistryRecord,
    VegaIssuerRecord,
}
fn direct_submission_executable(envelope: PrivacyProofEnvelopeV1) -> Executable {
    Executable::Instructions(vec![InstructionBox::from(SubmitPrivacyProofV1::new(envelope))].into())
}
fn independently_resigned_governance_tamper(
    transaction: &SignedTransaction,
    tamper: GovernanceTamper,
    client: &Client,
) -> Result<SignedTransaction> {
    let (_, submission) = transaction
        .privacy_transaction_intent_binding_if_present_v1()
        .wrap_err("scan canonical transaction before governance mutation")?
        .ok_or_else(|| eyre!("canonical privacy transaction omitted its direct submission"))?;
    let original_proof = submission.envelope.proof.clone();
    let mut envelope = submission.envelope.clone();
    match (tamper, &mut envelope.statement) {
        (GovernanceTamper::ZkAmsRegistryRecord, PrivacyStatementV1::IrohaZkAmsV1(statement)) => {
            let mut digest = *statement.registry_record_digest.as_bytes();
            digest[0] ^= 0x80;
            statement.registry_record_digest = PrivacyZkAmsRegistryRecordDigestV1::new(digest);
        }
        (
            GovernanceTamper::VegaIssuerRecord,
            PrivacyStatementV1::VegaExistingCredentialZkV1(statement),
        ) => {
            let mut digest = *statement.issuer_record_digest.as_bytes();
            digest[0] ^= 0x80;
            statement.issuer_record_digest = PrivacyVegaIssuerRecordDigestV1::new(digest);
        }
        _ => return Err(eyre!("governance tamper did not match statement protocol")),
    }
    envelope.statement.context_mut().transaction_intent_digest =
        PrivacyTransactionIntentDigestV1::new([0; 32]);
    envelope.statement_digest = PrivacyStatementDigestV1::new([0; 32]);
    let mut payload: TransactionPayload = transaction.payload().clone();
    payload.instructions = direct_submission_executable(envelope.clone());
    let intent = payload
        .privacy_transaction_intent_digest_v1()
        .wrap_err("derive intent for governance-tampered payload")?;
    envelope.statement.context_mut().transaction_intent_digest = intent;
    envelope.statement_digest = envelope
        .statement
        .digest()
        .wrap_err("derive governance-tampered statement digest")?;
    ensure!(
        envelope.proof == original_proof,
        "governance mutation unexpectedly changed native proof bytes"
    );
    payload.instructions = direct_submission_executable(envelope);
    let validated = payload
        .validate_privacy_transaction_intent_binding_v1()
        .wrap_err("self-consistent governance tamper failed transaction-intent validation")?;
    ensure!(
        validated == intent,
        "governance-tampered payload validated a different intent"
    );
    let tampered = TransactionBuilder::from_payload(payload)
        .wrap_err("re-open governance-tampered payload")?
        .try_sign(client.client().key_pair().private_key())
        .wrap_err("independently sign governance-tampered payload")?;
    tampered
        .verify_signature()
        .wrap_err("verify governance-tampered transaction signature")?;
    tampered
        .privacy_transaction_intent_binding_if_present_v1()
        .wrap_err("governance-tampered signed transaction lost its valid intent binding")?
        .ok_or_else(|| eyre!("governance-tampered transaction omitted direct submission"))?;
    Ok(tampered)
}
fn independently_resigned_vega_proof_corruption(
    transaction: &SignedTransaction,
    client: &Client,
) -> Result<SignedTransaction> {
    let (intent, submission) = transaction
        .privacy_transaction_intent_binding_if_present_v1()
        .wrap_err("scan canonical Vega transaction before proof corruption")?
        .ok_or_else(|| eyre!("canonical Vega transaction omitted its direct submission"))?;
    let mut envelope = submission.envelope.clone();
    let PrivacyProofV1::VegaExistingCredentialZkV1(proof) = &mut envelope.proof else {
        return Err(eyre!(
            "Vega proof corruption reached a different proof suite"
        ));
    };
    let mut corrupt = proof.as_bytes().to_vec();
    let interior_index = corrupt
        .len()
        .checked_div(2)
        .ok_or_else(|| eyre!("Vega proof length cannot select an interior byte"))?;
    let interior = corrupt
        .get_mut(interior_index)
        .ok_or_else(|| eyre!("canonical Vega proof unexpectedly has no interior byte"))?;
    *interior ^= 0x01;
    *proof = PrivacyProofBytesV1::new(corrupt);
    let mut payload: TransactionPayload = transaction.payload().clone();
    payload.instructions = direct_submission_executable(envelope);
    let observed_intent = payload
        .validate_privacy_transaction_intent_binding_v1()
        .wrap_err("proof-corrupted Vega payload lost its transaction-intent binding")?;
    ensure!(
        observed_intent == intent,
        "proof corruption changed the proof-independent Vega transaction intent"
    );
    let corrupt = TransactionBuilder::from_payload(payload)
        .wrap_err("re-open proof-corrupted Vega payload")?
        .try_sign(client.client().key_pair().private_key())
        .wrap_err("independently sign proof-corrupted Vega payload")?;
    corrupt
        .verify_signature()
        .wrap_err("verify proof-corrupted Vega transaction signature")?;
    Ok(corrupt)
}
async fn assert_rejected_with(
    client: &Client,
    transaction: &SignedTransaction,
    context: &str,
    expected_reasons: &[&str],
) -> Result<()> {
    let error = submit_signed_transaction(client, transaction, context)
        .await
        .expect_err(context);
    ensure!(
        error_chain_contains_any(&error, expected_reasons),
        "{context}: rejection had wrong reason: {error:?}"
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_zk_ams_and_vega_actions_survive_four_validator_activation_replay_and_restart()
-> Result<()> {
    init_instruction_registry();
    let context = stringify!(
        canonical_zk_ams_and_vega_actions_survive_four_validator_activation_replay_and_restart
    );
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_block_cadence(TEST_BLOCK_CADENCE)
        .with_permissioned_consensus()
        .with_config_layer(|layer| {
            // Keep the production handshake enabled while minimizing its supported
            // puzzle cost so this four-peer gate isolates consensus progress.
            layer
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                .write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                );
        });
    let Some(network) = sandbox::start_network_async_or_skip(builder, context).await? else {
        return Ok(());
    };
    let result: Result<()> = async {
        ensure!(
            network.peers().len() == 4,
            "ZK-AMS/Vega lifecycle test requires exactly four trusted validators"
        );
        let client = bounded_client(network.client());
        let genesis_hash = canonical_genesis_hash(&client).await?;
        let zk_compiled = compiled_privacy_profile_v1(ZK_AMS_PROTOCOL)
            .wrap_err("load canonical compiled ZK-AMS profile")?;
        let vega_compiled = compiled_privacy_profile_v1(VEGA_PROTOCOL)
            .wrap_err("load canonical compiled Vega profile")?;
        let zk_snapshot: PrivacyCompiledProfileSnapshotV1 = zk_compiled.into();
        let vega_snapshot: PrivacyCompiledProfileSnapshotV1 = vega_compiled.into();
        submit_instruction(
            &client,
            Grant::account_permission(
                Permission::from(CanEnactGovernance),
                client.client().account().clone(),
            ),
            "grant CanEnactGovernance",
        )
        .await?;
        for (protocol, compiled, snapshot) in [
            (ZK_AMS_PROTOCOL, zk_compiled, zk_snapshot),
            (VEGA_PROTOCOL, vega_compiled, vega_snapshot),
        ] {
            let incoming = next_execution_height(&client).await?;
            let mut mismatched = proposed_activation(compiled, incoming);
            mismatched.parameter_digest = PrivacyParameterDigestV1::new([0xA5; 32]);
            ensure!(
                mismatched.parameter_digest != compiled.parameter_digest,
                "{protocol:?} mismatched digest fixture accidentally equals compiled state"
            );
            let error = submit_instruction(
                &client,
                RegisterPrivacyProtocolActivationV1::new(mismatched),
                "mismatched compiled privacy activation must reject",
            )
            .await
            .expect_err("mismatched compiled privacy activation was accepted");
            ensure!(
                error_chain_contains(&error, "does not match compiled native profile"),
                "{protocol:?} compiled-digest rejection had wrong reason: {error:?}"
            );
            wait_for_all_peer_activations(
                &network,
                incoming,
                &[
                    (ZK_AMS_PROTOCOL, zk_snapshot, None),
                    (VEGA_PROTOCOL, vega_snapshot, None),
                ],
                "mismatched activation must not register protocol state",
            )
            .await?;
            assert_exact_protocol_row(
                &privacy_capabilities(&client)
                    .await
                    .wrap_err("query local row after activation mismatch")?,
                protocol,
                snapshot,
                None,
                "local mismatch row",
            )?;
        }
        let zk_registration_height = next_execution_height(&client).await?;
        let expected_vega_registration_height = zk_registration_height
            .checked_add(EXECUTION_CARRIER_BLOCKS)
            .ok_or_else(|| eyre!("Vega registration height overflowed"))?;
        let zk_proposed = proposed_activation(zk_compiled, zk_registration_height);
        submit_instruction(
            &client,
            RegisterPrivacyProtocolActivationV1::new(zk_proposed),
            "register exact compiled ZK-AMS activation",
        )
        .await?;
        let vega_registration_height = next_execution_height(&client).await?;
        ensure!(
            vega_registration_height == expected_vega_registration_height,
            "Vega proposal landed at {vega_registration_height}, expected \
             {expected_vega_registration_height}"
        );
        let vega_proposed = proposed_activation(vega_compiled, vega_registration_height);
        submit_instruction(
            &client,
            RegisterPrivacyProtocolActivationV1::new(vega_proposed),
            "register exact compiled Vega activation",
        )
        .await?;
        wait_for_all_peer_activations(
            &network,
            vega_registration_height,
            &[
                (ZK_AMS_PROTOCOL, zk_snapshot, Some(zk_proposed)),
                (VEGA_PROTOCOL, vega_snapshot, Some(vega_proposed)),
            ],
            "exact proposed ZK-AMS/Vega activation",
        )
        .await?;
        let zk_fixture = zk_ams_fixture()?;
        let zk_preactivation = build_zk_ams_batch_action(
            &client,
            &zk_fixture,
            &zk_fixture.credentials[..1],
            zk_ams_initial_registry_state(&zk_fixture),
            genesis_hash,
            11,
            [0x11; 32],
        )?
        .transaction;
        let (vega_issuer_record, vega_preactivation) =
            build_vega_action(&client, genesis_hash, 21, 0x31, [0x21; 32])?;
        submit_instruction(
            &client,
            RegisterPrivacyVegaIssuerV1::new(vega_issuer_record),
            "register canonical Vega issuer while protocol is Proposed",
        )
        .await?;
        let aliased_vega_issuer = PrivacyVegaIssuerRecordV1::new(
            PrivacyIssuerIdV1::new([0x4F; 32]),
            1,
            vega_issuer_record.issuer_public_key,
            vega_issuer_record.document_type,
            vega_issuer_record.namespace,
            vega_issuer_record.digest_algorithm,
            vega_issuer_record.issuer_authentication_algorithm,
            vega_issuer_record.device_authentication_algorithm,
            None,
            PrivacyVegaIssuerRecordLifecycleV1::Active,
        )
        .wrap_err("construct cross-lineage Vega issuer-key alias")?;
        let alias_error = submit_instruction(
            &client,
            RegisterPrivacyVegaIssuerV1::new(aliased_vega_issuer),
            "cross-lineage Vega issuer-key alias must reject",
        )
        .await
        .expect_err("one Vega P-256 key was registered under two issuer identities");
        ensure!(
            error_chain_contains(&alias_error, "permanently owned"),
            "cross-lineage Vega key alias rejected for wrong reason: {alias_error:?}"
        );
        let bootstrap_error = submit_instruction(
            &client,
            BootstrapPrivacyZkAmsRegistryV1::new(zk_fixture.bootstrap),
            "pre-activation ZK-AMS registry bootstrap must reject",
        )
        .await
        .expect_err("ZK-AMS registry bootstrap was accepted before activation");
        ensure!(
            error_chain_contains(
                &bootstrap_error,
                "cannot bootstrap a registry before ZK-AMS is active"
            ),
            "pre-activation ZK-AMS bootstrap rejected for wrong reason: {bootstrap_error:?}"
        );
        let advance_target = privacy_capabilities(&client).await?.committed_height;
        wait_for_all_peer_activations(
            &network,
            advance_target,
            &[
                (ZK_AMS_PROTOCOL, zk_snapshot, Some(zk_proposed)),
                (VEGA_PROTOCOL, vega_snapshot, Some(vega_proposed)),
            ],
            "both protocols remain Proposed before negative action probes",
        )
        .await?;
        assert_rejected_with(
            &client,
            &zk_preactivation,
            "canonical ZK-AMS action before activation",
            &[
                "trusted ZK-AMS registry state failed validation",
                "ZK-AMS registry has no governed issuer-policy record",
                "activation is not active",
            ],
        )
        .await?;
        assert_rejected_with(
            &client,
            &vega_preactivation,
            "canonical Vega action before activation",
            &["activation is not active"],
        )
        .await?;
        let last_pre_activation_height = privacy_capabilities(&client).await?.committed_height;
        wait_for_all_peer_activations(
            &network,
            last_pre_activation_height,
            &[
                (ZK_AMS_PROTOCOL, zk_snapshot, Some(zk_proposed)),
                (VEGA_PROTOCOL, vega_snapshot, Some(vega_proposed)),
            ],
            "both protocols remain Proposed after real rejected actions advance the chain",
        )
        .await?;
        let activation_height = next_execution_height(&client).await?;
        let zk_active = zk_compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
            PrivacyActiveLifecycleV1 {
                proposed_at_height: zk_registration_height,
                activated_at_height: activation_height,
                state_since_height: activation_height,
            },
        ));
        let vega_active = vega_compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
            PrivacyActiveLifecycleV1 {
                proposed_at_height: vega_registration_height,
                activated_at_height: activation_height,
                state_since_height: activation_height,
            },
        ));
        submit_instructions(
            &client,
            vec![
                TransitionPrivacyProtocolLifecycleV1::new(ZK_AMS_PROTOCOL, zk_active.lifecycle)
                    .into(),
                TransitionPrivacyProtocolLifecycleV1::new(VEGA_PROTOCOL, vega_active.lifecycle)
                    .into(),
            ],
            "explicitly activate both intentionally pending protocol proposals",
        )
        .await?;
        wait_for_all_peer_activations(
            &network,
            activation_height,
            &[
                (ZK_AMS_PROTOCOL, zk_snapshot, Some(zk_active)),
                (VEGA_PROTOCOL, vega_snapshot, Some(vega_active)),
            ],
            "exact Active ZK-AMS/Vega state on all validators",
        )
        .await?;
        submit_instruction(
            &client,
            BootstrapPrivacyZkAmsRegistryV1::new(zk_fixture.bootstrap),
            "bootstrap canonical active ZK-AMS registry",
        )
        .await?;
        let (first_admission, second_admission) = zk_fixture
            .credentials
            .split_at(ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1);
        ensure!(
            first_admission.len() == ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1
                && second_admission.len() == ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1,
            "ZK-AMS minimum ring must be assembled from two exact eight-member batches"
        );
        let zk_admission_one = build_zk_ams_batch_action(
            &client,
            &zk_fixture,
            first_admission,
            zk_ams_initial_registry_state(&zk_fixture),
            genesis_hash,
            12,
            [0x12; 32],
        )?;
        let zk_admission_two = build_zk_ams_batch_action(
            &client,
            &zk_fixture,
            second_admission,
            zk_admission_one.next_state,
            genesis_hash,
            13,
            [0x13; 32],
        )?;
        let provisioned_account = gen_account_in("zk-ams-provisioned").0;
        let replay_account = gen_account_in("zk-ams-key-image-replay").0;
        let restart_replay_account = gen_account_in("zk-ams-restart-key-image-replay").0;
        ensure!(
            provisioned_account != replay_account
                && provisioned_account != restart_replay_account
                && replay_account != restart_replay_account,
            "ZK-AMS provisioning and replay targets must be distinct"
        );
        let read_client = client.clone();
        let accounts_before_provision = read_on_dedicated_thread(move || {
            Ok(read_client.client().query(FindAccounts).execute_all()?)
        })
        .await
        .wrap_err("query accounts before ZK-AMS provisioning")?;
        for account_id in [
            &provisioned_account,
            &replay_account,
            &restart_replay_account,
        ] {
            ensure!(
                accounts_before_provision
                    .iter()
                    .all(|account| &account.id != account_id),
                "ZK-AMS fixture target account already exists: {account_id}"
            );
        }
        let zk_provision = build_zk_ams_provision_action(
            &client,
            &zk_fixture,
            zk_admission_two.next_state,
            provisioned_account.clone(),
            genesis_hash,
            14,
            [0x14; 32],
        )?;
        let zk_key_image_replay = build_zk_ams_provision_action(
            &client,
            &zk_fixture,
            zk_admission_two.next_state,
            replay_account.clone(),
            genesis_hash,
            15,
            [0x15; 32],
        )?;
        let zk_restart_key_image_replay = build_zk_ams_provision_action(
            &client,
            &zk_fixture,
            zk_admission_two.next_state,
            restart_replay_account.clone(),
            genesis_hash,
            16,
            [0x16; 32],
        )?;
        ensure!(
            zk_provision.account_id == provisioned_account
                && zk_key_image_replay.account_id == replay_account
                && zk_restart_key_image_replay.account_id == restart_replay_account
                && zk_provision.key_image == zk_key_image_replay.key_image
                && zk_provision.key_image == zk_restart_key_image_replay.key_image,
            "independently proved ZK-AMS replay fixtures must share only the key image"
        );
        ensure!(
            zk_provision.transaction.hash() != zk_key_image_replay.transaction.hash()
                && zk_provision.transaction.hash()
                    != zk_restart_key_image_replay.transaction.hash()
                && zk_key_image_replay.transaction.hash()
                    != zk_restart_key_image_replay.transaction.hash(),
            "independently proved ZK-AMS key-image replays must have distinct transaction hashes"
        );
        let (final_issuer_record, vega_final) =
            build_vega_action(&client, genesis_hash, 22, 0x33, [0x22; 32])?;
        ensure!(
            final_issuer_record == vega_issuer_record,
            "Vega action fixture drifted from registered issuer state"
        );
        let stale_zk =
            independently_resigned_stale_intent(&zk_admission_one.transaction, 112, &client)?;
        let stale_vega = independently_resigned_stale_intent(&vega_final, 122, &client)?;
        let tampered_zk = independently_resigned_governance_tamper(
            &zk_admission_one.transaction,
            GovernanceTamper::ZkAmsRegistryRecord,
            &client,
        )?;
        let tampered_vega = independently_resigned_governance_tamper(
            &vega_final,
            GovernanceTamper::VegaIssuerRecord,
            &client,
        )?;
        let corrupt_vega = independently_resigned_vega_proof_corruption(&vega_final, &client)?;
        assert_rejected_with(
            &client,
            &stale_zk,
            "independently signed stale ZK-AMS intent",
            &[
                "privacy statement transaction-intent digest differs",
                "transaction intent",
                "intent binding",
            ],
        )
        .await?;
        assert_rejected_with(
            &client,
            &stale_vega,
            "independently signed stale Vega intent",
            &[
                "privacy statement transaction-intent digest differs",
                "transaction intent",
                "intent binding",
            ],
        )
        .await?;
        assert_rejected_with(
            &client,
            &tampered_zk,
            "self-consistent ZK-AMS authoritative-head substitution",
            &["registry record does not match the authoritative head"],
        )
        .await?;
        assert_rejected_with(
            &client,
            &tampered_vega,
            "self-consistent Vega issuer-record substitution",
            &[
                "IssuerRecordDigestMismatch",
                "issuer record digest",
                "trusted Vega issuer state",
            ],
        )
        .await?;
        assert_rejected_with(
            &client,
            &corrupt_vega,
            "independently signed Vega proof corruption",
            &[
                "native Vega verification failed",
                "Vega proof verification failed",
            ],
        )
        .await?;
        let restart_index = network.peers().len() - 1;
        let restart_peer = network.peers()[restart_index].clone();
        let config_layers = network.config_layers().collect::<Vec<_>>();
        ensure!(
            restart_peer.shutdown_if_started().await,
            "selected Active privacy validator was not running before restart coverage"
        );
        for (label, transaction) in [
            ("ZK-AMS admission one", &zk_admission_one.transaction),
            ("ZK-AMS admission two", &zk_admission_two.transaction),
            ("Vega", &vega_final),
            ("ZK-AMS account provision", &zk_provision.transaction),
        ] {
            let submitted = submit_signed_transaction(
                &client,
                transaction,
                &format!("submit canonical active {label} action"),
            )
            .await?;
            ensure!(
                *submitted.as_ref() == *transaction.hash().as_ref(),
                "submitted {label} transaction hash differs from signed bytes"
            );
        }
        let finalized_height = privacy_capabilities(&client)
            .await
            .wrap_err("query height after ZK-AMS admission/provision and Vega finality")?
            .committed_height;
        let healthy_clients = network
            .peers()
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != restart_index)
            .map(|(_, peer)| bounded_client(peer.client()))
            .collect::<Vec<_>>();
        wait_for_transactions_on_peers(
            &healthy_clients,
            &[
                ("ZK-AMS admission one", &zk_admission_one.transaction),
                ("ZK-AMS admission two", &zk_admission_two.transaction),
                ("ZK-AMS provision", &zk_provision.transaction),
                ("Vega", &vega_final),
            ],
            "healthy-validator ZK-AMS lineage and Vega finality",
        )
        .await?;
        wait_for_zk_ams_account_state_on_peers(
            &healthy_clients,
            &provisioned_account,
            &[&replay_account, &restart_replay_account],
            "healthy-validator ZK-AMS account creation",
        )
        .await?;
        assert_rejected_with(
            &client,
            &zk_key_image_replay.transaction,
            "independently proved same-key-image ZK-AMS replay",
            &[
                "verified ZK-AMS provisioning key image was already consumed",
                "provisioning key image was already consumed",
            ],
        )
        .await?;
        ensure!(
            privacy_capabilities(&client)
                .await
                .wrap_err("query height after independent ZK-AMS key-image replay")?
                .committed_height
                == finalized_height,
            "independent ZK-AMS key-image replay unexpectedly committed another block"
        );
        wait_for_zk_ams_account_state_on_peers(
            &healthy_clients,
            &provisioned_account,
            &[&replay_account, &restart_replay_account],
            "healthy-validator ZK-AMS key-image replay rejection",
        )
        .await?;
        for (label, transaction) in [
            ("ZK-AMS admission one", &zk_admission_one.transaction),
            ("ZK-AMS admission two", &zk_admission_two.transaction),
            ("ZK-AMS provision", &zk_provision.transaction),
            ("Vega", &vega_final),
        ] {
            let replay_error = timeout(
                SUBMISSION_TIMEOUT,
                client.account_client().submit_transaction(transaction),
            )
            .await
            .map_err(|_| {
                eyre!("exact {label} privacy replay submission exceeded {SUBMISSION_TIMEOUT:?}")
            })?
            .expect_err("exact finalized privacy transaction replay was accepted");
            ensure!(
                is_exact_replay_error(&replay_error),
                "exact {label} replay rejected for wrong reason: {replay_error:?}"
            );
        }
        ensure!(
            privacy_capabilities(&client)
                .await
                .wrap_err("query height after exact replay rejections")?
                .committed_height
                == finalized_height,
            "exact privacy transaction replays unexpectedly committed another block"
        );
        timeout(
            RESTART_TIMEOUT,
            restart_peer.start_checked(config_layers.iter(), None),
        )
        .await
        .map_err(|_| eyre!("privacy validator restart exceeded {RESTART_TIMEOUT:?}"))?
        .wrap_err("restart privacy validator")?;
        wait_for_all_peer_activations(
            &network,
            finalized_height,
            &[
                (ZK_AMS_PROTOCOL, zk_snapshot, Some(zk_active)),
                (VEGA_PROTOCOL, vega_snapshot, Some(vega_active)),
            ],
            "post-restart Active bindings and catch-up height",
        )
        .await?;
        let all_clients = network
            .peers()
            .iter()
            .map(|peer| bounded_client(peer.client()))
            .collect::<Vec<_>>();
        wait_for_transactions_on_peers(
            &all_clients,
            &[
                ("ZK-AMS admission one", &zk_admission_one.transaction),
                ("ZK-AMS admission two", &zk_admission_two.transaction),
                ("ZK-AMS provision", &zk_provision.transaction),
                ("Vega", &vega_final),
            ],
            "post-restart exact ZK-AMS lineage and Vega transaction visibility",
        )
        .await?;
        wait_for_zk_ams_account_state_on_peers(
            &all_clients,
            &provisioned_account,
            &[&replay_account, &restart_replay_account],
            "post-restart ZK-AMS account and rejected-target persistence",
        )
        .await?;
        let restarted_client = bounded_client(restart_peer.client());
        assert_rejected_with(
            &restarted_client,
            &zk_restart_key_image_replay.transaction,
            "post-restart independently proved same-key-image ZK-AMS replay",
            &[
                "verified ZK-AMS provisioning key image was already consumed",
                "provisioning key image was already consumed",
            ],
        )
        .await?;
        ensure!(
            privacy_capabilities(&restarted_client)
                .await
                .wrap_err("query restarted height after persisted key-image replay")?
                .committed_height
                == finalized_height,
            "post-restart ZK-AMS key-image replay unexpectedly committed another block"
        );
        wait_for_zk_ams_account_state_on_peers(
            &all_clients,
            &provisioned_account,
            &[&replay_account, &restart_replay_account],
            "post-restart ZK-AMS key-image replay persistence",
        )
        .await?;
        ensure!(
            canonical_genesis_hash(&restarted_client).await? == genesis_hash,
            "restarted validator derived a different canonical genesis hash"
        );
        Ok(())
    }
    .await;
    network.shutdown().await;
    result
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_vega_action_survives_four_validator_activation_replay_and_restart() -> Result<()>
{
    init_instruction_registry();
    let context =
        stringify!(canonical_vega_action_survives_four_validator_activation_replay_and_restart);
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_block_cadence(TEST_BLOCK_CADENCE)
        .with_permissioned_consensus()
        .with_config_layer(|layer| {
            // Keep the production handshake enabled while minimizing its supported
            // puzzle cost so this four-peer gate isolates consensus progress.
            layer
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                .write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                );
        });
    let Some(network) = sandbox::start_network_async_or_skip(builder, context).await? else {
        return Ok(());
    };
    let result: Result<()> = async {
        ensure!(
            network.peers().len() == 4,
            "Vega lifecycle test requires exactly four trusted validators"
        );
        let client = bounded_client(network.client());
        let genesis_hash = canonical_genesis_hash(&client).await?;
        let compiled = compiled_privacy_profile_v1(VEGA_PROTOCOL)
            .wrap_err("load canonical compiled Vega profile")?;
        let snapshot: PrivacyCompiledProfileSnapshotV1 = compiled.into();
        submit_instruction(
            &client,
            Grant::account_permission(
                Permission::from(CanEnactGovernance),
                client.client().account().clone(),
            ),
            "grant CanEnactGovernance for Vega",
        )
        .await?;
        let mismatch_height = next_execution_height(&client).await?;
        let mut mismatched = proposed_activation(
            compiled,
            mismatch_height,
        );
        mismatched.parameter_digest = PrivacyParameterDigestV1::new([0xA5; 32]);
        ensure!(
            mismatched.parameter_digest != compiled.parameter_digest,
            "Vega mismatched digest fixture accidentally equals compiled state"
        );
        let mismatch_error = submit_instruction(
            &client,
            RegisterPrivacyProtocolActivationV1::new(mismatched),
            "mismatched compiled Vega activation must reject",
        )
        .await
        .expect_err("mismatched compiled Vega activation was accepted");
        ensure!(
            error_chain_contains(&mismatch_error, "does not match compiled native profile"),
            "Vega compiled-digest rejection had wrong reason: {mismatch_error:?}"
        );
        let registration_height = next_execution_height(&client).await?;
        let proposed = proposed_activation(compiled, registration_height);
        submit_instruction(
            &client,
            RegisterPrivacyProtocolActivationV1::new(proposed),
            "register exact compiled Vega activation",
        )
        .await?;
        wait_for_all_peer_activations(
            &network,
            registration_height,
            &[(VEGA_PROTOCOL, snapshot, Some(proposed))],
            "exact proposed Vega activation",
        )
        .await?;
        let (issuer_record, preactivation) =
            build_vega_action(&client, genesis_hash, 21, 0x31, [0x21; 32])?;
        submit_instruction(
            &client,
            RegisterPrivacyVegaIssuerV1::new(issuer_record),
            "register canonical Vega issuer while protocol is Proposed",
        )
        .await?;
        let last_pre_activation_height = privacy_capabilities(&client).await?.committed_height;
        wait_for_all_peer_activations(
            &network,
            last_pre_activation_height,
            &[(VEGA_PROTOCOL, snapshot, Some(proposed))],
            "Vega remains Proposed after issuer registration advances the chain",
        )
        .await?;
        assert_rejected_with(
            &client,
            &preactivation,
            "canonical Vega action before activation",
            &["activation is not active"],
        )
        .await?;
        let activation_height = next_execution_height(&client).await?;
        let active = compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
            PrivacyActiveLifecycleV1 {
                proposed_at_height: registration_height,
                activated_at_height: activation_height,
                state_since_height: activation_height,
            },
        ));
        submit_instruction(&client,
            TransitionPrivacyProtocolLifecycleV1::new(VEGA_PROTOCOL, active.lifecycle),
            "explicitly activate the intentionally pending Vega proposal").await?;
        wait_for_all_peer_activations(
            &network,
            activation_height,
            &[(VEGA_PROTOCOL, snapshot, Some(active))],
            "exact Active Vega state on all validators",
        )
        .await?;
        let (final_issuer_record, final_action) =
            build_vega_action(&client, genesis_hash, 22, 0x33, [0x22; 32])?;
        ensure!(
            final_issuer_record == issuer_record,
            "Vega action fixture drifted from registered issuer state"
        );
        let stale = independently_resigned_stale_intent(&final_action, 122, &client)?;
        let governance_tamper = independently_resigned_governance_tamper(
            &final_action,
            GovernanceTamper::VegaIssuerRecord,
            &client,
        )?;
        let proof_corruption =
            independently_resigned_vega_proof_corruption(&final_action, &client)?;
        assert_rejected_with(
            &client,
            &stale,
            "independently signed stale Vega intent",
            &[
                "privacy statement transaction-intent digest differs",
                "transaction intent",
                "intent binding",
            ],
        )
        .await?;
        assert_rejected_with(
            &client,
            &governance_tamper,
            "self-consistent Vega issuer-record substitution",
            &[
                "IssuerRecordDigestMismatch",
                "issuer record digest",
                "trusted Vega issuer state",
            ],
        )
        .await?;
        assert_rejected_with(
            &client,
            &proof_corruption,
            "independently signed Vega proof corruption",
            &["native Vega verification failed", "Vega proof verification failed"],
        )
        .await?;
        let restart_index = network.peers().len() - 1;
        let restart_peer = network.peers()[restart_index].clone();
        let config_layers = network.config_layers().collect::<Vec<_>>();
        ensure!(
            restart_peer.shutdown_if_started().await,
            "selected Active Vega validator was not running before restart"
        );
        let submitted = submit_signed_transaction(
            &client,
            &final_action,
            "submit canonical active Vega action",
        )
        .await?;
        ensure!(
            *submitted.as_ref() == *final_action.hash().as_ref(),
            "submitted Vega transaction hash differs from signed bytes"
        );
        let finalized_height = privacy_capabilities(&client).await
            .wrap_err("query height after Vega finality")?
            .committed_height;
        let healthy_clients = network
            .peers()
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != restart_index)
            .map(|(_, peer)| bounded_client(peer.client()))
            .collect::<Vec<_>>();
        wait_for_transactions_on_peers(
            &healthy_clients,
            &[("Vega", &final_action)],
            "healthy-validator Vega finality",
        )
        .await?;
        let replay_error = timeout(SUBMISSION_TIMEOUT, client.account_client().submit_transaction(&final_action)).await.map_err(|_| eyre!("exact Vega replay submission exceeded {SUBMISSION_TIMEOUT:?}"))?
            .expect_err("exact finalized Vega transaction replay was accepted");
        ensure!(
            is_exact_replay_error(&replay_error),
            "exact Vega replay rejected for wrong reason: {replay_error:?}"
        );
        timeout(
            RESTART_TIMEOUT,
            restart_peer.start_checked(config_layers.iter(), None),
        )
        .await
        .map_err(|_| eyre!("Vega validator restart exceeded {RESTART_TIMEOUT:?}"))?
        .wrap_err("restart Vega validator")?;
        wait_for_all_peer_activations(
            &network,
            finalized_height,
            &[(VEGA_PROTOCOL, snapshot, Some(active))],
            "post-restart Active Vega binding and catch-up height",
        )
        .await?;
        let all_clients = network
            .peers()
            .iter()
            .map(|peer| bounded_client(peer.client()))
            .collect::<Vec<_>>();
        wait_for_transactions_on_peers(
            &all_clients,
            &[("Vega", &final_action)],
            "post-restart exact Vega transaction visibility",
        )
        .await?;
        let restarted_client = bounded_client(restart_peer.client());
        ensure!(
            canonical_genesis_hash(&restarted_client).await? == genesis_hash,
            "restarted Vega validator derived a different canonical genesis hash"
        );
        println!(
            "TAIRA_PRIVACY_PROTOCOL_FOUR_PEER_CASE_V1:privacy_exact12_zk_ams_vega_network::canonical_vega_action_survives_four_validator_activation_replay_and_restart:passed"
        );
        Ok(())
    }
    .await;
    network.shutdown().await;
    result
}
