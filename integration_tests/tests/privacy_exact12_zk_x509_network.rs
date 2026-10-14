#![cfg(feature = "privacy-release-evidence")]

//! Release-only ZK-X509 four-peer production-action gate.
//!
//! Synthetic source-pin/readiness tests live beside the compiled profile. This
//! sole network target has no unavailable-as-success path: it becomes runnable
//! only after authenticated evidence makes the production profile available.
//!
//! Release gate:
//! ```text
//! TEST_NETWORK_IROHAD_FEATURES=zk-stark IROHA_TEST_REQUIRE_NETWORK=1 \
//! IROHA_TEST_SERIALIZE_NETWORKS=1 \
//! cargo test --locked -p integration_tests --test network_functional \
//! --features 'zk-stark privacy-release-evidence' \
//! privacy_exact12_zk_x509_network::canonical_zk_x509_action_survives_four_peer_activation_replay_and_restart \
//! -- --exact --nocapture --test-threads=1
//! ```
use eyre::{Result, WrapErr as _, ensure, eyre};
use integration_tests::{sandbox, sync::rebind_blocking_client};
use iroha::{
    blocking::Client,
    crypto::HashOf,
    data_model::{
        Level, ValidationFail,
        block::{BlockHeader, SignedBlock},
        isi::{
            Grant, InstructionBox, Log, SetParameter,
            error::{InstructionExecutionError, InvalidParameterError},
            privacy::{
                RegisterPrivacyProtocolActivationV1, RegisterPrivacyZkX509CertificatePolicyV1,
                RegisterPrivacyZkX509CrlV1, RegisterPrivacyZkX509TrustAnchorV1,
                RotatePrivacyZkX509CrlV1, TransitionPrivacyProtocolLifecycleV1,
            },
        },
        parameter::{Parameter, TransactionParameter},
        permission::Permission,
        prelude::QueryBuilderExt,
        privacy::{
            IrohaZkX509StarkP256StatementV1, PrivacyActiveLifecycleV1,
            PrivacyCapabilityReadinessV1, PrivacyCapabilityUnavailableReasonV1,
            PrivacyCompiledProfileResultV1, PrivacyCompiledProfileSnapshotV1,
            PrivacyExact12CapabilityManifestV1, PrivacyExecutionModeV1, PrivacyOperationSchemaV1,
            PrivacyProofV1, PrivacyProposedLifecycleV1, PrivacyProtocolActivationRecordV1,
            PrivacyProtocolIdV1, PrivacyProtocolLifecycleV1, PrivacyStatementV1,
        },
        query::{
            CommittedTransaction, block::prelude::FindBlocks,
            transaction::prelude::FindTransactions,
        },
        transaction::{
            FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionEntrypoint,
            TransactionResult, error::TransactionRejectionReason,
        },
    },
};
use iroha_core::privacy_release_evidence::{
    PRIVACY_RELEASE_RAYON_THREAD_COUNT_V1, PRIVACY_RELEASE_STAGE_STACK_BYTES_V1,
    PrivacyReleaseTransactionContextV1, PrivacyReleaseZkX509NetworkActionsV1,
    PrivacyReleaseZkX509ResourceCertificateV1, PrivacyReleaseZkX509SemanticReplayV1,
    build_privacy_release_zk_x509_network_actions_v1,
    build_privacy_release_zk_x509_semantic_replay_v1, initialize_privacy_release_rayon_pool_v1,
    privacy_release_zk_x509_resource_certificate_matches_source_v1,
};
use iroha_core_privacy::privacy_profiles::compiled_privacy_profile_v1;
use iroha_executor_data_model::permission::governance::CanEnactGovernance;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_test_network::{NetworkBuilder, init_instruction_registry, read_on_dedicated_thread};
use std::{
    fs,
    num::{NonZeroU32, NonZeroU64},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, sleep, timeout};
const RELEASE_TEST_NAME: &str =
    "canonical_zk_x509_action_survives_four_peer_activation_replay_and_restart";
const REQUIRED_DAEMON_FEATURE: &str = "zk-stark";
const ZK_X509_PROTOCOL: PrivacyProtocolIdV1 = PrivacyProtocolIdV1::IrohaZkX509StarkP256V1;
const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(120);
const PEER_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);
const RESTART_TIMEOUT: Duration = Duration::from_secs(120);
const SEMANTIC_TIME_ADVANCE_TIMEOUT: Duration = Duration::from_secs(240);
const TEST_BLOCK_CADENCE: Duration = Duration::from_millis(100);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const ACTION_TTL: Duration = Duration::from_secs(3_600);
const SEMANTIC_TIME_ADVANCE_MAX_BLOCKS: u64 = 16;
const SEMANTIC_TIME_ADVANCE_NONCE_BASE: u64 = 4_000_000_000;
const TRANSACTION_BUDGET_BYTES: u64 = 32 * 1024 * 1024;
const TORII_CONTENT_BUDGET_BYTES: i64 = 128 * 1024 * 1024;
const NETWORK_FRAME_BUDGET_BYTES: i64 = 128 * 1024 * 1024;
const RESOURCE_CERTIFICATE_MAX_BYTES: usize = 64 * 1024;
const RESOURCE_CERTIFICATE_RELATIVE_PATH: &str =
    "../fixtures/privacy/zk_x509_native_resource_v1.norito";
const DUPLICATE_CERTIFICATE_NULLIFIER_MESSAGE: &str = concat!(
    "privacy proof admission rejected: trusted X.509 state failed validation: ",
    "DuplicateCertificateNullifier"
);
fn require_test_network_feature(feature: &str) -> Result<()> {
    let enabled = std::env::var("TEST_NETWORK_IROHAD_FEATURES")
        .ok()
        .is_some_and(|value| {
            value
                .split([',', ' ', '\t', '\n'])
                .any(|item| item.trim() == feature)
        });
    ensure!(
        enabled,
        "{RELEASE_TEST_NAME}: TEST_NETWORK_IROHAD_FEATURES must include `{feature}` so the four real \
         validators expose the STARK-capable production surface required by this gate"
    );
    Ok(())
}
fn require_authoritative_network_mode() -> Result<()> {
    let enabled = std::env::var(sandbox::REQUIRE_NETWORK_ENV)
        .ok()
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        });
    ensure!(
        enabled,
        "{RELEASE_TEST_NAME}: {} must explicitly require the real four-peer network; this \
         authoritative release target cannot report a sandbox skip as success",
        sandbox::REQUIRE_NETWORK_ENV
    );
    Ok(())
}
fn bounded_client(client: Client) -> Client {
    rebind_blocking_client(&client, |client| {
        client.transaction_status_timeout = SUBMISSION_TIMEOUT;
        client.torii_request_timeout = Duration::from_secs(30);
        client.transaction_ttl = Some(ACTION_TTL);
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
fn installed_resource_certificate() -> Result<PrivacyReleaseZkX509ResourceCertificateV1> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(RESOURCE_CERTIFICATE_RELATIVE_PATH);
    let bytes = fs::read(&path).wrap_err_with(|| {
        format!(
            "read installed X.509 resource certificate {}",
            path.display()
        )
    })?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= RESOURCE_CERTIFICATE_MAX_BYTES,
        "installed X.509 resource certificate has invalid byte length {}",
        bytes.len()
    );
    let certificate: PrivacyReleaseZkX509ResourceCertificateV1 =
        norito::decode_canonical(&bytes)
            .wrap_err("decode installed canonical X.509 resource certificate")?;
    let canonical = norito::encode_canonical(&certificate)
        .wrap_err("re-encode installed canonical X.509 resource certificate")?;
    ensure!(
        canonical == bytes,
        "installed X.509 resource certificate is not its exact canonical Norito encoding"
    );
    ensure!(
        privacy_release_zk_x509_resource_certificate_matches_source_v1(&certificate),
        "installed X.509 resource certificate does not match every authenticated source pin"
    );
    Ok(certificate)
}
fn authenticated_network_prover_timeout(
    certificate: &PrivacyReleaseZkX509ResourceCertificateV1,
) -> Result<Duration> {
    ensure!(
        privacy_release_zk_x509_resource_certificate_matches_source_v1(certificate),
        "cannot derive the native ZK-X509 proof budget from an unauthenticated resource certificate"
    );
    ensure!(
        !SUBMISSION_TIMEOUT.is_zero(),
        "native ZK-X509 admission reserve must be nonzero"
    );
    let process_ceiling = Duration::from_millis(certificate.process_limits.elapsed_ceiling_millis);
    let proof_timeout = process_ceiling.checked_sub(SUBMISSION_TIMEOUT).ok_or_else(|| {
        eyre!(
            "authenticated native ZK-X509 process ceiling {process_ceiling:?} does not leave the \
             required {SUBMISSION_TIMEOUT:?} admission reserve"
        )
    })?;
    ensure!(
        !proof_timeout.is_zero()
            && Duration::from_millis(certificate.positive.elapsed_millis) <= proof_timeout,
        "authenticated positive native ZK-X509 observation of {}ms does not fit the \
         {proof_timeout:?} proof budget that preserves the {SUBMISSION_TIMEOUT:?} admission reserve",
        certificate.positive.elapsed_millis
    );
    Ok(proof_timeout)
}
async fn latest_committed_block_timestamp_ms(client: &Client) -> Result<u64> {
    let read_client = client.clone();
    let blocks = read_on_dedicated_thread(move || {
        Ok(read_client.client().query(FindBlocks).execute_all()?)
    })
    .await
    .wrap_err("query trusted block timestamp for native ZK-X509 action")?;
    let latest = blocks
        .iter()
        .max_by_key(|block| block.header().height().get())
        .ok_or_else(|| eyre!("native ZK-X509 action requires a committed genesis block"))?;
    u64::try_from(latest.header().creation_time().as_millis())
        .map_err(|_| eyre!("trusted block timestamp does not fit u64 milliseconds"))
}
async fn require_live_x509_submission_window(
    client: &Client,
    statement: &IrohaZkX509StarkP256StatementV1,
    context: &str,
) -> Result<()> {
    let current_millis = latest_committed_block_timestamp_ms(client).await?;
    let not_before_millis = statement
        .presentation_not_before_unix_seconds
        .checked_mul(1_000)
        .ok_or_else(|| eyre!("{context}: presentation start overflowed"))?;
    let deadline_exclusive_millis = statement
        .presentation_not_after_unix_seconds
        .checked_add(1)
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or_else(|| eyre!("{context}: presentation deadline overflowed"))?;
    let admission_reserve_millis = u64::try_from(SUBMISSION_TIMEOUT.as_millis())
        .map_err(|_| eyre!("{context}: submission timeout does not fit u64 milliseconds"))?;
    let remaining_millis = deadline_exclusive_millis
        .checked_sub(current_millis)
        .ok_or_else(|| eyre!("{context}: presentation window already expired"))?;
    ensure!(
        current_millis >= not_before_millis && remaining_millis >= admission_reserve_millis,
        "{context}: authoritative block timestamp {current_millis} is outside the live X.509 \
         window or leaves only {remaining_millis}ms, less than the full \
         {admission_reserve_millis}ms admission timeout"
    );
    Ok(())
}
fn single_zk_x509_proof_bytes<'a>(
    transaction: &'a SignedTransaction,
    expected_statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<&'a [u8]> {
    ensure!(
        transaction.instructions().explicit_instructions().count() == 1,
        "native ZK-X509 proof transaction must contain exactly one explicit instruction"
    );
    let (_, submission) = transaction
        .privacy_transaction_intent_binding_if_present_v1()
        .wrap_err("inspect native ZK-X509 proof transaction binding")?
        .ok_or_else(|| eyre!("native ZK-X509 transaction omitted its direct privacy action"))?;
    match (&submission.envelope.statement, &submission.envelope.proof) {
        (
            PrivacyStatementV1::IrohaZkX509StarkP256V1(statement),
            PrivacyProofV1::IrohaZkX509StarkP256V1(proof),
        ) => {
            ensure!(
                statement == expected_statement && statement.context.action_index == 0,
                "native ZK-X509 transaction did not carry its exact returned index-zero statement"
            );
            Ok(proof.as_bytes())
        }
        _ => Err(eyre!(
            "native ZK-X509 transaction carried a different statement or proof variant"
        )),
    }
}
async fn canonical_genesis_hash(client: &Client) -> Result<[u8; 32]> {
    let read_client = client.clone();
    let blocks = read_on_dedicated_thread(move || {
        Ok(read_client.client().query(FindBlocks).execute_all()?)
    })
    .await
    .wrap_err("query committed blocks for canonical ZK-X509 genesis binding")?;
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
    ensure!(hash != [0; 32], "canonical genesis hash must be non-zero");
    Ok(hash)
}
fn error_chain_contains(error: &eyre::Report, needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    error
        .chain()
        .any(|cause| cause.to_string().to_ascii_lowercase().contains(&needle))
}
fn is_exact_committed_transaction_replay(error: &eyre::Report) -> bool {
    error_chain_contains(error, "PRTRY:ALREADY_COMMITTED")
        && error_chain_contains(error, "transaction already committed to the blockchain")
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactCommittedBlock {
    height: u64,
    hash: HashOf<BlockHeader>,
    parent_hash: Option<HashOf<BlockHeader>>,
    creation_time_ms: u64,
}
#[derive(Clone, Copy, Debug)]
struct TipObservation {
    block: ExactCommittedBlock,
    contains_transaction: bool,
}
async fn query_tip(
    client: &Client,
    transaction: Option<&SignedTransaction>,
) -> Result<TipObservation> {
    let read_client = client.clone();
    let blocks = read_on_dedicated_thread(move || {
        Ok(read_client.client().query(FindBlocks).execute_all()?)
    })
    .await
    .wrap_err_with(|| format!("query committed blocks from {}", client.client().endpoint()))?;
    let tip = blocks
        .iter()
        .max_by_key(|block| block.header().height().get())
        .ok_or_else(|| {
            eyre!(
                "{} returned an empty committed chain",
                client.client().endpoint()
            )
        })?;
    let contains_transaction = if let Some(transaction) = transaction {
        let expected = transaction.hash_as_entrypoint();
        let matches = tip
            .network_input_hashes()
            .filter(|observed| observed == &expected)
            .count();
        ensure!(
            matches <= 1,
            "{} duplicated signed transaction {} in its committed tip",
            client.client().endpoint(),
            transaction.hash()
        );
        if matches == 1 {
            ensure!(
                !tip.is_empty() && tip.external_entrypoint_count() > 0,
                "{} exposed signed transaction {} through an empty or non-external tip",
                client.client().endpoint(),
                transaction.hash()
            );
        }
        matches == 1
    } else {
        false
    };
    Ok(TipObservation {
        block: ExactCommittedBlock {
            height: tip.header().height().get(),
            hash: tip.hash(),
            parent_hash: tip.header().prev_block_hash(),
            creation_time_ms: u64::try_from(tip.header().creation_time().as_millis()).map_err(
                |_| {
                    eyre!(
                        "{} tip timestamp does not fit u64",
                        client.client().endpoint()
                    )
                },
            )?,
        },
        contains_transaction,
    })
}
async fn wait_for_all_common_tip(
    clients: &[Client],
    wait: Duration,
    context: &str,
) -> Result<ExactCommittedBlock> {
    ensure!(!clients.is_empty(), "{context}: validator list is empty");
    let deadline = Instant::now() + wait;
    let mut last_observed = Vec::new();
    loop {
        let mut tips = Vec::with_capacity(clients.len());
        last_observed.clear();
        for (index, client) in clients.iter().enumerate() {
            match query_tip(client, None).await {
                Ok(observed) => {
                    tips.push((index, observed.block));
                    last_observed.push(format!("peer {index}: {:?}", observed.block));
                }
                Err(error) => last_observed.push(format!("peer {index}: {error:?}")),
            }
        }
        for (left_position, (left_index, left)) in tips.iter().enumerate() {
            for (right_index, right) in tips.iter().skip(left_position + 1) {
                ensure!(
                    left.height != right.height || left.hash == right.hash,
                    "{context}: peers {left_index} and {right_index} expose different hashes at \
                     height {}: {} != {}",
                    left.height,
                    left.hash,
                    right.hash
                );
            }
        }
        if tips.len() == clients.len() {
            let expected = tips[0].1;
            if tips.iter().all(|(_, tip)| *tip == expected) {
                return Ok(expected);
            }
        }
        ensure!(
            Instant::now() < deadline,
            "{context}: all {} peers failed to expose one exact tip within {wait:?}: {}",
            clients.len(),
            last_observed.join("; ")
        );
        sleep(POLL_INTERVAL).await;
    }
}
async fn wait_for_all_signed_tip(
    clients: &[Client],
    transaction: &SignedTransaction,
    required: Option<ExactCommittedBlock>,
    wait: Duration,
    context: &str,
) -> Result<ExactCommittedBlock> {
    ensure!(!clients.is_empty(), "{context}: validator list is empty");
    let deadline = Instant::now() + wait;
    let mut canonical = required;
    let mut last_observed = Vec::new();
    loop {
        let mut matching = 0_usize;
        last_observed.clear();
        for (index, client) in clients.iter().enumerate() {
            match query_tip(client, Some(transaction)).await {
                Ok(observed) => {
                    if observed.contains_transaction && canonical.is_none() {
                        canonical = Some(observed.block);
                    }
                    if let Some(expected) = canonical {
                        ensure!(
                            observed.block.height <= expected.height,
                            "{context}: peer {index} advanced past required exact tip \
                             {expected:?}: {:?}",
                            observed.block
                        );
                        ensure!(
                            observed.block.height != expected.height
                                || observed.block.hash == expected.hash,
                            "{context}: peer {index} exposed a divergent hash at height {}: {} != \
                             {}",
                            expected.height,
                            observed.block.hash,
                            expected.hash
                        );
                        if observed.block == expected && observed.contains_transaction {
                            matching = matching.saturating_add(1);
                        }
                    }
                    last_observed.push(format!(
                        "peer {index}: {:?}, contains={}",
                        observed.block, observed.contains_transaction
                    ));
                }
                Err(error) => last_observed.push(format!("peer {index}: {error:?}")),
            }
        }
        if matching == clients.len() {
            return canonical.ok_or_else(|| eyre!("{context}: exact tip identity is absent"));
        }
        ensure!(
            Instant::now() < deadline,
            "{context}: only {matching}/{} peers finalized signed transaction {} at exact tip \
             {canonical:?} within {wait:?}: {}",
            clients.len(),
            transaction.hash(),
            last_observed.join("; ")
        );
        sleep(POLL_INTERVAL).await;
    }
}
async fn assert_all_exact_tip(
    clients: &[Client],
    expected: ExactCommittedBlock,
    context: &str,
) -> Result<()> {
    ensure!(!clients.is_empty(), "{context}: validator list is empty");
    for (index, client) in clients.iter().enumerate() {
        let observed = query_tip(client, None).await?.block;
        ensure!(
            observed == expected,
            "{context}: peer {index} changed exact tip from {expected:?} to {observed:?}"
        );
    }
    Ok(())
}
fn tagged_metadata(tag: u64) -> Result<Metadata> {
    let mut metadata = Metadata::default();
    metadata.insert("zk_x509_network_probe".parse::<Name>()?, tag);
    Ok(metadata)
}
fn instruction_transaction(
    client: &Client,
    instruction: impl Into<InstructionBox>,
    tag: u64,
) -> Result<SignedTransaction> {
    let nonce = u32::try_from(tag)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(|| eyre!("native ZK-X509 transaction tag {tag} is not a nonzero u32 nonce"))?;
    let mut builder = TransactionBuilder::new(
        *client.client().network_id(),
        client.client().account().clone(),
        no_fee(),
    )
    .with_instructions([instruction.into()])
    .with_metadata(tagged_metadata(tag)?);
    builder.set_creation_time(now_duration()?);
    builder.set_ttl(ACTION_TTL);
    builder.set_nonce(nonce);
    builder
        .try_sign(client.client().key_pair().private_key())
        .wrap_err("sign exact tagged native ZK-X509 transaction")
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
async fn submit_expecting_rejection(
    client: &Client,
    transaction: &SignedTransaction,
    context: &str,
    unexpected_acceptance: &str,
) -> Result<eyre::Report> {
    match submit_signed_transaction(client, transaction, context).await {
        Ok(_) => Err(eyre!("{unexpected_acceptance}")),
        Err(error) => Ok(error),
    }
}
async fn submit_instruction(
    client: &Client,
    instruction: impl Into<InstructionBox>,
    tag: u64,
    context: &str,
) -> Result<(SignedTransaction, iroha_crypto::HashOf<SignedTransaction>)> {
    let transaction = instruction_transaction(client, instruction, tag)?;
    let hash = submit_signed_transaction(client, &transaction, context).await?;
    ensure!(
        *hash.as_ref() == *transaction.hash().as_ref(),
        "{context}: submitted hash differs from the signed transaction"
    );
    Ok((transaction, hash))
}
async fn exact_committed_transaction(
    client: &Client,
    transaction: &SignedTransaction,
) -> Result<Option<CommittedTransaction>> {
    let client = client.clone();
    let transaction = transaction.clone();
    read_on_dedicated_thread(move || {
        let expected_hash = transaction.hash_as_entrypoint();
        let expected_entrypoint = TransactionEntrypoint::External(transaction.clone());
        let expected_entrypoint_bytes = norito::encode_canonical(&expected_entrypoint)
            .wrap_err("encode expected finalized transaction entrypoint")?;
        let transactions = client
            .client()
            .query(FindTransactions::new())
            .execute_all()
            .wrap_err("query finalized transactions")?;
        let mut matching = transactions
            .iter()
            .filter(|committed| committed.entrypoint_hash() == &expected_hash);
        let Some(committed) = matching.next() else {
            return Ok(None);
        };
        ensure!(
            matching.next().is_none(),
            "finalized transaction query returned the same entrypoint hash more than once"
        );
        ensure!(
            committed.entrypoint() == &expected_entrypoint
                && norito::encode_canonical(committed.entrypoint())
                    .wrap_err("encode observed finalized transaction entrypoint")?
                    == expected_entrypoint_bytes,
            "entrypoint hash matched transaction bytes that differ from the exact signed entrypoint"
        );
        ensure!(
            committed.output_hash() == &HashOf::new(committed.output()),
            "finalized transaction output hash differs from its full typed output"
        );
        let blocks = client
            .client()
            .query(FindBlocks)
            .execute_all()
            .wrap_err("query exact finalized transaction carrier block")?;
        let mut carriers = blocks
            .iter()
            .filter(|block| block.hash() == *committed.block_hash());
        let carrier: &SignedBlock = carriers
            .next()
            .ok_or_else(|| eyre!("exact finalized transaction carrier block is absent"))?;
        ensure!(
            carriers.next().is_none(),
            "finalized block query returned the exact carrier hash more than once"
        );
        ensure!(
            committed.verify_inclusion_in_block(carrier),
            "finalized transaction entrypoint/result proofs do not match its exact carrier block"
        );
        Ok(Some(committed.clone()))
    })
    .await
}
async fn exact_transaction_result(
    client: &Client,
    transaction: &SignedTransaction,
) -> Result<Option<bool>> {
    Ok(exact_committed_transaction(client, transaction)
        .await?
        .map(|committed| committed.result().0.is_ok()))
}
async fn exact_applied_transaction_visible(
    client: &Client,
    transaction: &SignedTransaction,
) -> Result<bool> {
    match exact_transaction_result(client, transaction).await? {
        Some(true) => Ok(true),
        Some(false) => Err(eyre!("expected applied transaction finalized as rejected")),
        None => Ok(false),
    }
}
async fn wait_for_transaction_on_peers(
    clients: &[Client],
    transaction: &SignedTransaction,
    context: &str,
) -> Result<()> {
    let deadline = Instant::now() + PEER_CONVERGENCE_TIMEOUT;
    let mut last_observed = Vec::new();
    loop {
        let mut visible = 0_usize;
        last_observed.clear();
        for (index, client) in clients.iter().enumerate() {
            match exact_applied_transaction_visible(client, transaction).await {
                Ok(true) => {
                    visible += 1;
                    last_observed.push(format!("peer {index}: exact transaction visible"));
                }
                Ok(false) => last_observed.push(format!("peer {index}: transaction absent")),
                Err(error) => last_observed.push(format!("peer {index}: {error}")),
            }
        }
        if visible == clients.len() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{context}: transaction did not converge within {PEER_CONVERGENCE_TIMEOUT:?}; {}",
                last_observed.join("; ")
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
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
async fn assert_all_exact_duplicate_certificate_nullifier_results(
    clients: &[Client],
    transaction: &SignedTransaction,
    context: &str,
) -> Result<()> {
    ensure!(!clients.is_empty(), "{context}: validator list is empty");
    let mut canonical: Option<(HashOf<TransactionResult>, TransactionResult)> = None;
    for (index, client) in clients.iter().enumerate() {
        let committed = exact_committed_transaction(client, transaction)
            .await?
            .ok_or_else(|| {
                eyre!("{context}: peer {index} omitted the exact finalized transaction")
            })?;
        let observed_hash = committed.result().hash();
        let observed_result = committed.result().clone();
        match &observed_result {
            TransactionResult(
                Err(TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                    InstructionExecutionError::InvalidParameter(
                        InvalidParameterError::SmartContract(message),
                    ),
                ))),
                batch_outcomes,
                _,
                _,
            ) => {
                ensure!(
                    message.as_str() == DUPLICATE_CERTIFICATE_NULLIFIER_MESSAGE,
                    "{context}: peer {index} exposed the wrong smart-contract rejection: \
                     {message:?}"
                );
                ensure!(
                    batch_outcomes.is_empty(),
                    "{context}: peer {index} attached unexpected batch outcomes to the exact \
                     duplicate-nullifier rejection"
                );
            }
            actual => {
                return Err(eyre!(
                    "{context}: peer {index} exposed the wrong full transaction result: {actual:?}"
                ));
            }
        }
        if let Some((canonical_hash, canonical_result)) = &canonical {
            ensure!(
                &observed_hash == canonical_hash && &observed_result == canonical_result,
                "{context}: peer {index} full result/hash differs from the canonical peer: \
                 hash={observed_hash}, canonical_hash={canonical_hash}, \
                 result={observed_result:?}, canonical_result={canonical_result:?}"
            );
        } else {
            canonical = Some((observed_hash, observed_result));
        }
    }
    Ok(())
}
fn assert_zk_x509_capability(
    snapshot: &PrivacyExact12CapabilityManifestV1,
    expected_height: u64,
    compiled: PrivacyCompiledProfileSnapshotV1,
    activation: PrivacyProtocolActivationRecordV1,
    expected_readiness: PrivacyCapabilityReadinessV1,
    context: &str,
) -> Result<()> {
    snapshot
        .validate()
        .wrap_err_with(|| format!("{context}: invalid capability snapshot"))?;
    ensure!(
        snapshot.committed_height == expected_height,
        "{context}: committed height {} differs from exact height {expected_height}",
        snapshot.committed_height
    );
    let row = snapshot
        .protocols
        .iter()
        .find(|row| row.protocol_id == ZK_X509_PROTOCOL)
        .ok_or_else(|| eyre!("{context}: capability snapshot omitted ZK-X509"))?;
    ensure!(
        row.compiled_profile == PrivacyCompiledProfileResultV1::Available(compiled),
        "{context}: compiled ZK-X509 binding drifted: {:?}",
        row.compiled_profile
    );
    ensure!(
        row.readiness == expected_readiness,
        "{context}: ZK-X509 readiness differs from evidence-derived state: expected {expected_readiness:?}, got {:?}",
        row.readiness
    );
    ensure!(
        row.activation == Some(activation),
        "{context}: ZK-X509 activation mismatch: expected {activation:?}, got {:?}",
        row.activation
    );
    ensure!(
        row.operation_schema == PrivacyOperationSchemaV1::ZkX509IdentityPresentationV1
            && row.execution_mode == PrivacyExecutionModeV1::PresentationAction
            && row.privacy_feature_mask.bits() == 2,
        "{context}: ZK-X509 public capability tuple drifted"
    );
    ensure!(
        row.is_network_available()
            == matches!(
                expected_readiness,
                PrivacyCapabilityReadinessV1::ProductionQualified
            ),
        "{context}: ZK-X509 network availability disagrees with registered qualification"
    );
    Ok(())
}
async fn wait_for_available_snapshots(
    clients: &[Client],
    expected_height: u64,
    compiled: PrivacyCompiledProfileSnapshotV1,
    activation: PrivacyProtocolActivationRecordV1,
    expected_readiness: PrivacyCapabilityReadinessV1,
    context: &str,
) -> Result<()> {
    ensure!(!clients.is_empty(), "{context}: validator list is empty");
    let deadline = Instant::now() + PEER_CONVERGENCE_TIMEOUT;
    let mut last_observed = Vec::new();
    loop {
        let mut matching = Vec::with_capacity(clients.len());
        last_observed.clear();
        for (index, client) in clients.iter().enumerate() {
            match privacy_capabilities(&client).await {
                Ok(snapshot) => match assert_zk_x509_capability(
                    &snapshot,
                    expected_height,
                    compiled,
                    activation,
                    expected_readiness,
                    context,
                ) {
                    Ok(()) => match snapshot.canonical_bytes() {
                        Ok(bytes) => {
                            last_observed.push(format!(
                                "peer {index}: exact ZK-X509 manifest at height {} with \
                                     digest {:?}",
                                snapshot.committed_height, snapshot.manifest_digest
                            ));
                            matching.push((index, snapshot, bytes));
                        }
                        Err(error) => last_observed.push(format!(
                            "peer {index}: canonical manifest encoding failed: {error}"
                        )),
                    },
                    Err(error) => last_observed.push(format!("peer {index}: {error}")),
                },
                Err(error) => last_observed.push(format!("peer {index}: query failed: {error}")),
            }
        }
        if matching.len() == clients.len() {
            let (_, canonical, canonical_bytes) = &matching[0];
            for (index, snapshot, bytes) in matching.iter().skip(1) {
                ensure!(
                    snapshot.manifest_digest == canonical.manifest_digest,
                    "{context}: peer {index} manifest digest {:?} differs from canonical {:?} at \
                     exact height {expected_height}",
                    snapshot.manifest_digest,
                    canonical.manifest_digest
                );
                ensure!(
                    bytes == canonical_bytes && snapshot == canonical,
                    "{context}: peer {index} capability manifest is not byte-identical to the \
                     canonical manifest at exact height {expected_height}"
                );
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{context}: available snapshots did not converge within \
                 {PEER_CONVERGENCE_TIMEOUT:?}; {}",
                last_observed.join("; ")
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}
async fn next_incoming_height(client: &Client) -> Result<u64> {
    privacy_capabilities(&client)
        .await
        .wrap_err("query committed height before ZK-X509 governance transaction")?
        .committed_height
        .checked_add(1)
        .ok_or_else(|| eyre!("incoming ZK-X509 governance height overflowed"))
}
async fn advance_to_semantic_base_after_crl_second(
    clients: &[Client],
    submitter: &Client,
    mut semantic_base: ExactCommittedBlock,
    predecessor_this_update_unix_seconds: u64,
) -> Result<ExactCommittedBlock> {
    ensure!(
        clients.len() == 4,
        "native ZK-X509 semantic-time advance requires exactly four validators"
    );
    assert_all_exact_tip(
        clients,
        semantic_base,
        "native ZK-X509 semantic-time advance must start from one all-four exact tip",
    )
    .await?;
    if semantic_base.creation_time_ms / 1_000 > predecessor_this_update_unix_seconds {
        return Ok(semantic_base);
    }
    for ordinal in 0..SEMANTIC_TIME_ADVANCE_MAX_BLOCKS {
        let tag = SEMANTIC_TIME_ADVANCE_NONCE_BASE
            .checked_add(ordinal)
            .ok_or_else(|| eyre!("native ZK-X509 semantic-time advance nonce overflowed"))?;
        let (advance_transaction, _) = submit_instruction(
            submitter,
            Log::new(
                Level::INFO,
                format!("native ZK-X509 semantic-time advance block {ordinal}"),
            ),
            tag,
            "commit bounded native ZK-X509 semantic-time advance",
        )
        .await?;
        let next_base = wait_for_all_signed_tip(
            clients,
            &advance_transaction,
            None,
            PEER_CONVERGENCE_TIMEOUT,
            "all four validators must finalize one exact semantic-time advance block",
        )
        .await?;
        ensure!(
            next_base.height
                == semantic_base
                    .height
                    .checked_add(1)
                    .ok_or_else(|| eyre!("native ZK-X509 semantic-time height overflowed"))?
                && next_base.parent_hash == Some(semantic_base.hash),
            "native ZK-X509 semantic-time advance is not an exact adjacent successor: \
             prior={semantic_base:?}, next={next_base:?}"
        );
        wait_for_transaction_on_peers(
            clients,
            &advance_transaction,
            "all-four direct query of the exact semantic-time advance",
        )
        .await?;
        semantic_base = next_base;
        if semantic_base.creation_time_ms / 1_000 > predecessor_this_update_unix_seconds {
            return Ok(semantic_base);
        }
    }
    Err(eyre!(
        "native ZK-X509 semantic-time advance exhausted its explicit \
         {SEMANTIC_TIME_ADVANCE_MAX_BLOCKS}-block bound: exact base {semantic_base:?} did not \
         advance beyond predecessor CRL thisUpdate second \
         {predecessor_this_update_unix_seconds}"
    ))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_zk_x509_action_survives_four_peer_activation_replay_and_restart() -> Result<()> {
    // This is intentionally an error today. There is no unavailable-as-success
    // branch: authenticated release pins must make the production accessor
    // succeed before this gate can start a network or construct candidate data.
    let compiled = compiled_privacy_profile_v1(ZK_X509_PROTOCOL).wrap_err(
        "ZK-X509 four-peer release gate requires the complete authenticated Linux/aarch64 KAT, \
         expectation, and resource-certificate pins; compiled profile remains unavailable",
    )?;
    let compiled_snapshot: PrivacyCompiledProfileSnapshotV1 = compiled.into();
    let resource_certificate = installed_resource_certificate().wrap_err(
        "ZK-X509 four-peer release gate requires the canonical installed native-resource \
         certificate after source pin authentication",
    )?;
    require_authoritative_network_mode()?;
    require_test_network_feature(REQUIRED_DAEMON_FEATURE)?;
    ensure!(
        resource_certificate.process_limits.rayon_worker_count
            == PRIVACY_RELEASE_RAYON_THREAD_COUNT_V1
            && resource_certificate.process_limits.rayon_worker_stack_bytes
                == u64::try_from(PRIVACY_RELEASE_STAGE_STACK_BYTES_V1)
                    .expect("fixed release stack size fits u64"),
        "authenticated X.509 resource topology does not match the exact in-process release pool"
    );
    let prover_timeout = authenticated_network_prover_timeout(&resource_certificate)?;
    initialize_privacy_release_rayon_pool_v1().map_err(|error| {
        eyre!("initialize exact authenticated X.509 release worker pool: {error}")
    })?;
    init_instruction_registry();
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
        )));
    let network = sandbox::start_network_async_or_skip(builder, RELEASE_TEST_NAME)
        .await?
        .ok_or_else(|| {
            eyre!(
                "{RELEASE_TEST_NAME}: authoritative four-peer release target cannot skip network \
                 startup under any environment"
            )
        })?;
    let result: Result<()> = async {
        ensure!(
            network.peers().len() == 4,
            "native ZK-X509 release gate requires exactly four trusted validators"
        );
        let all_clients = network
            .peers()
            .iter()
            .map(|peer| bounded_client(peer.client()))
            .collect::<Vec<_>>();
        let client = all_clients[0].clone();
        let genesis_hash = canonical_genesis_hash(&client).await?;
        ensure!(
            client.client().network_id().as_bytes() == &genesis_hash,
            "client network ID is not derived from the canonical genesis hash"
        );
        let (grant_transaction, _) = submit_instruction(
            &client,
            Grant::account_permission(Permission::from(CanEnactGovernance), client.client().account().clone()),
            50_000,
            "grant CanEnactGovernance for native ZK-X509 release",
        )
        .await?;
        wait_for_transaction_on_peers(
            &all_clients,
            &grant_transaction,
            "native ZK-X509 governance permission convergence",
        )
        .await?;
        let proposed_at_height = next_incoming_height(&client).await?;
        let proposed = compiled.activation_record(PrivacyProtocolLifecycleV1::Proposed(
            PrivacyProposedLifecycleV1 {
                proposed_at_height,
            },
        ));
        let (activation_transaction, _) = submit_instruction(
            &client,
            RegisterPrivacyProtocolActivationV1::new(proposed),
            50_001,
            "register exact compiled ZK-X509 activation",
        )
        .await?;
        wait_for_transaction_on_peers(
            &all_clients,
            &activation_transaction,
            "exact proposed ZK-X509 activation convergence",
        )
        .await?;
        wait_for_available_snapshots(
            &all_clients,
            proposed_at_height,
            compiled_snapshot,
            proposed,
            PrivacyCapabilityReadinessV1::Unavailable(
                PrivacyCapabilityUnavailableReasonV1::Proposed,
            ),
            "exact proposed ZK-X509 capability row",
        )
        .await?;
        let activated_at_height = next_incoming_height(&client).await?;
        let active = compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
            PrivacyActiveLifecycleV1 {
                proposed_at_height,
                activated_at_height,
                state_since_height: activated_at_height,
            },
        ));
        let (active_transaction, _) = submit_instruction(&client,
            TransitionPrivacyProtocolLifecycleV1::new(ZK_X509_PROTOCOL, active.lifecycle),
            50_002, "explicitly activate the exact ZK-X509 profile").await?;
        wait_for_transaction_on_peers(&all_clients, &active_transaction,
            "explicit ZK-X509 activation convergence").await?;
        wait_for_available_snapshots(
            &all_clients,
            activated_at_height,
            compiled_snapshot,
            active,
            PrivacyCapabilityReadinessV1::Unavailable(
                PrivacyCapabilityUnavailableReasonV1::MissingProductionQualification,
            ),
            "exact active ZK-X509 capability row",
        )
        .await?;
        let trusted_block_timestamp_ms = latest_committed_block_timestamp_ms(&client).await?;
        let creation_time = now_duration()?;
        let action_context = PrivacyReleaseTransactionContextV1 {
            network_id: *client.client().network_id(),
            authority: client.client().account().clone(),
            creation_time,
            time_to_live: Some(ACTION_TTL),
            nonce: NonZeroU32::new(50_002),
            fee_payment: no_fee(),
            metadata: tagged_metadata(50_002)?,
            genesis_hash,
        };
        let signing_key = client.client().key_pair().private_key().clone();
        let initial_resource_certificate = resource_certificate.clone();
        let build_actions = tokio::task::spawn_blocking(move || {
            build_privacy_release_zk_x509_network_actions_v1(
                action_context,
                trusted_block_timestamp_ms,
                [0x5A; 32],
                &initial_resource_certificate,
                SUBMISSION_TIMEOUT,
                &signing_key,
            )
            .map_err(|error| eyre!("build native ZK-X509 network action: {error:?}"))
        });
        let actions: PrivacyReleaseZkX509NetworkActionsV1 = timeout(prover_timeout, build_actions)
            .await
            .map_err(|_| {
                eyre!(
                    "native ZK-X509 action construction exceeded the authenticated \
                     {prover_timeout:?} proof budget that preserves the \
                     {SUBMISSION_TIMEOUT:?} admission reserve"
                )
            })?
            .map_err(|error| eyre!("native ZK-X509 prover task failed: {error}"))??;
        ensure!(
            &actions.statement.wallet_account == client.client().account()
                && actions.statement.context.network_id == *client.client().network_id()
                && actions.statement.context.action_index == 0
                && actions.statement.context.parameter_id == compiled.parameter_id
                && actions.statement.context.parameter_digest == compiled.parameter_digest
                && actions.statement.context.verifier_digest == compiled.verifier_digest
                && actions.statement.context.statement_schema_digest
                    == compiled.statement_schema_digest
                && actions.statement.context.engine_manifest_digest
                    == compiled.engine_manifest_digest
                && !actions
                    .statement
                    .context
                    .transaction_intent_digest
                    .is_zero(),
            "native ZK-X509 builder did not bind the exact transaction authority and production \
             context"
        );
        ensure!(
            actions.statement.trust_anchor_record_digest == actions.trust_anchor.record_digest
                && actions.statement.certificate_policy_record_digest
                    == actions.certificate_policy.record_digest
                && actions.statement.crl_record_digest == actions.crl.record_digest
                && !actions.statement.certificate_nullifier.is_zero(),
            "native ZK-X509 action did not carry its exact governed revisions"
        );
        ensure!(
            actions.canonical_transaction.nonce() == NonZeroU32::new(50_002)
                && actions.malformed_transaction.nonce() == NonZeroU32::new(50_002)
                && actions.malformed_transaction.hash() != actions.canonical_transaction.hash()
                && actions
                    .canonical_transaction
                    .privacy_transaction_intent_digest_v1()
                    .wrap_err("derive canonical native ZK-X509 transaction intent")?
                    == actions.statement.context.transaction_intent_digest
                && actions
                    .malformed_transaction
                    .privacy_transaction_intent_digest_v1()
                    .wrap_err("derive malformed native ZK-X509 transaction intent")?
                    == actions.statement.context.transaction_intent_digest,
            "native ZK-X509 canonical/malformed controls lost their exact nonce, intent, or \
             distinct signed hashes"
        );
        let governance_transactions = [
            submit_instruction(
                &client,
                RegisterPrivacyZkX509TrustAnchorV1::new(actions.trust_anchor),
                50_003,
                "register native ZK-X509 trust-anchor origin",
            )
            .await?
            .0,
            submit_instruction(
                &client,
                RegisterPrivacyZkX509CertificatePolicyV1::new(
                    actions.certificate_policy.clone(),
                ),
                50_004,
                "register native ZK-X509 certificate-policy origin",
            )
            .await?
            .0,
            submit_instruction(
                &client,
                RegisterPrivacyZkX509CrlV1::new(actions.crl),
                50_005,
                "register native ZK-X509 signed-CRL origin",
            )
            .await?
            .0,
        ];
        for (transaction, label) in governance_transactions.iter().zip([
            "trust-anchor",
            "certificate-policy",
            "signed-CRL",
        ]) {
            wait_for_transaction_on_peers(
                &all_clients,
                transaction,
                &format!("native ZK-X509 {label} convergence"),
            )
            .await?;
        }
        require_live_x509_submission_window(
            &client,
            &actions.statement,
            "pre-submit malformed native ZK-X509 control",
        ).await?;
        let malformed_error = submit_expecting_rejection(
            &client,
            &actions.malformed_transaction,
            "signed malformed native ZK-X509 proof must reject",
            "signed malformed native ZK-X509 proof was accepted",
        )
        .await?;
        ensure!(
            error_chain_contains(&malformed_error, "native X.509 verification failed")
                && error_chain_contains(&malformed_error, "proof envelope is malformed"),
            "malformed native ZK-X509 proof rejected for wrong reason: {malformed_error:?}"
        );
        wait_for_transaction_result_on_peers(
            &all_clients,
            &actions.malformed_transaction,
            false,
            "malformed native ZK-X509 rejection convergence",
        )
        .await?;
        let pre_outage_tip = wait_for_all_common_tip(
            &all_clients,
            PEER_CONVERGENCE_TIMEOUT,
            "pre-outage native ZK-X509 exact-tip convergence",
        )
        .await?;
        wait_for_available_snapshots(
            &all_clients,
            pre_outage_tip.height,
            compiled_snapshot,
            active,
            PrivacyCapabilityReadinessV1::Unavailable(
                PrivacyCapabilityUnavailableReasonV1::MissingProductionQualification,
            ),
            "pre-outage byte-identical active ZK-X509 manifests",
        )
        .await?;
        let restart_index = all_clients.len() - 1;
        let restart_peer = network.peers()[restart_index].clone();
        let config_layers = network.config_layers().collect::<Vec<_>>();
        ensure!(
            restart_peer.shutdown_if_started().await,
            "selected active ZK-X509 validator was not running before restart coverage"
        );
        let healthy_clients = all_clients[..restart_index].to_vec();
        require_live_x509_submission_window(
            &client,
            &actions.statement,
            "pre-submit canonical native ZK-X509 action",
        ).await?;
        let submitted_hash = submit_signed_transaction(
            &client,
            &actions.canonical_transaction,
            "submit canonical native ZK-X509 action through three-validator DA/RBC",
        )
        .await?;
        ensure!(
            *submitted_hash.as_ref() == *actions.canonical_transaction.hash().as_ref(),
            "submitted native ZK-X509 hash differs from the signed transaction"
        );
        let canonical_action_block = wait_for_all_signed_tip(
            &healthy_clients,
            &actions.canonical_transaction,
            None,
            PEER_CONVERGENCE_TIMEOUT,
            "three healthy validators must finalize the native ZK-X509 action at one exact tip",
        )
        .await?;
        ensure!(
            canonical_action_block.height
                == pre_outage_tip
                    .height
                    .checked_add(1)
                    .ok_or_else(|| eyre!("native ZK-X509 action height overflowed"))?
                && canonical_action_block.parent_hash == Some(pre_outage_tip.hash),
            "native ZK-X509 action block is not the exact successor of the pre-outage tip: \
             pre_outage={pre_outage_tip:?}, action={canonical_action_block:?}"
        );
        wait_for_transaction_on_peers(
            &healthy_clients,
            &actions.canonical_transaction,
            "healthy-peer direct query of canonical native ZK-X509 finality",
        )
        .await?;
        for (index, replay_client) in healthy_clients.iter().enumerate() {
            let replay_error = timeout(SUBMISSION_TIMEOUT, replay_client.account_client().submit_transaction(&actions.canonical_transaction)).await.map_err(|_| eyre!("pre-restart native ZK-X509 replay to peer {index} submission exceeded {SUBMISSION_TIMEOUT:?}"))?
                .wrap_err_with(|| {
                    format!("submit exact native ZK-X509 replay to healthy peer {index}")
                })
                .expect_err("pre-restart peer accepted exact native ZK-X509 replay");
            ensure!(
                is_exact_committed_transaction_replay(&replay_error),
                "pre-restart peer {index} rejected native ZK-X509 replay without the exact \
                 committed-duplicate code and reason: {replay_error:?}"
            );
            assert_all_exact_tip(
                &healthy_clients,
                canonical_action_block,
                &format!("pre-restart replay through peer {index} must not advance any validator"),
            ).await?;
        }
        let (catch_up_transaction, _) = submit_instruction(
            &client,
            Log::new(
                Level::INFO,
                "native ZK-X509 post-action restart catch-up sentinel".to_owned(),
            ),
            50_006,
            "commit native ZK-X509 post-action catch-up sentinel",
        )
        .await?;
        let sentinel_block = wait_for_all_signed_tip(
            &healthy_clients,
            &catch_up_transaction,
            None,
            PEER_CONVERGENCE_TIMEOUT,
            "three healthy validators must finalize the catch-up sentinel at one exact tip",
        )
        .await?;
        ensure!(
            sentinel_block.height
                == canonical_action_block
                    .height
                    .checked_add(1)
                    .ok_or_else(|| eyre!("native ZK-X509 sentinel height overflowed"))?
                && sentinel_block.parent_hash == Some(canonical_action_block.hash)
                && sentinel_block.hash != canonical_action_block.hash,
            "native ZK-X509 sentinel is not the exact adjacent successor of the canonical \
             action: action={canonical_action_block:?}, \
             sentinel={sentinel_block:?}"
        );
        wait_for_transaction_on_peers(
            &healthy_clients,
            &catch_up_transaction,
            "three-validator direct query of native ZK-X509 catch-up sentinel finality",
        )
        .await?;
        timeout(
            RESTART_TIMEOUT,
            restart_peer.start_checked(config_layers.iter(), None),
        )
        .await
        .map_err(|_| eyre!("native ZK-X509 peer restart exceeded {RESTART_TIMEOUT:?}"))?
        .wrap_err("restart native ZK-X509 validator from persisted state")?;
        let recovered_clients = network
            .peers()
            .iter()
            .map(|peer| bounded_client(peer.client()))
            .collect::<Vec<_>>();
        let recovered_sentinel = wait_for_all_signed_tip(
            &recovered_clients,
            &catch_up_transaction,
            Some(sentinel_block),
            RESTART_TIMEOUT,
            "restarted validator must recover the exact sentinel height, hash, and parent",
        )
        .await?;
        ensure!(
            recovered_sentinel == sentinel_block,
            "post-restart sentinel identity drifted: expected {sentinel_block:?}, got \
             {recovered_sentinel:?}"
        );
        wait_for_available_snapshots(
            &recovered_clients,
            sentinel_block.height,
            compiled_snapshot,
            active,
            PrivacyCapabilityReadinessV1::Unavailable(
                PrivacyCapabilityUnavailableReasonV1::MissingProductionQualification,
            ),
            "post-restart byte-identical active ZK-X509 manifests at the exact sentinel",
        )
        .await?;
        wait_for_transaction_on_peers(
            &recovered_clients,
            &actions.canonical_transaction,
            "post-restart canonical native ZK-X509 transaction visibility",
        )
        .await?;
        wait_for_transaction_on_peers(
            &recovered_clients,
            &catch_up_transaction,
            "post-restart native ZK-X509 successor sentinel visibility",
        )
        .await?;
        wait_for_transaction_result_on_peers(
            &recovered_clients,
            &actions.malformed_transaction,
            false,
            "post-restart malformed native ZK-X509 rejection visibility",
        )
        .await?;
        wait_for_transaction_on_peers(
            &recovered_clients,
            &actions.canonical_transaction,
            "post-restart all-four canonical native ZK-X509 visibility",
        )
        .await?;
        let restarted_client = recovered_clients[restart_index].clone();
        let semantic_base_block = timeout(
            SEMANTIC_TIME_ADVANCE_TIMEOUT,
            advance_to_semantic_base_after_crl_second(
                &recovered_clients,
                &restarted_client,
                recovered_sentinel,
                actions.crl.this_update_unix_seconds,
            ),
        )
        .await
        .map_err(|_| {
            eyre!(
                "bounded all-four native ZK-X509 semantic-time advance exceeded \
                 {SEMANTIC_TIME_ADVANCE_TIMEOUT:?}"
            )
        })??;
        let semantic_trusted_block_timestamp_ms = semantic_base_block.creation_time_ms;
        ensure!(
            semantic_trusted_block_timestamp_ms / 1_000
                > actions.crl.this_update_unix_seconds,
            "native ZK-X509 semantic base did not strictly advance beyond predecessor CRL \
             thisUpdate: base={semantic_base_block:?}, predecessor_second={}",
            actions.crl.this_update_unix_seconds
        );
        let semantic_action_context = PrivacyReleaseTransactionContextV1 {
            network_id: *restarted_client.client().network_id(),
            authority: restarted_client.client().account().clone(),
            creation_time: now_duration()?,
            time_to_live: Some(ACTION_TTL),
            nonce: NonZeroU32::new(50_008),
            fee_payment: no_fee(),
            metadata: tagged_metadata(50_008)?,
            genesis_hash,
        };
        let semantic_signing_key = restarted_client.client().key_pair().private_key().clone();
        let semantic_resource_certificate = resource_certificate.clone();
        let current_crl = actions.crl.clone();
        let build_semantic_replay = tokio::task::spawn_blocking(move || {
            build_privacy_release_zk_x509_semantic_replay_v1(
                semantic_action_context,
                semantic_trusted_block_timestamp_ms,
                current_crl,
                [0x6B; 32],
                &semantic_resource_certificate,
                SUBMISSION_TIMEOUT,
                &semantic_signing_key,
            )
            .map_err(|error| eyre!("build fresh native ZK-X509 semantic replay: {error:?}"))
        });
        let semantic_replay: PrivacyReleaseZkX509SemanticReplayV1 =
            timeout(prover_timeout, build_semantic_replay)
                .await
                .map_err(|_| {
                    eyre!(
                        "fresh native ZK-X509 semantic replay construction exceeded its own \
                         authenticated {prover_timeout:?} proof budget that preserves the \
                         {SUBMISSION_TIMEOUT:?} admission reserve"
                    )
                })?
                .map_err(|error| eyre!("fresh native ZK-X509 prover task failed: {error}"))??;
        let original_intent = actions
            .canonical_transaction
            .privacy_transaction_intent_digest_v1()
            .wrap_err("derive original native ZK-X509 transaction intent")?;
        let semantic_intent = semantic_replay
            .transaction
            .privacy_transaction_intent_digest_v1()
            .wrap_err("derive fresh native ZK-X509 transaction intent")?;
        ensure!(
            actions.statement.context.action_index == 0
                && semantic_replay.statement.context.action_index == 0
                && actions.canonical_transaction.nonce() == NonZeroU32::new(50_002)
                && semantic_replay.transaction.nonce() == NonZeroU32::new(50_008)
                && semantic_replay.transaction.nonce()
                    != actions.canonical_transaction.nonce()
                && semantic_intent == semantic_replay.statement.context.transaction_intent_digest
                && semantic_intent != original_intent
                && semantic_replay.transaction.hash() != actions.canonical_transaction.hash(),
            "fresh native ZK-X509 semantic replay did not preserve index zero while changing its \
             nonce, intent, and signed transaction hash"
        );
        ensure!(
            single_zk_x509_proof_bytes(&actions.canonical_transaction, &actions.statement)?
                != single_zk_x509_proof_bytes(
                    &semantic_replay.transaction,
                    &semantic_replay.statement,
                )?,
            "fresh native ZK-X509 semantic replay reproduced the original proof bytes"
        );
        let expected_semantic_time = semantic_trusted_block_timestamp_ms / 1_000;
        let expected_semantic_deadline = expected_semantic_time
            .checked_add(300)
            .ok_or_else(|| eyre!("fresh native ZK-X509 presentation deadline overflowed"))?;
        ensure!(
            semantic_replay.statement.certificate_nullifier
                == actions.statement.certificate_nullifier
                && semantic_replay.statement.trust_anchor_record_digest
                    == actions.statement.trust_anchor_record_digest
                && semantic_replay
                    .statement
                    .certificate_policy_record_digest
                    == actions.statement.certificate_policy_record_digest
                && semantic_replay.statement.crl_record_digest
                    == semantic_replay.crl_successor.record_digest
                && semantic_replay.statement.crl_record_epoch
                    == semantic_replay.crl_successor.record_epoch
                && semantic_replay.statement.presentation_not_before_unix_seconds
                    == expected_semantic_time
                && semantic_replay.statement.presentation_not_after_unix_seconds
                    == expected_semantic_deadline,
            "fresh native ZK-X509 semantic replay changed certificate identity or failed to bind \
             the committed-time successor CRL window"
        );
        ensure!(
            semantic_replay.crl_successor.record_epoch
                == actions
                    .crl
                    .record_epoch
                    .checked_add(1)
                    .ok_or_else(|| eyre!("native ZK-X509 CRL epoch overflowed"))?
                && semantic_replay.crl_successor.crl_number
                    == actions
                        .crl
                        .crl_number
                        .checked_add(1)
                        .ok_or_else(|| eyre!("native ZK-X509 CRLNumber overflowed"))?
                && semantic_replay.crl_successor.previous_record_digest
                    == Some(actions.crl.record_digest)
                && semantic_replay.crl_successor.trust_anchor_id == actions.crl.trust_anchor_id
                && semantic_replay.crl_successor.certificate_policy_id
                    == actions.crl.certificate_policy_id
                && semantic_replay.crl_successor.issuer_spki_digest
                    == actions.crl.issuer_spki_digest
                && semantic_replay.crl_successor.crl_der_digest != actions.crl.crl_der_digest
                && semantic_replay.crl_successor.this_update_unix_seconds
                    == expected_semantic_time
                && semantic_replay.crl_successor.this_update_unix_seconds
                    > actions.crl.this_update_unix_seconds
                && semantic_replay.crl_successor.next_update_unix_seconds
                    == expected_semantic_deadline
                        .checked_add(1)
                        .ok_or_else(|| eyre!("native ZK-X509 CRL nextUpdate overflowed"))?,
            "fresh native ZK-X509 CRL is not the exact signed epoch/number/digest-linked successor"
        );
        let (crl_rotation_transaction, _) = submit_instruction(
            &restarted_client,
            RotatePrivacyZkX509CrlV1::new(
                actions.crl.record_digest,
                semantic_replay.crl_successor.clone(),
            ),
            50_007,
            "rotate native ZK-X509 to the fresh signed-CRL successor through the restarted validator",
        )
        .await?;
        ensure!(
            crl_rotation_transaction.nonce() == NonZeroU32::new(50_007)
                && semantic_replay.transaction.nonce() == NonZeroU32::new(50_008),
            "fresh signed-CRL rotation and semantic replay nonces do not follow submission order"
        );
        let crl_rotation_block = wait_for_all_signed_tip(
            &recovered_clients,
            &crl_rotation_transaction,
            None,
            PEER_CONVERGENCE_TIMEOUT,
            "all four validators must finalize the exact fresh signed-CRL rotation",
        )
        .await?;
        ensure!(
            crl_rotation_block.height
                == semantic_base_block
                    .height
                    .checked_add(1)
                    .ok_or_else(|| eyre!("native ZK-X509 CRL rotation height overflowed"))?
                && crl_rotation_block.parent_hash == Some(semantic_base_block.hash),
            "fresh signed-CRL rotation is not the exact successor of the semantic base: \
             base={semantic_base_block:?}, rotation={crl_rotation_block:?}"
        );
        wait_for_transaction_on_peers(
            &recovered_clients,
            &crl_rotation_transaction,
            "all-four direct query of the fresh signed-CRL rotation",
        )
        .await?;
        require_live_x509_submission_window(
            &restarted_client,
            &semantic_replay.statement,
            "pre-submit fresh post-restart native ZK-X509 semantic replay",
        ).await?;
        let semantic_replay_error = submit_expecting_rejection(
            &restarted_client,
            &semantic_replay.transaction,
            "submit fresh native ZK-X509 semantic replay through the restarted validator",
            "fresh native ZK-X509 semantic replay was accepted despite its consumed certificate nullifier",
        )
        .await?;
        ensure!(
            error_chain_contains(
                &semantic_replay_error,
                DUPLICATE_CERTIFICATE_NULLIFIER_MESSAGE,
            ),
            "fresh native ZK-X509 semantic replay rejected for the wrong category: \
             {semantic_replay_error:?}"
        );
        let semantic_rejection_block = wait_for_all_signed_tip(
            &recovered_clients,
            &semantic_replay.transaction,
            None,
            PEER_CONVERGENCE_TIMEOUT,
            "all four validators must finalize one exact rejected semantic-replay result",
        )
        .await?;
        ensure!(
            semantic_rejection_block.height
                == crl_rotation_block
                    .height
                    .checked_add(1)
                    .ok_or_else(|| eyre!("native ZK-X509 rejection height overflowed"))?
                && semantic_rejection_block.parent_hash == Some(crl_rotation_block.hash),
            "fresh semantic replay rejection produced a missing or unintended extra tip: \
             rotation={crl_rotation_block:?}, rejection={semantic_rejection_block:?}"
        );
        wait_for_transaction_result_on_peers(
            &recovered_clients,
            &semantic_replay.transaction,
            false,
            "fresh native ZK-X509 duplicate-nullifier rejection convergence",
        )
        .await?;
        assert_all_exact_duplicate_certificate_nullifier_results(
            &recovered_clients,
            &semantic_replay.transaction,
            "fresh native ZK-X509 duplicate-nullifier exact result identity",
        ).await?;
        assert_all_exact_tip(
            &recovered_clients,
            semantic_rejection_block,
            "fresh semantic replay rejection must leave every validator at its one exact result tip",
        ).await?;
        let (successor_transaction, _) = submit_instruction(
            &restarted_client,
            Log::new(
                Level::INFO,
                "native ZK-X509 all-four post-restart successor".to_owned(),
            ),
            50_009,
            "submit native ZK-X509 successor through the restarted validator",
        )
        .await?;
        ensure!(
            successor_transaction.nonce() == NonZeroU32::new(50_009),
            "post-restart liveness successor lost its ordered transaction nonce"
        );
        let successor_block = wait_for_all_signed_tip(
            &recovered_clients,
            &successor_transaction,
            None,
            PEER_CONVERGENCE_TIMEOUT,
            "all four validators must finalize one exact post-restart successor",
        )
        .await?;
        ensure!(
            successor_block.height
                == semantic_rejection_block
                    .height
                    .checked_add(1)
                    .ok_or_else(|| eyre!("native ZK-X509 successor height overflowed"))?
                && successor_block.parent_hash == Some(semantic_rejection_block.hash)
                && successor_block.hash != semantic_rejection_block.hash,
            "post-restart block is not the exact adjacent successor of the semantic-replay \
             rejection: rejection={semantic_rejection_block:?}, successor={successor_block:?}"
        );
        wait_for_transaction_on_peers(
            &recovered_clients,
            &successor_transaction,
            "all-four direct query of the exact post-restart successor",
        )
        .await?;
        wait_for_available_snapshots(
            &recovered_clients,
            successor_block.height,
            compiled_snapshot,
            active,
            PrivacyCapabilityReadinessV1::Unavailable(
                PrivacyCapabilityUnavailableReasonV1::MissingProductionQualification,
            ),
            "all-four byte-identical active ZK-X509 manifests at the exact successor",
        )
        .await?;
        for (index, replay_client) in recovered_clients.iter().enumerate() {
            let post_restart_replay_error = timeout(SUBMISSION_TIMEOUT, replay_client.account_client().submit_transaction(&actions.canonical_transaction)).await.map_err(|_| eyre!("post-restart native ZK-X509 replay to peer {index} submission exceeded {SUBMISSION_TIMEOUT:?}"))?
                .wrap_err_with(|| format!("submit exact native ZK-X509 replay to peer {index}"))
                .expect_err("post-restart peer accepted exact native ZK-X509 replay");
            ensure!(
                is_exact_committed_transaction_replay(&post_restart_replay_error),
                "post-restart peer {index} rejected native ZK-X509 replay without the exact \
                 committed-duplicate code and reason: {post_restart_replay_error:?}"
            );
            assert_all_exact_tip(
                &recovered_clients,
                successor_block,
                &format!(
                    "post-restart replay through peer {index} must not advance any validator"
                ),
            ).await?;
        }
        wait_for_transaction_on_peers(
            &recovered_clients,
            &actions.canonical_transaction,
            "all-four direct post-replay query of canonical native ZK-X509 finality",
        )
        .await?;
        for (index, recovered_client) in recovered_clients.iter().enumerate() {
            ensure!(
                canonical_genesis_hash(recovered_client).await? == genesis_hash,
                "post-restart peer {index} derived a different canonical genesis hash"
            );
        }
        println!(
            "TAIRA_PRIVACY_PROTOCOL_FOUR_PEER_CASE_V1:privacy_exact12_zk_x509_network::canonical_zk_x509_action_survives_four_peer_activation_replay_and_restart:passed"
        );
        Ok(())
    }
    .await;
    network.shutdown().await;
    result
}
