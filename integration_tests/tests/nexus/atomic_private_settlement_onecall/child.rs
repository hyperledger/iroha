//! One fresh SDK process per continuation; only original caller inputs enter on stdin.
//!
//! Child success is a normal process exit, not an injected crash. Journal acknowledgement
//! loss and actual validator restarts are recorded as distinct failure boundaries.
use super::*;
use iroha::client::PrivateSettlementRunOptions;
use iroha::workflow::{
    Digest32, FileWorkflowStorage, WorkflowId, WorkflowJournalV1, WorkflowRunnerLease,
    WorkflowStorage, WorkflowStorageDurability, WorkflowStorageError, WorkflowStorageErrorKind,
};
use iroha_data_model::{
    nexus::{PrivateSettlementProofIntentV1, PrivateSettlementReceiptV1},
    parameter::system::ConsensusMode,
    sumeragi_finality::{
        SignedGenesisPinsV1, SumeragiFinalityVerifier, authenticate_signed_genesis_v1,
    },
};
use iroha_private_settlement::{
    FilePrivateSettlementArtifacts, OneCallPrivateSettlementOperation,
    OneCallPrivateSettlementRequest, PrivateSettlementBusinessTerms,
};
use std::{
    io::Read,
    path::Path,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const CHILD_INPUT_MAX: u64 = 32 * 1024 * 1024;
pub(super) const CHILD_REPORT_MAX: usize = 512 * 1024;
pub(super) const CHILD_LOG_MAX: usize = 1024 * 1024;
const ARTIFACT_FILE_MAX: usize = 32 * 1024 * 1024 + 28;

/// Closed fixture controls, never protocol or node configuration switches.
#[derive(Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "integration_tests::private_onecall::Mode")]
pub(super) enum Mode {
    ReadOnly,
    Unaudited,
    Finish,
    Checkpoint(u8),
}
impl Mode {
    pub(super) fn label(self) -> String {
        match self {
            Self::ReadOnly => "read_only".to_owned(),
            Self::Unaudited => "unaudited".to_owned(),
            Self::Finish => "finish".to_owned(),
            Self::Checkpoint(step) => format!("checkpoint_{step}"),
        }
    }
    fn validate(self) -> Result<()> {
        ensure!(
            !matches!(self, Self::Checkpoint(step) if step > 3),
            "unknown cold SDK phase"
        );
        Ok(())
    }
}

/// Data-only transport of separately selected pins; decoding cannot confer authority.
#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "integration_tests::private_onecall::Pins")]
pub(super) struct Pins {
    chain: String,
    network: iroha_data_model::NetworkId,
    genesis_hash: HashOf<BlockHeader>,
    signed_genesis_sha256: [u8; 32],
    genesis_key: iroha_crypto::PublicKey,
    roster: Vec<PeerId>,
    mode: ConsensusMode,
}
impl Pins {
    pub(super) fn from_network(network: &Network, wire: &[u8]) -> Result<Self> {
        use sha2::{Digest as _, Sha256};
        let mut roster = network
            .validators()
            .iter()
            .map(|peer| peer.id())
            .collect::<Vec<_>>();
        roster.sort();
        Ok(Self {
            chain: network.chain_id().to_string(),
            network: network.network_id(),
            genesis_hash: network.genesis().0.hash(),
            signed_genesis_sha256: Sha256::digest(wire).into(),
            genesis_key: iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR
                .public_key()
                .clone(),
            roster,
            mode: ConsensusMode::Npos,
        })
    }
    fn selected(&self) -> SignedGenesisPinsV1 {
        SignedGenesisPinsV1 {
            chain_id: self.chain.clone(),
            network_id: self.network,
            genesis_hash: self.genesis_hash,
            signed_genesis_sha256: self.signed_genesis_sha256,
            genesis_public_key: self.genesis_key.clone(),
            roster: self.roster.clone(),
            mode: self.mode,
        }
    }
}
#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "integration_tests::private_onecall::ChildInput")]
pub(super) struct ChildInput {
    pub(super) intent: PrivateSettlementProofIntentV1,
    pub(super) policy_activation: u64,
    pub(super) original_genesis: Vec<u8>,
    pub(super) pins: Pins,
    pub(super) endpoint: String,
    pub(super) endpoints: Vec<Vec<String>>,
    pub(super) account_chain_discriminant: u16,
    pub(super) custody_path: String,
    pub(super) invocation: [u8; 32],
    pub(super) mode: Mode,
    pub(super) sequence: u64,
    pub(super) deadline_unix_ms: u64,
    pub(super) schema: Hash,
    pub(super) minimum_context_time_ms: u64,
    // Runtime-only: original caller retains this key; stdin is its only serialized transport.
    pub(super) artifact_key: [u8; 32],
}
impl Drop for ChildInput {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.artifact_key.zeroize();
    }
}
impl ChildInput {
    pub(super) fn binding(&self) -> Result<Hash> {
        let mut public = self.clone();
        public.artifact_key.fill(0);
        Ok(Hash::new(norito::encode_canonical(&public)?))
    }
    fn report_name(&self) -> String {
        format!(
            "child-{:03}-{}.norito",
            self.sequence,
            hex::encode(self.invocation)
        )
    }
}
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "integration_tests::private_onecall::ChildReport")]
pub(super) struct ChildReport {
    pub(super) pid: u32,
    binding: Hash,
    pub(super) preparation_id: [u8; 32],
    pub(super) settlement_id: Option<[u8; 32]>,
    pub(super) prepared: Option<PreparedPublic>,
    pub(super) receipt: Option<PrivateSettlementReceiptV1>,
    pub(super) evidence: Option<iroha_data_model::query::CommittedTransaction>,
    pub(super) openings: u64,
    pub(super) reservations: u64,
}

pub(super) fn unix_ms() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn remaining(input: &ChildInput) -> Result<Duration> {
    let remaining = input
        .deadline_unix_ms
        .checked_sub(unix_ms()?)
        .filter(|v| *v > 0)
        .ok_or_else(|| eyre!("original cold SDK deadline elapsed"))?;
    ensure!(
        remaining <= COLD_CASE_LIMIT.as_millis() as u64,
        "cold SDK deadline exceeds original finite bound"
    );
    Ok(Duration::from_millis(remaining))
}
fn directory_snapshot(
    root: &iroha_fs::PrivateDirectory,
    folder: &str,
    maximum_files: usize,
) -> Result<Vec<(String, Hash)>> {
    let directory = iroha_fs::PrivateDirectory::open_exact(root.path().join(folder))?;
    let mut names = Vec::new();
    directory.visit_private_files(maximum_files, |name, metadata| {
        if metadata.len() > ARTIFACT_FILE_MAX as u64 {
            return Err(std::io::Error::other("original custody file exceeds bound"));
        }
        names.push(
            name.to_str()
                .ok_or_else(|| std::io::Error::other("invalid custody name"))?
                .to_owned(),
        );
        Ok(())
    })?;
    names.sort();
    names
        .into_iter()
        .map(|name| {
            Ok((
                format!("{folder}/{name}"),
                Hash::new(&*directory.read(&name, ARTIFACT_FILE_MAX)?),
            ))
        })
        .collect()
}
pub(super) fn artifact_snapshot(root: &iroha_fs::PrivateDirectory) -> Result<Vec<(String, Hash)>> {
    let files = directory_snapshot(root, "encrypted-artifacts", 4)?;
    ensure!(
        files.len() == 4
            && files
                .iter()
                .filter(|(name, _)| name.ends_with(".contexts"))
                .count()
                == 1
            && files
                .iter()
                .filter(|(name, _)| name.ends_with(".prepared"))
                .count()
                == 3,
        "cold N3 must retain one original context and three genuine prepared artifacts"
    );
    Ok(files)
}
fn workflow_snapshot(
    root: &iroha_fs::PrivateDirectory,
    folder: &str,
    maximum: usize,
    effects_only: bool,
) -> Result<Vec<(String, Hash)>> {
    let directory = root.open_child(folder)?;
    let mut names = directory.entries(maximum)?;
    names.sort();
    let mut result = Vec::new();
    let mut worker_round = None;
    let mut lease_rows = Vec::new();
    let mut drivers = std::collections::BTreeSet::new();
    for name in names {
        let text = name
            .to_str()
            .ok_or_else(|| eyre!("invalid workflow custody name"))?;
        ensure!(
            text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()),
            "unexpected workflow directory"
        );
        let workflow = directory.open_child(&name)?;
        let files = workflow.entries(3)?;
        ensure!(
            files.iter().all(|file| ["journal", "lock", "runner"]
                .iter()
                .any(|expected| file.as_os_str() == *expected)),
            "unexpected workflow custody file"
        );
        let mut id = [0; 32];
        hex::decode_to_slice(text, &mut id)?;
        ensure!(
            text == hex::encode(id),
            "noncanonical workflow directory identity"
        );
        let storage = FileWorkflowStorage::open_or_create(directory.path())?;
        if let Some(bytes) = storage.load(&WorkflowId::from_bytes(id))? {
            let digest = if effects_only {
                let journal = WorkflowJournalV1::decode_record(&bytes)?;
                ensure!(
                    matches!(
                        journal.identity.driver.id.as_str(),
                        "private_settlement_preparation" | "private_settlement"
                    ) && drivers.insert(journal.identity.driver.id.clone()),
                    "unexpected or duplicate original workflow driver"
                );
                if journal.identity.driver.id == "private_settlement_preparation" {
                    worker_round = journal
                        .steps
                        .first()
                        .and_then(|step| step.round.as_ref())
                        .and_then(|round| round.round_id);
                }
                let effects = journal
                    .steps
                    .iter()
                    .map(|step| {
                        (
                            step.transaction.as_ref().map(|tx| {
                                tx.attempts
                                    .iter()
                                    .map(|attempt| {
                                        (
                                            attempt.ordinal,
                                            attempt.identity,
                                            attempt.dispatch_ordinal,
                                        )
                                    })
                                    .collect::<Vec<_>>()
                            }),
                            step.round
                                .as_ref()
                                .map(|round| (round.round_id, round.start_ordinal)),
                        )
                    })
                    .collect::<Vec<_>>();
                // Recovery may durably reconcile observed facts. It may not start a round,
                // create a new signed identity, or increment any original dispatch ordinal.
                Hash::new(norito::encode_canonical(&(journal.identity, effects))?)
            } else {
                Hash::new(&*bytes)
            };
            result.push((format!("{folder}/{text}/journal"), digest));
        } else {
            ensure!(
                effects_only
                    && files.len() == 2
                    && files.iter().all(|file| ["lock", "runner"]
                        .iter()
                        .any(|expected| file.as_os_str() == *expected)),
                "unexpected journal-less custody row"
            );
            lease_rows.push(text.to_owned());
        }
    }
    if effects_only {
        require_original_worker_lease(worker_round, &lease_rows)?;
        for name in lease_rows {
            // Pin the storage-owned lease identity. Lock contents are not application state.
            result.push((
                format!("{folder}/{name}/proof-worker-lease"),
                Hash::new(name.as_bytes()),
            ));
        }
        result.sort_by(|left, right| left.0.cmp(&right.0));
    }
    Ok(result)
}
fn require_original_worker_lease(round: Option<Digest32>, leases: &[String]) -> Result<()> {
    let expected = round.map(|round| {
        hex::encode(iroha::workflow::domain_digest(
            b"iroha:private-settlement:proof-worker:v1\0",
            &[&round],
        ))
    });
    ensure!(
        match expected {
            Some(expected) => leases == [expected],
            None => leases.is_empty(),
        },
        "proof-worker lease does not bind the original preparation round"
    );
    Ok(())
}
pub(super) fn custody_snapshot(root: &iroha_fs::PrivateDirectory) -> Result<Vec<(String, Hash)>> {
    let mut files = directory_snapshot(root, "encrypted-artifacts", 4)?;
    // Two actual workflow journals plus exactly one canonical proof-worker lease-only row.
    // The lease has no monetary journal; its identity is derived from the original round.
    files.extend(workflow_snapshot(root, "journals", 3, true)?);
    files.extend(workflow_snapshot(root, "wallet-reservations", 3, false)?);
    Ok(files)
}

struct CheckpointStorage {
    inner: FileWorkflowStorage,
    selected_step: Option<usize>,
    interrupted: AtomicBool,
}
impl WorkflowStorage for CheckpointStorage {
    fn durability(&self) -> WorkflowStorageDurability {
        self.inner.durability()
    }
    fn load(&self, id: &WorkflowId) -> std::result::Result<Option<Vec<u8>>, WorkflowStorageError> {
        self.inner.load(id)
    }
    fn acquire_runner(
        &self,
        id: &WorkflowId,
    ) -> std::result::Result<Box<dyn WorkflowRunnerLease>, WorkflowStorageError> {
        self.inner.acquire_runner(id)
    }
    fn compare_and_store(
        &self,
        id: &WorkflowId,
        expected: Option<&Digest32>,
        bytes: &[u8],
    ) -> std::result::Result<(), WorkflowStorageError> {
        let checkpoint = self.selected_step.is_some_and(|step| {
            WorkflowJournalV1::decode_record(bytes).is_ok_and(|journal| {
                journal.identity.driver.id == "private_settlement"
                    && journal
                        .steps
                        .get(step)
                        .is_some_and(|record| record.is_done())
            })
        });
        self.inner.compare_and_store(id, expected, bytes)?;
        if checkpoint && !self.interrupted.swap(true, Ordering::SeqCst) {
            return Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::WriteUncertain,
                "test acknowledgement loss after exact durable settlement checkpoint",
            ));
        }
        Ok(())
    }
}
fn client(input: &ChildInput) -> Result<iroha::client::AccountClient> {
    use iroha_config_base::{
        read::ConfigReader,
        toml::{TomlSource, Writer as TomlWriter},
    };
    let config = ConfigReader::new()
        .without_env()
        .with_toml_source(TomlSource::inline(
            TomlWriter::new()
                .write("chain", input.pins.chain.clone())
                .write("network_id", input.intent.network_id.to_string())
                .write(
                    ["account", "chain_discriminant"],
                    i64::from(input.account_chain_discriminant),
                )
                .write(
                    ["account", "public_key"],
                    ALICE_KEYPAIR.public_key().to_string(),
                )
                .write(
                    ["account", "private_key"],
                    iroha_crypto::ExposedPrivateKey(ALICE_KEYPAIR.private_key().clone())
                        .to_string(),
                )
                .write("torii_url", input.endpoint.clone())
                .write("torii_request_timeout_ms", 300_000_i64)
                .write(["transaction", "status_timeout_ms"], 300_000_i64)
                .write(["transaction", "time_to_live_ms"], 600_000_i64)
                .finish(),
        ))
        .read_and_complete::<iroha::config::UserConfig>()?
        .parse()?;
    Ok(SdkClient::builder(config).build()?.account_client()?)
}
pub(super) fn verifier(input: &ChildInput) -> Result<SumeragiFinalityVerifier> {
    ensure!(
        input.intent.network_id == input.pins.network,
        "caller intent substituted original network pin"
    );
    let pins = input.pins.selected();
    let authenticated = authenticate_signed_genesis_v1(&input.original_genesis, &pins)?;
    Ok(SumeragiFinalityVerifier::new(
        authenticated.block(),
        &pins.chain_id,
        authenticated.validators().to_vec(),
    )?)
}
fn options(input: &ChildInput) -> Result<PrivateSettlementRunOptions> {
    Ok(PrivateSettlementRunOptions {
        workflow: iroha::workflow::WorkflowRunOptions {
            observation_timeout: remaining(input)?.min(FINALITY_TIMEOUT),
            poll_interval: POLL_INTERVAL,
            retransmit_identical_bytes: false,
            retry_rejected_step: false,
        },
        ..Default::default()
    })
}
fn execute(input: ChildInput) -> Result<ChildReport> {
    input.mode.validate()?;
    remaining(&input)?;
    let original_verifier = verifier(&input)?; // Authenticate independently selected pins before opening any wallet.
    let root = Path::new(&input.custody_path);
    iroha_fs::PrivateDirectory::open_exact(root)?;
    let routes = input
        .intent
        .legs
        .iter()
        .map(|leg| leg.route)
        .collect::<Vec<_>>();
    let wallet = Arc::new(wallet::OriginalWallet::open(
        &routes,
        input.policy_activation,
        input.intent.expiry_height,
        &root.join("wallet-reservations"),
    )?);
    let storage = Arc::new(CheckpointStorage {
        inner: FileWorkflowStorage::open_or_create(root.join("journals"))?,
        selected_step: match input.mode {
            Mode::Checkpoint(step) => Some(usize::from(step)),
            _ => None,
        },
        interrupted: AtomicBool::new(false),
    });
    let artifacts = Arc::new(FilePrivateSettlementArtifacts::open(
        root.join("encrypted-artifacts"),
        &input.artifact_key,
    )?);
    let terms = input
        .intent
        .legs
        .iter()
        .enumerate()
        .map(|(ordinal, _)| {
            let data = default_private_settlement_leg_data(ordinal);
            PrivateSettlementBusinessTerms {
                asset: cbdc_asset_definition_id(ordinal),
                payer: AccountId::new(data.payer.public_key().clone()),
                recipient: AccountId::new(data.recipient.public_key().clone()),
                amount: data.amount,
                reimbursement: if ordinal == usize::from(input.intent.reimbursement_leg_ordinal) {
                    5
                } else {
                    0
                },
                memo: data.memo,
            }
        })
        .collect();
    let endpoints = input
        .endpoints
        .iter()
        .map(|row| {
            row.iter()
                .map(|url| Url::parse(url).map_err(eyre::Report::new))
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    let request = OneCallPrivateSettlementRequest::new(
        input.intent.clone(),
        terms,
        input.schema,
        input.minimum_context_time_ms,
        endpoints,
        PrivateSettlementCapsulePaddingV1::KiB16,
        input.intent.expiry_height + SIDECAR_RETENTION_BLOCKS,
        PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1 as u64,
        32 * 1024 * 1024,
        128 * 1024 * 1024,
    )?;
    let account = client(&input)?;
    let operation = OneCallPrivateSettlementOperation::new(
        account.clone(),
        request,
        storage.clone(),
        artifacts,
        wallet.clone(),
        original_verifier,
    )?;
    let preparation_id = *operation.id().as_bytes();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let recovered = runtime.block_on(operation.recover(&options(&input)?))?;
    ensure!(
        wallet.openings.load(Ordering::SeqCst) == 0
            && wallet.reservations_called.load(Ordering::SeqCst) == 0,
        "cold readonly recovery cannot reopen wallet secrets or acquire notes"
    );
    let verified = if input.mode == Mode::ReadOnly {
        recovered.receipt
    } else {
        wallet.enable_explicit_continuation();
        let result = runtime.block_on(operation.run(&options(&input)?));
        if matches!(input.mode, Mode::Checkpoint(_)) {
            ensure!(
                storage.interrupted.load(Ordering::SeqCst) && result.is_err(),
                "explicit continuation did not reach its original durable phase checkpoint"
            );
            None
        } else if input.mode == Mode::Unaudited {
            ensure!(
                matches!(&result, Err(iroha_private_settlement::OneCallPrivateSettlementError::Settlement(iroha::client::PrivateSettlementError::Workflow(error))) if error.step_index == Some(1) && error.code == iroha::workflow::WorkflowErrorCode::LocalResourceUnavailable),
                "unaudited original must stop at Prepare: {result:?}"
            );
            None
        } else {
            ensure!(input.mode == Mode::Finish, "unknown cold SDK fixture mode");
            Some(result?.receipt)
        }
    };
    let prepared = runtime.block_on(operation.prepared_request(&options(&input)?))?;
    let (settlement_id, public) = if let Some(prepared) = &prepared {
        let settlement =
            account.private_settlement(prepared.clone(), storage.clone(), verifier(&input)?)?;
        let id = settlement.id();
        let journal = storage
            .load(&id)?
            .ok_or_else(|| eyre!("prepared child omitted original settlement journal"))?;
        let journal = WorkflowJournalV1::decode_record(&journal)?;
        let certificates = journal.steps[0]
            .round
            .as_ref()
            .and_then(|round| round.transcript.as_deref())
            .ok_or_else(|| eyre!("original availability transcript absent"))?;
        let certificates: Vec<PrivateSettlementSidecarAvailabilityV1> =
            norito::decode_canonical(certificates)?;
        (
            Some(*id.as_bytes()),
            Some(PreparedPublic::from_materials(
                prepared.materials(),
                &certificates,
            )?),
        )
    } else {
        (None, None)
    };
    let evidence = verified.as_ref().map(|value| value.evidence().clone());
    let receipt = verified.as_ref().map(|value| value.receipt().clone());
    // Drop every material/operation/verifier owner before the process returns its public
    // report. Parent continuation always spawns a new executable and reconstructs inputs.
    drop(prepared);
    drop(verified);
    drop(operation);
    drop(account);
    drop(runtime);
    Ok(ChildReport {
        pid: std::process::id(),
        binding: input.binding()?,
        preparation_id,
        settlement_id,
        prepared: public,
        receipt,
        evidence,
        openings: wallet.openings.load(Ordering::SeqCst) as u64,
        reservations: wallet.reservations_called.load(Ordering::SeqCst) as u64,
    })
}

pub(super) fn test_filter() -> Result<String> {
    let (_, module) = module_path!()
        .split_once("::")
        .ok_or_else(|| eyre!("cold child module not nested in test crate"))?;
    Ok(format!("{module}::cold_sdk_child"))
}
fn validate_report(report: &ChildReport, input: &ChildInput, pid: u32) -> Result<()> {
    ensure!(
        report.pid == pid && pid != std::process::id() && report.binding == input.binding()?,
        "report substituted original invocation, phase, pins or actual child process"
    );
    if input.mode == Mode::ReadOnly {
        ensure!(report.openings == 0 && report.reservations == 0);
    }
    Ok(())
}
pub(super) struct CompletedChild {
    pub(super) report: ChildReport,
    pub(super) report_bytes: Vec<u8>,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}
async fn read_log(reader: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;
    let mut bytes = Vec::new();
    reader
        .take(CHILD_LOG_MAX as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() <= CHILD_LOG_MAX,
        "cold child output exceeds finite diagnostic bound"
    );
    Ok(bytes)
}
fn require_exact_terminal(stdout: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(stdout)?;
    let expected = format!("test {} ... ok", test_filter()?);
    ensure!(
        text.lines()
            .filter(|line| *line == "running 1 test")
            .count()
            == 1
            && text.lines().filter(|line| *line == expected).count() == 1
            && text
                .lines()
                .filter(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"))
                .count()
                == 1,
        "cold child did not execute exactly its selected internal test"
    );
    Ok(())
}
pub(super) fn spawn(
    runtime: &tokio::runtime::Runtime,
    input: &ChildInput,
    deadline: Instant,
) -> Result<CompletedChild> {
    input.mode.validate()?;
    remaining(input)?;
    let original = zeroize::Zeroizing::new(norito::encode_canonical(input)?);
    ensure!(original.len() as u64 <= CHILD_INPUT_MAX);
    let root = iroha_fs::PrivateDirectory::open_exact(&input.custody_path)?;
    let report_name = input.report_name();
    ensure!(
        root.read_optional(&report_name, CHILD_REPORT_MAX)?
            .is_none(),
        "stale child report already exists"
    );
    let (pid, stdout, stderr) = runtime.block_on(async {
        use tokio::io::AsyncWriteExt as _;
        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .arg(test_filter()?)
            .arg("--exact")
            .arg("--ignored")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let pid = child
            .id()
            .ok_or_else(|| eyre!("child process identity absent"))?;
        let outcome = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| eyre!("child stdout unavailable"))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| eyre!("child stderr unavailable"))?;
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| eyre!("child stdin unavailable"))?;
            let send_and_wait = async {
                stdin.write_all(&original).await?;
                stdin.shutdown().await?;
                drop(stdin);
                let status = child.wait().await?;
                ensure!(status.success(), "fresh cold SDK child failed: {status}");
                Ok::<_, eyre::Report>(())
            };
            let ((), stdout, stderr) =
                tokio::try_join!(send_and_wait, read_log(stdout), read_log(stderr))?;
            Ok::<_, eyre::Report>((stdout, stderr))
        })
        .await;
        if !matches!(outcome, Ok(Ok(_))) {
            // Only this exact owned child is stopped. No node, Cargo, compiler or agent process
            // is targeted. Cleanup gets five seconds solely to reap, never to continue work.
            let _ = child.start_kill();
            tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .wrap_err("cold child cleanup did not reap original process")??;
        }
        let (stdout, stderr) = outcome.wrap_err("original cold SDK deadline elapsed")??;
        require_exact_terminal(&stdout)?;
        Ok::<_, eyre::Report>((pid, stdout, stderr))
    })?;
    ensure!(
        Instant::now() < deadline,
        "child report missed original deadline"
    );
    let bytes = root.read(&report_name, CHILD_REPORT_MAX)?;
    let report: ChildReport = norito::decode_canonical(&bytes)?;
    validate_report(&report, input, pid)?;
    ensure!(
        Instant::now() < deadline,
        "child report read missed original deadline"
    );
    Ok(CompletedChild {
        report,
        report_bytes: bytes.to_vec(),
        stdout,
        stderr,
    })
}
#[test]
#[ignore = "internal bounded-stdin child of the genuine one-call N3 process test"]
fn cold_sdk_child() -> Result<()> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(CHILD_INPUT_MAX + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= CHILD_INPUT_MAX,
        "child requires exact bounded runtime-only request input"
    );
    let input: ChildInput = norito::decode_canonical(&bytes)?;
    drop(bytes);
    input.mode.validate()?;
    remaining(&input)?;
    let root = iroha_fs::PrivateDirectory::open_exact(&input.custody_path)?;
    let name = input.report_name();
    ensure!(
        root.read_optional(&name, CHILD_REPORT_MAX)?.is_none(),
        "child report collision"
    );
    let report = std::thread::Builder::new()
        .name("private-onecall-cold-child".to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(move || execute(input))?
        .join()
        .map_err(|_| eyre!("cold SDK child worker panicked"))??;
    let bytes = norito::encode_canonical(&report)?;
    ensure!(bytes.len() <= CHILD_REPORT_MAX);
    root.write_atomic(name, &bytes, iroha_fs::PublishMode::CreateNew)?;
    Ok(())
}

#[test]
fn cold_child_control_is_closed_and_filter_is_exact() {
    assert!(Mode::Checkpoint(3).validate().is_ok());
    assert!(Mode::Checkpoint(4).validate().is_err());
    assert!(Mode::Checkpoint(u8::MAX).validate().is_err());
    assert!(
        test_filter()
            .unwrap()
            .ends_with("atomic_private_settlement_onecall::child::cold_sdk_child")
    );
}

fn test_input(network: &Network, custody_path: String) -> ChildInput {
    let routes = (0..PARTICIPANT_COUNT)
        .map(|ordinal| PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(ordinal as u64 + 1),
            lane_id: LaneId::new(ordinal as u32 + 1),
            lane_incarnation: hash(0xE0 + ordinal as u8),
        })
        .collect::<Vec<_>>();
    let governed = governed_legs(&routes, 301, 401).unwrap();
    let wire = network.genesis().0.encode_wire().unwrap();
    ChildInput {
        intent: intent(network.network_id(), 301, 401, &governed).unwrap(),
        policy_activation: 301,
        pins: Pins::from_network(network, &wire).unwrap(),
        original_genesis: wire,
        endpoint: "http://127.0.0.1:1/".to_owned(),
        endpoints: vec![vec!["http://127.0.0.1:1/".to_owned()]; 3],
        account_chain_discriminant: network.client().client().account_chain_discriminant(),
        custody_path,
        invocation: [31; 32],
        mode: Mode::ReadOnly,
        sequence: 0,
        deadline_unix_ms: unix_ms().unwrap() + 10_000,
        schema: hash(7),
        minimum_context_time_ms: 0,
        artifact_key: [19; 32],
    }
}
#[test]
fn cold_child_rejects_substituted_signed_genesis_before_wallet_and_binds_reports() {
    let handle = std::thread::Builder::new()
        .stack_size(TEST_STACK_BYTES)
        .spawn(|| {
            let root = tempfile::tempdir().unwrap();
            let original = n3_smoke_builder(TopologyShape::new(PARTICIPANT_COUNT))
                .with_base_seed("cold-original-pins")
                .build();
            let replacement = n3_smoke_builder(TopologyShape::new(PARTICIPANT_COUNT))
                .with_base_seed("cold-replacement-pins")
                .build();
            let mut input = test_input(
                &original,
                root.path()
                    .join("never-opened")
                    .to_str()
                    .unwrap()
                    .to_owned(),
            );
            assert!(verifier(&input).is_ok());
            let pid = std::process::id().wrapping_add(1);
            let report = ChildReport {
                pid,
                binding: input.binding().unwrap(),
                preparation_id: [1; 32],
                settlement_id: None,
                prepared: None,
                receipt: None,
                evidence: None,
                openings: 0,
                reservations: 0,
            };
            assert!(validate_report(&report, &input, pid).is_ok());
            assert!(validate_report(&report, &input, pid.wrapping_add(1)).is_err());
            input.sequence += 1;
            assert!(validate_report(&report, &input, pid).is_err());
            input.sequence -= 1;
            input.mode = Mode::Finish;
            assert!(validate_report(&report, &input, pid).is_err());
            input.mode = Mode::ReadOnly;
            let original_deadline = input.deadline_unix_ms;
            input.deadline_unix_ms = 0;
            assert!(remaining(&input).is_err());
            input.deadline_unix_ms =
                unix_ms().unwrap() + COLD_CASE_LIMIT.as_millis() as u64 + 60_000;
            assert!(remaining(&input).is_err());
            input.deadline_unix_ms = original_deadline;
            input.original_genesis = replacement.genesis().0.encode_wire().unwrap();
            assert!(verifier(&input).is_err());
            assert!(execute(input).is_err());
            assert!(
                !root.path().join("never-opened").exists(),
                "untrusted genesis reached wallet/custody opening"
            );
        })
        .unwrap();
    handle.join().unwrap();
}
#[test]
fn cold_report_custody_refuses_overflow_collision_and_path_escape() {
    let temp = tempfile::tempdir().unwrap();
    let root = iroha_fs::PrivateDirectory::open_or_create(temp.path()).unwrap();
    root.write_atomic("report", &[1; 16], iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(root.read("report", 15).is_err());
    assert!(
        root.write_atomic("report", &[2], iroha_fs::PublishMode::CreateNew)
            .is_err()
    );
    assert!(root.read("../report", 16).is_err());
    assert!(root.read("report", 16).is_ok());
}

#[test]
fn cold_child_terminal_and_logs_are_exact_and_bounded() {
    let terminal = format!(
        "running 1 test\ntest {} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 5 filtered out; finished in 0.01s\n",
        test_filter().unwrap()
    );
    assert!(require_exact_terminal(terminal.as_bytes()).is_ok());
    assert!(require_exact_terminal(b"running 0 tests\ntest result: ok. 0 passed;").is_err());
    assert!(require_exact_terminal(format!("{terminal}{terminal}").as_bytes()).is_err());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert_eq!(
        runtime.block_on(read_log(&b"original"[..])).unwrap(),
        b"original"
    );
    assert!(
        runtime
            .block_on(read_log(&vec![0; CHILD_LOG_MAX + 1][..]))
            .is_err()
    );
}

#[test]
fn cold_snapshot_accepts_only_the_original_round_worker_lease() {
    let original = [7; 32];
    let name = hex::encode(iroha::workflow::domain_digest(
        b"iroha:private-settlement:proof-worker:v1\0",
        &[&original],
    ));
    assert!(require_original_worker_lease(None, &[]).is_ok());
    assert!(require_original_worker_lease(Some(original), &[name.clone()]).is_ok());
    assert!(require_original_worker_lease(None, &[name.clone()]).is_err());
    assert!(require_original_worker_lease(Some(original), &[]).is_err());
    assert!(require_original_worker_lease(Some([8; 32]), &[name.clone()]).is_err());
    assert!(require_original_worker_lease(Some(original), &[name.clone(), name]).is_err());
}
