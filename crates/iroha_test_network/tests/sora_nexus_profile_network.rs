//! Live P1 proofs on four `sora-nexus-v1-qual` validators (`specs/network_deployment.md` §13 P1).
//!
//! - **Unprivileged start.** The stock `iroha3d` runs four profile node files with the validator
//!   overlay (`soracloud_runtime.production_mode = true`) as the invoking user. Every secret is a
//!   fixed file under `data_dir/secrets/`, loaded by `irohad::node_secrets`.
//! - **Beacon pre-deal proof.** The global-beacon genesis session is dealt in process with
//!   `iroha_core::beacon::ceremony` (every seat runs Core's signed all-edge DKG with its own
//!   validator key) against its nominal phase windows before the first start, and each validator
//!   reads its `beacon.cred` at that first start. Ordinary transactions drive the
//!   tip to the session's `finalized_at_height`; `2f + 1` validators pre-sign install certificates
//!   for a range of effective heights, and the certificate for the next height is submitted. The
//!   session installs with no restart, every validator reports its provider ready, `/readyz` turns
//!   200, and the chain crosses a mandatory pulse that verifies against the installed session.
//!
//! Genesis is today's Kagami Taira localnet re-targeted to the profile (the P2 genesis builder
//! replaces this, TODO(P2)): content of the Taira catalog the profile omits (the Digital Shekel
//! dataspace and validator seats on lanes the profile does not define) is removed, the protocol
//! custody account becomes the profile's keyless account, the `NPoS` epoch becomes the qual
//! profile's, and Kagami signs it against the flattened profile render of validator 0.
//!
//! Requires `TEST_NETWORK_BIN_IROHAD` (stock `iroha3d`) and `KAGAMI_BIN`, both absolute. The test
//! name contains `four_peer`, so the nextest release gate skips it (TODO(P4)).

use color_eyre::eyre::{Result, WrapErr as _, ensure, eyre};
use futures::future::try_join_all;
use iroha::client::{AccountTransactionDraft, Client, FeeQuoteRequest};
use iroha_config::{
    node_config::{NodeConfigOptions, NodeFile, open_node_config},
    parameters::actual::{self, DataDir, NodeSecretFile, node_runtime_signer},
    profile::{Profile, ProfileId, ProfileRole, protocol_custody_account},
};
use iroha_core::{
    beacon::{
        self, RetainedFinalizedGlobalThresholdBeaconSessionV1,
        ceremony::{
            GlobalBeaconCeremonyPlanV1, GlobalBeaconInstallContextV1,
            GlobalBeaconInstallRangeSignaturesV1, deal_global_beacon_at_logical_clock_v1,
            global_beacon_genesis_dkg_session_v1,
        },
    },
    kura::{BlockIndex, BlockStore, Kura},
    sumeragi::{
        certified_chain::CertifiedBlock,
        native_journal::{NativeJournalCursor, with_verified_native_journal},
        startup::genesis_committee_peers,
    },
};
use iroha_crypto::{ExposedPrivateKey, KeyPair, PublicKey};
use iroha_data_model::{
    Level, NetworkId,
    account::{AccountId, address::ChainDiscriminantGuard},
    consensus::GlobalThresholdBeaconChainAnchorV1,
    isi::{InstructionBox, Log, consensus_keys::ApplyThresholdKeyLifecycleCertificateV1},
    parameter::system::{Parameters, SumeragiNposParameters},
    sumeragi::{
        BeaconHorizonStatusV1, SumeragiStatus,
        finality::{NativeFinalityArtifact, NativeFinalityJournal, NativeFinalityLimits},
    },
    transaction::FeePaymentIntent,
};
use iroha_genesis::{RawGenesisTransaction, validate_prepared_genesis_bundle};
use iroha_model_base::{metadata::Metadata, peer::PeerId};
use iroha_test_network::{init_instruction_registry, read_on_dedicated_thread};
use norito::json::{self, Value};
use std::{
    collections::BTreeSet,
    fs,
    num::NonZeroU64,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr as _,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::{Child, Command},
    time::{Instant, sleep, timeout_at},
};

/// Chain id of Taira, whose Kagami output is re-targeted.
const TAIRA_CHAIN: &str = "fc56984b-2be7-431d-840e-21514d1883f0";
/// Profile under test: `sora-nexus-v1` with 64-block epochs and a one-second cadence.
const PROFILE: ProfileId = ProfileId::SoraNexusV1Qual;
/// Validators; `n = 3f + 1` with `f = 1`.
const PEERS: usize = 4;
/// Deadline of every phase.
const PHASE: Duration = Duration::from_secs(300);
/// Bound on retrying a transiently unavailable status read.
const STATUS_RETRY: Duration = Duration::from_secs(30);
/// Effective heights each authorizing validator pre-signs.
const INSTALL_RANGE: u16 = 16;
/// Kagami's Digital Shekel asset and domain, which live in the Taira-only `is` dataspace.
const TAIRA_ONLY_MARKERS: [&str; 2] = ["7ZepsJTHCVLKsrFFNZGSRGZgvBhv", "\"boi.is\""];

fn required_binary(variable: &str) -> Result<PathBuf> {
    let path = std::env::var_os(variable)
        .map(PathBuf::from)
        .ok_or_else(|| eyre!("{variable} must name the prebuilt executable"))?;
    ensure!(
        path.is_absolute() && path.is_file(),
        "{variable} must be an absolute path to an existing executable"
    );
    Ok(path)
}

/// Owner-only workspace below the canonical temporary directory, whose ancestors are trusted
/// (no symlink and no group- or world-writable component), as `node_secrets` requires.
fn workspace() -> Result<tempfile::TempDir> {
    let base = fs::canonicalize(std::env::temp_dir())?;
    let dir = tempfile::Builder::new()
        .prefix("sora-nexus-profile-network-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(base)?;
    Ok(dir)
}

fn owner_only_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .wrap_err_with(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Four contiguous Torii and four contiguous P2P loopback ports, held until the peers start.
fn reserve_ports() -> Result<(u16, u16, Vec<std::net::TcpListener>)> {
    fn range() -> Result<(u16, Vec<std::net::TcpListener>)> {
        for _ in 0..100 {
            let first = std::net::TcpListener::bind(("127.0.0.1", 0))?;
            let base = first.local_addr()?.port();
            if base > u16::MAX - 3 {
                continue;
            }
            let mut held = vec![first];
            for offset in 1..4 {
                match std::net::TcpListener::bind(("127.0.0.1", base + offset)) {
                    Ok(listener) => held.push(listener),
                    Err(_) => break,
                }
            }
            if held.len() == 4 {
                return Ok((base, held));
            }
        }
        Err(eyre!("cannot reserve four contiguous loopback ports"))
    }
    let (api, mut held) = range()?;
    let (p2p, peers) = range()?;
    held.extend(peers);
    Ok((api, p2p, held))
}

/// Run a child to completion, keeping its output under `evidence`.
async fn run(mut command: Command, evidence: &Path, deadline: Instant) -> Result<Vec<u8>> {
    let output = timeout_at(
        deadline,
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?
            .wait_with_output(),
    )
    .await
    .wrap_err("child exceeded its phase deadline")??;
    fs::write(evidence.with_extension("stdout"), &output.stdout)?;
    fs::write(evidence.with_extension("stderr"), &output.stderr)?;
    ensure!(
        output.status.success(),
        "{} exited {}; see {}",
        evidence.display(),
        output.status,
        evidence.with_extension("stderr").display()
    );
    Ok(output.stdout)
}

/// Merge `overlay` into `base`: tables merge recursively, every other value replaces.
fn deep_merge(base: &mut toml::Table, overlay: toml::Table) {
    for (key, value) in overlay {
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(base)), toml::Value::Table(overlay)) => {
                deep_merge(base, overlay);
            }
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// Flatten a profile node file into one flat configuration with the loader's own layers.
///
/// The layers are exactly what `iroha3d` reads (defaults, `static`, `derive(n)`, `policy`, role
/// overlay, node file, `data_dir` layout), merged in order. `data_dir` itself is dropped because
/// its layout is already explicit, so readers of flat files (Kagami signing) accept the result.
fn flat_render(node_file: &Path) -> Result<toml::Table> {
    let _discriminant = ChainDiscriminantGuard::enter(369);
    let reader = open_node_config(
        NodeFile::Path(node_file.to_path_buf()),
        NodeConfigOptions::default(),
    )
    .map_err(|report| eyre!("{report:?}"))?;
    let mut flat = toml::Table::new();
    for source in reader.reader().toml_sources() {
        deep_merge(&mut flat, source.table().clone());
    }
    // Consume the reader: it validates the layers and defuses its drop guard.
    reader.read().map_err(|report| eyre!("{report:?}"))?;
    flat.remove("data_dir");
    Ok(flat)
}

fn read_profile_node(node_file: &Path) -> Result<actual::Root> {
    let _discriminant = ChainDiscriminantGuard::enter(369);
    let (user, binding) = open_node_config(
        NodeFile::Path(node_file.to_path_buf()),
        NodeConfigOptions::default(),
    )
    .and_then(iroha_config::node_config::NodeConfigReader::read)
    .map_err(|report| eyre!("{report:?}"))?;
    ensure!(
        binding.is_some_and(|binding| binding.profile == PROFILE),
        "node file did not select {PROFILE}"
    );
    user.parse().map_err(|report| eyre!("{report:?}"))
}

/// Lane indices the profile's baseline catalog defines.
fn profile_lanes(profile: &Profile) -> Result<BTreeSet<i64>> {
    profile
        .static_config()
        .get("nexus")
        .and_then(|nexus| nexus.get("lane_catalog"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| eyre!("profile has no lane catalog"))?
        .iter()
        .map(|lane| {
            lane.get("index")
                .and_then(toml::Value::as_integer)
                .ok_or_else(|| eyre!("lane without index"))
        })
        .collect()
}

/// Whether a Kagami Taira genesis instruction belongs to the Taira catalog the profile omits.
fn taira_catalog_only(instruction: &Value, lanes: &BTreeSet<i64>) -> Result<bool> {
    let text = json::to_string(instruction)?;
    if TAIRA_ONLY_MARKERS
        .iter()
        .any(|marker| text.contains(marker))
    {
        return Ok(true);
    }
    for kind in ["RegisterPublicLaneValidator", "ActivatePublicLaneValidator"] {
        if let Some(lane) = instruction
            .get(kind)
            .and_then(|body| body.get("lane_id"))
            .and_then(Value::as_i64)
        {
            return Ok(!lanes.contains(&lane));
        }
    }
    Ok(false)
}

/// Re-target Kagami's Taira manifest to the profile (see the module documentation).
fn profile_manifest(
    kagami: &Path,
    output: &Path,
    profile: &Profile,
    kagami_custody: &str,
    profile_custody: &str,
) -> Result<()> {
    let _discriminant = ChainDiscriminantGuard::enter(369);
    let lanes = profile_lanes(profile)?;
    let raw = RawGenesisTransaction::from_path(kagami.join("genesis.json"))?;
    let mut value = json::value::to_value(&raw)?;
    let transactions = value
        .get_mut("transactions")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| eyre!("Kagami manifest has no transactions"))?;
    let mut removed = 0;
    for transaction in transactions.iter_mut() {
        if let Some(instructions) = transaction
            .get_mut("instructions")
            .and_then(Value::as_array_mut)
        {
            let before = instructions.len();
            let mut kept = Vec::with_capacity(before);
            for instruction in instructions.drain(..) {
                if !taira_catalog_only(&instruction, &lanes)? {
                    kept.push(instruction);
                }
            }
            removed += before - kept.len();
            *instructions = kept;
        }
        let Some(parameters) = transaction.get_mut("parameters") else {
            continue;
        };
        if parameters.is_null() {
            continue;
        }
        let mut typed: Parameters = json::value::from_value(parameters.clone())?;
        let id = SumeragiNposParameters::parameter_id();
        let mut npos = typed
            .custom
            .get(&id)
            .map(SumeragiNposParameters::from_custom_parameter)
            .transpose()?
            .flatten()
            .ok_or_else(|| eyre!("Kagami genesis omitted NPoS parameters"))?;
        let epoch = profile.genesis_recipe().epoch_length_blocks;
        npos.epoch_length_blocks = NonZeroU64::new(epoch).ok_or_else(|| eyre!("zero epoch"))?;
        npos.evidence_horizon_blocks = epoch;
        npos.slashing_delay_blocks = epoch;
        npos.validate().map_err(|error| eyre!(error))?;
        typed.custom.insert(id, npos.into_custom_parameter());
        *parameters = json::value::to_value(&typed)?;
    }
    transactions.retain(|transaction| {
        ["instructions", "topology"].iter().any(|key| {
            transaction
                .get(*key)
                .and_then(Value::as_array)
                .is_some_and(|entries| !entries.is_empty())
        }) || transaction
            .get("parameters")
            .is_some_and(|parameters| !parameters.is_null())
    });
    ensure!(
        removed > 0,
        "Kagami Taira genesis carried no Taira-only content"
    );
    ensure!(
        replace_text(&mut value, kagami_custody, profile_custody) > 0,
        "Kagami Taira genesis never names its custody account"
    );
    let raw = RawGenesisTransaction::from_json_slice_at_path(&json::to_vec(&value)?, output)?
        .with_consensus_meta()?;
    fs::write(output, json::to_vec(&raw)?)?;
    Ok(())
}

/// Replace `from` by `to` inside every JSON string; returns how many strings changed.
fn replace_text(value: &mut Value, from: &str, to: &str) -> usize {
    match value {
        Value::String(text) if text.contains(from) => {
            *text = text.replace(from, to);
            1
        }
        Value::Array(items) => items
            .iter_mut()
            .map(|item| replace_text(item, from, to))
            .sum(),
        Value::Object(map) => map
            .values_mut()
            .map(|item| replace_text(item, from, to))
            .sum(),
        _ => 0,
    }
}

/// One validator's Kagami identity.
struct Seat {
    peer: toml::Table,
    key_pair: KeyPair,
    runtime_signer: PathBuf,
}

impl Seat {
    fn load(kagami: &Path, index: usize) -> Result<Self> {
        let peer: toml::Table = toml::from_str(&fs::read_to_string(
            kagami.join(format!("peer{index}.toml")),
        )?)?;
        let private = peer
            .get("private_key")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| eyre!("Kagami peer {index} has no private key"))?
            .parse::<ExposedPrivateKey>()?;
        Ok(Self {
            key_pair: KeyPair::from_private_key(private.0)?,
            runtime_signer: kagami.join(format!(
                "runtime/taira-runtime-signers/peer{index}.private_key"
            )),
            peer,
        })
    }

    fn text(&self, path: &[&str]) -> Result<String> {
        let mut value = self
            .peer
            .get(path[0])
            .ok_or_else(|| eyre!("Kagami peer omitted {path:?}"))?;
        for segment in &path[1..] {
            value = value
                .get(*segment)
                .ok_or_else(|| eyre!("Kagami peer omitted {path:?}"))?;
        }
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| eyre!("{path:?} is not text"))
    }

    fn value(&self, path: &[&str]) -> Result<toml::Value> {
        let mut value = self
            .peer
            .get(path[0])
            .ok_or_else(|| eyre!("Kagami peer omitted {path:?}"))?;
        for segment in &path[1..] {
            value = value
                .get(*segment)
                .ok_or_else(|| eyre!("Kagami peer omitted {path:?}"))?;
        }
        Ok(value.clone())
    }

    /// Write the fixed secret files of this seat under `data_dir/secrets/`.
    fn write_secrets(&self, data_dir: &DataDir) -> Result<()> {
        owner_only_dir(data_dir.root())?;
        owner_only_dir(&data_dir.secrets_dir())?;
        for (file, key) in [
            (NodeSecretFile::Validator, self.text(&["private_key"])?),
            (
                NodeSecretFile::Transport,
                self.text(&["soranet_transport_private_key"])?,
            ),
            (
                NodeSecretFile::Streaming,
                self.text(&["streaming", "identity_private_key"])?,
            ),
        ] {
            private_file(&data_dir.secret(file), format!("{key}\n").as_bytes())?;
        }
        private_file(
            &data_dir.secret(NodeSecretFile::RuntimeSigner),
            &fs::read(&self.runtime_signer)?,
        )?;
        Ok(())
    }

    /// The profile node file: only per-node values the allowlist admits.
    fn node_file(&self, data_dir: &DataDir, genesis: &toml::Table) -> Result<toml::Table> {
        let mut node = toml::Table::new();
        node.insert("profile".into(), PROFILE.as_str().into());
        node.insert("role".into(), ProfileRole::Validator.as_str().into());
        node.insert("validators".into(), toml::Value::Integer(4));
        node.insert(
            "data_dir".into(),
            data_dir.root().to_string_lossy().into_owned().into(),
        );
        for key in ["chain", "public_key", "trusted_peers", "trusted_peers_pop"] {
            node.insert(key.into(), self.value(&[key])?);
        }
        let table = |entries: Vec<(&str, toml::Value)>| {
            toml::Value::Table(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value))
                    .collect(),
            )
        };
        node.insert(
            "network".into(),
            table(vec![
                ("address", self.value(&["network", "address"])?),
                (
                    "public_address",
                    self.value(&["network", "public_address"])?,
                ),
            ]),
        );
        node.insert(
            "torii".into(),
            table(vec![
                ("address", self.value(&["torii", "address"])?),
                (
                    "operator_signatures",
                    table(vec![(
                        "allowed_public_keys",
                        self.value(&["torii", "operator_signatures", "allowed_public_keys"])?,
                    )]),
                ),
            ]),
        );
        node.insert("genesis".into(), toml::Value::Table(genesis.clone()));
        let public_key_hex = self.text(&[
            "soracloud_runtime",
            "submission",
            "signer",
            "public_key_hex",
        ])?;
        // The daemon admits exactly the compiled file-backed signer binding.
        let signer = table(vec![
            (
                "handle",
                format!("{}{public_key_hex}", node_runtime_signer::HANDLE_PREFIX_V1).into(),
            ),
            (
                "authority",
                self.value(&["soracloud_runtime", "submission", "signer", "authority"])?,
            ),
            ("algorithm", "ed25519".into()),
            ("public_key_hex", public_key_hex.into()),
            (
                "revision",
                toml::Value::Integer(i64::try_from(node_runtime_signer::REVISION_V1)?),
            ),
            (
                "policy_digest_hex",
                hex_lower(&node_runtime_signer::policy_digest_v1()).into(),
            ),
        ]);
        node.insert(
            "soracloud_runtime".into(),
            table(vec![("submission", table(vec![("signer", signer)]))]),
        );
        Ok(node)
    }
}

/// The dealt beacon session and the per-seat install signatures.
struct PreDeal {
    record: RetainedFinalizedGlobalThresholdBeaconSessionV1,
    install: GlobalBeaconInstallContextV1,
}

/// Deal the session before the network exists and write each seat's `beacon.cred`.
///
/// `signers` and `data_dirs` are in seat (genesis roster) order.
fn pre_deal(
    network_id: NetworkId,
    roster: &[PeerId],
    signers: &[&KeyPair],
    data_dirs: &[DataDir],
) -> Result<PreDeal> {
    // The genesis session's nominal phase windows [1, 2, 3, 4] serve as the logical clock;
    // every seat runs its signed all-edge DKG in process, the transcript is finalized at
    // height 4, and it installs at any effective height after it.
    let session = global_beacon_genesis_dkg_session_v1(network_id, roster)?;
    let session_hex = hex_lower(&session.session_id);
    let handles = (1..=roster.len())
        .map(|seat| format!("software://iroha/node-secrets/beacon/{session_hex}/seat-{seat}"))
        .collect();
    let plan = GlobalBeaconCeremonyPlanV1::new(session, roster.to_vec(), handles, 1)?;
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let dealt = deal_global_beacon_at_logical_clock_v1(&plan, signers, &budget)?;
    plan.verify_seat_bindings(
        &dealt.record,
        &dealt
            .seats
            .iter()
            .map(|seat| seat.binding.clone())
            .collect::<Vec<_>>(),
    )?;
    for seat in &dealt.seats {
        let index = usize::from(seat.binding.signer_index) - 1;
        private_file(
            &data_dirs[index].secret(NodeSecretFile::BeaconCredential),
            &seat.credential,
        )?;
    }
    let install = GlobalBeaconInstallContextV1::new(dealt.record.clone(), roster.to_vec())?;
    Ok(PreDeal {
        record: dealt.record,
        install,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Running validators.
struct Peers {
    children: Vec<Child>,
}

impl Peers {
    fn spawn(daemon: &Path, directory: &Path, node_files: &[PathBuf]) -> Result<Self> {
        let mut children = Vec::new();
        for (index, node_file) in node_files.iter().enumerate() {
            let log = |stream: &str| {
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(directory.join(format!("peer{index}.{stream}.log")))
            };
            let mut command = Command::new(daemon);
            command
                .env_clear()
                .current_dir(directory)
                .arg("--config")
                .arg(node_file)
                .stdin(Stdio::null())
                .stdout(Stdio::from(log("stdout")?))
                .stderr(Stdio::from(log("stderr")?))
                .kill_on_drop(true);
            children.push(command.spawn()?);
        }
        Ok(Self { children })
    }

    fn exited(&mut self) -> Result<Option<String>> {
        for (index, child) in self.children.iter_mut().enumerate() {
            if let Some(status) = child.try_wait()? {
                return Ok(Some(format!("validator {index} exited: {status}")));
            }
        }
        Ok(None)
    }

    async fn stop(&mut self, deadline: Instant) -> Result<()> {
        for child in &self.children {
            if let Some(pid) = child.id() {
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(i32::try_from(pid)?),
                    nix::sys::signal::Signal::SIGTERM,
                )?;
            }
        }
        for child in &mut self.children {
            timeout_at(deadline, child.wait())
                .await
                .wrap_err("validator did not stop")??;
        }
        self.children.clear();
        Ok(())
    }
}

/// Status code of `GET /readyz`. The public body is a generic envelope without the reason.
async fn readyz(port: u16) -> Result<u16> {
    let address = format!("127.0.0.1:{port}");
    let mut stream = tokio::net::TcpStream::connect(&address).await?;
    stream
        .write_all(
            format!("GET /readyz HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    let response = String::from_utf8_lossy(&bytes);
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| eyre!("malformed /readyz response"))
}

/// `(height, connected peers)` of every validator.
///
/// A status read may answer 503 with a typed retryable reason (`status_deadline_elapsed` or
/// `status_state_busy`) while State is being published; only those are retried, for at most
/// [`STATUS_RETRY`].
async fn heights(clients: &[Client]) -> Result<Vec<(u64, u64)>> {
    try_join_all(clients.iter().map(|client| async move {
        let give_up = Instant::now() + STATUS_RETRY;
        loop {
            match client.status().get().await {
                Ok(status) => return Ok::<_, color_eyre::Report>((status.blocks, status.peers)),
                Err(iroha::Error::StatusUnavailable {
                    reason:
                        Some(
                            iroha::StatusFailureReason::DeadlineElapsed
                            | iroha::StatusFailureReason::StateBusy,
                        ),
                    retry_after,
                }) if Instant::now() < give_up => {
                    sleep(
                        retry_after
                            .unwrap_or_default()
                            .max(Duration::from_millis(200)),
                    )
                    .await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }))
    .await
}

async fn wait_for_mesh(
    clients: &[Client],
    peers: &mut Peers,
    at_least: u64,
    deadline: Instant,
) -> Result<u64> {
    let mut last = Vec::new();
    loop {
        if let Some(exit) = peers.exited()? {
            return Err(eyre!("{exit}; last (height, peers)={last:?}"));
        }
        if let Ok(observed) = heights(clients).await {
            if observed
                .iter()
                .all(|(height, connected)| *height >= at_least && *connected == 3)
                && observed.iter().all(|(height, _)| *height == observed[0].0)
            {
                return Ok(observed[0].0);
            }
            last = observed;
        }
        ensure!(
            Instant::now() < deadline,
            "validators did not mesh at height {at_least}; last (height, peers)={last:?}"
        );
        sleep(Duration::from_millis(250)).await;
    }
}

/// Native local beacon readiness of every validator (see [`sumeragi_statuses`]).
async fn beacon_horizons(
    clients: &[Client],
    nodes: &[PeerId],
) -> Result<Vec<Option<BeaconHorizonStatusV1>>> {
    Ok(sumeragi_statuses(clients, nodes)
        .await?
        .into_iter()
        .map(|status| status.beacon_horizon)
        .collect())
}

/// Read native process diagnostics from every validator under the configured operator identity.
/// These observations do not certify execution; `verify_pulse` separately checks each actual
/// canonical Kura prefix under signed genesis and native quorum/Pasta authority.
/// A failed read is retried for at most [`STATUS_RETRY`]; the last error is returned.
async fn sumeragi_statuses(clients: &[Client], nodes: &[PeerId]) -> Result<Vec<SumeragiStatus>> {
    ensure!(clients.len() == nodes.len(), "one node identity per client");
    try_join_all(clients.iter().zip(nodes).map(|(client, node)| async move {
        let give_up = Instant::now() + STATUS_RETRY;
        loop {
            let (client, node) = (client.clone(), node.clone());
            let read = read_on_dedicated_thread(move || {
                let _discriminant = ChainDiscriminantGuard::enter(369);
                let status = client.get_sumeragi_status()?;
                ensure!(
                    status.signer.as_ref() == Some(node.public_key()) && !status.is_halted(),
                    "native diagnostic source does not report the expected running validator"
                );
                Ok::<_, color_eyre::Report>(status)
            })
            .await;
            match read {
                Ok(status) => return Ok::<_, color_eyre::Report>(status),
                Err(_) if Instant::now() < give_up => sleep(Duration::from_millis(250)).await,
                Err(error) => return Err(error),
            }
        }
    }))
    .await
}

/// The `--check-config --json` compatibility values must be what the network runs: the genesis
/// execution-policy and Nexus/AMX context hashes, and each validator's live handshake-bound
/// configuration fingerprint and protocol version.
fn ensure_compatibility_matches(
    reports: &[Value],
    genesis_hashes: (&str, &str),
    statuses: &[SumeragiStatus],
) -> Result<()> {
    ensure!(reports.len() == statuses.len(), "one report per validator");
    let text = |report: &Value, key: &str| -> Result<String> {
        report
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| eyre!("check-config report has no `{key}`: {report:?}"))
    };
    for (index, (report, status)) in reports.iter().zip(statuses).enumerate() {
        let (execution_policy_hash, nexus_amx_context_hash) = genesis_hashes;
        ensure!(
            text(report, "execution_policy_hash")? == execution_policy_hash
                && text(report, "nexus_amx_context_hash")? == nexus_amx_context_hash,
            "validator {index} check-config genesis hashes differ from the signed genesis"
        );
        let fingerprint: &[u8; 32] = status.config_fingerprint.as_ref();
        ensure!(
            text(report, "config_fingerprint")? == hex_lower(fingerprint),
            "validator {index} check-config fingerprint differs from its live status"
        );
        ensure!(
            report.get("protocol_version").and_then(Value::as_u64)
                == Some(u64::from(status.protocol_version)),
            "validator {index} check-config protocol version differs from its live status"
        );
    }
    let fingerprints: BTreeSet<_> = reports
        .iter()
        .map(|report| text(report, "config_fingerprint"))
        .collect::<Result<_>>()?;
    ensure!(
        fingerprints.len() == 1,
        "validators run different configuration fingerprints: {fingerprints:?}"
    );
    Ok(())
}

/// Submit one fee-paying `Log` transaction and wait until it is applied.
async fn submit_log(client: &Client, message: String) -> Result<()> {
    let account = client.account_client()?;
    let mut payload = account.prepare_transaction(AccountTransactionDraft::new(
        vec![InstructionBox::from(Log::new(Level::INFO, message))],
        FeePaymentIntent::authority(Vec::new(), None),
        Metadata::default(),
    ))?;
    let quote = account
        .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
        .await?;
    payload.fee_payment = quote.intent;
    let transaction = account.sign_transaction(payload)?;
    let hash = account.submit_transaction_and_wait(&transaction).await?;
    ensure!(
        hash == transaction.hash(),
        "applied a different transaction"
    );
    Ok(())
}

/// Drive the chain with `Log` transactions until every validator reaches `target`.
async fn drive_to(
    client: &Client,
    clients: &[Client],
    peers: &mut Peers,
    target: u64,
    deadline: Instant,
) -> Result<u64> {
    let mut height = wait_for_mesh(clients, peers, 1, deadline).await?;
    while height < target {
        submit_log(client, format!("drive height {height} toward {target}")).await?;
        height = wait_for_mesh(clients, peers, height + 1, deadline).await?;
    }
    Ok(height)
}

/// Submit the pre-signed install certificate for the next height, moving to the next pre-signed
/// height when another block lands first. Returns the install height and the superseded attempts.
async fn install(
    client: &Client,
    clients: &[Client],
    peers: &mut Peers,
    pre_deal: &PreDeal,
    ranges: &[GlobalBeaconInstallRangeSignaturesV1],
    deadline: Instant,
) -> Result<(u64, Vec<String>)> {
    let last = ranges[0].first_effective_height + u64::from(INSTALL_RANGE) - 1;
    let account = client.account_client()?;
    let mut failures = Vec::new();
    loop {
        let tip = wait_for_mesh(clients, peers, 1, deadline).await?;
        let height = tip + 1;
        ensure!(
            height <= last,
            "every pre-signed install height was consumed: {failures:?}"
        );
        let certificate = pre_deal.install.assemble_from_ranges(height, ranges)?;
        let mut payload = account.prepare_transaction(AccountTransactionDraft::new(
            vec![InstructionBox::from(
                ApplyThresholdKeyLifecycleCertificateV1 { certificate },
            )],
            FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        ))?;
        let quote = account
            .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
            .await?;
        if quote.observation.next_block_height != height {
            failures.push(format!(
                "quote moved from {height} to {}",
                quote.observation.next_block_height
            ));
            continue;
        }
        payload.fee_payment = quote.intent;
        let transaction = account.sign_transaction(payload)?;
        match account.submit_transaction_and_wait(&transaction).await {
            Ok(_) => return Ok((height, failures)),
            Err(error) => failures.push(format!("certificate for {height}: {error}")),
        }
    }
}

fn native_finality_limits() -> NativeFinalityLimits {
    NativeFinalityLimits {
        block_bytes: 32 * 1024 * 1024,
        journal_bytes: 64 * 1024 * 1024,
        block_count: 256,
        allocated_bytes: 512 * 1024 * 1024,
    }
}

fn journal_from_store(store: &mut BlockStore, height: u64) -> Result<NativeFinalityJournal> {
    let limits = native_finality_limits();
    ensure!(
        (2..=u64::try_from(limits.block_count)?).contains(&height),
        "native finality needs a bounded H2+ prefix"
    );
    let mut blocks = Vec::with_capacity(usize::try_from(height)?);
    let mut total = 0_usize;
    for at in 1..=height {
        let mut index = [BlockIndex {
            start: 0,
            length: 0,
        }];
        store.read_block_indices(at - 1, &mut index)?;
        let length = usize::try_from(index[0].length)?;
        total = total
            .checked_add(length)
            .ok_or_else(|| eyre!("native journal length overflow"))?;
        ensure!(
            length > 0 && length <= limits.block_bytes && total <= limits.journal_bytes,
            "native source exceeds configured bounds before allocation"
        );
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length)?;
        bytes.resize(length, 0);
        store.read_block_data(index[0].start, &mut bytes)?;
        blocks.push(NativeFinalityArtifact { block_wire: bytes });
    }
    Ok(NativeFinalityJournal { blocks })
}

/// Verify the mandatory pulse at `pulse_height` in every stopped validator's Kura against the
/// installed session. All validators must hold the same pulse block.
fn verify_pulse(
    node_files: &[PathBuf],
    record: &RetainedFinalizedGlobalThresholdBeaconSessionV1,
    pulse_height: u64,
) -> Result<()> {
    record.validate()?;
    let session = &record.session;
    let mut common = None;
    for node_file in node_files {
        let config = read_profile_node(node_file)?;
        let mut store = BlockStore::open_read_only(Kura::canonical_storage_path(
            config.kura.store_dir.value(),
        ))?;
        let network = NetworkId::from_genesis_hash(config.genesis.expected_hash);
        ensure!(
            network == record.session.network_id,
            "profile source network differs"
        );
        let journal = journal_from_store(&mut store, pulse_height)?;
        let cursor = NativeJournalCursor::new(
            config.common.chain.clone(),
            network,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            native_finality_limits(),
            &iroha_allocation::AllocationBudget::new(native_finality_limits().allocated_bytes),
        )
        .map_err(|error| eyre!(error))?;
        let certified = with_verified_native_journal(
            (&journal).into(),
            &config.common.chain,
            &network,
            native_finality_limits(),
            cursor.allocation_budget(),
            |reader| {
                reader
                    .walk(1, pulse_height)
                    .collect::<std::result::Result<Vec<CertifiedBlock>, _>>()
                    .map_err(iroha_core::sumeragi::native_journal::NativeJournalError::History)
            },
        )
        .map_err(|error| eyre!(error))?;
        let anchor = certified[usize::try_from(pulse_height - 2)?].block();
        let source = &certified[usize::try_from(pulse_height - 1)?];
        let block = source.block();
        let pulse =
            source.commitment().beacon.as_ref().ok_or_else(|| {
                eyre!("no native beacon pulse at mandatory height {pulse_height}")
            })?;
        ensure!(pulse.height == pulse_height, "pulse height differs");
        beacon::verify_finalized_global_threshold_beacon_pulse_v1(
            session,
            pulse,
            GlobalThresholdBeaconChainAnchorV1 {
                height: pulse_height - 1,
                block_hash: anchor.hash(),
            },
            &{
                let header = source
                    .header()
                    .ok_or_else(|| eyre!("native pulse header is absent"))?;
                iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1 {
                    instance: header.instance.0,
                    epoch: header.epoch.epoch,
                    epoch_context_id: header.epoch.context.0,
                    parent_consensus_hash: header.parent_hash.0,
                    parent_result: header.parent_result.0,
                }
            },
        )?;
        let proof = (block.hash(), *pulse);
        match &common {
            Some(expected) => ensure!(expected == &proof, "validators disagree on the pulse"),
            None => common = Some(proof),
        }
    }
    Ok(())
}

fn elapsed(since: Instant) -> String {
    format!("{:.1}s", since.elapsed().as_secs_f64())
}

#[test]
fn deep_merge_overlays_leaves_and_merges_tables() {
    let mut base: toml::Table = toml::from_str("a = 1\n[t]\nx = 1\ny = 2\n").unwrap();
    deep_merge(
        &mut base,
        toml::from_str("b = 2\n[t]\ny = 3\nz = 4\n").unwrap(),
    );
    assert_eq!(
        base,
        toml::from_str::<toml::Table>("a = 1\nb = 2\n[t]\nx = 1\ny = 3\nz = 4\n").unwrap()
    );
}

#[test]
fn taira_catalog_content_is_recognized() {
    let lanes = BTreeSet::from([0, 1, 2, 3]);
    let register = |lane: i64| {
        json::from_str::<Value>(&format!(
            r#"{{"RegisterPublicLaneValidator":{{"lane_id":{lane},"initial_stake":"1"}}}}"#
        ))
        .unwrap()
    };
    assert!(!taira_catalog_only(&register(3), &lanes).unwrap());
    assert!(taira_catalog_only(&register(4), &lanes).unwrap());
    let domain = json::from_str::<Value>(r#"{"Register":{"Domain":{"id":"boi.is"}}}"#).unwrap();
    assert!(taira_catalog_only(&domain, &lanes).unwrap());
    let mut nested = json::from_str::<Value>(r#"{"a":["x-old-y",{"b":"old"}],"c":1}"#).unwrap();
    assert_eq!(replace_text(&mut nested, "old", "new"), 2);
    assert_eq!(
        nested,
        json::from_str::<Value>(r#"{"a":["x-new-y",{"b":"new"}],"c":1}"#).unwrap()
    );
    let other = json::from_str::<Value>(r#"{"Register":{"Domain":{"id":"x.universal"}}}"#).unwrap();
    assert!(!taira_catalog_only(&other, &lanes).unwrap());
    let profile = Profile::compiled(PROFILE).unwrap();
    assert_eq!(profile_lanes(&profile).unwrap(), lanes);
    assert_eq!(hex_lower(&[0x0a, 0xff]), "0aff");
}

/// Unprivileged `production_mode` start plus the beacon pre-deal proof (see module docs).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_peer_sora_nexus_qual_predealt_beacon_installs_without_restart() -> Result<()> {
    init_instruction_registry();
    let started = Instant::now();
    let daemon = required_binary("TEST_NETWORK_BIN_IROHAD")?;
    let kagami = required_binary("KAGAMI_BIN")?;
    let profile = Profile::compiled(PROFILE)?;
    let workspace = workspace()?;
    let root = workspace.path().to_path_buf();
    let outcome = async {
        let deadline = Instant::now() + PHASE;
        let (api, p2p, reservations) = reserve_ports()?;
        // 1. Today's Kagami Taira localnet with the qual cadence.
        let kagami_dir = root.join("kagami");
        let mut generate = Command::new(&kagami);
        generate
            .args(["localnet", "generate", "--peers", "4", "--chain-id", TAIRA_CHAIN])
            .args(["--sora-profile", "nexus", "--consensus-mode", "npos"])
            .args(["--seed", "sora-nexus-v1-qual-predeal"])
            .arg("--block-cadence-ms")
            .arg(profile.genesis_recipe().block_cadence_ms.to_string())
            .args(["--bind-host", "127.0.0.1", "--public-host", "127.0.0.1"])
            .arg("--base-api-port")
            .arg(api.to_string())
            .arg("--base-p2p-port")
            .arg(p2p.to_string())
            .arg("--out-dir")
            .arg(&kagami_dir);
        run(generate, &root.join("kagami-localnet"), deadline).await?;
        eprintln!("[{}] Kagami Taira localnet generated", elapsed(started));
        let seats = (0..PEERS)
            .map(|index| Seat::load(&kagami_dir, index))
            .collect::<Result<Vec<_>>>()?;
        let genesis_public_key =
            PublicKey::from_str(fs::read_to_string(kagami_dir.join("genesis.public_key"))?.trim())?;
        // 2. Profile node files and data directories (provisional genesis binding).
        let data_dirs = (0..PEERS)
            .map(|index| DataDir::new(root.join(format!("node{index}/data"))))
            .collect::<Vec<_>>();
        let node_files = (0..PEERS)
            .map(|index| root.join(format!("node{index}/node.toml")))
            .collect::<Vec<_>>();
        let write_nodes = |genesis: &toml::Table| -> Result<()> {
            for ((seat, data_dir), path) in seats.iter().zip(&data_dirs).zip(&node_files) {
                let node = seat.node_file(data_dir, genesis)?;
                fs::write(path, toml::to_string(&node)?)?;
            }
            Ok(())
        };
        for (seat, data_dir) in seats.iter().zip(&data_dirs) {
            seat.write_secrets(data_dir)?;
        }
        let mut genesis = seats[0]
            .value(&["genesis"])?
            .as_table()
            .cloned()
            .ok_or_else(|| eyre!("genesis is not a table"))?;
        genesis.remove("expected_hash_file");
        genesis.insert(
            "expected_hash".into(),
            fs::read_to_string(kagami_dir.join("genesis.expected_hash"))?
                .trim()
                .into(),
        );
        write_nodes(&genesis)?;
        // 3. Re-target the manifest and sign it against the flattened profile render.
        let genesis_dir = root.join("genesis");
        owner_only_dir(&genesis_dir)?;
        let kagami_custody = seats[0].text(&["pipeline", "gas", "tech_account_id"])?;
        let profile_custody = protocol_custody_account(ProfileId::SoraNexusV1)
            .to_i105_for_discriminant(369)?;
        ensure!(
            seats[0].text(&["nexus", "fees", "fee_sink_account_id"])? == kagami_custody,
            "Kagami custody roles no longer share one account"
        );
        profile_manifest(
            &kagami_dir,
            &genesis_dir.join("genesis.json"),
            &profile,
            &kagami_custody,
            &profile_custody,
        )?;
        let flat = genesis_dir.join("flat-validator0.toml");
        private_file(&flat, toml::to_string(&flat_render(&node_files[0])?)?.as_bytes())?;
        let mut sign = Command::new(&kagami);
        sign.args(["genesis", "sign"])
            .arg(genesis_dir.join("genesis.json"))
            .arg("--out-file")
            .arg(genesis_dir.join("genesis.signed.nrt"))
            .arg("--bound-manifest-out")
            .arg(genesis_dir.join("genesis.bound.json"))
            .arg("--expected-hash-out")
            .arg(genesis_dir.join("genesis.expected_hash"))
            .arg("--private-key-file")
            .arg(kagami_dir.join("genesis.private_key"))
            .arg("--expected-public-key")
            .arg(genesis_public_key.to_string())
            .arg("--config")
            .arg(&flat);
        run(sign, &root.join("kagami-genesis-sign"), deadline).await?;
        let network_id = {
            let _discriminant = ChainDiscriminantGuard::enter(369);
            NetworkId::from_str(
                fs::read_to_string(genesis_dir.join("genesis.expected_hash"))?.trim(),
            )?
        };
        let (roster, genesis_hashes) = {
            let _discriminant = ChainDiscriminantGuard::enter(369);
            let manifest = RawGenesisTransaction::from_path(genesis_dir.join("genesis.bound.json"))?;
            let context = manifest.sumeragi_context_parameters();
            let genesis_hashes = (
                hex_lower(&context.execution_policy_hash),
                hex_lower(&context.nexus_amx_context_hash),
            );
            let bundle = validate_prepared_genesis_bundle(
                &fs::read(genesis_dir.join("genesis.signed.nrt"))?,
                &manifest,
                &genesis_public_key,
                network_id.into_genesis_hash(),
            )?;
            (genesis_committee_peers(bundle.block())?, genesis_hashes)
        };
        ensure!(roster.len() == PEERS, "genesis roster is not four validators");
        eprintln!(
            "[{}] profile genesis signed against the flattened profile render: {network_id}",
            elapsed(started)
        );
        // Seats follow the authenticated genesis roster order.
        let seat_of = |index: usize| -> Result<usize> {
            let peer = PeerId::new(seats[index].key_pair.public_key().clone());
            roster
                .iter()
                .position(|candidate| candidate == &peer)
                .ok_or_else(|| eyre!("validator {index} is outside the genesis roster"))
        };
        let mut seat_dirs = vec![None; PEERS];
        for (index, data_dir) in data_dirs.iter().enumerate() {
            seat_dirs[seat_of(index)?] = Some(data_dir.clone());
        }
        let seat_dirs = seat_dirs.into_iter().flatten().collect::<Vec<_>>();
        let mut seat_signers = vec![None; PEERS];
        for (index, seat) in seats.iter().enumerate() {
            seat_signers[seat_of(index)?] = Some(&seat.key_pair);
        }
        let seat_signers = seat_signers.into_iter().flatten().collect::<Vec<_>>();
        // 4. The pre-deal: before the network exists.
        let pre_deal = pre_deal(network_id, &roster, &seat_signers, &seat_dirs)?;
        let finalized_at = pre_deal.record.session.adaptive_dkg.finalized_at_height;
        eprintln!(
            "[{}] beacon session {} pre-dealt against its logical clock (finalized at {finalized_at})",
            elapsed(started),
            hex_lower(&pre_deal.record.session.session_id)
        );
        genesis.insert(
            "file".into(),
            genesis_dir
                .join("genesis.signed.nrt")
                .to_string_lossy()
                .into_owned()
                .into(),
        );
        genesis.insert("expected_hash".into(), network_id.to_string().into());
        write_nodes(&genesis)?;
        // 5. Offline admission of every profile node (restages genesis under its own render).
        let rans = root.join("codec/rans/tables");
        fs::create_dir_all(&rans)?;
        fs::copy(
            iroha_test_network::repo_root().join("codec/rans/tables/rans_seed0.toml"),
            rans.join("rans_seed0.toml"),
        )?;
        let mut compatibility = Vec::with_capacity(PEERS);
        for (index, node_file) in node_files.iter().enumerate() {
            let mut check = Command::new(&daemon);
            check
                .env_clear()
                .current_dir(&root)
                .arg("--config")
                .arg(node_file)
                .args(["--check-config", "--json"]);
            let report = run(check, &root.join(format!("check-config-{index}")), deadline).await?;
            let report: Value = json::from_slice(&report)?;
            ensure!(
                report.get("status").and_then(Value::as_str) == Some("ready"),
                "validator {index} is not ready offline: {report:?}"
            );
            eprintln!("check-config validator {index}: {}", json::to_string(&report)?);
            compatibility.push(report);
        }
        // 6. Unprivileged first start with `beacon.cred` already in place.
        ensure!(
            !nix::unistd::geteuid().is_root(),
            "the unprivileged start proof must not run as root"
        );
        drop(reservations);
        let mut peers = Peers::spawn(&daemon, &root, &node_files)?;
        let network = async {
            let _discriminant = ChainDiscriminantGuard::enter(369);
            let clients = (0..PEERS)
                .map(|index| client(&kagami_dir, &network_id, api + u16::try_from(index)?))
                .collect::<Result<Vec<_>>>()?;
            let nodes = seats
                .iter()
                .map(|seat| PeerId::new(seat.key_pair.public_key().clone()))
                .collect::<Vec<_>>();
            let deadline = Instant::now() + PHASE;
            let height = wait_for_mesh(&clients, &mut peers, 1, deadline).await?;
            eprintln!(
                "[{}] four production_mode validators meshed at height {height} as uid {}",
                elapsed(started),
                nix::unistd::geteuid()
            );
            ensure_compatibility_matches(
                &compatibility,
                (&genesis_hashes.0, &genesis_hashes.1),
                &sumeragi_statuses(&clients, &nodes).await?,
            )?;
            eprintln!("check-config compatibility values equal the live network's");
            // Before the install `/readyz` is 503 (its public body is a generic envelope) and
            // the native readiness horizon names no active session.
            let horizons = beacon_horizons(&clients, &nodes).await?;
            for (offset, horizon) in (0_u16..).zip(&horizons) {
                let code = readyz(api + offset).await?;
                ensure!(
                    code == 503
                        && horizon.is_none_or(|horizon| {
                            horizon.active_session_id.is_none() && !horizon.local_provider_ready
                        }),
                    "validator {offset} before the install: /readyz {code}, horizon {horizon:?}"
                );
            }
            eprintln!("before the install: /readyz 503 on all four; horizons {horizons:?}");
            // 7. Drive the tip to the session's finalization height.
            let tip = drive_to(&clients[0], &clients, &mut peers, finalized_at, deadline).await?;
            // 8. 2f + 1 validators pre-sign a range; submit the certificate for the next height.
            let ranges = (0..3)
                .map(|seat| {
                    let index = (0..PEERS)
                        .find(|index| seat_of(*index).ok() == Some(seat))
                        .ok_or_else(|| eyre!("no validator for seat {seat}"))?;
                    Ok(pre_deal.install.sign_range(
                        &seats[index].key_pair,
                        tip + 1,
                        INSTALL_RANGE,
                    )?)
                })
                .collect::<Result<Vec<_>>>()?;
            let (installed_at, superseded) = install(
                &clients[0], &clients, &mut peers, &pre_deal, &ranges, deadline,
            )
            .await?;
            eprintln!(
                "[{}] session installed at height {installed_at} (tip was {tip}; superseded attempts: {superseded:?})",
                elapsed(started)
            );
            // 9. Providers loaded at first start become ready with no further block.
            let session_id = pre_deal.record.session.session_id;
            let horizon = loop {
                let horizons = beacon_horizons(&clients, &nodes).await?;
                let tips = heights(&clients).await?;
                ensure!(
                    tips.iter().all(|(height, _)| *height == installed_at),
                    "a block landed before every provider reported ready: {tips:?}"
                );
                if horizons.iter().all(|horizon| {
                    horizon.as_ref().is_some_and(|horizon| {
                        horizon.active_session_id == Some(session_id)
                            && horizon.local_provider_ready
                            && horizon.session_covers_next_pulse
                    })
                }) {
                    break horizons[0].expect("checked");
                }
                ensure!(
                    Instant::now() < deadline,
                    "providers did not become ready after the install: {horizons:?}"
                );
                sleep(Duration::from_millis(250)).await;
            };
            // `/readyz` also requires an unchanged committed-state generation, so it may lag the
            // horizon briefly; it must turn 200 at the install height, before any further block.
            let ready_since = Instant::now();
            let mut not_ready = Vec::new();
            for offset in 0..4 {
                loop {
                    let code = readyz(api + offset).await?;
                    if code == 200 {
                        break;
                    }
                    not_ready.push((offset, code, ready_since.elapsed()));
                    let tips = heights(&clients).await?;
                    ensure!(
                        tips.iter().all(|(height, _)| *height == installed_at)
                            && Instant::now() < deadline,
                        "validator {offset} /readyz stayed {code} after the install; tips {tips:?}"
                    );
                    sleep(Duration::from_millis(250)).await;
                }
            }
            eprintln!(
                "[{}] /readyz 200 on all four after {:.2}s at the install height; earlier 503 polls: {}",
                elapsed(started),
                ready_since.elapsed().as_secs_f64(),
                not_ready.len()
            );
            eprintln!(
                "[{}] every provider ready and /readyz 200 at height {installed_at}; horizon {horizon:?}",
                elapsed(started)
            );
            // 10. Cross the mandatory pulse.
            let pulse = horizon
                .next_required_pulse_height
                .ok_or_else(|| eyre!("no mandatory pulse is scheduled"))?;
            // About 60 driven heights; an unoptimized build commits one in roughly 11 s.
            let pulse_deadline = Instant::now() + PHASE * 4;
            let crossed =
                drive_to(&clients[0], &clients, &mut peers, pulse + 2, pulse_deadline).await?;
            let after = beacon_horizons(&clients, &nodes).await?;
            ensure!(
                after.iter().all(|horizon| horizon.as_ref().is_some_and(|horizon| {
                    horizon.local_provider_ready
                        && horizon
                            .next_required_pulse_height
                            .is_some_and(|next| next > pulse)
                })),
                "the horizon did not move past pulse {pulse}: {after:?}"
            );
            // `/readyz` is 503 between a block commit and the next height's activation, so it
            // is polled; every validator must report ready again after the pulse.
            let settle = Instant::now() + Duration::from_secs(60);
            for offset in 0..4 {
                while readyz(api + offset).await? != 200 {
                    ensure!(
                        Instant::now() < settle,
                        "validator {offset} did not return to ready after the pulse"
                    );
                    sleep(Duration::from_millis(250)).await;
                }
            }
            eprintln!(
                "[{}] crossed mandatory pulse {pulse}; tip {crossed}",
                elapsed(started)
            );
            Ok::<_, color_eyre::Report>(pulse)
        }
        .await;
        let stopped = peers.stop(Instant::now() + Duration::from_secs(60)).await;
        let pulse = network?;
        stopped?;
        verify_pulse(&node_files, &pre_deal.record, pulse)?;
        eprintln!(
            "[{}] pulse {pulse} verifies against the pre-dealt session on all four validators",
            elapsed(started)
        );
        // 11. The stopped stores pass the read-only storage check, including the restore of a
        //     real signed snapshot the qualification cadence wrote, reconciled against every
        //     retained Kura hash.
        let deadline = Instant::now() + PHASE;
        for (index, node_file) in node_files.iter().enumerate() {
            let mut check = Command::new(&daemon);
            check
                .env_clear()
                .current_dir(&root)
                .arg("--config")
                .arg(node_file)
                .arg("--check-storage");
            let report = run(check, &root.join(format!("check-storage-{index}")), deadline).await?;
            let report: Value = json::from_slice(&report)?;
            ensure!(
                report.get("snapshot_restore_dry_run").and_then(Value::as_str) == Some("ok")
                    && report.get("tip_height").and_then(Value::as_u64) >= Some(pulse + 2)
                    && report
                        .get("snapshot_height")
                        .and_then(Value::as_u64)
                        .is_some_and(|height| height > 0),
                "validator {index} failed the storage check with a restored snapshot: {report:?}"
            );
            eprintln!("check-storage validator {index}: {}", json::to_string(&report)?);
        }
        Ok::<_, color_eyre::Report>(())
    }
    .await;
    if outcome.is_err() {
        eprintln!("evidence retained at {}", workspace.keep().display());
    }
    outcome
}

/// A client for Kagami's funded operator account on one validator. Operator-signed reads use
/// Kagami's HTTP operator key, which every node file allows.
fn client(kagami: &Path, network_id: &NetworkId, port: u16) -> Result<Client> {
    let mut table: toml::Table = toml::from_str(&fs::read_to_string(kagami.join("client.toml"))?)?;
    table.remove("network_id_file");
    table.insert("network_id".into(), network_id.to_string().into());
    let path = kagami.join(format!("client-{port}.toml"));
    fs::write(&path, toml::to_string(&table)?)?;
    let mut config = iroha::config::Config::load_file(&path)
        .map_err(|error| eyre!("client configuration: {error:?}"))?;
    config.torii_api_url = format!("http://127.0.0.1:{port}/").parse()?;
    config.transaction_status_timeout = Duration::from_secs(60);
    let operator = fs::read_to_string(kagami.join("runtime/operator-signer.key"))?
        .trim()
        .parse::<ExposedPrivateKey>()?;
    let mut builder = Client::builder(config);
    builder.operator_key_pair = Some(KeyPair::from_private_key(operator.0)?);
    Ok(builder.build()?)
}

#[test]
fn account_literal_encodes_for_the_profile_discriminant() {
    let _discriminant = ChainDiscriminantGuard::enter(369);
    let custody = protocol_custody_account(ProfileId::SoraNexusV1);
    let literal = custody.to_i105_for_discriminant(369).unwrap();
    assert_eq!(AccountId::parse_encoded(&literal).unwrap(), custody);
}
