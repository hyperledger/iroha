//! Foreground, owner-private conductor for the native four-validator genesis beacon.
//!
//! The existing native DKG owns every secret seat. This binary reads original Kura
//! carriers, submits ordinary signed transactions, and retains completed custody.
//! It does not adopt, complete, or rewrite a public-reset deployment journal.
//!
//! This disposable test-network development tool requires explicit opt-in:
//! `cargo run -p iroha_test_network --features dev-tools --bin taira_beacon_bootstrap -- <arguments>`.
//! Signing inputs remain in owner-private runtime configuration, never on argv.

use color_eyre::eyre::{Result, ensure, eyre};
use iroha::client::{
    AccountTransactionDraft, Client, FeeQuoteRequest, TransactionDispatchOutcomeUnknownError,
    TransactionWaitOptions,
};
use iroha_config::base::read::ConfigReader;
use iroha_core::{
    beacon::{
        AdaptiveGlobalThresholdBeaconDkgCryptoV1, GlobalThresholdBeaconDkgSnapshotV1,
        GlobalThresholdBeaconDkgStateV1,
        ceremony::{global_beacon_genesis_attempt_id_v1, global_beacon_genesis_session_id_v1},
        credential::global_beacon_partial_signer_public_inventory_digest_v1,
        global_threshold_beacon_roster_hash_v1,
    },
    kura::{BlockIndex, BlockStore, Kura},
    sumeragi::{
        native_journal::{NativeJournalCursor, authenticate_signed_genesis},
        startup::genesis_committee_peers,
    },
};
use iroha_crypto::{HashOf, sha256, sha256_reader_bounded};
use iroha_data_model::{
    Level, NetworkId,
    account::address::ChainDiscriminantGuard,
    block::consensus::SumeragiRootScope,
    consensus::{GlobalThresholdBeaconDkgSessionV1, GlobalThresholdBeaconKeySessionV1},
    isi::{
        InstructionBox, Log,
        consensus_keys::{
            ApplyThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleActionV1,
            ThresholdKeyLifecycleCertificateV1,
        },
    },
    sumeragi::finality::{NativeFinalityArtifact, NativeFinalityJournal, NativeFinalityLimits},
    transaction::{Executable, FeePaymentIntent, SignedTransaction},
};
use iroha_model_base::{chain::ChainId, metadata::Metadata, peer::PeerId};
use iroha_test_network::{
    DisposableGenesisConfigSeat, NativeGenesisProvisioningBundle,
    run_disposable_genesis_dkg_from_configs,
};
use iroha_version::codec::DecodeVersioned as _;
use norito::{JsonDeserialize, JsonSerialize, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::{Zeroize as _, Zeroizing};

const FILE_BOUND: u64 = 64 * 1024 * 1024;
const DAEMON_BOUND: u64 = 2 * 1024 * 1024 * 1024;
const ACTION_TIMEOUT: Duration = Duration::from_secs(180);
const CREDENTIAL: &str = "iroha-global-beacon-partial-signer-v1.norito";
const PROVIDER_FIELDS: [&str; 3] = [
    "global_beacon_partial_signer_provider_handle",
    "global_beacon_partial_signer_provider_revision",
    "global_beacon_partial_signer_provider_policy_digest_hex",
];

/// Public command binding; no signing key is accepted on argv.
#[derive(Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Binding {
    input_dir: PathBuf,
    daemon: PathBuf,
    daemon_sha256: String,
    chain_id: ChainId,
    network_id: NetworkId,
    chain_discriminant: u16,
    genesis_manifest: PathBuf,
    manifest_sha256: String,
    genesis_signed: PathBuf,
    signed_genesis_sha256: String,
    client_config: PathBuf,
    validator_configs: Vec<PathBuf>,
}

struct Args {
    binding: Binding,
    output: PathBuf,
    recover: bool,
    submit_retained_install: bool,
}

#[derive(Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Provider {
    signer_index: u16,
    validator: PeerId,
    handle: String,
    revision: u64,
    policy_digest: [u8; 32],
}

#[derive(Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RetainedSeat {
    provider: Provider,
    initial_config_path: PathBuf,
    initial_config_sha256: String,
    credential_path: PathBuf,
    credential_sha256: String,
    provider_path: PathBuf,
    provider_sha256: String,
    config_path: PathBuf,
    config_sha256: String,
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Ceremony<Session> {
    schema: String,
    binding: Binding,
    public_session: Session,
    bundle_sha256: String,
    instruction_sha256: String,
    seats: Vec<RetainedSeat>,
}

#[derive(JsonSerialize)]
struct Receipt {
    schema: String,
    chain_id: ChainId,
    network_id: NetworkId,
    install_applied: bool,
    install_transaction_hash: HashOf<SignedTransaction>,
    install_height: u64,
    session: GlobalThresholdBeaconKeySessionV1,
    seats: Vec<RetainedSeat>,
}

/// One signed ledger audit of a completed, genuine public DKG phase.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PhaseAudit {
    schema: String,
    chain_id: ChainId,
    network_id: NetworkId,
    manifest_sha256: String,
    signed_genesis_sha256: String,
    height: u64,
    purpose: String,
    session: GlobalThresholdBeaconDkgSessionV1,
    public_snapshot_sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest_literal(value: String) -> Result<String> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "SHA256 must be 64 lowercase hex digits"
    );
    Ok(value)
}

fn arguments(values: impl IntoIterator<Item = String>) -> Result<Args> {
    let mut values = values.into_iter();
    let mut fields = BTreeMap::new();
    let mut validators = Vec::new();
    let mut recover = false;
    let mut submit_retained_install = false;
    while let Some(name) = values.next() {
        if name == "--recover" {
            ensure!(!recover, "duplicate recovery flag");
            recover = true;
            continue;
        }
        if name == "--submit-retained-install" {
            ensure!(
                !submit_retained_install,
                "duplicate retained installation flag"
            );
            submit_retained_install = true;
            continue;
        }
        ensure!(
            matches!(
                name.as_str(),
                "--input-dir"
                    | "--daemon"
                    | "--daemon-sha256"
                    | "--output-root"
                    | "--chain-id"
                    | "--network-id"
                    | "--chain-discriminant"
                    | "--genesis-manifest"
                    | "--manifest-sha256"
                    | "--genesis-signed"
                    | "--signed-genesis-sha256"
                    | "--client-config"
                    | "--validator-config"
            ),
            "unknown operator argument"
        );
        let value = values
            .next()
            .ok_or_else(|| eyre!("missing operator argument value"))?;
        if name == "--validator-config" {
            validators.push(PathBuf::from(value));
        } else {
            ensure!(
                fields.insert(name, value).is_none(),
                "duplicate operator argument"
            );
        }
    }
    ensure!(
        !(recover && submit_retained_install),
        "read-only recovery and installation submission are separate actions"
    );
    let mut take = |name: &str| fields.remove(name).ok_or_else(|| eyre!("missing {name}"));
    let args = Args {
        binding: Binding {
            input_dir: take("--input-dir")?.into(),
            daemon: take("--daemon")?.into(),
            daemon_sha256: digest_literal(take("--daemon-sha256")?)?,
            chain_id: take("--chain-id")?.parse()?,
            network_id: take("--network-id")?.parse()?,
            chain_discriminant: take("--chain-discriminant")?.parse()?,
            genesis_manifest: take("--genesis-manifest")?.into(),
            manifest_sha256: digest_literal(take("--manifest-sha256")?)?,
            genesis_signed: take("--genesis-signed")?.into(),
            signed_genesis_sha256: digest_literal(take("--signed-genesis-sha256")?)?,
            client_config: take("--client-config")?.into(),
            validator_configs: validators,
        },
        output: take("--output-root")?.into(),
        recover,
        submit_retained_install,
    };
    ensure!(
        args.binding.chain_discriminant != 0 && args.binding.validator_configs.len() == 4,
        "four validator configs and a nonzero discriminant are required"
    );
    for path in [
        &args.binding.input_dir,
        &args.binding.daemon,
        &args.output,
        &args.binding.genesis_manifest,
        &args.binding.genesis_signed,
        &args.binding.client_config,
    ]
    .into_iter()
    .chain(args.binding.validator_configs.iter())
    {
        ensure!(
            path.is_absolute()
                && path
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
            "operator paths must be direct absolute paths"
        );
    }
    ensure!(
        args.binding
            .genesis_manifest
            .starts_with(&args.binding.input_dir)
            && args
                .binding
                .genesis_signed
                .starts_with(&args.binding.input_dir)
            && args
                .binding
                .client_config
                .starts_with(&args.binding.input_dir),
        "genesis and client inputs must belong to the explicit input directory"
    );
    Ok(args)
}

fn directory(path: &Path, private: bool) -> Result<()> {
    let uid = nix::unistd::Uid::effective().as_raw();
    for (index, ancestor) in path.ancestors().enumerate() {
        let m = fs::symlink_metadata(ancestor)?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.mode() & 0o022 == 0
                && (m.uid() == uid || (index != 0 && m.uid() == 0)),
            "unsafe operator directory ancestry"
        );
        if index == 0 && private {
            ensure!(
                m.uid() == uid && m.mode() & 0o7777 == 0o700,
                "operator directory must be owner-only 0700"
            );
        }
    }
    Ok(())
}

fn identity(m: &fs::Metadata) -> (u64, u64, u32, u32, u64, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.mode(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn unchanged(path: &Path, file: &File, before: &fs::Metadata) -> Result<()> {
    ensure!(
        identity(before) == identity(&file.metadata()?)
            && identity(before) == identity(&fs::symlink_metadata(path)?),
        "selected input changed identity or metadata"
    );
    Ok(())
}

fn open_input(path: &Path, private: bool, bound: u64) -> Result<File> {
    directory(
        path.parent().ok_or_else(|| eyre!("input has no parent"))?,
        false,
    )?;
    let before = fs::symlink_metadata(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() > 0 && m.len() <= bound && m.mode() & 0o022 == 0,
        "input file exceeds custody or size bounds"
    );
    if private {
        ensure!(
            m.uid() == nix::unistd::Uid::effective().as_raw() && m.mode() & 0o7777 == 0o600,
            "private input must be owned mode 0600"
        );
    }
    unchanged(path, &file, &before)?;
    Ok(file)
}

fn read_input(path: &Path, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = open_input(path, private, FILE_BOUND)?;
    let before = file.metadata()?;
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut file)
        .take(FILE_BOUND + 1)
        .read_to_end(&mut bytes)?;
    unchanged(path, &file, &before)?;
    ensure!(
        bytes.len() as u64 == before.len(),
        "input changed during bounded read"
    );
    Ok(bytes)
}

fn file_digest(path: &Path, private: bool) -> Result<String> {
    Ok(hex(&sha256(&*read_input(path, private)?)))
}

fn daemon_digest(path: &Path) -> Result<String> {
    let mut file = open_input(path, false, DAEMON_BOUND)?;
    let before = file.metadata()?;
    ensure!(before.mode() & 0o111 != 0, "daemon is not executable");
    let (digest, size) = sha256_reader_bounded(&mut file, DAEMON_BOUND)?;
    unchanged(path, &file, &before)?;
    ensure!(size == before.len(), "daemon changed during authentication");
    Ok(hex(&digest))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().ok_or_else(|| eyre!("output has no parent"))?)?.sync_all()?;
    Ok(())
}

fn native_config(path: &Path, binding: &Binding) -> Result<iroha_config::parameters::actual::Root> {
    let _guard = ChainDiscriminantGuard::enter(binding.chain_discriminant);
    let file = open_input(path, true, 1024 * 1024)?;
    let before = file.metadata()?;
    let native: iroha_config::parameters::actual::Root = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(path.to_owned())
        .map_err(|_| eyre!("cannot read selected native config"))?
        .read_and_complete::<iroha_config::parameters::user::Root>()
        .map_err(|_| eyre!("cannot decode selected native config"))?
        .parse()
        .map_err(|_| eyre!("cannot validate selected native config"))?;
    unchanged(path, &file, &before)?;
    ensure!(
        native.common.chain == binding.chain_id
            && native.genesis.expected_hash == binding.network_id.into_genesis_hash()
            && *native.common.chain_discriminant.value() == binding.chain_discriminant
            && matches!(native.kura.init_mode, iroha_config::kura::InitMode::Strict),
        "selected config differs from independent native anchor"
    );
    Ok(native)
}

fn limits() -> NativeFinalityLimits {
    NativeFinalityLimits {
        block_bytes: 32 * 1024 * 1024,
        journal_bytes: 64 * 1024 * 1024,
        block_count: 256,
        allocated_bytes: 512 * 1024 * 1024,
    }
}

fn native_journal(binding: &Binding, height: Option<u64>) -> Result<NativeFinalityJournal> {
    native_journal_with_deadline(binding, height, None)
}

// The ordinary reader and ceremony reader share the same source verification.
// Only a ceremony caller supplies its retained enclosing absolute deadline.
fn native_journal_with_deadline(
    binding: &Binding,
    height: Option<u64>,
    deadline: Option<Instant>,
) -> Result<NativeFinalityJournal> {
    if let Some(deadline) = deadline {
        ensure!(
            Instant::now() < deadline,
            "native phase finality deadline elapsed"
        );
    }
    // Keep native verification off accumulated asynchronous poll frames, as in
    // the maintained conductor fixture. This is a joined default-stack worker.
    std::thread::scope(|scope| {
        scope
            .spawn(|| -> Result<NativeFinalityJournal> {
                let _guard = ChainDiscriminantGuard::enter(binding.chain_discriminant);
                let native = native_config(&binding.validator_configs[0], binding)?;
                let mut store = BlockStore::open_read_only(Kura::canonical_storage_path(
                    native.kura.store_dir.value(),
                ))?;
                let count = store.read_index_count()?;
                let height = height.unwrap_or(count);
                ensure!(
                    (1..=limits().block_count as u64).contains(&height) && count >= height,
                    "durable native prefix is not available within bounds"
                );
                let mut blocks = Vec::new();
                let mut total = 0_usize;
                for at in 1..=height {
                    if let Some(deadline) = deadline {
                        ensure!(
                            Instant::now() < deadline,
                            "native phase finality deadline elapsed"
                        );
                    }
                    let mut index = [BlockIndex {
                        start: 0,
                        length: 0,
                    }];
                    store.read_block_indices(at - 1, &mut index)?;
                    let length = usize::try_from(index[0].length)?;
                    total = total
                        .checked_add(length)
                        .ok_or_else(|| eyre!("journal length overflow"))?;
                    ensure!(
                        length > 0
                            && length <= limits().block_bytes
                            && total <= limits().journal_bytes,
                        "native carrier exceeds preallocation bounds"
                    );
                    let mut bytes = Vec::new();
                    bytes.try_reserve_exact(length)?;
                    bytes.resize(length, 0);
                    store.read_block_data(index[0].start, &mut bytes)?;
                    blocks.push(NativeFinalityArtifact { block_wire: bytes });
                }
                let journal = NativeFinalityJournal { blocks };
                if height == 1 {
                    // H1 supplies signed genesis authority, never an invented QC.
                    let (block, _) = authenticate_signed_genesis(
                        &journal.blocks[0].block_wire,
                        binding.network_id,
                        limits(),
                    )
                    .map_err(|error| eyre!(error))?;
                    ensure!(
                        block.header().height().get() == 1,
                        "native genesis height differs"
                    );
                    if let Some(deadline) = deadline {
                        ensure!(
                            Instant::now() < deadline,
                            "native phase finality deadline elapsed"
                        );
                    }
                    return Ok(journal);
                }
                let mut cursor = NativeJournalCursor::new(
                    binding.chain_id.clone(),
                    binding.network_id,
                    SumeragiRootScope::Global,
                    limits(),
                    &iroha_allocation::AllocationBudget::new(
                        native
                            .runtime_provider_broker
                            .credential_max_memory_bytes
                            .get(),
                    ),
                )
                .map_err(|error| eyre!(error))?;
                ensure!(
                    cursor
                        .advance((&journal).into())
                        .map_err(|error| eyre!(error))?
                        .height()
                        == height,
                    "native phase height differs"
                );
                if let Some(deadline) = deadline {
                    ensure!(
                        Instant::now() < deadline,
                        "native phase finality deadline elapsed"
                    );
                }
                Ok(journal)
            })
            .join()
            .map_err(|_| eyre!("native journal worker panicked"))?
    })
}

fn genesis_roster(binding: &Binding) -> Result<Vec<PeerId>> {
    let native = native_config(&binding.validator_configs[0], binding)?;
    let manifest: iroha_genesis::RawGenesisTransaction =
        json::from_slice(&read_input(&binding.genesis_manifest, false)?)?;
    ensure!(
        manifest.chain_id() == &binding.chain_id
            && manifest.chain_discriminant() == binding.chain_discriminant,
        "manifest differs from independent chain"
    );
    let validated = iroha_genesis::validate_prepared_genesis_bundle(
        &read_input(&binding.genesis_signed, false)?,
        &manifest,
        &native.genesis.public_key,
        binding.network_id.into_genesis_hash(),
    )?;
    let roster = genesis_committee_peers(validated.block())?;
    ensure!(
        roster.len() == 4,
        "native bootstrap requires four validators"
    );
    Ok(roster)
}

fn phase_audit(
    binding: &Binding,
    roster: &[PeerId],
    height: u64,
    snapshot: &GlobalThresholdBeaconDkgSnapshotV1,
) -> Result<(PhaseAudit, Vec<u8>)> {
    let (purpose, edges, acceptances) = match height {
        2 => ("signed-dealer-commitments-complete", 0, 0),
        3 => ("signed-encrypted-deliveries-complete", 16, 0),
        4 => ("signed-recipient-acceptances-complete", 16, 16),
        _ => return Err(eyre!("unexpected native DKG audit phase")),
    };
    let session = snapshot.session;
    ensure!(
        roster.len() == 4
            && session.version == 1
            && session.network_id == binding.network_id
            && session.session_id == global_beacon_genesis_session_id_v1(binding.network_id)
            && session.attempt_id == global_beacon_genesis_attempt_id_v1(binding.network_id)
            && session.authority_generation == 0
            && session.roster_hash == global_threshold_beacon_roster_hash_v1(roster)
            && session.committee_size == 4
            && session.threshold == 2
            && session.start_height == 1
            && session.commitments_end_height == 2
            && session.deliveries_end_height == 3
            && session.acceptances_end_height == 4
            && snapshot.last_updated_height == height - 1
            && snapshot.recipient_keys.len() == 4
            && snapshot
                .recipient_keys
                .iter()
                .map(|key| &key.validator)
                .eq(roster.iter())
            && snapshot.dealer_commitments.len() == 4
            && snapshot.encrypted_shares.len() == edges
            && snapshot.share_acceptances.len() == acceptances,
        "public DKG snapshot differs from exact genesis phase, attempt or roster"
    );
    // Restoration re-derives the public generators and verifies every signed
    // record. Only this public DTO is encoded or hashed; no private share enters it.
    GlobalThresholdBeaconDkgStateV1::from_snapshot(
        snapshot,
        &AdaptiveGlobalThresholdBeaconDkgCryptoV1,
        &iroha_allocation::AllocationBudget::new(usize::try_from(FILE_BOUND)?),
    )?;
    let bytes = norito::encode_canonical(snapshot)?;
    ensure!(
        bytes.len() as u64 <= FILE_BOUND,
        "public DKG snapshot exceeds retention bound"
    );
    let audit = PhaseAudit {
        schema: "iroha.operator.genesis-beacon.phase-audit.v1".to_owned(),
        chain_id: binding.chain_id.clone(),
        network_id: binding.network_id,
        manifest_sha256: binding.manifest_sha256.clone(),
        signed_genesis_sha256: binding.signed_genesis_sha256.clone(),
        height,
        purpose: purpose.to_owned(),
        session,
        public_snapshot_sha256: hex(&sha256(&bytes)),
    };
    Ok((audit, bytes))
}

fn phase_instructions(audit: &PhaseAudit) -> Result<Vec<InstructionBox>> {
    // The ledger records the exact independently bound, publicly replayable
    // ceremony evidence. This is an audit action, not an empty-height request.
    Ok(vec![Log::new(Level::INFO, json::to_json(audit)?).into()])
}

fn retained_phase_audit(args: &Args, roster: &[PeerId], height: u64) -> Result<PhaseAudit> {
    let bytes = read_input(
        &args.output.join(format!("phase-h{height}-public.norito")),
        false,
    )?;
    let retained = read_input(
        &args.output.join(format!("phase-h{height}-audit.json")),
        false,
    )?;
    validate_retained_phase_audit(&args.binding, roster, height, &bytes, &retained)
}

fn validate_retained_phase_audit(
    binding: &Binding,
    roster: &[PeerId],
    height: u64,
    bytes: &[u8],
    audit_bytes: &[u8],
) -> Result<PhaseAudit> {
    let snapshot: GlobalThresholdBeaconDkgSnapshotV1 =
        norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))?;
    let (expected, canonical) = phase_audit(binding, roster, height, &snapshot)?;
    ensure!(
        canonical.as_slice() == bytes,
        "retained public DKG snapshot is not canonical"
    );
    let retained: PhaseAudit = json::from_slice(audit_bytes)?;
    ensure!(retained == expected, "retained public DKG audit changed");
    Ok(expected)
}

fn verify_transaction_carrier(
    journal: &NativeFinalityJournal,
    transaction: &SignedTransaction,
    height: u64,
    discriminant: u16,
) -> Result<()> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| -> Result<()> {
                let _guard = ChainDiscriminantGuard::enter(discriminant);
                let index = usize::try_from(
                    height
                        .checked_sub(1)
                        .ok_or_else(|| eyre!("zero transaction height"))?,
                )?;
                let block = journal
                    .blocks
                    .get(index)
                    .ok_or_else(|| eyre!("transaction carrier is absent"))?
                    .decode_block(limits())
                    .map_err(|error| eyre!(error))?;
                ensure!(
                    block
                        .external_transactions()
                        .any(|actual| actual == transaction),
                    "authenticated carrier does not contain the identical retained transaction"
                );
                Ok(())
            })
            .join()
            .map_err(|_| eyre!("transaction carrier worker panicked"))?
    })
}

fn retain_phase_journal(output: &Path, height: u64, journal: &NativeFinalityJournal) -> Result<()> {
    let bytes = norito::encode_canonical(journal)?;
    let path = output.join(format!("phase-h{height}.norito"));
    if path.try_exists()? {
        ensure!(
            read_input(&path, false)?.as_slice() == bytes,
            "retained native phase journal changed"
        );
    } else {
        write_new(&path, &bytes)?;
    }
    Ok(())
}

fn client(binding: &Binding) -> Result<Client> {
    let file = open_input(&binding.client_config, true, 1024 * 1024)?;
    let before = file.metadata()?;
    let config = iroha::config::Config::load_file(&binding.client_config)
        .map_err(|_| eyre!("cannot load selected runtime client"))?;
    unchanged(&binding.client_config, &file, &before)?;
    ensure!(
        config.chain == binding.chain_id
            && config.network_id == binding.network_id
            && config.account_chain_discriminant == binding.chain_discriminant,
        "runtime client differs from independent anchor"
    );
    Ok(Client::builder(config).build()?)
}

async fn recover_applied(
    client: &Client,
    transaction: &SignedTransaction,
    output: &Path,
    label: &str,
    expected_height: u64,
    discriminant: u16,
    deadline: Instant,
) -> Result<()> {
    ensure!(
        Instant::now() < deadline,
        "native transaction recovery deadline elapsed"
    );
    let client = client.with_request_deadline(deadline);
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(ACTION_TIMEOUT);
    let hash = transaction.hash();
    let outcome = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let _guard = ChainDiscriminantGuard::enter(discriminant);
                client.wait_for_transaction_applied(
                    hash,
                    TransactionWaitOptions {
                        timeout: remaining,
                        poll_interval: Duration::from_millis(500),
                    },
                )
            })
            .join()
            .map_err(|_| eyre!("transaction recovery worker panicked"))?
    })?;
    ensure!(
        Instant::now() < deadline,
        "native transaction recovery deadline elapsed"
    );
    ensure!(
        outcome.block_height == Some(expected_height),
        "transaction applied at another height"
    );
    let path = output.join(format!("{label}-transaction-applied.json"));
    if !path.try_exists()? {
        write_new(&path, &json::to_vec(&outcome)?)?;
    }
    Ok(())
}

async fn submit_once(
    client: &Client,
    instructions: Vec<InstructionBox>,
    output: &Path,
    label: &str,
    expected_height: u64,
    discriminant: u16,
    deadline: Instant,
) -> Result<()> {
    let deadline = deadline.min(Instant::now() + ACTION_TIMEOUT);
    ensure!(
        Instant::now() < deadline,
        "native transaction submission deadline elapsed"
    );
    let dispatch_client = client.with_request_deadline(deadline);
    let account = dispatch_client.account_client()?;
    let mut payload = account.prepare_transaction(AccountTransactionDraft::new(
        instructions,
        FeePaymentIntent::authority(Vec::new(), None),
        Metadata::default(),
    ))?;
    let quote = account
        .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
        .await?;
    ensure!(
        quote.observation.next_block_height == expected_height
            && payload
                .fee_payment
                .has_same_payer_and_gas_bound(&quote.intent),
        "fee quote changed exact height, payer or gas bound"
    );
    payload.fee_payment = quote.intent;
    let transaction = account.sign_transaction(payload)?;
    write_new(
        &output.join(format!("{label}-submitted.nrt")),
        &transaction.encode_wire_v1()?,
    )?;
    // There is exactly one dispatch. On an uncertain result only the maintained
    // read-only finality wait is used; recovery never posts this wire again.
    if let Err(error) = account.submit_transaction(&transaction).await {
        if error
            .downcast_ref::<TransactionDispatchOutcomeUnknownError>()
            .is_none()
        {
            return Err(eyre!(
                "transaction dispatch refused; exact signed wire is retained for read-only recovery"
            ));
        }
    }
    recover_applied(
        client,
        &transaction,
        output,
        label,
        expected_height,
        discriminant,
        deadline,
    )
    .await
}

fn scrub_table(value: &mut toml::Value) {
    match value {
        toml::Value::String(value) => value.zeroize(),
        toml::Value::Array(values) => values.iter_mut().for_each(scrub_table),
        toml::Value::Table(values) => values.iter_mut().for_each(|(_, value)| scrub_table(value)),
        _ => {}
    }
}

fn derived_config(path: &Path, provider: &Provider) -> Result<Zeroizing<Vec<u8>>> {
    let input = read_input(path, true)?;
    let text = std::str::from_utf8(&input).map_err(|_| eyre!("selected config is not UTF8"))?;
    let mut table: toml::Value =
        toml::from_str(text).map_err(|_| eyre!("selected config is not TOML"))?;
    let result = (|| {
        let root = table
            .as_table_mut()
            .ok_or_else(|| eyre!("config is not a table"))?;
        ensure!(
            !root.contains_key("extends"),
            "beacon projection refuses inherited config"
        );
        let sumeragi = root
            .get_mut("sumeragi")
            .and_then(toml::Value::as_table_mut)
            .ok_or_else(|| eyre!("config omits sumeragi"))?;
        ensure!(
            PROVIDER_FIELDS
                .iter()
                .all(|field| !sumeragi.contains_key(*field)),
            "config already has a beacon provider"
        );
        sumeragi.insert(
            PROVIDER_FIELDS[0].into(),
            toml::Value::String(provider.handle.clone()),
        );
        sumeragi.insert(
            PROVIDER_FIELDS[1].into(),
            toml::Value::Integer(i64::try_from(provider.revision)?),
        );
        sumeragi.insert(
            PROVIDER_FIELDS[2].into(),
            toml::Value::String(hex(&provider.policy_digest)),
        );
        Ok(Zeroizing::new(toml::to_string(&table)?.into_bytes()))
    })();
    scrub_table(&mut table);
    result
}

fn installation(
    output: &Path,
    ceremony: &Ceremony<GlobalThresholdBeaconKeySessionV1>,
) -> Result<Vec<InstructionBox>> {
    let path = output.join("install-instruction.json");
    ensure!(
        file_digest(&path, false)? == ceremony.instruction_sha256,
        "retained installation changed"
    );
    let instructions: Vec<InstructionBox> = json::from_slice(&read_input(&path, false)?)?;
    ensure!(
        instructions.len() == 1,
        "installation must be exactly one instruction"
    );
    let install = instructions[0]
        .as_any()
        .downcast_ref::<ApplyThresholdKeyLifecycleCertificateV1>()
        .ok_or_else(|| eyre!("installation is not the native lifecycle instruction"))?;
    ensure!(
        install.certificate.action == ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey
            && install.certificate.effective_height == 5,
        "installation misses the exact native genesis boundary"
    );
    let bundle: json::Value = json::from_slice(&read_input(
        &output.join("genesis-public-bundle.json"),
        false,
    )?)?;
    let expected: ThresholdKeyLifecycleCertificateV1 = json::from_value(
        bundle
            .get("finalization_draft")
            .ok_or_else(|| eyre!("native bundle omits certificate draft"))?
            .clone(),
    )?;
    let mut observed = install.certificate.clone();
    observed.signatures.clear();
    ensure!(
        observed == expected
            && bundle
                .get("finalized_observed_height")
                .and_then(json::Value::as_u64)
                == Some(4),
        "installation differs from original native certificate draft"
    );
    Ok(instructions)
}

fn retained_transaction(
    args: &Args,
    label: &str,
    instructions: &[InstructionBox],
) -> Result<SignedTransaction> {
    let bytes = read_input(&args.output.join(format!("{label}-submitted.nrt")), true)?;
    let transaction = SignedTransaction::decode_all_versioned(&bytes)?;
    ensure!(
        transaction.encode_wire_v1()?.as_slice() == bytes.as_slice(),
        "retained transaction is not canonical"
    );
    transaction.verify_signature()?;
    let config = iroha::config::Config::load_file(&args.binding.client_config)
        .map_err(|_| eyre!("cannot load recovery client"))?;
    let Executable::Instructions(actual) = transaction.instructions() else {
        return Err(eyre!(
            "retained transaction is not one exact instruction sequence"
        ));
    };
    ensure!(
        transaction.payload().network_id() == Some(&args.binding.network_id)
            && transaction.authority() == &config.account
            && actual.as_ref() == instructions,
        "retained transaction differs from original native action"
    );
    Ok(transaction)
}

async fn run(args: Args) -> Result<()> {
    let _guard = ChainDiscriminantGuard::enter(args.binding.chain_discriminant);
    directory(&args.binding.input_dir, true)?;
    ensure!(
        daemon_digest(&args.binding.daemon)? == args.binding.daemon_sha256,
        "selected daemon digest differs"
    );
    ensure!(
        file_digest(&args.binding.genesis_manifest, false)? == args.binding.manifest_sha256
            && file_digest(&args.binding.genesis_signed, false)?
                == args.binding.signed_genesis_sha256,
        "selected signed genesis bytes differ"
    );
    if args.recover || args.submit_retained_install {
        directory(&args.output, true)?;
        let binding: Binding =
            json::from_slice(&read_input(&args.output.join("attempt.json"), false)?)?;
        ensure!(
            binding == args.binding,
            "recovery differs from retained attempt"
        );
    } else {
        directory(
            args.output
                .parent()
                .ok_or_else(|| eyre!("output has no parent"))?,
            false,
        )?;
        fs::DirBuilder::new().mode(0o700).create(&args.output)?;
        write_new(
            &args.output.join("attempt.json"),
            &json::to_vec(&args.binding)?,
        )?;
    }
    let client = client(&args.binding)?;
    let ceremony_path = args.output.join("ceremony.json");
    if args.submit_retained_install {
        ensure!(
            ceremony_path.try_exists()?
                && !args.output.join("install-submitted.nrt").try_exists()?,
            "submission requires completed custody and no previously retained install; use read-only recovery after signing"
        );
    }
    if args.recover && !ceremony_path.try_exists()? {
        let roster = genesis_roster(&args.binding)?;
        for height in (2..=4).rev() {
            let label = format!("phase-h{height}");
            if !args
                .output
                .join(format!("{label}-submitted.nrt"))
                .try_exists()?
            {
                continue;
            }
            let audit = retained_phase_audit(&args, &roster, height)?;
            let transaction = retained_transaction(&args, &label, &phase_instructions(&audit)?)?;
            recover_applied(
                &client,
                &transaction,
                &args.output,
                &label,
                height,
                args.binding.chain_discriminant,
                Instant::now() + ACTION_TIMEOUT,
            )
            .await?;
            let journal = native_journal(&args.binding, Some(height))?;
            verify_transaction_carrier(
                &journal,
                &transaction,
                height,
                args.binding.chain_discriminant,
            )?;
            retain_phase_journal(&args.output, height, &journal)?;
            return Err(eyre!(
                "retained phase H{height} audit is Applied; DKG completion is absent and this consumed attempt cannot be restarted"
            ));
        }
        return Err(eyre!(
            "DKG completion is absent; recovery cannot restart or submit the consumed attempt"
        ));
    }
    if !args.recover && !args.submit_retained_install {
        let native = native_config(&args.binding.validator_configs[0], &args.binding)?;
        let manifest_json = read_input(&args.binding.genesis_manifest, false)?.to_vec();
        let signed_wire = read_input(&args.binding.genesis_signed, false)?.to_vec();
        let manifest: iroha_genesis::RawGenesisTransaction = json::from_slice(&manifest_json)?;
        ensure!(
            manifest.chain_id() == &args.binding.chain_id
                && manifest.chain_discriminant() == args.binding.chain_discriminant,
            "manifest differs from independent chain"
        );
        let validated = iroha_genesis::validate_prepared_genesis_bundle(
            &signed_wire,
            &manifest,
            &native.genesis.public_key,
            args.binding.network_id.into_genesis_hash(),
        )?;
        let roster = genesis_committee_peers(validated.block())?;
        ensure!(
            roster.len() == 4,
            "native bootstrap requires four validators"
        );
        let mut seats = Vec::new();
        for validator in &roster {
            let mut matching = Vec::new();
            for path in &args.binding.validator_configs {
                let config = native_config(path, &args.binding)?;
                if config.common.peer.id() == validator {
                    matching.push(path.clone());
                }
            }
            ensure!(matching.len() == 1, "validator config mapping is not exact");
            seats.push(DisposableGenesisConfigSeat {
                validator: validator.clone(),
                config_path: matching.remove(0),
            });
        }
        let tip = native_journal(&args.binding, None)?.blocks.len();
        ensure!(
            tip == 1,
            "fresh genesis bootstrap requires the exact signed H1 boundary"
        );
        let bundle = NativeGenesisProvisioningBundle {
            manifest_sha256: sha256(&manifest_json),
            manifest_json,
            signed_wire,
            public_key: native.genesis.public_key,
            block_hash: args.binding.network_id.into_genesis_hash(),
            chain_discriminant: args.binding.chain_discriminant,
        };
        let dkg = run_disposable_genesis_dkg_from_configs(
            bundle,
            args.binding.network_id,
            &args.binding.chain_id,
            &seats,
            &args.binding.daemon,
            limits(),
            5,
            |height, snapshot, deadline| {
                let binding = args.binding.clone();
                let output = args.output.clone();
                let client = client.clone();
                let roster = roster.clone();
                async move {
                    ensure!(
                        Instant::now() < deadline,
                        "native phase callback deadline elapsed"
                    );
                    ensure!((2..=4).contains(&height), "unexpected native DKG phase");
                    ensure!(
                        native_journal_with_deadline(&binding, None, Some(deadline))?
                            .blocks
                            .len() as u64
                            == height - 1,
                        "completed public DKG phase has lost its exact predecessor boundary"
                    );
                    let (audit, public_bytes) = phase_audit(&binding, &roster, height, &snapshot)?;
                    write_new(
                        &output.join(format!("phase-h{height}-public.norito")),
                        &public_bytes,
                    )?;
                    write_new(
                        &output.join(format!("phase-h{height}-audit.json")),
                        &json::to_vec(&audit)?,
                    )?;
                    let label = format!("phase-h{height}");
                    let instructions = phase_instructions(&audit)?;
                    submit_once(
                        &client,
                        instructions.clone(),
                        &output,
                        &label,
                        height,
                        binding.chain_discriminant,
                        deadline,
                    )
                    .await?;
                    loop {
                        let native = native_config(&binding.validator_configs[0], &binding)?;
                        let mut store = BlockStore::open_read_only(Kura::canonical_storage_path(
                            native.kura.store_dir.value(),
                        ))?;
                        if store.read_index_count()? >= height {
                            break;
                        }
                        ensure!(
                            Instant::now() < deadline,
                            "native phase was not durably stored before deadline"
                        );
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    ensure!(
                        Instant::now() < deadline,
                        "native phase callback deadline elapsed"
                    );
                    let journal =
                        native_journal_with_deadline(&binding, Some(height), Some(deadline))?;
                    ensure!(
                        Instant::now() < deadline,
                        "native phase callback deadline elapsed"
                    );
                    let phase_args = Args {
                        binding: binding.clone(),
                        output: output.clone(),
                        recover: true,
                        submit_retained_install: false,
                    };
                    let transaction = retained_transaction(&phase_args, &label, &instructions)?;
                    verify_transaction_carrier(
                        &journal,
                        &transaction,
                        height,
                        binding.chain_discriminant,
                    )?;
                    retain_phase_journal(&output, height, &journal)?;
                    ensure!(
                        Instant::now() < deadline,
                        "native phase callback deadline elapsed"
                    );
                    Ok(journal)
                }
            },
        )
        .await?;
        ensure!(
            daemon_digest(&args.binding.daemon)? == args.binding.daemon_sha256,
            "daemon changed during native ceremony"
        );
        let bundle = read_input(&dkg.public_bundle_path, false)?;
        let instruction = read_input(&dkg.install_instruction_path, false)?;
        write_new(&args.output.join("genesis-public-bundle.json"), &bundle)?;
        write_new(&args.output.join("install-instruction.json"), &instruction)?;
        let mut retained = Vec::new();
        for seat in &dkg.seats {
            let provider_bytes = read_input(&seat.provider_path, false)?;
            let provider: Provider = json::from_slice(&provider_bytes)?;
            ensure!(
                provider.validator == seat.validator
                    && provider.signer_index == seat.signer_index
                    && provider.handle == seat.provider_handle
                    && provider.revision == seat.provider_revision
                    && provider.policy_digest
                        == global_beacon_partial_signer_public_inventory_digest_v1(
                            args.binding.network_id,
                            &[(dkg.public_session.record(), seat.signer_index)]
                        )?,
                "native provider differs from exact completed seat"
            );
            iroha_config::parameters::validate_production_runtime_handle(&provider.handle)
                .map_err(|_| eyre!("native provider handle is not canonical"))?;
            let owner = args.output.join(format!("seat-{}", seat.signer_index));
            fs::DirBuilder::new().mode(0o700).create(&owner)?;
            let credential_path = owner.join(CREDENTIAL);
            write_new(&credential_path, &read_input(&seat.credential_path, true)?)?;
            let provider_path = owner.join("provider.json");
            write_new(&provider_path, &provider_bytes)?;
            let config_path = owner.join("beacon.toml");
            let original = &seats[usize::from(seat.signer_index - 1)].config_path;
            write_new(&config_path, &derived_config(original, &provider)?)?;
            native_config(&config_path, &args.binding)?;
            retained.push(RetainedSeat {
                provider,
                initial_config_path: original.clone(),
                initial_config_sha256: file_digest(original, true)?,
                credential_sha256: file_digest(&credential_path, true)?,
                credential_path,
                provider_sha256: file_digest(&provider_path, false)?,
                provider_path,
                config_sha256: file_digest(&config_path, true)?,
                config_path,
            });
        }
        let ceremony = Ceremony {
            schema: "iroha.operator.genesis-beacon.ceremony.v1".to_owned(),
            binding: args.binding.clone(),
            public_session: dkg.public_session.record(),
            bundle_sha256: hex(&sha256(&*bundle)),
            instruction_sha256: hex(&sha256(&*instruction)),
            seats: retained,
        };
        write_new(&ceremony_path, &json::to_vec(&ceremony)?)?;
    }
    // Recovery is deliberately limited to retained transactions. A consumed or
    // incomplete DKG attempt cannot be restarted through this command.
    let ceremony: Ceremony<GlobalThresholdBeaconKeySessionV1> =
        json::from_slice(&read_input(&ceremony_path, false)?)?;
    ensure!(
        ceremony.schema == "iroha.operator.genesis-beacon.ceremony.v1"
            && ceremony.binding == args.binding
            && ceremony.seats.len() == 4
            && file_digest(&args.output.join("genesis-public-bundle.json"), false)?
                == ceremony.bundle_sha256,
        "retained ceremony binding differs"
    );
    for (index, seat) in ceremony.seats.iter().enumerate() {
        ensure!(
            usize::from(seat.provider.signer_index) == index + 1
                && args
                    .binding
                    .validator_configs
                    .contains(&seat.initial_config_path),
            "retained seat ordering or initial config selection differs"
        );
        ensure!(
            file_digest(&seat.initial_config_path, true)? == seat.initial_config_sha256
                && native_config(&seat.initial_config_path, &args.binding)?
                    .common
                    .peer
                    .id()
                    == &seat.provider.validator,
            "retained initial validator binding changed"
        );
        ensure!(
            seat.credential_path
                == args
                    .output
                    .join(format!("seat-{}", seat.provider.signer_index))
                    .join(CREDENTIAL)
                && seat.provider_path
                    == seat
                        .credential_path
                        .parent()
                        .ok_or_else(|| eyre!("credential has no owner"))?
                        .join("provider.json")
                && seat.config_path
                    == seat
                        .credential_path
                        .parent()
                        .ok_or_else(|| eyre!("credential has no owner"))?
                        .join("beacon.toml"),
            "retained seat path is not its separate owner location"
        );
        directory(
            seat.credential_path
                .parent()
                .ok_or_else(|| eyre!("credential has no owner"))?,
            true,
        )?;
        ensure!(
            file_digest(&seat.credential_path, true)? == seat.credential_sha256
                && file_digest(&seat.provider_path, false)? == seat.provider_sha256
                && file_digest(&seat.config_path, true)? == seat.config_sha256,
            "retained provider custody changed"
        );
    }
    let instructions = installation(&args.output, &ceremony)?;
    // Ceremony completion can outlive an idle HTTP connection. Installation has
    // a fresh SDK transport; retained signed wire still prevents a second post.
    let install_client = self::client(&args.binding)?;
    if args.recover {
        let transaction = retained_transaction(&args, "install", &instructions)?;
        recover_applied(
            &install_client,
            &transaction,
            &args.output,
            "install",
            5,
            args.binding.chain_discriminant,
            Instant::now() + ACTION_TIMEOUT,
        )
        .await?;
    } else {
        submit_once(
            &install_client,
            instructions.clone(),
            &args.output,
            "install",
            5,
            args.binding.chain_discriminant,
            Instant::now() + ACTION_TIMEOUT,
        )
        .await?;
    }
    let transaction = retained_transaction(&args, "install", &instructions)?;
    let journal = native_journal(&args.binding, Some(5))?;
    verify_transaction_carrier(&journal, &transaction, 5, args.binding.chain_discriminant)?;
    let receipt = Receipt {
        schema: "iroha.operator.genesis-beacon.install-applied.v1".to_owned(),
        chain_id: args.binding.chain_id,
        network_id: args.binding.network_id,
        install_applied: true,
        install_transaction_hash: transaction.hash(),
        install_height: 5,
        session: ceremony.public_session,
        seats: ceremony.seats,
    };
    let bytes = json::to_vec(&receipt)?;
    let receipt_path = args.output.join("install-applied.json");
    if receipt_path.try_exists()? {
        ensure!(
            read_input(&receipt_path, false)?.as_slice() == bytes,
            "retained install receipt changed"
        );
    } else {
        write_new(&receipt_path, &bytes)?;
    }
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = arguments(std::env::args().skip(1))?;
    // Errors identify public paths and refusal classes, never private material.
    Box::pin(run(args)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::beacon::{
        LocalGlobalThresholdBeaconDkgSeatV1, PreparedLocalGlobalThresholdBeaconDkgSeatV1,
        ceremony::global_beacon_genesis_dkg_session_v1,
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair, Signature};
    use iroha_data_model::block::BlockHeader;

    type AuditFixture = (
        Binding,
        Vec<PeerId>,
        [GlobalThresholdBeaconDkgSnapshotV1; 3],
    );

    fn audit_fixture() -> &'static AuditFixture {
        static FIXTURE: std::sync::LazyLock<AuditFixture> = std::sync::LazyLock::new(|| {
            let mut signers = (1..=4)
                .map(|index| KeyPair::try_from_seed(vec![index; 32], Algorithm::BlsNormal).unwrap())
                .collect::<Vec<_>>();
            signers.sort_by(|left, right| left.public_key().cmp(right.public_key()));
            let roster = signers
                .iter()
                .map(|key| PeerId::new(key.public_key().clone()))
                .collect::<Vec<_>>();
            let network_id = NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"phase-audit-test")),
            );
            let binding = Binding {
                input_dir: "/native/input".into(),
                daemon: "/native/iroha3d".into(),
                daemon_sha256: "0".repeat(64),
                chain_id: ChainId::from("phase-audit-test"),
                network_id,
                chain_discriminant: 369,
                genesis_manifest: "/native/input/genesis.json".into(),
                manifest_sha256: "1".repeat(64),
                genesis_signed: "/native/input/genesis.signed.nrt".into(),
                signed_genesis_sha256: "2".repeat(64),
                client_config: "/native/input/client.toml".into(),
                validator_configs: Vec::new(),
            };
            let session = global_beacon_genesis_dkg_session_v1(network_id, &roster).unwrap();
            let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
            let mut local = signers
                .iter()
                .enumerate()
                .map(|(index, signer)| {
                    PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
                        session,
                        &roster,
                        u16::try_from(index + 1).unwrap(),
                        signer,
                        &budget,
                    )
                    .unwrap()
                    .generate(signer)
                    .unwrap()
                })
                .collect::<Vec<_>>();
            let publications = local
                .iter()
                .map(LocalGlobalThresholdBeaconDkgSeatV1::publication)
                .collect::<Vec<_>>();
            let keys = publications
                .iter()
                .map(|(key, _)| (**key).clone())
                .collect::<Vec<_>>();
            let commitments = publications
                .iter()
                .map(|(_, commitment)| (**commitment).clone())
                .collect::<Vec<_>>();
            let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;
            let mut public =
                GlobalThresholdBeaconDkgStateV1::new(session, &crypto, &budget).unwrap();
            for key in &keys {
                public.record_recipient_key(1, key).unwrap();
            }
            for commitment in &commitments {
                public
                    .record_dealer_commitment(1, commitment, &crypto)
                    .unwrap();
            }
            let committed = public.public_snapshot().unwrap();
            for (seat, signer) in local.iter_mut().zip(&signers) {
                for edge in seat.deliver(&keys, &commitments, 2, signer).unwrap() {
                    public.record_encrypted_share(2, edge).unwrap();
                }
            }
            // Logical audit fixture mirrors completed original public publication;
            // the daemon owns the actual file/directory durability requirement.
            for seat in &mut local {
                seat.retire_durably_published_dealer().unwrap();
            }
            let delivered = public.public_snapshot().unwrap();
            for (seat, signer) in local.iter_mut().zip(&signers) {
                for acceptance in seat.accept(&delivered, 3, signer).unwrap() {
                    public.record_share_acceptance(3, acceptance).unwrap();
                }
            }
            let accepted = public.public_snapshot().unwrap();
            public.finalize(4, &crypto).unwrap();
            assert!(
                public.public_snapshot().is_err(),
                "acceptance snapshot must precede consuming finalization"
            );
            let phases = [
                committed.record().clone(),
                delivered.record().clone(),
                accepted.record().clone(),
            ];
            drop(committed);
            drop(delivered);
            drop(accepted);
            drop(local);
            drop(public);
            assert_eq!(budget.reserved_bytes(), 0);
            (binding, roster, phases)
        });
        &FIXTURE
    }

    #[test]
    fn phase_audits_bind_real_signed_stage_purpose_and_genesis_context() {
        let (binding, roster, snapshots) = audit_fixture();
        let mut digests = Vec::new();
        for (index, snapshot) in snapshots.iter().enumerate() {
            let height = u64::try_from(index + 2).unwrap();
            let (audit, bytes) = phase_audit(binding, roster, height, snapshot).unwrap();
            let instructions = phase_instructions(&audit).unwrap();
            let log = instructions[0].as_any().downcast_ref::<Log>().unwrap();
            assert_eq!(log.level, Level::INFO);
            let recorded: PhaseAudit = json::from_str(&log.msg).unwrap();
            assert_eq!(recorded, audit);
            assert_eq!(audit.network_id, binding.network_id);
            assert_eq!(audit.manifest_sha256, binding.manifest_sha256);
            assert_eq!(audit.signed_genesis_sha256, binding.signed_genesis_sha256);
            assert_eq!(audit.public_snapshot_sha256, hex(&sha256(&bytes)));
            assert_ne!(audit.purpose, format!("phase-h{height}"));
            digests.push(audit.public_snapshot_sha256);
            assert!(phase_audit(binding, roster, height + 1, snapshot).is_err());
        }
        assert!(digests.windows(2).all(|pair| pair[0] != pair[1]));
        let mut forged = snapshots[0].clone();
        forged.dealer_commitments[0].signature = Signature::from_bytes(&[]);
        assert!(phase_audit(binding, roster, 2, &forged).is_err());
        let mut foreign = snapshots[0].clone();
        foreign.session.attempt_id[0] ^= 1;
        assert!(phase_audit(binding, roster, 2, &foreign).is_err());
        let mut reordered = roster.clone();
        reordered.swap(0, 1);
        assert!(phase_audit(binding, &reordered, 2, &snapshots[0]).is_err());
    }

    #[test]
    fn retained_phase_audit_regenerates_identical_action_and_rejects_substitution() {
        let (binding, roster, snapshots) = audit_fixture();
        let (audit, bytes) = phase_audit(binding, roster, 3, &snapshots[1]).unwrap();
        let audit_bytes = json::to_vec(&audit).unwrap();
        let recovered =
            validate_retained_phase_audit(binding, roster, 3, &bytes, &audit_bytes).unwrap();
        assert_eq!(
            phase_instructions(&recovered).unwrap(),
            phase_instructions(&audit).unwrap()
        );
        assert!(validate_retained_phase_audit(binding, roster, 4, &bytes, &audit_bytes).is_err());
        let mut substituted = audit.clone();
        substituted.public_snapshot_sha256 = "3".repeat(64);
        assert!(
            validate_retained_phase_audit(
                binding,
                roster,
                3,
                &bytes,
                &json::to_vec(&substituted).unwrap()
            )
            .is_err()
        );
        let mut foreign_binding = binding.clone();
        foreign_binding.signed_genesis_sha256 = "4".repeat(64);
        assert!(
            validate_retained_phase_audit(&foreign_binding, roster, 3, &bytes, &audit_bytes)
                .is_err()
        );
        let mut corrupted = bytes.clone();
        corrupted.pop();
        assert!(
            validate_retained_phase_audit(binding, roster, 3, &corrupted, &audit_bytes).is_err()
        );
    }

    #[test]
    fn ceremony_json_borrows_the_public_field_without_changing_recovery_bytes() {
        // The generic ceremony container has one JSON layout. Session proof
        // validation stays at its existing native boundary, independently of
        // whether this encoding borrows a retained graph or owns decoded data.
        let binding = Binding {
            input_dir: PathBuf::from("input"),
            daemon: PathBuf::from("iroha3d"),
            daemon_sha256: "a".repeat(64),
            chain_id: ChainId::from("ceremony-container"),
            network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"ceremony-container"),
            )),
            chain_discriminant: 42,
            genesis_manifest: PathBuf::from("genesis.json"),
            manifest_sha256: "b".repeat(64),
            genesis_signed: PathBuf::from("genesis.norito"),
            signed_genesis_sha256: "c".repeat(64),
            client_config: PathBuf::from("client.toml"),
            validator_configs: Vec::new(),
        };
        #[derive(Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
        struct PublicField {
            values: Vec<u16>,
        }
        let public_field = PublicField {
            values: vec![3_u16, 7, 31],
        };
        let borrowed = Ceremony {
            schema: "iroha.operator.genesis-beacon.ceremony.v1".to_owned(),
            binding: binding.clone(),
            public_session: &public_field,
            bundle_sha256: "d".repeat(64),
            instruction_sha256: "e".repeat(64),
            seats: Vec::new(),
        };
        let bytes = json::to_vec(&borrowed).unwrap();
        let recovered: Ceremony<PublicField> = json::from_slice(&bytes).unwrap();
        assert_eq!(recovered.public_session, public_field);
        assert!(recovered.binding == binding);
        assert_eq!(json::to_vec(&recovered).unwrap(), bytes);
        assert!(std::ptr::eq(borrowed.public_session, &public_field));
    }

    #[test]
    fn operator_rejects_secret_arguments_and_noncanonical_digests() {
        assert!(arguments(["--private-key".to_owned(), "secret".to_owned()]).is_err());
        assert!(digest_literal("A".repeat(64)).is_err());
        assert!(digest_literal("0".repeat(63)).is_err());
        assert!(digest_literal("a".repeat(64)).is_ok());
        assert!(
            arguments([
                "--recover".to_owned(),
                "--submit-retained-install".to_owned()
            ])
            .is_err()
        );
    }

    #[test]
    fn operator_daemon_digest_streams_executable_above_old_bound() {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().expect("private daemon test directory");
        let root_path = root
            .path()
            .canonicalize()
            .expect("canonical daemon test directory");
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700))
            .expect("owner-only daemon test directory");
        directory(&root_path, true).expect("safe daemon test directory ancestry");
        let path = root_path.join("daemon");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)
            .expect("new owned executable daemon fixture");
        file.set_len(512 * 1024 * 1024 + 1)
            .expect("sparse daemon above historical limit");
        drop(file);
        let before = fs::symlink_metadata(&path).expect("fixture metadata");
        // Independently precomputed SHA-256 of exactly 536870913 zero bytes.
        // Sparse set_len and the shared fixed-buffer reader avoid a full-file allocation.
        assert_eq!(
            daemon_digest(&path).expect("large executable daemon authenticates"),
            "7c40fe5ce847740d0f0d0cdde3949d6585804cdec3ae61a15b923165699c8137"
        );
        assert_eq!(
            identity(&before),
            identity(&fs::symlink_metadata(&path).expect("unchanged fixture metadata"))
        );
    }

    #[test]
    fn operator_daemon_digest_refuses_oversized_and_nonexecutable_files() {
        use std::{
            io::Write as _,
            os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
        };

        let root = tempfile::tempdir().expect("private daemon test directory");
        let root_path = root
            .path()
            .canonicalize()
            .expect("canonical daemon test directory");
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700))
            .expect("owner-only daemon test directory");
        directory(&root_path, true).expect("safe daemon test directory ancestry");
        let oversized = root_path.join("oversized-daemon");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&oversized)
            .expect("new owned oversized executable fixture");
        file.set_len(DAEMON_BOUND + 1)
            .expect("sparse daemon above current limit");
        drop(file);
        let error = daemon_digest(&oversized).expect_err("size rejects before hashing");
        assert!(
            error
                .to_string()
                .contains("input file exceeds custody or size bounds")
        );

        let nonexecutable = root_path.join("nonexecutable-daemon");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&nonexecutable)
            .expect("new owned nonexecutable fixture");
        file.write_all(b"daemon").expect("small fixture body");
        drop(file);
        let error = daemon_digest(&nonexecutable).expect_err("executable permission required");
        assert!(error.to_string().contains("daemon is not executable"));
    }

    #[test]
    fn operator_private_outputs_refuse_replacement() {
        let root = tempfile::tempdir().expect("private test directory");
        let path = root.path().join("attempt.json");
        write_new(&path, b"first").expect("first durable output");
        assert!(write_new(&path, b"second").is_err());
        assert_eq!(fs::read(&path).expect("original output"), b"first");
    }
}
