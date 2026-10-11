//! Real per-seat DKG exchange for disposable multi-validator networks.

use super::*;
use color_eyre::eyre::ensure;
use iroha_core::sumeragi::native_journal::{NativeJournalCursor, authenticate_signed_genesis};
use iroha_core::{
    beacon::{
        AdaptiveGlobalThresholdBeaconDkgCryptoV1, GlobalThresholdBeaconDkgSnapshotV1,
        GlobalThresholdBeaconDkgStateV1, RetainedGlobalThresholdBeaconDkgFinalizationV1,
        RetainedGlobalThresholdBeaconDkgSnapshotV1, global_threshold_beacon_roster_hash_v1,
    },
    validator_committee_evidence::{
        ValidatorCommitteeProvisioningEvidenceV1, ValidatorCommitteeSelectionEvidenceV1,
        verify_validator_committee_provisioning_evidence_v1,
        verify_validator_committee_selection_evidence_v1,
    },
};
use iroha_data_model::{
    NetworkId,
    consensus::{GlobalThresholdBeaconDkgSessionV1, GlobalThresholdBeaconKeySessionV1},
    sumeragi::finality::{NativeFinalityJournal, NativeFinalityLimits},
};
use norito::derive::JsonSerialize;
use std::{
    os::{
        fd::AsRawFd as _,
        unix::{
            fs::{MetadataExt as _, OpenOptionsExt as _},
            process::CommandExt as _,
        },
    },
    time::Instant,
};
use tempfile::TempDir;

const KEY_FD: i32 = 198;
const PUBLIC_FD: i32 = 201;
const FINALITY_FD: i32 = 202;
const MAX_PUBLIC_FRAME_BYTES: usize = 32 * 1024 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(600);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const GLOBAL_BEACON_CREDENTIAL_FILE: &str = "iroha-global-beacon-partial-signer-v1.norito";

/// Independently anchored arguments to the native per-seat rotation command.
#[derive(Clone, Debug)]
pub struct DisposableRotationProofInput {
    /// Signed-genesis network identity.
    pub network_id: NetworkId,
    /// Independently configured chain instance, never inferred from returned proof bytes.
    pub chain_id: ChainId,
    /// Explicit finite source and cumulative decoded-allocation limits.
    pub finality_limits: NativeFinalityLimits,
    /// Exact scheduling epoch of the frozen target.
    pub target_epoch: u64,
    /// Exact frozen transition, independently selected by the operator.
    pub transition_id: CryptoHash,
}

/// Independently pinned inputs to one native pending-custody preparation.
#[derive(Clone, Debug)]
pub struct DisposablePendingCustodyInput {
    /// Explicit original registry limit; must equal the current catalog when retaining custody.
    pub credential_max_memory_bytes: std::num::NonZeroUsize,
    /// Signed-genesis network identity.
    pub network_id: NetworkId,
    /// Explicit finite source and cumulative decoded-allocation limits.
    pub finality_limits: NativeFinalityLimits,
    /// Exact target scheduling epoch.
    pub target_epoch: u64,
    /// Exact immutable frozen attempt.
    pub transition_id: CryptoHash,
    /// Actual validator that owns the private pending share.
    pub local_validator: PeerId,
    /// Signed chain identifier consumed by the stock provider catalog.
    pub chain_id: String,
    /// Exact production provider handle for this seat.
    pub handle: String,
    /// New catalog revision after retaining incumbent custody.
    pub revision: u64,
}

/// One current credential and its authenticated public catalog for an incumbent seat.
pub struct DisposableRetainedBeaconCredential<'a> {
    /// Owner-private native credential file; never passed on argv.
    pub credential_path: &'a Path,
    /// Canonical public catalog qualifying that credential.
    pub catalog: &'a [u8],
}

/// Native atomic current-plus-pending generation for one actual target process.
pub struct DisposablePreparedBeaconCustody {
    /// Exact validator that owns the prepared credential.
    pub validator: PeerId,
    /// Production credential frame retained in the owner-private generation.
    pub credential_path: PathBuf,
    /// Canonical public catalog for the prepared credential.
    pub catalog_path: PathBuf,
    /// Native signed-context preparation receipt.
    pub receipt_path: PathBuf,
    _owner_root: Arc<TempDir>,
}

/// One real target seat's private output, retained only in its owner-private root.
pub struct DisposableRotationSeatOutput {
    /// Frozen validator identity served by this DKG process.
    pub validator: PeerId,
    /// One-based index in the exact frozen roster.
    pub signer_index: u16,
    /// Exact credential-free provider identity pinned by the native seat request.
    pub provider_handle: String,
    /// Exact public catalog revision pinned by the native seat request.
    pub provider_revision: u64,
    /// Exact canonical single-session credential for this seat alone.
    pub credential_path: PathBuf,
    /// Exact private share for production current-plus-pending custody preparation.
    pub pending_share_path: PathBuf,
    /// Non-secret public provider identity and qualification digest.
    pub provider_path: PathBuf,
    _owner_root: Arc<TempDir>,
}

/// One signed-genesis voter and its owner-private native validator config.
///
/// The native config reader resolves this direct generated root at its original
/// origin. The seat child consumes a separate canonical BLS key record through
/// FD198; its private key never appears in command arguments or environment values.
#[derive(Clone, Debug)]
pub struct DisposableGenesisConfigSeat {
    /// Exact voter in the signed genesis roster.
    pub validator: PeerId,
    /// Direct owner-private generated validator config with this voter's key.
    pub config_path: PathBuf,
}

/// Public finalized DKG result and separate private output for each real seat.
pub struct DisposableRotationDkgOutput {
    /// All-edge finalized public transcript retaining the original ceremony pool.
    pub public_session: RetainedGlobalThresholdBeaconDkgFinalizationV1,
    /// One output per exact frozen roster seat, in roster order.
    pub seats: Vec<DisposableRotationSeatOutput>,
    /// Native operator bundle containing the independently verified public record.
    pub public_bundle_path: PathBuf,
    /// Native exact-incumbent-quorum finalization instructions, encoded as Norito JSON.
    pub finalization_instruction_path: PathBuf,
    _controller_root: Arc<TempDir>,
}

/// Four independently provisioned genesis shares and their quorum-signed install instruction.
pub struct DisposableGenesisDkgOutput {
    /// Finalized public session and original pool custody assembled from every signed edge.
    pub public_session: RetainedGlobalThresholdBeaconDkgFinalizationV1,
    /// One private output for each signed-genesis voter, in exact roster order.
    pub seats: Vec<DisposableRotationSeatOutput>,
    /// Native operator bundle containing the independently verified public record.
    pub public_bundle_path: PathBuf,
    /// Native quorum-assembled installation instructions, encoded as Norito JSON.
    pub install_instruction_path: PathBuf,
    _controller_root: Arc<TempDir>,
}

#[derive(JsonSerialize)]
struct GenesisRequest {
    schema: String,
    dkg_session: GlobalThresholdBeaconDkgSessionV1,
    target_roster: Vec<PeerId>,
    authorization_roster: Vec<PeerId>,
    provider_handles: Vec<String>,
    provider_revision: u64,
}

struct SeatProcess {
    validator: PeerId,
    signer_index: u16,
    child: Child,
    public_writer: fs::File,
    finality_writer: fs::File,
    attempt_path: PathBuf,
    owner_root: Arc<TempDir>,
}

fn attempt_child_name(session: &GlobalThresholdBeaconDkgSessionV1, signer_index: u16) -> String {
    use fmt::Write as _;
    let mut name = String::from("attempt-");
    for byte in session.attempt_id {
        write!(name, "{byte:02x}").expect("writing into a String cannot fail");
    }
    write!(name, "-seat-{signer_index}").expect("writing into a String cannot fail");
    name
}

fn provider_handle(peer: &PeerId) -> String {
    use fmt::Write as _;
    let identity: [u8; 32] =
        CryptoHash::new_from_chunks(&[b"iroha:disposable-beacon-provider:v1", &peer.encode()])
            .into();
    let mut handle = String::from("software://iroha/global-beacon/disposable-validator-");
    for byte in identity {
        write!(handle, "{byte:02x}").expect("writing into a String cannot fail");
    }
    handle
}

// The verified generation contains canonical PeerIds. Keep every seat and its order bound
// to that authenticated generation before starting the target DKG processes.
fn verify_incumbent_seats(seats: &[&NetworkPeer], incumbent: &[PeerId]) -> Result<()> {
    ensure!(
        seats.len() == incumbent.len()
            && seats
                .iter()
                .zip(incumbent)
                .all(|(seat, peer)| seat.id() == *peer),
        "rotation signers must match the complete exact incumbent roster in order"
    );
    Ok(())
}

fn verify_input(
    seats: &[&NetworkPeer],
    authorizing_seats: &[&NetworkPeer],
    evidence: &ValidatorCommitteeSelectionEvidenceV1,
    input: &DisposableRotationProofInput,
) -> Result<(GlobalThresholdBeaconDkgSessionV1, NativeJournalCursor)> {
    let mut verifier = NativeJournalCursor::new(
        input.chain_id.clone(),
        input.network_id,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        input.finality_limits,
        &iroha_allocation::AllocationBudget::new(input.finality_limits.allocated_bytes),
    )
    .map_err(|error| eyre!(error))?;
    let selected = verify_validator_committee_selection_evidence_v1(
        evidence,
        &input.chain_id,
        input.network_id,
        input.target_epoch,
        input.transition_id.into(),
        input.finality_limits,
        verifier.allocation_budget(),
    )
    .wrap_err("rotation selection evidence verification failed")?;
    let preparation = selected.preparation();
    verify_incumbent_seats(
        authorizing_seats,
        &selected.incumbent_authority().validators,
    )?;
    let roster = preparation
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<Vec<_>>();
    ensure!(
        roster.len() == seats.len()
            && seats
                .iter()
                .zip(&roster)
                .all(|(seat, peer)| seat.id() == *peer)
            && iroha_data_model::block::consensus::is_valid_committee_size(roster.len()),
        "rotation processes must match every exact frozen 3f+1 seat in order"
    );
    let observed = selected.observed_height();
    let commitments_end_height = observed
        .checked_add(1)
        .ok_or_else(|| eyre!("height overflow"))?;
    let deliveries_end_height = observed
        .checked_add(2)
        .ok_or_else(|| eyre!("height overflow"))?;
    let acceptances_end_height = observed
        .checked_add(3)
        .ok_or_else(|| eyre!("height overflow"))?;
    let cutoff = preparation
        .first_height
        .checked_sub(1)
        .ok_or_else(|| eyre!("invalid cutoff"))?;
    ensure!(
        acceptances_end_height < cutoff,
        "rotation DKG misses the preparation cutoff"
    );
    verifier
        .advance((&evidence.finality_journal).into())
        .map_err(|error| eyre!(error))?;
    Ok((
        GlobalThresholdBeaconDkgSessionV1 {
            version: 1,
            network_id: input.network_id,
            session_id: preparation
                .beacon_session_id()
                .map_err(|error| eyre!(error))?,
            attempt_id: preparation.transition_id().map_err(|error| eyre!(error))?,
            authority_generation: preparation.authority_generation,
            roster_hash: global_threshold_beacon_roster_hash_v1(&roster),
            committee_size: u16::try_from(roster.len())?,
            threshold: u16::try_from((roster.len() - 1) / 3 + 1)?,
            start_height: observed,
            commitments_end_height,
            deliveries_end_height,
            acceptances_end_height,
        },
        verifier,
    ))
}

fn write_frame(writer: &mut fs::File, bytes: &[u8], limit: usize, deadline: Instant) -> Result<()> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};

    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "rotation frame has invalid size"
    );
    let length = u32::try_from(bytes.len())?.to_be_bytes();
    // A blocking FIFO write larger than its current capacity can deadlock a
    // polling reader after the length prefix on Darwin. Keep the original
    // frame and operation deadline, but send bounded nonblocking pieces.
    let flags = OFlag::from_bits_retain(fcntl(&*writer, FcntlArg::F_GETFL)?);
    fcntl(&*writer, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    for part in [&length[..], bytes] {
        let mut remaining = part;
        while !remaining.is_empty() {
            ensure!(
                Instant::now() < deadline,
                "rotation transport deadline elapsed"
            );
            match writer.write(&remaining[..remaining.len().min(4_096)]) {
                Ok(0) => return Err(std::io::Error::from(ErrorKind::WriteZero).into()),
                Ok(count) => remaining = &remaining[count..],
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(
                        Duration::from_millis(1)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn broadcast_public<T: norito::NoritoSerialize>(
    seats: &mut [SeatProcess],
    value: &T,
    deadline: Instant,
) -> Result<()> {
    let bytes = norito::encode_canonical(value)?;
    for seat in seats {
        write_frame(
            &mut seat.public_writer,
            &bytes,
            MAX_PUBLIC_FRAME_BYTES,
            deadline,
        )?;
    }
    Ok(())
}

/// Explicit bounded operation policy for disposable DKG processes.
fn credential_memory_args(bytes: std::num::NonZeroUsize) -> [String; 2] {
    [
        "--credential-max-memory-bytes".to_owned(),
        bytes.get().to_string(),
    ]
}

fn finality_limit_args(limits: NativeFinalityLimits) -> Vec<String> {
    vec![
        "--finality-block-bytes".into(),
        limits.block_bytes.to_string(),
        "--finality-journal-bytes".into(),
        limits.journal_bytes.to_string(),
        "--finality-block-count".into(),
        limits.block_count.to_string(),
        "--finality-allocated-bytes".into(),
        limits.allocated_bytes.to_string(),
    ]
}

/// The cursor authenticates real source heights before a public phase advances.
fn advance_native_phase(
    cursor: &mut NativeJournalCursor,
    journal: &NativeFinalityJournal,
    height: u64,
) -> Result<()> {
    ensure!(
        u64::try_from(journal.blocks.len())? == height,
        "native phase source count differs from requested height"
    );
    ensure!(
        cursor
            .tip()
            .map(|tip| tip.height())
            .unwrap_or(1)
            .checked_add(1)
            == Some(height),
        "native phase is not consecutive"
    );
    ensure!(
        cursor
            .advance(journal.into())
            .map_err(|error| eyre!(error))?
            .height()
            == height,
        "native phase source differs from requested height"
    );
    Ok(())
}

fn encode_phase_journal(
    journal: &NativeFinalityJournal,
    limits: NativeFinalityLimits,
) -> Result<Vec<u8>> {
    journal
        .validate_source(limits)
        .map_err(|error| eyre!(error))?;
    let count = {
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        norito::core::encoded_payload_len(journal)?
            .checked_add(norito::core::Header::SIZE)
            .ok_or_else(|| eyre!("native phase archive size overflow"))?
    };
    ensure!(
        count <= limits.journal_bytes,
        "native phase archive exceeds configured transport before encoding"
    );
    let bytes = norito::encode_canonical(journal)?;
    ensure!(
        bytes.len() == count,
        "native phase archive length changed during encoding"
    );
    Ok(bytes)
}

// Persist the complete unchanged journal contract before passing its original
// owner into the next phase. A deadline/IO error is terminal; no file is retried
// or supplied to the later public signing commands after refusal.
fn write_rotation_phase_journal(
    directory: &Path,
    journal: &NativeFinalityJournal,
    limits: NativeFinalityLimits,
    deadline: Instant,
) -> Result<PathBuf> {
    ensure!(
        Instant::now() < deadline,
        "rotation phase archive deadline elapsed"
    );
    let path = directory.join(format!("phase-{}.norito", journal.blocks.len()));
    fs::write(&path, encode_phase_journal(journal, limits)?)?;
    ensure!(
        Instant::now() < deadline,
        "rotation phase archive deadline elapsed"
    );
    Ok(path)
}

fn broadcast_finality(
    seats: &mut [SeatProcess],
    journal: &NativeFinalityJournal,
    limits: NativeFinalityLimits,
    deadline: Instant,
) -> Result<()> {
    let bytes = encode_phase_journal(journal, limits)?;
    for seat in seats {
        write_frame(
            &mut seat.finality_writer,
            &bytes,
            limits.journal_bytes,
            deadline,
        )?;
    }
    Ok(())
}

fn read_public_snapshot(
    path: &Path,
    maximum: usize,
) -> Result<Option<GlobalThresholdBeaconDkgSnapshotV1>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        bytes.len() <= maximum,
        "rotation public artifact exceeds its bound"
    );
    match norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
    {
        Ok(snapshot) => Ok(Some(snapshot)),
        // The daemon creates an output file before finishing its write; a
        // partial frame is not an observation and must be read again.
        Err(_) => Ok(None),
    }
}

async fn wait_for_snapshots(
    seats: &mut [SeatProcess],
    name: &str,
    deadline: Instant,
) -> Result<Vec<GlobalThresholdBeaconDkgSnapshotV1>> {
    let mut observed = (0..seats.len()).map(|_| None).collect::<Vec<_>>();
    loop {
        ensure!(Instant::now() < deadline, "rotation {name} phase timed out");
        for (index, seat) in seats.iter_mut().enumerate() {
            if observed[index].is_some() {
                continue;
            }
            if let Some(snapshot) =
                read_public_snapshot(&seat.attempt_path.join(name), MAX_PUBLIC_FRAME_BYTES)?
            {
                observed[index] = Some(snapshot);
            } else if let Some(status) = seat.child.try_wait()? {
                return Err(eyre!(
                    "rotation seat {} exited before {name}: {status}; private diagnostics: {}",
                    seat.signer_index,
                    seat.owner_root.path().display()
                ));
            }
        }
        if observed.iter().all(Option::is_some) {
            return observed
                .into_iter()
                .map(|snapshot| snapshot.ok_or_else(|| eyre!("missing rotation snapshot")))
                .collect();
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn merge_publications(
    session: GlobalThresholdBeaconDkgSessionV1,
    snapshots: &[GlobalThresholdBeaconDkgSnapshotV1],
    crypto: &AdaptiveGlobalThresholdBeaconDkgCryptoV1,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<GlobalThresholdBeaconDkgStateV1> {
    let mut state = GlobalThresholdBeaconDkgStateV1::new(session, crypto, budget)?;
    for (index, snapshot) in snapshots.iter().enumerate() {
        let seat_index = u16::try_from(index + 1)?;
        ensure!(
            snapshot.session == session
                && snapshot.last_updated_height == session.start_height
                && snapshot.recipient_keys.len() == 1
                && snapshot.dealer_commitments.len() == 1
                && snapshot.recipient_keys[0].recipient_index == seat_index
                && snapshot.dealer_commitments[0].dealer_index == seat_index
                && snapshot.encrypted_shares.is_empty()
                && snapshot.share_acceptances.is_empty(),
            "rotation publication is not one exact signed target seat"
        );
        let _ = GlobalThresholdBeaconDkgStateV1::from_snapshot(
            snapshot,
            crypto,
            state.allocation_budget(),
        )?;
        state.record_recipient_key(session.start_height, &snapshot.recipient_keys[0])?;
    }
    for snapshot in snapshots {
        state.record_dealer_commitment(
            session.start_height,
            &snapshot.dealer_commitments[0],
            crypto,
        )?;
    }
    Ok(state)
}

fn merge_deliveries(
    state: &mut GlobalThresholdBeaconDkgStateV1,
    snapshots: &[GlobalThresholdBeaconDkgSnapshotV1],
    crypto: &AdaptiveGlobalThresholdBeaconDkgCryptoV1,
) -> Result<()> {
    let previous = state.public_snapshot()?;
    let session = previous.session;
    for (index, snapshot) in snapshots.iter().enumerate() {
        ensure!(
            snapshot.session == session
                && snapshot.last_updated_height == session.commitments_end_height
                && snapshot.recipient_keys == previous.recipient_keys
                && snapshot.dealer_commitments == previous.dealer_commitments
                && snapshot.share_acceptances.is_empty()
                && snapshot.encrypted_shares.len() == usize::from(session.committee_size)
                && snapshot
                    .encrypted_shares
                    .iter()
                    .all(|edge| edge.dealer_index == u16::try_from(index + 1).unwrap_or(0)),
            "rotation delivery is not one exact dealer's full private-edge set"
        );
        let _ = GlobalThresholdBeaconDkgStateV1::from_snapshot(
            snapshot,
            crypto,
            state.allocation_budget(),
        )?;
        for edge in &snapshot.encrypted_shares {
            state.record_encrypted_share(session.commitments_end_height, edge)?;
        }
    }
    Ok(())
}

fn merge_acceptances(
    state: &mut GlobalThresholdBeaconDkgStateV1,
    snapshots: &[GlobalThresholdBeaconDkgSnapshotV1],
    crypto: &AdaptiveGlobalThresholdBeaconDkgCryptoV1,
) -> Result<()> {
    let previous = state.public_snapshot()?;
    let session = previous.session;
    for (index, snapshot) in snapshots.iter().enumerate() {
        ensure!(
            snapshot.session == session
                && snapshot.last_updated_height == session.deliveries_end_height
                && snapshot.recipient_keys == previous.recipient_keys
                && snapshot.dealer_commitments == previous.dealer_commitments
                && snapshot.encrypted_shares == previous.encrypted_shares
                && snapshot.share_acceptances.len() == usize::from(session.committee_size)
                && snapshot
                    .share_acceptances
                    .iter()
                    .all(|acceptance| acceptance.recipient_index
                        == u16::try_from(index + 1).unwrap_or(0)),
            "rotation acceptance is not one exact recipient's full edge set"
        );
        let _ = GlobalThresholdBeaconDkgStateV1::from_snapshot(
            snapshot,
            crypto,
            state.allocation_budget(),
        )?;
        for acceptance in &snapshot.share_acceptances {
            state.record_share_acceptance(session.deliveries_end_height, acceptance)?;
        }
    }
    Ok(())
}

fn write_owner_private_key(path: &Path, signer: &KeyPair) -> Result<fs::File> {
    ensure!(
        signer.public_key().algorithm() == Algorithm::BlsNormal,
        "rotation seat does not own a real BLS identity"
    );
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{}", ExposedPrivateKey(signer.private_key().clone()))?;
    file.sync_all()?;
    ensure!(
        file.metadata()?.len() == 71,
        "native BLS private record is not canonical"
    );
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[allow(
    unsafe_code,
    reason = "the disposable supervisor transfers already opened owner-private inputs to fixed native child descriptors"
)]
fn inherit_native_descriptors<const N: usize>(
    command: &mut tokio::process::Command,
    descriptors: [(i32, i32); N],
) {
    // Every native destination in this module is below this duplication floor.
    assert!(descriptors.iter().all(|(_, target)| *target <= FINALITY_FD));
    unsafe {
        command.as_std_mut().pre_exec(move || {
            // Pin all inputs before replacing a destination. Even identity mappings
            // use a distinct source so dup2 clears close-on-exec on the fixed target.
            // These descriptor operations are async-signal-safe and allocate nothing.
            let mut pinned = [-1; N];
            for (index, (source, _)) in descriptors.into_iter().enumerate() {
                let descriptor =
                    nix::libc::fcntl(source, nix::libc::F_DUPFD_CLOEXEC, FINALITY_FD + 1);
                if descriptor < 0 {
                    let error = std::io::Error::last_os_error();
                    for descriptor in pinned {
                        if descriptor >= 0 {
                            nix::libc::close(descriptor);
                        }
                    }
                    return Err(error);
                }
                pinned[index] = descriptor;
            }
            for (source, (_, target)) in pinned.into_iter().zip(descriptors) {
                if nix::libc::dup2(source, target) < 0 {
                    let error = std::io::Error::last_os_error();
                    for descriptor in pinned {
                        nix::libc::close(descriptor);
                    }
                    return Err(error);
                }
            }
            for descriptor in pinned {
                nix::libc::close(descriptor);
            }
            Ok(())
        });
    }
}

fn inherit_rotation_descriptors(
    command: &mut tokio::process::Command,
    key: i32,
    public: i32,
    finality: i32,
) {
    inherit_native_descriptors(
        command,
        [(key, KEY_FD), (public, PUBLIC_FD), (finality, FINALITY_FD)],
    );
}

// Open the child input as read-only without waiting for a writer. Retain the
// parent writer before spawning so the child cannot observe a transient EOF.
fn open_native_phase_fifo(path: &Path) -> Result<(fs::File, fs::File)> {
    let reader = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)?;
    let writer = fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)?;
    Ok((reader, writer))
}

fn spawn_seat(
    binary: &Path,
    seat: &NetworkPeer,
    signer_index: u16,
    session: &GlobalThresholdBeaconDkgSessionV1,
    evidence_path: &Path,
    input: &DisposableRotationProofInput,
    provider_revision: u64,
) -> Result<SeatProcess> {
    let owner_root =
        super::disposable_runtime_provider_broker::new_disposable_owner_private_root()?;
    let key = write_owner_private_key(
        &owner_root.path().join("identity.private"),
        seat.bls_key_pair()
            .ok_or_else(|| eyre!("target seat has no BLS identity"))?,
    )?;
    let public_path = owner_root.path().join("public.fifo");
    let finality_path = owner_root.path().join("finality.fifo");
    nix::unistd::mkfifo(
        &public_path,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )?;
    nix::unistd::mkfifo(
        &finality_path,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )?;
    let (public_fifo, public_writer) = open_native_phase_fifo(&public_path)?;
    let (finality_fifo, finality_writer) = open_native_phase_fifo(&finality_path)?;
    let private_log = |name| -> Result<fs::File> {
        Ok(fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(owner_root.path().join(name))?)
    };
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("beacon-bootstrap")
        .args(credential_memory_args(iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES))
        .arg("provision-rotation-seat")
        .arg("--selection-evidence")
        .arg(evidence_path)
        .arg("--network-id")
        .arg(input.network_id.to_string())
        .arg("--chain-id")
        .arg(input.chain_id.to_string())
        .args(finality_limit_args(input.finality_limits))
        .arg("--target-epoch")
        .arg(input.target_epoch.to_string())
        .arg("--transition-id")
        .arg(input.transition_id.to_string())
        .arg("--signer-index")
        .arg(signer_index.to_string())
        .arg("--key-fd")
        .arg(KEY_FD.to_string())
        .arg("--public-fd")
        .arg(PUBLIC_FD.to_string())
        .arg("--finality-fd")
        .arg(FINALITY_FD.to_string())
        .arg("--provider-handle")
        .arg(provider_handle(&seat.id()))
        .arg("--provider-revision")
        .arg(provider_revision.to_string())
        .arg("--attempt-root")
        .arg(owner_root.path())
        .arg("--timeout-ms")
        .arg(PROCESS_TIMEOUT.as_millis().to_string())
        .env_clear()
        .current_dir(owner_root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::from(private_log("stdout.log")?))
        .stderr(Stdio::from(private_log("stderr.log")?))
        .kill_on_drop(true);
    inherit_rotation_descriptors(
        &mut command,
        key.as_raw_fd(),
        public_fifo.as_raw_fd(),
        finality_fifo.as_raw_fd(),
    );
    let child = command.spawn()?;
    drop(key);
    drop(public_fifo);
    drop(finality_fifo);
    Ok(SeatProcess {
        validator: seat.id(),
        signer_index,
        child,
        public_writer,
        finality_writer,
        attempt_path: owner_root
            .path()
            .join(attempt_child_name(session, signer_index)),
        owner_root,
    })
}

fn verify_genesis_input(
    network: &Network,
    limits: NativeFinalityLimits,
) -> Result<(
    NativeGenesisProvisioningBundle,
    GlobalThresholdBeaconDkgSessionV1,
    Vec<PeerId>,
    NativeJournalCursor,
)> {
    ensure!(
        network.validators().len() == 4,
        "genesis DKG requires four exact voting seats"
    );
    let bundle = network.native_genesis_provisioning_bundle()?;
    let network_id = network.network_id();
    ensure!(
        network_id.into_genesis_hash() == bundle.block_hash,
        "genesis DKG source is not the exact retained signed genesis"
    );
    let (body, epoch) = authenticate_signed_genesis(&bundle.signed_wire, network_id, limits)
        .map_err(|error| eyre!(error))?;
    ensure!(body.hash() == bundle.block_hash, "genesis body changed");
    let roster = epoch
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<Vec<_>>();
    let available = network
        .validators()
        .iter()
        .map(NetworkPeer::id)
        .collect::<BTreeSet<_>>();
    ensure!(
        roster.iter().cloned().collect::<BTreeSet<_>>() == available
            && available.len() == roster.len(),
        "disposable genesis DKG lacks an exact real process for each signed voter"
    );
    let verifier = NativeJournalCursor::new(
        network.chain_id(),
        network_id,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits,
        &iroha_allocation::AllocationBudget::new(limits.allocated_bytes),
    )
    .map_err(|error| eyre!(error))?;
    let session = genesis_dkg_session(network_id, &roster);
    GlobalThresholdBeaconDkgStateV1::validate_session(
        &session,
        &AdaptiveGlobalThresholdBeaconDkgCryptoV1,
    )?;
    Ok((bundle, session, roster, verifier))
}

fn genesis_dkg_session(
    network_id: NetworkId,
    roster: &[PeerId],
) -> GlobalThresholdBeaconDkgSessionV1 {
    GlobalThresholdBeaconDkgSessionV1 {
        version: 1,
        network_id,
        session_id: CryptoHash::new_from_chunks(&[
            b"iroha.global-beacon.genesis-session.v1\0",
            network_id.as_bytes(),
        ])
        .into(),
        attempt_id: CryptoHash::new_from_chunks(&[
            b"iroha.global-beacon.genesis-attempt.v1\0",
            network_id.as_bytes(),
        ])
        .into(),
        authority_generation: 0,
        roster_hash: global_threshold_beacon_roster_hash_v1(&roster),
        committee_size: 4,
        threshold: 2,
        start_height: 1,
        commitments_end_height: 2,
        deliveries_end_height: 3,
        acceptances_end_height: 4,
    }
}

fn spawn_genesis_seat(
    binary: &Path,
    seat: &NetworkPeer,
    signer_index: u16,
    session: &GlobalThresholdBeaconDkgSessionV1,
    public_paths: &[PathBuf; 4],
    chain_discriminant: u16,
    chain_id: &ChainId,
    limits: NativeFinalityLimits,
) -> Result<SeatProcess> {
    let owner_root =
        super::disposable_runtime_provider_broker::new_disposable_owner_private_root()?;
    let retained_key = write_owner_private_key(
        &owner_root.path().join("identity.private"),
        seat.bls_key_pair()
            .ok_or_else(|| eyre!("genesis voter has no real BLS identity"))?,
    )?;
    let provision_key = copy_owner_private_genesis_signer_input(
        &owner_root.path().join("identity.private"),
        &owner_root.path().join("provision.fd198"),
    )?;
    drop(retained_key);
    let public_path = owner_root.path().join("public.fifo");
    let finality_path = owner_root.path().join("finality.fifo");
    nix::unistd::mkfifo(
        &public_path,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )?;
    nix::unistd::mkfifo(
        &finality_path,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )?;
    let (public_fifo, public_writer) = open_native_phase_fifo(&public_path)?;
    let (finality_fifo, finality_writer) = open_native_phase_fifo(&finality_path)?;
    let private_log = |name| -> Result<fs::File> {
        Ok(fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(owner_root.path().join(name))?)
    };
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("beacon-bootstrap")
        .args(credential_memory_args(iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES))
        .arg("provision-genesis-seat")
        .arg("--network-id")
        .arg(session.network_id.to_string())
        .arg("--chain-discriminant")
        .arg(chain_discriminant.to_string())
        .arg("--request")
        .arg(&public_paths[0])
        .arg("--genesis-manifest")
        .arg(&public_paths[1])
        .arg("--genesis-signed")
        .arg(&public_paths[2])
        .arg("--genesis-public-key")
        .arg(&public_paths[3])
        .arg("--chain-id")
        .arg(chain_id.to_string())
        .args(finality_limit_args(limits))
        .arg("--signer-index")
        .arg(signer_index.to_string())
        .arg("--key-fd")
        .arg(KEY_FD.to_string())
        .arg("--public-fd")
        .arg(PUBLIC_FD.to_string())
        .arg("--finality-fd")
        .arg(FINALITY_FD.to_string())
        .arg("--attempt-root")
        .arg(owner_root.path())
        .arg("--timeout-ms")
        .arg(PROCESS_TIMEOUT.as_millis().to_string())
        .env_clear()
        .current_dir(owner_root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::from(private_log("stdout.log")?))
        .stderr(Stdio::from(private_log("stderr.log")?))
        .kill_on_drop(true);
    inherit_rotation_descriptors(
        &mut command,
        provision_key.as_raw_fd(),
        public_fifo.as_raw_fd(),
        finality_fifo.as_raw_fd(),
    );
    let child = command.spawn().map_err(|error| {
        let _ = retire_one_shot_genesis_descriptor(&owner_root.path().join("provision.fd198"));
        error
    })?;
    drop(provision_key);
    drop(public_fifo);
    drop(finality_fifo);
    Ok(SeatProcess {
        validator: seat.id(),
        signer_index,
        child,
        public_writer,
        finality_writer,
        attempt_path: owner_root
            .path()
            .join(attempt_child_name(session, signer_index)),
        owner_root,
    })
}

fn copy_owner_private_genesis_signer_input(source: &Path, target: &Path) -> Result<fs::File> {
    let before = fs::symlink_metadata(source)?;
    ensure!(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.uid() == nix::unistd::Uid::effective().as_raw()
            && before.mode() & 0o7777 == 0o600
            && before.nlink() == 1
            && (1..=1024 * 1024).contains(&before.len()),
        "genesis signer input is not a direct owner-private file"
    );
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(source)?;
    let opened = input.metadata()?;
    ensure!(
        (opened.dev(), opened.ino(), opened.len()) == (before.dev(), before.ino(), before.len()),
        "genesis signer input changed before descriptor handoff"
    );
    let mut output = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)?;
    ensure!(
        std::io::copy(&mut input, &mut output)? == before.len(),
        "genesis signer input changed during descriptor handoff"
    );
    output.sync_all()?;
    let after = input.metadata()?;
    ensure!(
        (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec()
        ) == (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec()
        ),
        "genesis signer input changed after descriptor handoff"
    );
    output.rewind()?;
    Ok(output)
}

fn retire_one_shot_genesis_descriptor(path: &Path) -> Result<bool> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.uid() == nix::unistd::Uid::effective().as_raw()
            && before.mode() & 0o7777 == 0o600
            && before.nlink() == 1
            && before.len() <= 1024 * 1024,
        "genesis one-shot descriptor lost private-file custody"
    );
    let consumed = before.len() == 0;
    if !consumed {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)?;
        let opened = file.metadata()?;
        ensure!(
            (opened.dev(), opened.ino(), opened.len())
                == (before.dev(), before.ino(), before.len()),
            "genesis one-shot descriptor changed before retirement"
        );
        file.write_all(&vec![0_u8; usize::try_from(before.len())?])?;
        file.sync_data()?;
        file.set_len(0)?;
        file.sync_data()?;
    }
    fs::remove_file(path)?;
    Ok(consumed)
}

/// Erase every string in the native configuration projection before it is dropped.
fn scrub_genesis_config_table(table: &mut toml::Table) {
    use zeroize::Zeroize as _;

    fn scrub(value: &mut toml::Value) {
        match value {
            toml::Value::String(value) => value.zeroize(),
            toml::Value::Array(values) => values.iter_mut().for_each(scrub),
            toml::Value::Table(table) => scrub_genesis_config_table(table),
            _ => {}
        }
    }
    table.iter_mut().for_each(|(_, value)| scrub(value));
}

/// Read the selected generated root at its original origin and bind its BLS key
/// to the independently authenticated genesis voter and chain context.
fn read_owner_private_genesis_config_key(
    seat: &DisposableGenesisConfigSeat,
    network: NetworkId,
    chain_discriminant: u16,
    chain_id: &ChainId,
) -> Result<KeyPair> {
    let path = &seat.config_path;
    ensure!(
        path.is_absolute()
            && path.components().all(|component| matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )),
        "genesis config seat path is not a canonical absolute path"
    );
    let uid = nix::unistd::Uid::effective().as_raw();
    let parent = path
        .parent()
        .ok_or_else(|| eyre!("genesis config seat has no parent"))?;
    for (index, ancestor) in parent.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.mode() & 0o022 == 0
                && (metadata.uid() == uid || (index != 0 && metadata.uid() == 0)),
            "genesis config seat has an untrusted directory ancestor"
        );
    }
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.uid() == nix::unistd::Uid::effective().as_raw()
            && before.mode() & 0o7777 == 0o600
            && before.nlink() == 1
            && (1..=1024 * 1024).contains(&before.len()),
        "genesis config seat is not a direct owner-private root file"
    );
    let identity = |m: &fs::Metadata| {
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
    };
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        identity(&before) == identity(&file.metadata()?),
        "genesis config seat changed before its pinned read"
    );
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "genesis config seat changed during its pinned read"
    );
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| eyre!("selected genesis config seat is not UTF-8"))?;
    let table = toml::from_str(text)
        .map_err(|_| eyre!("cannot decode selected genesis config seat TOML"))?;
    let mut source = TomlSource::new_sensitive(path.clone(), table, scrub_genesis_config_table);
    ensure!(
        !source.table_mut().contains_key("extends"),
        "genesis config seat must select a direct generated root without extends"
    );
    let _guard =
        iroha_data_model::account::address::ChainDiscriminantGuard::enter(chain_discriminant);
    let native: iroha_config::parameters::actual::Root = ConfigReader::new()
        .without_env()
        .with_toml_source(source)
        .read_and_complete::<iroha_config::parameters::user::Root>()
        .map_err(|_| eyre!("cannot read selected native genesis config seat"))?
        .parse()
        .map_err(|_| eyre!("cannot validate selected native genesis config seat"))?;
    ensure!(
        identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "genesis config seat changed during native validation"
    );
    ensure!(
        native.common.chain == *chain_id
            && *native.common.chain_discriminant.value() == chain_discriminant
            && native.genesis.expected_hash == network.into_genesis_hash()
            && native.common.peer.id() == &seat.validator
            && native.common.key_pair.public_key().algorithm() == Algorithm::BlsNormal
            && native.common.key_pair.public_key() == seat.validator.public_key()
            && matches!(native.kura.init_mode, iroha_config::kura::InitMode::Strict),
        "genesis config seat differs from its independent native anchors"
    );
    Ok(native.common.key_pair)
}

fn spawn_genesis_config_seat(
    binary: &Path,
    seat: &DisposableGenesisConfigSeat,
    signer_index: u16,
    session: &GlobalThresholdBeaconDkgSessionV1,
    public_paths: &[PathBuf; 4],
    chain_discriminant: u16,
    chain_id: &ChainId,
    limits: NativeFinalityLimits,
) -> Result<SeatProcess> {
    let owner_root =
        super::disposable_runtime_provider_broker::new_disposable_owner_private_root()?;
    let key = read_owner_private_genesis_config_key(
        seat,
        session.network_id,
        chain_discriminant,
        chain_id,
    )?;
    let retained_key = write_owner_private_key(&owner_root.path().join("identity.private"), &key)?;
    let provision_key = copy_owner_private_genesis_signer_input(
        &owner_root.path().join("identity.private"),
        &owner_root.path().join("provision.fd198"),
    )?;
    drop(retained_key);
    let public_path = owner_root.path().join("public.fifo");
    let finality_path = owner_root.path().join("finality.fifo");
    nix::unistd::mkfifo(
        &public_path,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )?;
    nix::unistd::mkfifo(
        &finality_path,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )?;
    let (public_fifo, public_writer) = open_native_phase_fifo(&public_path)?;
    let (finality_fifo, finality_writer) = open_native_phase_fifo(&finality_path)?;
    let private_log = |name| -> Result<fs::File> {
        Ok(fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(owner_root.path().join(name))?)
    };
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("beacon-bootstrap")
        .args(credential_memory_args(iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES))
        .arg("provision-genesis-seat")
        .arg("--network-id")
        .arg(session.network_id.to_string())
        .arg("--chain-discriminant")
        .arg(chain_discriminant.to_string())
        .arg("--request")
        .arg(&public_paths[0])
        .arg("--genesis-manifest")
        .arg(&public_paths[1])
        .arg("--genesis-signed")
        .arg(&public_paths[2])
        .arg("--genesis-public-key")
        .arg(&public_paths[3])
        .arg("--chain-id")
        .arg(chain_id.to_string())
        .args(finality_limit_args(limits))
        .arg("--signer-index")
        .arg(signer_index.to_string())
        .arg("--key-fd")
        .arg(KEY_FD.to_string())
        .arg("--public-fd")
        .arg(PUBLIC_FD.to_string())
        .arg("--finality-fd")
        .arg(FINALITY_FD.to_string())
        .arg("--attempt-root")
        .arg(owner_root.path())
        .arg("--timeout-ms")
        .arg(PROCESS_TIMEOUT.as_millis().to_string())
        .env_clear()
        .current_dir(owner_root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::from(private_log("stdout.log")?))
        .stderr(Stdio::from(private_log("stderr.log")?))
        .kill_on_drop(true);
    inherit_rotation_descriptors(
        &mut command,
        provision_key.as_raw_fd(),
        public_fifo.as_raw_fd(),
        finality_fifo.as_raw_fd(),
    );
    let child = command.spawn().map_err(|error| {
        let _ = retire_one_shot_genesis_descriptor(&owner_root.path().join("provision.fd198"));
        error
    })?;
    drop(provision_key);
    drop(public_fifo);
    drop(finality_fifo);
    Ok(SeatProcess {
        validator: seat.validator.clone(),
        signer_index,
        child,
        public_writer,
        finality_writer,
        attempt_path: owner_root
            .path()
            .join(attempt_child_name(session, signer_index)),
        owner_root,
    })
}

fn genesis_public_args(
    paths: &[PathBuf; 4],
    network: NetworkId,
    discriminant: u16,
    chain_id: &ChainId,
    limits: NativeFinalityLimits,
) -> Vec<String> {
    let mut args = vec![
        "--network-id".into(),
        network.to_string(),
        "--chain-discriminant".into(),
        discriminant.to_string(),
        "--chain-id".into(),
        chain_id.to_string(),
        "--request".into(),
        paths[0].display().to_string(),
        "--genesis-manifest".into(),
        paths[1].display().to_string(),
        "--genesis-signed".into(),
        paths[2].display().to_string(),
        "--genesis-public-key".into(),
        paths[3].display().to_string(),
    ];
    args.extend(finality_limit_args(limits));
    args
}

/// Fixed phase labels selected by maintained callers, never by argv or paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativePublicCommandPhase {
    GenesisDkg,
    GenesisInstall,
    RotationDkg,
    RotationFinalize,
}
impl NativePublicCommandPhase {
    const fn label(self) -> &'static str {
        match self {
            Self::GenesisDkg => "genesis_dkg",
            Self::GenesisInstall => "genesis_install",
            Self::RotationDkg => "rotation_dkg",
            Self::RotationFinalize => "rotation_finalize",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativePublicCommandOutcome {
    Success,
    InvalidInput,
    InvalidCustody,
    Crypto,
    Height,
    Deadline,
    Io,
    Session,
    LocalDkg,
    Journal,
    GenesisBundle,
    Export,
    Attempt,
    PendingAttempt,
    UnknownExit,
    Signaled,
    UnknownStatus,
    ProcessIoFailure,
    Timeout,
}
impl NativePublicCommandOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::InvalidInput => "invalid_input",
            Self::InvalidCustody => "invalid_custody",
            Self::Crypto => "crypto",
            Self::Height => "height",
            Self::Deadline => "deadline",
            Self::Io => "io",
            Self::Session => "session",
            Self::LocalDkg => "local_dkg",
            Self::Journal => "journal",
            Self::GenesisBundle => "genesis_bundle",
            Self::Export => "export",
            Self::Attempt => "attempt",
            Self::PendingAttempt => "pending_attempt",
            Self::UnknownExit => "unknown_exit",
            Self::Signaled => "signaled",
            Self::UnknownStatus => "unknown_status",
            Self::ProcessIoFailure => "process_io_failure",
            Self::Timeout => "timeout",
        }
    }
}

fn native_public_command_completed_outcome(
    code: Option<i32>,
    signal: Option<i32>,
) -> NativePublicCommandOutcome {
    match (code, signal) {
        (Some(0), None) => NativePublicCommandOutcome::Success,
        (Some(70), None) => NativePublicCommandOutcome::InvalidInput,
        (Some(71), None) => NativePublicCommandOutcome::InvalidCustody,
        (Some(72), None) => NativePublicCommandOutcome::Crypto,
        (Some(73), None) => NativePublicCommandOutcome::Height,
        (Some(74), None) => NativePublicCommandOutcome::Deadline,
        (Some(75), None) => NativePublicCommandOutcome::Io,
        (Some(76), None) => NativePublicCommandOutcome::Session,
        (Some(77), None) => NativePublicCommandOutcome::LocalDkg,
        (Some(78), None) => NativePublicCommandOutcome::Journal,
        (Some(79), None) => NativePublicCommandOutcome::GenesisBundle,
        (Some(80), None) => NativePublicCommandOutcome::Export,
        (Some(81), None) => NativePublicCommandOutcome::Attempt,
        (Some(82), None) => NativePublicCommandOutcome::PendingAttempt,
        (Some(code), None) if (0..=255).contains(&code) => NativePublicCommandOutcome::UnknownExit,
        (None, Some(signal)) if signal > 0 => NativePublicCommandOutcome::Signaled,
        _ => NativePublicCommandOutcome::UnknownStatus,
    }
}

// This projection contains only fixed literals and numeric operating-system status.
// Worker classes require an authenticated Source pair; foreign exit codes prove no cause.
// It describes one command outcome; it never establishes ceremony or H5 success.
fn native_public_command_status_line(
    phase: NativePublicCommandPhase,
    outcome: NativePublicCommandOutcome,
    exit_code: Option<i32>,
    signal: Option<i32>,
) -> String {
    let exit_code = exit_code.map_or_else(|| "none".to_owned(), |code| code.to_string());
    let signal = signal.map_or_else(|| "none".to_owned(), |value| value.to_string());
    format!(
        "iroha-native-public-command-v1 phase={} outcome={} exit_code={} signal={}",
        phase.label(),
        outcome.label(),
        exit_code,
        signal,
    )
}

async fn run_genesis_public_command(
    binary: &Path,
    arguments: &[String],
    phase: NativePublicCommandPhase,
) -> Result<()> {
    let waited = timeout(
        PROCESS_TIMEOUT,
        tokio::process::Command::new(binary)
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await;
    let (outcome, exit_code, signal) = match &waited {
        Ok(Ok(status)) => {
            use std::os::unix::process::ExitStatusExt as _;
            (
                native_public_command_completed_outcome(status.code(), status.signal()),
                status.code(),
                status.signal(),
            )
        }
        Ok(Err(_)) => (NativePublicCommandOutcome::ProcessIoFailure, None, None),
        Err(_) => (NativePublicCommandOutcome::Timeout, None, None),
    };
    eprintln!(
        "{}",
        native_public_command_status_line(phase, outcome, exit_code, signal)
    );
    let status = waited??;
    ensure!(
        status.success(),
        "native genesis public command failed: {status}"
    );
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "the disposable supervisor passes one already opened owner-private BLS descriptor to the native signer"
)]
async fn sign_genesis_draft(
    chain_id: &ChainId,
    limits: NativeFinalityLimits,
    binary: &Path,
    network: NetworkId,
    discriminant: u16,
    public_bundle: &Path,
    seat: &DisposableRotationSeatOutput,
    output: &Path,
) -> Result<()> {
    let one_shot_path = seat._owner_root.path().join("sign.fd198");
    let key = copy_owner_private_genesis_signer_input(
        &seat._owner_root.path().join("identity.private"),
        &one_shot_path,
    )?;
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("beacon-bootstrap")
        .args(credential_memory_args(iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES))
        .arg("sign-genesis-install")
        .arg("--chain-id")
        .arg(chain_id.to_string())
        .args(finality_limit_args(limits))
        .arg("--network-id")
        .arg(network.to_string())
        .arg("--chain-discriminant")
        .arg(discriminant.to_string())
        .arg("--bundle")
        .arg(public_bundle)
        .arg("--signer-index")
        .arg((seat.signer_index - 1).to_string())
        .arg("--key-fd")
        .arg(KEY_FD.to_string())
        .arg("--output")
        .arg(output)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    inherit_native_descriptors(&mut command, [(key.as_raw_fd(), KEY_FD)]);
    let waited = timeout(PROCESS_TIMEOUT, command.status()).await;
    let consumed = retire_one_shot_genesis_descriptor(&one_shot_path)?;
    let status = waited??;
    ensure!(
        status.success() && consumed,
        "native genesis seat signature failed: {status}"
    );
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "the disposable supervisor passes one already opened owner-private BLS descriptor to the native signer"
)]
async fn sign_rotation_draft(
    binary: &Path,
    seat: &NetworkPeer,
    public_bundle: &Path,
    proof_args: &[String],
    signer_index: usize,
    output: &Path,
) -> Result<()> {
    let root = super::disposable_runtime_provider_broker::new_disposable_owner_private_root()?;
    let key = write_owner_private_key(
        &root.path().join("identity.private"),
        seat.bls_key_pair()
            .ok_or_else(|| eyre!("incumbent signer has no real BLS identity"))?,
    )?;
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("beacon-bootstrap")
        .args(credential_memory_args(iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES))
        .arg("sign-rotation")
        .args(proof_args)
        .arg("--bundle")
        .arg(public_bundle)
        .arg("--signer-index")
        .arg(signer_index.to_string())
        .arg("--key-fd")
        .arg(KEY_FD.to_string())
        .arg("--output")
        .arg(output)
        .env_clear()
        .current_dir(root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    inherit_native_descriptors(&mut command, [(key.as_raw_fd(), KEY_FD)]);
    let status = timeout(PROCESS_TIMEOUT, command.status()).await??;
    ensure!(
        status.success(),
        "native incumbent signature failed: {status}"
    );
    Ok(())
}

/// Open the existing private record with the access required by the native loader.
fn open_pending_custody_descriptor(path: &Path) -> std::io::Result<fs::File> {
    // The native loader reopens inherited descriptors read-write, and consumes a
    // pending share after import. On macOS /dev/fd cannot widen read-only access.
    // Opening an existing record must neither create it nor truncate its contents.
    fs::OpenOptions::new().read(true).write(true).open(path)
}

/// Verify exact incumbent authorization, then import one seat's pending share
/// with the stock native current-plus-pending custody command.
///
/// The private share and optional incumbent credential travel only as inherited
/// owner-private descriptors. The native command validates and atomically
/// publishes the resulting generation; this helper has no alternate decoder.
///
/// # Errors
///
/// Rejects stale or foreign evidence, a different target seat, bad descriptor
/// custody, or any native generation-publishing failure.
#[allow(
    unsafe_code,
    reason = "the disposable supervisor transfers already opened owner-private custody files to fixed native child FDs"
)]
pub async fn prepare_disposable_pending_custody(
    evidence: &ValidatorCommitteeProvisioningEvidenceV1,
    pending_share_path: &Path,
    retained: Option<DisposableRetainedBeaconCredential<'_>>,
    input: DisposablePendingCustodyInput,
) -> Result<DisposablePreparedBeaconCustody> {
    ensure!(
        input.revision != 0,
        "pending custody revision must be positive"
    );
    iroha_config::parameters::validate_production_runtime_handle(&input.handle)
        .map_err(|error| eyre!("invalid production beacon provider handle: {error:?}"))?;
    let chain_id = input
        .chain_id
        .parse::<ChainId>()
        .map_err(|error| eyre!("invalid chain identifier: {error}"))?;
    let credential_budget =
        iroha_allocation::AllocationBudget::new(input.credential_max_memory_bytes.get());
    let verified = verify_validator_committee_provisioning_evidence_v1(
        evidence,
        &chain_id,
        input.network_id,
        input.target_epoch,
        input.transition_id.into(),
        input.finality_limits,
        &credential_budget,
    )
    .wrap_err("pending custody evidence is invalid")?;
    ensure!(
        verified
            .transition()
            .preparation
            .committee
            .iter()
            .any(|seat| seat.validator == input.local_validator),
        "pending custody owner is not one exact target seat"
    );
    let binary = Program::IrohadTaira.resolve_async().await?;
    let root = super::disposable_runtime_provider_broker::new_disposable_owner_private_root()?;
    let evidence_path = root.path().join("custody-evidence.norito");
    fs::write(&evidence_path, norito::encode_canonical(evidence)?)?;
    let share = open_pending_custody_descriptor(pending_share_path)?;
    let current = retained
        .as_ref()
        .map(|retained| open_pending_custody_descriptor(retained.credential_path))
        .transpose()?;
    let catalog_path = retained
        .as_ref()
        .map(|retained| {
            let path = root.path().join("current-catalog.norito");
            fs::write(&path, retained.catalog)?;
            Ok::<_, Report>(path)
        })
        .transpose()?;
    let output = root.path().join("prepared-generation");
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("beacon-prepare-custody")
        .args(credential_memory_args(input.credential_max_memory_bytes))
        .arg("--evidence")
        .arg(&evidence_path)
        .arg("--network-id")
        .arg(input.network_id.to_string())
        .args(finality_limit_args(input.finality_limits))
        .arg("--target-epoch")
        .arg(input.target_epoch.to_string())
        .arg("--transition-id")
        .arg(input.transition_id.to_string())
        .arg("--local-validator")
        .arg(input.local_validator.to_string())
        .arg("--chain-id")
        .arg(&input.chain_id)
        .arg("--handle")
        .arg(&input.handle)
        .arg("--revision")
        .arg(input.revision.to_string())
        .arg("--output")
        .arg(&output)
        .env_clear()
        .current_dir(root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // The pinned provisioning command emits static rejection categories only;
        // inherited private descriptors never enter its diagnostics or arguments.
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    if let Some(path) = &catalog_path {
        command.arg("--current-catalog").arg(path);
    }
    let retained_fd = current.as_ref().map(std::os::fd::AsRawFd::as_raw_fd);
    if let Some(source) = retained_fd {
        inherit_native_descriptors(&mut command, [(share.as_raw_fd(), KEY_FD), (source, 200)]);
    } else {
        inherit_native_descriptors(&mut command, [(share.as_raw_fd(), KEY_FD)]);
    }
    let status = timeout(PROCESS_TIMEOUT, command.status()).await??;
    ensure!(
        status.success(),
        "native pending custody preparation failed: {status}"
    );
    Ok(DisposablePreparedBeaconCustody {
        validator: input.local_validator,
        credential_path: output.join(GLOBAL_BEACON_CREDENTIAL_FILE),
        catalog_path: output.join("runtime-provider-catalog.norito"),
        receipt_path: output.join("pending-beacon-custody.json"),
        _owner_root: root,
    })
}

/// Run four real signed-genesis dealers/recipients and assemble their install certificate.
///
/// The retained signed genesis supplies body authority; the caller supplies a live native finality
/// source with explicit bounded admission. This function requests h2, h3, and h4 only after each preceding
/// public phase is ready, supplying its authenticated public-only snapshot to the caller.
/// Every seat owns its private DKG share and signing
/// descriptor; only signed public artifacts cross the coordinator.
///
/// # Errors
///
/// Rejects a mismatched signed genesis, non-contiguous finality, incomplete
/// private edge acceptance, failed native process, or invalid quorum assembly.
pub async fn run_disposable_genesis_dkg<F, Fut>(
    network: &Network,
    limits: NativeFinalityLimits,
    certificate_height: u64,
    next_finality: F,
) -> Result<DisposableGenesisDkgOutput>
where
    F: FnMut(u64, RetainedGlobalThresholdBeaconDkgSnapshotV1, Instant) -> Fut,
    Fut: Future<Output = Result<NativeFinalityJournal>>,
{
    let (bundle, session, roster, verifier) = verify_genesis_input(network, limits)?;
    let binary = Program::IrohadTaira.resolve_async().await?;
    let ordered_seats = roster
        .iter()
        .map(|peer| {
            network
                .validators()
                .iter()
                .find(|seat| seat.id() == *peer)
                .ok_or_else(|| eyre!("signed genesis voter has no disposable process"))
        })
        .collect::<Result<Vec<_>>>()?;
    run_genesis_dkg_with_seats(
        bundle,
        session,
        roster,
        verifier,
        certificate_height,
        next_finality,
        &binary,
        |binary, _validator, index, session, paths, discriminant, chain_id, limits| {
            spawn_genesis_seat(
                binary,
                ordered_seats[usize::from(index - 1)],
                index,
                session,
                paths,
                discriminant,
                chain_id,
                limits,
            )
        },
    )
    .await
}

/// Run the same real per-seat genesis DKG using independently generated native configs.
///
/// This accepts the exact signed manifest and four direct owner-private
/// validator configs from an external disposable localnet generator. The
/// signed voter order, h1 authority and every phase finality proof are
/// revalidated before any credential is returned. The phase callback receives
/// the same fixed ceremony deadline and the merged signed public snapshot; plaintext shares remain in their seat.
/// No signer key is read into
/// an argument or environment value.
///
/// # Errors
///
/// Rejects an altered signed genesis, reordered or foreign voter config,
/// unsafe private config file, incomplete public DKG, or missed phase cutoff.
pub async fn run_disposable_genesis_dkg_from_configs<F, Fut>(
    bundle: NativeGenesisProvisioningBundle,
    network_id: NetworkId,
    chain_id: &ChainId,
    seats: &[DisposableGenesisConfigSeat],
    native_binary: &Path,
    limits: NativeFinalityLimits,
    certificate_height: u64,
    next_finality: F,
) -> Result<DisposableGenesisDkgOutput>
where
    F: FnMut(u64, RetainedGlobalThresholdBeaconDkgSnapshotV1, Instant) -> Fut,
    Fut: Future<Output = Result<NativeFinalityJournal>>,
{
    ensure!(
        seats.len() == 4,
        "genesis DKG requires four exact voter configs"
    );
    ensure!(
        sha256(&bundle.manifest_json) == bundle.manifest_sha256
            && network_id.into_genesis_hash() == bundle.block_hash,
        "external genesis DKG anchor differs from retained signed genesis"
    );
    let manifest: RawGenesisTransaction = norito::json::from_slice(&bundle.manifest_json)?;
    let validated = iroha_genesis::validate_prepared_genesis_bundle(
        &bundle.signed_wire,
        &manifest,
        &bundle.public_key,
        bundle.block_hash,
    )?;
    ensure!(
        manifest.chain_id() == chain_id,
        "external genesis chain differs from independent configuration"
    );
    let (body, epoch) = authenticate_signed_genesis(&bundle.signed_wire, network_id, limits)
        .map_err(|error| eyre!(error))?;
    ensure!(
        body.hash() == validated.block().hash(),
        "external signed body differs"
    );
    let roster = epoch
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<Vec<_>>();
    ensure!(
        roster.len() == 4 && seats.iter().map(|seat| &seat.validator).eq(roster.iter()),
        "native config seats differ from exact signed-genesis voter order"
    );
    let verifier = NativeJournalCursor::new(
        chain_id.clone(),
        network_id,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits,
        &iroha_allocation::AllocationBudget::new(limits.allocated_bytes),
    )
    .map_err(|error| eyre!(error))?;
    let session = genesis_dkg_session(network_id, &roster);
    let _ = GlobalThresholdBeaconDkgStateV1::validate_session(
        &session,
        &AdaptiveGlobalThresholdBeaconDkgCryptoV1,
    )?;
    run_genesis_dkg_with_seats(
        bundle,
        session,
        roster,
        verifier,
        certificate_height,
        next_finality,
        native_binary,
        |binary, _validator, index, session, paths, discriminant, chain_id, limits| {
            spawn_genesis_config_seat(
                binary,
                &seats[usize::from(index - 1)],
                index,
                session,
                paths,
                discriminant,
                chain_id,
                limits,
            )
        },
    )
    .await
}

// Preserve the original ceremony deadline across callback construction and execution.
// The postcheck also rejects a synchronous Ready poll that consumed the deadline.
// Dropping this wait does not stop a dedicated read thread: its same absolute
// deadline still governs HTTP reads and it must naturally retire its original work.
async fn await_ceremony_finality<T, F, Fut>(height: u64, deadline: Instant, next: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    ensure!(
        Instant::now() < deadline,
        "rotation H{height} finality callback deadline elapsed"
    );
    let outcome = tokio::time::timeout_at(deadline.into(), next())
        .await
        .map_err(|_| eyre!("rotation H{height} finality callback deadline elapsed"))?;
    ensure!(
        Instant::now() < deadline,
        "rotation H{height} finality callback deadline elapsed"
    );
    outcome
}

async fn run_genesis_dkg_with_seats<F, Fut, S>(
    bundle: NativeGenesisProvisioningBundle,
    session: GlobalThresholdBeaconDkgSessionV1,
    roster: Vec<PeerId>,
    mut verifier: NativeJournalCursor,
    certificate_height: u64,
    mut next_finality: F,
    binary: &Path,
    mut spawn_seat: S,
) -> Result<DisposableGenesisDkgOutput>
where
    F: FnMut(u64, RetainedGlobalThresholdBeaconDkgSnapshotV1, Instant) -> Fut,
    Fut: Future<Output = Result<NativeFinalityJournal>>,
    S: FnMut(
        &Path,
        &PeerId,
        u16,
        &GlobalThresholdBeaconDkgSessionV1,
        &[PathBuf; 4],
        u16,
        &ChainId,
        NativeFinalityLimits,
    ) -> Result<SeatProcess>,
{
    ensure!(
        certificate_height > 4,
        "genesis install cannot precede DKG finality"
    );
    let mut proofs = Vec::with_capacity(3);
    let chain_id = verifier.chain_id().clone();
    let limits = verifier.limits();
    let controller =
        super::disposable_runtime_provider_broker::new_disposable_owner_private_root()?;
    let controller_path = controller.path();
    let paths = [
        controller_path.join("request.json"),
        controller_path.join("genesis-manifest.json"),
        controller_path.join("genesis.signed.nrt"),
        controller_path.join("genesis.public-key"),
    ];
    let request = GenesisRequest {
        schema: "iroha.global-beacon.bootstrap.request.v1".to_owned(),
        dkg_session: session,
        target_roster: roster.clone(),
        authorization_roster: roster.clone(),
        provider_handles: roster.iter().map(provider_handle).collect(),
        provider_revision: 1,
    };
    fs::write(&paths[0], norito::json::to_vec(&request)?)?;
    fs::write(&paths[1], &bundle.manifest_json)?;
    ensure!(
        sha256(fs::read(&paths[1])?) == bundle.manifest_sha256,
        "staged raw manifest differs from the signed-genesis builder's exact bytes"
    );
    fs::write(&paths[2], &bundle.signed_wire)?;
    fs::write(&paths[3], format!("{}\n", bundle.public_key))?;
    let mut processes = roster
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            spawn_seat(
                binary,
                validator,
                u16::try_from(index + 1)?,
                &session,
                &paths,
                bundle.chain_discriminant,
                &chain_id,
                limits,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;

    let publications = wait_for_snapshots(&mut processes, "publication.norito", deadline).await?;
    let mut public = merge_publications(
        session,
        &publications,
        &crypto,
        verifier.allocation_budget(),
    )?;
    let commitments = public.public_snapshot()?;
    broadcast_public(&mut processes, commitments.record(), deadline)?;
    let proof =
        await_ceremony_finality(2, deadline, || next_finality(2, commitments, deadline)).await?;
    advance_native_phase(&mut verifier, &proof, 2)?;
    broadcast_finality(&mut processes, &proof, verifier.limits(), deadline)?;
    proofs.push(proof);

    let deliveries = wait_for_snapshots(&mut processes, "deliveries.norito", deadline).await?;
    merge_deliveries(&mut public, &deliveries, &crypto)?;
    let delivered = public.public_snapshot()?;
    broadcast_public(&mut processes, delivered.record(), deadline)?;
    let proof =
        await_ceremony_finality(3, deadline, || next_finality(3, delivered, deadline)).await?;
    advance_native_phase(&mut verifier, &proof, 3)?;
    broadcast_finality(&mut processes, &proof, verifier.limits(), deadline)?;
    proofs.push(proof);

    let acceptances = wait_for_snapshots(&mut processes, "acceptances.norito", deadline).await?;
    merge_acceptances(&mut public, &acceptances, &crypto)?;
    // The callback keeps the original funded acceptance graph across finalization.
    let accepted = public.public_snapshot()?;
    public.finalize(session.acceptances_end_height, &crypto)?;
    let assembled = public.into_finalized()?;
    broadcast_public(&mut processes, assembled.record(), deadline)?;
    let proof =
        await_ceremony_finality(4, deadline, || next_finality(4, accepted, deadline)).await?;
    advance_native_phase(&mut verifier, &proof, 4)?;
    broadcast_finality(&mut processes, &proof, verifier.limits(), deadline)?;
    proofs.push(proof);

    let mut outputs = Vec::with_capacity(processes.len());
    for mut process in processes {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let waited = timeout(remaining, process.child.wait()).await;
        if !matches!(&waited, Ok(Ok(_))) {
            let _ = process.child.kill().await;
            let _ = process.child.wait().await;
        }
        let consumed =
            retire_one_shot_genesis_descriptor(&process.owner_root.path().join("provision.fd198"))?;
        let status = waited??;
        ensure!(
            status.success() && consumed,
            "genesis seat {} failed: {status}; private diagnostics: {}",
            process.signer_index,
            process.owner_root.path().display()
        );
        let bytes = fs::read(process.attempt_path.join("public-session.norito"))?;
        let observed: GlobalThresholdBeaconKeySessionV1 = norito::decode_canonical_with_limits(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )?;
        ensure!(
            &observed == assembled.record(),
            "genesis seat finalized another public transcript"
        );
        outputs.push(DisposableRotationSeatOutput {
            validator: process.validator.clone(),
            signer_index: process.signer_index,
            provider_handle: provider_handle(&process.validator),
            provider_revision: 1,
            credential_path: process.attempt_path.join(GLOBAL_BEACON_CREDENTIAL_FILE),
            pending_share_path: process.attempt_path.join("pending-share.bin"),
            provider_path: process.attempt_path.join("provider.json"),
            _owner_root: process.owner_root,
        });
    }
    let public_session_path = controller_path.join("public-session.norito");
    fs::write(
        &public_session_path,
        norito::encode_canonical(assembled.record())?,
    )?;
    let phase_paths = (0..3)
        .map(|index| {
            let path = controller_path.join(format!("phase-{}.norito", index + 2));
            fs::write(
                &path,
                encode_phase_journal(&proofs[index], verifier.limits())?,
            )?;
            Ok(path)
        })
        .collect::<Result<Vec<_>>>()?;
    let public_bundle_path = controller_path.join("genesis-public-bundle.json");
    let mut assemble_args = vec![
        "beacon-bootstrap".to_owned(),
        "--credential-max-memory-bytes".to_owned(),
        iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES
            .get()
            .to_string(),
        "assemble-genesis-dkg".to_owned(),
    ];
    assemble_args.extend(genesis_public_args(
        &paths,
        session.network_id,
        bundle.chain_discriminant,
        &chain_id,
        limits,
    ));
    for phase in &phase_paths {
        assemble_args.push("--phase-proof".to_owned());
        assemble_args.push(phase.display().to_string());
    }
    assemble_args.extend([
        "--public-session".to_owned(),
        public_session_path.display().to_string(),
    ]);
    for seat in &outputs {
        assemble_args.push("--provider".to_owned());
        assemble_args.push(seat.provider_path.display().to_string());
    }
    assemble_args.extend([
        "--certificate-height".to_owned(),
        certificate_height.to_string(),
        "--output".to_owned(),
        public_bundle_path.display().to_string(),
    ]);
    run_genesis_public_command(
        &binary,
        &assemble_args,
        NativePublicCommandPhase::GenesisDkg,
    )
    .await?;

    let mut signatures = Vec::with_capacity(3);
    for seat in outputs.iter().take(3) {
        let signature =
            controller_path.join(format!("install-signature-{}.json", seat.signer_index));
        sign_genesis_draft(
            &chain_id,
            limits,
            &binary,
            session.network_id,
            bundle.chain_discriminant,
            &public_bundle_path,
            seat,
            &signature,
        )
        .await?;
        signatures.push(signature);
    }
    let install_instruction_path = controller_path.join("install-instruction.json");
    let mut install_args = vec![
        "beacon-bootstrap".to_owned(),
        "--credential-max-memory-bytes".to_owned(),
        iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES
            .get()
            .to_string(),
        "assemble-genesis-install".to_owned(),
        "--chain-id".to_owned(),
        chain_id.to_string(),
        "--network-id".to_owned(),
        session.network_id.to_string(),
        "--chain-discriminant".to_owned(),
        bundle.chain_discriminant.to_string(),
        "--bundle".to_owned(),
        public_bundle_path.display().to_string(),
    ];
    install_args.extend(finality_limit_args(limits));
    for signature in &signatures {
        install_args.push("--signature".to_owned());
        install_args.push(signature.display().to_string());
    }
    install_args.extend([
        "--output".to_owned(),
        install_instruction_path.display().to_string(),
    ]);
    run_genesis_public_command(
        &binary,
        &install_args,
        NativePublicCommandPhase::GenesisInstall,
    )
    .await?;
    Ok(DisposableGenesisDkgOutput {
        public_session: assembled,
        seats: outputs,
        public_bundle_path,
        install_instruction_path,
        _controller_root: controller,
    })
}

/// Exchange one exact frozen committee's real dealer and recipient messages.
///
/// Each child receives only its own BLS key through FD198. The coordinator
/// combines signed public frames and independently verified finality proofs;
/// it never reads, derives, or collects any seat's private DKG share. The
/// returned credential and pending-share paths remain separate per seat so
/// production custody preparation can retain current and pending keys. The owned
/// selection journal moves through each callback and complete phase archive;
/// callback errors terminate this ceremony rather than retrying acquired frames.
///
/// # Errors
///
/// Rejects a non-exact roster, forged or discontinuous finality, incomplete
/// public edges, failed native child, or any missed preparation deadline.
pub async fn run_disposable_rotation_dkg<F, Fut>(
    seats: &[&NetworkPeer],
    authorizing_seats: &[&NetworkPeer],
    evidence: ValidatorCommitteeSelectionEvidenceV1,
    input: DisposableRotationProofInput,
    provider_revision: u64,
    certificate_height: u64,
    mut next_finality: F,
) -> Result<DisposableRotationDkgOutput>
where
    F: FnMut(u64, Instant, NativeFinalityJournal) -> Fut,
    Fut: Future<Output = Result<NativeFinalityJournal>>,
{
    ensure!(provider_revision != 0, "provider revision must be positive");
    let (session, mut verifier) = verify_input(seats, authorizing_seats, &evidence, &input)?;
    ensure!(
        certificate_height > session.acceptances_end_height
            && certificate_height
                < evidence
                    .status
                    .selected
                    .as_ref()
                    .ok_or_else(|| eyre!("missing selected attempt"))?
                    .transition
                    .preparation
                    .first_height
                    - 1,
        "rotation certificate misses its exact preparation window"
    );
    let binary = Program::IrohadTaira.resolve_async().await?;
    let controller =
        super::disposable_runtime_provider_broker::new_disposable_owner_private_root()?;
    let evidence_path = controller.path().join("selection-evidence.norito");
    fs::write(&evidence_path, norito::encode_canonical(&evidence)?)?;
    let mut processes = seats
        .iter()
        .enumerate()
        .map(|(index, seat)| {
            spawn_seat(
                &binary,
                seat,
                u16::try_from(index + 1)?,
                &session,
                &evidence_path,
                &input,
                provider_revision,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;
    // All evidence borrows ended after verification, canonical persistence and spawn.
    // Move the same original journal through each terminal callback; its earlier
    // canonical frame buffers are never cloned or reacquired.
    let journal = evidence.finality_journal;
    let mut phase_paths = Vec::with_capacity(3);

    let publications = wait_for_snapshots(&mut processes, "publication.norito", deadline).await?;
    let mut public = merge_publications(
        session,
        &publications,
        &crypto,
        verifier.allocation_budget(),
    )?;
    broadcast_public(&mut processes, public.public_snapshot()?.record(), deadline)?;
    let proof = await_ceremony_finality(session.commitments_end_height, deadline, || {
        next_finality(session.commitments_end_height, deadline, journal)
    })
    .await?;
    advance_native_phase(&mut verifier, &proof, session.commitments_end_height)?;
    broadcast_finality(&mut processes, &proof, verifier.limits(), deadline)?;
    phase_paths.push(write_rotation_phase_journal(
        controller.path(),
        &proof,
        verifier.limits(),
        deadline,
    )?);

    let deliveries = wait_for_snapshots(&mut processes, "deliveries.norito", deadline).await?;
    merge_deliveries(&mut public, &deliveries, &crypto)?;
    broadcast_public(&mut processes, public.public_snapshot()?.record(), deadline)?;
    let proof = await_ceremony_finality(session.deliveries_end_height, deadline, || {
        next_finality(session.deliveries_end_height, deadline, proof)
    })
    .await?;
    advance_native_phase(&mut verifier, &proof, session.deliveries_end_height)?;
    broadcast_finality(&mut processes, &proof, verifier.limits(), deadline)?;
    phase_paths.push(write_rotation_phase_journal(
        controller.path(),
        &proof,
        verifier.limits(),
        deadline,
    )?);

    let acceptances = wait_for_snapshots(&mut processes, "acceptances.norito", deadline).await?;
    merge_acceptances(&mut public, &acceptances, &crypto)?;
    public.finalize(session.acceptances_end_height, &crypto)?;
    let assembled = public.into_finalized()?;
    broadcast_public(&mut processes, assembled.record(), deadline)?;
    let proof = await_ceremony_finality(session.acceptances_end_height, deadline, || {
        next_finality(session.acceptances_end_height, deadline, proof)
    })
    .await?;
    advance_native_phase(&mut verifier, &proof, session.acceptances_end_height)?;
    broadcast_finality(&mut processes, &proof, verifier.limits(), deadline)?;
    phase_paths.push(write_rotation_phase_journal(
        controller.path(),
        &proof,
        verifier.limits(),
        deadline,
    )?);

    let mut outputs = Vec::with_capacity(processes.len());
    for mut process in processes {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let status = timeout(remaining, process.child.wait()).await??;
        ensure!(
            status.success(),
            "rotation seat {} failed: {status}; private diagnostics: {}",
            process.signer_index,
            process.owner_root.path().display()
        );
        let public_bytes = fs::read(process.attempt_path.join("public-session.norito"))?;
        let seat_session: GlobalThresholdBeaconKeySessionV1 = norito::decode_canonical_with_limits(
            &public_bytes,
            norito::canonical_decode_limits(public_bytes.len()),
        )?;
        ensure!(
            &seat_session == assembled.record(),
            "seat finalized another public transcript"
        );
        outputs.push(DisposableRotationSeatOutput {
            validator: process.validator.clone(),
            signer_index: process.signer_index,
            provider_handle: provider_handle(&process.validator),
            provider_revision,
            credential_path: process.attempt_path.join(GLOBAL_BEACON_CREDENTIAL_FILE),
            pending_share_path: process.attempt_path.join("pending-share.bin"),
            provider_path: process.attempt_path.join("provider.json"),
            _owner_root: process.owner_root,
        });
    }
    let public_session_path = controller.path().join("public-session.norito");
    fs::write(
        &public_session_path,
        norito::encode_canonical(assembled.record())?,
    )?;
    let public_bundle_path = controller.path().join("rotation-public-bundle.json");
    let mut proof_args = vec![
        "--selection-evidence".to_owned(),
        evidence_path.display().to_string(),
        "--network-id".to_owned(),
        input.network_id.to_string(),
        "--chain-id".to_owned(),
        input.chain_id.to_string(),
        "--target-epoch".to_owned(),
        input.target_epoch.to_string(),
        "--transition-id".to_owned(),
        input.transition_id.to_string(),
    ];
    proof_args.extend(finality_limit_args(input.finality_limits));
    let mut assemble_args = vec![
        "beacon-bootstrap".to_owned(),
        "--credential-max-memory-bytes".to_owned(),
        iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES
            .get()
            .to_string(),
        "assemble-rotation-dkg".to_owned(),
    ];
    assemble_args.extend(proof_args.iter().cloned());
    assemble_args.extend([
        "--public-session".to_owned(),
        public_session_path.display().to_string(),
    ]);
    for phase in &phase_paths {
        assemble_args.extend(["--phase-proof".to_owned(), phase.display().to_string()]);
    }
    for seat in &outputs {
        assemble_args.extend([
            "--provider".to_owned(),
            seat.provider_path.display().to_string(),
        ]);
    }
    assemble_args.extend([
        "--certificate-height".to_owned(),
        certificate_height.to_string(),
        "--output".to_owned(),
        public_bundle_path.display().to_string(),
    ]);
    run_genesis_public_command(
        &binary,
        &assemble_args,
        NativePublicCommandPhase::RotationDkg,
    )
    .await?;

    let faults = (authorizing_seats.len() - 1) / 3;
    let quorum = authorizing_seats.len() - faults;
    let mut signatures = Vec::with_capacity(quorum);
    for (index, seat) in authorizing_seats.iter().take(quorum).enumerate() {
        let signature = controller
            .path()
            .join(format!("rotation-signature-{index}.json"));
        sign_rotation_draft(
            &binary,
            seat,
            &public_bundle_path,
            &proof_args,
            index,
            &signature,
        )
        .await?;
        signatures.push(signature);
    }
    let finalization_instruction_path = controller.path().join("rotation-finalization.json");
    let mut finalize_args = vec![
        "beacon-bootstrap".to_owned(),
        "--credential-max-memory-bytes".to_owned(),
        iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES
            .get()
            .to_string(),
        "assemble-rotation".to_owned(),
    ];
    finalize_args.append(&mut proof_args);
    finalize_args.extend([
        "--bundle".to_owned(),
        public_bundle_path.display().to_string(),
    ]);
    for signature in &signatures {
        finalize_args.extend(["--signature".to_owned(), signature.display().to_string()]);
    }
    finalize_args.extend([
        "--output".to_owned(),
        finalization_instruction_path.display().to_string(),
    ]);
    run_genesis_public_command(
        &binary,
        &finalize_args,
        NativePublicCommandPhase::RotationFinalize,
    )
    .await?;
    Ok(DisposableRotationDkgOutput {
        public_session: assembled,
        seats: outputs,
        public_bundle_path,
        finalization_instruction_path,
        _controller_root: controller,
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn rotation_incumbent_seats_require_the_complete_exact_verified_peer_order() {
        let network = NetworkBuilder::new()
            .with_peers(4)
            .with_base_seed("verified-incumbent-peer-order")
            .build();
        let peers = network.validators().iter().collect::<Vec<_>>();
        let incumbent = peers.iter().map(|peer| peer.id()).collect::<Vec<_>>();
        assert_eq!(incumbent.len(), 4);
        verify_incumbent_seats(&peers, &incumbent).unwrap();
        let refused = |seats: &[&NetworkPeer]| {
            assert_eq!(
                verify_incumbent_seats(seats, &incumbent)
                    .expect_err("only the exact incumbent roster may authorize a rotation")
                    .to_string(),
                "rotation signers must match the complete exact incumbent roster in order"
            );
        };
        refused(&peers[..3]);
        refused(&[]);
        let mut changed = peers.clone();
        changed.swap(0, 1);
        refused(&changed);
        changed.swap(0, 1);
        verify_incumbent_seats(&changed, &incumbent).unwrap();
        changed[1] = changed[0];
        refused(&changed);
        let mut extra = peers.clone();
        extra.push(peers[0]);
        refused(&extra);
        verify_incumbent_seats(&peers, &incumbent).unwrap();
    }

    #[test]
    fn rotation_phase_archive_preserves_complete_canonical_journal_and_native_verification() {
        use iroha_core::{
            state::{StateReadOnly as _, World},
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        use iroha_data_model::sumeragi::finality::NativeFinalityArtifact;
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 50_000))
            .expect("executed native fixture");
        chain.commit_at(50_001, Vec::new());
        let chain_id = chain.state().view().chain_id().clone();
        let limits = NativeFinalityLimits {
            block_bytes: 32 * 1024 * 1024,
            journal_bytes: 64 * 1024 * 1024,
            block_count: 2,
            allocated_bytes: 512 * 1024 * 1024,
        };
        let journal = NativeFinalityJournal {
            blocks: (1..=2)
                .map(|height| {
                    NativeFinalityArtifact::from_block(chain.committed(height).block(), limits)
                        .unwrap()
                })
                .collect(),
        };
        let budget = iroha_allocation::AllocationBudget::new(limits.allocated_bytes);
        let mut cursor = NativeJournalCursor::new(
            chain_id.clone(),
            chain.network_id(),
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            limits,
            &budget,
        )
        .unwrap();
        advance_native_phase(&mut cursor, &journal, 2).unwrap();
        let expected = encode_phase_journal(&journal, limits).unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = write_rotation_phase_journal(
            root.path(),
            &journal,
            limits,
            Instant::now() + PROCESS_TIMEOUT,
        )
        .unwrap();
        assert_eq!(path, root.path().join("phase-2.norito"));
        let original = fs::read(&path).unwrap();
        assert_eq!(original, expected);
        assert_eq!(original, norito::encode_canonical(&journal).unwrap());
        let decoded = NativeFinalityJournal::decode(&original, limits).unwrap();
        assert_eq!(decoded, journal);
        let mut independent = NativeJournalCursor::new(
            chain_id,
            chain.network_id(),
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            limits,
            &budget,
        )
        .unwrap();
        advance_native_phase(&mut independent, &decoded, 2).unwrap();
        assert_eq!(independent.tip().unwrap().id(), cursor.tip().unwrap().id());
    }

    #[test]
    fn rotation_phase_archive_refuses_original_deadline_before_any_file() {
        let root = tempfile::tempdir().unwrap();
        let journal = NativeFinalityJournal { blocks: Vec::new() };
        let limits = NativeFinalityLimits {
            block_bytes: 1024,
            journal_bytes: 4096,
            block_count: 8,
            allocated_bytes: 8192,
        };
        let error = write_rotation_phase_journal(root.path(), &journal, limits, Instant::now())
            .expect_err("expired ceremony must not publish a phase archive");
        assert_eq!(error.to_string(), "rotation phase archive deadline elapsed");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn ceremony_finality_callback_preserves_original_deadline_before_late_refusal() {
        let deadline = Instant::now() + Duration::from_millis(10);
        let result = await_ceremony_finality(9, deadline, || async {
            tokio::time::sleep(Duration::from_millis(40)).await;
            Err::<NativeFinalityJournal, _>(eyre!("original late callback sentinel"))
        })
        .await;
        let error = result.expect_err("a late callback must not replenish the ceremony");
        assert!(
            error
                .to_string()
                .contains("rotation H9 finality callback deadline elapsed")
        );
    }

    #[tokio::test]
    async fn ceremony_finality_callback_never_starts_after_original_deadline() {
        let called = std::cell::Cell::new(false);
        let result = await_ceremony_finality(9, Instant::now(), || {
            called.set(true);
            std::future::ready(Err::<NativeFinalityJournal, _>(eyre!(
                "original unused sentinel"
            )))
        })
        .await;
        assert!(result.is_err());
        assert!(
            !called.get(),
            "an expired ceremony must not start a fresh callback attempt"
        );
    }

    #[tokio::test]
    async fn ceremony_finality_callback_retains_same_early_original_error() {
        let original = eyre!(std::io::Error::other("original callback refusal"));
        let identity = core::ptr::from_ref(original.downcast_ref::<std::io::Error>().unwrap());
        let error = await_ceremony_finality(9, Instant::now() + PROCESS_TIMEOUT, || {
            std::future::ready(Err::<NativeFinalityJournal, _>(original))
        })
        .await
        .expect_err("the original early refusal must survive");
        assert!(core::ptr::eq(
            error.downcast_ref::<std::io::Error>().unwrap(),
            identity
        ));
    }

    #[tokio::test]
    async fn ceremony_finality_callback_rejects_synchronous_late_completion() {
        let deadline = Instant::now() + Duration::from_millis(10);
        let error = await_ceremony_finality(9, deadline, || async {
            // A Ready poll can consume the deadline without yielding to the timer.
            std::thread::sleep(Duration::from_millis(40));
            Err::<NativeFinalityJournal, _>(eyre!("original synchronously late sentinel"))
        })
        .await
        .expect_err("a synchronous poll must not return an answer after its deadline");
        assert!(
            error
                .to_string()
                .contains("rotation H9 finality callback deadline elapsed")
        );
    }

    /// Exercise the production handoff in a child without modifying parent descriptors.
    #[allow(
        unsafe_code,
        reason = "the fixture owns the duplicated descriptors and only installs them in its child before exec"
    )]
    async fn observe_rotation_descriptor_handoff(
        source_targets: [i32; 3],
        close_on_exec: bool,
        destinations: usize,
    ) -> std::process::Output {
        use std::os::fd::{FromRawFd as _, OwnedFd};

        let root = tempfile::tempdir().unwrap();
        let mut owned = Vec::new();
        for (index, bytes) in [b"key-record".as_slice(), b"public-frame", b"finality-frame"]
            .into_iter()
            .enumerate()
        {
            let path = root.path().join(format!("input-{index}"));
            fs::write(&path, bytes).unwrap();
            let file = fs::File::open(path).unwrap();
            let copy = unsafe {
                nix::libc::fcntl(
                    file.as_raw_fd(),
                    nix::libc::F_DUPFD_CLOEXEC,
                    FINALITY_FD + 1,
                )
            };
            assert!(
                copy > FINALITY_FD,
                "pin fixture descriptors above all destinations"
            );
            owned.push(unsafe { OwnedFd::from_raw_fd(copy) });
        }
        let originals = [
            owned[0].as_raw_fd(),
            owned[1].as_raw_fd(),
            owned[2].as_raw_fd(),
        ];
        let script = match destinations {
            1 => {
                r#"set -eu
 test "$(/bin/cat /dev/fd/198)" = key-record
"#
            }
            2 => {
                r#"set -eu
 test "$(/bin/cat /dev/fd/198)" = key-record
 test "$(/bin/cat /dev/fd/200)" = public-frame
"#
            }
            3 => {
                r#"set -eu
 test "$(/bin/cat /dev/fd/198)" = key-record
 test "$(/bin/cat /dev/fd/201)" = public-frame
 test "$(/bin/cat /dev/fd/202)" = finality-frame
"#
            }
            _ => panic!("fixture supports the exact one-, two- and three-input native commands"),
        };
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(script)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.as_std_mut().pre_exec(move || {
                for index in 0..originals.len() {
                    if nix::libc::dup2(originals[index], source_targets[index]) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if close_on_exec
                        && nix::libc::fcntl(
                            source_targets[index],
                            nix::libc::F_SETFD,
                            nix::libc::FD_CLOEXEC,
                        ) < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        match destinations {
            1 => inherit_native_descriptors(&mut command, [(source_targets[0], KEY_FD)]),
            2 => inherit_native_descriptors(
                &mut command,
                [(source_targets[0], KEY_FD), (source_targets[1], 200)],
            ),
            3 => inherit_rotation_descriptors(
                &mut command,
                source_targets[0],
                source_targets[1],
                source_targets[2],
            ),
            _ => unreachable!("fixture checked its exact destination count"),
        }
        let output = command.output().await.unwrap();
        drop(owned);
        output
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_rotation_descriptor_handoff_preserves_overlapping_sources() {
        let output =
            observe_rotation_descriptor_handoff([PUBLIC_FD, KEY_FD, FINALITY_FD], false, 3).await;
        assert!(
            output.status.success(),
            "overlapping source descriptors must retain all three original inputs: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_rotation_descriptor_handoff_clears_close_on_exec_for_fixed_sources() {
        let output =
            observe_rotation_descriptor_handoff([KEY_FD, PUBLIC_FD, FINALITY_FD], true, 3).await;
        assert!(
            output.status.success(),
            "fixed source descriptors must survive exec with their original inputs: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn native_pending_descriptor_handoff_preserves_overlapping_sources() {
        let output =
            observe_rotation_descriptor_handoff([200, KEY_FD, FINALITY_FD], false, 2).await;
        assert!(
            output.status.success(),
            "pending and retained custody inputs must survive overlap: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_single_descriptor_handoff_clears_close_on_exec() {
        let output =
            observe_rotation_descriptor_handoff([KEY_FD, PUBLIC_FD, FINALITY_FD], true, 1).await;
        assert!(
            output.status.success(),
            "the fixed signer descriptor must survive exec: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Inspect the actual peer spawn paths without claiming a completed DKG.
    async fn observe_native_peer_phase_handoff(genesis: bool) {
        use std::os::unix::fs::PermissionsExt as _;

        let root =
            super::super::disposable_runtime_provider_broker::new_disposable_owner_private_root()
                .unwrap();
        let python = std::process::Command::new("python3")
            .args(["-c", "import sys; print(sys.executable)"])
            .output()
            .unwrap();
        assert!(python.status.success());
        let python = String::from_utf8(python.stdout).unwrap();
        let python = format!("'{}'", python.trim().replace('\'', "'\"'\"'"));
        let script = root.path().join("observe-peer-phase-handoff.sh");
        let consume = if genesis { ": > ./provision.fd198" } else { "" };
        fs::write(
            &script,
            format!(
                r#"#!/bin/sh
set -eu
test "$(/usr/bin/wc -c < /dev/fd/198)" -eq 71
{consume}
{python} -c 'import fcntl, os; assert fcntl.fcntl(201, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY; assert fcntl.fcntl(202, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY'
"#,
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let network = NetworkBuilder::new()
            .with_peers(4)
            .with_base_seed(if genesis {
                "native_genesis_phase_input"
            } else {
                "native_rotation_phase_input"
            })
            .build();
        let seat = &network.validators()[0];
        let roster = network
            .validators()
            .iter()
            .map(NetworkPeer::id)
            .collect::<Vec<_>>();
        let session = genesis_dkg_session(network.network_id(), &roster);
        let limits = NativeFinalityLimits {
            block_bytes: 1024,
            journal_bytes: 4096,
            block_count: 8,
            allocated_bytes: 8192,
        };
        let mut process = if genesis {
            let paths =
                ["request", "manifest", "signed", "public-key"].map(|name| root.path().join(name));
            spawn_genesis_seat(
                &script,
                seat,
                1,
                &session,
                &paths,
                369,
                &network.chain_id(),
                limits,
            )
        } else {
            let input = DisposableRotationProofInput {
                network_id: network.network_id(),
                chain_id: network.chain_id(),
                finality_limits: limits,
                target_epoch: 2,
                transition_id: CryptoHash::new(b"native rotation descriptor fixture"),
            };
            spawn_seat(
                &script,
                seat,
                1,
                &session,
                &root.path().join("selection"),
                &input,
                1,
            )
        }
        .unwrap();
        assert!(
            timeout(Duration::from_secs(5), process.child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        assert_eq!(
            fs::metadata(process.owner_root.path().join("identity.private"))
                .unwrap()
                .len(),
            71
        );
        if genesis {
            assert!(
                retire_one_shot_genesis_descriptor(
                    &process.owner_root.path().join("provision.fd198")
                )
                .unwrap()
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_rotation_peer_seat_hands_read_only_phases_to_owned_child() {
        observe_native_peer_phase_handoff(false).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_genesis_peer_seat_hands_read_only_phases_to_owned_child() {
        observe_native_peer_phase_handoff(true).await;
    }

    #[test]
    fn native_public_command_projection_is_exact_and_body_free() {
        use super::{
            NativePublicCommandOutcome as Outcome, NativePublicCommandPhase as Phase,
            native_public_command_completed_outcome, native_public_command_status_line,
        };
        let expected = [
            Outcome::InvalidInput,
            Outcome::InvalidCustody,
            Outcome::Crypto,
            Outcome::Height,
            Outcome::Deadline,
            Outcome::Io,
            Outcome::Session,
            Outcome::LocalDkg,
            Outcome::Journal,
            Outcome::GenesisBundle,
            Outcome::Export,
            Outcome::Attempt,
            Outcome::PendingAttempt,
        ];
        for (code, outcome) in (70..=82).zip(expected) {
            assert_eq!(
                native_public_command_completed_outcome(Some(code), None),
                outcome
            );
            let line =
                native_public_command_status_line(Phase::GenesisInstall, outcome, Some(code), None);
            assert_eq!(
                line,
                format!(
                    "iroha-native-public-command-v1 phase=genesis_install outcome={} exit_code={} signal=none",
                    outcome.label(),
                    code
                )
            );
        }
        assert_eq!(
            native_public_command_completed_outcome(Some(0), None),
            Outcome::Success
        );
        for code in [1, 2, 69, 83, 101, 255] {
            assert_eq!(
                native_public_command_completed_outcome(Some(code), None),
                Outcome::UnknownExit
            );
        }
        assert_eq!(
            native_public_command_completed_outcome(None, Some(15)),
            Outcome::Signaled
        );
        for (code, signal) in [
            (None, None),
            (Some(0), Some(15)),
            (Some(70), Some(15)),
            (Some(82), Some(15)),
            (Some(-1), None),
            (Some(256), None),
            (None, Some(0)),
            (None, Some(-1)),
        ] {
            assert_eq!(
                native_public_command_completed_outcome(code, signal),
                Outcome::UnknownStatus
            );
        }
        assert_eq!(
            native_public_command_status_line(
                Phase::GenesisInstall,
                Outcome::GenesisBundle,
                Some(79),
                None
            ),
            "iroha-native-public-command-v1 phase=genesis_install outcome=genesis_bundle exit_code=79 signal=none"
        );
        assert_eq!(
            native_public_command_status_line(Phase::GenesisDkg, Outcome::Timeout, None, None),
            "iroha-native-public-command-v1 phase=genesis_dkg outcome=timeout exit_code=none signal=none"
        );
        assert_eq!(
            native_public_command_status_line(
                Phase::RotationDkg,
                Outcome::ProcessIoFailure,
                None,
                None
            ),
            "iroha-native-public-command-v1 phase=rotation_dkg outcome=process_io_failure exit_code=none signal=none"
        );
        assert_eq!(
            native_public_command_status_line(
                Phase::RotationFinalize,
                Outcome::Signaled,
                None,
                Some(15)
            ),
            "iroha-native-public-command-v1 phase=rotation_finalize outcome=signaled exit_code=none signal=15"
        );
    }

    #[test]
    fn public_reducer_admission_retains_original_ceremony_pool_and_retry() {
        use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
        use iroha_core::beacon::GlobalThresholdBeaconSessionError;
        use std::task::{Context, Waker};

        let roster = (1_u8..=4)
            .map(|seat| {
                PeerId::new(
                    KeyPair::try_from_seed(vec![seat; 32], Algorithm::BlsNormal)
                        .unwrap()
                        .public_key()
                        .clone(),
                )
            })
            .collect::<Vec<_>>();
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            CryptoHash::new(b"disposable DKG original ceremony pool"),
        ));
        let session = genesis_dkg_session(network, &roster);
        let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;
        let budget = AllocationBudget::new(1024 * 1024);
        let mut slot = budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut slot).unwrap();
        drop(slot);
        let floor = budget.reserved_bytes();
        // This empty input exercises admission before any signed publication is
        // received. It does not assert that a complete ceremony has finalized.
        let initial = merge_publications(session, &[], &crypto, &budget).unwrap();
        assert!(initial.allocation_budget().same_pool(&budget));
        let retained_bytes = budget.reserved_bytes() - floor;
        assert!(retained_bytes > 0);
        drop(initial);
        assert_eq!(budget.reserved_bytes(), floor);
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - floor)
            .unwrap();
        let expected = budget.try_reserve_bytes(retained_bytes).unwrap_err();
        let error = merge_publications(session, &[], &crypto, &budget)
            .err()
            .expect("actual original pool is fully occupied");
        let Some(GlobalThresholdBeaconSessionError::Admission(actual)) =
            error.downcast_ref::<GlobalThresholdBeaconSessionError>()
        else {
            panic!("relay must retain actual typed original admission: {error:?}");
        };
        assert_eq!(actual, &expected);
        let AllocationRefusal::Capacity { release, .. } = actual else {
            panic!("occupied original pool has a real release source");
        };
        let mut context = Context::from_waker(Waker::noop());
        assert!(registration.poll_wait(release, &mut context).is_pending());
        let foreign = AllocationBudget::new(1);
        drop(foreign.try_reserve_bytes(1).unwrap());
        assert!(registration.poll_wait(release, &mut context).is_pending());
        drop(blocker);
        assert!(registration.poll_wait(release, &mut context).is_ready());
        registration.cancel();
        let retry = merge_publications(session, &[], &crypto, &budget).unwrap();
        assert!(retry.allocation_budget().same_pool(&budget));
        assert_eq!(retry.session_id(), session.session_id);
        assert_eq!(budget.reserved_bytes(), floor + retained_bytes);
        drop(retry);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn pending_custody_descriptor_preserves_record_and_supports_native_consumption() {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("pending-share.bin");
        let bytes = [0x51; 96];
        let mut record = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        record.write_all(&bytes).unwrap();
        record.sync_all().unwrap();
        let original = record.metadata().unwrap();
        drop(record);

        let inherited = open_pending_custody_descriptor(&path).unwrap();
        let opened = inherited.metadata().unwrap();
        assert_eq!(
            (opened.dev(), opened.ino()),
            (original.dev(), original.ino())
        );
        assert_eq!(opened.mode() & 0o7777, 0o600);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let flags = OFlag::from_bits_retain(fcntl(&inherited, FcntlArg::F_GETFL).unwrap());
        assert_eq!(flags & OFlag::O_ACCMODE, OFlag::O_RDWR);

        // Match the native loader's kernel-descriptor reopen. macOS refuses this
        // for a read-only inherited descriptor even when its file is writable.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let descriptor_path = format!("/proc/self/fd/{}", inherited.as_raw_fd());
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let descriptor_path = format!("/dev/fd/{}", inherited.as_raw_fd());
        let mut consumed = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(descriptor_path)
            .unwrap();
        let mut loaded = [0; 96];
        consumed.read_exact(&mut loaded).unwrap();
        assert_eq!(loaded, bytes);
        consumed.seek(SeekFrom::Start(0)).unwrap();
        consumed.write_all(&[0; 96]).unwrap();
        consumed.set_len(0).unwrap();
        assert_eq!(inherited.metadata().unwrap().len(), 0);
        assert_eq!(fs::metadata(&path).unwrap().ino(), original.ino());

        let missing = root.path().join("missing");
        assert!(open_pending_custody_descriptor(&missing).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn credential_bound_is_forwarded_exactly_to_native_operation() {
        assert_eq!(
            credential_memory_args(std::num::NonZeroUsize::new(123_456).unwrap()),
            ["--credential-max-memory-bytes", "123456"]
        );
    }

    #[test]
    fn native_phase_bounds_are_forwarded_without_context_hash_fallback() {
        let limits = NativeFinalityLimits {
            block_bytes: 1024,
            journal_bytes: 4096,
            block_count: 8,
            allocated_bytes: 8192,
        };
        assert_eq!(
            finality_limit_args(limits),
            vec![
                "--finality-block-bytes",
                "1024",
                "--finality-journal-bytes",
                "4096",
                "--finality-block-count",
                "8",
                "--finality-allocated-bytes",
                "8192"
            ]
        );
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            CryptoHash::new(b"native phase refusal"),
        ));
        let mut cursor = NativeJournalCursor::new(
            ChainId::from("phase-refusal"),
            network,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            limits,
            &iroha_allocation::AllocationBudget::new(limits.allocated_bytes),
        )
        .unwrap();
        let journal = NativeFinalityJournal { blocks: Vec::new() };
        assert!(advance_native_phase(&mut cursor, &journal, 2).is_err());
        assert!(cursor.tip().is_none());
        assert!(encode_phase_journal(&journal, limits).is_err());
    }

    use super::*;

    #[test]
    fn attempt_roots_and_provider_handles_are_distinct_and_canonical() {
        let first = PeerId::new(
            KeyPair::try_from_seed(b"seat-a".to_vec(), Algorithm::BlsNormal)
                .unwrap()
                .public_key()
                .clone(),
        );
        let second = PeerId::new(
            KeyPair::try_from_seed(b"seat-b".to_vec(), Algorithm::BlsNormal)
                .unwrap()
                .public_key()
                .clone(),
        );
        assert_ne!(provider_handle(&first), provider_handle(&second));
        for peer in [&first, &second] {
            iroha_config::parameters::validate_production_runtime_handle(&provider_handle(peer))
                .unwrap();
        }
    }

    #[test]
    fn native_phase_fifo_uses_read_only_input_and_keeps_writer_alive() {
        use std::io::Read as _;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("phase.fifo");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let (mut reader, mut writer) = open_native_phase_fifo(&path).unwrap();
        // SAFETY: both descriptors are live owned files; F_GETFL only reads flags.
        #[allow(unsafe_code)]
        let (read_flags, write_flags) = unsafe {
            (
                nix::libc::fcntl(reader.as_raw_fd(), nix::libc::F_GETFL),
                nix::libc::fcntl(writer.as_raw_fd(), nix::libc::F_GETFL),
            )
        };
        assert!(read_flags >= 0 && write_flags >= 0);
        assert_eq!(read_flags & nix::libc::O_ACCMODE, nix::libc::O_RDONLY);
        assert_eq!(write_flags & nix::libc::O_ACCMODE, nix::libc::O_WRONLY);
        assert_ne!(read_flags & nix::libc::O_NONBLOCK, 0);
        let mut observed = [0; 5];
        assert_eq!(
            reader.read(&mut observed).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        writer.write_all(b"phase").unwrap();
        reader.read_exact(&mut observed).unwrap();
        assert_eq!(&observed, b"phase");
    }

    #[test]
    fn public_frame_rejects_empty_and_oversized_bytes() {
        let root =
            super::super::disposable_runtime_provider_broker::new_disposable_owner_private_root()
                .unwrap();
        let path = root.path().join("frame");
        let mut writer = fs::File::create(path).unwrap();
        assert!(write_frame(&mut writer, b"", 4, Instant::now() + PROCESS_TIMEOUT).is_err());
        assert!(
            write_frame(
                &mut writer,
                b"oversized",
                4,
                Instant::now() + PROCESS_TIMEOUT
            )
            .is_err()
        );
    }

    #[test]
    fn public_frame_fifo_preserves_large_frames_and_bounds_an_unread_peer() {
        use std::os::unix::fs::OpenOptionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("public.fifo");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let mut reader = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        let mut writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let payload = vec![0x5A; 256 * 1024];
        let expected = payload.clone();
        let deadline = Instant::now() + Duration::from_secs(5);
        let receiving = std::thread::spawn(move || {
            let mut observed = Vec::new();
            let mut scratch = [0_u8; 1_013];
            while observed.len() < expected.len() + 4 {
                assert!(
                    Instant::now() < deadline,
                    "complete FIFO frame must make progress"
                );
                match reader.read(&mut scratch) {
                    Ok(0) => panic!("writer closed before its complete frame"),
                    Ok(count) => observed.extend_from_slice(&scratch[..count]),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("FIFO read failed: {error}"),
                }
            }
            assert_eq!(
                &observed[..4],
                &u32::try_from(expected.len()).unwrap().to_be_bytes()
            );
            assert_eq!(&observed[4..], expected);
            reader
        });
        write_frame(&mut writer, &payload, payload.len(), deadline).unwrap();
        let _reader = receiving.join().unwrap();
        let error = write_frame(
            &mut writer,
            &vec![0xA5; 2 * 1024 * 1024],
            2 * 1024 * 1024,
            Instant::now() + Duration::from_millis(25),
        )
        .expect_err("an open peer that stops reading cannot block the ceremony forever");
        assert!(
            error
                .to_string()
                .contains("rotation transport deadline elapsed")
        );
    }

    /// Own generated root using the same file-based checked identity as bare Kagami output.
    fn genesis_config_key_fixture(
        root: &Path,
        algorithm: Algorithm,
    ) -> (DisposableGenesisConfigSeat, KeyPair, NetworkId, ChainId) {
        use std::os::unix::fs::PermissionsExt as _;

        let key = KeyPair::try_from_seed(vec![0x31; 32], algorithm).unwrap();
        let transport = KeyPair::try_from_seed(vec![0x32; 32], Algorithm::Ed25519).unwrap();
        let streaming = KeyPair::try_from_seed(vec![0x33; 32], Algorithm::Ed25519).unwrap();
        let genesis = KeyPair::try_from_seed(vec![0x34; 32], Algorithm::Ed25519).unwrap();
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            CryptoHash::new(b"owned ordinary genesis config seat"),
        ));
        let chain = ChainId::from("00000000-0000-0000-0000-000000000000");
        // Bare Kagami explicitly renders every account-bearing default for
        // the generated chain. Native defaults deliberately remain Sora753
        // literals, even inside an ambient chain-discriminant guard.
        let literal = |account: iroha_data_model::account::AccountId| {
            account.to_i105_for_discriminant(369).unwrap()
        };
        let governance =
            iroha_config::parameters::defaults::governance::slash_receiver_account_id();
        let identity_path = root.join("network.id");
        fs::write(&identity_path, format!("{network}\n")).unwrap();
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600)).unwrap();
        let table = Table::new()
            .write("chain", chain.to_string())
            .write("chain_discriminant", 369_i64)
            .write("public_key", key.public_key().to_string())
            .write(
                "private_key",
                ExposedPrivateKey(key.private_key().clone()).to_string(),
            )
            .write(
                "soranet_transport_public_key",
                transport.public_key().to_string(),
            )
            .write(
                "soranet_transport_private_key",
                ExposedPrivateKey(transport.private_key().clone()).to_string(),
            )
            .write(
                ["streaming", "identity_public_key"],
                streaming.public_key().to_string(),
            )
            .write(
                ["streaming", "identity_private_key"],
                ExposedPrivateKey(streaming.private_key().clone()).to_string(),
            )
            .write(["network", "address"], "addr:127.0.0.1:1337#8F78")
            .write(["network", "public_address"], "addr:127.0.0.1:1337#8F78")
            .write(
                ["network", "soranet_vpn", "operator_account_id"],
                literal(iroha_data_model::account::AccountId::new(
                    transport.public_key().clone(),
                )),
            )
            .write(
                ["gov", "citizenship_escrow_account"],
                literal(iroha_config::parameters::defaults::governance::citizenship_escrow_account_id()),
            )
            .write(
                ["gov", "bond_escrow_account"],
                literal(iroha_config::parameters::defaults::governance::bond_escrow_account_id()),
            )
            .write(["gov", "slash_receiver_account"], literal(governance.clone()))
            .write(["gov", "viral_incentive_pool_account"], literal(governance.clone()))
            .write(["gov", "viral_escrow_account"], literal(governance.clone()))
            .write(
                ["gov", "sorafs_pin_fee_treasury_account"],
                literal(iroha_config::parameters::defaults::governance::sorafs_pin_fee::treasury_account_id()),
            )
            .write(
                ["nexus", "fees", "sponsor_vault_custody_account_id"],
                literal(iroha_config::parameters::defaults::nexus::fees::sponsor_vault_custody_account_id()),
            )
            .write(["torii", "address"], "addr:127.0.0.1:8080#8942")
            .write(["genesis", "public_key"], genesis.public_key().to_string())
            .write(["genesis", "expected_hash_file"], "network.id");
        let config_path = root.join("validator.toml");
        fs::write(&config_path, toml::to_string(&table).unwrap()).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        (
            DisposableGenesisConfigSeat {
                validator: PeerId::new(key.public_key().clone()),
                config_path,
            },
            key,
            network,
            chain,
        )
    }

    #[test]
    fn native_genesis_config_key_preserves_original_and_consumes_canonical_copy() {
        let root =
            super::super::disposable_runtime_provider_broker::new_disposable_owner_private_root()
                .unwrap();
        let (seat, key, network, chain) =
            genesis_config_key_fixture(root.path(), Algorithm::BlsNormal);
        let original = fs::read(&seat.config_path).unwrap();
        let before = fs::metadata(&seat.config_path).unwrap();
        let loaded = read_owner_private_genesis_config_key(&seat, network, 369, &chain).unwrap();
        assert_eq!(loaded.public_key(), key.public_key());
        let retained_path = root.path().join("identity.private");
        let retained = write_owner_private_key(&retained_path, &loaded).unwrap();
        assert_eq!(retained.metadata().unwrap().len(), 71);
        assert_eq!(retained.metadata().unwrap().mode() & 0o7777, 0o600);
        drop(retained);
        let one_shot_path = root.path().join("provision.fd198");
        let mut one_shot =
            copy_owner_private_genesis_signer_input(&retained_path, &one_shot_path).unwrap();
        let mut observed = zeroize::Zeroizing::new(Vec::new());
        one_shot.read_to_end(&mut observed).unwrap();
        assert_eq!(observed.len(), 71);
        assert_eq!(
            observed.as_slice(),
            format!("{}\n", ExposedPrivateKey(key.private_key().clone())).as_bytes()
        );
        one_shot.rewind().unwrap();
        one_shot.write_all(&[0; 71]).unwrap();
        one_shot.sync_data().unwrap();
        one_shot.set_len(0).unwrap();
        one_shot.sync_data().unwrap();
        assert!(retire_one_shot_genesis_descriptor(&one_shot_path).unwrap());
        assert!(!one_shot_path.exists());
        assert_eq!(fs::metadata(&retained_path).unwrap().len(), 71);
        let after = fs::metadata(&seat.config_path).unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.uid(),
                before.gid(),
                before.mode(),
                before.nlink(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.dev(),
                after.ino(),
                after.uid(),
                after.gid(),
                after.mode(),
                after.nlink(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            ),
        );
        assert_eq!(fs::read(&seat.config_path).unwrap(), original);
    }

    #[test]
    fn native_genesis_config_key_rejects_each_independent_anchor_mismatch() {
        let root =
            super::super::disposable_runtime_provider_broker::new_disposable_owner_private_root()
                .unwrap();
        let (seat, _, network, chain) =
            genesis_config_key_fixture(root.path(), Algorithm::BlsNormal);
        let other_chain = ChainId::from("00000000-0000-0000-0000-000000000001");
        let other_network =
            NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                CryptoHash::new(b"another independently selected network"),
            ));
        let original = fs::read(&seat.config_path).unwrap();
        assert!(read_owner_private_genesis_config_key(&seat, network, 369, &other_chain).is_err());
        assert!(read_owner_private_genesis_config_key(&seat, network, 370, &chain).is_err());
        assert!(read_owner_private_genesis_config_key(&seat, other_network, 369, &chain).is_err());
        let mut other_seat = seat.clone();
        other_seat.validator = PeerId::new(
            KeyPair::try_from_seed(vec![0x41; 32], Algorithm::BlsNormal)
                .unwrap()
                .public_key()
                .clone(),
        );
        assert!(read_owner_private_genesis_config_key(&other_seat, network, 369, &chain).is_err());
        assert_eq!(fs::read(&seat.config_path).unwrap(), original);
    }

    #[test]
    fn native_genesis_config_key_rejects_untrusted_custody_and_indirect_root() {
        use std::os::unix::fs::PermissionsExt as _;

        let root =
            super::super::disposable_runtime_provider_broker::new_disposable_owner_private_root()
                .unwrap();
        let (seat, _, network, chain) =
            genesis_config_key_fixture(root.path(), Algorithm::BlsNormal);
        let original = fs::read(&seat.config_path).unwrap();
        fs::set_permissions(&seat.config_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_owner_private_genesis_config_key(&seat, network, 369, &chain).is_err());
        fs::set_permissions(&seat.config_path, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = root.path().join("alias.toml");
        std::os::unix::fs::symlink(&seat.config_path, &alias).unwrap();
        let mut indirect = seat.clone();
        indirect.config_path = alias;
        assert!(read_owner_private_genesis_config_key(&indirect, network, 369, &chain).is_err());
        let linked = root.path().join("hardlink.toml");
        fs::hard_link(&seat.config_path, &linked).unwrap();
        assert!(read_owner_private_genesis_config_key(&seat, network, 369, &chain).is_err());
        fs::remove_file(linked).unwrap();
        fs::write(&seat.config_path, b"").unwrap();
        assert!(read_owner_private_genesis_config_key(&seat, network, 369, &chain).is_err());
        fs::write(&seat.config_path, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert!(read_owner_private_genesis_config_key(&seat, network, 369, &chain).is_err());
        let mut extended = b"extends = ['other.toml']\n".to_vec();
        extended.extend_from_slice(&original);
        fs::write(&seat.config_path, &extended).unwrap();
        assert!(read_owner_private_genesis_config_key(&seat, network, 369, &chain).is_err());
        fs::write(&seat.config_path, &original).unwrap();
        indirect.config_path = PathBuf::from("validator.toml");
        assert!(read_owner_private_genesis_config_key(&indirect, network, 369, &chain).is_err());
        let ancestor_link = root.path().join("linked-root");
        std::os::unix::fs::symlink(root.path(), &ancestor_link).unwrap();
        indirect.config_path = ancestor_link.join("validator.toml");
        assert!(read_owner_private_genesis_config_key(&indirect, network, 369, &chain).is_err());
        indirect.config_path = root
            .path()
            .join("..")
            .join(root.path().file_name().unwrap())
            .join("validator.toml");
        assert!(read_owner_private_genesis_config_key(&indirect, network, 369, &chain).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(read_owner_private_genesis_config_key(&seat, network, 369, &chain).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn native_genesis_config_key_rejects_non_bls_and_invalid_native_identity_file() {
        let root =
            super::super::disposable_runtime_provider_broker::new_disposable_owner_private_root()
                .unwrap();
        let (seat, _, network, chain) = genesis_config_key_fixture(root.path(), Algorithm::Ed25519);
        assert!(read_owner_private_genesis_config_key(&seat, network, 369, &chain).is_err());
        let (seat, _, network, chain) =
            genesis_config_key_fixture(root.path(), Algorithm::BlsNormal);
        fs::write(
            root.path().join("network.id"),
            b"not a checked native identity\n",
        )
        .unwrap();
        assert!(read_owner_private_genesis_config_key(&seat, network, 369, &chain).is_err());
    }

    #[test]
    fn native_genesis_config_scrubber_erases_nested_private_values() {
        let mut table: toml::Table = toml::from_str(
            "private_key = 'secret'\nvalues = ['secret', 4]\n[nested]\nprivate_key = 'secret'\n",
        )
        .unwrap();
        scrub_genesis_config_table(&mut table);
        assert_eq!(table["private_key"].as_str(), Some(""));
        assert_eq!(table["values"].as_array().unwrap()[0].as_str(), Some(""));
        assert_eq!(table["values"].as_array().unwrap()[1].as_integer(), Some(4));
        assert_eq!(table["nested"]["private_key"].as_str(), Some(""));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_genesis_config_seat_hands_only_key_record_to_owned_child() {
        use std::os::unix::fs::PermissionsExt as _;

        let root =
            super::super::disposable_runtime_provider_broker::new_disposable_owner_private_root()
                .unwrap();
        let (seat, _, network, chain) =
            genesis_config_key_fixture(root.path(), Algorithm::BlsNormal);
        let script = root.path().join("observe-key-handoff.sh");
        let python = std::process::Command::new("python3")
            .args(["-c", "import sys; print(sys.executable)"])
            .output()
            .expect("Python 3 is required to inspect inherited native FIFO access modes");
        assert!(
            python.status.success(),
            "resolve the Python 3 test interpreter"
        );
        let python = String::from_utf8(python.stdout).unwrap();
        let python = format!("'{}'", python.trim().replace('\'', "'\"'\"'"));
        let memory_bound = iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get();
        let script_body = format!(
            r#"#!/bin/sh
set -eu
key=0
memory=0
previous=''
for argument do
  test "$argument" != '--config-fd'
  if test "$previous" = '--key-fd'; then test "$argument" = '198'; key=1; fi
  if test "$previous" = '--credential-max-memory-bytes'; then test "$argument" = '{memory_bound}'; memory=1; fi
  previous=$argument
done
test "$key" = 1
test "$memory" = 1
test "$(/usr/bin/wc -c < /dev/fd/198)" -eq 71
: > ./provision.fd198
{python} -c 'import fcntl, os; assert fcntl.fcntl(201, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY; assert fcntl.fcntl(202, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY'
"#,
        );
        fs::write(&script, script_body.as_bytes()).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let roster = (1_u8..=4)
            .map(|index| {
                if index == 1 {
                    seat.validator.clone()
                } else {
                    PeerId::new(
                        KeyPair::try_from_seed(vec![index; 32], Algorithm::BlsNormal)
                            .unwrap()
                            .public_key()
                            .clone(),
                    )
                }
            })
            .collect::<Vec<_>>();
        let session = genesis_dkg_session(network, &roster);
        let public_paths =
            ["request", "manifest", "signed", "public-key"].map(|name| root.path().join(name));
        let limits = NativeFinalityLimits {
            block_bytes: 1024,
            journal_bytes: 4096,
            block_count: 8,
            allocated_bytes: 8192,
        };
        let original = fs::read(&seat.config_path).unwrap();
        let mut process = spawn_genesis_config_seat(
            &script,
            &seat,
            1,
            &session,
            &public_paths,
            369,
            &chain,
            limits,
        )
        .unwrap();
        assert!(
            timeout(Duration::from_secs(5), process.child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        assert!(
            retire_one_shot_genesis_descriptor(&process.owner_root.path().join("provision.fd198"))
                .unwrap()
        );
        assert_eq!(
            fs::metadata(process.owner_root.path().join("identity.private"))
                .unwrap()
                .len(),
            71
        );
        assert_eq!(fs::read(&seat.config_path).unwrap(), original);
    }

    #[test]
    fn native_genesis_config_descriptor_requires_direct_owner_private_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("validator.toml");
        let copied = root.path().join("fd198.toml");
        fs::write(&source, b"[common]\npeer = 'signed-seat'\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let mut descriptor = copy_owner_private_genesis_signer_input(&source, &copied).unwrap();
        let mut observed = Vec::new();
        descriptor.read_to_end(&mut observed).unwrap();
        assert_eq!(observed, fs::read(&source).unwrap());
        assert_eq!(descriptor.metadata().unwrap().mode() & 0o7777, 0o600);
        assert!(!retire_one_shot_genesis_descriptor(&copied).unwrap());
        assert!(!copied.exists());
        let one_shot = root.path().join("consumed.fd198");
        let consumed = copy_owner_private_genesis_signer_input(&source, &one_shot).unwrap();
        consumed.set_len(0).unwrap();
        assert!(retire_one_shot_genesis_descriptor(&one_shot).unwrap());
        assert!(!one_shot.exists());
        assert!(
            source.exists(),
            "retained signer source must survive one-shot children"
        );
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            copy_owner_private_genesis_signer_input(&source, &root.path().join("unsafe")).is_err()
        );
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(
            copy_owner_private_genesis_signer_input(&alias, &root.path().join("link")).is_err()
        );
    }
}
