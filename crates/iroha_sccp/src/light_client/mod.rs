//! Stateless SCCP v1 inbound light-client verification (spec `specs/sccp.md` §4.13).
//!
//! Every function here checks untrusted source-chain evidence (finality updates, validator-set
//! transitions, header segments, key-block links and inclusion proofs) against light-client
//! state read through [`state::SccpLcStateView`]. The modules keep no state of their own and
//! perform no I/O, so Taira execution, the irohad keeper and wallets run the same verifier:
//!
//! - [`verify_bootstrap`] checks a Parliament-enacted `InitializeLightClient` bootstrap, fresh at
//!   the enactment block time, and returns what to install; [`initialize_light_client`] adds the
//!   `expected` check against stored state and the re-initialization purge (a frozen light
//!   client's learned sets and checkpoints never survive it);
//! - [`apply_advance`] checks a permissionless `AdvanceSccpLightClientV1` (including `Backfill`)
//!   and returns a [`state::SccpLcDeltaV1`]; re-proving stored data yields an empty delta and
//!   conflicting data an error pointing to `ReportSccpLightClientEquivocationV1`;
//! - [`verify_proof`] checks an inbound or void proof and returns its normalized source event and
//!   the checkpoints to record;
//! - [`verify_equivocation`] checks two conflicting quorum-valid records and returns the freeze
//!   reason.
//!
//! Frames travel as headered canonical Norito frames ([`proof`]) inside the data-model byte
//! wrappers. The source-chain fork schedule and `supported_until` come from the compiled
//! [`profile`], never from stored params. [`SccpVerifierWorkV1`] estimates the committed `sccp` (ZK validity policy) work
//! categories of every call before it runs, so core can meter and reject oversized work cheaply.

pub mod bsc;
pub mod ethereum;
pub mod profile;
pub mod proof;
pub mod state;
pub mod ton;
pub mod tron;

use core::fmt;

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        inbound::SccpSourceProofBytesV1,
        light_client::{
            SCCP_LC_BOOTSTRAP_MAX_BYTES_V1, SccpLcAdvanceBytesV1, SccpLcBootstrapV1,
            SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1,
            SccpLcEvidenceBytesV1, SccpLcFreezeReasonV1, SccpLcInitExpectationV1,
            SccpLightClientParamsError, SccpLightClientParamsV1, SccpLightClientV1,
        },
    },
};

use self::{
    bsc::BscLcError, ethereum::EthereumLcError, profile::SccpChainProfilesV1, ton::TonLcError,
    tron::TronLcError,
};
pub use self::{
    proof::{
        SccpLcAdvanceV1, SccpLcBootstrapDataV1, SccpLcEvidenceV1, SccpLcSegmentV1, SccpLcSetDataV1,
        SccpNormalizedEventV1, SccpSourceEmitterV1, SccpSourceProofV1, SccpVerifiedProofV1,
    },
    state::{SccpLcDeltaV1, SccpLcInitialStateV1, SccpLcPurgeV1, SccpLcStateView},
};

/// Stored data an advance, proof or bootstrap conflicts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SccpLcConflictV1 {
    /// A stored checkpoint at this source height describes another block (hash, roots or time,
    /// see [`state::same_checkpoint_block`]).
    Checkpoint {
        /// Source height.
        source_height: u64,
    },
    /// A stored consensus set with this id has other content.
    ConsensusSet {
        /// Set id.
        set_id: u64,
    },
}

impl fmt::Display for SccpLcConflictV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Checkpoint { source_height } => {
                write!(
                    formatter,
                    "stored checkpoint at source height {source_height}"
                )
            }
            Self::ConsensusSet { set_id } => write!(formatter, "stored consensus set {set_id}"),
        }
    }
}

/// Light-client verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SccpLcError {
    /// No light client of this release verifies the network (Taira, or a chain whose light
    /// client lands later).
    UnsupportedNetwork(SccpNetworkV1),
    /// A frame, params record or bootstrap names another network than the instruction.
    NetworkMismatch {
        /// Network of the instruction.
        expected: SccpNetworkV1,
        /// Network named by the data.
        found: SccpNetworkV1,
    },
    /// No light client is installed for the network.
    NotInstalled(SccpNetworkV1),
    /// `InitializeLightClient` names an expectation the stored state does not meet (§4.14.3):
    /// `Absent` while a light client is installed, or `Unusable` while none is installed or the
    /// installed one is neither frozen nor aged beyond its weak-subjectivity bound.
    UnexpectedLightClientState {
        /// Network of the action.
        network: SccpNetworkV1,
        /// Expectation named by the action.
        expected: SccpLcInitExpectationV1,
    },
    /// The light client is frozen and accepts no advance or proof.
    Frozen(SccpNetworkV1),
    /// The params are invalid.
    InvalidParams(SccpLightClientParamsError),
    /// A frame is not a canonical headered Norito frame of its type.
    MalformedFrame(&'static str),
    /// A frame exceeds its byte bound.
    FrameTooLarge {
        /// Frame kind.
        kind: &'static str,
        /// Actual length.
        len: usize,
        /// Bound.
        max: usize,
    },
    /// A frame carries more items than allowed.
    TooManyItems {
        /// Item kind.
        kind: &'static str,
        /// Actual count.
        count: usize,
        /// Bound.
        max: usize,
    },
    /// A frame carries fewer items than required.
    TooFewItems {
        /// Item kind.
        kind: &'static str,
        /// Actual count.
        count: usize,
        /// Minimum.
        min: usize,
    },
    /// The signing set is not stored.
    UnknownSigningSet {
        /// Set id.
        set_id: u64,
    },
    /// The signing set was superseded longer than `ws_bound_ms` ago (weak subjectivity).
    StaleSigningSet {
        /// Set id.
        set_id: u64,
        /// Taira time from which the set is stale.
        stale_from_ms: u64,
    },
    /// The evidence is signed under a fork beyond the compiled `supported_until`.
    ForkBeyondSupported {
        /// Epoch (or chain-specific unit) of the evidence.
        epoch: u64,
        /// Compiled bound.
        supported_until: u64,
    },
    /// Source time is ahead of the Taira block time.
    SourceTimeInFuture {
        /// Source time (ms).
        source_ms: u64,
        /// Taira block time (ms).
        taira_now_ms: u64,
    },
    /// The data conflicts with stored light-client data; report the conflict with
    /// `ReportSccpLightClientEquivocationV1`.
    ConflictsWithStoredData(SccpLcConflictV1),
    /// The referenced stored checkpoint does not exist.
    UnknownCheckpoint {
        /// Source height.
        source_height: u64,
    },
    /// The two evidence records do not conflict.
    EvidenceNotConflicting,
    /// Ethereum-specific verification failure.
    Ethereum(EthereumLcError),
    /// BSC-specific verification failure.
    Bsc(BscLcError),
    /// TRON-specific verification failure.
    Tron(TronLcError),
    /// TON-specific verification failure.
    Ton(TonLcError),
}

impl fmt::Display for SccpLcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedNetwork(network) => write!(
                formatter,
                "no SCCP light client verifies {} in this release",
                network.profile_key()
            ),
            Self::NetworkMismatch { expected, found } => write!(
                formatter,
                "light-client data names {} instead of {}",
                found.profile_key(),
                expected.profile_key()
            ),
            Self::NotInstalled(network) => write!(
                formatter,
                "no light client is installed for {}",
                network.profile_key()
            ),
            Self::UnexpectedLightClientState { network, expected } => write!(
                formatter,
                "the {} light client is not {}",
                network.profile_key(),
                match expected {
                    SccpLcInitExpectationV1::Absent => "absent",
                    SccpLcInitExpectationV1::Unusable => "frozen or aged beyond its bound",
                }
            ),
            Self::Frozen(network) => {
                write!(
                    formatter,
                    "the {} light client is frozen",
                    network.profile_key()
                )
            }
            Self::InvalidParams(error) => write!(formatter, "invalid light-client params: {error}"),
            Self::MalformedFrame(kind) => write!(formatter, "malformed {kind} frame"),
            Self::FrameTooLarge { kind, len, max } => {
                write!(
                    formatter,
                    "{kind} frame has {len} bytes; at most {max} are allowed"
                )
            }
            Self::TooManyItems { kind, count, max } => {
                write!(formatter, "{count} {kind}; at most {max} are allowed")
            }
            Self::TooFewItems { kind, count, min } => {
                write!(formatter, "{count} {kind}; at least {min} are required")
            }
            Self::UnknownSigningSet { set_id } => {
                write!(formatter, "signing set {set_id} is not stored")
            }
            Self::StaleSigningSet {
                set_id,
                stale_from_ms,
            } => write!(
                formatter,
                "signing set {set_id} is beyond the weak-subjectivity bound since {stale_from_ms} ms"
            ),
            Self::ForkBeyondSupported {
                epoch,
                supported_until,
            } => write!(
                formatter,
                "epoch {epoch} is beyond the compiled supported_until {supported_until}"
            ),
            Self::SourceTimeInFuture {
                source_ms,
                taira_now_ms,
            } => write!(
                formatter,
                "source time {source_ms} ms is ahead of the Taira block time {taira_now_ms} ms"
            ),
            Self::ConflictsWithStoredData(conflict) => write!(
                formatter,
                "conflicts with the {conflict}; report it with ReportSccpLightClientEquivocationV1"
            ),
            Self::UnknownCheckpoint { source_height } => {
                write!(
                    formatter,
                    "no checkpoint is stored at source height {source_height}"
                )
            }
            Self::EvidenceNotConflicting => {
                formatter.write_str("the evidence records do not conflict")
            }
            Self::Ethereum(error) => write!(formatter, "Ethereum light client: {error}"),
            Self::Bsc(error) => write!(formatter, "BSC light client: {error}"),
            Self::Tron(error) => write!(formatter, "TRON light client: {error}"),
            Self::Ton(error) => write!(formatter, "TON light client: {error}"),
        }
    }
}

impl std::error::Error for SccpLcError {}

impl From<EthereumLcError> for SccpLcError {
    fn from(value: EthereumLcError) -> Self {
        Self::Ethereum(value)
    }
}

/// Verifier work of one call in the committed `sccp` limit categories of the ZK validity policy (§4.12.1 step 5).
///
/// `proofs` counts inbound and void proofs only; `proof_bytes` counts every verified frame
/// (proofs, advances and evidence). Core reserves the estimate per transaction and per block
/// before running the verifier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SccpVerifierWorkV1 {
    /// Inbound or void proofs.
    pub proofs: u32,
    /// Verified frame bytes.
    pub proof_bytes: u64,
    /// Execution or native headers hashed and linked.
    pub native_headers: u32,
    /// Bytes of those headers.
    pub native_header_bytes: u64,
    /// Ethereum `LightClientUpdate`s (each one fast-aggregate BLS check).
    pub ethereum_light_client_updates: u32,
    /// BSC fast-finality vote attestations (each one fast-aggregate BLS check).
    pub bls_vote_attestations: u32,
    /// secp256k1 recoveries (TRON headers).
    pub secp256k1_recoveries: u32,
    /// Ed25519 signature checks (TON blocks).
    pub ed25519_signature_checks: u32,
}

impl SccpVerifierWorkV1 {
    /// Field-wise checked sum.
    #[must_use]
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        Some(Self {
            proofs: self.proofs.checked_add(other.proofs)?,
            proof_bytes: self.proof_bytes.checked_add(other.proof_bytes)?,
            native_headers: self.native_headers.checked_add(other.native_headers)?,
            native_header_bytes: self
                .native_header_bytes
                .checked_add(other.native_header_bytes)?,
            ethereum_light_client_updates: self
                .ethereum_light_client_updates
                .checked_add(other.ethereum_light_client_updates)?,
            bls_vote_attestations: self
                .bls_vote_attestations
                .checked_add(other.bls_vote_attestations)?,
            secp256k1_recoveries: self
                .secp256k1_recoveries
                .checked_add(other.secp256k1_recoveries)?,
            ed25519_signature_checks: self
                .ed25519_signature_checks
                .checked_add(other.ed25519_signature_checks)?,
        })
    }
}

/// Fail unless this release has a light client for `network`.
fn ensure_supported(network: SccpNetworkV1) -> Result<(), SccpLcError> {
    match network {
        SccpNetworkV1::EthereumMainnet
        | SccpNetworkV1::BscMainnet
        | SccpNetworkV1::TronMainnet
        | SccpNetworkV1::TonMainnet => Ok(()),
        SccpNetworkV1::SoraTaira => Err(SccpLcError::UnsupportedNetwork(network)),
    }
}

fn usable_light_client<V: SccpLcStateView + ?Sized>(
    view: &V,
    network: SccpNetworkV1,
) -> Result<SccpLightClientV1, SccpLcError> {
    let light_client = view
        .light_client(network)
        .ok_or(SccpLcError::NotInstalled(network))?;
    if light_client.is_frozen() {
        return Err(SccpLcError::Frozen(network));
    }
    if light_client.params.network != network {
        return Err(SccpLcError::NetworkMismatch {
            expected: network,
            found: light_client.params.network,
        });
    }
    Ok(light_client)
}

const fn check_frame_len(kind: &'static str, len: usize, max: usize) -> Result<(), SccpLcError> {
    if len > max {
        Err(SccpLcError::FrameTooLarge { kind, len, max })
    } else {
        Ok(())
    }
}

fn u32_bound(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Verify an `InitializeLightClient` bootstrap with the compiled profiles.
///
/// See [`verify_bootstrap_with_profiles`].
///
/// # Errors
///
/// Returns the first violated rule.
pub fn verify_bootstrap(
    network: SccpNetworkV1,
    params: &SccpLightClientParamsV1,
    bootstrap: &SccpLcBootstrapV1,
    taira_now_ms: u64,
) -> Result<SccpLcInitialStateV1, SccpLcError> {
    verify_bootstrap_with_profiles(
        SccpChainProfilesV1::compiled(),
        network,
        params,
        bootstrap,
        taira_now_ms,
    )
}

/// Verify a bootstrap: the params are valid for `network`, the frame is bounded and names
/// `network`, its signing set is fresh at `taira_now_ms` (§4.13.2), and the chain rules hold.
/// Returns the light client, set and checkpoint (origin `Parliament`) to install.
///
/// # Errors
///
/// Returns the first violated rule.
pub fn verify_bootstrap_with_profiles(
    profiles: &SccpChainProfilesV1,
    network: SccpNetworkV1,
    params: &SccpLightClientParamsV1,
    bootstrap: &SccpLcBootstrapV1,
    taira_now_ms: u64,
) -> Result<SccpLcInitialStateV1, SccpLcError> {
    ensure_supported(network)?;
    params.validate().map_err(SccpLcError::InvalidParams)?;
    for found in [params.network, bootstrap.network] {
        if found != network {
            return Err(SccpLcError::NetworkMismatch {
                expected: network,
                found,
            });
        }
    }
    check_frame_len(
        "bootstrap",
        bootstrap.bytes.len(),
        SCCP_LC_BOOTSTRAP_MAX_BYTES_V1,
    )?;
    let data = SccpLcBootstrapDataV1::from_frame(&bootstrap.bytes)?;
    data.expect_network(network)?;
    match data {
        SccpLcBootstrapDataV1::Ethereum(bootstrap) => {
            ethereum::verify_bootstrap(&profiles.ethereum, params, &bootstrap, taira_now_ms)
        }
        SccpLcBootstrapDataV1::Bsc(bootstrap) => {
            bsc::verify_bootstrap(&profiles.bsc, params, &bootstrap, taira_now_ms)
        }
        SccpLcBootstrapDataV1::Tron(bootstrap) => {
            tron::verify_bootstrap(&profiles.tron, params, &bootstrap, taira_now_ms)
        }
        SccpLcBootstrapDataV1::Ton(bootstrap) => {
            ton::verify_bootstrap(&profiles.ton, params, &bootstrap, taira_now_ms)
        }
    }
}

/// Check an enacted `InitializeLightClient` with the compiled profiles.
///
/// See [`initialize_light_client_with_profiles`].
///
/// # Errors
///
/// Returns the first violated rule.
pub fn initialize_light_client<V: SccpLcStateView + ?Sized>(
    view: &V,
    network: SccpNetworkV1,
    expected: SccpLcInitExpectationV1,
    params: &SccpLightClientParamsV1,
    bootstrap: &SccpLcBootstrapV1,
    taira_now_ms: u64,
) -> Result<SccpLcInitialStateV1, SccpLcError> {
    initialize_light_client_with_profiles(
        SccpChainProfilesV1::compiled(),
        view,
        network,
        expected,
        params,
        bootstrap,
        taira_now_ms,
    )
}

/// Check an enacted `InitializeLightClient` (§4.14.3) against stored state and return what to
/// write, including what to delete first.
///
/// - `expected = Absent`: no light client is installed. Anything stored for the network is
///   orphaned, so the result purges it ([`SccpLcPurgeV1::DiscardUnvetted`]).
/// - `expected = Unusable` and the installed light client is frozen: its learned sets and
///   non-Parliament checkpoints may be forged, so the result purges them
///   ([`SccpLcPurgeV1::DiscardUnvetted`]); Parliament checkpoints stay.
/// - `expected = Unusable` and the installed light client aged beyond its weak-subjectivity
///   bound without a freeze: stored sets and checkpoints stay ([`SccpLcPurgeV1::KeepStored`]) so
///   old burns remain provable, and its newest set is recorded as superseded when its source
///   period ended, so set retention can prune it.
///
/// The bootstrap is checked by [`verify_bootstrap_with_profiles`] (fresh at `taira_now_ms`), and
/// its set and checkpoint must not conflict with a stored record that survives the purge.
///
/// # Errors
///
/// Returns [`SccpLcError::UnexpectedLightClientState`] when the expectation does not hold,
/// [`SccpLcError::ConflictsWithStoredData`] for a conflict with a surviving record, or the first
/// violated bootstrap rule.
pub fn initialize_light_client_with_profiles<V: SccpLcStateView + ?Sized>(
    profiles: &SccpChainProfilesV1,
    view: &V,
    network: SccpNetworkV1,
    expected: SccpLcInitExpectationV1,
    params: &SccpLightClientParamsV1,
    bootstrap: &SccpLcBootstrapV1,
    taira_now_ms: u64,
) -> Result<SccpLcInitialStateV1, SccpLcError> {
    ensure_supported(network)?;
    let unexpected = SccpLcError::UnexpectedLightClientState { network, expected };
    let aged = match (expected, view.light_client(network)) {
        (SccpLcInitExpectationV1::Absent, None) => None,
        (SccpLcInitExpectationV1::Unusable, Some(installed)) if installed.is_frozen() => None,
        (SccpLcInitExpectationV1::Unusable, Some(installed))
            if is_aged_with_profiles(profiles, view, &installed, network, taira_now_ms)? =>
        {
            Some(installed)
        }
        _ => return Err(unexpected),
    };
    let mut initial =
        verify_bootstrap_with_profiles(profiles, network, params, bootstrap, taira_now_ms)?;
    if let Some(installed) = aged {
        initial.purge = SccpLcPurgeV1::KeepStored;
        initial.superseded_sets = match network {
            SccpNetworkV1::EthereumMainnet => {
                ethereum::aged_supersessions(&profiles.ethereum, view, &installed)?
            }
            SccpNetworkV1::BscMainnet => bsc::aged_supersessions(view, &installed),
            SccpNetworkV1::TronMainnet => {
                tron::aged_supersessions(&profiles.tron, view, &installed)?
            }
            SccpNetworkV1::TonMainnet => ton::aged_supersessions(view, &installed),
            SccpNetworkV1::SoraTaira => return Err(SccpLcError::UnsupportedNetwork(network)),
        };
    }
    for checkpoint in &initial.checkpoints {
        let height = checkpoint.data.source_height;
        if let Some(stored) = view.checkpoint(network, height) {
            let survives = initial.purge == SccpLcPurgeV1::KeepStored
                || stored.origin == SccpLcCheckpointOriginV1::Parliament;
            if survives && !state::same_checkpoint_block(&stored.data, &checkpoint.data) {
                return Err(SccpLcError::ConflictsWithStoredData(
                    SccpLcConflictV1::Checkpoint {
                        source_height: height,
                    },
                ));
            }
        }
    }
    if initial.purge == SccpLcPurgeV1::KeepStored {
        for set in &initial.sets {
            if view
                .consensus_set(network, set.set_id)
                .is_some_and(|stored| stored.set_bytes != set.set_bytes)
            {
                return Err(SccpLcError::ConflictsWithStoredData(
                    SccpLcConflictV1::ConsensusSet { set_id: set.set_id },
                ));
            }
        }
    }
    Ok(initial)
}

/// Apply an advance with the compiled profiles.
///
/// See [`apply_advance_with_profiles`].
///
/// # Errors
///
/// Returns the first violated rule.
pub fn apply_advance<V: SccpLcStateView + ?Sized>(
    view: &V,
    network: SccpNetworkV1,
    advance: &SccpLcAdvanceBytesV1,
    taira_now_ms: u64,
) -> Result<SccpLcDeltaV1, SccpLcError> {
    apply_advance_with_profiles(
        SccpChainProfilesV1::compiled(),
        view,
        network,
        advance,
        taira_now_ms,
    )
}

/// Verify an `AdvanceSccpLightClientV1` payload against stored data and return what to write.
///
/// The light client must be installed and not frozen, and the frame must fit
/// `params.max_advance_bytes`. Re-proving stored data returns an empty delta; data that conflicts
/// with stored data returns [`SccpLcError::ConflictsWithStoredData`].
///
/// # Errors
///
/// Returns the first violated rule.
pub fn apply_advance_with_profiles<V: SccpLcStateView + ?Sized>(
    profiles: &SccpChainProfilesV1,
    view: &V,
    network: SccpNetworkV1,
    advance: &SccpLcAdvanceBytesV1,
    taira_now_ms: u64,
) -> Result<SccpLcDeltaV1, SccpLcError> {
    ensure_supported(network)?;
    let light_client = usable_light_client(view, network)?;
    check_frame_len(
        "advance",
        advance.len(),
        u32_bound(light_client.params.max_advance_bytes),
    )?;
    let decoded = SccpLcAdvanceV1::from_frame(advance.as_bytes())?;
    decoded.expect_network(network)?;
    match decoded {
        SccpLcAdvanceV1::Ethereum(advance) => ethereum::apply_advance(
            &profiles.ethereum,
            view,
            &light_client,
            &advance,
            taira_now_ms,
        ),
        SccpLcAdvanceV1::Bsc(advance) => {
            bsc::apply_advance(&profiles.bsc, view, &light_client, &advance, taira_now_ms)
        }
        SccpLcAdvanceV1::Tron(advance) => {
            tron::apply_advance(&profiles.tron, view, &light_client, &advance, taira_now_ms)
        }
        SccpLcAdvanceV1::Ton(advance) => {
            ton::apply_advance(&profiles.ton, view, &light_client, &advance, taira_now_ms)
        }
        SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Ethereum(segment),
        } => ethereum::apply_backfill(view, &light_client, &segment, taira_now_ms),
        SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Bsc(segment),
        } => bsc::apply_backfill(&profiles.bsc, view, &light_client, &segment, taira_now_ms),
        SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Tron(segment),
        } => tron::apply_backfill(&profiles.tron, view, &light_client, &segment, taira_now_ms),
    }
}

/// Verify an inbound or void proof with the compiled profiles.
///
/// See [`verify_proof_with_profiles`].
///
/// # Errors
///
/// Returns the first violated rule.
pub fn verify_proof<V: SccpLcStateView + ?Sized>(
    view: &V,
    network: SccpNetworkV1,
    proof: &SccpSourceProofBytesV1,
    taira_now_ms: u64,
) -> Result<SccpVerifiedProofV1, SccpLcError> {
    verify_proof_with_profiles(
        SccpChainProfilesV1::compiled(),
        view,
        network,
        proof,
        taira_now_ms,
    )
}

/// Verify an inbound or void proof against stored data (§4.12, §4.16) and return the normalized
/// source event and the checkpoints (origin `Proof`) to record.
///
/// The caller checks the event kind, the emitter against the revision's deployment and the
/// event fields against the payload.
///
/// # Errors
///
/// Returns the first violated rule.
pub fn verify_proof_with_profiles<V: SccpLcStateView + ?Sized>(
    profiles: &SccpChainProfilesV1,
    view: &V,
    network: SccpNetworkV1,
    proof: &SccpSourceProofBytesV1,
    taira_now_ms: u64,
) -> Result<SccpVerifiedProofV1, SccpLcError> {
    ensure_supported(network)?;
    let light_client = usable_light_client(view, network)?;
    check_frame_len(
        "source proof",
        proof.len(),
        u32_bound(light_client.params.max_proof_bytes),
    )?;
    let decoded = SccpSourceProofV1::from_frame(proof.as_bytes())?;
    decoded.expect_network(network)?;
    match decoded {
        SccpSourceProofV1::Ethereum(proof) => ethereum::verify_proof(
            &profiles.ethereum,
            view,
            &light_client,
            &proof,
            taira_now_ms,
        ),
        SccpSourceProofV1::Bsc(proof) => {
            bsc::verify_proof(&profiles.bsc, view, &light_client, &proof, taira_now_ms)
        }
        SccpSourceProofV1::Tron(proof) => {
            tron::verify_proof(&profiles.tron, view, &light_client, &proof, taira_now_ms)
        }
        SccpSourceProofV1::Ton(proof) => {
            ton::verify_proof(&profiles.ton, view, &proof, taira_now_ms)
        }
    }
}

/// Verify equivocation evidence with the compiled profiles.
///
/// See [`verify_equivocation_with_profiles`].
///
/// # Errors
///
/// Returns the first violated rule.
pub fn verify_equivocation<V: SccpLcStateView + ?Sized>(
    view: &V,
    network: SccpNetworkV1,
    a: &SccpLcEvidenceBytesV1,
    b: &SccpLcEvidenceBytesV1,
    taira_now_ms: u64,
) -> Result<SccpLcFreezeReasonV1, SccpLcError> {
    verify_equivocation_with_profiles(
        SccpChainProfilesV1::compiled(),
        view,
        network,
        a,
        b,
        taira_now_ms,
    )
}

/// Verify `ReportSccpLightClientEquivocationV1`: both records are quorum-valid under fresh
/// stored sets and conflict (same period, height or slot with different content, or finalized
/// source blocks whose heights and times are ordered inconsistently). Returns the freeze reason
/// naming the evidence pair.
///
/// A frozen light client may still be reported; core decides whether that changes anything.
///
/// # Errors
///
/// Returns the first violated rule, or [`SccpLcError::EvidenceNotConflicting`].
pub fn verify_equivocation_with_profiles<V: SccpLcStateView + ?Sized>(
    profiles: &SccpChainProfilesV1,
    view: &V,
    network: SccpNetworkV1,
    a: &SccpLcEvidenceBytesV1,
    b: &SccpLcEvidenceBytesV1,
    taira_now_ms: u64,
) -> Result<SccpLcFreezeReasonV1, SccpLcError> {
    ensure_supported(network)?;
    let light_client = view
        .light_client(network)
        .ok_or(SccpLcError::NotInstalled(network))?;
    let first = SccpLcEvidenceV1::from_frame(a.as_bytes())?;
    let second = SccpLcEvidenceV1::from_frame(b.as_bytes())?;
    first.expect_network(network)?;
    second.expect_network(network)?;
    match (first, second) {
        (SccpLcEvidenceV1::Ethereum(first), SccpLcEvidenceV1::Ethereum(second)) => {
            ethereum::verify_equivocation(
                &profiles.ethereum,
                view,
                &light_client,
                (&first, a.as_bytes()),
                (&second, b.as_bytes()),
                taira_now_ms,
            )
        }
        (SccpLcEvidenceV1::Bsc(first), SccpLcEvidenceV1::Bsc(second)) => bsc::verify_equivocation(
            &profiles.bsc,
            view,
            &light_client,
            (&first, a.as_bytes()),
            (&second, b.as_bytes()),
            taira_now_ms,
        ),
        (SccpLcEvidenceV1::Tron(first), SccpLcEvidenceV1::Tron(second)) => {
            tron::verify_equivocation(
                &profiles.tron,
                view,
                &light_client,
                (&first, a.as_bytes()),
                (&second, b.as_bytes()),
                taira_now_ms,
            )
        }
        (SccpLcEvidenceV1::Ton(first), SccpLcEvidenceV1::Ton(second)) => ton::verify_equivocation(
            &profiles.ton,
            view,
            (&first, a.as_bytes()),
            (&second, b.as_bytes()),
            taira_now_ms,
        ),
        (first, second) => Err(SccpLcError::NetworkMismatch {
            expected: first.network(),
            found: second.network(),
        }),
    }
}

/// Whether the installed light client has aged beyond its weak-subjectivity bound: its newest
/// signing set is stale at `taira_now_ms`, so it cannot advance and needs re-initialization
/// (`InitializeLightClient { expected: Unusable }`, §4.14.3).
///
/// # Errors
///
/// Returns [`SccpLcError::NotInstalled`] or [`SccpLcError::UnsupportedNetwork`].
pub fn is_aged<V: SccpLcStateView + ?Sized>(
    view: &V,
    network: SccpNetworkV1,
    taira_now_ms: u64,
) -> Result<bool, SccpLcError> {
    let light_client = view
        .light_client(network)
        .ok_or(SccpLcError::NotInstalled(network))?;
    is_aged_with_profiles(
        SccpChainProfilesV1::compiled(),
        view,
        &light_client,
        network,
        taira_now_ms,
    )
}

fn is_aged_with_profiles<V: SccpLcStateView + ?Sized>(
    profiles: &SccpChainProfilesV1,
    view: &V,
    light_client: &SccpLightClientV1,
    network: SccpNetworkV1,
    taira_now_ms: u64,
) -> Result<bool, SccpLcError> {
    match network {
        SccpNetworkV1::EthereumMainnet => Ok(ethereum::is_aged(
            &profiles.ethereum,
            light_client,
            taira_now_ms,
        )),
        SccpNetworkV1::BscMainnet => Ok(bsc::is_aged(light_client, taira_now_ms)),
        SccpNetworkV1::TronMainnet => Ok(tron::is_aged(&profiles.tron, light_client, taira_now_ms)),
        SccpNetworkV1::TonMainnet => Ok(ton::is_aged(
            &profiles.ton,
            view,
            light_client,
            taira_now_ms,
        )),
        SccpNetworkV1::SoraTaira => Err(SccpLcError::UnsupportedNetwork(network)),
    }
}

/// Taira time from which the newest signing set of the installed light client is stale (the
/// weak-subjectivity deadline Torii reports and wallets check before burning, §4.13.4, §7.2).
///
/// # Errors
///
/// Returns [`SccpLcError::NotInstalled`] or [`SccpLcError::UnsupportedNetwork`].
pub fn weak_subjectivity_deadline_ms<V: SccpLcStateView + ?Sized>(
    view: &V,
    network: SccpNetworkV1,
) -> Result<u64, SccpLcError> {
    let light_client = view
        .light_client(network)
        .ok_or(SccpLcError::NotInstalled(network))?;
    ensure_supported(network)?;
    let profiles = SccpChainProfilesV1::compiled();
    Ok(match network {
        SccpNetworkV1::BscMainnet => bsc::weak_subjectivity_deadline_ms(&light_client),
        SccpNetworkV1::TronMainnet => {
            tron::weak_subjectivity_deadline_ms(&profiles.tron, &light_client)
        }
        SccpNetworkV1::TonMainnet => {
            ton::weak_subjectivity_deadline_ms(&profiles.ton, view, &light_client)
        }
        _ => ethereum::weak_subjectivity_deadline_ms(&profiles.ethereum, &light_client),
    })
}

/// Check an enacted `InstallTrustedCheckpoint` (§4.14.3) and return the checkpoint to write.
///
/// The light client must be installed (frozen or aged is allowed: the action recovers burns),
/// the block hash and root must be nonzero, and a stored checkpoint at the same height must
/// describe the same block ([`state::same_checkpoint_block`]). The result has `origin: Parliament`, so an identical stored checkpoint is
/// upgraded to a permanent one. The weak-subjectivity bound does not apply.
///
/// # Errors
///
/// Returns [`SccpLcError::NotInstalled`], [`SccpLcError::MalformedFrame`] for a zero hash or
/// root, or [`SccpLcError::ConflictsWithStoredData`].
pub fn verify_trusted_checkpoint<V: SccpLcStateView + ?Sized>(
    view: &V,
    network: SccpNetworkV1,
    data: &SccpLcCheckpointDataV1,
    taira_now_ms: u64,
) -> Result<SccpLcCheckpointV1, SccpLcError> {
    if !network.is_external() {
        return Err(SccpLcError::UnsupportedNetwork(network));
    }
    view.light_client(network)
        .ok_or(SccpLcError::NotInstalled(network))?;
    if data.block_hash == [0; 32] || data.receipts_or_tx_root == [0; 32] {
        return Err(SccpLcError::MalformedFrame("trusted checkpoint"));
    }
    if let Some(stored) = view.checkpoint(network, data.source_height)
        && !state::same_checkpoint_block(&stored.data, data)
    {
        return Err(SccpLcError::ConflictsWithStoredData(
            SccpLcConflictV1::Checkpoint {
                source_height: data.source_height,
            },
        ));
    }
    Ok(SccpLcCheckpointV1 {
        data: *data,
        recorded_at_taira_ms: taira_now_ms,
        origin: SccpLcCheckpointOriginV1::Parliament,
    })
}

/// Work estimate of an advance, from its frame alone.
///
/// # Errors
///
/// Returns a frame error for an undecodable advance.
pub fn advance_work(
    network: SccpNetworkV1,
    advance: &SccpLcAdvanceBytesV1,
) -> Result<SccpVerifierWorkV1, SccpLcError> {
    ensure_supported(network)?;
    let decoded = SccpLcAdvanceV1::from_frame(advance.as_bytes())?;
    decoded.expect_network(network)?;
    Ok(match &decoded {
        SccpLcAdvanceV1::Ethereum(advance) => ethereum::advance_work(advance),
        SccpLcAdvanceV1::Bsc(advance) => bsc::advance_work(advance),
        SccpLcAdvanceV1::Tron(advance) => tron::advance_work(advance),
        SccpLcAdvanceV1::Ton(advance) => ton::advance_work(advance),
        SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Ethereum(segment),
        } => ethereum::segment_work(segment),
        SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Bsc(segment),
        } => bsc::segment_work(segment),
        SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Tron(segment),
        } => tron::segment_work(segment),
    }
    .with_frame_bytes(advance.len()))
}

/// Work estimate of an inbound or void proof, from its frame alone.
///
/// # Errors
///
/// Returns a frame error for an undecodable proof.
pub fn proof_work(
    network: SccpNetworkV1,
    proof: &SccpSourceProofBytesV1,
) -> Result<SccpVerifierWorkV1, SccpLcError> {
    ensure_supported(network)?;
    let decoded = SccpSourceProofV1::from_frame(proof.as_bytes())?;
    decoded.expect_network(network)?;
    Ok(match &decoded {
        SccpSourceProofV1::Ethereum(proof) => ethereum::proof_work(proof),
        SccpSourceProofV1::Bsc(proof) => bsc::proof_work(proof),
        SccpSourceProofV1::Tron(proof) => tron::proof_work(proof),
        SccpSourceProofV1::Ton(proof) => ton::proof_work(proof),
    }
    .with_frame_bytes(proof.len()))
}

/// Work estimate of equivocation evidence, from its frames alone.
///
/// # Errors
///
/// Returns a frame error for undecodable evidence.
pub fn evidence_work(
    network: SccpNetworkV1,
    a: &SccpLcEvidenceBytesV1,
    b: &SccpLcEvidenceBytesV1,
) -> Result<SccpVerifierWorkV1, SccpLcError> {
    ensure_supported(network)?;
    let mut total = SccpVerifierWorkV1::default();
    for evidence in [a, b] {
        let decoded = SccpLcEvidenceV1::from_frame(evidence.as_bytes())?;
        decoded.expect_network(network)?;
        let work = match &decoded {
            SccpLcEvidenceV1::Ethereum(record) => ethereum::evidence_work(record),
            SccpLcEvidenceV1::Bsc(record) => bsc::evidence_work(record),
            SccpLcEvidenceV1::Tron(record) => tron::evidence_work(record),
            SccpLcEvidenceV1::Ton(record) => ton::evidence_work(record),
        }
        .with_frame_bytes(evidence.len());
        total = total.checked_add(&work).unwrap_or(total);
    }
    Ok(total)
}

impl SccpVerifierWorkV1 {
    fn with_frame_bytes(mut self, len: usize) -> Self {
        self.proof_bytes = u64::try_from(len).unwrap_or(u64::MAX);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::light_client::state::SccpLcMemoryStateV1;

    #[test]
    fn work_sums_are_checked() {
        let one = SccpVerifierWorkV1 {
            proofs: 1,
            proof_bytes: 10,
            native_headers: 2,
            native_header_bytes: 20,
            ethereum_light_client_updates: 3,
            bls_vote_attestations: 7,
            secp256k1_recoveries: 4,
            ed25519_signature_checks: 5,
        };
        let two = one.checked_add(&one).expect("no overflow");
        assert_eq!(two.proofs, 2);
        assert_eq!(two.bls_vote_attestations, 14);
        assert_eq!(two.ed25519_signature_checks, 10);
        let full = SccpVerifierWorkV1 {
            proofs: u32::MAX,
            ..SccpVerifierWorkV1::default()
        };
        assert_eq!(full.checked_add(&one), None);
        assert_eq!(one.with_frame_bytes(77).proof_bytes, 77);
    }

    #[test]
    fn dispatch_rejects_missing_frozen_and_unsupported_light_clients() {
        let memory = SccpLcMemoryStateV1::new();
        let advance = SccpLcAdvanceBytesV1::new(vec![1, 2, 3]).expect("bounded");
        assert_eq!(
            apply_advance(&memory, SccpNetworkV1::EthereumMainnet, &advance, 0),
            Err(SccpLcError::NotInstalled(SccpNetworkV1::EthereumMainnet))
        );
        assert_eq!(
            is_aged(&memory, SccpNetworkV1::BscMainnet, 0),
            Err(SccpLcError::NotInstalled(SccpNetworkV1::BscMainnet))
        );
        assert!(matches!(
            advance_work(SccpNetworkV1::EthereumMainnet, &advance),
            Err(SccpLcError::MalformedFrame(_))
        ));
        let params = SccpLightClientParamsV1::defaults_for(SccpNetworkV1::EthereumMainnet)
            .expect("external");
        let bootstrap = SccpLcBootstrapV1 {
            network: SccpNetworkV1::BscMainnet,
            bytes: vec![1],
        };
        assert_eq!(
            verify_bootstrap(SccpNetworkV1::EthereumMainnet, &params, &bootstrap, 0),
            Err(SccpLcError::NetworkMismatch {
                expected: SccpNetworkV1::EthereumMainnet,
                found: SccpNetworkV1::BscMainnet,
            })
        );
        let mut bad = params;
        bad.max_proof_bytes = 0;
        assert!(matches!(
            verify_bootstrap(SccpNetworkV1::EthereumMainnet, &bad, &bootstrap, 0),
            Err(SccpLcError::InvalidParams(_))
        ));
        let oversized = SccpLcBootstrapV1 {
            network: SccpNetworkV1::EthereumMainnet,
            bytes: vec![0; SCCP_LC_BOOTSTRAP_MAX_BYTES_V1 + 1],
        };
        assert!(matches!(
            verify_bootstrap(SccpNetworkV1::EthereumMainnet, &params, &oversized, 0),
            Err(SccpLcError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn trusted_checkpoints_are_parliament_origin_and_conflict_checked() {
        use iroha_data_model::sccp::light_client::{SccpLcHeadV1, SccpLcPointV1};
        let network = SccpNetworkV1::EthereumMainnet;
        let data = SccpLcCheckpointDataV1 {
            source_height: 10,
            block_hash: [1; 32],
            state_root: None,
            receipts_or_tx_root: [2; 32],
            source_time_ms: 3,
        };
        let mut memory = SccpLcMemoryStateV1::new();
        assert_eq!(
            verify_trusted_checkpoint(&memory, network, &data, 5),
            Err(SccpLcError::NotInstalled(network))
        );
        let params = SccpLightClientParamsV1::defaults_for(network).expect("external");
        let head = SccpLcHeadV1 {
            latest_set_id: 1,
            latest_finalized: SccpLcPointV1 {
                source_height: 10,
                block_hash: [1; 32],
                source_time_ms: 3,
            },
            last_progress_taira_ms: 0,
        };
        memory.install(
            network,
            &state::SccpLcInitialStateV1 {
                light_client: SccpLightClientV1 {
                    params,
                    head,
                    frozen: None,
                    state_hash: state::state_hash(&params, &head, None),
                },
                purge: SccpLcPurgeV1::DiscardUnvetted,
                superseded_sets: Vec::new(),
                sets: Vec::new(),
                checkpoints: Vec::new(),
            },
        );
        let installed = verify_trusted_checkpoint(&memory, network, &data, 5).expect("installs");
        assert_eq!(installed.origin, SccpLcCheckpointOriginV1::Parliament);
        assert_eq!(installed.recorded_at_taira_ms, 5);
        memory.record_checkpoints(network, &[installed]);
        assert!(verify_trusted_checkpoint(&memory, network, &data, 6).is_ok());
        let mut conflicting = data;
        conflicting.block_hash = [9; 32];
        let mut other_root = data;
        other_root.receipts_or_tx_root = [8; 32];
        for conflicting in [conflicting, other_root] {
            assert_eq!(
                verify_trusted_checkpoint(&memory, network, &conflicting, 6),
                Err(SccpLcError::ConflictsWithStoredData(
                    SccpLcConflictV1::Checkpoint { source_height: 10 }
                ))
            );
        }
        let mut zero = data;
        zero.block_hash = [0; 32];
        assert_eq!(
            verify_trusted_checkpoint(&memory, network, &zero, 6),
            Err(SccpLcError::MalformedFrame("trusted checkpoint"))
        );
        assert_eq!(
            verify_trusted_checkpoint(&memory, SccpNetworkV1::SoraTaira, &data, 6),
            Err(SccpLcError::UnsupportedNetwork(SccpNetworkV1::SoraTaira))
        );
        let deadline = weak_subjectivity_deadline_ms(&memory, network).expect("installed");
        assert_eq!(
            deadline,
            profile::ETHEREUM_MAINNET.period_end_ms(1).expect("time") + params.ws_bound_ms
        );
        assert_eq!(is_aged(&memory, network, deadline - 1), Ok(false));
        assert_eq!(is_aged(&memory, network, deadline), Ok(true));
    }

    #[test]
    fn errors_render_the_equivocation_pointer() {
        let error =
            SccpLcError::ConflictsWithStoredData(SccpLcConflictV1::Checkpoint { source_height: 9 });
        assert!(
            error
                .to_string()
                .contains("ReportSccpLightClientEquivocationV1")
        );
        assert!(
            SccpLcError::ConflictsWithStoredData(SccpLcConflictV1::ConsensusSet { set_id: 3 })
                .to_string()
                .contains("consensus set 3")
        );
        assert!(
            SccpLcError::UnsupportedNetwork(SccpNetworkV1::TonMainnet)
                .to_string()
                .contains("ton-mainnet")
        );
        let unexpected = SccpLcError::UnexpectedLightClientState {
            network: SccpNetworkV1::EthereumMainnet,
            expected: SccpLcInitExpectationV1::Unusable,
        };
        assert!(unexpected.to_string().contains("frozen or aged"));
    }
}
