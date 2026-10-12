//! Canonical global epoch authority, lag-two chain parameters and atomic boundary application.
//!
//! Genesis independently authenticates the initial complete authority from its signed body.
//! Ordinary heights retain that authority and its original ordered proofs. Registering a
//! candidate never changes voting membership. At boundary B, only the current quorum's
//! certified result authorizes B+1; pending slots cannot supply guessed authority.
//!
//! The pristine B-prestate freezes target activation/readiness and the E+2 election. The
//! original overlay retains those obligations through transaction rollback and output sealing.
//! Its canonical result contains the complete current context, boundary outcome and successor
//! slots. Runtime graph owners share retained original-pool allocations; snapshot DTOs are
//! quarantined until explicit admission and authenticated restore validation.
//!
//! Chain parameters retain their lag-two rule. Each global committee has exactly 3f+1 seats,
//! 1 <= f <= 10, and exact 2f+1 equal votes. Noncommittee-sized candidate pools are eligible for
//! deterministic selection, never automatic voting authority.
//!
//! Native proposals transport their signed control witness and exact beacon pulse. Missing
//! authenticated pulse work fails closed; follower validation never depends on local aggregation.

use std::collections::BTreeMap;

use iroha_crypto::Algorithm;
use iroha_data_model::parameter::system::{SumeragiParameter, SumeragiParameters};
use iroha_genesis::GenesisBlock;
use iroha_model_base::peer::PeerId;
use iroha_sumeragi::types::{Committee, PublicKey};

/// The schedule lag: the state after `h` schedules height `h + LAG` (§10.1).
pub const LAG: u64 = 2;

pub use iroha_data_model::sumeragi_finality::{
    CHAIN_TRANSPORT_FRAME_LIMIT, ChainParamsRecord, GenesisCommitteeError, ScheduleError,
    consensus_key, genesis_registrations, global_committee,
};

mod epoch_graph;
mod execution;
pub(crate) use execution::authenticate_successor_context;
mod retained;
pub(crate) use epoch_graph::NativeExecutionInputs;
pub use epoch_graph::{
    ConsensusSchedule, ScheduleOutcome, ScheduledConfig, ScheduledSlot, core_epoch,
};
pub(crate) use execution::ScheduleStep;
pub use retained::RetainedConsensusSchedule;

/// The peer of a core consensus key (inverse of [`consensus_key`]).
///
/// # Errors
/// [`ScheduleError::NotBlsNormal`] if the bytes are not a BLS-normal public key.
pub fn peer_of(key: &PublicKey) -> Result<PeerId, ScheduleError> {
    iroha_crypto::PublicKey::from_bytes(Algorithm::BlsNormal, key.as_bytes())
        .map(PeerId::new)
        .map_err(|_| ScheduleError::NotBlsNormal(format!("{key:?}")))
}

/// Peers in the core's canonical committee order, deduplicated.
///
/// # Errors
/// A peer without a BLS-normal key.
pub fn canonical_committee(
    peers: impl IntoIterator<Item = PeerId>,
) -> Result<Vec<PeerId>, ScheduleError> {
    let ordered = peers
        .into_iter()
        .map(|peer| Ok((consensus_key(&peer)?, peer)))
        .collect::<Result<BTreeMap<_, _>, ScheduleError>>()?;
    Ok(ordered.into_values().collect())
}

/// Resolve the exact authenticated proposal-height committee in canonical order.
///
/// # Errors
/// The retained schedule, epoch authority, proofs, or parameters are invalid or unavailable.
pub fn scheduled_committee(
    world: &impl crate::state::WorldReadOnly,
    height: u64,
) -> Result<Vec<PeerId>, ScheduleError> {
    let schedule = world.consensus_schedule();
    if !schedule.is_well_formed() {
        return Err(ScheduleError::Malformed);
    }
    let config = schedule.ready(height)?;
    config.height_config()?;
    Ok(config
        .epoch
        .committee
        .iter()
        .map(|member| member.validator.clone())
        .collect())
}

/// The complete original proofs for the authenticated scheduled committee. Mutable peer
/// registrations never supply, replace, or remove a retained voting credential.
///
/// # Errors
/// The schedule has invalid geometry, order, proof alignment, proofs, or parameters.
pub fn committee_pops(config: &ScheduledConfig) -> Result<Vec<(PeerId, Vec<u8>)>, ScheduleError> {
    config.height_config()?;
    Ok(config
        .epoch
        .committee
        .iter()
        .map(|member| (member.validator.clone(), member.proof_of_possession.clone()))
        .collect())
}

impl From<super::epoch_election::BoundaryCaptureError> for ScheduleError {
    fn from(error: super::epoch_election::BoundaryCaptureError) -> Self {
        match error {
            super::epoch_election::BoundaryCaptureError::Invalid(message) => Self::Epoch(message),
            super::epoch_election::BoundaryCaptureError::Admission(error) => Self::Admission(error),
            super::epoch_election::BoundaryCaptureError::Allocator { requested_bytes } => {
                Self::Allocator { requested_bytes }
            }
        }
    }
}

/// Check a `SetParameter` of a Sumeragi parameter against the current parameters: the demotion
/// window only in the genesis block; after genesis, a chain parameter change must leave chain
/// parameters that pass [`ChainParamsRecord::validate`]. (In genesis the parameters are checked
/// together when the genesis schedule is installed, so their order does not matter.) The change
/// takes effect at `h + 2` through the schedule. While SCCP exists, an epoch-length
/// change must also preserve its one-hour floor, including after genesis initialization.
///
/// # Errors
/// [`ScheduleError::GenesisOnly`], [`ScheduleError::Params`], or an SCCP epoch-floor
/// violation as [`ScheduleError::Epoch`].
pub fn validate_parameter_change(
    current: &SumeragiParameters,
    change: &SumeragiParameter,
    is_genesis: bool,
    sccp_exists: bool,
) -> Result<(), ScheduleError> {
    if sccp_exists && let SumeragiParameter::EpochLengthBlocks(blocks) = change {
        crate::smartcontracts::isi::sccp::params::validate_epoch(
            blocks.get(),
            current.block_cadence_ms.get(),
        )
        .map_err(|error| ScheduleError::Epoch(error.to_string()))?;
    }
    if is_genesis {
        return Ok(());
    }
    if change.is_genesis_only() {
        return Err(ScheduleError::GenesisOnly);
    }
    if matches!(change, SumeragiParameter::MaxClockDriftMs(_)) {
        return Ok(());
    }
    let mut candidate = current.clone();
    match *change {
        SumeragiParameter::PayloadRetryIntervalMs(value) => {
            candidate.payload_retry_interval_ms = value
        }
        SumeragiParameter::ExecBudgetMs(value) => candidate.exec_budget_ms = value,
        SumeragiParameter::ApplyBudgetMs(value) => candidate.apply_budget_ms = value,
        SumeragiParameter::MaxBlockBytes(value) => candidate.max_block_bytes = value,
        SumeragiParameter::EpochLengthBlocks(value) => candidate.epoch_length_blocks = value,
        SumeragiParameter::MaxClockDriftMs(_) | SumeragiParameter::DemotionWindow(_) => {}
    }
    ChainParamsRecord::from_parameters(&candidate)
        .validate()
        .map_err(ScheduleError::Params)
}

/// The validators signed into genesis: every `RegisterPeerWithPop` of the genesis body with its
/// exact proof of possession, which is verified here (`specs/sumeragi.md` §10.3: a key enters
/// the schedule only with a valid PoP). Lane-committee registrations are not validators.
///
/// # Errors
/// A non-instruction transaction, a non-BLS-normal key, an invalid PoP or a duplicate.
pub fn genesis_validators(
    genesis: &GenesisBlock,
) -> Result<BTreeMap<PeerId, Vec<u8>>, GenesisCommitteeError> {
    let validators = genesis_registrations(&genesis.0)?;
    for (peer, pop) in &validators {
        iroha_crypto::bls_normal_pop_verify(peer.public_key(), pop)
            .map_err(|_| GenesisCommitteeError::InvalidProofOfPossession(peer.to_string()))?;
    }
    Ok(validators)
}

/// The genesis committee `C_{g+1} = C_{g+2}` as the core sees it.
///
/// # Errors
/// See [`genesis_validators`]; also a committee outside the exact bounded `3f + 1` geometry.
pub fn genesis_committee(genesis: &GenesisBlock) -> Result<Committee, GenesisCommitteeError> {
    let keys = genesis_validators(genesis)?
        .into_keys()
        .map(|peer| {
            consensus_key(&peer)
                .map_err(|_| GenesisCommitteeError::NonBlsValidator(peer.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    global_committee(keys).map_err(GenesisCommitteeError::Committee)
}

#[cfg(test)]
mod tests;
