//! The Sumeragi instance of a node (`specs/sumeragi.md` §12): startup, the production
//! backends and the driver.
//!
//! [`start`] applies (fresh chain) or re-executes (restart) genesis, replays the blocks Kura
//! holds through the executor, installs the safety records of the node's keys, assembles the
//! core's `Init` and spawns the driver over:
//! the transport `N` (P2P in the node, in-memory in tests), the file record and body stores,
//! Kura, the system clock and the State executor.

mod configuration;
pub use configuration::consensus_configuration_fingerprint;

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use iroha_config::parameters::actual::SumeragiLocalOverrides;

use iroha_crypto::{Hash, KeyPair};
use iroha_data_model::{
    account::AccountId,
    block::SignedBlock,
    parameter::system::ConsensusMode,
    sumeragi::{SumeragiFootprint, SumeragiHaltReason, SumeragiStatus},
};
use iroha_model_base::peer::PeerId;
/// The Sumeragi wire protocol version peers bind in the handshake.
pub use iroha_sumeragi::message::PROTOCOL_VERSION;
#[cfg(test)]
use iroha_sumeragi::preimage::{InstanceKind, instance_id};
use iroha_sumeragi::{
    api::{CoreStatus, HaltReason, LocalParams},
    types::{Hash32, PublicKey},
};

use super::{
    block_store::{KuraBlockStore, Staging},
    bodies::{BodyLimits, FileBodyStore},
    crypto::{BlsCrypto, KeyPairSigner, core_key, iroha_key},
    driver::{
        Driver, DriverConfig, DriverHandle, DriverStart, RunningDriver, SharedCrypto,
        assemble_init,
        traits::{BlockStore, Net, Observer, SystemClock},
    },
    executor::{ExecutorContext, StateExecutor},
    net::{FrameCaps, P2pNet, SumeragiIngress, spawn_ingress},
    records::{FileRecordStore, FreshKeyAssertion, install},
    schedule,
    startup::{self, GENESIS_HEIGHT, GenesisTip, StartupError},
};
#[cfg(feature = "telemetry")]
use crate::sumeragi::metrics::{InstanceMetrics, MetricsInstance};

use crate::{
    EventsSender, IrohaNetwork,
    queue::Queue,
    state::{State, StateReadOnly, WorldReadOnly},
};

#[cfg(test)]
use crate::kura::Kura;

/// Where the instance keeps its files, and the operator's startup choices.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Safety records (one file per instance and key; never backed up or restored).
    pub records_dir: PathBuf,
    /// The installation log, outside `records_dir`.
    pub installation_log: PathBuf,
    /// Root of the body store (bodies of accepted, unapplied blocks).
    pub bodies_dir: PathBuf,
    /// Overrides of the core's local parameters (the rest are the defaults for the committee
    /// size).
    pub local: SumeragiLocalOverrides,
    /// The operator asserts, at first boot, that the node's keys never signed for this chain
    /// (the one-shot `--sumeragi-assert-fresh-key` flag, §7.4).
    pub assert_fresh_key: bool,
    /// Retired consensus keys (restored, never signing).
    pub retired_keys: Vec<iroha_crypto::PublicKey>,
}

/// What [`prepare`] needs: the original State owns its store, pool and configured chain identity.
pub struct PrepareInputs {
    /// The node's state (empty: it is rebuilt from genesis and its original Kura).
    pub state: Arc<State>,
    /// Pipeline and state events.
    pub events: EventsSender,
    /// The signed genesis block of a fresh chain (ignored when Kura already holds genesis).
    pub genesis: Option<SignedBlock>,
    /// The genesis account.
    pub genesis_account: AccountId,
    /// The consensus mode.
    pub consensus_mode: ConsensusMode,
}

/// What [`Prepared::start`] adds: the queue, the transport, the node's key and files.
pub struct StartInputs<N> {
    /// The transport.
    pub net: Arc<N>,
    /// The transaction queue. One successful native startup owns it for its lifetime;
    /// authenticated restart requires a fresh Queue, not a retired binding.
    pub queue: Arc<Queue>,
    /// The node's consensus key pair (BLS normal).
    pub key_pair: KeyPair,
    /// Runtime-only custody for current and pending beacon sessions; never serialized.
    pub beacon_signer: Option<Arc<dyn crate::beacon::GlobalThresholdBeaconPartialSignerV1>>,
    /// Files and operator choices.
    pub config: NodeConfig,
    /// Reports of the instance.
    pub observer: Arc<dyn Observer>,
    /// Driver limits.
    pub driver: DriverConfig,
}

/// Everything [`start`] needs from the node.
pub struct NodeInputs<N> {
    /// The node's state (empty before genesis).
    pub state: Arc<State>,
    /// The transaction queue.
    pub queue: Arc<Queue>,
    /// Pipeline and state events.
    pub events: EventsSender,
    /// The transport.
    pub net: Arc<N>,
    /// The node's consensus key pair (BLS normal).
    pub key_pair: KeyPair,
    /// The signed genesis block of a fresh chain (ignored when Kura already holds genesis).
    pub genesis: Option<SignedBlock>,
    /// The genesis account.
    pub genesis_account: AccountId,
    /// The consensus mode.
    pub consensus_mode: ConsensusMode,
    /// Runtime-only custody for current and pending beacon sessions; never serialized.
    pub beacon_signer: Option<Arc<dyn crate::beacon::GlobalThresholdBeaconPartialSignerV1>>,
    /// Files and operator choices.
    pub config: NodeConfig,
    /// Reports of the instance.
    pub observer: Arc<dyn Observer>,
    /// Driver limits.
    pub driver: DriverConfig,
}

/// A running Sumeragi instance.
pub struct RunningNode {
    state: Arc<State>,
    config_fingerprint: iroha_crypto::Hash,
    beacon_readiness: super::epoch_beacon::producer::NativeBeaconReadiness,
    startup_recovery: crate::snapshot::StartupRecovery,
    // Retire notification first; permanent Queue exclusion remains through all joins.
    queue_wake: crate::queue::SumeragiQueueRegistration,
    /// The driver.
    pub driver: RunningDriver,
    /// The instance id (`I`).
    pub instance: Hash32,
    /// The instance's cryptography.
    pub crypto: Arc<BlsCrypto>,
    identity: NodeIdentity,
    /// The node's lane instances.
    pub lanes: super::lanes::runner::LaneRunner,
    /// Routes inbound frames to the node's instances.
    pub ingress: Arc<SumeragiIngress>,
}

impl RunningNode {
    /// The handle Torii, the transport and the node's services use.
    pub fn handle(&self) -> NodeHandle {
        NodeHandle {
            driver: self.driver.handle(),
            instance: self.instance,
            identity: self.identity.clone(),
            lanes: self.lanes.handle(),
            state: Arc::clone(&self.state),
            config_fingerprint: self.config_fingerprint,
            beacon_readiness: self.beacon_readiness.clone(),
            startup_recovery: self.startup_recovery.clone(),
        }
    }
}

/// A cheap, cloneable handle of the node's running instance.
#[derive(Clone)]
pub struct NodeHandle {
    driver: DriverHandle,
    instance: Hash32,
    identity: NodeIdentity,
    lanes: super::lanes::runner::LaneRunnerHandle,
    state: Arc<State>,
    config_fingerprint: iroha_crypto::Hash,
    beacon_readiness: super::epoch_beacon::producer::NativeBeaconReadiness,
    startup_recovery: crate::snapshot::StartupRecovery,
}

/// Immutable identity and resolved configuration of the running consensus instance.
#[derive(Clone, Debug)]
pub struct NodeIdentity {
    /// Consensus peer identity installed at startup.
    pub node_id: PeerId,
    /// Canonical fingerprint of the effective local and driver settings.
    pub config_fingerprint: Hash,
}

impl core::fmt::Debug for NodeHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeHandle")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

impl NodeHandle {
    /// Successful authenticated replay and startup, revoked on a native worker failure or halt.
    /// Snapshot maintenance must retain this gate and check it before every storage operation.
    pub fn startup_recovery(&self) -> crate::snapshot::StartupRecovery {
        self.startup_recovery.clone()
    }

    /// Identity captured from the actual startup inputs, never from HTTP parameters.
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// The instance id (`I`).
    pub fn instance(&self) -> Hash32 {
        self.instance
    }

    /// The core's latest diagnostics (`None` before the core started).
    pub fn status(&self) -> Option<CoreStatus> {
        self.driver.status()
    }

    /// Why the instance halted, if it did (a stopped worker stops it too).
    pub fn halted(&self) -> Option<HaltReason> {
        self.driver.halted()
    }

    /// The status the node serves (`/v1/sumeragi/status`; `None` before the core started).
    pub fn status_dto(&self) -> Option<SumeragiStatus> {
        let status = self.status()?;
        status_dto(
            &self.driver,
            self.config_fingerprint,
            self.beacon_observation(&status).map(|(horizon, _)| horizon),
        )
    }

    /// Every lane of the committed state with the node's instance of it
    /// (`/v1/sumeragi/lanes`, `specs/sumeragi_lanes.md` §8).
    pub fn lane_statuses(&self) -> Vec<iroha_data_model::sumeragi_lanes::SumeragiLaneStatus> {
        self.lanes.statuses()
    }
}

/// The served status of the instance `driver` runs (`None` before its core started).
pub(crate) fn status_dto(
    driver: &DriverHandle,
    config_fingerprint: Hash,
    beacon_horizon: Option<iroha_data_model::sumeragi::BeaconHorizonStatusV1>,
) -> Option<SumeragiStatus> {
    let status = driver.status()?;
    let key = |key: &PublicKey| iroha_key(key).ok();
    let widen = |count: usize| u64::try_from(count).unwrap_or(u64::MAX);
    let footprint = &status.footprint;
    Some(SumeragiStatus {
        protocol_version: PROTOCOL_VERSION,
        config_fingerprint,
        beacon_horizon,
        instance: status.instance.0,
        height: status.height,
        view: status.view,
        stage: status.stage,
        leader: status.leader.as_ref().and_then(key),
        proxy_tail: status.proxy_tail.as_ref().and_then(key),
        high_qc_view: status.high_qc_view,
        level: status.level,
        start_level: status.start_level,
        t_retx_ms: status.t_retx,
        committed_height: status.committed_height,
        applied_height: status.applied_height,
        awaiting: status.awaiting,
        signer: status.signer.as_ref().and_then(key),
        unanchored: status.unanchored,
        abstaining: status.abstaining,
        halted: driver.halted().map(halt_reason_dto),
        footprint: SumeragiFootprint {
            votes: widen(footprint.votes),
            timeouts: widen(footprint.timeouts),
            blocks: widen(footprint.blocks),
            exec_entries: widen(footprint.exec_entries),
            wants: widen(footprint.wants),
            pending_apply: widen(footprint.pending_apply),
            sync_entries: widen(footprint.sync_entries),
            sync_bytes: widen(footprint.sync_bytes),
            peers: widen(footprint.peers),
            recent_headers: widen(footprint.recent_headers),
            configs: widen(footprint.configs),
            cert_cache: widen(footprint.cert_cache),
            evidence_keys: widen(footprint.evidence_keys),
            probe: widen(footprint.probe),
        },
    })
}

/// The served form of a core halt reason (`/v1/sumeragi/status`, `sumeragi_halted{reason}`).
pub(crate) fn halt_reason_dto(reason: HaltReason) -> SumeragiHaltReason {
    match reason {
        HaltReason::SafetyRecordCorrupt => SumeragiHaltReason::SafetyRecordCorrupt,
        HaltReason::SafetyRecordInconsistent => SumeragiHaltReason::SafetyRecordInconsistent,
        HaltReason::SafetyViolation { height } => SumeragiHaltReason::SafetyViolation(height),
        HaltReason::ApplyDiverged { height } => SumeragiHaltReason::ApplyDiverged(height),
        HaltReason::PublicationRecoveryRequired { height } => {
            SumeragiHaltReason::PublicationRecoveryRequired(height)
        }
        HaltReason::DriverAnomaly => SumeragiHaltReason::DriverAnomaly,
    }
}

impl NodeHandle {
    /// The instance halted or stopped: only a restart recovers the node's consensus.
    pub fn restart_required(&self) -> bool {
        // A clean shutdown retains diagnostics without recording a halt. Once
        // initialized, a non-running driver cannot serve live attestations.
        self.halted().is_some() || (self.status().is_some() && !self.driver.ready())
    }

    /// The core started, has not halted, and the instance runs.
    /// A beacon refresh leaves this immediate diagnostic unavailable until its result is ready.
    pub fn ready(&self) -> bool {
        self.ready_with_deadline(None)
    }

    /// Wait for current beacon readiness until the caller's original monotonic deadline.
    /// Expiry fails closed; source generation, core height, applied height and custody remain
    /// mandatory. Call this bounded blocking observation only from a blocking worker.
    pub fn ready_until(&self, deadline: Instant) -> bool {
        self.ready_with_deadline(Some(deadline))
    }

    fn ready_with_deadline(&self, deadline: Option<Instant>) -> bool {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return false;
        }
        let ready = self.driver.ready()
            && self.status().is_some_and(|status| {
                // Observers have no signing obligation and the core does not drive their
                // partial producer. An unanchored local validator cannot use this exemption.
                (status.abstaining && !status.unanchored)
                    || self
                        .beacon_observation_with_deadline(&status, deadline)
                        .is_some_and(|(_, ready)| ready)
            });
        ready && deadline.is_none_or(|deadline| Instant::now() < deadline)
    }

    fn beacon_observation(
        &self,
        status: &CoreStatus,
    ) -> Option<(iroha_data_model::sumeragi::BeaconHorizonStatusV1, bool)> {
        self.beacon_observation_with_deadline(status, None)
    }

    fn beacon_observation_with_deadline(
        &self,
        status: &CoreStatus,
        deadline: Option<Instant>,
    ) -> Option<(iroha_data_model::sumeragi::BeaconHorizonStatusV1, bool)> {
        let generation = self.state.state_view_generation();
        let observed = match deadline {
            Some(deadline) => self.beacon_readiness.read_until(
                generation,
                status.height,
                status.applied_height,
                deadline,
            ),
            None => self
                .beacon_readiness
                .read(generation, status.height, status.applied_height),
        }?;
        (self.state.state_view_generation() == generation).then_some(observed)
    }

    /// An includable transaction entered the queue (the leader's `PayloadReady`).
    pub fn transactions_available(&self) {
        self.driver.transactions_available();
        self.lanes.transactions_available();
    }

    /// The driver's handle (the transport's frame sink).
    pub fn driver(&self) -> &DriverHandle {
        &self.driver
    }
}

/// The root instance id (`I`, §1.8) selected by authenticated signed genesis and chain id.
/// Peers bind this exact global or dataspace instance in their handshake.
///
/// # Errors
/// Missing, duplicate or malformed signed scope metadata. No global fallback is permitted.
pub fn root_instance(
    genesis: &SignedBlock,
    chain_id: &str,
) -> Result<Hash32, crate::execution_attempt::ExecutionAttemptError<String>> {
    iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(genesis)
        .map_err(|error| {
            crate::execution_attempt::genesis_read_attempt_error(error, |error| error.to_string())
        })?
        .sumeragi_context
        .root_scope
        .instance_id(
            &BlsCrypto::new(),
            iroha_data_model::NetworkId::from_genesis_hash(genesis.hash()),
            chain_id,
        )
        .map_err(|error| {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error.to_string())
        })
}

/// The original failed startup replay operation, retaining local refusal ownership.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// Reading or restoring the original committed body did not finish.
    #[error(transparent)]
    Read(crate::execution_attempt::ExecutionAttemptError<std::io::Error>),
    /// The committed height has no body in its authoritative store.
    #[error("committed body missing")]
    MissingBody,
    /// The serialized original execution or completion acknowledgement did not finish.
    #[error(transparent)]
    Execution(super::driver::traits::PublicationError),
    /// The final cold World-root check could not acquire its original storage or rejected content.
    #[error(transparent)]
    StateRoot(crate::state::WorldStateVerificationError),
}

/// Why the instance could not start.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// Startup could not complete under the original local capacity owner.
    #[error("native availability startup deferred: {0}")]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// Genesis or replay failed.
    #[error(transparent)]
    Startup(#[from] StartupError),
    /// No genesis: Kura holds none and none was supplied.
    #[error("no genesis block: Kura holds none and none was supplied")]
    NoGenesis,
    /// The node's key is not BLS normal.
    #[error("the consensus key is not BLS normal: {0}")]
    Key(String),
    /// A block Kura holds does not replay.
    #[error("replay of height {height} failed: {reason}")]
    Replay {
        /// Height.
        height: u64,
        /// Original read, execution, or authenticated State failure.
        #[source]
        reason: ReplayError,
    },
    /// The exact committed startup prefix could not be read under its original owner.
    #[error("startup history: {0}")]
    History(
        #[from] crate::execution_attempt::ExecutionAttemptError<super::driver::StartupHistoryError>,
    ),
    /// Records, bodies or the schedule could not be loaded.
    #[error("startup input: {0}")]
    Input(String),
    /// The native execution worker thread could not start.
    #[error("executor thread: {0}")]
    ExecutorStart(#[source] std::io::Error),
    /// The serialized worker retained an unfinished original control attachment.
    #[error("native control attachment: {0}")]
    ControlAttachment(#[from] super::driver::traits::PublicationError),
    /// The lane runner thread could not start.
    #[error("lane runner thread: {0}")]
    LaneRunner(#[source] std::io::Error),
    /// The driver did not start under its original configuration and resource owners.
    #[error("driver: {0}")]
    Driver(#[from] super::driver::DriverError),
    /// The retained P2P actor refused the original FIFO subscriptions.
    #[error(transparent)]
    Subscription(#[from] super::net::SubscribeError),
    /// The original inbound FIFO thread could not start.
    #[error("ingress thread: {0}")]
    IngressThread(#[source] std::io::Error),
}

fn node_policy_error(error: crate::execution_attempt::ExecutionAttemptError<String>) -> NodeError {
    match error {
        crate::execution_attempt::ExecutionAttemptError::Rejected(message) => {
            NodeError::Input(message)
        }
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
            NodeError::Deferred(reason)
        }
    }
}

/// Start the node's Sumeragi instance: [`prepare`], then [`Prepared::start`].
///
/// # Errors
/// See [`NodeError`].
pub fn start<N: Net + 'static>(inputs: NodeInputs<N>) -> Result<RunningNode, NodeError> {
    let NodeInputs {
        state,
        queue,
        events,
        net,
        key_pair,
        genesis,
        genesis_account,
        consensus_mode,
        beacon_signer,
        config,
        observer,
        driver,
    } = inputs;
    prepare(PrepareInputs {
        state,
        events,
        genesis,
        genesis_account,
        consensus_mode,
    })?
    .start(StartInputs {
        net,
        queue,
        key_pair,
        beacon_signer,
        config,
        observer,
        driver,
    })
}

/// The instance with its state rebuilt, ready to start.
pub struct Prepared {
    state: Arc<State>,
    crypto: Arc<BlsCrypto>,
    instance: Hash32,
    tip: GenesisTip,
    /// Original signed and independently executed genesis epoch for fresh safety records.
    genesis_epoch: iroha_sumeragi::types::EpochId,
    config_fingerprint: iroha_crypto::Hash,
    blocks: Arc<KuraBlockStore>,
    executor: StateExecutor,
    applied_watch: Arc<crate::sumeragi::lanes::global::AppliedWatch>,
    lane_stores: Arc<crate::sumeragi::lanes::registry::LaneStores>,
    chain_id: String,
}

impl core::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Prepared")
            .field("instance", &self.instance)
            .field("tip", &self.tip)
            .finish_non_exhaustive()
    }
}

/// Rebuild the state (§12.1): apply the supplied genesis to the empty state (fresh chain) or
/// re-execute the stored one, then replay every block Kura holds, each checked against its
/// certified result. Nothing is sent or signed.
///
/// # Errors
/// See [`NodeError`].
pub fn prepare(inputs: PrepareInputs) -> Result<Prepared, NodeError> {
    let PrepareInputs {
        state,
        events,
        genesis,
        genesis_account,
        consensus_mode,
    } = inputs;
    // Storage and configured consensus identity have one original owner. Accepting either
    // independently can publish genesis into State while routing replay to a foreign store.
    #[cfg(not(all(test, sumeragi_core_mutation = "HC21")))]
    let kura = state.kura_handle();
    #[cfg(all(test, sumeragi_core_mutation = "HC21"))]
    let kura = Kura::blank_kura_for_testing();
    let chain_id = state.chain_id_ref().to_string();
    // Local snapshot signatures authenticate exports, not full-World execution. Native R
    // commits the complete World state (Appendix E, E51), but restoring a snapshot against it
    // is not implemented (TODO(S9)); Strict startup therefore rebuilds original State from the
    // signed genesis and certified journal before maintenance is authorized.
    if startup::applied_height(&state) != 0 {
        return Err(NodeError::Input(
            "the state must be empty: Sumeragi rebuilds it from genesis and Kura".into(),
        ));
    }
    // Genesis: re-execute the stored one, or apply the supplied one.
    let (tip, config_fingerprint, instance): (GenesisTip, iroha_crypto::Hash, Hash32) =
        match startup::stored_genesis(&state)? {
            Some((block, certificate, stored)) => {
                if let Some(supplied) = &genesis
                    && startup::core_hash_of(supplied) != stored.block_hash
                {
                    return Err(NodeError::Input(
                        "the supplied genesis differs from the one Kura holds".into(),
                    ));
                }
                let fingerprint =
                    consensus_configuration_fingerprint(&block).map_err(node_policy_error)?;
                let instance = root_instance(&block, &chain_id).map_err(node_policy_error)?;
                (
                    startup::apply_genesis(
                        &state,
                        block,
                        &genesis_account,
                        consensus_mode,
                        Some(&certificate),
                    )?,
                    fingerprint,
                    instance,
                )
            }
            None => {
                let genesis = genesis.ok_or(NodeError::NoGenesis)?;
                let fingerprint =
                    consensus_configuration_fingerprint(&genesis).map_err(node_policy_error)?;
                let instance = root_instance(&genesis, &chain_id).map_err(node_policy_error)?;
                (
                    startup::apply_genesis(
                        &state,
                        genesis,
                        &genesis_account,
                        consensus_mode,
                        None,
                    )?,
                    fingerprint,
                    instance,
                )
            }
        };
    let genesis_epoch = {
        let view = state.view();
        let config = view
            .world()
            .consensus_schedule()
            .ready(GENESIS_HEIGHT)
            .map_err(|error| NodeError::Input(error.to_string()))?;
        schedule::core_epoch(&config.epoch)
            .map_err(|error| NodeError::Input(error.to_string()))?
            .id
    };
    let crypto = Arc::new(BlsCrypto::new());
    let shared: SharedCrypto = crypto.clone();
    let availability = Arc::new(
        super::runtime_availability::NativeGlobalAvailability::new(
            Arc::clone(&state),
            instance,
            Arc::clone(&crypto),
        )
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                NodeError::Deferred(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                NodeError::Input(error.to_string())
            }
        })?,
    );
    let lane_authorities = Arc::new(
        super::runtime_availability::NativeLaneStoreAuthorities::new(
            Arc::clone(&state),
            Arc::clone(&crypto),
        ),
    );
    let staging = Staging::new();
    let blocks = Arc::new(KuraBlockStore::new(
        Arc::clone(&kura),
        Arc::clone(&shared),
        GENESIS_HEIGHT,
        staging.clone(),
        state.ivm_execution_budget(),
        availability,
    ));
    let applied_watch = Arc::new(crate::sumeragi::lanes::global::AppliedWatch::new(
        GENESIS_HEIGHT,
        state.view().latest_block_hash(),
    ));
    // Lane blocks live next to Kura; replay merges from them as live execution does.
    let lane_stores = Arc::new(crate::sumeragi::lanes::registry::LaneStores::new(
        kura.store_root().join("lanes"),
        *state.network_id_ref(),
        chain_id.clone(),
        shared,
        state.ivm_execution_budget(),
        lane_authorities,
    ));
    let mut executor = StateExecutor::spawn(ExecutorContext {
        state: Arc::clone(&state),
        native_context_archive: Arc::new(
            crate::query::native_context_archive::NativeContextArchive::open(
                state.kura(),
                state.ivm_execution_budget(),
                state.kura().native_context_archive_max_bytes(),
            )
            .map_err(|error| NodeError::Input(error.to_string()))?,
        ),
        queue: None,
        staging,
        events,
        genesis_account,
        consensus_mode,
        applied: (GENESIS_HEIGHT, tip.block_hash),
        crypto: Some(Arc::clone(&crypto)),
        applied_watch: Arc::clone(&applied_watch),
        lane_blocks: lane_stores.clone(),
    })
    .map_err(NodeError::ExecutorStart)?;
    admit_window(&state, &crypto, GENESIS_HEIGHT).map_err(NodeError::Input)?;
    // Replay what Kura holds above genesis.
    let stored = blocks.height();
    for height in GENESIS_HEIGHT.saturating_add(1)..=stored {
        let (body, commit_qc) = blocks
            .committed_body(height)
            .map_err(|error| NodeError::Replay {
                height,
                reason: ReplayError::Read(error),
            })?
            .ok_or_else(|| NodeError::Replay {
                height,
                reason: ReplayError::MissingBody,
            })?;
        executor
            .replay(&body, &commit_qc)
            .map_err(|reason| NodeError::Replay {
                height,
                reason: ReplayError::Execution(reason),
            })?;
    }
    // Every replayed result bound the complete World state roots; the incrementally advanced
    // accumulator must also equal a cold capture of the rebuilt World (Appendix E, E51).
    state
        .verify_world_state_accumulator()
        .map_err(|reason| NodeError::Replay {
            height: stored.max(GENESIS_HEIGHT),
            reason: ReplayError::StateRoot(reason),
        })?;
    admit_window(&state, &crypto, stored.max(GENESIS_HEIGHT)).map_err(NodeError::Input)?;
    Ok(Prepared {
        state,
        crypto,
        instance,
        tip,
        genesis_epoch,
        config_fingerprint,
        blocks,
        executor,
        applied_watch,
        lane_stores,
        chain_id,
    })
}

impl Prepared {
    /// Bind SoraFS capture after startup reconciliation and before consensus can advance.
    ///
    /// # Errors
    /// The exact committed tip cannot be captured or this executor is already bound.
    pub fn attach_finalized_archives(
        &self,
        archives: super::executor::FinalizedArchives,
    ) -> Result<(), NodeError> {
        self.executor
            .attach_finalized_archives(archives)
            .map_err(NodeError::Input)
    }

    /// The instance id (`I`): peers bind it in the handshake.
    pub fn instance(&self) -> Hash32 {
        self.instance
    }

    /// The independently verified signed-genesis native consensus configuration fingerprint.
    pub fn config_fingerprint(&self) -> iroha_crypto::Hash {
        self.config_fingerprint
    }

    /// Install the safety records of the node's keys, assemble the core's `Init` and spawn the
    /// driver over `inputs.net`. The Queue is reserved before attachment or signer launch.
    /// A successful Queue cannot be started again, including after shutdown; ordinary
    /// authenticated restart supplies a fresh Queue and the original State/journal source.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn start<N: Net + 'static>(self, inputs: StartInputs<N>) -> Result<RunningNode, NodeError> {
        let Self {
            state,
            crypto,
            instance,
            tip,
            genesis_epoch,
            config_fingerprint,
            blocks,
            executor,
            applied_watch,
            lane_stores,
            chain_id,
        } = self;
        let StartInputs {
            net,
            queue,
            key_pair,
            beacon_signer,
            config,
            observer,
            driver,
        } = inputs;
        let queue_reservation = queue
            .reserve_sumeragi_start(&state.ivm_execution_budget())
            .map_err(|error| NodeError::Input(error.into()))?;
        let node_gate = state.view().kura().native_consensus_gate();
        let _startup = node_gate
            .enter()
            .ok_or(NodeError::Driver(super::driver::DriverError::StorageClosed))?;
        executor.attach_queue(Arc::clone(&queue));
        let shared: SharedCrypto = crypto.clone();
        // Records of the node's keys.
        let key =
            core_key(key_pair.public_key()).map_err(|error| NodeError::Key(error.to_string()))?;
        let budget = state.ivm_execution_budget();
        let mut keys: Vec<(PublicKey, bool)> = vec![(key, false)];
        for retired in &config.retired_keys {
            keys.push((
                core_key(retired).map_err(|error| NodeError::Key(error.to_string()))?,
                true,
            ));
        }
        let records = Arc::new(
            FileRecordStore::open(&config.records_dir, &config.installation_log)
                .map_err(|error| NodeError::Input(error.to_string()))?,
        );
        let assertion = FreshKeyAssertion::from_operator_flag(config.assert_fresh_key);
        let found = install(
            &*records,
            &*crypto,
            &instance,
            genesis_epoch,
            &keys,
            GENESIS_HEIGHT,
            assertion.as_ref(),
        )
        .map_err(|error| NodeError::Input(error.to_string()))?;
        // Height configurations of the window (t, t + 1, t + 2).
        let (configs, demotion_window) = {
            let view = state.view();
            let configs = view
                .world()
                .consensus_schedule()
                .init_configs(GENESIS_HEIGHT)
                .map_err(|error| NodeError::Input(error.to_string()))?;
            (
                configs,
                view.world().parameters().sumeragi().demotion_window.get(),
            )
        };
        let n = configs
            .iter()
            .find_map(|(_, slot)| match slot {
                iroha_sumeragi::types::ConfigSlot::Ready(config) => Some(config.committee.n()),
                iroha_sumeragi::types::ConfigSlot::PendingBoundary { .. } => None,
            })
            .ok_or_else(|| {
                NodeError::Input("native startup has no authenticated ready committee".into())
            })?;
        let identity = NodeIdentity {
            node_id: PeerId::new(key_pair.public_key().clone()),
            config_fingerprint: configuration_fingerprint(
                n,
                &config.local,
                &driver,
                &config.retired_keys,
            ),
        };
        let init = assemble_init(
            &*blocks,
            instance,
            GENESIS_HEIGHT,
            (tip.block_hash, tip.result),
            demotion_window,
            found,
            configs,
            startup_nonce(),
        )
        .map_err(NodeError::from)?;
        let bodies = Arc::new(
            FileBodyStore::open(
                &config.bodies_dir,
                &instance,
                Arc::clone(&shared),
                BodyLimits::default(),
                state.ivm_execution_budget(),
            )
            .map_err(|error| NodeError::Input(error.to_string()))?,
        );
        let signer =
            KeyPairSigner::new(&key_pair).map_err(|error| NodeError::Key(error.to_string()))?;
        let (_, beacon_key) = key_pair
            .public_key()
            .try_to_bytes()
            .map_err(|error| NodeError::Key(error.to_string()))?;
        let beacon_key: [u8; 48] = beacon_key.try_into().map_err(|_| {
            NodeError::Key("native beacon identity must be the actual BLS key".into())
        })?;
        let beacon_readiness = executor
            .attach_beacon(instance, Some(beacon_key), beacon_signer)
            .map_err(NodeError::from)?;
        // Inbound frames reach the driver of their instance: the global one and each lane's.
        let ingress = Arc::new(SumeragiIngress::new(FrameCaps::TRANSPORT));
        // Lane instances (`specs/sumeragi_lanes.md` §4.1) share the transport, ingress,
        // records, key and limits.
        let lanes =
            super::lanes::runner::LaneRunner::spawn(super::lanes::runner::LaneRunnerInputs {
                state: Arc::clone(&state),
                queue: Arc::clone(&queue),
                watch: applied_watch,
                stores: lane_stores,
                crypto: Arc::clone(&crypto),
                net: net.clone(),
                ingress: Some(Arc::clone(&ingress)),
                records: Arc::clone(&records),
                global_instance: instance,
                bodies_dir: config.bodies_dir.clone(),
                key_pair: key_pair.clone(),
                local: config.local.clone(),
                driver,
                network: *state.network_id_ref(),
                chain_id,
            })
            .map_err(NodeError::LaneRunner)?;
        let (recovery_publisher, startup_recovery) = crate::snapshot::startup_recovery_channel();
        let recovery_publisher = Arc::new(parking_lot::Mutex::new(recovery_publisher));
        let driver_owner = Driver::new(
            net,
            records,
            bodies,
            blocks,
            Arc::new(SystemClock::new()),
            executor,
            Arc::new(NativeEvidenceObserver {
                state: Arc::clone(&state),
                downstream: observer,
                recovery: Arc::clone(&recovery_publisher),
            }),
        );
        #[cfg(feature = "telemetry")]
        let driver_owner = driver_owner.with_metrics(InstanceMetrics::for_node(
            &state.telemetry,
            MetricsInstance::Global,
        ));
        let running = driver_owner
            .spawn(
                driver,
                DriverStart {
                    node_gate: state.view().kura().native_consensus_gate(),
                    allocation_budget: budget,
                    local: local_params(n, &config.local),
                    init,
                    signers: vec![Arc::new(signer)],
                    crypto: shared,
                },
            )
            .map_err(NodeError::from)?;
        ingress.register(instance, Arc::new(running.handle()));
        let queue_wake = queue_reservation
            .install(running.handle().queue_wake(), lanes.queue_wake())
            .map_err(|error| NodeError::Input(error.into()))?;
        recovery_publisher.lock().ready();
        Ok(RunningNode {
            state,
            config_fingerprint,
            beacon_readiness,
            startup_recovery,
            queue_wake,
            driver: running,
            instance,
            crypto,
            identity,
            lanes,
            ingress,
        })
    }

    /// [`Prepared::start`] over the actor retained by `inputs.net`. Inbound frames reach
    /// the driver through a [`SumeragiIngress`] fed by that same actor's three FIFOs,
    /// each holding up to `fifo_capacity` messages. Subscription refusal precedes driver
    /// construction and key-record installation.
    ///
    /// # Errors
    /// See [`NodeError`]; subscription and ingress-thread errors retain their
    /// concrete owners as [`NodeError::Subscription`] and [`NodeError::IngressThread`].
    pub fn start_on_network(
        self,
        inputs: StartInputs<P2pNet<IrohaNetwork>>,
        fifo_capacity: usize,
    ) -> Result<NetworkedNode, NodeError> {
        let subscription = inputs
            .net
            .subscribe(fifo_capacity)
            .map_err(NodeError::from)?;
        let node = self.start(inputs)?;
        let ingress = Arc::clone(&node.ingress);
        let ingress_thread = match spawn_ingress(subscription, Arc::clone(&ingress)) {
            Ok(thread) => thread,
            Err(error) => {
                drop(node.queue_wake);
                node.lanes.shutdown();
                node.driver.shutdown();
                return Err(NodeError::IngressThread(error));
            }
        };
        Ok(NetworkedNode {
            node,
            ingress,
            ingress_thread,
        })
    }
}

/// The node's instance on the P2P network: the running instance and the thread routing its
/// three FIFOs (§12.3 O8) to the driver.
pub struct NetworkedNode {
    /// The running instance.
    pub node: RunningNode,
    ingress: Arc<SumeragiIngress>,
    ingress_thread: std::thread::JoinHandle<()>,
}

impl NetworkedNode {
    /// The instance's handle.
    pub fn handle(&self) -> NodeHandle {
        self.node.handle()
    }

    /// Stop the instance and wait for its threads. The ingress thread ends with the network.
    pub fn shutdown(self) {
        self.ingress.unregister(&self.node.instance);
        drop(self.node.queue_wake);
        self.node.lanes.shutdown();
        self.node.driver.shutdown();
        drop(self.ingress_thread);
    }
}

/// Retains independently authenticated observations for the next original global candidate.
/// Lane reducers retain their own bounded reports through the lane runner observer.
struct NativeEvidenceObserver {
    state: Arc<State>,
    downstream: Arc<dyn Observer>,
    recovery: Arc<parking_lot::Mutex<crate::snapshot::StartupRecoveryPublisher>>,
}
impl Observer for NativeEvidenceObserver {
    fn evidence(&self, evidence: &iroha_sumeragi::message::Evidence) {
        if let Err(error) = super::evidence::observe(&self.state, evidence) {
            iroha_logger::warn!(%error, "sumeragi: native evidence observation was not retained");
        }
        self.downstream.evidence(evidence);
    }
    fn fault(&self, fault: &iroha_sumeragi::api::LocalFault) {
        self.downstream.fault(fault);
    }
    fn halt(&self, reason: &iroha_sumeragi::api::HaltReason) {
        self.recovery.lock().fail();
        self.downstream.halt(reason);
    }
    fn stopped(&self, worker: super::driver::Worker) {
        self.recovery.lock().fail();
        self.downstream.stopped(worker);
    }
    fn finished(&self) {
        self.recovery.lock().finish();
        self.downstream.finished();
    }
    fn frame_limit(&self, exceeded: &super::driver::FrameLimitExceeded) {
        self.downstream.frame_limit(exceeded);
    }
}

/// Reports of the instance in the node's log. Evidence is logged for the operator; the
/// status endpoint reads [`super::driver::DriverHandle::status`].
#[derive(Clone, Copy, Debug, Default)]
pub struct LogObserver;

impl Observer for LogObserver {
    fn evidence(&self, evidence: &iroha_sumeragi::message::Evidence) {
        iroha_logger::warn!(?evidence, "sumeragi: evidence of misbehaviour");
    }

    fn fault(&self, fault: &iroha_sumeragi::api::LocalFault) {
        iroha_logger::warn!(?fault, "sumeragi: local fault");
    }

    fn halt(&self, reason: &iroha_sumeragi::api::HaltReason) {
        iroha_logger::error!(?reason, "sumeragi: the instance halted");
    }

    fn stopped(&self, worker: super::driver::Worker) {
        iroha_logger::error!(
            ?worker,
            "sumeragi: a worker stopped and the instance with it; a restart recovers"
        );
    }

    fn frame_limit(&self, exceeded: &super::driver::FrameLimitExceeded) {
        iroha_logger::error!(
            height = exceeded.height,
            needed = exceeded.needed,
            limit = exceeded.limit,
            "sumeragi: a committed configuration outgrows the transport frame limit"
        );
    }
}

/// Canonical fingerprint shared by release inventory and the actual running driver.
///
/// Binds every resolved local/driver limit, the body-store cap and retired keys. Chain
/// parameters are authenticated by the committed execution-result preimage. File locations
/// and the one-shot fresh-key assertion do not change the running protocol configuration.
#[must_use]
pub fn configuration_fingerprint(
    committee_size: usize,
    overrides: &SumeragiLocalOverrides,
    driver: &DriverConfig,
    retired_keys: &[iroha_crypto::PublicKey],
) -> Hash {
    use norito::codec::Encode as _;
    let local = local_params(committee_size, overrides);
    let mut bytes = b"iroha/sumeragi/node-configuration/v1\0".to_vec();
    for value in [
        u64::from(PROTOCOL_VERSION),
        local.t_base,
        local.t_max,
        u64::from(local.start_cap),
        u64::from(local.decay_after),
        local.rebroadcast_interval,
        local.status_keepalive,
        local.build_timeout,
        local.fetch_retry,
        u64::from(local.sync_batch),
        local.sync_retry,
        u64::from(local.sync_max_bytes),
        u64::from(local.max_observers),
        driver.ingress.per_peer[0] as u64,
        driver.ingress.per_peer[1] as u64,
        driver.ingress.per_peer[2] as u64,
        u64::from(driver.ingress.bulk_every),
        driver.backoff.initial,
        driver.backoff.max,
        driver.held.effects as u64,
        driver.held.payload_bytes,
        driver.serve.bytes_per_sec,
        driver.serve.burst_bytes,
        driver.serve.max_peers as u64,
        driver.frame_limit,
        BodyLimits::default().max_bytes,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let mut retired = retired_keys.to_vec();
    retired.sort();
    bytes.extend_from_slice(&retired.encode());
    Hash::new(bytes)
}

/// The core's local parameters for a committee of `n`, with the node's overrides.
pub(crate) fn local_params(n: usize, overrides: &SumeragiLocalOverrides) -> LocalParams {
    let millis = |duration: Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    let defaults = LocalParams::for_committee_size(n);
    LocalParams {
        t_base: overrides.t_base.map_or(defaults.t_base, millis),
        t_max: overrides.t_max.map_or(defaults.t_max, millis),
        start_cap: overrides.start_cap.unwrap_or(defaults.start_cap),
        decay_after: overrides.decay_after.unwrap_or(defaults.decay_after),
        rebroadcast_interval: overrides
            .rebroadcast_interval
            .map_or(defaults.rebroadcast_interval, millis),
        status_keepalive: overrides
            .status_keepalive
            .map_or(defaults.status_keepalive, millis),
        build_timeout: overrides
            .build_timeout
            .map_or(defaults.build_timeout, millis),
        fetch_retry: overrides.fetch_retry.map_or(defaults.fetch_retry, millis),
        sync_batch: overrides.sync_batch.unwrap_or(defaults.sync_batch),
        sync_retry: overrides.sync_retry.map_or(defaults.sync_retry, millis),
        sync_max_bytes: overrides.sync_max_bytes.unwrap_or(defaults.sync_max_bytes),
        max_observers: overrides.max_observers.unwrap_or(defaults.max_observers),
    }
}

/// Admit the committee keys scheduled for `t`, `t + 1` and `t + 2`.
fn admit_window(state: &State, crypto: &BlsCrypto, t: u64) -> Result<(), String> {
    let view = state.view();
    let world = view.world();
    for height in t..=t.saturating_add(2) {
        let Some(schedule::ScheduledSlot::Ready(config)) = world.consensus_schedule().get(height)
        else {
            continue;
        };
        for (peer, pop) in schedule::committee_pops(config).map_err(|error| error.to_string())? {
            crypto
                .admit(peer.public_key(), &pop)
                .map_err(|error| format!("scheduled committee member {peer}: {error}"))?;
        }
    }
    Ok(())
}

/// A fresh nonce for the record-loss probe (§7.4 R2): distinct at every start.
pub(crate) fn startup_nonce() -> u64 {
    rand::random()
}

#[cfg(test)]
mod tests {
    #[path = "dataspace_roots.rs"]
    mod dataspace_roots;
    #[path = "history_cutover_tests.rs"]
    mod history_cutover_tests;
    #[path = "p2p_owner_tests.rs"]
    mod p2p_owner_tests;
    #[path = "queue_wake_tests.rs"]
    mod queue_wake_tests;
    #[path = "root_owner_tests.rs"]
    mod root_owner_tests;
    #[test]
    fn configuration_fingerprint_binds_effective_runtime_settings() {
        use super::{DriverConfig, SumeragiLocalOverrides, configuration_fingerprint};
        let local = SumeragiLocalOverrides::default();
        let driver = DriverConfig::default();
        let original = configuration_fingerprint(4, &local, &driver, &[]);
        let explicit_default = SumeragiLocalOverrides {
            t_base: Some(std::time::Duration::from_millis(2_000)),
            ..local
        };
        assert_eq!(
            original,
            configuration_fingerprint(4, &explicit_default, &driver, &[])
        );
        let changed = SumeragiLocalOverrides {
            build_timeout: Some(std::time::Duration::from_millis(201)),
            ..local
        };
        assert_ne!(
            original,
            configuration_fingerprint(4, &changed, &driver, &[])
        );
        let mut changed_driver = driver;
        changed_driver.ingress.per_peer[0] += 1;
        assert_ne!(
            original,
            configuration_fingerprint(4, &local, &changed_driver, &[])
        );
        changed_driver = driver;
        changed_driver.held.payload_bytes += 1;
        assert_ne!(
            original,
            configuration_fingerprint(4, &local, &changed_driver, &[])
        );
        let first =
            iroha_crypto::KeyPair::from_seed(vec![1; 32], iroha_crypto::Algorithm::BlsNormal)
                .public_key()
                .clone();
        let second =
            iroha_crypto::KeyPair::from_seed(vec![2; 32], iroha_crypto::Algorithm::BlsNormal)
                .public_key()
                .clone();
        assert_ne!(
            original,
            configuration_fingerprint(4, &local, &driver, &[first.clone()])
        );
        assert_eq!(
            configuration_fingerprint(4, &local, &driver, &[first.clone(), second.clone()]),
            configuration_fingerprint(4, &local, &driver, &[second, first])
        );
    }

    use std::{collections::HashMap, num::NonZeroU64, time::Duration};

    use iroha_crypto::HashOf;
    use iroha_crypto::{Algorithm, bls_normal_pop_prove};
    use iroha_data_model::{
        NetworkId,
        block::consensus::SumeragiGenesisContextParameters,
        parameter::{Parameter, system::SumeragiParameter},
        prelude::*,
    };
    use iroha_data_model::{
        isi::Log,
        transaction::{FeePaymentIntent, TransactionEntrypoint},
    };
    use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};
    use iroha_model_base::{chain::ChainId, peer::PeerId};
    use iroha_primitives::time::TimeSource;
    use iroha_test_samples::{
        ALICE_ID, ALICE_KEYPAIR, SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
    };

    use super::*;
    use crate::{
        governance::manifest::LaneManifestRegistry,
        query::store::LiveQueryStore,
        state::World,
        sumeragi::driver::traits::{Frame, PendingSend, SendOutcome},
        tx::AcceptedTransaction,
    };
    use iroha_sumeragi::types::PublicKey as CoreKey;

    /// The in-memory transport: every node's handle, filled once the nodes start.
    /// Missing routes and temporary ingress refusals retain their original send occurrence.
    #[derive(Default)]
    struct Registry(parking_lot::Mutex<HashMap<CoreKey, Arc<SumeragiIngress>>>);

    struct MemNet {
        from: CoreKey,
        registry: Arc<Registry>,
    }

    impl Net for MemNet {
        fn send(&self, to: &CoreKey, frame: &Frame) -> SendOutcome {
            Box::new(PendingMemSend {
                from: self.from.clone(),
                to: to.clone(),
                registry: Arc::clone(&self.registry),
                frame: frame.clone(),
            })
            .retry()
        }
    }

    /// One in-process occurrence keeps the same source, recipient and encoded frame on retry.
    struct PendingMemSend {
        from: CoreKey,
        to: CoreKey,
        registry: Arc<Registry>,
        frame: Frame,
    }

    impl super::super::driver::traits::PendingSend for PendingMemSend {
        fn retry(self: Box<Self>) -> SendOutcome {
            let ingress = self.registry.0.lock().get(&self.to).cloned();
            let Some(ingress) = ingress else {
                return SendOutcome::Backpressured(self);
            };
            match ingress.deliver(&self.from, &self.frame) {
                super::super::net::Routed::Delivered => SendOutcome::Admitted,
                super::super::net::Routed::Refused | super::super::net::Routed::UnknownInstance => {
                    SendOutcome::Backpressured(self)
                }
                _ => SendOutcome::Rejected,
            }
        }
    }

    mod mem_net_tests {
        use super::*;
        use iroha_sumeragi::{
            message::{PayloadRequest, TrafficClass, WireMessage},
            types::Hash32,
        };
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Default)]
        struct Gate {
            accepts: AtomicBool,
            attempts: parking_lot::Mutex<Vec<(CoreKey, Vec<u8>, usize)>>,
        }

        impl super::super::super::net::FrameSink for Gate {
            fn deliver(&self, from: &CoreKey, bytes: &[u8]) -> bool {
                self.attempts
                    .lock()
                    .push((from.clone(), bytes.to_vec(), bytes.as_ptr() as usize));
                self.accepts.load(Ordering::Relaxed)
            }
        }

        fn pending(outcome: SendOutcome) -> Box<dyn PendingSend> {
            let SendOutcome::Backpressured(owner) = outcome else {
                panic!("an unadmitted original frame must remain retryable");
            };
            owner
        }

        fn transport() -> (MemNet, CoreKey, Frame) {
            let sender = KeyPair::from_seed(vec![0xD1; 32], Algorithm::BlsNormal);
            let recipient = KeyPair::from_seed(vec![0xD2; 32], Algorithm::BlsNormal);
            let instance = Hash32([0x31; 32]);
            let frame = Frame {
                instance,
                class: TrafficClass::Control,
                bytes: WireMessage::PayloadRequest(PayloadRequest {
                    instance,
                    height: 2,
                    block_hash: Hash32([0x32; 32]),
                })
                .encode()
                .expect("canonical original frame")
                .into(),
            };
            (
                MemNet {
                    from: core_key(sender.public_key()).unwrap(),
                    registry: Arc::new(Registry::default()),
                },
                core_key(recipient.public_key()).unwrap(),
                frame,
            )
        }

        #[test]
        fn mem_net_retains_original_occurrence_until_actual_ingress_admission() {
            let (net, recipient, frame) = transport();
            let original_bytes = Arc::clone(&frame.bytes);
            let owner = pending(net.send(&recipient, &frame));
            let ingress = Arc::new(SumeragiIngress::new(FrameCaps::TRANSPORT));
            net.registry
                .0
                .lock()
                .insert(recipient.clone(), Arc::clone(&ingress));
            let owner = pending(owner.retry());
            let gate = Arc::new(Gate::default());
            ingress.register(frame.instance, gate.clone());
            let owner = pending(owner.retry());
            let owner = pending(owner.retry());
            assert_eq!(ingress.stats().delivered, 0);
            assert_eq!(ingress.stats().dropped, 3);
            gate.accepts.store(true, Ordering::Relaxed);
            assert!(matches!(owner.retry(), SendOutcome::Admitted));
            let attempts = gate.attempts.lock();
            assert_eq!(attempts.len(), 3);
            for (from, bytes, address) in attempts.iter() {
                assert_eq!(from, &net.from);
                assert_eq!(bytes.as_slice(), original_bytes.as_ref());
                assert_eq!(*address, original_bytes.as_ptr() as usize);
            }
            assert_eq!(ingress.stats().delivered, 1);
            assert_eq!(ingress.stats().dropped, 3);
        }

        #[test]
        fn mem_net_rejects_oversize_and_cancellation_releases_original_frame() {
            let (net, recipient, frame) = transport();
            let original_count = Arc::strong_count(&frame.bytes);
            let owner = pending(net.send(&recipient, &frame));
            assert_eq!(Arc::strong_count(&frame.bytes), original_count + 1);
            drop(owner);
            assert_eq!(Arc::strong_count(&frame.bytes), original_count);
            let ingress = Arc::new(SumeragiIngress::new(FrameCaps {
                control: frame.bytes.len() - 1,
                ..FrameCaps::TRANSPORT
            }));
            let gate = Arc::new(Gate::default());
            gate.accepts.store(true, Ordering::Relaxed);
            ingress.register(frame.instance, gate.clone());
            net.registry
                .0
                .lock()
                .insert(recipient.clone(), Arc::clone(&ingress));
            assert!(matches!(
                net.send(&recipient, &frame),
                SendOutcome::Rejected
            ));
            assert!(gate.attempts.lock().is_empty());
            assert_eq!(ingress.stats().delivered, 0);
            assert_eq!(ingress.stats().dropped, 1);
            assert_eq!(Arc::strong_count(&frame.bytes), original_count);
        }
    }

    /// Prints what the instance reports (shown on failure).
    struct PrintObserver(usize);

    impl Observer for PrintObserver {
        fn evidence(&self, evidence: &iroha_sumeragi::message::Evidence) {
            eprintln!("node {}: evidence {evidence:?}", self.0);
        }
        fn fault(&self, fault: &iroha_sumeragi::api::LocalFault) {
            eprintln!("node {}: fault {fault:?}", self.0);
        }
        fn halt(&self, reason: &iroha_sumeragi::api::HaltReason) {
            eprintln!("node {}: halt {reason:?}", self.0);
        }
        fn stopped(&self, worker: crate::sumeragi::driver::Worker) {
            eprintln!("node {}: stopped {worker:?}", self.0);
        }
    }

    struct Chain {
        genesis: SignedBlock,
        keys: Vec<KeyPair>,
        chain_id: ChainId,
    }

    /// A chain of `validators` with a 100 ms block time and the given idle interval.
    fn chain(validators: u8, payload_retry_interval_ms: u64) -> Chain {
        chain_with(validators, payload_retry_interval_ms, |_| Vec::new())
    }

    /// [`chain`] whose genesis also sets the parameters `extra` derives from the validators'
    /// keys (in canonical order).
    fn chain_with(
        validators: u8,
        payload_retry_interval_ms: u64,
        extra: impl FnOnce(&[KeyPair]) -> Vec<Parameter>,
    ) -> Chain {
        // The global logger's actor must outlive each synchronous node fixture.
        // Keep its actual reactor alive even when this is the first selected test.
        static LOGGER_RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> =
            std::sync::OnceLock::new();
        let _logger = {
            let runtime = LOGGER_RUNTIME.get_or_init(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .expect("node fixture logger runtime")
            });
            let _entered = runtime.enter();
            iroha_logger::test_logger()
        };
        iroha_genesis::init_instruction_registry();
        let chain_id = ChainId::from("sumeragi-node-test");
        let mut keys = (0..validators)
            .map(|index| {
                KeyPair::try_from_seed(vec![0xC0 + index; 32], Algorithm::BlsNormal).expect("key")
            })
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        let entries = keys
            .iter()
            .map(|key| {
                GenesisTopologyEntry::new(
                    PeerId::new(key.public_key().clone()),
                    bls_normal_pop_prove(key.private_key()).expect("pop"),
                )
            })
            .collect::<Vec<_>>();
        let extra = extra(&keys);
        let mut builder = GenesisBuilder::new_without_executor(chain_id.clone(), ".")
            .append_parameter(Parameter::Sumeragi(
                SumeragiParameter::PayloadRetryIntervalMs(
                    NonZeroU64::new(payload_retry_interval_ms).expect("non-zero"),
                ),
            ));
        for parameter in extra {
            builder = builder.append_parameter(parameter);
        }
        let manifest = builder
            .with_block_cadence_ms(NonZeroU64::new(100).expect("non-zero"))
            .set_topology(entries)
            .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
            .build_raw()
            .expect("genesis manifest")
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let genesis = manifest
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                &SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
                None,
                Some(crate::state::default_genesis_confidential_policy_hash()),
                1_000,
            )
            .expect("genesis")
            .0;
        let custody = keys
            .iter()
            .map(|key| {
                (
                    PeerId::new(key.public_key().clone()),
                    bls_normal_pop_prove(key.private_key()).expect("pop"),
                )
            })
            .collect::<Vec<_>>();
        let (genesis, _, _, _) = super::super::test_chain::prepare_configured_genesis(
            initial_world(),
            &chain_id,
            &SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
            &custody,
            genesis,
            manifest,
            iroha_data_model::parameter::system::SumeragiConsensusMode::Permissioned,
            1_000,
            &iroha_config::parameters::actual::Pipeline::default(),
            &iroha_config::parameters::actual::FraudMonitoring::default(),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("original signed genesis policies derived from node execution configuration");
        Chain {
            genesis,
            keys,
            chain_id,
        }
    }

    fn initial_world() -> World {
        let account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
        World::with(
            [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&account)],
            [
                Account::new(account.clone()).build(&account),
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(second_shard_account()).build(&second_shard_account()),
            ],
            [],
        )
    }

    fn empty_state(chain_id: &ChainId, genesis: &SignedBlock, kura: &Arc<Kura>) -> Arc<State> {
        let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
            initial_world(),
            Arc::clone(kura),
            LiveQueryStore::start_test(),
            chain_id.clone(),
            NetworkId::from_genesis_hash(genesis.hash()),
        ));
        let nexus = state.nexus_snapshot();
        state.install_lane_manifests_for_testing(&Arc::new(
            LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
        ));
        state
    }

    /// One validator's durable parts: Kura and its directory (records, bodies).
    struct Disk {
        kura: Arc<Kura>,
        dir: tempfile::TempDir,
    }

    fn disks(chain: &Chain) -> Vec<Disk> {
        (0..chain.keys.len())
            .map(|_| Disk {
                kura: Kura::blank_kura_for_testing(),
                dir: tempfile::tempdir().expect("tempdir"),
            })
            .collect()
    }

    /// A running validator and the parts the test drives.
    struct Validator {
        node: RunningNode,
        state: Arc<State>,
        queue: Arc<Queue>,
    }

    fn start_all(chain: &Chain, disks: &[Disk], fresh: bool) -> Vec<Validator> {
        let registry = Arc::new(Registry::default());
        let validators = disks
            .iter()
            .enumerate()
            .map(|(index, disk)| {
                let key_pair = chain.keys[index].clone();
                let (_, time_source) = TimeSource::new_mock(Duration::ZERO);
                let state = empty_state(&chain.chain_id, &chain.genesis, &disk.kura);
                let queue = Arc::new(Queue::test(
                    iroha_config::parameters::actual::Queue::default(),
                    &time_source,
                ));
                let node = start(NodeInputs {
                    state: Arc::clone(&state),
                    queue: Arc::clone(&queue),
                    events: tokio::sync::broadcast::channel(1024).0,
                    net: Arc::new(MemNet {
                        from: core_key(key_pair.public_key()).expect("BLS key"),
                        registry: Arc::clone(&registry),
                    }),
                    key_pair,
                    beacon_signer: None,
                    genesis: Some(chain.genesis.clone()),
                    genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
                    consensus_mode: ConsensusMode::Permissioned,
                    config: NodeConfig {
                        records_dir: disk.dir.path().join("records"),
                        installation_log: disk.dir.path().join("keys").join("installation.log"),
                        bodies_dir: disk.dir.path().join("bodies"),
                        local: SumeragiLocalOverrides::default(),
                        assert_fresh_key: fresh,
                        retired_keys: Vec::new(),
                    },
                    observer: Arc::new(PrintObserver(index)),
                    driver: DriverConfig::default(),
                })
                .expect("start");
                assert!(node.handle().startup_recovery().is_ready());
                Validator { node, state, queue }
            })
            .collect::<Vec<_>>();
        let mut peers = registry.0.lock();
        for (key, validator) in chain.keys.iter().zip(&validators) {
            peers.insert(
                core_key(key.public_key()).expect("BLS key"),
                Arc::clone(&validator.node.ingress),
            );
        }
        drop(peers);
        validators
    }

    fn shutdown(validators: Vec<Validator>) {
        for validator in validators {
            let recovery = validator.node.handle().startup_recovery();
            drop(validator.node.queue_wake);
            validator.node.lanes.shutdown();
            validator.node.driver.shutdown();
            assert!(
                recovery.is_ready(),
                "orderly shutdown retains completed recovery"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn readiness_until_expired_deadline_refuses_live_node() {
        let chain = chain(4, 200);
        let disks = disks(&chain);
        let validators = start_all(&chain, &disks, true);
        let startup_deadline = Instant::now() + Duration::from_secs(5);
        for validator in &validators {
            let handle = validator.node.handle();
            while !handle.driver.ready() && Instant::now() < startup_deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(handle.driver.ready(), "the native driver must be running");
            assert!(
                !handle.ready_until(Instant::now()),
                "an expired diagnostic cannot use any readiness shortcut"
            );
        }
        shutdown(validators);
    }

    #[test]
    fn native_observer_revokes_export_authority_on_failure_and_late_start_cannot_restore_it() {
        let chain = chain(4, 200);
        let state = empty_state(
            &chain.chain_id,
            &chain.genesis,
            &Kura::blank_kura_for_testing(),
        );
        for (ready_first, halted) in [(false, false), (false, true), (true, false), (true, true)] {
            let (publisher, recovery) = crate::snapshot::startup_recovery_channel();
            let publisher = Arc::new(parking_lot::Mutex::new(publisher));
            let observer = NativeEvidenceObserver {
                state: Arc::clone(&state),
                downstream: Arc::new(super::super::driver::traits::NoObserver),
                recovery: Arc::clone(&publisher),
            };
            if ready_first {
                publisher.lock().ready();
                assert!(recovery.is_ready());
            }
            if halted {
                observer.halt(&HaltReason::ApplyDiverged { height: 2 });
            } else {
                observer.stopped(super::super::driver::Worker::Exec);
            }
            assert!(!recovery.is_ready());
            publisher.lock().ready();
            observer.finished();
            assert!(
                !recovery.is_ready(),
                "failure is terminal even across late startup and orderly exit"
            );
        }
    }

    /// Each validator's stored complete World state root (Appendix E, E51).
    fn world_state_roots(validators: &[Validator]) -> Vec<Result<Hash, String>> {
        validators
            .iter()
            .map(|validator| validator.state.world.state_accumulator.view().get().root())
            .collect()
    }

    fn committed_heights(validators: &[Validator]) -> Vec<u64> {
        validators
            .iter()
            .map(|validator| {
                validator
                    .node
                    .driver
                    .handle()
                    .status()
                    .map_or(0, |status| status.committed_height)
            })
            .collect()
    }

    /// Wait until `done` holds, failing on a halt or after `limit`.
    fn wait_until(
        validators: &[Validator],
        limit: Duration,
        what: &str,
        mut done: impl FnMut() -> bool,
    ) {
        let start = std::time::Instant::now();
        while !done() {
            for validator in validators {
                let halted = validator.node.driver.handle().halted();
                assert!(halted.is_none(), "halted: {halted:?}");
            }
            if start.elapsed() >= limit {
                for validator in validators {
                    eprintln!("{:#?}", validator.node.driver.handle().status());
                    eprintln!("lanes: {:#?}", validator.node.lanes.handle().statuses());
                    let view = validator.state.view();
                    let block_parameters = view.world().parameters().block();
                    let pending = validator.queue.bounded_pending_snapshot_for_testing(
                        &view,
                        crate::sumeragi::payload::MAX_QUEUE_SCAN,
                    );
                    eprintln!(
                        "  original parent: {:?}, root: {:?}, Network capacity: {:?}, queued: {}, pending: {:?}",
                        view.native_execution_tip(),
                        crate::sumeragi::lanes::routing::committed_root_scope(view.world()),
                        block_parameters
                            .fastpq_source()
                            .maximum_network_inputs(block_parameters.execution_output()),
                        validator.queue.queued_len(),
                        pending.as_ref().map(Vec::len),
                    );
                    if let Some(pending) = pending.as_ref() {
                        for transaction in pending {
                            let hash = transaction.hash_as_entrypoint();
                            eprintln!(
                                "  pending input: {hash:?}, committed: {}",
                                validator.state.has_committed_entrypoint(hash)
                            );
                        }
                    }
                    for height in 2..=view.height() {
                        let block = validator
                            .state
                            .kura()
                            .get_block(
                                core::num::NonZeroUsize::new(height).expect("non-zero"),
                                &validator.state.ivm_execution_budget(),
                            )
                            .expect("original block read attempt")
                            .expect("stored");
                        eprintln!(
                            "  block {height}: {} entrypoints, queued {}",
                            block.network_entrypoint_count(),
                            validator.queue.queued_len()
                        );
                        for entrypoint in block.external_entrypoints_slice() {
                            let hash = entrypoint.hash();
                            eprintln!(
                                "    stored input: {hash:?}, committed: {}, pending: {}",
                                validator.state.has_committed_entrypoint(hash),
                                validator.queue.contains_entrypoint_hash(hash)
                            );
                        }
                    }
                }
                panic!(
                    "{what}: not reached in {limit:?} (heights {:?})",
                    committed_heights(validators)
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn assert_idle_height_unchanged(validators: &[Validator], duration: Duration) {
        let baseline = committed_heights(validators);
        let started = std::time::Instant::now();
        while started.elapsed() < duration {
            assert_eq!(
                committed_heights(validators),
                baseline,
                "idle chain advanced"
            );
            for validator in validators {
                assert!(validator.node.driver.handle().halted().is_none());
                assert_eq!(validator.queue.queued_len(), 0);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The key of an account whose default route is the second of two shards (an elastic lane
    /// next to lane 0).
    fn second_shard_key() -> KeyPair {
        (1u8..)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519))
            .find(|key| {
                crate::sumeragi::lanes::routing::default_shard(
                    &AccountId::new(key.public_key().clone()),
                    2,
                ) == 1
            })
            .expect("a key on the second shard")
    }

    fn second_shard_account() -> AccountId {
        AccountId::new(second_shard_key().public_key().clone())
    }

    /// Submit a transaction to every validator's queue (the transaction gossip's job in the
    /// node) and tell the drivers.
    fn submit(
        chain: &Chain,
        validators: &[Validator],
        message: &str,
    ) -> HashOf<TransactionEntrypoint> {
        submit_as(chain, validators, &ALICE_KEYPAIR, message)
    }

    /// [`submit`] signed by `key`'s account.
    fn submit_as(
        chain: &Chain,
        validators: &[Validator],
        key: &KeyPair,
        message: &str,
    ) -> HashOf<TransactionEntrypoint> {
        let network_id = NetworkId::from_genesis_hash(chain.genesis.hash());
        let signed = TransactionBuilder::new(
            network_id,
            AccountId::new(key.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, message.to_owned())])
        .sign(key.private_key());
        let accepted = AcceptedTransaction::accept(
            signed,
            &network_id,
            Duration::from_secs(10),
            TransactionParameters::default(),
            &iroha_config::parameters::actual::Crypto::default(),
        )
        .expect("accepted");
        let hash = accepted.hash_as_entrypoint();
        for validator in validators {
            validator
                .queue
                .push(accepted.clone(), validator.state.view())
                .expect("queued");
            validator.node.handle().transactions_available();
        }
        hash
    }

    fn committed_everywhere(validators: &[Validator], hash: HashOf<TransactionEntrypoint>) -> bool {
        validators.iter().all(|validator| {
            validator.state.has_committed_entrypoint(hash)
                && validator
                    .node
                    .driver
                    .handle()
                    .status()
                    .is_some_and(|status| {
                        status.applied_height
                            == u64::try_from(validator.state.view().height()).unwrap()
                    })
        })
    }

    /// Every validator stored the same blocks up to `height`, each with its commit certificate
    /// (genesis with its result-only one).
    fn assert_same_certified_blocks(disks: &[Disk], height: usize) {
        let inspection_budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        for height in 1..=height {
            let height = core::num::NonZeroUsize::new(height).expect("non-zero");
            let blocks = disks
                .iter()
                .map(|disk| {
                    disk.kura
                        .get_block(height, &inspection_budget)
                        .expect("original block read attempt")
                        .expect("stored")
                })
                .collect::<Vec<_>>();
            for block in &blocks {
                assert!(block.commit_certificate().is_some(), "height {height}");
                assert_eq!(block.hash(), blocks[0].hash(), "height {height}");
                assert!(
                    block.network_entrypoint_count() > 0,
                    "empty block at {height}"
                );
            }
        }
    }

    /// A lane policy pinning fixed lane 2 to the whole validator set and routing Alice's
    /// transactions to it.
    fn fixed_lane_policy(keys: &[KeyPair]) -> Vec<Parameter> {
        fixed_lane_policy_with_retry(keys, 200)
    }

    fn fixed_lane_policy_with_retry(keys: &[KeyPair], retry_ms: u64) -> Vec<Parameter> {
        use iroha_data_model::sumeragi_lanes::{
            SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRoute,
        };
        let policy = SumeragiLanePolicy {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            anchor_freshness: 64,
            max_merge_blocks: 16,
            stall_window: 10_000,
            lane_params: iroha_data_model::parameter::system::SumeragiParameters {
                block_cadence_ms: NonZeroU64::new(100).expect("non-zero"),
                payload_retry_interval_ms: NonZeroU64::new(retry_ms).expect("non-zero"),
                ..iroha_data_model::parameter::system::SumeragiParameters::default()
            },
            fixed: vec![SumeragiFixedLane {
                lane: iroha_model_base::topology::LaneId::new(2),
                dataspace: iroha_model_base::topology::DataSpaceId::new(0),
                committee: keys
                    .iter()
                    .map(|key| SumeragiLaneMember {
                        peer: PeerId::new(key.public_key().clone()),
                        pop: bls_normal_pop_prove(key.private_key()).expect("pop"),
                    })
                    .collect(),
            }],
            routes: vec![SumeragiLaneRoute {
                lane: iroha_model_base::topology::LaneId::new(2),
                account: Some(ALICE_ID.to_string()),
                instruction: None,
            }],
            autoscale: None,
        };
        vec![Parameter::Custom(policy.into_custom_parameter())]
    }

    /// Transactions every validator's stored blocks executed from merged lane blocks.
    fn merged_everywhere(validators: &[Validator], disks: &[Disk]) -> Vec<usize> {
        validators
            .iter()
            .zip(disks)
            .map(|(validator, disk)| {
                (1..=validator.state.view().height())
                    .filter_map(|height| {
                        disk.kura
                            .get_block(
                                core::num::NonZeroUsize::new(height).expect("non-zero"),
                                &validator.state.ivm_execution_budget(),
                            )
                            .expect("original block read attempt")
                    })
                    .map(|block| block.merged_entrypoint_count())
                    .sum::<usize>()
            })
            .collect()
    }

    #[test]
    fn a_fixed_lane_carries_transactions_the_global_chain_merges() {
        let lane = iroha_model_base::topology::LaneId::new(2);
        let chain = chain_with(4, 200, fixed_lane_policy);
        let disks = disks(&chain);
        let validators = start_all(&chain, &disks, true);
        // Genesis creates the lane, active from global height 3: until the global chain has
        // applied it, Alice's transactions stay on lane 0.
        for message in ["before the lane 1", "before the lane 2"] {
            let hash = submit(&chain, &validators, message);
            wait_until(&validators, Duration::from_secs(30), message, || {
                committed_everywhere(&validators, hash)
            });
        }
        wait_until(
            &validators,
            Duration::from_secs(30),
            "every validator runs the lane",
            || {
                validators
                    .iter()
                    .all(|validator| validator.node.lanes.instances().len() == 1)
            },
        );
        let hash = submit(&chain, &validators, "through the lane");
        wait_until(
            &validators,
            Duration::from_secs(60),
            "the lane's transaction merged",
            || committed_everywhere(&validators, hash),
        );
        let frontier = |validators: &[Validator]| {
            validators
                .iter()
                .map(|validator| {
                    validator
                        .state
                        .view()
                        .world()
                        .sumeragi_lanes()
                        .lane(lane)
                        .expect("the lane")
                        .merged
                })
                .collect::<Vec<_>>()
        };
        let merged = frontier(&validators);
        assert!(merged[0].height >= 1, "a lane block was merged");
        assert!(merged.iter().all(|frontier| *frontier == merged[0]));
        assert_eq!(
            merged_everywhere(&validators, &disks),
            vec![1; 4],
            "the transaction came through the lane"
        );
        shutdown(validators);

        // Restart: replay re-executes the merged blocks from the lane stores on disk, the lane
        // instances resume from their stores, and the lane keeps carrying transactions.
        let validators = start_all(&chain, &disks, false);
        assert!(committed_everywhere(&validators, hash));
        assert_eq!(frontier(&validators), merged);
        wait_until(
            &validators,
            Duration::from_secs(30),
            "every validator runs the lane again",
            || {
                validators
                    .iter()
                    .all(|validator| validator.node.lanes.instances().len() == 1)
            },
        );
        let hash = submit(&chain, &validators, "through the lane after restart");
        wait_until(
            &validators,
            Duration::from_secs(60),
            "the lane's transaction merged after restart",
            || committed_everywhere(&validators, hash),
        );
        assert_eq!(merged_everywhere(&validators, &disks), vec![2; 4]);
        assert!(frontier(&validators)[0].height > merged[0].height);
        shutdown(validators);
    }

    const ELASTIC_BURST_INPUTS: u32 = 256;

    /// A lane policy that autoscales one elastic lane (16) over the whole validator set.
    fn elastic_lane_policy(_keys: &[KeyPair]) -> Vec<Parameter> {
        use iroha_data_model::{
            parameter::{ExecutionOutputPolicyV1, FastpqSourcePolicyV1, system::BlockParameter},
            sumeragi_lanes::{SumeragiLaneAutoscale, SumeragiLanePolicy},
        };
        // This signed genesis supports the test's Log-only load, with no Pipeline callbacks.
        // Keep every other output/source ceiling; the default 256 callbacks per input reserve
        // most source capacity and limit native proposals to eleven Network inputs.
        let output = ExecutionOutputPolicyV1 {
            max_pipeline_triggers: 0,
            ..ExecutionOutputPolicyV1::bootstrap()
        };
        output
            .validate()
            .expect("finite signed Log-workload profile");
        assert!(
            FastpqSourcePolicyV1::bootstrap()
                .maximum_network_inputs(output)
                .expect("original finite source capacity")
                >= ELASTIC_BURST_INPUTS
        );
        let policy = SumeragiLanePolicy {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            anchor_freshness: 4,
            max_merge_blocks: 16,
            stall_window: 10_000,
            lane_params: iroha_data_model::parameter::system::SumeragiParameters {
                block_cadence_ms: NonZeroU64::new(100).expect("non-zero"),
                payload_retry_interval_ms: NonZeroU64::new(200).expect("non-zero"),
                ..iroha_data_model::parameter::system::SumeragiParameters::default()
            },
            fixed: Vec::new(),
            routes: Vec::new(),
            autoscale: Some(SumeragiLaneAutoscale {
                min_lane: iroha_model_base::topology::LaneId::new(16),
                max_lane_exclusive: iroha_model_base::topology::LaneId::new(17),
                dataspace: iroha_model_base::topology::DataSpaceId::new(0),
                committee_size: 4,
                per_lane_target_tps: 10,
                window: 3,
                scale_out_permille: 300,
                scale_in_permille: 150,
                cooldown: 3,
            }),
        };
        vec![
            Parameter::Block(BlockParameter::ExecutionOutput(output)),
            Parameter::Custom(policy.into_custom_parameter()),
        ]
    }

    fn lane_record(
        validator: &Validator,
        lane: iroha_model_base::topology::LaneId,
    ) -> Option<iroha_data_model::sumeragi_lanes::SumeragiLaneRecord> {
        validator
            .state
            .view()
            .world()
            .sumeragi_lanes()
            .lane(lane)
            .cloned()
    }

    #[test]
    fn autoscale_opens_an_elastic_lane_under_load_and_retires_it_when_idle() {
        let elastic = iroha_model_base::topology::LaneId::new(16);
        let chain = chain_with(4, 200, elastic_lane_policy);
        let disks = disks(&chain);
        let validators = start_all(&chain, &disks, true);
        let autoscale = crate::sumeragi::lanes::lane_policy(validators[0].state.view().world())
            .expect("completed original routing metadata read")
            .expect("the signed lane policy")
            .autoscale
            .expect("the signed autoscale policy");
        {
            let view = validators[0].state.view();
            let block = view.world().parameters().block();
            assert_eq!(block.execution_output().max_pipeline_triggers, 0);
            assert!(
                block
                    .fastpq_source()
                    .maximum_network_inputs(block.execution_output())
                    .expect("authenticated genesis source capacity")
                    >= ELASTIC_BURST_INPUTS
            );
        }
        let peak_utilization = std::cell::Cell::new(None::<u64>);
        let mut round = 0usize;
        let mut burst = |validators: &[Validator], size: usize| {
            round += 1;
            let hashes = (0..size)
                .map(|index| submit(&chain, validators, &format!("load {round}.{index}")))
                .collect::<Vec<_>>();
            wait_until(
                validators,
                Duration::from_secs(60),
                &format!("burst {round} with {size} inputs commits"),
                || {
                    let view = validators[0].state.view();
                    if let Some(utilization) = crate::sumeragi::lanes::step::utilization_permille(
                        &view.world().sumeragi_lanes().samples,
                        autoscale.window,
                        autoscale.per_lane_target_tps,
                    ) {
                        peak_utilization
                            .set(Some(peak_utilization.get().unwrap_or(0).max(utilization)));
                    }
                    drop(view);
                    hashes
                        .iter()
                        .all(|hash| committed_everywhere(validators, *hash))
                },
            );
        };
        let running = |validators: &[Validator]| {
            validators
                .iter()
                .map(|validator| validator.node.lanes.instances().len())
                .collect::<Vec<_>>()
        };
        // Load opens the elastic lane; once the global chain applies its activation height,
        // every validator runs it.
        for _ in 0..16 {
            if running(&validators) == vec![1; 4] {
                break;
            }
            // Amortize real proposal/QC work with a bounded queue of ordinary signed inputs.
            // Six inputs per several-second commit do not supply the policy's 3 TPS threshold.
            burst(
                &validators,
                usize::try_from(ELASTIC_BURST_INPUTS).expect("bounded burst"),
            );
        }
        assert!(
            peak_utilization
                .get()
                .is_some_and(|value| value >= u64::from(autoscale.scale_out_permille)),
            "the actual committed load must cross the signed scale-out threshold: peak {:?}, threshold {}",
            peak_utilization.get(),
            autoscale.scale_out_permille,
        );
        assert_eq!(
            running(&validators),
            vec![1; 4],
            "the elastic lane runs: {:?}",
            validators
                .iter()
                .map(|validator| validator.state.view().world().sumeragi_lanes().clone())
                .collect::<Vec<_>>()
        );
        let record = lane_record(&validators[0], elastic).expect("the elastic lane");
        assert_eq!(record.committee.len(), 4, "drawn from the validators");
        // The second shard's account is routed to the elastic lane.
        let hash = submit_as(
            &chain,
            &validators,
            &second_shard_key(),
            "through the elastic lane",
        );
        wait_until(
            &validators,
            Duration::from_secs(60),
            "the elastic lane's transaction merged",
            || committed_everywhere(&validators, hash),
        );
        assert!(
            merged_everywhere(&validators, &disks)
                .iter()
                .all(|merged| *merged >= 1)
        );
        // Idle: spaced transactions show low utilization and the lane closes.
        for index in 0..12 {
            if lane_record(&validators[0], elastic).is_none_or(|record| record.closing.is_some()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1_600));
            let hash = submit(&chain, &validators, &format!("idle {index}"));
            wait_until(
                &validators,
                Duration::from_secs(60),
                "idle work commits",
                || committed_everywhere(&validators, hash),
            );
        }
        let closing = lane_record(&validators[0], elastic)
            .and_then(|record| record.closing)
            .expect("the idle lane closes");
        // It retires at c + A + 1, and every validator stops its instance.
        for _ in 0..16 {
            if validators
                .iter()
                .all(|validator| lane_record(validator, elastic).is_none())
            {
                break;
            }
            burst(&validators, 1);
        }
        assert!(
            validators
                .iter()
                .all(|validator| lane_record(validator, elastic).is_none()),
            "the lane closed at {closing} retires"
        );
        wait_until(
            &validators,
            Duration::from_secs(30),
            "every validator stops the retired lane",
            || running(&validators) == vec![0; 4],
        );
        shutdown(validators);
    }

    #[test]
    fn idle_chain_never_advances_and_real_work_survives_restart() {
        let chain = chain(4, 200);
        let disks = disks(&chain);
        let validators = start_all(&chain, &disks, true);
        assert_eq!(committed_heights(&validators), vec![GENESIS_HEIGHT; 4]);
        assert_idle_height_unchanged(&validators, Duration::from_millis(750));
        let hash = submit(&chain, &validators, "after idle");
        wait_until(
            &validators,
            Duration::from_secs(30),
            "real work after idle",
            || committed_everywhere(&validators, hash),
        );
        assert_idle_height_unchanged(&validators, Duration::from_millis(750));
        // Every validator holds the same complete World.
        let roots = world_state_roots(&validators);
        assert!(roots[0].is_ok() && roots.iter().all(|root| *root == roots[0]));
        shutdown(validators);
        let committed = disks
            .iter()
            .map(|disk| disk.kura.blocks_count())
            .min()
            .expect("validators");
        assert_eq!(committed, 2, "only genesis and the submitted transaction");
        assert_same_certified_blocks(&disks, committed);
        // Replay the exact retained history, remain idle, then accept new work. Startup
        // checks the replayed accumulator against a cold capture; the restarted World equals
        // the one before shutdown.
        let validators = start_all(&chain, &disks, false);
        assert_eq!(world_state_roots(&validators), roots);
        assert_idle_height_unchanged(&validators, Duration::from_millis(750));
        let hash = submit(&chain, &validators, "after idle restart");
        wait_until(
            &validators,
            Duration::from_secs(30),
            "real work after restart",
            || committed_everywhere(&validators, hash),
        );
        assert_eq!(committed_heights(&validators), vec![3; 4]);
        shutdown(validators);
        assert_same_certified_blocks(&disks, 3);
    }

    #[test]
    fn all_seat_restart_reproduces_missing_original_context_archives_from_certified_execution() {
        let chain = chain(4, 200);
        let disks = disks(&chain);
        let validators = start_all(&chain, &disks, true);
        let hash = submit(&chain, &validators, "original context archive restart");
        wait_until(
            &validators,
            Duration::from_secs(30),
            "archive source committed",
            || committed_everywhere(&validators, hash),
        );
        shutdown(validators);
        let mut records = Vec::new();
        for disk in &disks {
            let directory = disk.kura.store_root().join("native-contexts");
            let mut files = std::fs::read_dir(&directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            files.sort();
            assert_eq!(
                files.len(),
                2,
                "original genesis and its actual work successor"
            );
            for file in files {
                let bytes = std::fs::read(&file).unwrap();
                std::fs::remove_file(&file).unwrap();
                records.push((file, bytes));
            }
        }
        let validators = start_all(&chain, &disks, false);
        assert_eq!(committed_heights(&validators), vec![2; 4]);
        for (file, original) in &records {
            assert_eq!(
                &std::fs::read(file).unwrap(),
                original,
                "fresh State replay must reproduce the exact certified execution projection"
            );
        }
        let hash = submit(&chain, &validators, "work after context archive repair");
        wait_until(
            &validators,
            Duration::from_secs(30),
            "work after replay",
            || committed_everywhere(&validators, hash),
        );
        shutdown(validators);
        assert_same_certified_blocks(&disks, 3);
        // Neither genesis nor a later record may be repaired by overwriting conflicts.
        for (index, (file, original)) in records[..2].iter().enumerate() {
            let mut corrupt = original.clone();
            corrupt[0] ^= 1;
            std::fs::write(file, &corrupt).unwrap();
            let state = empty_state(&chain.chain_id, &chain.genesis, &disks[0].kura);
            let result = prepare(PrepareInputs {
                state: Arc::clone(&state),
                events: tokio::sync::broadcast::channel(16).0,
                genesis: Some(chain.genesis.clone()),
                genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
                consensus_mode: ConsensusMode::Permissioned,
            });
            if index == 0 {
                assert!(matches!(
                    result,
                    Err(NodeError::Startup(StartupError::Local(_)))
                ));
                assert_eq!(
                    state.view().height(),
                    0,
                    "failed original genesis archive cannot expose State"
                );
            } else {
                assert!(matches!(result, Err(NodeError::Replay { height: 2, .. })));
            }
            assert_eq!(std::fs::read(file).unwrap(), corrupt);
            std::fs::write(file, original).unwrap();
        }
    }

    /// Replay checks every stored block against its certified result (§12.1): a certificate
    /// whose result differs from re-execution stops the replay.
    #[test]
    fn replay_rejects_a_block_whose_certified_result_differs() {
        let chain = chain(4, 200);
        let disks = disks(&chain);
        let validators = start_all(&chain, &disks, true);
        let hash = submit(&chain, &validators, "certified replay input");
        wait_until(
            &validators,
            Duration::from_secs(30),
            "replay input committed",
            || committed_everywhere(&validators, hash),
        );
        shutdown(validators);
        let kura = Arc::clone(&disks[0].kura);
        let state = empty_state(&chain.chain_id, &chain.genesis, &kura);
        let (genesis, certificate, _) = startup::stored_genesis(&state)
            .expect("valid stored genesis projection")
            .expect("stored genesis");
        let tip = startup::apply_genesis(
            &state,
            genesis,
            &SAMPLE_GENESIS_ACCOUNT_ID,
            ConsensusMode::Permissioned,
            Some(&certificate),
        )
        .expect("genesis re-executes");
        let crypto = Arc::new(BlsCrypto::new());
        let shared: SharedCrypto = crypto.clone();
        let instance = instance_id(
            &*crypto,
            &tip.block_hash,
            chain.chain_id.to_string().as_bytes(),
            InstanceKind::Global,
            0,
        );
        let availability = Arc::new(
            super::super::runtime_availability::NativeGlobalAvailability::new(
                Arc::clone(&state),
                instance,
                Arc::clone(&crypto),
            )
            .expect("availability authority bound to original applied genesis"),
        );
        let staging = Staging::new();
        let blocks = KuraBlockStore::new(
            kura,
            shared,
            GENESIS_HEIGHT,
            staging.clone(),
            state.ivm_execution_budget(),
            availability,
        );
        let mut executor = StateExecutor::spawn(ExecutorContext {
            state: Arc::clone(&state),
            native_context_archive: Arc::new(
                crate::query::native_context_archive::NativeContextArchive::open(
                    state.kura(),
                    state.ivm_execution_budget(),
                    state.kura().native_context_archive_max_bytes(),
                )
                .expect("original-pool native context archive"),
            ),
            queue: None,
            staging,
            events: tokio::sync::broadcast::channel(16).0,
            genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
            consensus_mode: ConsensusMode::Permissioned,
            applied: (GENESIS_HEIGHT, tip.block_hash),
            crypto: Some(Arc::clone(&crypto)),
            applied_watch: Arc::new(crate::sumeragi::lanes::global::AppliedWatch::new(
                GENESIS_HEIGHT,
                state.view().latest_block_hash(),
            )),
            lane_blocks: std::sync::Arc::new(crate::sumeragi::lanes::merge::NoLanes),
        })
        .expect("executor");
        admit_window(&state, &crypto, GENESIS_HEIGHT).expect("authenticated schedule admission");
        // Metadata is not available body custody. Restore the original payload/frame
        // through the independent genesis-bound schedule and complete stored-body checks.
        let (body, commit_qc) = blocks
            .committed_body(2)
            .expect("authenticate and restore height 2 from original storage")
            .expect("height 2 stored");
        assert_eq!(body.source().instance(), instance);
        assert_eq!(body.source().height(), 2);
        let mut forged = commit_qc.clone();
        forged.result = Hash32([0xAB; 32]);
        // This negative must reach execution comparison, not fail earlier on a stale
        // signature. The original committee signs the wrong result over the real block.
        use iroha_sumeragi::crypto::{Crypto as _, Signer as _};
        let committee = schedule::scheduled_committee(state.view().world(), 2)
            .expect("authenticated original committee");
        let preimage = forged.preimage();
        let signatures = forged
            .signers
            .ones()
            .map(|index| {
                let member = &committee[usize::try_from(index).expect("committee index")];
                let key = chain
                    .keys
                    .iter()
                    .find(|key| key.public_key() == member.public_key())
                    .expect("original validator custody");
                KeyPairSigner::new(key)
                    .expect("original BLS signer")
                    .sign(&preimage)
            })
            .collect::<Vec<_>>();
        forged.agg_sig = crypto.aggregate(&signatures);
        let error = executor
            .replay(&body, &forged)
            .expect_err("a differing certified result");
        assert!(
            matches!(&error, super::super::driver::traits::PublicationError::Retryable(reason) if reason.contains("diverges")),
            "{error}"
        );
        assert_eq!(startup::applied_height(&state), GENESIS_HEIGHT);
        // The stored certificate replays.
        executor
            .replay(&body, &commit_qc)
            .expect("the certified result reproduces");
        assert_eq!(startup::applied_height(&state), 2);
        {
            use iroha_allocation::{AllocationBudget, AllocationRefusal};
            use std::task::{Context, Waker};

            let _epoch = crossbeam_epoch::pin();
            let budget = state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let occupied = budget
                .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                .unwrap();
            let error = NodeError::Replay {
                height: 2,
                reason: ReplayError::Execution(
                    executor
                        .replay(&body, &commit_qc)
                        .expect_err("completed replay still needs original-pool encoding scratch"),
                ),
            };
            let NodeError::Replay {
                reason:
                    ReplayError::Execution(super::super::driver::traits::PublicationError::Deferred(
                        source,
                    )),
                ..
            } = &error
            else {
                panic!("serialized replay erased its original refusal: {error}");
            };
            let refusal = source.allocation_refusal().unwrap();
            let AllocationRefusal::Capacity {
                requested_bytes, ..
            } = refusal
            else {
                panic!("actual occupied State pool: {refusal}");
            };
            assert_eq!(
                refusal,
                &budget.try_reserve_bytes(*requested_bytes).unwrap_err()
            );
            let release = source.release_wait().unwrap();
            let mut context = Context::from_waker(Waker::noop());
            assert!(registration.poll_wait(release, &mut context).is_pending());
            let foreign = AllocationBudget::new(1);
            drop(foreign.try_reserve_bytes(1).unwrap());
            assert!(registration.poll_wait(release, &mut context).is_pending());
            drop(occupied);
            assert!(registration.poll_wait(release, &mut context).is_ready());
            registration.cancel();
            executor
                .replay(&body, &commit_qc)
                .expect("actual source release preserves the original completion");
            assert_eq!(startup::applied_height(&state), 2);
        }
        // Even a deployment without SoraFS archives binds its empty capture
        // catalog after replay. A completed replay receipt is no live overlay
        // and must retire before this same-worker startup handoff.
        executor
            .attach_finalized_archives(super::super::executor::FinalizedArchives::default())
            .expect("completed replay permits the once-only archive handoff");
        assert!(
            executor
                .attach_finalized_archives(super::super::executor::FinalizedArchives::default())
                .is_err(),
            "replay retirement must preserve once-only archive custody"
        );
    }

    #[test]
    fn every_committed_block_contains_work_before_and_after_restart() {
        // Explicit queue notifications must bypass even a long rebuild retry interval.
        let chain = chain(4, 600_000);
        let disks = disks(&chain);
        let validators = start_all(&chain, &disks, true);
        for index in 0..3 {
            let hash = submit(&chain, &validators, &format!("before restart {index}"));
            wait_until(
                &validators,
                Duration::from_secs(30),
                &format!("transaction {index} before restart commits"),
                || committed_everywhere(&validators, hash),
            );
        }
        let heights = committed_heights(&validators);
        assert_eq!(heights, vec![4; 4]);
        // Applied transactions leave every queue.
        wait_until(
            &validators,
            Duration::from_secs(10),
            "queues drained",
            || {
                validators
                    .iter()
                    .all(|validator| validator.queue.queued_len() == 0)
            },
        );
        shutdown(validators);
        let committed = disks
            .iter()
            .map(|disk| disk.kura.blocks_count())
            .min()
            .expect("validators");
        assert_same_certified_blocks(&disks, committed);
        let validators = start_all(&chain, &disks, false);
        let hash = submit(&chain, &validators, "after restart");
        wait_until(
            &validators,
            Duration::from_secs(30),
            "transaction committed",
            || committed_everywhere(&validators, hash),
        );
        shutdown(validators);
        assert_same_certified_blocks(&disks, 5);
    }
}
