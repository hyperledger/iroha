//! Finite canonical replay into one isolated destination, from original startup inputs.
//!
//! There is no imported State checkpoint, signer, transaction builder or work journal here.
//! The FASTPQ worker retains this continuation and its original source while unavailable.

use super::*;
use crate::{
    execution_attempt::ExecutionAttemptError as Attempt,
    kura::Kura,
    state::{IsolatedReplayStateError, LaneLifecycleError, World, WorldConstructionError},
};
use iroha_config::parameters::actual as config;
use iroha_data_model::Registrable as _;
use iroha_sumeragi::{availability::AvailableBody, message::Qc};
use std::io;

/// Refusal to capture original empty-State replay inputs at actual startup.
#[derive(Debug, thiserror::Error)]
pub enum NativeReplaySeedError {
    /// The original State could not be observed once.
    #[error(transparent)]
    View(#[from] crate::state::StateViewError),
    /// A seed can be captured only before genesis, never from current World state.
    #[error("replay seed requires original pre-genesis State")]
    NotEmpty,
}

/// Original pre-genesis input identity and public policy snapshots.
/// Fields are private; no codec, clone or checkpoint importer exists. The node
/// captures this before its first native prepare. No World rows or signing keys
/// are retained. Live source Kura is used only by canonical readers.
pub struct NativeReplaySeed {
    source: Arc<Kura>,
    budget: iroha_allocation::AllocationBudget,
    chain: iroha_model_base::chain::ChainId,
    network: iroha_data_model::NetworkId,
    genesis_account: AccountId,
    consensus_mode: ConsensusMode,
    kura_config: config::Kura,
    pipeline: config::Pipeline,
    zk: config::Zk,
    crypto: Arc<config::Crypto>,
    nexus: config::Nexus,
    oracle: config::Oracle,
    fraud: config::FraudMonitoring,
    governance: config::Governance,
    content: config::Content,
    settlement: config::Settlement,
    manifests: crate::governance::manifest::LaneManifestRegistryHandle,
    compliance: Option<Arc<crate::compliance::LaneComplianceEngine>>,
}
impl NativeReplaySeed {
    /// Capture only the actual original startup policy and immutable input owner.
    /// Signed genesis is subsequently read from this same Kura and checked against
    /// this exact configured security identity. No current World is copied.
    ///
    /// # Errors
    /// A nonempty/restored State or original State-view refusal.
    pub fn capture(
        state: &State,
        kura_config: config::Kura,
        genesis_account: AccountId,
        consensus_mode: ConsensusMode,
    ) -> Result<Self, NativeReplaySeedError> {
        let view = state.try_view_once()?;
        if view.height() != 0
            || view.native_execution_tip().is_some()
            || state.nexus_runtime_restored_from_snapshot()
        {
            return Err(NativeReplaySeedError::NotEmpty);
        }
        drop(view);
        Ok(Self {
            source: state.kura_handle(),
            budget: state.ivm_execution_budget(),
            chain: state.chain_id_ref().clone(),
            network: *state.network_id_ref(),
            genesis_account,
            consensus_mode,
            kura_config,
            pipeline: state.installed_pipeline().clone(),
            zk: state.installed_zk().clone(),
            crypto: state.crypto(),
            nexus: state.nexus_snapshot(),
            oracle: state.oracle.clone(),
            fraud: state.fraud_monitoring.clone(),
            governance: state.gov.clone(),
            content: state.content.clone(),
            settlement: state.settlement,
            manifests: state.lane_manifests.read().clone(),
            compliance: state.lane_compliance_engine(),
        })
    }

    pub(crate) fn belongs_to(&self, state: &State) -> bool {
        Arc::ptr_eq(&self.source, &state.kura_handle())
            && self.budget.same_pool(&state.ivm_execution_budget())
            && self.chain == *state.chain_id_ref()
            && self.network == *state.network_id_ref()
    }

    // A failed initial bootstrap publishes only into its own disposable Kura.
    // Rebuilding that unfinished local seed cannot change the original source.
    pub(crate) fn begin(
        &self,
        target: &super::super::certified_chain::AuthenticatedExecutionBlock,
        deadline: Instant,
    ) -> Result<IsolatedNativeReplay, IsolatedReplayError> {
        check_replay_deadline(deadline)?;
        let exact_target = ReplayTarget::from_native(target);
        let target = target.committed();
        if target.height() == 0 || target.commitment().schedule.current.network_id != self.network {
            return Err(IsolatedReplayError::Identity(
                "replay target differs from startup network",
            ));
        }
        let _observations = crate::status::isolate_replay_observations();
        let genesis = self
            .source
            .get_block(std::num::NonZeroUsize::MIN, &self.budget)?
            .ok_or(IsolatedReplayError::Identity(
                "original signed genesis is missing",
            ))?;
        if genesis.hash() != self.network.into_genesis_hash() {
            return Err(IsolatedReplayError::Identity(
                "original genesis differs from startup pin",
            ));
        }
        check_replay_deadline(deadline)?;
        let kura = Kura::new_temporary_with_configured_lane_catalog(
            &self.kura_config,
            &self.nexus.lane_config,
            &self.nexus.configured_lane_catalog,
        )?;
        // The canonical store owns serialization, certificates and exact-byte
        // idempotency. No original source destination is ever opened for writing.
        kura.store_block(genesis.clone())?;
        let account = iroha_data_model::account::Account::new(self.genesis_account.clone())
            .build(&self.genesis_account);
        let domain =
            iroha_data_model::domain::Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone())
                .build(&self.genesis_account);
        let mut world = World::try_with_execution_budget([domain], [account], [], &self.budget)?;
        crate::sns::seed_genesis_alias_bootstrap(
            &mut world,
            &genesis,
            &self.nexus.dataspace_catalog,
        )?;
        let query = crate::query::store::LiveQueryStore::from_config(
            Default::default(),
            iroha_futures::supervisor::ShutdownSignal::new(),
        )
        .into_inert_handle();
        let mut state = State::try_new_for_isolated_replay(
            self.budget.clone(),
            world,
            kura,
            query,
            self.chain.clone(),
            self.network,
            self.pipeline.clone(),
        )?;
        state.install_node_zk(self.zk.clone())?;
        state.install_crypto_snapshot_for_isolated_replay((*self.crypto).clone());
        state.set_oracle(self.oracle.clone());
        state.install_node_fraud_monitoring(self.fraud.clone());
        state.set_gov(self.governance.clone());
        state.content = self.content.clone();
        state.set_settlement(self.settlement);
        state.install_materialized_lane_manifests_for_catalog(
            &self.manifests,
            &self.nexus.lane_catalog,
            &self.nexus.governance,
        )?;
        state.install_lane_compliance_engine(self.compliance.clone());
        state.prepare_configured_primary_geometry_anchor(&self.nexus.configured_lane_catalog)?;
        state.restore_kura_lane_segments_before_startup_replay()?;
        state.set_nexus_from_config(self.nexus.clone())?;
        // The new State's tiered backend is disabled and has no configured external
        // paths; no live tiered directory, signer, runtime or query route is attached.
        let state = Arc::new(state);
        let (events, _) = tokio::sync::broadcast::channel(1);
        check_replay_deadline(deadline)?;
        let prepared = prepare_genesis(
            PrepareInputs {
                state: Arc::clone(&state),
                events,
                genesis: None,
                genesis_account: self.genesis_account.clone(),
                consensus_mode: self.consensus_mode,
            },
            Some((self.source.store_root().join("lanes"), target.height())),
        )?;
        check_replay_deadline(deadline)?;
        let scope = state
            .try_view_once()?
            .native_execution_tip()
            .ok_or(IsolatedReplayError::Identity(
                "replayed genesis omitted native execution",
            ))?
            .root_scope();
        let availability = Arc::new(
            super::super::runtime_availability::NativeGlobalAvailability::new(
                Arc::clone(&state),
                prepared.instance,
                Arc::clone(&prepared.crypto),
            )?,
        );
        let source = KuraBlockStore::new(
            Arc::clone(&self.source),
            prepared.crypto.clone(),
            GENESIS_HEIGHT,
            scope,
            Staging::new(),
            self.budget.clone(),
            availability,
        );
        Ok(IsolatedNativeReplay {
            prepared,
            source,
            pending: None,
            next: GENESIS_HEIGHT + 1,
            scope,
            target: exact_target,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IsolatedReplayError {
    #[error("isolated replay step deadline expired")]
    Deadline,
    #[error("isolated replay source: {0}")]
    Identity(&'static str),
    #[error(transparent)]
    View(#[from] crate::state::StateViewError),
    #[error(transparent)]
    Read(#[from] Attempt<io::Error>),
    #[error(transparent)]
    Kura(#[from] crate::kura::Error),
    #[error(transparent)]
    KuraRead(#[from] Attempt<crate::kura::Error>),
    #[error(transparent)]
    World(#[from] WorldConstructionError),
    #[error(transparent)]
    State(#[from] IsolatedReplayStateError),
    #[error(transparent)]
    Sns(#[from] crate::sns::SnsError),
    #[error(transparent)]
    Pipeline(#[from] crate::pipeline_validity_policy::PipelineValidityPolicyError),
    #[error(transparent)]
    Zk(#[from] crate::state::ZkConfigInstallError),
    #[error(transparent)]
    Lifecycle(#[from] LaneLifecycleError),
    #[error(transparent)]
    Startup(#[from] NodeError),
    #[error(transparent)]
    Execution(#[from] super::super::driver::traits::PublicationError),
    #[error(transparent)]
    WorldRoot(#[from] crate::state::WorldStateVerificationError),
}

/// Exact completed isolated replay transport, still untrusted by FASTPQ until
/// the original source reader joins the complete tape to its independent target.
pub(crate) struct ReplayedNativeTransport {
    kura: Arc<Kura>,
    target: ReplayTarget,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct ReplayTarget {
    height: u64,
    carrier: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
    core: Hash32,
    result: Hash32,
    scope: iroha_data_model::block::consensus::SumeragiRootScope,
}
impl ReplayTarget {
    fn from_native(native: &super::super::certified_chain::AuthenticatedExecutionBlock) -> Self {
        let target = native.committed();
        Self {
            height: target.height(),
            carrier: target.block_hash(),
            core: target.core_hash(),
            result: target.result(),
            scope: target.root_scope(),
        }
    }
}
impl ReplayedNativeTransport {
    pub(crate) fn into_for(
        self,
        native: &super::super::certified_chain::AuthenticatedExecutionBlock,
    ) -> Result<Arc<Kura>, IsolatedReplayError> {
        if self.target != ReplayTarget::from_native(native) || !self.kura.is_temporary_staging() {
            return Err(IsolatedReplayError::Identity(
                "completed replay transport differs from original target",
            ));
        }
        Ok(self.kura)
    }
}

/// The existing startup executor, retained at one exact next height. Its source
/// KuraBlockStore only reads; its prepared owner only publishes into temporary Kura.
pub(crate) struct IsolatedNativeReplay {
    prepared: Prepared,
    source: KuraBlockStore,
    pending: Option<(AvailableBody, Qc)>,
    next: u64,
    target: ReplayTarget,
    scope: iroha_data_model::block::consensus::SumeragiRootScope,
}
impl IsolatedNativeReplay {
    /// Cooperative finite continuation. The caller retains the original target,
    /// deadline and refusal. No intermediate height is a FASTPQ cursor completion.
    pub(crate) fn advance(
        &mut self,
        target: &super::super::certified_chain::AuthenticatedExecutionBlock,
        deadline: Instant,
        maximum_steps: usize,
    ) -> Result<Option<ReplayedNativeTransport>, IsolatedReplayError> {
        if ReplayTarget::from_native(target) != self.target {
            return Err(IsolatedReplayError::Identity(
                "replay target changed during continuation",
            ));
        }
        let target = target.committed();
        if maximum_steps == 0
            || maximum_steps > 64
            || target.height() == 0
            || target.root_scope() != self.scope
            || target.commitment().schedule.current.network_id
                != *self.prepared.state.network_id_ref()
            || target.height() < self.next - 1
        {
            return Err(IsolatedReplayError::Identity(
                "target differs from original replay source",
            ));
        }
        for _ in 0..maximum_steps {
            if Instant::now() >= deadline {
                return Err(IsolatedReplayError::Deadline);
            }
            if self.next > target.height() {
                break;
            }
            if self.pending.is_none() {
                self.pending = Some(self.source.committed_body(self.next)?.ok_or(
                    IsolatedReplayError::Identity("committed original replay frame missing"),
                )?);
            }
            let (body, qc) = self.pending.as_ref().expect("original next replay body");
            if self.prepared.executor.prepare_replay(body, qc)? != Some(qc.result) {
                return Err(IsolatedReplayError::Identity(
                    "canonical replay differs from certified result",
                ));
            }
            if Instant::now() >= deadline {
                return Err(IsolatedReplayError::Deadline);
            }
            // Same canonical append and serialized publication as live/native
            // startup. The exact staged executed block, not a copied source, is durable.
            self.prepared.blocks.append(body, qc)?;
            self.prepared.executor.replay(body, qc)?;
            self.next = self
                .next
                .checked_add(1)
                .ok_or(IsolatedReplayError::Identity("replay height exhausted"))?;
            self.pending = None;
        }
        if Instant::now() >= deadline {
            return Err(IsolatedReplayError::Deadline);
        }
        if self.next <= target.height() {
            return Ok(None);
        }
        {
            let view = self.prepared.state.try_view_once()?;
            let tip = view
                .native_execution_tip()
                .ok_or(IsolatedReplayError::Identity(
                    "replay has no applied native result",
                ))?;
            if tip.height() != target.height()
                || tip.iroha_hash() != target.block_hash()
                || tip.core_hash() != target.core_hash()
                || tip.result() != target.result()
                || tip.root_scope() != target.root_scope()
                || view.latest_block_hash() != Some(target.block_hash())
            {
                return Err(IsolatedReplayError::Identity(
                    "replayed cut differs from independently authenticated target",
                ));
            }
        }
        self.prepared.state.verify_world_state_accumulator()?;
        if Instant::now() >= deadline {
            return Err(IsolatedReplayError::Deadline);
        }
        Ok(Some(ReplayedNativeTransport {
            kura: self.prepared.state.kura_handle(),
            target: self.target,
        }))
    }
}

fn check_replay_deadline(deadline: Instant) -> Result<(), IsolatedReplayError> {
    if Instant::now() >= deadline {
        Err(IsolatedReplayError::Deadline)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn original_source_fixture_for_test(
    seed_count: usize,
) -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    Vec<NativeReplaySeed>,
    iroha_data_model::asset::AssetId,
) {
    tests::fixture_with_seeds(seed_count)
}
