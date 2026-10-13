//! Actor responsible for configuration state and its dynamic updates.
//!
//! Currently the API exposed by [`KisoHandle`] works only with [`Configuration`], because no any
//! part of Iroha is interested in the whole state. However, the API could be extended in future.
//!
//! Mutable node-local settings publish committed snapshots through
//! [`tokio::sync::watch`] channels. Runtime-validated `SoraNet` updates use an
//! acknowledged request channel before publication.
//! Consensus-relevant settings, including confidential gas, are deliberately absent
//! from the runtime update surface.
use eyre::Result;
use hex;
use iroha_config::{
    base::WithOrigin,
    parameters::actual::{
        Logger as LoggerConfig, NoritoRpcStage, Root as Config,
        SoranetHandshake as ActualSoranetHandshake, SoranetPow,
    },
};
use iroha_futures::supervisor::{Child, OnShutdown};
use iroha_torii_shared::configuration::{
    Configuration, ConfigurationUpdate, Logger, NetworkAcl, ResumeHashDirective,
    SoranetHandshakePowUpdate, SoranetHandshakeUpdate, TransportUpdate,
};
use std::{num::NonZeroU32, time::Duration};
use tokio::sync::{mpsc, oneshot, watch};
const DEFAULT_CHANNEL_SIZE: usize = 32;
/// Handle to work with the actor.
///
/// The actor will shutdown when all its handles are dropped.
#[derive(Clone)]
pub struct KisoHandle {
    actor: mpsc::Sender<Message>,
}
impl KisoHandle {
    /// Spawn a new actor
    pub fn start(state: Config) -> (Self, Child) {
        let (actor_sender, actor_receiver) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let initial_logger = state.logger.clone();
        let initial_acl = Actor::snapshot_network_acl(&state);
        let (logger_update, _) = watch::channel(initial_logger);
        let (network_acl_update, _) = watch::channel(initial_acl);
        let initial_handshake = state.network.soranet_handshake.clone();
        let (soranet_handshake_update, _) = watch::channel(initial_handshake);
        // The verification gas schedule is consensus policy: the committed ZK validity
        // policy or the protocol default installs it (`State::install_node_zk` and block
        // construction). A node configuration holds no schedule.
        let mut actor = Actor {
            handle: actor_receiver,
            state,
            logger_update,
            network_acl_update,
            soranet_handshake_update,
            soranet_handshake_applier: None,
        };
        (
            Self {
                actor: actor_sender,
            },
            Child::new(
                tokio::spawn(async move { actor.run().await }),
                OnShutdown::Abort,
            ),
        )
    }
    /// Fetch the [`Configuration`] from the actor's state.
    ///
    /// # Errors
    /// If communication with actor fails.
    pub async fn get_dto(&self) -> Result<Configuration, Error> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::GetDTO { respond_to: tx };
        let _ = self.actor.send(msg).await;
        let dto = rx.await?;
        Ok(dto)
    }
    /// Update the configuration state and notify subscribers.
    ///
    /// The response is returned only after local validation and the registered
    /// runtime applier, if any, has accepted the update.
    ///
    /// # Errors
    /// If communication with actor fails.
    pub async fn update_with_dto(&self, dto: ConfigurationUpdate) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::UpdateWithDTO {
            dto: Box::new(dto),
            respond_to: tx,
        };
        let _ = self.actor.send(msg).await;
        rx.await?
    }
    /// Subscribe on updates of `logger.level` parameter.
    ///
    /// # Errors
    /// If communication with actor fails.
    pub async fn subscribe_on_logger_updates(
        &self,
    ) -> Result<watch::Receiver<LoggerConfig>, Error> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::SubscribeOnLogLevel { respond_to: tx };
        let _ = self.actor.send(msg).await;
        let receiver = rx.await?;
        Ok(receiver)
    }
    /// Subscribe on updates of network ACL settings.
    ///
    /// # Errors
    /// Returns an error if communication with the actor fails.
    pub async fn subscribe_on_network_acl_updates(
        &self,
    ) -> Result<watch::Receiver<NetworkAcl>, Error> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::SubscribeOnNetworkAcl { respond_to: tx };
        let _ = self.actor.send(msg).await;
        let receiver = rx.await?;
        Ok(receiver)
    }
    /// Subscribe on updates of the `SoraNet` handshake configuration.
    ///
    /// # Errors
    /// Returns an error if communication with the actor fails.
    pub async fn subscribe_on_soranet_handshake_updates(
        &self,
    ) -> Result<watch::Receiver<ActualSoranetHandshake>, Error> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::SubscribeOnSoranetHandshake { respond_to: tx };
        let _ = self.actor.send(msg).await;
        let receiver = rx.await?;
        Ok(receiver)
    }
    /// Register the single live `SoraNet` handshake runtime applier.
    ///
    /// Proposed handshake updates are sent through the returned receiver and
    /// are not committed until the receiver acknowledges their exact result.
    ///
    /// # Errors
    /// Returns an error if communication with the actor fails or an applier is
    /// already registered.
    pub async fn register_soranet_handshake_runtime_applier(
        &self,
    ) -> Result<mpsc::Receiver<SoranetHandshakeApplyRequest>, Error> {
        let (requests, receiver) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (respond_to, response) = oneshot::channel();
        let msg = Message::RegisterSoranetHandshakeApplier {
            requests,
            respond_to,
        };
        let _ = self.actor.send(msg).await;
        response.await??;
        Ok(receiver)
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Lightweight mock handle used in tests to avoid spinning up the full actor and watchers.
    ///
    /// The mock serves `get_dto` requests from the provided configuration snapshot and acknowledges
    /// updates/subscriptions with pre-seeded watch channels.
    pub fn mock(state: &Config) -> Self {
        let dto = Configuration::from(state);
        let (actor_sender, actor_receiver) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let logger = state.logger.clone();
        let network_acl = Actor::snapshot_network_acl(state);
        let soranet_handshake = state.network.soranet_handshake.clone();
        let mock_actor =
            run_mock_actor(actor_receiver, logger, network_acl, soranet_handshake, dto);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(mock_actor);
        } else {
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test Kiso mock runtime");
                runtime.block_on(mock_actor);
            });
        }
        Self {
            actor: actor_sender,
        }
    }
}
#[cfg(any(test, feature = "iroha-core-tests"))]
async fn run_mock_actor(
    mut actor_receiver: mpsc::Receiver<Message>,
    logger: LoggerConfig,
    network_acl: NetworkAcl,
    soranet_handshake: ActualSoranetHandshake,
    dto: Configuration,
) {
    let (logger_tx, _) = watch::channel(logger);
    let (network_acl_tx, _) = watch::channel(network_acl);
    let (handshake_tx, _) = watch::channel(soranet_handshake);
    let mut dto_snapshot = dto;
    let mut soranet_handshake_applier = None;
    while let Some(msg) = actor_receiver.recv().await {
        match msg {
            Message::GetDTO { respond_to } => {
                let _ = respond_to.send(dto_snapshot.clone());
            }
            Message::UpdateWithDTO { dto, respond_to } => {
                // Update the exposed Norito-RPC summary if provided; ignore the rest to
                // keep the mock lightweight.
                if let Some(transport) = dto.transport.as_ref() {
                    if let Some(norito_rpc) = transport.norito_rpc.as_ref() {
                        if let Some(enabled) = norito_rpc.enabled {
                            dto_snapshot.transport.norito_rpc.enabled = enabled;
                        }
                        if let Some(stage) = norito_rpc.stage.as_ref() {
                            dto_snapshot.transport.norito_rpc.stage.clone_from(stage);
                        }
                        if let Some(require_mtls) = norito_rpc.require_mtls {
                            dto_snapshot.transport.norito_rpc.require_mtls = require_mtls;
                        }
                        if let Some(allowlist) = norito_rpc.allowed_clients.as_ref() {
                            dto_snapshot.transport.norito_rpc.canary_allowlist_size =
                                allowlist.len();
                        }
                    }
                }
                let _ = respond_to.send(Ok(()));
            }
            Message::SubscribeOnLogLevel { respond_to } => {
                let _ = respond_to.send(logger_tx.subscribe());
            }
            Message::SubscribeOnNetworkAcl { respond_to } => {
                let _ = respond_to.send(network_acl_tx.subscribe());
            }
            Message::SubscribeOnSoranetHandshake { respond_to } => {
                let _ = respond_to.send(handshake_tx.subscribe());
            }
            Message::RegisterSoranetHandshakeApplier {
                requests,
                respond_to,
            } => {
                let result = if soranet_handshake_applier.is_some() {
                    Err(Error::Validation(
                        "SoraNet handshake runtime applier is already registered".to_owned(),
                    ))
                } else {
                    soranet_handshake_applier = Some(requests);
                    Ok(())
                };
                let _ = respond_to.send(result);
            }
        }
    }
}
enum Message {
    GetDTO {
        respond_to: oneshot::Sender<Configuration>,
    },
    UpdateWithDTO {
        dto: Box<ConfigurationUpdate>,
        respond_to: oneshot::Sender<Result<(), Error>>,
    },
    SubscribeOnLogLevel {
        respond_to: oneshot::Sender<watch::Receiver<LoggerConfig>>,
    },
    SubscribeOnNetworkAcl {
        respond_to: oneshot::Sender<watch::Receiver<NetworkAcl>>,
    },
    SubscribeOnSoranetHandshake {
        respond_to: oneshot::Sender<watch::Receiver<ActualSoranetHandshake>>,
    },
    RegisterSoranetHandshakeApplier {
        requests: mpsc::Sender<SoranetHandshakeApplyRequest>,
        respond_to: oneshot::Sender<Result<(), Error>>,
    },
}
/// One proposed `SoraNet` handshake runtime update and its exact response.
#[derive(Debug)]
pub struct SoranetHandshakeApplyRequest {
    /// Candidate configuration staged by Kiso but not yet committed.
    pub handshake: ActualSoranetHandshake,
    /// Runtime acceptance or rejection of this exact candidate.
    pub respond_to: oneshot::Sender<std::result::Result<(), String>>,
}
/// Possible errors might occur while working with [`KisoHandle`]
#[derive(thiserror::Error, displaydoc::Display, Debug)]
pub enum Error {
    /// Failed to get actor's response
    Communication(#[from] oneshot::error::RecvError),
    /// Configuration validation failed: {0}
    Validation(String),
    /// SoraNet handshake runtime update failed: {0}
    SoranetHandshakeRuntime(String),
}
struct Actor {
    handle: mpsc::Receiver<Message>,
    state: Config,
    // Current implementation is somewhat not scalable in terms of code writing: for any
    // future dynamic parameter, it will require its own `subscribe_on_<field>` function in [`KisoHandle`],
    // new channel here, and new [`Message`] variant. If boilerplate expands, a more general solution will be
    // required. However, as of now a single manually written implementation seems optimal.
    logger_update: watch::Sender<LoggerConfig>,
    network_acl_update: watch::Sender<NetworkAcl>,
    soranet_handshake_update: watch::Sender<ActualSoranetHandshake>,
    soranet_handshake_applier: Option<mpsc::Sender<SoranetHandshakeApplyRequest>>,
}
impl Actor {
    async fn run(&mut self) {
        while let Some(msg) = self.handle.recv().await {
            self.handle_message(msg).await
        }
    }
    async fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::GetDTO { respond_to } => {
                let dto = Configuration::from(&self.state);
                let _ = respond_to.send(dto);
            }
            Message::UpdateWithDTO { dto, respond_to } => {
                let result = Box::pin(self.apply_config_update(*dto)).await;
                let _ = respond_to.send(result);
            }
            Message::SubscribeOnLogLevel { respond_to } => {
                let _ = respond_to.send(self.logger_update.subscribe());
            }
            Message::SubscribeOnNetworkAcl { respond_to } => {
                let _ = respond_to.send(self.network_acl_update.subscribe());
            }
            Message::SubscribeOnSoranetHandshake { respond_to } => {
                let _ = respond_to.send(self.soranet_handshake_update.subscribe());
            }
            Message::RegisterSoranetHandshakeApplier {
                requests,
                respond_to,
            } => {
                let result = if self.soranet_handshake_applier.is_some() {
                    Err(Error::Validation(
                        "SoraNet handshake runtime applier is already registered".to_owned(),
                    ))
                } else {
                    self.soranet_handshake_applier = Some(requests);
                    Ok(())
                };
                let _ = respond_to.send(result);
            }
        }
    }
    #[allow(clippy::too_many_lines)]
    async fn apply_config_update(&mut self, dto: ConfigurationUpdate) -> Result<(), Error> {
        let ConfigurationUpdate {
            logger,
            network_acl,
            network,
            soranet_handshake,
            transport,
            compute_pricing,
        } = dto;
        // Stage updates on a clone to keep the config update atomic.
        let mut next = self.state.clone();
        let mut notify_network_acl = false;
        let mut notify_soranet_handshake = false;
        let Logger { level, filter } = logger;
        next.logger.level = level;
        next.logger.filter = filter
            .map(|value| value.parse())
            .transpose()
            .map_err(|error| Error::Validation(format!("invalid logger filter: {error}")))?;
        if let Some(acl) = network_acl {
            let iroha_torii_shared::configuration::NetworkAcl {
                allowlist_only,
                allow_keys,
                deny_keys,
                allow_cidrs,
                deny_cidrs,
            } = acl;
            if let Some(b) = allowlist_only {
                next.network.allowlist_only = b;
            }
            if let Some(keys) = allow_keys {
                next.network.allow_keys = keys;
            }
            if let Some(keys) = deny_keys {
                next.network.deny_keys = keys;
            }
            if let Some(cidrs) = allow_cidrs {
                next.network.allow_cidrs = cidrs;
            }
            if let Some(cidrs) = deny_cidrs {
                next.network.deny_cidrs = cidrs;
            }
            notify_network_acl = true;
        }
        if let Some(network) = network {
            if let Some(value) = network.require_sm_handshake_match {
                if !value {
                    return Err(Error::Validation(
                        "SoraNet SM handshake matching is mandatory in the first-release policy"
                            .to_string(),
                    ));
                }
                next.network.require_sm_handshake_match = value;
            }
            if let Some(value) = network.require_sm_openssl_preview_match {
                if !value {
                    return Err(Error::Validation(
                        "SoraNet SM OpenSSL preview matching is mandatory in the first-release policy"
                            .to_string(),
                    ));
                }
                next.network.require_sm_openssl_preview_match = value;
            }
            if let Some(profile) = network.lane_profile {
                next.network.lane_profile = profile.into();
                let limits = next.network.lane_profile.derived_limits();
                next.network.max_incoming = limits.max_incoming;
                next.network.max_total_connections = limits.max_total_connections;
                next.network.low_priority_bytes_per_sec = limits.low_priority_bytes_per_sec;
                next.network.low_priority_rate_per_sec = limits.low_priority_rate_per_sec;
            }
        }
        if let Some(handshake_update) = soranet_handshake {
            Self::apply_soranet_handshake_update(
                &mut next.network.soranet_handshake,
                handshake_update,
            )
            .map_err(Error::Validation)?;
            notify_soranet_handshake = true;
        }
        if let Some(transport_update) = transport {
            Self::apply_transport_update(&mut next.torii.transport, transport_update)
                .map_err(Error::Validation)?;
        }
        if let Some(pricing_update) = compute_pricing {
            let mut compute = next.compute.clone();
            for (family, weights) in pricing_update.price_families {
                compute
                    .apply_price_update(&family, weights)
                    .map_err(|err| Error::Validation(err.to_string()))?;
            }
            if let Some(default_family) = pricing_update.default_price_family {
                if !compute.price_families.contains_key(&default_family) {
                    return Err(Error::Validation(format!(
                        "compute default_price_family `{default_family}` missing from price_families"
                    )));
                }
                compute.default_price_family = default_family;
            }
            next.compute = compute;
        }
        if notify_soranet_handshake {
            Self::apply_soranet_handshake_runtime(
                self.soranet_handshake_applier.clone(),
                next.network.soranet_handshake.clone(),
            )
            .await?;
        }
        self.state = next;
        let _ = self.logger_update.send_replace(self.state.logger.clone());
        if notify_network_acl {
            let snapshot = Self::snapshot_network_acl(&self.state);
            let _ = self.network_acl_update.send_replace(snapshot);
        }
        if notify_soranet_handshake {
            let _ = self
                .soranet_handshake_update
                .send_replace(self.state.network.soranet_handshake.clone());
        }
        Ok(())
    }
    async fn apply_soranet_handshake_runtime(
        applier: Option<mpsc::Sender<SoranetHandshakeApplyRequest>>,
        handshake: ActualSoranetHandshake,
    ) -> Result<(), Error> {
        let Some(applier) = applier else {
            return Err(Error::SoranetHandshakeRuntime(
                "runtime applier is not registered".to_owned(),
            ));
        };
        let (respond_to, response) = oneshot::channel();
        applier
            .send(SoranetHandshakeApplyRequest {
                handshake,
                respond_to,
            })
            .await
            .map_err(|_| {
                Error::SoranetHandshakeRuntime(
                    "runtime applier closed before accepting the update".to_owned(),
                )
            })?;
        response
            .await
            .map_err(|_| {
                Error::SoranetHandshakeRuntime(
                    "runtime applier closed before acknowledging the update".to_owned(),
                )
            })?
            .map_err(Error::SoranetHandshakeRuntime)
    }
    fn apply_soranet_handshake_update(
        handshake: &mut ActualSoranetHandshake,
        update: SoranetHandshakeUpdate,
    ) -> Result<(), String> {
        let decode_hex = |value: &str, field: &str| {
            hex::decode(value).map_err(|_| format!("invalid hex in {field}"))
        };
        if let Some(value) = update.descriptor_commit_hex {
            let bytes = decode_hex(&value, "descriptor_commit_hex")?;
            handshake.descriptor_commit = WithOrigin::inline(bytes);
        }
        if let Some(value) = update.client_capabilities_hex {
            let bytes = decode_hex(&value, "client_capabilities_hex")?;
            handshake.client_capabilities = WithOrigin::inline(bytes);
        }
        if let Some(value) = update.relay_capabilities_hex {
            let bytes = decode_hex(&value, "relay_capabilities_hex")?;
            handshake.relay_capabilities = WithOrigin::inline(bytes);
        }
        if let Some(value) = update.kem_id {
            handshake.kem_id = value;
        }
        if let Some(value) = update.sig_id {
            handshake.sig_id = value;
        }
        if let Some(resume) = update.resume_hash_hex {
            handshake.resume_hash = match resume {
                ResumeHashDirective::Set(hex_value) => {
                    let bytes = decode_hex(&hex_value, "resume_hash_hex")?;
                    Some(WithOrigin::inline(bytes))
                }
                ResumeHashDirective::Clear => None,
            };
        }
        if let Some(pow_update) = update.pow {
            Self::apply_pow_update(&mut handshake.pow, &pow_update)?;
        }
        Ok(())
    }
    fn apply_transport_update(
        transport: &mut iroha_config::parameters::actual::ToriiTransport,
        update: TransportUpdate,
    ) -> Result<(), String> {
        if let Some(norito_rpc_update) = update.norito_rpc {
            let cfg = &mut transport.norito_rpc;
            if let Some(value) = norito_rpc_update.enabled {
                cfg.enabled = value;
            }
            if let Some(value) = norito_rpc_update.require_mtls {
                cfg.require_mtls = value;
            }
            if let Some(clients) = norito_rpc_update.allowed_clients {
                cfg.allowed_clients = clients;
            }
            if let Some(stage_label) = norito_rpc_update.stage {
                let stage = NoritoRpcStage::parse(&stage_label).ok_or_else(|| {
                    format!(
                        "invalid transport.norito_rpc.stage `{stage_label}` (expected disabled|canary|ga)"
                    )
                })?;
                cfg.stage = stage;
            }
        }
        Ok(())
    }
    fn apply_pow_update(
        pow: &mut SoranetPow,
        update: &SoranetHandshakePowUpdate,
    ) -> Result<(), String> {
        if let Some(difficulty) = update.difficulty {
            if difficulty == 0 {
                return Err(
                    "SoraNet PoW difficulty must be greater than zero in the first-release policy"
                        .to_owned(),
                );
            }
            if difficulty > iroha_crypto::soranet::puzzle::MAX_DIFFICULTY {
                return Err(format!(
                    "SoraNet PoW difficulty {difficulty} exceeds the supported maximum {}",
                    iroha_crypto::soranet::puzzle::MAX_DIFFICULTY
                ));
            }
        }
        for (name, requested, active) in [
            (
                "outbound_mint_capacity",
                update.outbound_mint_capacity,
                pow.outbound_mint_capacity.get(),
            ),
            (
                "inbound_verify_capacity",
                update.inbound_verify_capacity,
                pow.inbound_verify_capacity.get(),
            ),
        ] {
            let Some(requested) = requested else { continue };
            if !(1..=SoranetPow::MAX_PUZZLE_WORK_CAPACITY_PER_DIRECTION).contains(&requested) {
                return Err(format!(
                    "SoraNet {name} must be in 1..={}",
                    SoranetPow::MAX_PUZZLE_WORK_CAPACITY_PER_DIRECTION
                ));
            }
            if requested != active {
                return Err(format!(
                    "SoraNet {name} cannot change while the network runtime is active; restart required"
                ));
            }
        }
        if let Some(puzzle_update) = &update.puzzle {
            if let Some(memory) = puzzle_update.memory_kib
                && !(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB
                    ..=iroha_crypto::soranet::puzzle::MAX_MEMORY_KIB)
                    .contains(&memory)
            {
                return Err(format!(
                    "SoraNet Argon2 memory_kib {memory} is outside the supported range {}..={}",
                    iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB,
                    iroha_crypto::soranet::puzzle::MAX_MEMORY_KIB
                ));
            }
            if let Some(time_cost) = puzzle_update.time_cost
                && !(1..=iroha_crypto::soranet::puzzle::MAX_TIME_COST).contains(&time_cost)
            {
                return Err(format!(
                    "SoraNet Argon2 time_cost {time_cost} is outside the supported range 1..={}",
                    iroha_crypto::soranet::puzzle::MAX_TIME_COST
                ));
            }
            if let Some(lanes) = puzzle_update.lanes
                && !(1..=iroha_crypto::soranet::puzzle::MAX_LANES).contains(&lanes)
            {
                return Err(format!(
                    "SoraNet Argon2 lanes {lanes} is outside the supported range 1..={}",
                    iroha_crypto::soranet::puzzle::MAX_LANES
                ));
            }
        }
        if let Some(difficulty) = update.difficulty {
            pow.difficulty = difficulty;
        }
        if let Some(secs) = update.max_future_skew_secs {
            pow.max_future_skew = Duration::from_secs(secs);
        }
        if let Some(secs) = update.min_ticket_ttl_secs {
            pow.min_ticket_ttl = Duration::from_secs(secs);
        }
        if let Some(secs) = update.ticket_ttl_secs {
            pow.ticket_ttl = Duration::from_secs(secs);
        }
        if let Some(puzzle_update) = &update.puzzle {
            if let Some(memory) = puzzle_update.memory_kib {
                pow.puzzle.memory_kib =
                    NonZeroU32::new(memory).expect("validated puzzle memory is non-zero");
            }
            if let Some(time_cost) = puzzle_update.time_cost {
                pow.puzzle.time_cost =
                    NonZeroU32::new(time_cost).expect("validated puzzle time cost is non-zero");
            }
            if let Some(lanes) = puzzle_update.lanes {
                pow.puzzle.lanes =
                    NonZeroU32::new(lanes).expect("validated puzzle lane count is non-zero");
            }
        }
        Ok(())
    }
    fn snapshot_network_acl(state: &Config) -> NetworkAcl {
        NetworkAcl {
            allowlist_only: Some(state.network.allowlist_only),
            allow_keys: Some(state.network.allow_keys.clone()),
            deny_keys: Some(state.network.deny_keys.clone()),
            allow_cidrs: Some(state.network.allow_cidrs.clone()),
            deny_cidrs: Some(state.network.deny_cidrs.clone()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::{
        base::WithOrigin,
        parameters::{
            actual::{
                Acceleration, BlockSync, Common, Concurrency, Confidential, Connect,
                DataspaceGossip, FraudMonitoring, Genesis, Governance, IsoBridge, Ivm, Kura,
                LiveQueryStore, Logger, Network, Nexus, Queue, Root, Settlement,
                SoranetHandshake as ActualSoranetHandshake, SoranetPow, SoranetPrivacy, Streaming,
                Sumeragi, TieredState, Torii, TransactionGossiper, TrustedPeers,
            },
            defaults,
        },
    };
    use iroha_crypto::{
        Algorithm, Hash, HashOf, KeyPair,
        soranet::handshake::{
            DEFAULT_CLIENT_CAPABILITIES, DEFAULT_DESCRIPTOR_COMMIT, DEFAULT_RELAY_CAPABILITIES,
        },
        streaming::StreamingKeyMaterial,
    };
    use iroha_data_model::{
        block::BlockHeader, peer::Peer, sorafs::pricing::PricingScheduleRecord,
    };
    use iroha_logger::Level;
    use iroha_model_base::chain::ChainId;
    use iroha_primitives::addr::socket_addr;
    use iroha_torii_shared::configuration::{
        ComputePricingUpdate, Logger as LoggerDTO, NetworkUpdate, SoranetHandshakePuzzleUpdate,
    };
    use std::{
        num::{NonZeroU32, NonZeroU64, NonZeroUsize},
        path::PathBuf,
        time::Duration,
    };
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("Kiso fixture key generation should succeed")
    }
    fn checked_soranet_transport_keypair() -> KeyPair {
        KeyPair::try_from_seed(
            b"iroha:kiso:test:soranet-transport:v1".to_vec(),
            Algorithm::Ed25519,
        )
        .expect("Kiso SoraNet transport fixture key generation should succeed")
    }
    fn checked_public_key() -> iroha_crypto::PublicKey {
        checked_keypair().public_key().clone()
    }
    #[test]
    fn checked_keypair_preserves_default_algorithm() {
        assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    }
    #[test]
    fn pow_updates_reject_unbounded_costs_before_mutating_state() {
        fn update(
            difficulty: Option<u8>,
            memory_kib: Option<u32>,
            time_cost: Option<u32>,
            lanes: Option<u32>,
        ) -> SoranetHandshakePowUpdate {
            SoranetHandshakePowUpdate {
                difficulty,
                max_future_skew_secs: Some(999),
                min_ticket_ttl_secs: None,
                ticket_ttl_secs: None,
                outbound_mint_capacity: None,
                inbound_verify_capacity: None,
                puzzle: Some(SoranetHandshakePuzzleUpdate {
                    memory_kib,
                    time_cost,
                    lanes,
                }),
            }
        }
        let invalid = [
            (update(Some(0), None, None, None), "difficulty"),
            (
                update(
                    Some(iroha_crypto::soranet::puzzle::MAX_DIFFICULTY + 1),
                    None,
                    None,
                    None,
                ),
                "difficulty",
            ),
            (
                update(
                    None,
                    Some(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB - 1),
                    None,
                    None,
                ),
                "memory_kib",
            ),
            (
                update(
                    None,
                    Some(iroha_crypto::soranet::puzzle::MAX_MEMORY_KIB + 1),
                    None,
                    None,
                ),
                "memory_kib",
            ),
            (
                update(
                    None,
                    None,
                    Some(iroha_crypto::soranet::puzzle::MAX_TIME_COST + 1),
                    None,
                ),
                "time_cost",
            ),
            (
                update(
                    None,
                    None,
                    None,
                    Some(iroha_crypto::soranet::puzzle::MAX_LANES + 1),
                ),
                "lanes",
            ),
        ];
        for (update, field) in invalid {
            let mut pow = SoranetPow::default();
            let original_difficulty = pow.difficulty;
            let original_skew = pow.max_future_skew;
            let original_puzzle = pow.puzzle;
            let error = Actor::apply_pow_update(&mut pow, &update)
                .expect_err("unbounded puzzle update must fail");
            assert!(error.contains(field), "unexpected error: {error}");
            assert_eq!(pow.difficulty, original_difficulty);
            assert_eq!(pow.max_future_skew, original_skew);
            assert_eq!(pow.puzzle, original_puzzle);
        }
        let mut pow = SoranetPow::default();
        let original_outbound_mint_capacity = pow.outbound_mint_capacity.get();
        let mut update = update(None, None, None, None);
        update.outbound_mint_capacity = Some(if original_outbound_mint_capacity == 1 {
            2
        } else {
            1
        });
        let error = Actor::apply_pow_update(&mut pow, &update)
            .expect_err("live puzzle-work capacity change must require restart");
        assert!(
            error.contains("restart required"),
            "unexpected error: {error}"
        );
        assert_eq!(
            pow.outbound_mint_capacity.get(),
            original_outbound_mint_capacity
        );
    }
    #[allow(clippy::too_many_lines)]
    fn test_config() -> Root {
        // Minimal, self-contained config for testing Kiso subscriptions.
        let key_pair = checked_keypair();
        let peer = Peer::new(socket_addr!(127.0.0.1:0), key_pair.public_key().clone());
        let streaming_identity = key_pair.clone();
        let soranet_transport_key_pair = checked_soranet_transport_keypair();
        assert_ne!(
            soranet_transport_key_pair.public_key(),
            key_pair.public_key(),
            "SoraNet transport and node-signing identities must be independent"
        );
        Root {
            sccp: iroha_config::parameters::actual::SccpNode::default(),
            common: Common {
                chain: ChainId::from("test-chain"),
                key_pair,
                soranet_transport_key_pair,
                peer: peer.clone(),
                trusted_peers: WithOrigin::inline(TrustedPeers {
                    myself: peer,
                    others: <_>::default(),
                    pops: std::collections::BTreeMap::new(),
                }),
                chain_discriminant: WithOrigin::inline(defaults::common::chain_discriminant()),
            },
            runtime_provider_broker: iroha_config::parameters::actual::RuntimeProviderBroker {
                observer_operation_timeout: defaults::runtime_provider_broker::OBSERVER_OPERATION_TIMEOUT,
                credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES,
                endpoint_path:
                    iroha_config::parameters::actual::RuntimeProviderBrokerEndpointPath::try_new(
                        defaults::runtime_provider_broker::endpoint_path(),
                    )
                    .expect("default runtime-provider broker endpoint is valid"),
            },
            network: Network {
                address: WithOrigin::inline(socket_addr!(127.0.0.1:0)),
                public_address: WithOrigin::inline(socket_addr!(127.0.0.1:0)),
                relay_mode: iroha_config::parameters::actual::RelayMode::Disabled,
                relay_hub_addresses: Vec::new(),
                relay_ttl: defaults::network::RELAY_TTL,
                soranet_handshake: ActualSoranetHandshake {
                    descriptor_commit: WithOrigin::inline(DEFAULT_DESCRIPTOR_COMMIT.to_vec()),
                    client_capabilities: WithOrigin::inline(DEFAULT_CLIENT_CAPABILITIES.to_vec()),
                    relay_capabilities: WithOrigin::inline(DEFAULT_RELAY_CAPABILITIES.to_vec()),
                    trust_gossip: defaults::network::TRUST_GOSSIP,
                    kem_id: 1,
                    sig_id: 1,
                    resume_hash: None,
                    pow: SoranetPow::default(),
                },
                soranet_privacy: SoranetPrivacy::default(),
                soranet_vpn: iroha_config::parameters::actual::SoranetVpn::default(),
                lane_profile: iroha_config::parameters::actual::LaneProfile::Core,
                require_sm_handshake_match: true,
                require_sm_openssl_preview_match: true,
                idle_timeout: std::time::Duration::from_secs(5),
                preauth_timeout: defaults::network::PREAUTH_TIMEOUT,
                preauth_max_connections_per_ip:
                    defaults::network::PREAUTH_MAX_CONNECTIONS_PER_IP,
                reply_writer_flush_timeout: defaults::network::REPLY_WRITER_FLUSH_TIMEOUT,
                connect_startup_delay: defaults::network::CONNECT_STARTUP_DELAY,
                dial_timeout: defaults::network::DIAL_TIMEOUT,
                deferred_send_ttl: Duration::from_millis(
                    defaults::network::DEFERRED_SEND_TTL_MS,
                ),
                deferred_send_max_per_peer: defaults::network::DEFERRED_SEND_MAX_PER_PEER,
                deferred_send_max_bytes_per_peer:
                    defaults::network::DEFERRED_SEND_MAX_BYTES_PER_PEER,
                deferred_send_max_bytes_total: iroha_config::parameters::defaults::network::DEFERRED_SEND_MAX_BYTES_TOTAL,
                peer_gossip_period: defaults::network::PEER_GOSSIP_PERIOD,
                peer_gossip_max_period: defaults::network::PEER_GOSSIP_PERIOD,
                trust_decay_half_life: defaults::network::TRUST_DECAY_HALF_LIFE,
                trust_penalty_bad_gossip: defaults::network::TRUST_PENALTY_BAD_GOSSIP,
                trust_penalty_unknown_peer: defaults::network::TRUST_PENALTY_UNKNOWN_PEER,
                trust_min_score: defaults::network::TRUST_MIN_SCORE,
                trust_gossip: defaults::network::TRUST_GOSSIP,
                dns_refresh_interval: None,
                dns_refresh_ttl: None,
                p2p_proxy: None,
                p2p_proxy_required: false,
                p2p_no_proxy: Vec::new(),
                outbound_dial_allow_cidrs: Vec::new(),
                outbound_dial_deny_cidrs: Vec::new(),
                outbound_dial_allow_dns_suffixes: Vec::new(),
                outbound_dial_deny_dns_suffixes: Vec::new(),
                p2p_proxy_tls_verify: true,
                p2p_proxy_tls_pinned_cert_der_base64: None,
                quic_enabled: false,
                quic_datagrams_enabled: defaults::network::QUIC_DATAGRAMS_ENABLED,
                quic_datagram_max_payload_bytes: defaults::network::QUIC_DATAGRAM_MAX_PAYLOAD_BYTES
                    .get(),
                quic_datagram_receive_buffer_bytes:
                    defaults::network::QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES.get(),
                quic_datagram_send_buffer_bytes:
                    defaults::network::QUIC_DATAGRAM_SEND_BUFFER_BYTES.get(),
                p2p_queue_cap_high: NonZeroUsize::new(128).unwrap(),
                p2p_queue_cap_low: NonZeroUsize::new(512).unwrap(),
                p2p_post_queue_cap: NonZeroUsize::new(128).unwrap(),
                p2p_outbound_frame_queue_max_high_bytes:
                    defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_BYTES,
                p2p_outbound_frame_queue_max_low_bytes:
                    defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_BYTES,
                p2p_outbound_frame_queue_max_high_frames:
                    defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_FRAMES,
                p2p_outbound_frame_queue_max_low_frames:
                    defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_FRAMES,
                p2p_subscriber_queue_cap: NonZeroUsize::new(128).unwrap(),
                consensus_ingress_rate_per_sec: defaults::network::CONSENSUS_INGRESS_RATE_PER_SEC,
                consensus_ingress_burst: defaults::network::CONSENSUS_INGRESS_BURST,
                consensus_ingress_bytes_per_sec:
                    defaults::network::CONSENSUS_INGRESS_BYTES_PER_SEC,
                consensus_ingress_bytes_burst:
                    defaults::network::CONSENSUS_INGRESS_BYTES_BURST,
                consensus_ingress_critical_rate_per_sec:
                    iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_RATE_PER_SEC,
                consensus_ingress_critical_burst:
                    iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_BURST,
                consensus_ingress_critical_bytes_per_sec:
                    iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_BYTES_PER_SEC,
                consensus_ingress_critical_bytes_burst:
                    iroha_config::parameters::defaults::network::CONSENSUS_INGRESS_CRITICAL_BYTES_BURST,
                consensus_ingress_penalty_threshold:
                    defaults::network::CONSENSUS_INGRESS_PENALTY_THRESHOLD,
                consensus_ingress_penalty_window: Duration::from_millis(
                    defaults::network::CONSENSUS_INGRESS_PENALTY_WINDOW_MS,
                ),
                consensus_ingress_penalty_cooldown: Duration::from_millis(
                    defaults::network::CONSENSUS_INGRESS_PENALTY_COOLDOWN_MS,
                ),
                happy_eyeballs_stagger: Duration::from_millis(100),
                addr_ipv6_first: false,
                max_incoming: None,
                max_total_connections: None,
                accept_rate_per_ip_per_sec: None,
                accept_burst_per_ip: None,
                max_accept_buckets: defaults::network::MAX_ACCEPT_BUCKETS,
                accept_bucket_idle: defaults::network::ACCEPT_BUCKET_IDLE,
                accept_prefix_v4_bits: defaults::network::ACCEPT_PREFIX_V4_BITS,
                accept_prefix_v6_bits: defaults::network::ACCEPT_PREFIX_V6_BITS,
                accept_rate_per_prefix_per_sec: None,
                accept_burst_per_prefix: None,
                low_priority_rate_per_sec: None,
                low_priority_burst: None,
                low_priority_bytes_per_sec: None,
                low_priority_bytes_burst: None,
                allowlist_only: false,
                allow_keys: Vec::new(),
                deny_keys: Vec::new(),
                allow_cidrs: Vec::new(),
                deny_cidrs: Vec::new(),
                disconnect_on_post_overflow: false,
                max_frame_bytes:
                    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES.get(),
                tcp_nodelay: true,
                tcp_keepalive: None,
                max_frame_bytes_consensus:
                    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONSENSUS.get(),
                max_frame_bytes_control:
                    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONTROL.get(),
                max_frame_bytes_block_sync:
                    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_BLOCK_SYNC.get(),
                max_frame_bytes_tx_gossip:
                    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_TX_GOSSIP.get(),
                max_frame_bytes_peer_gossip:
                    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_PEER_GOSSIP.get(),
                max_frame_bytes_health:
                    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_HEALTH.get(),
                max_frame_bytes_connect: iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONNECT.get(),
                max_frame_bytes_other:
                    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_OTHER.get(),
                quic_max_idle_timeout: None,
            },
            genesis: Genesis {
                public_key: checked_public_key(),
                file: None,
                manifest_json: None,
                expected_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                    b"Kiso test genesis trust anchor",
                )),
            },
            torii: Torii {
                address: WithOrigin::inline(socket_addr!(127.0.0.1:0)),
                cors: iroha_config::parameters::actual::ToriiCors::default(),
                max_content_len: 1_048_576u64.into(),
                data_dir: iroha_config::parameters::defaults::torii::data_dir(),
                receipt_signer: None,
                query_rate_per_authority_per_sec: None,
                query_burst_per_authority: None,
                query_max_inflight: iroha_config::parameters::defaults::torii::QUERY_MAX_INFLIGHT,
                query_heavy_max_inflight:
                    iroha_config::parameters::defaults::torii::QUERY_HEAVY_MAX_INFLIGHT,
                query_fanout_max_retained_bytes:
                    iroha_config::parameters::defaults::torii::QUERY_FANOUT_MAX_RETAINED_BYTES,
                query_fanout_max_working_set_bytes:
                    iroha_config::parameters::defaults::torii::QUERY_FANOUT_MAX_WORKING_SET_BYTES,
                sccp_history_cache_max_bytes: iroha_config::parameters::defaults::torii::SCCP_HISTORY_CACHE_MAX_BYTES,
                app_api_routed_read_body_read_timeout: Duration::from_millis(
                    iroha_config::parameters::defaults::torii::APP_API_ROUTED_READ_BODY_READ_TIMEOUT_MS,
                ),
                query_queue_timeout: Duration::from_millis(
                    iroha_config::parameters::defaults::torii::QUERY_QUEUE_TIMEOUT_MS,
                ),
                tx_rate_per_authority_per_sec: None,
                tx_burst_per_authority: None,
                deploy_rate_per_origin_per_sec: None,
                deploy_burst_per_origin: None,
                soracloud_public_rate_per_ip_per_sec:
                    iroha_config::parameters::defaults::torii::SORACLOUD_PUBLIC_RATE_PER_IP_PER_SEC
                        .and_then(std::num::NonZeroU32::new),
                soracloud_public_burst_per_ip:
                    iroha_config::parameters::defaults::torii::SORACLOUD_PUBLIC_BURST_PER_IP
                        .and_then(std::num::NonZeroU32::new),
                soracloud_public_max_inflight:
                    iroha_config::parameters::defaults::torii::SORACLOUD_PUBLIC_MAX_INFLIGHT,
                soracloud_public_max_response_bytes:
                    iroha_config::parameters::defaults::torii::SORACLOUD_PUBLIC_MAX_RESPONSE_BYTES,
                soracloud_mutation_rate_per_account_origin_per_sec:
                    iroha_config::parameters::defaults::torii::SORACLOUD_MUTATION_RATE_PER_ACCOUNT_ORIGIN_PER_SEC
                        .and_then(std::num::NonZeroU32::new),
                soracloud_mutation_burst_per_account_origin:
                    iroha_config::parameters::defaults::torii::SORACLOUD_MUTATION_BURST_PER_ACCOUNT_ORIGIN
                        .and_then(std::num::NonZeroU32::new),
                soracloud_mutation_max_inflight:
                    iroha_config::parameters::defaults::torii::SORACLOUD_MUTATION_MAX_INFLIGHT,
                soracloud_mutation_max_body_bytes:
                    iroha_config::parameters::defaults::torii::SORACLOUD_MUTATION_MAX_BODY_BYTES,
                require_api_token: false,
                api_tokens: Vec::new().into(),
                api_fee_asset_id: None,
                api_fee_amount: None,
                api_fee_receiver: None,
                api_rate_limit_bypass_cidrs: Vec::new(),
                internal_api_trusted_cidrs:
                    iroha_config::parameters::defaults::torii::internal_api_trusted_cidrs(),
                peer_telemetry_urls: Vec::new(),
                peer_geo: iroha_config::parameters::actual::ToriiPeerGeo::default(),
                soranet_privacy_ingest: iroha_config::parameters::actual::SoranetPrivacyIngest::default(),
                privacy_bootle_lantern_issuer: None,
                debug_match_filters: false,
                webhooks_enabled: iroha_config::parameters::defaults::torii::WEBHOOKS_ENABLED,
                zk_attachments_enabled:
                    iroha_config::parameters::defaults::torii::ZK_ATTACHMENTS_ENABLED,
                operator_auth: iroha_config::parameters::actual::ToriiOperatorAuth::default(),
                operator_signatures: iroha_config::parameters::actual::ToriiOperatorSignatures::default(),
                preauth_max_connections: None,
                preauth_max_connections_per_ip: None,
                preauth_rate_per_ip_per_sec: None,
                preauth_burst_per_ip: None,
                preauth_temp_ban: None,
                preauth_ban_capacity:
                    iroha_config::parameters::defaults::torii::PREAUTH_BAN_CAPACITY,
                preauth_allow_cidrs: Vec::new(),
                preauth_scheme_limits: Vec::new(),
                api_high_load_tx_threshold: None,
                api_high_load_stream_threshold: None,
                api_high_load_subscription_threshold: None,
                ram_lfe: None,
                tx_history: None,
                recipient_lookup: iroha_config::parameters::actual::ToriiRecipientLookup::default(),
                kagemusha_enrollment: None,
                public_dataspace_upstreams: Vec::new(),
                events_buffer_capacity: NonZeroUsize::new(
                    iroha_config::parameters::defaults::torii::EVENTS_BUFFER_CAPACITY,
                )
                .expect("non-zero events buffer capacity"),
                ws_message_timeout: Duration::from_millis(
                    iroha_config::parameters::defaults::torii::WS_MESSAGE_TIMEOUT_MS,
                ),
                attachments_ttl_secs: 3600,
                attachments_max_bytes: 4 * 1024 * 1024,
                attachments_per_tenant_max_count:
                    iroha_config::parameters::defaults::torii::ATTACHMENTS_PER_TENANT_MAX_COUNT,
                attachments_per_tenant_max_bytes:
                    iroha_config::parameters::defaults::torii::ATTACHMENTS_PER_TENANT_MAX_BYTES,
                attachments_global_max_count:
                    iroha_config::parameters::defaults::torii::ATTACHMENTS_GLOBAL_MAX_COUNT,
                attachments_global_max_bytes:
                    iroha_config::parameters::defaults::torii::ATTACHMENTS_GLOBAL_MAX_BYTES,
                attachments_allowed_mime_types:
                    iroha_config::parameters::defaults::torii::attachments_allowed_mime_types(),
                attachments_max_expanded_bytes:
                    iroha_config::parameters::defaults::torii::ATTACHMENTS_MAX_EXPANDED_BYTES,
                attachments_max_archive_depth:
                    iroha_config::parameters::defaults::torii::ATTACHMENTS_MAX_ARCHIVE_DEPTH,
                attachments_sanitizer_mode:
                    iroha_config::parameters::actual::AttachmentSanitizerMode::Subprocess,
                attachments_sanitize_timeout_ms:
                    iroha_config::parameters::defaults::torii::ATTACHMENTS_SANITIZE_TIMEOUT_MS,
                zk_prover_enabled: false,
                zk_prover_scan_period_secs: 60,
                zk_prover_reports_ttl_secs: 3600,
                zk_prover_reports_max_count:
                    iroha_config::parameters::defaults::torii::ZK_PROVER_REPORTS_MAX_COUNT,
                zk_prover_reports_max_bytes:
                    iroha_config::parameters::defaults::torii::ZK_PROVER_REPORTS_MAX_BYTES,
                zk_prover_max_inflight:
                    iroha_config::parameters::defaults::torii::ZK_PROVER_MAX_INFLIGHT,
                zk_prover_max_scan_bytes:
                    iroha_config::parameters::defaults::torii::ZK_PROVER_MAX_SCAN_BYTES,
                zk_prover_max_scan_millis:
                    iroha_config::parameters::defaults::torii::ZK_PROVER_MAX_SCAN_MILLIS,
                zk_prover_keys_dir:
                    iroha_config::parameters::defaults::torii::zk_prover_keys_dir(),
                zk_prover_allowed_backends:
                    iroha_config::parameters::defaults::torii::zk_prover_allowed_backends(),
                zk_prover_allowed_circuits:
                    iroha_config::parameters::defaults::torii::zk_prover_allowed_circuits(),
                ivm_tooling_max_inflight:
                    iroha_config::parameters::defaults::torii::IVM_TOOLING_MAX_INFLIGHT,
                ivm_tooling_timeout_ms:
                    iroha_config::parameters::defaults::torii::IVM_TOOLING_TIMEOUT_MS,
                transaction_ingress:
                    iroha_config::parameters::actual::TransactionIngress::default(),
                da_ingest: iroha_config::parameters::actual::DaIngest::default(),
                connect: Connect {
                    enabled: false,
                    ws_max_sessions: 64,
                    ws_per_ip_max_sessions: 8,
                    ws_rate_per_ip_per_min: 60,
                    session_ttl: std::time::Duration::from_secs(300),
                    frame_max_bytes: 256 * 1024,
                    session_buffer_max_bytes: 512 * 1024,
                    ping_interval: std::time::Duration::from_secs(30),
                    ping_miss_tolerance: 3,
                    ping_min_interval: std::time::Duration::from_secs(15),
                    dedupe_ttl: std::time::Duration::from_secs(60),
                    dedupe_cap: 1024,
                    relay_enabled: false,
                    relay_strategy:
                        iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
                    p2p_ttl_hops: 0,
                },
                iso_bridge: IsoBridge {
                    enabled: false,
                    max_body_bytes:
                        iroha_config::parameters::defaults::torii::ISO_BRIDGE_MAX_BODY_BYTES,
                    dedupe_ttl_secs: 3600,
                    default_profile: iroha_config::parameters::defaults::torii::ISO_BRIDGE_DEFAULT_PROFILE
                        .to_owned(),
                    profiles: Vec::new(),
                    store_dir: None,
                    store_retention_secs:
                        iroha_config::parameters::defaults::torii::ISO_BRIDGE_STORE_RETENTION_SECS,
                    store_max_records:
                        iroha_config::parameters::defaults::torii::ISO_BRIDGE_STORE_MAX_RECORDS,
                    audit_export_dir: None,
                    embedded_signature_policy: None,
                    signer: None,
                    participants: Vec::new(),
                    audit_admin_keys: Vec::new(),
                    account_aliases: Vec::new(),
                    currency_assets: Vec::new(),
                    reference_data: iroha_config::parameters::actual::IsoReferenceData::default(),
                },
                sorafs_discovery: iroha_config::parameters::actual::SorafsDiscovery::default(),
                sorafs_storage: iroha_config::parameters::actual::SorafsStorage::default(),
                sorafs_repair: iroha_config::parameters::actual::SorafsRepair::default(),
                sorafs_gc: iroha_config::parameters::actual::SorafsGc::default(),
                sorafs_quota: iroha_config::parameters::actual::SorafsQuota::default(),
                sorafs_alias_cache:
                    iroha_config::parameters::actual::SorafsAliasCachePolicy::default(),
                sorafs_gateway: iroha_config::parameters::actual::SorafsGateway::default(),
                sorafs_por: iroha_config::parameters::actual::SorafsPor::default(),
                sorafs_appeal_finance_settlement:
                    iroha_config::parameters::actual::SorafsAppealFinanceSettlement {
                        submitter_signers: Vec::new(),
                        worker_scan_interval: Duration::from_millis(
                            iroha_config::parameters::defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_SCAN_INTERVAL_MS,
                        ),
                        worker_max_retry_attempts:
                            iroha_config::parameters::defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_RETRY_ATTEMPTS,
                        worker_max_pending:
                            iroha_config::parameters::defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_PENDING,
                        worker_max_completed:
                            iroha_config::parameters::defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_COMPLETED,
                        worker_max_dead_letters:
                            iroha_config::parameters::defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_DEAD_LETTERS,
                        worker_checkpoint_max_bytes:
                            iroha_config::parameters::defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MAX_BYTES,
                        ..iroha_config::parameters::actual::SorafsAppealFinanceSettlement::default()
                    },
                transport: iroha_config::parameters::actual::ToriiTransport::default(),
                mcp: iroha_config::parameters::actual::ToriiMcp::default(),
                account_onboarding: None,
                faucet: None,
                proof_api: iroha_config::parameters::actual::ProofApi {
                    rate_per_minute: iroha_config::parameters::defaults::torii::PROOF_RATE_PER_MIN
                        .and_then(NonZeroU32::new),
                    burst: iroha_config::parameters::defaults::torii::PROOF_BURST
                        .and_then(NonZeroU32::new),
                    max_body_bytes: iroha_config::parameters::defaults::torii::PROOF_MAX_BODY_BYTES,
                    body_max_inflight:
                        iroha_config::parameters::defaults::torii::PROOF_BODY_MAX_INFLIGHT,
                    body_read_timeout: Duration::from_millis(
                        iroha_config::parameters::defaults::torii::PROOF_BODY_READ_TIMEOUT_MS,
                    ),
                    egress_bytes_per_sec: iroha_config::parameters::defaults::torii::PROOF_EGRESS_BYTES_PER_SEC
                        .and_then(std::num::NonZeroU64::new),
                    egress_burst_bytes: iroha_config::parameters::defaults::torii::PROOF_EGRESS_BURST_BYTES
                        .and_then(std::num::NonZeroU64::new),
                    max_list_limit: NonZeroU32::new(
                        iroha_config::parameters::defaults::torii::PROOF_MAX_LIST_LIMIT,
                    )
                    .expect("non-zero list limit"),
                    request_timeout: Duration::from_millis(
                        iroha_config::parameters::defaults::torii::PROOF_REQUEST_TIMEOUT_MS,
                    ),
                    cache_max_age: Duration::from_secs(
                        iroha_config::parameters::defaults::torii::PROOF_CACHE_MAX_AGE_SECS,
                    ),
                    retry_after: Duration::from_secs(
                        iroha_config::parameters::defaults::torii::PROOF_RETRY_AFTER_SECS,
                    ),
                },
                app_api: iroha_config::parameters::actual::AppApi {
                    default_list_limit: NonZeroU32::new(
                        iroha_config::parameters::defaults::torii::APP_API_DEFAULT_LIST_LIMIT,
                    )
                    .expect("non-zero default list limit"),
                    max_list_limit: NonZeroU32::new(
                        iroha_config::parameters::defaults::torii::APP_API_MAX_LIST_LIMIT,
                    )
                    .expect("non-zero max list limit"),
                    max_fetch_size: NonZeroU32::new(
                        iroha_config::parameters::defaults::torii::APP_API_MAX_FETCH_SIZE,
                    )
                    .expect("non-zero max fetch size"),
                    rate_limit_cost_per_page: NonZeroU32::new(
                        iroha_config::parameters::defaults::torii::APP_API_RATE_LIMIT_COST_PER_PAGE,
                    )
                    .expect("non-zero app-api rate limit cost"),
                    request_signature_max_clock_skew: Duration::from_secs(
                        iroha_config::parameters::defaults::torii::app_auth::MAX_CLOCK_SKEW_SECS,
                    ),
                    request_signature_nonce_ttl: Duration::from_secs(
                        iroha_config::parameters::defaults::torii::app_auth::NONCE_TTL_SECS,
                    ),
                    request_signature_replay_cache_capacity: NonZeroUsize::new(
                        iroha_config::parameters::defaults::torii::app_auth::REPLAY_CACHE_CAPACITY,
                    )
                    .expect("non-zero app-api replay cache capacity"),
                },
                webhook: iroha_config::parameters::actual::Webhook {
                    queue_capacity: NonZeroUsize::new(
                        iroha_config::parameters::defaults::torii::WEBHOOK_QUEUE_CAPACITY,
                    )
                    .expect("non-zero webhook queue capacity"),
                    max_attempts: NonZeroU32::new(
                        iroha_config::parameters::defaults::torii::WEBHOOK_MAX_ATTEMPTS,
                    )
                    .expect("non-zero webhook max attempts"),
                    backoff_initial: Duration::from_millis(
                        iroha_config::parameters::defaults::torii::WEBHOOK_BACKOFF_INITIAL_MS,
                    ),
                    backoff_max: Duration::from_millis(
                        iroha_config::parameters::defaults::torii::WEBHOOK_BACKOFF_MAX_MS,
                    ),
                    connect_timeout: Duration::from_millis(
                        iroha_config::parameters::defaults::torii::WEBHOOK_CONNECT_TIMEOUT_MS,
                    ),
                    write_timeout: Duration::from_millis(
                        iroha_config::parameters::defaults::torii::WEBHOOK_WRITE_TIMEOUT_MS,
                    ),
                    read_timeout: Duration::from_millis(
                        iroha_config::parameters::defaults::torii::WEBHOOK_READ_TIMEOUT_MS,
                    ),
                },
                webhook_security: iroha_config::parameters::actual::WebhookSecurity::default(),
                push: iroha_config::parameters::actual::Push {
                    enabled: iroha_config::parameters::defaults::torii::PUSH_ENABLED,
                    rate_per_minute:
                        iroha_config::parameters::defaults::torii::PUSH_RATE_LIMIT_ENABLED
                            .then_some(
                                iroha_config::parameters::defaults::torii::PUSH_RATE_PER_MINUTE,
                            ),
                    burst: iroha_config::parameters::defaults::torii::PUSH_RATE_LIMIT_ENABLED
                        .then_some(iroha_config::parameters::defaults::torii::PUSH_BURST),
                    connect_timeout: Duration::from_millis(
                        iroha_config::parameters::defaults::torii::PUSH_CONNECT_TIMEOUT_MS,
                    ),
                    request_timeout: Duration::from_millis(
                        iroha_config::parameters::defaults::torii::PUSH_REQUEST_TIMEOUT_MS,
                    ),
                    max_topics_per_device:
                        iroha_config::parameters::defaults::torii::PUSH_MAX_TOPICS_PER_DEVICE,
                    fcm_project_id: None,
                    fcm_service_account_path: None,
                    apns_environment:
                        iroha_config::parameters::defaults::torii::PUSH_APNS_ENVIRONMENT.to_string(),
                    apns_topic: None,
                    apns_team_id: None,
                    apns_key_id: None,
                    apns_private_key_path: None,
                    apns_endpoint: None,
                },
            },
            soracloud_runtime: iroha_config::parameters::actual::SoracloudRuntime::default(),
            musubi_publication: iroha_config::parameters::actual::MusubiPublication::default(),
            amx_relay: iroha_config::parameters::actual::AmxRelay::default(),
            kura: Kura { init_mode: iroha_config::kura::InitMode::Strict, store_dir: WithOrigin::inline(std::env::temp_dir()),
                max_disk_usage_bytes:
                    iroha_config::parameters::defaults::kura::MAX_DISK_USAGE_BYTES,
                blocks_in_memory: NonZeroUsize::new(10).unwrap(),
                debug_output_new_blocks: false,
                fsync_mode: iroha_config::kura::FsyncMode::Batched,
                fsync_interval: iroha_config::parameters::defaults::kura::FSYNC_INTERVAL,
                native_context_archive_max_bytes: iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity: iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
                block_hash_history_bytes: iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
                transaction_history_bytes: iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
                membership_storage:
                    iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
                fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
            },
            sumeragi: Sumeragi::default(),
            block_sync: BlockSync {
                gossip_period: std::time::Duration::from_millis(200),
                gossip_max_period: std::time::Duration::from_millis(200),
                gossip_size: NonZeroU32::new(32).unwrap(),
            },
            transaction_gossiper: TransactionGossiper {
                gossip_period: std::time::Duration::from_millis(200),
                gossip_size: NonZeroU32::new(32).unwrap(),
                gossip_resend_ticks:
                    iroha_config::parameters::defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS,
                dataspace: DataspaceGossip::default(),
            },
            live_query_store: LiveQueryStore::default(),
            logger: Logger {
                level: Level::INFO,
                filter: None,
                format: iroha_config::logger::Format::default(),
                terminal_colors: false,
            },
            queue: Queue::default(),
            nexus: Nexus::default(),
            snapshot: iroha_config::parameters::user::Snapshot {
                mode: iroha_config::snapshot::Mode::Disabled,
                create_every_ms: iroha_config::base::util::DurationMs(
                    std::time::Duration::from_secs(60),
                ),
                store_dir: WithOrigin::inline(std::env::temp_dir()),
                merkle_chunk_size_bytes:
                    iroha_config::parameters::defaults::snapshot::MERKLE_CHUNK_SIZE_BYTES,
                max_payload_bytes:
                    iroha_config::parameters::defaults::snapshot::MAX_PAYLOAD_BYTES,
                max_read_buffer_bytes:
                    iroha_config::parameters::defaults::snapshot::MAX_READ_BUFFER_BYTES,
                resources: iroha_config::parameters::actual::SnapshotResourcePolicy::default(),
                verification_public_key: None,
                signing_private_key: None,
            },
            telemetry_profile: iroha_config::parameters::actual::TelemetryProfile::Disabled,
            telemetry: None,
            telemetry_integrity: iroha_config::parameters::actual::TelemetryIntegrity::default(),
            dev_telemetry: iroha_config::parameters::user::DevTelemetry {
                out_file: None,
                panic_on_duplicate_metrics:
                    iroha_config::parameters::defaults::telemetry::PANIC_ON_DUPLICATE_METRICS,
            },
            pipeline: iroha_config::parameters::actual::Pipeline {
                dynamic_prepass: false,
                access_set_cache_enabled:
                    iroha_config::parameters::defaults::pipeline::ACCESS_SET_CACHE_ENABLED,
                parallel_overlay: false,
                workers: iroha_config::parameters::defaults::pipeline::WORKERS,
                stateless_cache_cap: iroha_config::parameters::defaults::pipeline::STATELESS_CACHE_CAP,
                parallel_apply: true,
                ready_queue_heap: iroha_config::parameters::defaults::pipeline::READY_QUEUE_HEAP,
                gpu_key_bucket: iroha_config::parameters::defaults::pipeline::GPU_KEY_BUCKET,
                debug_trace_scheduler_inputs:
                    iroha_config::parameters::defaults::pipeline::DEBUG_TRACE_SCHEDULER_INPUTS,
                debug_trace_tx_eval:
                    iroha_config::parameters::defaults::pipeline::DEBUG_TRACE_TX_EVAL,
                signature_batch_max_ed25519:
                    iroha_config::parameters::defaults::pipeline::SIGNATURE_BATCH_MAX_ED25519,
                signature_batch_max_secp256k1:
                    iroha_config::parameters::defaults::pipeline::SIGNATURE_BATCH_MAX_SECP256K1,
                signature_batch_max_pqc:
                    iroha_config::parameters::defaults::pipeline::SIGNATURE_BATCH_MAX_PQC,
                signature_batch_max_bls:
                    iroha_config::parameters::defaults::pipeline::SIGNATURE_BATCH_MAX_BLS,
                cache_size: iroha_config::parameters::defaults::pipeline::CACHE_SIZE,
                ivm_cache_max_decoded_ops:
                    iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
                ivm_cache_max_bytes:
                    iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_BYTES,
                ivm_execution_max_bytes:
                    iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
                ivm_prover_threads:
                    iroha_config::parameters::defaults::pipeline::IVM_PROVER_THREADS,
                overlay_max_instructions:
                    iroha_config::parameters::defaults::pipeline::OVERLAY_MAX_INSTRUCTIONS,
                overlay_max_bytes: iroha_config::parameters::defaults::pipeline::OVERLAY_MAX_BYTES,
                overlay_chunk_instructions:
                    iroha_config::parameters::defaults::pipeline::OVERLAY_CHUNK_INSTRUCTIONS,
                gas: iroha_config::parameters::actual::Gas {
                    tech_account_id:
                        iroha_config::parameters::defaults::pipeline::GAS_TECH_ACCOUNT_ID
                            .to_string(),
                    accepted_assets: Vec::new(),
                    units_per_gas: Vec::new(),
                },
                ivm_max_cycles_upper_bound:
                    iroha_config::parameters::defaults::pipeline::IVM_MAX_CYCLES_UPPER_BOUND,
                ivm_max_decoded_instructions:
                    iroha_config::parameters::defaults::pipeline::IVM_MAX_DECODED_INSTRUCTIONS,
                ivm_max_decoded_bytes:
                    iroha_config::parameters::defaults::pipeline::IVM_MAX_DECODED_BYTES,
                quarantine_max_txs_per_block:
                    iroha_config::parameters::defaults::pipeline::QUARANTINE_MAX_TXS_PER_BLOCK,
                quarantine_tx_max_cycles:
                    iroha_config::parameters::defaults::pipeline::QUARANTINE_TX_MAX_CYCLES,
                query_default_cursor_mode:
                    iroha_config::parameters::actual::QueryCursorMode::Ephemeral,
                query_max_fetch_size:
                    iroha_config::parameters::defaults::pipeline::QUERY_MAX_FETCH_SIZE,
                query_stored_min_gas_units:
                    iroha_config::parameters::defaults::pipeline::QUERY_STORED_MIN_GAS_UNITS,
                amx_per_dataspace_budget_ms:
                    iroha_config::parameters::defaults::pipeline::AMX_PER_DATASPACE_BUDGET_MS,
                amx_group_budget_ms:
                    iroha_config::parameters::defaults::pipeline::AMX_GROUP_BUDGET_MS,
                amx_per_instruction_ns:
                    iroha_config::parameters::defaults::pipeline::AMX_PER_INSTRUCTION_NS,
                amx_per_memory_access_ns:
                    iroha_config::parameters::defaults::pipeline::AMX_PER_MEMORY_ACCESS_NS,
                amx_per_syscall_ns:
                    iroha_config::parameters::defaults::pipeline::AMX_PER_SYSCALL_NS,
            },
            tiered_state: TieredState {
                enabled: false,
                hot_retained_keys: 0,
                hot_retained_bytes: iroha_config::parameters::defaults::tiered_state::HOT_RETAINED_BYTES,
                hot_retained_grace_snapshots:
                    iroha_config::parameters::defaults::tiered_state::HOT_RETAINED_GRACE_SNAPSHOTS,
                cold_store_root: None,
                da_store_root: None,
                max_snapshots: 2,
                max_cold_bytes: iroha_config::parameters::defaults::tiered_state::MAX_COLD_BYTES,
            },
            compute: iroha_config::parameters::actual::Compute {
                enabled: iroha_config::parameters::defaults::compute::ENABLED,
                namespaces: iroha_config::parameters::defaults::compute::default_namespaces()
                    .into_iter()
                    .collect(),
                default_ttl_slots:
                    iroha_config::parameters::defaults::compute::default_ttl_slots(),
                max_ttl_slots: iroha_config::parameters::defaults::compute::max_ttl_slots(),
                max_request_bytes: iroha_config::parameters::defaults::compute::MAX_REQUEST_BYTES,
                max_response_bytes: iroha_config::parameters::defaults::compute::MAX_RESPONSE_BYTES,
                max_gas_per_call: iroha_config::parameters::defaults::compute::max_gas_per_call(),
                resource_profiles:
                    iroha_config::parameters::defaults::compute::resource_profiles(),
                default_resource_profile: iroha_config::parameters::defaults::compute::default_resource_profile(),
                price_families: iroha_config::parameters::defaults::compute::price_families(),
                default_price_family: iroha_config::parameters::defaults::compute::default_price_family(),
                auth_policy: iroha_config::parameters::defaults::compute::default_auth_policy(),
                sandbox: iroha_config::parameters::defaults::compute::sandbox_rules(),
                economics: iroha_config::parameters::actual::ComputeEconomics {
                    max_cu_per_call: iroha_config::parameters::defaults::compute::max_cu_per_call(),
                    max_amplification_ratio: iroha_config::parameters::defaults::compute::max_amplification_ratio(),
                    fee_split: iroha_config::parameters::defaults::compute::fee_split(),
                    sponsor_policy: iroha_config::parameters::defaults::compute::sponsor_policy(),
                    price_bounds: iroha_config::parameters::defaults::compute::price_bounds(),
                    price_risk_classes: iroha_config::parameters::defaults::compute::price_risk_classes(),
                    price_family_baseline: iroha_config::parameters::defaults::compute::price_families(),
                    price_amplifiers: iroha_config::parameters::defaults::compute::price_amplifiers(),
                },
                slo: iroha_config::parameters::actual::ComputeSlo {
                    max_inflight_per_route: iroha_config::parameters::defaults::compute::max_inflight_per_route(),
                    queue_depth_per_route: iroha_config::parameters::defaults::compute::queue_depth_per_route(),
                    max_requests_per_second: iroha_config::parameters::defaults::compute::max_requests_per_second(),
                    target_p50_latency_ms: iroha_config::parameters::defaults::compute::target_p50_latency_ms(),
                    target_p95_latency_ms: iroha_config::parameters::defaults::compute::target_p95_latency_ms(),
                    target_p99_latency_ms: iroha_config::parameters::defaults::compute::target_p99_latency_ms(),
                },
            },
            content: iroha_config::parameters::actual::Content {
                max_bundle_bytes: iroha_config::parameters::defaults::content::MAX_BUNDLE_BYTES,
                max_files: iroha_config::parameters::defaults::content::MAX_FILES,
                max_path_len: iroha_config::parameters::defaults::content::MAX_PATH_LEN,
                max_retention_blocks: iroha_config::parameters::defaults::content::MAX_RETENTION_BLOCKS,
                chunk_size_bytes: iroha_config::parameters::defaults::content::CHUNK_SIZE_BYTES,
                publish_allow_accounts: Vec::new(),
                limits: iroha_config::parameters::actual::ContentLimits {
                    max_requests_per_second: std::num::NonZeroU32::new(
                        iroha_config::parameters::defaults::content::MAX_REQUESTS_PER_SECOND
                    )
                    .unwrap(),
                    request_burst: std::num::NonZeroU32::new(
                        iroha_config::parameters::defaults::content::REQUEST_BURST
                    )
                    .unwrap(),
                    max_egress_bytes_per_second: std::num::NonZeroU64::new(
                        u64::from(
                            iroha_config::parameters::defaults::content::MAX_EGRESS_BYTES_PER_SECOND,
                        )
                    )
                    .unwrap(),
                    egress_burst_bytes: std::num::NonZeroU64::new(
                        iroha_config::parameters::defaults::content::EGRESS_BURST_BYTES
                    )
                    .unwrap(),
                },
                default_cache_max_age_secs:
                    iroha_config::parameters::defaults::content::DEFAULT_CACHE_MAX_AGE_SECS,
                max_cache_max_age_secs: iroha_config::parameters::defaults::content::MAX_CACHE_MAX_AGE_SECS,
                immutable_bundles: iroha_config::parameters::defaults::content::IMMUTABLE_BUNDLES,
                default_auth_mode: iroha_data_model::content::ContentAuthMode::Public,
                slo: iroha_config::parameters::actual::ContentSlo {
                    target_p50_latency_ms: std::num::NonZeroU32::new(
                        iroha_config::parameters::defaults::content::TARGET_P50_LATENCY_MS
                    )
                    .unwrap(),
                    target_p99_latency_ms: std::num::NonZeroU32::new(
                        iroha_config::parameters::defaults::content::TARGET_P99_LATENCY_MS
                    )
                    .unwrap(),
                    target_availability_bps: std::num::NonZeroU32::new(
                        iroha_config::parameters::defaults::content::TARGET_AVAILABILITY_BPS
                    )
                    .unwrap(),
                },
                pow: iroha_config::parameters::actual::ContentPow {
                    difficulty_bits: iroha_config::parameters::defaults::content::POW_DIFFICULTY_BITS,
                    header_name: iroha_config::parameters::defaults::content::default_pow_header(),
                },
                stripe_layout: iroha_config::parameters::defaults::content::default_stripe_layout(),
            },
            oracle: iroha_config::parameters::actual::Oracle {
                history_depth: iroha_config::parameters::defaults::oracle::history_depth(),
                economics: iroha_config::parameters::actual::OracleEconomics {
                    reward_asset: iroha_config::parameters::defaults::oracle::reward_asset(),
                    reward_pool: iroha_config::parameters::defaults::oracle::reward_pool(),
                    reward_amount: iroha_config::parameters::defaults::oracle::reward_amount(),
                    slash_asset: iroha_config::parameters::defaults::oracle::slash_asset(),
                    slash_receiver: iroha_config::parameters::defaults::oracle::slash_receiver(),
                    slash_outlier_amount:
                        iroha_config::parameters::defaults::oracle::slash_outlier_amount(),
                    slash_error_amount: iroha_config::parameters::defaults::oracle::slash_error_amount(),
                    slash_no_show_amount:
                        iroha_config::parameters::defaults::oracle::slash_no_show_amount(),
                    dispute_bond_asset: iroha_config::parameters::defaults::oracle::dispute_bond_asset(),
                    dispute_bond_amount:
                        iroha_config::parameters::defaults::oracle::dispute_bond_amount(),
                    dispute_reward_amount:
                        iroha_config::parameters::defaults::oracle::dispute_reward_amount(),
                    frivolous_slash_amount:
                        iroha_config::parameters::defaults::oracle::frivolous_slash_amount(),
                },
                governance: iroha_config::parameters::actual::OracleGovernance {
                    intake_sla_blocks: iroha_config::parameters::defaults::oracle::intake_sla_blocks(),
                    rules_sla_blocks: iroha_config::parameters::defaults::oracle::rules_sla_blocks(),
                    cop_sla_blocks: iroha_config::parameters::defaults::oracle::cop_sla_blocks(),
                    technical_sla_blocks: iroha_config::parameters::defaults::oracle::technical_sla_blocks(),
                    policy_jury_sla_blocks: iroha_config::parameters::defaults::oracle::policy_jury_sla_blocks(),
                    enact_sla_blocks: iroha_config::parameters::defaults::oracle::enact_sla_blocks(),
                    intake_min_votes: iroha_config::parameters::defaults::oracle::intake_min_votes(),
                    rules_min_votes: iroha_config::parameters::defaults::oracle::rules_min_votes(),
                    cop_min_votes: iroha_config::parameters::actual::OracleChangeThresholds {
                        low: iroha_config::parameters::defaults::oracle::cop_low_votes(),
                        medium: iroha_config::parameters::defaults::oracle::cop_medium_votes(),
                        high: iroha_config::parameters::defaults::oracle::cop_high_votes(),
                    },
                    technical_min_votes: iroha_config::parameters::defaults::oracle::technical_min_votes(),
                policy_jury_min_votes: iroha_config::parameters::actual::OracleChangeThresholds {
                    low: iroha_config::parameters::defaults::oracle::policy_jury_low_votes(),
                    medium: iroha_config::parameters::defaults::oracle::policy_jury_medium_votes(),
                    high: iroha_config::parameters::defaults::oracle::policy_jury_high_votes(),
                },
            },
            twitter_binding: iroha_config::parameters::actual::OracleTwitterBinding {
                feed_id: iroha_config::parameters::defaults::oracle::twitter_binding_feed_id(),
                pepper_id: iroha_config::parameters::defaults::oracle::twitter_binding_pepper_id(),
                max_ttl_ms: iroha_config::parameters::defaults::oracle::twitter_binding_max_ttl_ms(),
                min_ttl_ms: iroha_config::parameters::defaults::oracle::twitter_binding_min_ttl_ms(),
                min_update_spacing_ms: iroha_config::parameters::defaults::oracle::twitter_binding_min_update_spacing_ms(),
            },
        },
            zk: iroha_config::parameters::actual::Zk {
                pipa_r: iroha_config::parameters::actual::PipaR::default(),
                trace: iroha_config::parameters::actual::DiagnosticTrace::default(),
        ipa_commitment: iroha_config::parameters::actual::IpaCommitment::default(),
            max_verify_batch: iroha_config::parameters::defaults::zk::MAX_VERIFY_BATCH,
                fastpq: iroha_config::parameters::actual::Fastpq {
                    execution_mode: iroha_config::parameters::actual::FastpqExecutionMode::Cpu,
                    poseidon_mode: iroha_config::parameters::actual::FastpqPoseidonMode::Cpu,
                    proof_sidecar_queue_cap:
                        iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
                    proof_sidecar_max_bytes:
                        iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
                    proof_sidecar_max_retries:
                        iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
                    device_class: None,
                    chip_family: None,
                    gpu_kind: None,
                    metal_queue_fanout: None,
                    metal_queue_column_threshold: None,
                    metal_max_in_flight: None,
                    metal_threadgroup_width: None,
                    metal_trace: iroha_config::parameters::defaults::zk::fastpq::METAL_TRACE,
                    metal_debug_enum:
                        iroha_config::parameters::defaults::zk::fastpq::METAL_DEBUG_ENUM,
                },
                stark: iroha_config::parameters::actual::Stark::default(),
                sccp: iroha_config::parameters::actual::Sccp::default(),
                ballot_history_cap:
                    iroha_config::parameters::defaults::zk::vote::BALLOT_HISTORY_CAP,
                preverify_max_bytes: iroha_config::parameters::defaults::zk::preverify::MAX_BYTES,
                preverify_budget_bytes:
                    iroha_config::parameters::defaults::zk::preverify::BUDGET_BYTES,
                proof_history_cap:
                    iroha_config::parameters::defaults::zk::proof::RECORD_HISTORY_CAP,
                proof_retention_grace_blocks:
                    iroha_config::parameters::defaults::zk::proof::RETENTION_GRACE_BLOCKS,
                proof_prune_batch:
                    iroha_config::parameters::defaults::zk::proof::PRUNE_BATCH_SIZE,
                bridge_proof_max_range_len:
                    iroha_config::parameters::defaults::zk::proof::BRIDGE_MAX_RANGE_LEN,
                bridge_proof_max_past_age_blocks:
                    iroha_config::parameters::defaults::zk::proof::BRIDGE_MAX_PAST_AGE_BLOCKS,
                bridge_proof_max_future_drift_blocks:
                    iroha_config::parameters::defaults::zk::proof::BRIDGE_MAX_FUTURE_DRIFT_BLOCKS,
                poseidon_params_id:
                    iroha_config::parameters::defaults::confidential::POSEIDON_PARAMS_ID,
                pedersen_params_id:
                    iroha_config::parameters::defaults::confidential::PEDERSEN_PARAMS_ID,
                kaigi_authorization_vk: None,

                kaigi_usage_vk: None,
                max_proof_size_bytes:
                    iroha_config::parameters::defaults::confidential::MAX_PROOF_SIZE_BYTES,
                max_nullifiers_per_tx:
                    iroha_config::parameters::defaults::confidential::MAX_NULLIFIERS_PER_TX,
                max_commitments_per_tx:
                    iroha_config::parameters::defaults::confidential::MAX_COMMITMENTS_PER_TX,
                max_confidential_ops_per_block:
                    iroha_config::parameters::defaults::confidential::MAX_CONFIDENTIAL_OPS_PER_BLOCK,
                verify_timeout: iroha_config::parameters::defaults::confidential::VERIFY_TIMEOUT,
                max_anchor_age_blocks:
                    iroha_config::parameters::defaults::confidential::MAX_ANCHOR_AGE_BLOCKS,
                max_proof_bytes_block:
                    iroha_config::parameters::defaults::confidential::MAX_PROOF_BYTES_BLOCK,
                max_verify_calls_per_tx:
                    iroha_config::parameters::defaults::confidential::MAX_VERIFY_CALLS_PER_TX,
                max_verify_calls_per_block:
                    iroha_config::parameters::defaults::confidential::MAX_VERIFY_CALLS_PER_BLOCK,
                max_public_inputs:
                    iroha_config::parameters::defaults::confidential::MAX_PUBLIC_INPUTS,
                reorg_depth_bound:
                    iroha_config::parameters::defaults::confidential::REORG_DEPTH_BOUND,
                policy_transition_delay_blocks:
                    iroha_config::parameters::defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS,
                policy_transition_window_blocks:
                    iroha_config::parameters::defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS,
                policy_transition_max_per_height:
                    iroha_config::parameters::defaults::confidential::POLICY_TRANSITION_MAX_PER_HEIGHT,
                tree_roots_history_len:
                    iroha_config::parameters::defaults::confidential::TREE_ROOTS_HISTORY_LEN,
                tree_frontier_checkpoint_interval:
                    iroha_config::parameters::defaults::confidential::TREE_FRONTIER_CHECKPOINT_INTERVAL,
                registry_max_vk_entries:
                    iroha_config::parameters::defaults::confidential::REGISTRY_MAX_VK_ENTRIES,
                registry_max_params_entries:
                    iroha_config::parameters::defaults::confidential::REGISTRY_MAX_PARAMS_ENTRIES,
                registry_max_delta_per_block:
                    iroha_config::parameters::defaults::confidential::REGISTRY_MAX_DELTA_PER_BLOCK,
                gas: iroha_config::parameters::actual::ConfidentialGas {
                    proof_base: iroha_config::parameters::defaults::confidential::gas::PROOF_BASE,
                    per_public_input:
                        iroha_config::parameters::defaults::confidential::gas::PER_PUBLIC_INPUT,
                    per_proof_byte:
                        iroha_config::parameters::defaults::confidential::gas::PER_PROOF_BYTE,
                    per_nullifier:
                        iroha_config::parameters::defaults::confidential::gas::PER_NULLIFIER,
                    per_commitment:
                        iroha_config::parameters::defaults::confidential::gas::PER_COMMITMENT,
                },
            },
            norito: iroha_config::parameters::actual::Norito {
                allow_gpu_compression:
                    iroha_config::parameters::defaults::norito::ALLOW_GPU_COMPRESSION,
                max_archive_len: iroha_config::parameters::defaults::norito::MAX_ARCHIVE_LEN,
            },
            fraud_monitoring: FraudMonitoring::new(
                Vec::new(),
                iroha_config::parameters::defaults::fraud_monitoring::CONNECT_TIMEOUT,
                iroha_config::parameters::defaults::fraud_monitoring::REQUEST_TIMEOUT,
            ),
            gov: Governance {
                vk_ballot: None,
                vk_tally: None,
                voting_asset_id: iroha_config::parameters::defaults::governance::voting_asset_id()
                    .parse()
                    .expect("valid default voting asset id"),
                citizenship_asset_id: iroha_config::parameters::defaults::governance::citizenship_asset_id()
                    .parse()
                    .expect("valid default citizenship asset id"),
                citizenship_bond_amount:
                    iroha_config::parameters::defaults::governance::CITIZENSHIP_BOND_AMOUNT.into(),
                citizenship_escrow_account:
                    iroha_config::parameters::defaults::governance::citizenship_escrow_account_id(),
                min_bond_amount: 150_u64.into(),
                bond_escrow_account:
                    iroha_config::parameters::defaults::governance::bond_escrow_account_id(),
                slash_receiver_account:
                    iroha_config::parameters::defaults::governance::slash_receiver_account_id(),
                slash_double_vote_bps: 0,
                slash_invalid_proof_bps: 0,
                slash_ineligible_proof_bps: 0,
                debug_trace_pipeline: iroha_config::parameters::defaults::governance::DEBUG_TRACE_PIPELINE,
                jdg_signature_schemes: iroha_config::parameters::defaults::governance::jdg_signature_schemes()
                    .into_iter()
                    .map(|scheme| {
                        scheme
                            .parse::<iroha_data_model::jurisdiction::JdgSignatureScheme>()
                            .expect("valid default JDG signature scheme")
                    })
                    .collect(),
                runtime_upgrade_provenance:
                    iroha_config::parameters::actual::RuntimeUpgradeProvenancePolicy::default(),
                viral_incentives: iroha_config::parameters::actual::ViralIncentives::default(),
                sorafs_pin_policy: iroha_config::parameters::actual::SorafsPinPolicyConstraints::default(),
                sorafs_pin_fee_asset_id:
                    iroha_config::parameters::defaults::governance::sorafs_pin_fee::asset_id()
                        .parse()
                        .expect("default SoraFS pin fee asset id"),
                sorafs_pin_fee_treasury_account:
                    iroha_data_model::account::AccountId::parse_encoded(
                        &iroha_config::parameters::defaults::governance::sorafs_pin_fee::treasury_account(),
                    )
                    .expect("default SoraFS pin fee treasury account"),
                sorafs_pricing: PricingScheduleRecord::launch_default(),
                alias_teu_minimum: iroha_config::parameters::defaults::governance::alias_teu_minimum(),
                alias_frontier_telemetry: iroha_config::parameters::defaults::governance::alias_frontier_telemetry(),
                sorafs_penalty: iroha_config::parameters::actual::SorafsPenaltyPolicy::default(),
                sorafs_telemetry: iroha_config::parameters::actual::SorafsTelemetryPolicy::default(),
                sorafs_provider_owners: std::collections::BTreeMap::new(),
                conviction_step_blocks: 100,
                max_conviction: 6,
                min_enactment_delay: 20,
                window_span: 100,
                max_active_referenda:
                    iroha_config::parameters::defaults::governance::MAX_ACTIVE_REFERENDA,
                max_lock_owners_per_referendum:
                    iroha_config::parameters::defaults::governance::MAX_LOCK_OWNERS_PER_REFERENDUM,
                plain_voting_enabled:
                    iroha_config::parameters::defaults::governance::PLAIN_VOTING_ENABLED,
                approval_threshold_q_num: 1,
                approval_threshold_q_den: 2,
                min_turnout: 0,
                parliament_alternate_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_ALTERNATE_SIZE,
                parliament_sortition_pulse_delay_blocks:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_SORTITION_PULSE_DELAY_BLOCKS,
                parliament_invitation_phase_blocks:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_INVITATION_PHASE_BLOCKS,
                parliament_public_finding_phase_blocks:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_PUBLIC_FINDING_PHASE_BLOCKS,
                parliament_timed_ovn:
                    iroha_config::parameters::actual::ParliamentTimedOvn::default(),
                parliament_tle_key_lifecycle:
                    iroha_config::parameters::actual::ParliamentTleKeyLifecycle::default(),
                parliament_tle_partial_release_signer_provider_handle: None,
                parliament_tle_partial_release_signer_provider_revision: None,
                parliament_tle_partial_release_signer_provider_policy_digest: None,
                rules_committee_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_RULES_COMMITTEE_SIZE,
                agenda_council_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_AGENDA_COUNCIL_SIZE,
                interest_panel_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_INTEREST_PANEL_SIZE,
                review_panel_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_REVIEW_PANEL_SIZE,
                coordination_council_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_COORDINATION_COUNCIL_SIZE,
                policy_jury_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_POLICY_JURY_SIZE,
                confirmation_jury_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_CONFIRMATION_JURY_SIZE,
                oversight_committee_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_OVERSIGHT_COMMITTEE_SIZE,
                mpc_committee_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_MPC_COMMITTEE_SIZE,
                fma_committee_size:
                    iroha_config::parameters::defaults::governance::PARLIAMENT_FMA_COMMITTEE_SIZE,
            },
            nts: iroha_config::parameters::actual::Nts {
                sample_interval: iroha_config::parameters::defaults::time::NTS_SAMPLE_INTERVAL,
                sample_cap_per_round:
                    iroha_config::parameters::defaults::time::NTS_SAMPLE_CAP_PER_ROUND,
                max_rtt_ms: iroha_config::parameters::defaults::time::NTS_MAX_RTT_MS,
                trim_percent: iroha_config::parameters::defaults::time::NTS_TRIM_PERCENT,
                per_peer_buffer: iroha_config::parameters::defaults::time::NTS_PER_PEER_BUFFER,
                smoothing_enabled: iroha_config::parameters::defaults::time::NTS_SMOOTHING_ENABLED,
                smoothing_alpha: iroha_config::parameters::defaults::time::NTS_SMOOTHING_ALPHA,
                max_adjust_ms_per_min:
                    iroha_config::parameters::defaults::time::NTS_MAX_ADJUST_MS_PER_MIN,
                min_samples: iroha_config::parameters::defaults::time::NTS_MIN_SAMPLES,
                max_offset_ms: iroha_config::parameters::defaults::time::NTS_MAX_OFFSET_MS,
                max_confidence_ms: iroha_config::parameters::defaults::time::NTS_MAX_CONFIDENCE_MS,
                enforcement_mode: iroha_config::parameters::actual::NtsEnforcementMode::Warn,
            },
            accel: Acceleration {
                resource_limits: iroha_config::parameters::defaults::accel::RESOURCE_LIMITS,
                enable_simd: iroha_config::parameters::defaults::accel::ENABLE_SIMD,
                enable_cuda: false,
                enable_metal: false,
                max_gpus: None,
                merkle_min_leaves_gpu:
                    iroha_config::parameters::defaults::accel::MERKLE_MIN_LEAVES_GPU,
                merkle_min_leaves_metal: None,
                merkle_min_leaves_cuda: None,
                prefer_cpu_sha2_max_leaves_aarch64: None,
                prefer_cpu_sha2_max_leaves_x86: None,
            },
            ivm: Ivm::default(),
            concurrency: Concurrency::from_defaults(),
            confidential: Confidential {
                enabled: iroha_config::parameters::defaults::confidential::ENABLED,
                assume_valid: iroha_config::parameters::defaults::confidential::ASSUME_VALID,
                verifier_backend: iroha_config::parameters::defaults::confidential::VERIFIER_BACKEND
                    .to_string(),
                verify_timeout: iroha_config::parameters::defaults::confidential::VERIFY_TIMEOUT,
            },
            crypto: iroha_config::parameters::actual::Crypto::default(),
            settlement: Settlement::default(),
            streaming: Streaming {
                key_material: StreamingKeyMaterial::new(streaming_identity)
                    .expect("streaming key material"),
                session_store_dir: PathBuf::from(
                    iroha_config::parameters::defaults::streaming::SESSION_STORE_DIR,
                ),
                feature_bits: iroha_config::parameters::defaults::streaming::FEATURE_BITS,
                sync: iroha_config::parameters::actual::StreamingSync::from_defaults(),
                codec: iroha_config::parameters::actual::StreamingCodec::from_defaults(),
            },
            data_dir: None,
            lifecycle: iroha_config::parameters::actual::Lifecycle::default(),
        }
    }
    #[tokio::test]
    async fn subscription_on_log_level_works() {
        const INIT_LOG_LEVEL: Level = Level::WARN;
        const NEW_LOG_LEVEL: Level = Level::DEBUG;
        const WATCH_LAG_MILLIS: u64 = 30;
        let mut config = test_config();
        config.logger.level = INIT_LOG_LEVEL;
        let (kiso, _) = KisoHandle::start(config);
        let mut recv = kiso
            .subscribe_on_logger_updates()
            .await
            .expect("Subscription should be fine");
        let _err = tokio::time::timeout(Duration::from_millis(WATCH_LAG_MILLIS), recv.changed())
            .await
            .expect_err("Watcher should not be active initially");
        kiso.update_with_dto(ConfigurationUpdate {
            logger: LoggerDTO {
                level: NEW_LOG_LEVEL,
                filter: Some("trace,trace,trace".parse().unwrap()),
            },
            network_acl: None,
            network: None,
            soranet_handshake: None,
            transport: None,
            compute_pricing: None,
        })
        .await
        .expect("Update should work fine");
        let () = tokio::time::timeout(Duration::from_millis(WATCH_LAG_MILLIS), recv.changed())
            .await
            .expect("Watcher should resolve within timeout")
            .expect("Watcher should not be closed");
        let value = recv.borrow_and_update().clone();
        assert_eq!(value.level, NEW_LOG_LEVEL);
        assert_eq!(format!("{}", value.filter.unwrap()), "trace,trace,trace");
    }
    #[tokio::test]
    async fn configuration_dto_carries_the_protocol_default_gas_until_state_replaces_it() {
        // The node configuration has no verification gas schedule: the DTO the
        // configuration authority builds holds the protocol default, runtime
        // updates leave it alone, and starting the authority installs nothing
        // into the schedule State charges (no process-wide schedule exists; each
        // block meters with its frozen ZK settings). Torii replaces the DTO field
        // with the committed schedule before it serves the record.
        let default = crate::state::default_zk_config().gas;
        let (kiso, _) = KisoHandle::start(test_config());
        kiso.update_with_dto(ConfigurationUpdate {
            logger: LoggerDTO {
                level: iroha_logger::Level::DEBUG,
                filter: None,
            },
            network_acl: None,
            network: None,
            soranet_handshake: None,
            transport: None,
            compute_pricing: None,
        })
        .await
        .expect("update should succeed");
        let dto = kiso.get_dto().await.expect("fetch updated dto");
        assert_eq!(dto.confidential_gas.proof_base, default.proof_base);
        assert_eq!(
            dto.confidential_gas.per_public_input,
            default.per_public_input
        );
        assert_eq!(dto.confidential_gas.per_proof_byte, default.per_proof_byte);
        assert_eq!(dto.confidential_gas.per_nullifier, default.per_nullifier);
        assert_eq!(dto.confidential_gas.per_commitment, default.per_commitment);
        assert_eq!(default.proof_base, crate::gas::DEFAULT_ZK_GAS.proof_base);
    }
    #[tokio::test]
    async fn network_acl_updates_are_canonical_and_allow_clearing() {
        use iroha_logger::Level;
        const WATCH_LAG_MILLIS: u64 = 30;
        let initial_allow_keys = vec![checked_public_key()];
        let initial_deny_keys = vec![checked_public_key()];
        let initial_allow_cidrs = vec!["10.0.0.0/8".to_owned()];
        let initial_deny_cidrs = vec!["192.168.0.0/16".to_owned()];
        let mut config = test_config();
        config.network.allowlist_only = true;
        config.network.allow_keys.clone_from(&initial_allow_keys);
        config.network.deny_keys.clone_from(&initial_deny_keys);
        config.network.allow_cidrs.clone_from(&initial_allow_cidrs);
        config.network.deny_cidrs.clone_from(&initial_deny_cidrs);
        let (kiso, _) = KisoHandle::start(config);
        let mut recv = kiso
            .subscribe_on_network_acl_updates()
            .await
            .expect("subscription should succeed");
        let initial = recv.borrow().clone();
        assert_eq!(initial.allowlist_only, Some(true));
        assert_eq!(initial.allow_keys.clone().unwrap(), initial_allow_keys);
        assert_eq!(
            initial.deny_keys.clone().unwrap(),
            initial_deny_keys.clone()
        );
        assert_eq!(
            initial.allow_cidrs.clone().unwrap(),
            initial_allow_cidrs.clone()
        );
        assert_eq!(
            initial.deny_cidrs.clone().unwrap(),
            initial_deny_cidrs.clone()
        );
        let replacement_key = checked_public_key();
        kiso.update_with_dto(ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::INFO,
                filter: None,
            },
            network_acl: Some(NetworkAcl {
                allowlist_only: Some(false),
                allow_keys: Some(vec![replacement_key.clone()]),
                deny_keys: None,
                allow_cidrs: None,
                deny_cidrs: None,
            }),
            network: None,
            soranet_handshake: None,
            transport: None,
            compute_pricing: None,
        })
        .await
        .expect("update should succeed");
        tokio::time::timeout(Duration::from_millis(WATCH_LAG_MILLIS), recv.changed())
            .await
            .expect("watcher should resolve within timeout")
            .expect("watcher should remain active");
        let updated = recv.borrow_and_update().clone();
        assert_eq!(updated.allowlist_only, Some(false));
        assert_eq!(
            updated.allow_keys.clone().unwrap(),
            vec![replacement_key.clone()]
        );
        assert_eq!(updated.deny_keys.clone().unwrap(), initial_deny_keys);
        assert_eq!(updated.allow_cidrs.clone().unwrap(), initial_allow_cidrs);
        assert_eq!(updated.deny_cidrs.clone().unwrap(), initial_deny_cidrs);
        kiso.update_with_dto(ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::INFO,
                filter: None,
            },
            network_acl: Some(NetworkAcl {
                allowlist_only: None,
                allow_keys: Some(Vec::new()),
                deny_keys: Some(Vec::new()),
                allow_cidrs: Some(Vec::new()),
                deny_cidrs: Some(Vec::new()),
            }),
            network: None,
            soranet_handshake: None,
            transport: None,
            compute_pricing: None,
        })
        .await
        .expect("clearing update should succeed");
        tokio::time::timeout(Duration::from_millis(WATCH_LAG_MILLIS), recv.changed())
            .await
            .expect("watcher should resolve within timeout")
            .expect("watcher should remain active");
        let cleared = recv.borrow_and_update().clone();
        assert_eq!(cleared.allowlist_only, Some(false));
        assert!(cleared.allow_keys.as_ref().unwrap().is_empty());
        assert!(cleared.deny_keys.as_ref().unwrap().is_empty());
        assert!(cleared.allow_cidrs.as_ref().unwrap().is_empty());
        assert!(cleared.deny_cidrs.as_ref().unwrap().is_empty());
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn soranet_handshake_update_applies() {
        let config = test_config();
        let (kiso, _) = KisoHandle::start(config);
        let descriptor_hex = "01".repeat(iroha_crypto::Hash::LENGTH);
        let resume_hex = "fe".repeat(iroha_crypto::Hash::LENGTH);
        let descriptor_bytes = hex::decode(&descriptor_hex).expect("descriptor hex");
        let resume_bytes = hex::decode(&resume_hex).expect("resume hex");
        let mut handshake_rx = kiso
            .subscribe_on_soranet_handshake_updates()
            .await
            .expect("subscribe handshake watcher");
        let mut runtime_requests = kiso
            .register_soranet_handshake_runtime_applier()
            .await
            .expect("register handshake runtime applier");
        let runtime = tokio::spawn(async move {
            for _ in 0..2 {
                runtime_requests
                    .recv()
                    .await
                    .expect("runtime proposal")
                    .respond_to
                    .send(Ok(()))
                    .expect("Kiso request should remain active");
            }
        });
        kiso.update_with_dto(ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::INFO,
                filter: None,
            },
            network_acl: None,
            network: None,
            soranet_handshake: Some(SoranetHandshakeUpdate {
                descriptor_commit_hex: Some(descriptor_hex.clone()),
                client_capabilities_hex: None,
                relay_capabilities_hex: None,
                kem_id: Some(2),
                sig_id: Some(1),
                resume_hash_hex: Some(ResumeHashDirective::Set(resume_hex.clone())),
                pow: Some(SoranetHandshakePowUpdate {
                    difficulty: Some(6),
                    max_future_skew_secs: Some(1200),
                    min_ticket_ttl_secs: Some(90),
                    ticket_ttl_secs: Some(240),
                    outbound_mint_capacity: None,
                    inbound_verify_capacity: None,
                    puzzle: Some(SoranetHandshakePuzzleUpdate {
                        memory_kib: Some(131_072),
                        time_cost: Some(3),
                        lanes: Some(2),
                    }),
                }),
            }),
            transport: None,
            compute_pricing: None,
        })
        .await
        .expect("handshake update should succeed");
        tokio::time::timeout(Duration::from_millis(30), handshake_rx.changed())
            .await
            .expect("handshake watcher should resolve within timeout")
            .expect("handshake watcher should remain active");
        let observed = handshake_rx.borrow_and_update().clone();
        assert_eq!(
            observed.descriptor_commit.value(),
            descriptor_bytes.as_slice()
        );
        assert_eq!(observed.kem_id, 2);
        assert_eq!(observed.sig_id, 1);
        let resume = observed
            .resume_hash
            .as_ref()
            .expect("resume hash present")
            .value();
        assert_eq!(resume, resume_bytes.as_slice());
        assert_eq!(observed.pow.difficulty, 6);
        assert_eq!(observed.pow.max_future_skew.as_secs(), 1200);
        assert_eq!(observed.pow.min_ticket_ttl.as_secs(), 90);
        assert_eq!(observed.pow.ticket_ttl.as_secs(), 240);
        let puzzle_cfg = observed.pow.puzzle;
        assert_eq!(puzzle_cfg.memory_kib.get(), 131_072);
        assert_eq!(puzzle_cfg.time_cost.get(), 3);
        assert_eq!(puzzle_cfg.lanes.get(), 2);
        let dto = kiso.get_dto().await.expect("fetch handshake dto");
        let handshake = dto.network.soranet_handshake;
        assert_eq!(handshake.descriptor_commit_hex, descriptor_hex);
        assert_eq!(handshake.kem_id, 2);
        assert_eq!(handshake.sig_id, 1);
        assert_eq!(handshake.resume_hash_hex, Some(resume_hex.clone()));
        assert_eq!(handshake.pow.difficulty, 6);
        assert_eq!(handshake.pow.max_future_skew_secs, 1200);
        assert_eq!(handshake.pow.min_ticket_ttl_secs, 90);
        assert_eq!(handshake.pow.ticket_ttl_secs, 240);
        let puzzle = handshake.pow.puzzle;
        assert_eq!(puzzle.memory_kib, 131_072);
        assert_eq!(puzzle.time_cost, 3);
        assert_eq!(puzzle.lanes, 2);
        // Clear resume hash without touching other fields.
        kiso.update_with_dto(ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::INFO,
                filter: None,
            },
            network_acl: None,
            network: None,
            soranet_handshake: Some(SoranetHandshakeUpdate {
                descriptor_commit_hex: None,
                client_capabilities_hex: None,
                relay_capabilities_hex: None,
                kem_id: None,
                sig_id: None,
                resume_hash_hex: Some(ResumeHashDirective::Clear),
                pow: None,
            }),
            transport: None,
            compute_pricing: None,
        })
        .await
        .expect("resume hash clear should succeed");
        let dto = kiso.get_dto().await.expect("fetch updated dto");
        assert_eq!(dto.network.soranet_handshake.resume_hash_hex, None);
        runtime.await.expect("runtime responder task");
    }
    #[tokio::test]
    async fn soranet_handshake_watch_updates_without_subscribers() {
        let (kiso, _) = KisoHandle::start(test_config());
        let mut runtime_requests = kiso
            .register_soranet_handshake_runtime_applier()
            .await
            .expect("register handshake runtime applier");
        let runtime = tokio::spawn(async move {
            runtime_requests
                .recv()
                .await
                .expect("runtime proposal")
                .respond_to
                .send(Ok(()))
                .expect("Kiso request should remain active");
        });
        let updated_pow = SoranetHandshakePowUpdate {
            difficulty: Some(9),
            max_future_skew_secs: Some(30),
            min_ticket_ttl_secs: Some(15),
            ticket_ttl_secs: Some(45),
            outbound_mint_capacity: None,
            inbound_verify_capacity: None,
            puzzle: Some(SoranetHandshakePuzzleUpdate {
                memory_kib: Some(32 * 1024),
                time_cost: Some(1),
                lanes: Some(2),
            }),
        };
        // Apply the update before any watchers are subscribed.
        kiso.update_with_dto(ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::INFO,
                filter: None,
            },
            network_acl: None,
            network: None,
            soranet_handshake: Some(SoranetHandshakeUpdate {
                descriptor_commit_hex: None,
                client_capabilities_hex: None,
                relay_capabilities_hex: None,
                kem_id: None,
                sig_id: None,
                resume_hash_hex: None,
                pow: Some(updated_pow),
            }),
            transport: None,
            compute_pricing: None,
        })
        .await
        .expect("handshake update should succeed without subscribers");
        let rx = kiso
            .subscribe_on_soranet_handshake_updates()
            .await
            .expect("subscribe to handshake updates");
        let snapshot = rx.borrow().clone();
        assert_eq!(snapshot.pow.difficulty, 9);
        assert_eq!(snapshot.pow.ticket_ttl.as_secs(), 45);
        assert_eq!(snapshot.pow.puzzle.memory_kib.get(), 32 * 1024);
        assert_eq!(snapshot.pow.puzzle.time_cost.get(), 1);
        assert_eq!(snapshot.pow.puzzle.lanes.get(), 2);
        runtime.await.expect("runtime responder task");
    }
    #[tokio::test]
    async fn soranet_runtime_ack_precedes_commit_and_publication() {
        let (kiso, _) = KisoHandle::start(test_config());
        let mut runtime_requests = kiso
            .register_soranet_handshake_runtime_applier()
            .await
            .expect("register runtime applier");
        let mut handshake_updates = kiso
            .subscribe_on_soranet_handshake_updates()
            .await
            .expect("subscribe committed handshake updates");
        let runtime = tokio::spawn(async move {
            let accepted = runtime_requests
                .recv()
                .await
                .expect("accepted runtime proposal");
            assert_eq!(accepted.handshake.pow.difficulty, 6);
            accepted
                .respond_to
                .send(Ok(()))
                .expect("accepted Kiso request should remain active");

            let rejected = runtime_requests
                .recv()
                .await
                .expect("rejected runtime proposal");
            assert_eq!(rejected.handshake.pow.difficulty, 7);
            rejected
                .respond_to
                .send(Err("pow.revocation_store_path restart required".to_owned()))
                .expect("rejected Kiso request should remain active");
        });
        let handshake_update = |difficulty| ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::INFO,
                filter: None,
            },
            network_acl: None,
            network: None,
            soranet_handshake: Some(SoranetHandshakeUpdate {
                descriptor_commit_hex: None,
                client_capabilities_hex: None,
                relay_capabilities_hex: None,
                kem_id: None,
                sig_id: None,
                resume_hash_hex: None,
                pow: Some(SoranetHandshakePowUpdate {
                    difficulty: Some(difficulty),
                    max_future_skew_secs: None,
                    min_ticket_ttl_secs: None,
                    ticket_ttl_secs: None,
                    outbound_mint_capacity: None,
                    inbound_verify_capacity: None,
                    puzzle: None,
                }),
            }),
            transport: None,
            compute_pricing: None,
        };

        kiso.update_with_dto(handshake_update(6))
            .await
            .expect("runtime-accepted update should commit");
        handshake_updates
            .changed()
            .await
            .expect("accepted update should be published");
        assert_eq!(handshake_updates.borrow_and_update().pow.difficulty, 6);
        assert_eq!(
            kiso.get_dto()
                .await
                .expect("accepted config snapshot")
                .network
                .soranet_handshake
                .pow
                .difficulty,
            6
        );

        let error = kiso
            .update_with_dto(handshake_update(7))
            .await
            .expect_err("runtime rejection must reject the Kiso update");
        assert!(matches!(
            error,
            Error::SoranetHandshakeRuntime(message) if message.contains("restart required")
        ));
        assert_eq!(
            kiso.get_dto()
                .await
                .expect("post-rejection config snapshot")
                .network
                .soranet_handshake
                .pow
                .difficulty,
            6,
            "runtime rejection must leave Kiso state unchanged"
        );
        assert!(
            !handshake_updates
                .has_changed()
                .expect("committed handshake watch should remain open"),
            "runtime rejection must not publish the staged snapshot"
        );

        kiso.update_with_dto(ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::DEBUG,
                filter: None,
            },
            network_acl: None,
            network: None,
            soranet_handshake: None,
            transport: None,
            compute_pricing: None,
        })
        .await
        .expect("unrelated update must not require the handshake applier");
        assert_eq!(
            kiso.get_dto()
                .await
                .expect("logger config snapshot")
                .logger
                .level,
            Level::DEBUG
        );
        runtime.await.expect("runtime responder task");
    }
    #[tokio::test]
    async fn soranet_sm_policy_update_rejects_relaxation() {
        let config = test_config();
        let (kiso, _) = KisoHandle::start(config);
        let err = kiso
            .update_with_dto(ConfigurationUpdate {
                logger: LoggerDTO {
                    level: Level::INFO,
                    filter: None,
                },
                network_acl: None,
                network: Some(NetworkUpdate {
                    lane_profile: None,
                    require_sm_handshake_match: Some(false),
                    require_sm_openssl_preview_match: Some(false),
                }),
                soranet_handshake: None,
                transport: None,
                compute_pricing: None,
            })
            .await
            .expect_err("SM policy relaxation should be rejected");
        assert!(
            err.to_string()
                .contains("SM handshake matching is mandatory"),
            "unexpected error: {err}"
        );
        let err = kiso
            .update_with_dto(ConfigurationUpdate {
                logger: LoggerDTO {
                    level: Level::INFO,
                    filter: None,
                },
                network_acl: None,
                network: Some(NetworkUpdate {
                    lane_profile: None,
                    require_sm_handshake_match: None,
                    require_sm_openssl_preview_match: Some(false),
                }),
                soranet_handshake: None,
                transport: None,
                compute_pricing: None,
            })
            .await
            .expect_err("SM OpenSSL preview relaxation should be rejected");
        assert!(
            err.to_string()
                .contains("SM OpenSSL preview matching is mandatory"),
            "unexpected error: {err}"
        );
        let dto = kiso.get_dto().await.expect("fetch updated dto");
        assert!(dto.network.require_sm_handshake_match);
        assert!(dto.network.require_sm_openssl_preview_match);
    }
    #[tokio::test]
    async fn invalid_logger_filter_does_not_publish_or_change_configuration() {
        let (kiso, _child) = KisoHandle::start(test_config());
        let before = kiso.get_dto().await.expect("configuration before update");
        let error = kiso
            .update_with_dto(ConfigurationUpdate {
                logger: LoggerDTO {
                    level: Level::DEBUG,
                    filter: Some("module=not-a-level".to_owned()),
                },
                network_acl: None,
                network: None,
                soranet_handshake: None,
                transport: None,
                compute_pricing: None,
            })
            .await
            .expect_err("node must reject invalid tracing directives");
        assert!(error.to_string().contains("invalid logger filter"));
        let after = kiso.get_dto().await.expect("configuration after rejection");
        assert_eq!(
            norito::json::to_json(&before).expect("encode original configuration"),
            norito::json::to_json(&after).expect("encode unchanged configuration"),
        );
    }
    #[tokio::test]
    async fn lane_profile_update_applies_runtime_derived_limits() {
        let config = test_config();
        let (logger_tx, _) = watch::channel(config.logger.clone());
        let (network_acl_tx, _) = watch::channel(Actor::snapshot_network_acl(&config));
        let (handshake_tx, _) = watch::channel(config.network.soranet_handshake.clone());
        let (_, handle_rx) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let mut actor = Actor {
            handle: handle_rx,
            state: config,
            logger_update: logger_tx,
            network_acl_update: network_acl_tx,
            soranet_handshake_update: handshake_tx,
            soranet_handshake_applier: None,
        };
        for wire_profile in [
            iroha_torii_shared::configuration::LaneProfile::Home,
            iroha_torii_shared::configuration::LaneProfile::Core,
        ] {
            Box::pin(actor.apply_config_update(ConfigurationUpdate {
                logger: LoggerDTO {
                    level: Level::INFO,
                    filter: None,
                },
                network_acl: None,
                network: Some(NetworkUpdate {
                    lane_profile: Some(wire_profile),
                    require_sm_handshake_match: None,
                    require_sm_openssl_preview_match: None,
                }),
                soranet_handshake: None,
                transport: None,
                compute_pricing: None,
            }))
            .await
            .expect("wire profile update must use its runtime limits");
            let expected: iroha_config::parameters::actual::LaneProfile = wire_profile.into();
            let limits = expected.derived_limits();
            let network = &actor.state.network;
            assert_eq!(network.lane_profile, expected);
            assert_eq!(network.max_incoming, limits.max_incoming);
            assert_eq!(network.max_total_connections, limits.max_total_connections);
            assert_eq!(
                network.low_priority_bytes_per_sec,
                limits.low_priority_bytes_per_sec
            );
            assert_eq!(
                network.low_priority_rate_per_sec,
                limits.low_priority_rate_per_sec
            );
        }
    }
    #[tokio::test]
    async fn config_update_is_atomic_on_handshake_error() {
        let config = test_config();
        let (logger_tx, logger_rx) = watch::channel(config.logger.clone());
        let (network_acl_tx, network_acl_rx) = watch::channel(Actor::snapshot_network_acl(&config));
        let (handshake_tx, handshake_rx) = watch::channel(config.network.soranet_handshake.clone());
        let (_, handle_rx) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let mut actor = Actor {
            handle: handle_rx,
            state: config,
            logger_update: logger_tx,
            network_acl_update: network_acl_tx,
            soranet_handshake_update: handshake_tx,
            soranet_handshake_applier: None,
        };
        let initial_logger_level = actor.state.logger.level;
        let initial_allowlist_only = actor.state.network.allowlist_only;
        let initial_allow_keys = actor.state.network.allow_keys.clone();
        let initial_deny_keys = actor.state.network.deny_keys.clone();
        let initial_allow_cidrs = actor.state.network.allow_cidrs.clone();
        let initial_deny_cidrs = actor.state.network.deny_cidrs.clone();
        let initial_descriptor = actor
            .state
            .network
            .soranet_handshake
            .descriptor_commit
            .value()
            .clone();
        let initial_kem_id = actor.state.network.soranet_handshake.kem_id;
        let initial_sig_id = actor.state.network.soranet_handshake.sig_id;
        let replacement_key = checked_public_key();
        let err = Box::pin(actor.apply_config_update(ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::DEBUG,
                filter: None,
            },
            network_acl: Some(NetworkAcl {
                allowlist_only: Some(!initial_allowlist_only),
                allow_keys: Some(vec![replacement_key]),
                deny_keys: None,
                allow_cidrs: None,
                deny_cidrs: None,
            }),
            network: None,
            soranet_handshake: Some(SoranetHandshakeUpdate {
                descriptor_commit_hex: Some("0102".to_string()),
                client_capabilities_hex: Some("zz".to_string()),
                relay_capabilities_hex: None,
                kem_id: Some(initial_kem_id.saturating_add(1)),
                sig_id: Some(initial_sig_id.saturating_add(1)),
                resume_hash_hex: None,
                pow: None,
            }),
            transport: None,
            compute_pricing: None,
        }))
        .await
        .expect_err("handshake validation should fail");
        assert!(
            matches!(err, Error::Validation(msg) if msg.contains("invalid hex in client_capabilities_hex"))
        );
        assert_eq!(actor.state.logger.level, initial_logger_level);
        assert_eq!(actor.state.network.allowlist_only, initial_allowlist_only);
        assert_eq!(actor.state.network.allow_keys, initial_allow_keys);
        assert_eq!(actor.state.network.deny_keys, initial_deny_keys);
        assert_eq!(actor.state.network.allow_cidrs, initial_allow_cidrs);
        assert_eq!(actor.state.network.deny_cidrs, initial_deny_cidrs);
        assert_eq!(
            actor
                .state
                .network
                .soranet_handshake
                .descriptor_commit
                .value(),
            initial_descriptor.as_slice()
        );
        assert_eq!(actor.state.network.soranet_handshake.kem_id, initial_kem_id);
        assert_eq!(actor.state.network.soranet_handshake.sig_id, initial_sig_id);
        assert_eq!(logger_rx.borrow().level, initial_logger_level);
        assert!(logger_rx.borrow().filter.is_none());
        let acl_snapshot = network_acl_rx.borrow();
        assert_eq!(acl_snapshot.allowlist_only, Some(initial_allowlist_only));
        assert_eq!(
            acl_snapshot.allow_keys.as_ref().unwrap(),
            &initial_allow_keys
        );
        assert_eq!(acl_snapshot.deny_keys.as_ref().unwrap(), &initial_deny_keys);
        assert_eq!(
            acl_snapshot.allow_cidrs.as_ref().unwrap(),
            &initial_allow_cidrs
        );
        assert_eq!(
            acl_snapshot.deny_cidrs.as_ref().unwrap(),
            &initial_deny_cidrs
        );
        let handshake_snapshot = handshake_rx.borrow();
        assert_eq!(
            handshake_snapshot.descriptor_commit.value(),
            initial_descriptor.as_slice()
        );
        assert_eq!(handshake_snapshot.kem_id, initial_kem_id);
        assert_eq!(handshake_snapshot.sig_id, initial_sig_id);
    }
    #[tokio::test]
    async fn config_update_is_atomic_on_transport_error() {
        let config = test_config();
        let (logger_tx, logger_rx) = watch::channel(config.logger.clone());
        let (network_acl_tx, network_acl_rx) = watch::channel(Actor::snapshot_network_acl(&config));
        let (handshake_tx, handshake_rx) = watch::channel(config.network.soranet_handshake.clone());
        let (_, handle_rx) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let mut actor = Actor {
            handle: handle_rx,
            state: config,
            logger_update: logger_tx,
            network_acl_update: network_acl_tx,
            soranet_handshake_update: handshake_tx,
            soranet_handshake_applier: None,
        };
        let initial_logger_level = actor.state.logger.level;
        let initial_allowlist_only = actor.state.network.allowlist_only;
        let initial_allow_keys = actor.state.network.allow_keys.clone();
        let initial_transport_enabled = actor.state.torii.transport.norito_rpc.enabled;
        let initial_transport_require_mtls = actor.state.torii.transport.norito_rpc.require_mtls;
        let initial_transport_allowed = actor
            .state
            .torii
            .transport
            .norito_rpc
            .allowed_clients
            .clone();
        let initial_transport_stage = actor.state.torii.transport.norito_rpc.stage;
        let err = Box::pin(actor.apply_config_update(ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::WARN,
                filter: None,
            },
            network_acl: Some(NetworkAcl {
                allowlist_only: Some(!initial_allowlist_only),
                allow_keys: Some(vec![checked_public_key()]),
                deny_keys: None,
                allow_cidrs: None,
                deny_cidrs: None,
            }),
            network: None,
            soranet_handshake: None,
            transport: Some(TransportUpdate {
                norito_rpc: Some(iroha_torii_shared::configuration::NoritoRpcUpdate {
                    enabled: Some(!initial_transport_enabled),
                    require_mtls: Some(!initial_transport_require_mtls),
                    allowed_clients: Some(vec!["canary".to_string()]),
                    stage: Some("not-a-stage".to_string()),
                }),
            }),
            compute_pricing: None,
        }))
        .await
        .expect_err("transport validation should fail");
        assert!(
            matches!(err, Error::Validation(msg) if msg.contains("invalid transport.norito_rpc.stage"))
        );
        assert_eq!(actor.state.logger.level, initial_logger_level);
        assert_eq!(actor.state.network.allowlist_only, initial_allowlist_only);
        assert_eq!(actor.state.network.allow_keys, initial_allow_keys);
        assert_eq!(
            actor.state.torii.transport.norito_rpc.enabled,
            initial_transport_enabled
        );
        assert_eq!(
            actor.state.torii.transport.norito_rpc.require_mtls,
            initial_transport_require_mtls
        );
        assert_eq!(
            actor.state.torii.transport.norito_rpc.allowed_clients,
            initial_transport_allowed
        );
        assert_eq!(
            actor.state.torii.transport.norito_rpc.stage,
            initial_transport_stage
        );
        assert_eq!(logger_rx.borrow().level, initial_logger_level);
        let acl_snapshot = network_acl_rx.borrow();
        assert_eq!(acl_snapshot.allowlist_only, Some(initial_allowlist_only));
        assert_eq!(
            acl_snapshot.allow_keys.as_ref().unwrap(),
            &initial_allow_keys
        );
        let handshake_snapshot = handshake_rx.borrow();
        assert_eq!(
            handshake_snapshot.kem_id,
            actor.state.network.soranet_handshake.kem_id
        );
    }
    #[tokio::test]
    async fn compute_pricing_updates_enforce_delta_bounds() {
        let config = test_config();
        let (logger_tx, _) = watch::channel(config.logger.clone());
        let (network_acl_tx, _) = watch::channel(Actor::snapshot_network_acl(&config));
        let (handshake_tx, _) = watch::channel(config.network.soranet_handshake.clone());
        let (_, handle_rx) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let mut actor = Actor {
            handle: handle_rx,
            state: config,
            logger_update: logger_tx,
            network_acl_update: network_acl_tx,
            soranet_handshake_update: handshake_tx,
            soranet_handshake_applier: None,
        };
        let family = defaults::compute::default_price_family();
        let mut invalid = actor
            .state
            .compute
            .price_families
            .get(&family)
            .cloned()
            .expect("default price family present");
        invalid.cycles_per_unit =
            NonZeroU64::new(invalid.cycles_per_unit.get().saturating_mul(2)).expect("non-zero");
        let err = Box::pin(actor.apply_config_update(ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::INFO,
                filter: None,
            },
            network_acl: None,
            network: None,
            soranet_handshake: None,
            transport: None,
            compute_pricing: Some(ComputePricingUpdate {
                price_families: [(family.clone(), invalid)].into_iter().collect(),
                default_price_family: None,
            }),
        }))
        .await
        .expect_err("delta beyond bounds should be rejected");
        assert!(matches!(err, Error::Validation(msg) if msg.contains("delta")));
        let mut ok = actor
            .state
            .compute
            .price_families
            .get(&family)
            .cloned()
            .expect("default price family present");
        ok.cycles_per_unit = NonZeroU64::new(
            ok.cycles_per_unit
                .get()
                .saturating_add(ok.cycles_per_unit.get() / 10),
        )
        .expect("non-zero");
        Box::pin(actor.apply_config_update(ConfigurationUpdate {
            logger: LoggerDTO {
                level: Level::INFO,
                filter: None,
            },
            network_acl: None,
            network: None,
            soranet_handshake: None,
            transport: None,
            compute_pricing: Some(ComputePricingUpdate {
                price_families: [(family.clone(), ok.clone())].into_iter().collect(),
                default_price_family: None,
            }),
        }))
        .await
        .expect("delta within bounds should apply");
        assert_eq!(actor.state.compute.price_families.get(&family), Some(&ok));
    }
}
