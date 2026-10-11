mod monitor;
#[cfg(test)]
mod shared_client_tests;
use crate::{
    explorer::ExplorerDurationDto,
    json_macros::{JsonDeserialize, JsonSerialize},
};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::NetworkId;
use iroha_futures::supervisor::ShutdownSignal;
use iroha_torii_shared::configuration::Configuration;
use monitor::Metrics as PeerMetricsSnapshot;
pub use monitor::Update;
#[cfg(test)]
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};
use tokio::{
    sync::RwLock,
    task::{JoinHandle, JoinSet},
};
use url::Url;
const PROPAGATION_HISTORY_LIMIT: usize = 64;
const PROPAGATION_SNAPSHOT_LIMIT: usize = 32;
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
pub struct GeoLocation {
    pub lat: f64,
    pub lon: f64,
    pub country: String,
    pub city: String,
}
#[derive(Clone, Debug, JsonSerialize)]
pub struct PeerConfigDto {
    #[norito(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub queue_capacity: Option<u32>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub network_block_gossip_size: Option<u32>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub network_block_gossip_period: Option<ExplorerDurationDto>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub network_tx_gossip_size: Option<u32>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub network_tx_gossip_period: Option<ExplorerDurationDto>,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct PeerConfigSnapshot {
    pub public_key: Option<PublicKey>,
    pub queue_capacity: Option<u32>,
    pub network_block_gossip_size: Option<u32>,
    pub network_block_gossip_period_ms: Option<u64>,
    pub network_tx_gossip_size: Option<u32>,
    pub network_tx_gossip_period_ms: Option<u64>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub struct PeerInfoDto {
    pub url: String,
    pub connected: bool,
    pub telemetry_unsupported: bool,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub config: Option<PeerConfigDto>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub location: Option<GeoLocation>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub connected_peers: Option<Vec<String>>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub struct PeerStatusDto {
    pub url: String,
    pub block: u32,
    pub commit_time: ExplorerDurationDto,
    pub avg_commit_time: ExplorerDurationDto,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub status_rtt: Option<ExplorerDurationDto>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub status_rtt_avg: Option<ExplorerDurationDto>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub status_rtt_p95: Option<ExplorerDurationDto>,
    pub queue_size: u32,
    pub uptime: ExplorerDurationDto,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub propagation_time: Option<ExplorerDurationDto>,
    #[norito(skip_serializing_if = "Option::is_none")]
    pub observed_at_ms: Option<u64>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub struct PeerPropagationDto {
    pub block: u32,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
    pub spread_ms: u64,
    pub peers_reported: u32,
}
#[derive(Clone, Debug)]
pub struct PeerTelemetrySnapshot {
    pub peers_info: Vec<PeerInfoDto>,
    pub peers_status: Vec<PeerStatusDto>,
    pub propagation: Vec<PeerPropagationDto>,
}
#[derive(Clone, Debug)]
pub struct GeoLookupConfig {
    pub enabled: bool,
    pub endpoint: Option<Url>,
}
impl GeoLookupConfig {
    #[cfg(test)]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            endpoint: None,
        }
    }
}
impl From<&iroha_config::parameters::actual::ToriiPeerGeo> for GeoLookupConfig {
    fn from(config: &iroha_config::parameters::actual::ToriiPeerGeo) -> Self {
        Self {
            enabled: config.enabled,
            endpoint: config.endpoint.clone(),
        }
    }
}
pub struct PeerTelemetryService {
    peers: RwLock<BTreeMap<ToriiUrl, PeerState>>,
    propagation: RwLock<PropagationTracker>,
    peer_urls: BTreeSet<ToriiUrl>,
    geo_config: GeoLookupConfig,
    network_id: NetworkId,
    operator_signer: Option<KeyPair>,
}

async fn drain_peer_monitor_workers(workers: &mut JoinSet<crate::ToriiCriticalWorkerExit>) -> bool {
    let mut failed = false;
    while let Some(result) = workers.join_next().await {
        match result {
            Ok(crate::ToriiCriticalWorkerExit::StoppedByShutdown) => {}
            Ok(crate::ToriiCriticalWorkerExit::UnexpectedExit) => {
                failed = true;
            }
            Err(error) => {
                iroha_logger::error!(?error, "peer telemetry worker failed during shutdown");
                failed = true;
            }
        }
    }
    failed
}

async fn abort_peer_monitor_workers(workers: &mut JoinSet<crate::ToriiCriticalWorkerExit>) {
    workers.abort_all();
    while let Some(result) = workers.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            iroha_logger::error!(
                ?error,
                "peer telemetry worker failed while stopping its siblings"
            );
        }
    }
}

fn classify_peer_monitor_exit(
    url: &ToriiUrl,
    shutdown_signal: &ShutdownSignal,
    exit: crate::ToriiCriticalWorkerExit,
) -> crate::ToriiCriticalWorkerExit {
    match exit {
        crate::ToriiCriticalWorkerExit::StoppedByShutdown if shutdown_signal.is_sent() => exit,
        crate::ToriiCriticalWorkerExit::StoppedByShutdown => {
            iroha_logger::error!(
                %url,
                "peer telemetry monitor reported shutdown before shutdown was sent"
            );
            crate::ToriiCriticalWorkerExit::UnexpectedExit
        }
        crate::ToriiCriticalWorkerExit::UnexpectedExit => {
            iroha_logger::error!(%url, "peer telemetry monitor failed");
            exit
        }
    }
}

async fn supervise_peer_monitor_workers(
    shutdown_signal: &ShutdownSignal,
    mut workers: JoinSet<crate::ToriiCriticalWorkerExit>,
) -> crate::ToriiCriticalWorkerExit {
    loop {
        tokio::select! {
            biased;
            () = shutdown_signal.receive() => {
                let failed = drain_peer_monitor_workers(&mut workers).await;
                return if failed {
                    crate::ToriiCriticalWorkerExit::UnexpectedExit
                } else {
                    crate::ToriiCriticalWorkerExit::StoppedByShutdown
                };
            }
            result = workers.join_next() => match result {
                Some(Ok(crate::ToriiCriticalWorkerExit::StoppedByShutdown))
                    if shutdown_signal.is_sent() =>
                {
                    let failed = drain_peer_monitor_workers(&mut workers).await;
                    return if failed {
                        crate::ToriiCriticalWorkerExit::UnexpectedExit
                    } else {
                        crate::ToriiCriticalWorkerExit::StoppedByShutdown
                    };
                }
                Some(Ok(crate::ToriiCriticalWorkerExit::StoppedByShutdown)) => {
                    abort_peer_monitor_workers(&mut workers).await;
                    return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                }
                Some(Ok(crate::ToriiCriticalWorkerExit::UnexpectedExit)) => {
                    abort_peer_monitor_workers(&mut workers).await;
                    return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                }
                Some(Err(error)) => {
                    iroha_logger::error!(
                        ?error,
                        "peer telemetry worker failed before shutdown"
                    );
                    abort_peer_monitor_workers(&mut workers).await;
                    return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                }
                None if shutdown_signal.is_sent() => {
                    return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                }
                None => return crate::ToriiCriticalWorkerExit::UnexpectedExit,
            },
        }
    }
}

impl PeerTelemetryService {
    pub fn new(
        peer_urls: Vec<ToriiUrl>,
        geo_config: GeoLookupConfig,
        network_id: NetworkId,
        operator_signer: Option<KeyPair>,
    ) -> Arc<Self> {
        Arc::new(Self {
            peers: RwLock::new(BTreeMap::new()),
            propagation: RwLock::new(PropagationTracker::default()),
            peer_urls: BTreeSet::from_iter(peer_urls),
            geo_config,
            network_id,
            operator_signer,
        })
    }
    /// Start the configured peer monitors under the supplied shutdown signal.
    ///
    /// Returns `None` when no peer telemetry URLs were configured. The returned
    /// task owns HTTP pool initialization and every per-peer worker. One pool is shared
    /// across configured URLs and reconnects; normal shutdown awaits its initializer
    /// and workers. Callers should keep and supervise its [`JoinHandle`].
    pub(crate) fn start(
        self: &Arc<Self>,
        shutdown_signal: ShutdownSignal,
    ) -> Option<JoinHandle<crate::ToriiCriticalWorkerExit>> {
        self.start_with_http_factory(shutdown_signal, monitor::peer_monitor_http_client)
    }

    // One start owns its successful pool and the blocking initialization task. The factory
    // seam keeps native construction, retry and shutdown controls on this shipping path.
    fn start_with_http_factory<F>(
        self: &Arc<Self>,
        shutdown_signal: ShutdownSignal,
        factory: F,
    ) -> Option<JoinHandle<crate::ToriiCriticalWorkerExit>>
    where
        F: FnMut() -> Result<reqwest::Client, reqwest::Error> + Send + 'static,
    {
        if self.peer_urls.is_empty() {
            return None;
        }

        let service = Arc::clone(self);
        Some(tokio::spawn(async move {
            let (client, initial_config_interval) =
                match monitor::initialize_http_client(&shutdown_signal, factory).await {
                    Ok(Some(initialized)) => initialized,
                    Ok(None) => return crate::ToriiCriticalWorkerExit::StoppedByShutdown,
                    Err(error) => {
                        iroha_logger::error!(
                            ?error,
                            "peer telemetry HTTP initialization task failed"
                        );
                        return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                    }
                };
            let mut workers = JoinSet::new();
            for url in service.peer_urls.iter().cloned() {
                let service = Arc::clone(&service);
                let worker_shutdown = shutdown_signal.clone();
                let client = client.clone();
                workers.spawn(async move {
                    service
                        .monitor_peer(url, client, initial_config_interval, worker_shutdown)
                        .await
                });
            }

            supervise_peer_monitor_workers(&shutdown_signal, workers).await
        }))
    }
    async fn monitor_peer(
        self: &Arc<Self>,
        url: ToriiUrl,
        client: reqwest::Client,
        initial_config_interval: std::time::Duration,
        shutdown_signal: ShutdownSignal,
    ) -> crate::ToriiCriticalWorkerExit {
        let (mut rx, monitor) = monitor::run(
            url.clone(),
            client,
            initial_config_interval,
            self.geo_config.clone(),
            self.network_id,
            self.operator_signer.clone(),
            shutdown_signal.clone(),
        );
        tokio::pin!(monitor);
        loop {
            tokio::select! {
                biased;
                exit = &mut monitor => {
                    return classify_peer_monitor_exit(&url, &shutdown_signal, exit);
                }
                update = rx.recv() => match update {
                    Some(update) => self.apply_update(url.clone(), update).await,
                    None if shutdown_signal.is_sent() => {
                        let exit = (&mut monitor).await;
                        return classify_peer_monitor_exit(&url, &shutdown_signal, exit);
                    }
                    None => {
                        iroha_logger::error!(
                            %url,
                            "peer telemetry update stream closed before shutdown"
                        );
                        return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                    }
                },
            }
        }
    }
    async fn apply_update(&self, url: ToriiUrl, update: Update) {
        let peer_url = url.as_str().to_owned();
        let mut metrics_update = None;
        let mut guard = self.peers.write().await;
        let state = guard
            .entry(url.clone())
            .or_insert_with(|| PeerState::new(url.clone()));
        match update {
            Update::Connected(config) => {
                state.connected = true;
                state.telemetry_unsupported = false;
                state.config = Some(*config);
            }
            Update::Disconnected => {
                state.connected = false;
            }
            Update::TelemetryUnsupported => {
                state.telemetry_unsupported = true;
            }
            Update::Geo(geo) => {
                state.geo = Some(geo);
            }
            Update::Peers(peers) => {
                let list = peers
                    .into_iter()
                    .map(|pk| pk.to_string())
                    .collect::<Vec<_>>();
                state.connected_peers = Some(list);
            }
            Update::Metrics(metrics) => {
                state.metrics = Some(metrics);
                metrics_update = Some(metrics);
            }
        }
        drop(guard);
        if let Some(metrics) = metrics_update {
            self.observe_propagation(&peer_url, metrics).await;
        }
    }
    async fn observe_propagation(&self, peer_url: &str, metrics: PeerMetricsSnapshot) {
        let Some(observed_at_ms) = metrics.observed_at_ms else {
            return;
        };
        let mut propagation = self.propagation.write().await;
        propagation.observe(peer_url, metrics.block, observed_at_ms);
    }
    pub async fn peers_info(&self) -> Vec<PeerInfoDto> {
        let guard = self.peers.read().await;
        guard.values().map(PeerState::info).collect()
    }
    #[cfg(test)]
    pub async fn peers_status(&self) -> Vec<PeerStatusDto> {
        let first_seen_by_block = {
            let propagation = self.propagation.read().await;
            propagation.first_seen_by_block()
        };
        let guard = self.peers.read().await;
        guard
            .values()
            .filter_map(|peer| peer.status(&first_seen_by_block))
            .collect()
    }
    pub async fn propagation(&self, limit: usize) -> Vec<PeerPropagationDto> {
        let propagation = self.propagation.read().await;
        propagation.snapshot(limit)
    }
    pub async fn snapshot(&self) -> PeerTelemetrySnapshot {
        let (first_seen_by_block, propagation) = {
            let propagation = self.propagation.read().await;
            (
                propagation.first_seen_by_block(),
                propagation.snapshot(PROPAGATION_SNAPSHOT_LIMIT),
            )
        };
        let guard = self.peers.read().await;
        let peers_info = guard.values().map(PeerState::info).collect();
        let peers_status = guard
            .values()
            .filter_map(|peer| peer.status(&first_seen_by_block))
            .collect();
        PeerTelemetrySnapshot {
            peers_info,
            peers_status,
            propagation,
        }
    }
}
/// Error returned when a peer telemetry URL is not a canonical Torii HTTP origin.
#[derive(Debug, thiserror::Error)]
#[error("invalid Torii peer telemetry URL: {reason}")]
pub struct ToriiUrlError {
    reason: String,
}
impl ToriiUrlError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}
/// Validated, credential-free Torii HTTP(S) origin with infallibly derived endpoints.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ToriiUrl {
    base: Url,
    configuration_endpoint: Url,
    peers_endpoint: Url,
    status_endpoint: Url,
}
impl ToriiUrl {
    pub fn as_str(&self) -> &str {
        self.base.as_str()
    }
    pub fn host_str(&self) -> Option<&str> {
        self.base.host_str()
    }
    pub(super) fn configuration_endpoint(&self) -> &Url {
        &self.configuration_endpoint
    }
    pub(super) fn peers_endpoint(&self) -> &Url {
        &self.peers_endpoint
    }
    pub(super) fn status_endpoint(&self) -> &Url {
        &self.status_endpoint
    }
}
impl fmt::Display for ToriiUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base)
    }
}
impl FromStr for ToriiUrl {
    type Err = ToriiUrlError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s)
            .map_err(|error| ToriiUrlError::new(format!("failed to parse URL: {error}")))?;
        let origin = Self::try_from(url)?;
        // URL parsing discards an empty userinfo marker. Inspect the original
        // input as well so `https://@host/` cannot bypass credential rejection.
        if s.contains('@') {
            return Err(ToriiUrlError::new("URL must not contain user credentials"));
        }
        Ok(origin)
    }
}
impl TryFrom<Url> for ToriiUrl {
    type Error = ToriiUrlError;
    fn try_from(url: Url) -> Result<Self, Self::Error> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ToriiUrlError::new(format!(
                "scheme `{}` is not HTTP or HTTPS",
                url.scheme()
            )));
        }
        if url.cannot_be_a_base() {
            return Err(ToriiUrlError::new("URL cannot be used as a base URL"));
        }
        if url.host_str().is_none() {
            return Err(ToriiUrlError::new("URL does not contain a host"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ToriiUrlError::new("URL must not contain user credentials"));
        }
        if url.path() != "/" {
            return Err(ToriiUrlError::new("URL path must be exactly `/`"));
        }
        if url.query().is_some() {
            return Err(ToriiUrlError::new("URL must not contain a query"));
        }
        if url.fragment().is_some() {
            return Err(ToriiUrlError::new("URL must not contain a fragment"));
        }
        let canonical_origin = format!("{}/", url.origin().ascii_serialization());
        if url.as_str() != canonical_origin {
            return Err(ToriiUrlError::new("URL must be a canonical HTTP(S) origin"));
        }
        let derive_endpoint = |path: &'static str| {
            url.join(path).map_err(|error| {
                ToriiUrlError::new(format!("failed to derive endpoint `{path}`: {error}"))
            })
        };
        let configuration_endpoint =
            derive_endpoint(iroha_torii_shared::route_catalog::core::CONFIGURATION_GET.path())?;
        let peers_endpoint =
            derive_endpoint(iroha_torii_shared::route_catalog::core::PEERS.path())?;
        let status_endpoint = derive_endpoint("/status")?;
        Ok(Self {
            base: url,
            configuration_endpoint,
            peers_endpoint,
            status_endpoint,
        })
    }
}
impl TryFrom<SocketAddr> for ToriiUrl {
    type Error = ToriiUrlError;
    fn try_from(addr: SocketAddr) -> Result<Self, Self::Error> {
        format!("http://{addr}").parse()
    }
}
struct PeerState {
    url: ToriiUrl,
    connected: bool,
    telemetry_unsupported: bool,
    config: Option<PeerConfigSnapshot>,
    geo: Option<GeoLocation>,
    connected_peers: Option<Vec<String>>,
    metrics: Option<PeerMetricsSnapshot>,
}
impl PeerState {
    fn new(url: ToriiUrl) -> Self {
        Self {
            url,
            connected: false,
            telemetry_unsupported: false,
            config: None,
            geo: None,
            connected_peers: None,
            metrics: None,
        }
    }
    fn info(&self) -> PeerInfoDto {
        PeerInfoDto {
            url: self.url.as_str().to_string(),
            connected: self.connected,
            telemetry_unsupported: self.telemetry_unsupported,
            config: self.config.as_ref().map(PeerConfigDto::from_config),
            location: self.geo.clone(),
            connected_peers: self.connected_peers.clone(),
        }
    }
    fn status(&self, first_seen_by_block: &BTreeMap<u32, u64>) -> Option<PeerStatusDto> {
        let metrics = self.metrics?;
        let propagation_time = metrics.observed_at_ms.and_then(|observed_at_ms| {
            first_seen_by_block
                .get(&metrics.block)
                .copied()
                .map(|first_seen_ms| observed_at_ms.saturating_sub(first_seen_ms))
        });
        Some(PeerStatusDto {
            url: self.url.as_str().to_string(),
            block: metrics.block,
            commit_time: ExplorerDurationDto {
                ms: duration_ms_u64(metrics.block_commit_time),
            },
            avg_commit_time: ExplorerDurationDto {
                ms: duration_ms_u64(metrics.avg_commit_time),
            },
            status_rtt: metrics.status_rtt.map(|duration| ExplorerDurationDto {
                ms: duration_ms_u64(duration),
            }),
            status_rtt_avg: metrics.status_rtt_avg.map(|duration| ExplorerDurationDto {
                ms: duration_ms_u64(duration),
            }),
            status_rtt_p95: metrics.status_rtt_p95.map(|duration| ExplorerDurationDto {
                ms: duration_ms_u64(duration),
            }),
            queue_size: metrics.queue_size,
            uptime: ExplorerDurationDto {
                ms: duration_ms_u64(metrics.uptime),
            },
            propagation_time: propagation_time.map(|ms| ExplorerDurationDto { ms }),
            observed_at_ms: metrics.observed_at_ms,
        })
    }
}
fn duration_ms_u64(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
#[derive(Default)]
struct PropagationTracker {
    by_block: BTreeMap<u32, BlockPropagationEntry>,
}
impl PropagationTracker {
    fn observe(&mut self, peer_url: &str, block: u32, observed_at_ms: u64) {
        match self.by_block.entry(block) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(BlockPropagationEntry::new(peer_url, observed_at_ms));
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                slot.get_mut().observe(peer_url, observed_at_ms);
            }
        }
        while self.by_block.len() > PROPAGATION_HISTORY_LIMIT {
            let Some(oldest) = self.by_block.keys().next().copied() else {
                break;
            };
            self.by_block.remove(&oldest);
        }
    }
    fn first_seen_by_block(&self) -> BTreeMap<u32, u64> {
        self.by_block
            .iter()
            .map(|(block, entry)| (*block, entry.first_seen_at_ms))
            .collect()
    }
    fn snapshot(&self, limit: usize) -> Vec<PeerPropagationDto> {
        if limit == 0 {
            return Vec::new();
        }
        let mut entries = self
            .by_block
            .iter()
            .rev()
            .take(limit)
            .map(|(block, entry)| PeerPropagationDto {
                block: *block,
                first_seen_at_ms: entry.first_seen_at_ms,
                last_seen_at_ms: entry.last_seen_at_ms,
                spread_ms: entry.spread_ms(),
                peers_reported: entry.peers_reported(),
            })
            .collect::<Vec<_>>();
        entries.reverse();
        entries
    }
}
#[derive(Clone, Debug)]
struct BlockPropagationEntry {
    first_seen_at_ms: u64,
    last_seen_at_ms: u64,
    peers: BTreeSet<String>,
}
impl BlockPropagationEntry {
    fn new(peer_url: &str, observed_at_ms: u64) -> Self {
        let mut peers = BTreeSet::new();
        peers.insert(peer_url.to_owned());
        Self {
            first_seen_at_ms: observed_at_ms,
            last_seen_at_ms: observed_at_ms,
            peers,
        }
    }
    fn observe(&mut self, peer_url: &str, observed_at_ms: u64) {
        if !self.peers.insert(peer_url.to_owned()) {
            return;
        }
        self.first_seen_at_ms = self.first_seen_at_ms.min(observed_at_ms);
        self.last_seen_at_ms = self.last_seen_at_ms.max(observed_at_ms);
    }
    fn spread_ms(&self) -> u64 {
        self.last_seen_at_ms.saturating_sub(self.first_seen_at_ms)
    }
    fn peers_reported(&self) -> u32 {
        u32::try_from(self.peers.len()).unwrap_or(u32::MAX)
    }
}
impl PeerConfigDto {
    fn from_config(cfg: &PeerConfigSnapshot) -> Self {
        Self {
            public_key: cfg.public_key.as_ref().map(ToString::to_string),
            queue_capacity: cfg.queue_capacity,
            network_block_gossip_size: cfg.network_block_gossip_size,
            network_block_gossip_period: cfg
                .network_block_gossip_period_ms
                .map(|ms| ExplorerDurationDto { ms: ms.into() }),
            network_tx_gossip_size: cfg.network_tx_gossip_size,
            network_tx_gossip_period: cfg
                .network_tx_gossip_period_ms
                .map(|ms| ExplorerDurationDto { ms: ms.into() }),
        }
    }
}
impl From<&Configuration> for PeerConfigSnapshot {
    fn from(cfg: &Configuration) -> Self {
        Self {
            public_key: Some(cfg.public_key.clone()),
            queue_capacity: cfg.queue.capacity.get().try_into().ok(),
            network_block_gossip_size: Some(cfg.network.block_gossip_size.get()),
            network_block_gossip_period_ms: Some(cfg.network.block_gossip_period_ms.into()),
            network_tx_gossip_size: Some(cfg.network.transaction_gossip_size.get()),
            network_tx_gossip_period_ms: Some(cfg.network.transaction_gossip_period_ms.into()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn geo_lookup_config_respects_disable_helper() {
        let config = GeoLookupConfig::disabled();
        assert!(!config.enabled);
        assert!(config.endpoint.is_none());
    }
    #[test]
    fn geo_lookup_config_from_actual_copies_values() {
        let endpoint = Url::parse("https://geo.example").expect("valid endpoint");
        let actual = iroha_config::parameters::actual::ToriiPeerGeo {
            enabled: true,
            endpoint: Some(endpoint.clone()),
        };
        let config = GeoLookupConfig::from(&actual);
        assert!(config.enabled);
        assert_eq!(
            config.endpoint.as_ref().map(Url::as_str),
            Some(endpoint.as_str())
        );
    }
    #[test]
    fn torii_url_accepts_http_bases_and_prederives_exact_endpoints() {
        let url: ToriiUrl = "https://peer.example:8443/"
            .parse()
            .expect("valid HTTPS Torii base URL");

        assert_eq!(url.as_str(), "https://peer.example:8443/");
        assert_eq!(
            url.configuration_endpoint().as_str(),
            "https://peer.example:8443/v1/configuration"
        );
        assert_eq!(
            url.peers_endpoint().as_str(),
            "https://peer.example:8443/v1/peers"
        );
        assert_eq!(
            url.status_endpoint().as_str(),
            "https://peer.example:8443/status"
        );
    }
    #[test]
    fn torii_url_rejects_non_http_and_non_base_urls() {
        for candidate in [
            "mailto:operator@example.com",
            "data:text/plain,peer",
            "file:///tmp/torii.sock",
            "ftp://peer.example/",
        ] {
            let error = candidate
                .parse::<ToriiUrl>()
                .expect_err("non-HTTP Torii URL must be rejected");
            assert!(
                error.to_string().contains("is not HTTP or HTTPS"),
                "unexpected error for {candidate}: {error}"
            );
        }
    }
    #[test]
    fn torii_url_rejects_invalid_or_hostless_http_urls() {
        for candidate in ["http://", "https://?query=only", "http://#fragment"] {
            assert!(
                candidate.parse::<ToriiUrl>().is_err(),
                "hostless Torii URL must be rejected: {candidate}"
            );
        }
    }
    #[test]
    fn torii_url_rejects_non_origin_http_urls() {
        for candidate in [
            "https://peer.example/base",
            "https://peer.example/?source=config",
            "https://peer.example/#fragment",
            "https://operator:secret@peer.example/",
            "https://@peer.example/",
            "https://@peer.example",
            "https://:@peer.example/",
            "https://\t@peer.example/",
            "https://@\npeer.example/",
        ] {
            assert!(
                candidate.parse::<ToriiUrl>().is_err(),
                "non-origin Torii URL must be rejected: {candidate}"
            );
        }
    }
    #[test]
    fn construction_is_inert() {
        let peer_url = "http://127.0.0.1:9".parse().expect("torii url");
        let service = PeerTelemetryService::new(
            vec![peer_url],
            GeoLookupConfig::disabled(),
            crate::signed_query_test_network_id(),
            None,
        );

        assert_eq!(Arc::strong_count(&service), 1);
    }
    #[tokio::test]
    async fn started_worker_stops_and_releases_service_on_shutdown() {
        let peer_url = "http://127.0.0.1:9".parse().expect("torii url");
        let service = PeerTelemetryService::new(
            vec![peer_url],
            GeoLookupConfig::disabled(),
            crate::signed_query_test_network_id(),
            None,
        );
        let shutdown = ShutdownSignal::new();
        let worker = service
            .start(shutdown.clone())
            .expect("configured peer starts a worker");

        shutdown.send();
        let exit = tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("peer telemetry worker observes shutdown")
            .expect("peer telemetry worker stops cleanly");
        assert_eq!(exit, crate::ToriiCriticalWorkerExit::StoppedByShutdown);
        assert_eq!(Arc::strong_count(&service), 1);
    }
    #[tokio::test]
    async fn service_supervisor_preserves_panicked_worker_failure_after_shutdown() {
        let shutdown = ShutdownSignal::new();
        let worker_shutdown = shutdown.clone();
        let mut workers: JoinSet<crate::ToriiCriticalWorkerExit> = JoinSet::new();
        workers.spawn(async move {
            worker_shutdown.send();
            assert!(!iroha_panic_hook::is_suppressed());
            panic!("injected peer telemetry worker panic");
        });

        assert_eq!(
            supervise_peer_monitor_workers(&shutdown, workers).await,
            crate::ToriiCriticalWorkerExit::UnexpectedExit
        );
    }
    #[tokio::test]
    async fn service_supervisor_preserves_typed_failure_after_shutdown() {
        let shutdown = ShutdownSignal::new();
        let worker_shutdown = shutdown.clone();
        let mut workers = JoinSet::new();
        workers.spawn(async move {
            worker_shutdown.send();
            crate::ToriiCriticalWorkerExit::UnexpectedExit
        });

        assert_eq!(
            supervise_peer_monitor_workers(&shutdown, workers).await,
            crate::ToriiCriticalWorkerExit::UnexpectedExit
        );
    }
    #[tokio::test]
    async fn peers_status_reflects_metrics_updates() {
        let service = PeerTelemetryService::new(
            Vec::new(),
            GeoLookupConfig::disabled(),
            crate::signed_query_test_network_id(),
            None,
        );
        let url: ToriiUrl = "http://peer.example:8080".parse().expect("torii url");
        service
            .apply_update(
                url.clone(),
                Update::Metrics(monitor::Metrics {
                    block: 42,
                    block_commit_time: Duration::from_millis(850),
                    avg_commit_time: Duration::from_millis(700),
                    queue_size: 3,
                    uptime: Duration::from_secs(3600),
                    status_rtt: Some(Duration::from_millis(18)),
                    status_rtt_avg: Some(Duration::from_millis(21)),
                    status_rtt_p95: Some(Duration::from_millis(34)),
                    observed_at_ms: Some(100),
                }),
            )
            .await;
        let statuses = service.peers_status().await;
        assert_eq!(statuses.len(), 1);
        let status = &statuses[0];
        assert_eq!(status.url, url.as_str());
        assert_eq!(status.block, 42);
        assert_eq!(status.commit_time.ms, 850);
        assert_eq!(status.avg_commit_time.ms, 700);
        assert_eq!(
            status.status_rtt.as_ref().map(|duration| duration.ms),
            Some(18)
        );
        assert_eq!(
            status.status_rtt_avg.as_ref().map(|duration| duration.ms),
            Some(21)
        );
        assert_eq!(
            status.status_rtt_p95.as_ref().map(|duration| duration.ms),
            Some(34)
        );
        assert_eq!(status.queue_size, 3);
        assert_eq!(status.uptime.ms, 3_600_000);
        assert_eq!(
            status.propagation_time.as_ref().map(|duration| duration.ms),
            Some(0)
        );
        assert_eq!(status.observed_at_ms, Some(100));
    }
    #[tokio::test]
    async fn snapshot_returns_info_and_status_views() {
        let service = PeerTelemetryService::new(
            Vec::new(),
            GeoLookupConfig::disabled(),
            crate::signed_query_test_network_id(),
            None,
        );
        let url: ToriiUrl = "http://peer.example:8080".parse().expect("torii url");
        service
            .apply_update(
                url.clone(),
                Update::Connected(Box::new(PeerConfigSnapshot {
                    public_key: None,
                    queue_capacity: Some(256),
                    network_block_gossip_size: Some(64),
                    network_block_gossip_period_ms: Some(1_500),
                    network_tx_gossip_size: Some(32),
                    network_tx_gossip_period_ms: Some(2_500),
                })),
            )
            .await;
        service
            .apply_update(
                url.clone(),
                Update::Metrics(monitor::Metrics {
                    block: 9,
                    block_commit_time: Duration::from_millis(1200),
                    avg_commit_time: Duration::from_millis(1100),
                    queue_size: 1,
                    uptime: Duration::from_secs(120),
                    status_rtt: None,
                    status_rtt_avg: None,
                    status_rtt_p95: None,
                    observed_at_ms: Some(200),
                }),
            )
            .await;
        let snapshot = service.snapshot().await;
        assert_eq!(snapshot.peers_info.len(), 1);
        assert_eq!(snapshot.peers_status.len(), 1);
        assert_eq!(snapshot.propagation.len(), 1);
        assert_eq!(snapshot.peers_info[0].url, url.as_str());
        assert_eq!(snapshot.peers_status[0].url, url.as_str());
        assert_eq!(snapshot.propagation[0].block, 9);
        assert_eq!(snapshot.propagation[0].spread_ms, 0);
        assert_eq!(snapshot.propagation[0].peers_reported, 1);
    }
    #[tokio::test]
    async fn peers_status_computes_propagation_from_first_seen_timestamp() {
        let service = PeerTelemetryService::new(
            Vec::new(),
            GeoLookupConfig::disabled(),
            crate::signed_query_test_network_id(),
            None,
        );
        let url_a: ToriiUrl = "http://peer-a.example:8080".parse().expect("torii url");
        let url_b: ToriiUrl = "http://peer-b.example:8080".parse().expect("torii url");
        service
            .apply_update(
                url_a.clone(),
                Update::Metrics(monitor::Metrics {
                    block: 20,
                    block_commit_time: Duration::from_millis(400),
                    avg_commit_time: Duration::from_millis(390),
                    queue_size: 1,
                    uptime: Duration::from_secs(10),
                    status_rtt: Some(Duration::from_millis(14)),
                    status_rtt_avg: Some(Duration::from_millis(16)),
                    status_rtt_p95: Some(Duration::from_millis(20)),
                    observed_at_ms: Some(1_000),
                }),
            )
            .await;
        service
            .apply_update(
                url_b.clone(),
                Update::Metrics(monitor::Metrics {
                    block: 20,
                    block_commit_time: Duration::from_millis(410),
                    avg_commit_time: Duration::from_millis(395),
                    queue_size: 2,
                    uptime: Duration::from_secs(11),
                    status_rtt: Some(Duration::from_millis(18)),
                    status_rtt_avg: Some(Duration::from_millis(19)),
                    status_rtt_p95: Some(Duration::from_millis(27)),
                    observed_at_ms: Some(1_045),
                }),
            )
            .await;
        let statuses = service.peers_status().await;
        let status_a = statuses
            .iter()
            .find(|status| status.url == url_a.as_str())
            .expect("status for peer a");
        let status_b = statuses
            .iter()
            .find(|status| status.url == url_b.as_str())
            .expect("status for peer b");
        assert_eq!(
            status_a
                .propagation_time
                .as_ref()
                .map(|duration| duration.ms),
            Some(0)
        );
        assert_eq!(
            status_b
                .propagation_time
                .as_ref()
                .map(|duration| duration.ms),
            Some(45)
        );
        let propagation = service.propagation(10).await;
        assert_eq!(propagation.len(), 1);
        assert_eq!(propagation[0].block, 20);
        assert_eq!(propagation[0].spread_ms, 45);
        assert_eq!(propagation[0].peers_reported, 2);
    }
}
