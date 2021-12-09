//! [`Metrics`] and [`Status`]-related logic and functions.
use std::{sync::Arc, time::Duration};

use prometheus::{
    core::{AtomicU64, GenericGauge},
    Encoder, IntCounter, IntCounterVec, Opts, Registry,
};
use serde::{Deserialize, Serialize};

/// Thin wrapper around duration that `impl`s [`Default`]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Uptime(Duration);

impl Default for Uptime {
    fn default() -> Self {
        Self(Duration::from_millis(0))
    }
}

/// Response body for GET status request
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct Status {
    /// Number of connected peers, except for the reporting peer itself
    pub peers: u64,
    /// Number of committed blocks
    pub blocks: u64,
    /// Number of transactions committed in the last block
    pub txs: u64,
    /// Uptime since genesis block creation
    pub uptime: Uptime,
}

impl From<&Arc<Metrics>> for Status {
    fn from(val: &Arc<Metrics>) -> Self {
        Self {
            peers: val.connected_peers.get(),
            blocks: val.block_height.get(),
            txs: val.txs.with_label_values(&["total"]).get(),
            uptime: Uptime(Duration::from_millis(val.uptime_since_genesis_ms.get())),
        }
    }
}

/// A strict superset of [`Status`].
#[derive(Debug)]
pub struct Metrics {
    /// Transactions in the last committed block
    pub txs: IntCounterVec,
    /// Current block height
    pub block_height: IntCounter,
    /// Total number of currently connected peers
    pub connected_peers: GenericGauge<AtomicU64>,
    /// Uptime of the network, starting from commit of the genesis block
    pub uptime_since_genesis_ms: GenericGauge<AtomicU64>,
    /// Number of domains.
    pub domains: GenericGauge<AtomicU64>,
    /// Number of users with non-zero assets.
    pub users: GenericGauge<AtomicU64>,
    /// Queries handled by this peer
    pub queries: IntCounterVec,
    // Internal use only.
    registry: Registry,
}

impl Default for Metrics {
    // The constructors either always fail, or never.
    #[allow(clippy::expect_used)]
    fn default() -> Self {
        let txs = IntCounterVec::new(Opts::new("txs", "Transactions committed"), &["type"])
            .expect("Infallible");
        let queries = IntCounterVec::new(
            Opts::new("queries", "Queries handled by this peer"),
            &["type", "success_status"],
        )
        .expect("Infallible");
        let block_height =
            IntCounter::new("block_height", "Current block height").expect("Infallible");
        let connected_peers = GenericGauge::new(
            "connected_peers",
            "Total number of currently connected peers",
        )
        .expect("Infallible");
        let uptime_since_genesis_ms = GenericGauge::new(
            "uptime_since_genesis_ms",
            "Network uptime, from creation of the genesis block",
        )
        .expect("Infallible");
        let domains = GenericGauge::new("domains", "Total number of domains").expect("Infallible");
        let users = GenericGauge::new("users", "Total number of users").expect("Infallible");

        let registry = Registry::new();

        macro_rules! register {
			($metric:expr)=> {
				registry.register(Box::new($metric.clone())).expect("Infallible");
			};
			($metric:expr,$($metrics:expr),+)=>{
				register!($metric);
				register!($($metrics),+);
			}
		}

        register!(
            txs,
            block_height,
            connected_peers,
            uptime_since_genesis_ms,
            domains,
            users,
            queries
        );

        Self {
            txs,
            block_height,
            connected_peers,
            uptime_since_genesis_ms,
            registry,
            domains,
            users,
            queries,
        }
    }
}

impl Metrics {
    /// Convert the current [`Metrics`] into a Prometheus-readable format.
    ///
    /// # Errors
    /// - If [`Encoder`] fails to encode the data
    /// - If the buffer produced by [`Encoder`] causes [`String::from_utf8`] to fail.
    pub fn try_to_string(&self) -> eyre::Result<String> {
        let mut buffer = vec![];
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        Encoder::encode(&encoder, &metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}
