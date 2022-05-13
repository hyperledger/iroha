//! [`Metrics`] and [`Status`]-related logic and functions.
use std::{
    ops::Deref,
    time::{Duration, SystemTime},
};

use prometheus::{
    core::{AtomicU64, GenericGauge, GenericGaugeVec},
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry,
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
    /// Number of accepted transactions
    pub txs_accepted: u64,
    /// Number of rejected transactions
    pub txs_rejected: u64,
    /// Uptime since genesis block creation
    pub uptime: Uptime,
    /// Number of view changes in the current round
    pub view_changes: u64,
}

impl<T: Deref<Target = Metrics>> From<&T> for Status {
    fn from(value: &T) -> Self {
        let val: &Metrics = &*value;
        Self {
            peers: val.connected_peers.get(),
            blocks: val.block_height.get(),
            txs_accepted: val.txs.with_label_values(&["accepted"]).get(),
            txs_rejected: val.txs.with_label_values(&["rejected"]).get(),
            uptime: Uptime(Duration::from_millis(val.uptime_since_genesis_ms.get())),
            view_changes: val.view_changes.get(),
        }
    }
}

/// A strict superset of [`Status`].
#[derive(Debug)]
pub struct Metrics {
    /// Total number of transactions
    pub txs: IntCounterVec,
    /// Current block height
    pub block_height: IntCounter,
    /// Total number of currently connected peers
    pub connected_peers: GenericGauge<AtomicU64>,
    /// Uptime of the network, starting from commit of the genesis block
    pub uptime_since_genesis_ms: GenericGauge<AtomicU64>,
    /// Number of domains.
    pub domains: GenericGauge<AtomicU64>,
    /// Total number of users per domain
    pub accounts: GenericGaugeVec<AtomicU64>,
    /// Transaction amounts.
    pub tx_amounts: Histogram,
    /// Queries handled by this peer
    pub isi: IntCounterVec,
    /// Query handle time Histogram
    pub isi_times: HistogramVec,
    /// Number of view changes in the current round
    pub view_changes: GenericGauge<AtomicU64>,
    // Internal use only.
    registry: Registry,
}

impl Default for Metrics {
    // The constructors either always fail, or never.
    #[allow(clippy::expect_used)]
    fn default() -> Self {
        let txs = IntCounterVec::new(Opts::new("txs", "Transactions committed"), &["type"])
            .expect("Infallible");
        let isi = IntCounterVec::new(
            Opts::new("isi", "Iroha special instructions handled by this peer"),
            &["type", "success_status"],
        )
        .expect("Infallible");
        let isi_times = HistogramVec::new(
            HistogramOpts::new("isi_times", "Time to handle isi in this peer"),
            &["type"],
        )
        .expect("Infallible");
        let tx_amounts = Histogram::with_opts(HistogramOpts::new(
            "tx_amount",
            "average amount involved in a transaction on this peer",
        ))
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
            "Network up-time, from creation of the genesis block",
        )
        .expect("Infallible");
        let domains = GenericGauge::new("domains", "Total number of domains").expect("Infallible");
        let accounts = GenericGaugeVec::new(
            Opts::new("accounts", "User accounts registered at this time"),
            &["domain"],
        )
        .expect("Infallible");
        let view_changes = GenericGauge::new(
            "view_changes",
            "Number of view changes in the current round",
        )
        .expect("Infallible");
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
            tx_amounts,
            block_height,
            connected_peers,
            uptime_since_genesis_ms,
            domains,
            accounts,
            isi,
            isi_times,
            view_changes
        );

        Self {
            txs,
            block_height,
            connected_peers,
            uptime_since_genesis_ms,
            registry,
            domains,
            accounts,
            tx_amounts,
            isi,
            isi_times,
            view_changes,
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

    /// Get time elapsed since Unix epoch.
    ///
    /// # Panics
    /// Never
    #[allow(clippy::unused_self, clippy::expect_used)]
    pub fn current_time(&self) -> Duration {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get the current system time")
    }
}
