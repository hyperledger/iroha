//! [`Metrics`] and [`Status`]-related logic and functions.

use std::{ops::Deref, time::Duration};

use parity_scale_codec::{Compact, Decode, Encode};
use prometheus::{
    core::{AtomicU64, GenericGauge, GenericGaugeVec},
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry,
};
use serde::{Deserialize, Serialize};

/// Type for reporting amount of dropped messages for sumeragi
pub type DroppedMessagesCounter = IntCounter;
/// Type for reporting view change index of current round
pub type ViewChangesGauge = GenericGauge<AtomicU64>;

/// Thin wrapper around duration that `impl`s [`Default`]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Uptime(pub Duration);

impl Default for Uptime {
    fn default() -> Self {
        Self(Duration::from_millis(0))
    }
}

impl Encode for Uptime {
    fn encode(&self) -> Vec<u8> {
        let secs = self.0.as_secs();
        let nanos = self.0.subsec_nanos();
        // While seconds are rarely very large, nanos could be anywhere between zero and one billion,
        // eliminating the profit of Compact
        (Compact(secs), nanos).encode()
    }
}

impl Decode for Uptime {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let (secs, nanos) = <(Compact<u64>, u32)>::decode(input)?;
        Ok(Self(
            Duration::from_secs(secs.0) + Duration::from_nanos(nanos.into()),
        ))
    }
}

/// Response body for GET status request
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Encode, Decode)]
pub struct Status {
    /// Number of currently connected peers excluding the reporting peer
    #[codec(compact)]
    pub peers: u64,
    /// Number of committed blocks (blockchain height)
    #[codec(compact)]
    pub blocks: u64,
    /// Number of approved transactions
    #[codec(compact)]
    pub txs_approved: u64,
    /// Number of rejected transactions
    #[codec(compact)]
    pub txs_rejected: u64,
    /// Uptime since genesis block creation
    pub uptime: Uptime,
    /// Number of view changes in the current round
    #[codec(compact)]
    pub view_changes: u32,
    /// Number of the transactions in the queue
    #[codec(compact)]
    pub queue_size: u64,
}

impl<T: Deref<Target = Metrics>> From<&T> for Status {
    fn from(value: &T) -> Self {
        let val: &Metrics = value;
        Self {
            peers: val.connected_peers.get(),
            blocks: val.block_height.get(),
            txs_approved: val.txs.with_label_values(&["accepted"]).get(),
            txs_rejected: val.txs.with_label_values(&["rejected"]).get(),
            uptime: Uptime(Duration::from_millis(val.uptime_since_genesis_ms.get())),
            view_changes: val
                .view_changes
                .get()
                .try_into()
                .expect("INTERNAL BUG: Number of view changes exceeds u32::MAX"),
            queue_size: val.queue_size.get(),
        }
    }
}

/// A strict superset of [`Status`].
#[derive(Debug, Clone)]
pub struct Metrics {
    /// Total number of transactions
    pub txs: IntCounterVec,
    /// Number of committed blocks (blockchain height)
    pub block_height: IntCounter,
    /// Number of currently connected peers excluding the reporting peer
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
    pub view_changes: ViewChangesGauge,
    /// Number of transactions in the queue
    pub queue_size: GenericGauge<AtomicU64>,
    /// Number of sumeragi dropped messages
    pub dropped_messages: DroppedMessagesCounter,
    /// Internal use only. Needed for generating the response.
    registry: Registry,
}

impl Default for Metrics {
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
        let queue_size = GenericGauge::new("queue_size", "Number of the transactions in the queue")
            .expect("Infallible");
        let dropped_messages =
            IntCounter::new("dropped_messages", "Sumeragi dropped messages").expect("Infallible");
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
            view_changes,
            queue_size,
            dropped_messages
        );

        Self {
            txs,
            block_height,
            connected_peers,
            uptime_since_genesis_ms,
            domains,
            accounts,
            tx_amounts,
            isi,
            isi_times,
            view_changes,
            queue_size,
            dropped_messages,
            registry,
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
        let mut buffer = Vec::new();
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        Encoder::encode(&encoder, &metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::restriction)]

    use super::*;

    #[test]
    fn metrics_lifecycle() {
        let metrics = Metrics::default();
        println!(
            "{:?}",
            metrics
                .try_to_string()
                .expect("Should not fail for default")
        );
        println!("{:?}", Status::from(&Box::new(metrics)));
        println!("{:?}", Status::default());
    }

    fn sample_status() -> Status {
        Status {
            peers: 4,
            blocks: 5,
            txs_approved: 31,
            txs_rejected: 3,
            uptime: Uptime(Duration::new(5, 937_000_000)),
            view_changes: 2,
            queue_size: 18,
        }
    }

    #[test]
    fn serialize_status_json() {
        let value = sample_status();

        let actual = serde_json::to_string_pretty(&value).expect("Sample is valid");
        // CAUTION: if this is outdated, make sure to update the documentation:
        // https://docs.iroha.tech/reference/torii-endpoints.html#status
        let expected = expect_test::expect![[r#"
            {
              "peers": 4,
              "blocks": 5,
              "txs_approved": 31,
              "txs_rejected": 3,
              "uptime": {
                "secs": 5,
                "nanos": 937000000
              },
              "view_changes": 2,
              "queue_size": 18
            }"#]];
        expected.assert_eq(&actual);
    }

    #[test]
    fn serialize_status_scale() {
        let value = sample_status();
        let bytes = value.encode();

        let actual = hex::encode_upper(bytes);
        // CAUTION: if this is outdated, make sure to update the documentation:
        // https://docs.iroha.tech/reference/torii-endpoints.html#status
        let expected = expect_test::expect!["10147C0C14407CD9370848"];
        expected.assert_eq(&actual);
    }
}
