//! Metrics and status reporting

use std::{num::NonZeroUsize, sync::Arc, time::SystemTime};

use eyre::{Result, WrapErr as _};
use iroha_data_model::peer::Peer;
use iroha_telemetry::metrics::Metrics;
use mv::storage::StorageReadOnly;
use parking_lot::Mutex;

use crate::{
    kura::Kura,
    queue::Queue,
    state::{State, StateReadOnly, WorldReadOnly},
    IrohaNetwork,
};

/// Responsible for collecting and updating metrics
#[derive(Clone)]
pub struct MetricsReporter {
    state: Arc<State>,
    network: IrohaNetwork,
    kura: Arc<Kura>,
    queue: Arc<Queue>,
    metrics: Metrics,
    /// Latest observed and processed height by metrics reporter
    latest_block_height: Arc<Mutex<usize>>,
}

impl MetricsReporter {
    /// Construct [`Self`]
    pub fn new(
        state: Arc<State>,
        network: IrohaNetwork,
        kura: Arc<Kura>,
        queue: Arc<Queue>,
    ) -> Self {
        Self {
            state,
            network,
            queue,
            kura,
            metrics: Metrics::default(),
            latest_block_height: Arc::new(Mutex::new(0)),
        }
    }

    /// Update the metrics on the state.
    ///
    /// # Errors
    /// - Domains fail to compose
    ///
    /// # Panics
    /// - If either mutex is poisoned
    #[allow(clippy::cast_precision_loss)]
    pub fn update_metrics(&self) -> Result<()> {
        let online_peers_count: usize = self.network.online_peers(
            #[allow(clippy::disallowed_types)]
            std::collections::HashSet::len,
        );

        let state_view = self.state.view();

        let mut lastest_block_height = self.latest_block_height.lock();

        let start_index = *lastest_block_height;
        {
            let mut block_index = start_index;
            while block_index < state_view.height() {
                let Some(block) = NonZeroUsize::new(
                    block_index
                        .checked_add(1)
                        .expect("INTERNAL BUG: Blockchain height exceeds usize::MAX"),
                )
                .and_then(|index| self.kura.get_block(index)) else {
                    break;
                };
                block_index += 1;
                let block_txs_rejected = block.errors().count() as u64;
                let block_txs_approved = block.transactions().count() as u64 - block_txs_rejected;

                self.metrics
                    .txs
                    .with_label_values(&["accepted"])
                    .inc_by(block_txs_approved);
                self.metrics
                    .txs
                    .with_label_values(&["rejected"])
                    .inc_by(block_txs_rejected);
                self.metrics
                    .txs
                    .with_label_values(&["total"])
                    .inc_by(block_txs_approved + block_txs_rejected);
                self.metrics.block_height.inc();
            }
            *lastest_block_height = block_index;
        }

        let new_tx_amounts = {
            let mut new_buf = Vec::new();
            core::mem::swap(&mut new_buf, &mut state_view.new_tx_amounts.lock());
            new_buf
        };

        for amount in &new_tx_amounts {
            self.metrics.tx_amounts.observe(*amount);
        }

        #[allow(clippy::cast_possible_truncation)]
        if let Some(timestamp) = state_view.genesis_timestamp() {
            let curr_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();

            // this will overflow in 584942417years.
            self.metrics.uptime_since_genesis_ms.set(
                (curr_time - timestamp)
                    .as_millis()
                    .try_into()
                    .expect("Timestamp should fit into u64"),
            )
        };

        self.metrics.connected_peers.set(online_peers_count as u64);

        self.metrics
            .domains
            .set(state_view.world().domains().len() as u64);
        for domain in state_view.world().domains_iter() {
            self.metrics
                .accounts
                .get_metric_with_label_values(&[domain.id.name.as_ref()])
                .wrap_err("Failed to compose domains")?
                .set(
                    state_view
                        .world()
                        .accounts_in_domain_iter(&domain.id)
                        .count() as u64,
                );
        }

        self.metrics.queue_size.set(self.queue.tx_len() as u64);

        Ok(())
    }

    /// Access node metrics.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Last known online peers
    pub fn online_peers(&self) -> Vec<Peer> {
        self.network.online_peers(|x| x.iter().cloned().collect())
    }
}
