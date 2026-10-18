//! Bounded destination observations and certificate discovery from configured EVM transports.

use super::*;
use crate::sccp::monitor::{Discovery, EvmCursor, Observation as MonitorObservation};
use iroha::data_model::isi::sccp::SubmitSccpForgeryEvidenceV1;
use iroha_sccp::v1::{
    committee::signature_from_evm192, destination_abi::TOPIC_CERTIFICATE, evm_abi::CertificateLogV1,
};

impl EvmDestination {
    pub(crate) fn monitor_connect(
        config: &iroha_sccp_wallet::config::SccpClientConfig,
        network: SccpNetworkV1,
        contract: [u8; 20],
        destination: DestinationV1,
        code_hash: [u8; 32],
    ) -> Result<Self> {
        Self::connect(config, "", network, contract, destination, code_hash)
    }

    pub(crate) fn monitor_observe(&self) -> Result<MonitorObservation> {
        // Re-observe the selected high checkpoint and all scalars at the same block.
        let first = self.observe([])?;
        let heights =
            (first.committee.high >= first.committee.start).then_some(first.committee.high);
        let observed = self.observe(heights)?;
        ensure!(
            observed.committee == first.committee,
            "destination committee changed during checkpoint selection; retry observation"
        );
        Ok(MonitorObservation {
            network: observed.network,
            instance: observed.instance,
            committee: observed.committee,
            checkpoints: observed.checkpoints,
            now_ms: observed.now_ms,
            pause: observed.pause,
        })
    }

    pub(crate) fn monitor_certificates(&self, after: Option<EvmCursor>) -> Result<Discovery> {
        let latest = self
            .client
            .block_by_number(BlockTag::Latest)?
            .ok_or_else(|| eyre!("no latest destination block"))?
            .header
            .number;
        let from = after.map_or_else(|| latest.saturating_sub(2047), |cursor| cursor.block);
        ensure!(from <= latest, "certificate cursor is ahead of destination");
        let through = from.saturating_add(2047).min(latest);
        let mut logs =
            self.client
                .destination_logs(self.contract, from, through, &[TOPIC_CERTIFICATE])?;
        logs.sort_by_key(|log| (log.block_number, log.log_index));
        ensure!(
            logs.windows(2)
                .all(|pair| (pair[0].block_number, pair[0].log_index)
                    != (pair[1].block_number, pair[1].log_index)),
            "duplicate destination log positions"
        );
        let mut result = Discovery::default();
        for log in logs {
            let cursor = EvmCursor {
                block: log.block_number.ok_or_else(|| eyre!("missing log block"))?,
                log_index: log.log_index.ok_or_else(|| eyre!("missing log index"))?,
            };
            if log.removed || after.is_some_and(|after| cursor <= after) {
                continue;
            }
            if result.certificates.len() == 16 {
                return Ok(result);
            }
            let cert = CertificateLogV1::decode(&log.topics, &log.data)?;
            result.certificates.push(SubmitSccpForgeryEvidenceV1 {
                qc: cert.qc,
                header: cert.header,
                aggregate_signature: signature_from_evm192(&cert.signature)?,
                anchor: None,
            });
            result.next_evm = Some(cursor);
        }
        // The exclusive cursor covers the complete queried range, even an empty range.
        result.next_evm = Some(EvmCursor {
            block: through,
            log_index: u64::MAX,
        });
        Ok(result)
    }
}
