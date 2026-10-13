//! Bounded configured TON observations and linked account certificate discovery.

use super::*;
use crate::sccp::monitor::{Discovery, Observation as MonitorObservation, TonCursor};
use iroha::data_model::isi::sccp::SubmitSccpForgeryEvidenceV1;

impl TonDestination {
    pub(crate) fn monitor_connect(
        config: &iroha_sccp_wallet::config::SccpClientConfig,
        minter: TonAccountV1,
        destination: DestinationV1,
    ) -> Result<Self> {
        Self::connect(config, "", minter, destination)
    }

    pub(crate) fn monitor_observe(&self) -> Result<MonitorObservation> {
        let observed = self.observe()?;
        Ok(MonitorObservation {
            network: observed.network,
            instance: observed.instance,
            committee: observed.committee,
            checkpoints: observed.checkpoints,
            now_ms: observed.now_ms,
            pause: iroha_sccp::v1::evm_abi::PauseViewV1 {
                parliament_paused: observed.control.parliament_paused,
                fast_pause_until_ms: observed.control.fast_pause_until_ms,
                control_nonce: observed.control.control_nonce,
                effective: observed.paused,
            },
        })
    }

    pub(crate) fn monitor_certificates(&self, after: Option<TonCursor>) -> Result<Discovery> {
        use iroha_sccp::ton_watch;
        let account = AccountId {
            workchain: 0,
            address: self.minter,
        };
        let cursor = if let Some(cursor) = after {
            ton_watch::Cursor {
                lt: cursor.lt,
                hash: cursor.hash,
            }
        } else {
            let state = self
                .lite
                .get_account_state(last_block(&self.lite)?, account)?;
            ton_watch::account_cursor(&state.proof, &self.minter)
                .ok_or_else(|| eyre!("original minter account history cursor unavailable"))?
        };
        let page = self
            .lite
            .get_transactions(16, account, cursor.lt, cursor.hash)?;
        let mut result = Discovery::default();
        let next = ton_watch::certificates(
            &page.transactions,
            &self.minter,
            cursor,
            |cert| {
                if result.certificates.len() == 16 {
                    return false;
                }
                result.certificates.push(SubmitSccpForgeryEvidenceV1 {
                    qc: cert.qc,
                    header: cert.header,
                    aggregate_signature: cert.aggregate_signature,
                    anchor: None,
                });
                true
            },
            |_| {},
        )?;
        result.next_ton = next.map(|cursor| TonCursor {
            lt: cursor.lt,
            hash: cursor.hash,
        });
        result.ton_history_complete = next.is_none();
        Ok(result)
    }
}
