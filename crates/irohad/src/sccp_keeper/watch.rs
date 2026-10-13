//! Independent bounded destination discovery and original-state forgery submission.

use std::{
    ops::Bound::{Excluded, Unbounded},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_core::smartcontracts::isi::sccp::{forgery, read::native::SccpNativeReadControl};
use iroha_data_model::{
    isi::sccp::SubmitSccpForgeryEvidenceV1, sccp::deployment::SccpDeploymentV1,
};
use iroha_sccp::{
    ton_watch,
    v1::{
        committee::signature_from_evm192,
        destination_abi::*,
        evm_abi::{CertificateLogV1, decode_committee_state_return},
    },
};
use iroha_sccp_rpc::{
    evm::{BlockId, BlockTag, EvmCallRequest},
    ton::AccountId as TonAccount,
};
use mv::storage::StorageReadOnly as _;

use super::*;

const SCAN_PAGE: usize = 64;
const CURSOR_POOL_BYTES: usize = 8 << 20;
const SOURCE_POOL_BYTES: usize = 128 << 20;
const ALERT_LEAD_MS: u64 = 3 * 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, Default)]
struct EvmCursor {
    next: Option<u64>,
    older: Option<u64>,
}

impl EvmCursor {
    fn ranges(&mut self, head: u64) -> [Option<(u64, u64)>; 2] {
        if self.next.is_none() {
            let first = head.saturating_sub(2047);
            self.next = Some(first);
            self.older = first.checked_sub(1);
        }
        let first = self.next.expect("initialized");
        let recent = (first <= head).then_some((first, first.saturating_add(2047).min(head)));
        let older = self.older.map(|end| (end.saturating_sub(2047), end));
        [recent, older]
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TonCursor {
    newest: Option<ton_watch::Cursor>,
    catchup: Option<ton_watch::Cursor>,
    tip: Option<ton_watch::Cursor>,
    older: Option<ton_watch::Cursor>,
}

#[derive(Clone, Copy)]
struct Row {
    revision: u32,
    deployment: SccpDeploymentV1,
    generation: u64,
    until_ms: u64,
    evm: EvmCursor,
    ton: TonCursor,
}

/// Actual vector backing is reserved before it exists and retired before its allowance.
#[derive(Default)]
struct Rows {
    rows: Vec<Row>,
    charge: Option<AllocationReservation>,
}

impl Rows {
    fn insert(&mut self, row: &Row, budget: &AllocationBudget) -> eyre::Result<()> {
        match self
            .rows
            .binary_search_by_key(&row.revision, |r| r.revision)
        {
            Ok(index) => {
                if self.rows[index].deployment != row.deployment {
                    self.rows[index] = *row;
                }
            }
            Err(index) => {
                if self.rows.len() == self.rows.capacity() {
                    let capacity = self
                        .rows
                        .len()
                        .checked_add(SCAN_PAGE)
                        .ok_or_else(|| eyre::eyre!("watch cursor extent overflow"))?;
                    let charge = budget.try_reserve_bytes(
                        capacity
                            .checked_mul(size_of::<Row>())
                            .ok_or_else(|| eyre::eyre!("watch cursor extent overflow"))?,
                    )?;
                    let mut replacement = Vec::new();
                    replacement.try_reserve_exact(capacity)?;
                    replacement.append(&mut self.rows);
                    self.rows = replacement;
                    self.charge = Some(charge);
                }
                self.rows.insert(index, *row);
            }
        }
        Ok(())
    }
}

enum Source {
    Evm(EvmClient),
    Ton(Box<LiteClient>),
}
impl Source {
    fn rotate_after_refusal(&self) {
        match self {
            Self::Evm(client) => client.transport().rotate_preferred(),
            Self::Ton(client) => client.rotate_preferred(),
        }
    }
}

struct Lane {
    network: SccpNetworkV1,
    source: Source,
    budget: PollBudget,
    cursors: AllocationBudget,
    work: AllocationBudget,
    rows: Rows,
    revision_after: u32,
    selected: usize,
}

/// Watch all three networks independently; one slow endpoint never delays another duty.
pub(super) async fn run(
    host: Arc<NodeHost>,
    config: SccpLightClientKeeper,
    seed: u64,
    shutdown: ShutdownSignal,
) {
    let mut tasks = JoinSet::new();
    for network in NETWORKS {
        let host = Arc::clone(&host);
        let config = config.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move { run_lane(host, config, seed, network, shutdown).await });
    }
    shutdown.receive().await;
    tasks.shutdown().await;
}

async fn run_lane(
    host: Arc<NodeHost>,
    config: SccpLightClientKeeper,
    seed: u64,
    network: SccpNetworkV1,
    shutdown: ShutdownSignal,
) {
    let builder = config.clone();
    let lane = join_recoverable(spawn_blocking_recoverable(move || {
        Lane::new(&builder, seed, network)
    }))
    .await;
    let mut lane = if let Ok(Ok(lane)) = lane {
        lane
    } else {
        health::Health::Poll(network, health::Duty::Watch, false).report();
        iroha_logger::warn!(
            network = network.profile_key(),
            "SCCP watch endpoints unavailable"
        );
        shutdown.receive().await;
        return;
    };
    let stop = Arc::new(AtomicBool::new(false));
    let mut cadence = Cadence::new(config.poll_interval, lane_seed(seed, network));
    let mut wait = cadence.first();
    loop {
        tokio::select! { () = tokio::time::sleep(wait) => {}, () = shutdown.receive() => return }
        let host = Arc::clone(&host);
        let poll_stop = Arc::clone(&stop);
        let duration = config.poll_budget;
        let poll = spawn_blocking_recoverable(move || {
            let _poll = lane.budget.start(duration);
            let control = SccpNativeReadControl {
                deadline: Instant::now() + duration,
                stop: &poll_stop,
            };
            let result = lane.poll(&host, control);
            (lane, result)
        });
        let finished = tokio::select! {
            result = join_recoverable(poll) => result,
            () = shutdown.receive() => { stop.store(true, Ordering::Release); return; }
        };
        let Ok((returned, result)) = finished else {
            health::Health::Poll(network, health::Duty::Watch, false).report();
            shutdown.receive().await;
            return;
        };
        lane = returned;
        health::Health::Poll(network, health::Duty::Watch, result.is_ok()).report();
        wait = match result {
            Ok(()) => cadence.after_success(),
            Err(error) => {
                iroha_logger::warn!(%error, network = network.profile_key(), "SCCP watch poll unavailable");
                lane.source.rotate_after_refusal();
                cadence.after_failure()
            }
        };
    }
}

impl Lane {
    fn new(
        config: &SccpLightClientKeeper,
        seed: u64,
        network: SccpNetworkV1,
    ) -> eyre::Result<Self> {
        let budget = PollBudget::new();
        let source = match network {
            SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet => {
                let kind = if network == SccpNetworkV1::EthereumMainnet {
                    HttpEndpointKind::EthereumExecution
                } else {
                    HttpEndpointKind::Bsc
                };
                Source::Evm(EvmClient::new(
                    HttpTransport::from_keeper_config(config, kind, seed)?
                        .with_budget(budget.clone()),
                ))
            }
            SccpNetworkV1::TonMainnet => Source::Ton(Box::new(
                LiteClient::from_keeper_config(config, seed)?.with_budget(budget.clone()),
            )),
            SccpNetworkV1::SoraTaira => eyre::bail!("Taira is not a destination"),
        };
        Ok(Self {
            network,
            source,
            budget,
            cursors: AllocationBudget::new(CURSOR_POOL_BYTES),
            work: AllocationBudget::new(SOURCE_POOL_BYTES),
            rows: Rows::default(),
            revision_after: 0,
            selected: 0,
        })
    }

    fn poll(&mut self, host: &NodeHost, control: SccpNativeReadControl<'_>) -> eyre::Result<()> {
        {
            let view = host.state.view();
            let Some(route) = store::routes::get(view.world(), &self.network) else {
                return Ok(());
            };
            let mut count = 0;
            for (revision, record) in route
                .revisions
                .range((Excluded(self.revision_after), Unbounded))
                .take(SCAN_PAGE)
            {
                check(control)?;
                self.rows.insert(
                    &Row {
                        revision: *revision,
                        deployment: record.deployment,
                        generation: record.initial_committee.generation,
                        until_ms: record.initial_committee.until_ms,
                        evm: EvmCursor::default(),
                        ton: TonCursor::default(),
                    },
                    &self.cursors,
                )?;
                self.revision_after = *revision;
                count += 1;
            }
            if count < SCAN_PAGE {
                self.revision_after = 0;
            }
        }
        if self.rows.rows.is_empty() {
            return Ok(());
        }
        self.selected %= self.rows.rows.len();
        let index = self.selected;
        self.selected += 1;
        let mut row = self.rows.rows[index];
        let still_registered = {
            let view = host.state.view();
            store::routes::get(view.world(), &self.network).is_some_and(|route| {
                route
                    .revisions
                    .get(&row.revision)
                    .is_some_and(|record| record.deployment == row.deployment)
            })
        };
        if !still_registered {
            self.rows.rows.remove(index);
            return Ok(());
        }
        let result = match (&self.source, row.deployment) {
            (Source::Evm(client), SccpDeploymentV1::Evm(deployment)) => {
                self.poll_evm(client, deployment.address, &mut row, host, control)
            }
            (Source::Ton(client), SccpDeploymentV1::Ton(deployment)) => {
                self.poll_ton(client, deployment.master_account, &mut row, host, control)
            }
            _ => eyre::bail!("registered deployment family differs"),
        };
        self.rows.rows[index] = row;
        if wall_clock_ms().saturating_add(ALERT_LEAD_MS) >= row.until_ms {
            iroha_logger::warn!(
                network = self.network.profile_key(),
                revision = row.revision,
                until_ms = row.until_ms,
                health = "sccp_destination_expiry",
                "SCCP destination expiry is within three days (untrusted destination observation)"
            );
        }
        result
    }

    fn poll_evm(
        &self,
        client: &EvmClient,
        address: [u8; 20],
        row: &mut Row,
        host: &NodeHost,
        control: SccpNativeReadControl<'_>,
    ) -> eyre::Result<()> {
        let expected_chain = if self.network == SccpNetworkV1::EthereumMainnet {
            1
        } else {
            56
        };
        eyre::ensure!(
            client.chain_id()? == expected_chain,
            "watch RPC chain id differs"
        );
        let head = client.block_number()?;
        let state = client.call(
            &EvmCallRequest::new(address, SELECTOR_COMMITTEE_STATE.to_vec()),
            BlockId::Tag(BlockTag::Number(head)),
        )?;
        let committee = decode_committee_state_return(&state)?;
        row.generation = committee.generation;
        row.until_ms = committee.until_ms;
        for (position, range) in row.evm.ranges(head).into_iter().enumerate() {
            let Some((first, last)) = range else {
                continue;
            };
            let logs = client.destination_logs(
                address,
                first,
                last,
                &[
                    TOPIC_CERTIFICATE,
                    TOPIC_COMMITTEE_ROTATED,
                    TOPIC_CHECKPOINTED,
                    TOPIC_LATCHED,
                ],
            )?;
            for log in logs {
                check(control)?;
                if log.removed {
                    continue;
                }
                if log.topics[0] == TOPIC_CERTIFICATE {
                    let cert = CertificateLogV1::decode(&log.topics, &log.data)?;
                    let evidence = SubmitSccpForgeryEvidenceV1 {
                        qc: cert.qc,
                        header: cert.header,
                        aggregate_signature: signature_from_evm192(&cert.signature)?,
                        anchor: None,
                    };
                    if !inspect(host, evidence, &self.work, control)? {
                        return Ok(());
                    }
                } else {
                    iroha_logger::debug!(
                        network = self.network.profile_key(),
                        revision = row.revision,
                        "SCCP destination progress event observed"
                    );
                }
            }
            if position == 0 {
                // Revisit a bounded recent overlap: event positions are untrusted and an
                // ordinary destination reorganisation must not hide replacement logs.
                row.evm.next = Some(last.saturating_sub(63));
            } else {
                row.evm.older = first.checked_sub(1);
            }
        }
        Ok(())
    }

    fn poll_ton(
        &self,
        client: &LiteClient,
        account: [u8; 32],
        row: &mut Row,
        host: &NodeHost,
        control: SccpNativeReadControl<'_>,
    ) -> eyre::Result<()> {
        let id = TonAccount {
            workchain: 0,
            address: account,
        };
        let at = client.get_masterchain_info()?.last;
        let state = client.get_account_state(at, id)?;
        let latest = ton_watch::account_cursor(&state.proof, &account)
            .ok_or_else(|| eyre::eyre!("TON watch account cursor unavailable"))?;
        if row.ton.catchup.is_none() && row.ton.newest != Some(latest) {
            row.ton.tip = Some(latest);
            row.ton.catchup = Some(latest);
        }
        for older in [false, true] {
            let Some(cursor) = (if older {
                row.ton.older
            } else {
                row.ton.catchup
            }) else {
                continue;
            };
            check(control)?;
            let page = client.get_transactions(16, id, cursor.lt, cursor.hash)?;
            let mut refusal = None;
            let mut pending = false;
            let next = ton_watch::certificates(
                &page.transactions,
                &account,
                cursor,
                |cert| {
                    let evidence = SubmitSccpForgeryEvidenceV1 {
                        qc: cert.qc,
                        header: cert.header,
                        aggregate_signature: cert.aggregate_signature,
                        anchor: None,
                    };
                    match inspect(host, evidence, &self.work, control) {
                        Ok(true) => true,
                        Ok(false) => {
                            pending = true;
                            false
                        }
                        Err(error) => {
                            refusal = Some(error);
                            false
                        }
                    }
                },
                |progress| match progress {
                    ton_watch::Progress::Rotation {
                        generation,
                        until_ms,
                    } if generation > row.generation => {
                        row.generation = generation;
                        row.until_ms = until_ms;
                    }
                    _ => iroha_logger::debug!(
                        revision = row.revision,
                        ?progress,
                        "SCCP TON destination progress observed"
                    ),
                },
            );
            if let Some(error) = refusal {
                return Err(error);
            }
            let next = match next {
                Ok(next) => next,
                Err(ton_watch::CertificatePageError::VisitorRefused) if pending => return Ok(()),
                Err(_) => eyre::bail!("TON watch transaction page malformed or unlinked"),
            };
            if older {
                row.ton.older = next;
            } else if row.ton.newest.is_none()
                || next.is_none_or(|position| {
                    row.ton.newest.is_some_and(|seen| position.lt <= seen.lt)
                })
            {
                if row.ton.newest.is_none() {
                    row.ton.older = next;
                }
                row.ton.newest = row.ton.tip;
                row.ton.catchup = None;
            } else {
                row.ton.catchup = next;
            }
        }
        Ok(())
    }
}

fn check(control: SccpNativeReadControl<'_>) -> eyre::Result<()> {
    eyre::ensure!(!control.stop.load(Ordering::Acquire), "watch stopped");
    eyre::ensure!(
        Instant::now() < control.deadline,
        "watch poll deadline expired"
    );
    Ok(())
}

/// True retires this discovery item; false retains its source page until publication.
fn inspect(
    host: &NodeHost,
    mut evidence: SubmitSccpForgeryEvidenceV1,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> eyre::Result<bool> {
    check(control)?;
    let now = wall_clock_ms();
    {
        let view = host.state.view();
        let mut checked = forgery::verify_committed(&view, &evidence, now, budget, control);
        if matches!(
            checked,
            Err(forgery::ForgeryVerificationError::WitnessRequired)
        ) {
            let height =
                iroha_sccp::v1::finality::SccpFinalityHeaderV1::parse(&evidence.header)?.height();
            evidence.anchor = Some(forgery::keeper::anchor_witness(
                &view, height, budget, control,
            )?);
            checked = forgery::verify_committed(&view, &evidence, now, budget, control);
        }
        match checked {
            Ok(candidate) => {
                if view
                    .world()
                    .consensus_evidence()
                    .get(&iroha_crypto::Hash::prehashed(candidate.evidence_id()))
                    .is_some()
                {
                    return Ok(true);
                }
            }
            Err(
                forgery::ForgeryVerificationError::NotEvidence
                | forgery::ForgeryVerificationError::EvidenceExpired
                | forgery::ForgeryVerificationError::BadSignature,
            ) => return Ok(true),
            Err(error) => return Err(error.into()),
        }
    }
    submit_transaction_at(&host.state, &host.queue, &host.key, evidence.into(), now)?;
    iroha_logger::warn!(
        health = "sccp_forgery_submitted",
        "SCCP watch submitted original-state verified destination forgery evidence"
    );
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_watch_pages_rotate_both_endpoint_families() {
        use iroha_sccp_rpc::{
            FailoverPolicy,
            ton::{LiteClientConfig, LiteServerSet},
        };
        let mut config = SccpLightClientKeeper::default();
        config.endpoints.bsc = ["http://127.0.0.1:1", "http://127.0.0.1:2"]
            .into_iter()
            .map(|url| url.parse().unwrap())
            .collect();
        let evm = Source::Evm(EvmClient::new(
            HttpTransport::from_keeper_config(&config, HttpEndpointKind::Bsc, 0).unwrap(),
        ));
        let key = "n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=";
        let servers =
            LiteServerSet::parse(&[&format!("127.0.0.1:1:{key}"), &format!("127.0.0.1:2:{key}")])
                .unwrap();
        let ton = Source::Ton(Box::new(LiteClient::new(
            servers,
            LiteClientConfig::default(),
            FailoverPolicy::default(),
        )));
        for source in [evm, ton] {
            let preferred = |source: &Source| match source {
                Source::Evm(client) => client.transport().endpoints().preferred(),
                Source::Ton(client) => client.servers().preferred(),
            };
            let first = preferred(&source);
            source.rotate_after_refusal();
            assert_eq!(preferred(&source), (first + 1) % 2);
            source.rotate_after_refusal();
            assert_eq!(preferred(&source), first);
        }
    }

    #[test]
    fn recent_watch_and_older_backfill_have_independent_bounded_progress() {
        let mut cursor = EvmCursor::default();
        assert_eq!(EvmCursor::default().ranges(0), [Some((0, 0)), None]);
        assert_eq!(cursor.ranges(5000), [Some((2953, 5000)), Some((905, 2952))]);
        cursor.next = Some(5001);
        cursor.older = Some(904);
        assert_eq!(cursor.ranges(5001), [Some((5001, 5001)), Some((0, 904))]);
        cursor.older = None;
        cursor.next = Some(5002);
        assert_eq!(cursor.ranges(5001), [None, None]);
    }

    #[test]
    fn original_cursor_pool_refuses_before_allocating_rows() {
        let mut rows = Rows::default();
        let row = Row {
            revision: 1,
            deployment: SccpDeploymentV1::Evm(
                iroha_data_model::sccp::deployment::SccpEvmDeploymentV1 {
                    address: [1; 20],
                    runtime_code_hash: [2; 32],
                },
            ),
            generation: 1,
            until_ms: 100,
            evm: EvmCursor::default(),
            ton: TonCursor::default(),
        };
        assert!(rows.insert(&row, &AllocationBudget::new(0)).is_err());
        assert!(rows.rows.is_empty());
        let budget = AllocationBudget::new(CURSOR_POOL_BYTES);
        rows.insert(&row, &budget).unwrap();
        rows.insert(&row, &budget).unwrap();
        assert_eq!(rows.rows.len(), 1);
        assert!(rows.charge.is_some());
    }
}
