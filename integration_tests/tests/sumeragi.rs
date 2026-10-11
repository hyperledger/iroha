#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Sumeragi on real peers (`specs/sumeragi_goals.md` S4): four validators over P2P commit
//! transactions, restart, survive a crashed leader, and recover a held observer transport.
#[path = "kagemusha_network_setup.rs"]
mod kagemusha_network_setup;

use std::time::{Duration, Instant};

use eyre::{Result, bail, ensure, eyre};
use integration_tests::{
    sandbox::{self, SerializedNetwork},
    sync::sumeragi_statuses_reach_height,
};
use iroha::data_model::{account::Account, isi::Register, prelude::*, sumeragi::SumeragiStatus};
use iroha_test_network::{Network, NetworkBuilder, NetworkPeer, init_instruction_registry};
use iroha_test_samples::gen_account_in;
use tokio::runtime::Runtime;

const TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES: i64 = 1024 * 1024 * 1024;

fn builder() -> NetworkBuilder {
    NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_config_layer(|layer| {
            layer
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                // Isolate consensus from fee funding: keep the fee asset, quote zero charges.
                .write(["nexus", "fees", "base_fee"], "0")
                .write(["nexus", "fees", "per_byte_fee"], "0")
                .write(["nexus", "fees", "per_instruction_fee"], "0")
                .write(["nexus", "fees", "per_gas_unit_fee"], "0");
        })
}

fn start(name: &str) -> Result<Option<(SerializedNetwork, Runtime)>> {
    init_instruction_registry();
    sandbox::start_network_blocking_or_skip(builder(), name)
}

/// Every configured peer's Sumeragi status for the all-validator assertions.
fn statuses(network: &Network) -> Vec<Result<SumeragiStatus>> {
    network
        .peers()
        .iter()
        .map(|peer| peer.client().client().get_sumeragi_status())
        .collect()
}

/// Wait for every configured peer except seats the scenario explicitly stopped.
fn wait_for_committed(
    network: &Network,
    height: u64,
    limit: Duration,
    stopped: &[&NetworkPeer],
) -> Result<()> {
    let peers: Vec<_> = network
        .peers()
        .iter()
        .filter(|peer| !stopped.iter().any(|stopped| stopped.id() == peer.id()))
        .collect();
    let deadline = Instant::now() + limit;
    loop {
        let statuses: Vec<_> = peers
            .iter()
            .map(|peer| peer.client().client().get_sumeragi_status())
            .collect();
        if sumeragi_statuses_reach_height(&statuses, height)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let summary = statuses
                .iter()
                .map(|status| match status {
                    Ok(status) => format!(
                        "h{}/v{} committed={} signing={} unanchored={}",
                        status.height,
                        status.view,
                        status.committed_height,
                        status.is_signing(),
                        status.unanchored
                    ),
                    Err(error) => format!("error: {error}"),
                })
                .collect::<Vec<_>>();
            bail!("peers did not commit height {height} in {limit:?}: {summary:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The first running peer: clients must not talk to a peer a test shut down (the crashed leader
/// may be any peer, including the first).
fn running_peer(network: &Network) -> Result<&NetworkPeer> {
    network
        .peers()
        .iter()
        .find(|peer| peer.is_running())
        .ok_or_else(|| eyre::eyre!("no peer is running"))
}

fn committed_height(network: &Network) -> Result<u64> {
    Ok(running_peer(network)?
        .client()
        .client()
        .get_sumeragi_status()?
        .committed_height)
}

/// Register a fresh account through a running peer (the client waits until the transaction is
/// applied), then wait until every seat the scenario expects committed its block.
fn register_account_everywhere(network: &Network, stopped: &[&NetworkPeer]) -> Result<AccountId> {
    let (account, _) = gen_account_in("wonderland");
    running_peer(network)?.client().submit(
        Register::account(Account::new(account.clone())),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let height = committed_height(network)?;
    wait_for_committed(network, height, Duration::from_secs(60), stopped)?;
    Ok(account)
}

#[test]
fn four_validators_commit_a_transaction() -> Result<()> {
    let Some((network, rt)) = start(stringify!(four_validators_commit_a_transaction))? else {
        return Ok(());
    };
    let result = (|| -> Result<()> {
        wait_for_committed(&network, 1, network.sync_timeout(), &[])?;
        let before = committed_height(&network)?;
        register_account_everywhere(&network, &[])?;
        let after = committed_height(&network)?;
        assert!(after > before, "the transaction's block is committed");
        for status in statuses(&network) {
            let status = status?;
            assert!(status.is_signing(), "every validator signs: {status:?}");
            assert_eq!(status.applied_height, status.committed_height);
        }
        Ok(())
    })();
    rt.block_on(async { network.shutdown().await });
    result
}

/// One validator restarts (records and Kura kept) while the other three commit, catches up and
/// signs again; then the whole cluster restarts and goes on.
#[test]
fn validators_restart_one_and_all() -> Result<()> {
    let Some((network, rt)) = start(stringify!(validators_restart_one_and_all))? else {
        return Ok(());
    };
    let result = (|| -> Result<()> {
        wait_for_committed(&network, 1, network.sync_timeout(), &[])?;
        // One validator down: the remaining quorum (3 of 4) commits.
        let restarted = &network.peers()[1];
        rt.block_on(restarted.shutdown());
        register_account_everywhere(&network, &[restarted])?;
        let height = committed_height(&network)?;
        let layers: Vec<_> = network.config_layers_for_peer(restarted).collect();
        rt.block_on(restarted.start_checked(layers.iter(), None))?;
        wait_for_committed(&network, height, Duration::from_secs(60), &[])?;
        register_account_everywhere(&network, &[])?;
        // Whole cluster down and up: every validator rebuilds its state from Kura.
        let height = committed_height(&network)?;
        for peer in network.peers() {
            rt.block_on(peer.shutdown());
        }
        for peer in network.peers() {
            let layers: Vec<_> = network.config_layers_for_peer(peer).collect();
            rt.block_on(peer.start_checked(layers.iter(), None))?;
        }
        wait_for_committed(&network, height, Duration::from_secs(60), &[])?;
        register_account_everywhere(&network, &[])?;
        for status in statuses(&network) {
            let status = status?;
            assert!(
                status.is_signing(),
                "every validator signs again: {status:?}"
            );
        }
        Ok(())
    })();
    rt.block_on(async { network.shutdown().await });
    result
}

/// The leader of the next round crashes: the others time out, change the view, and commit a
/// transaction under the next leader.
#[test]
fn a_crashed_leader_is_replaced() -> Result<()> {
    let Some((network, rt)) = start(stringify!(a_crashed_leader_is_replaced))? else {
        return Ok(());
    };
    let result = (|| -> Result<()> {
        wait_for_committed(&network, 1, network.sync_timeout(), &[])?;
        let status = network.client().client().get_sumeragi_status()?;
        let leader = status
            .leader
            .clone()
            .ok_or_else(|| eyre::eyre!("no leader while awaiting: {status:?}"))?;
        let leader_peer = network
            .peers()
            .iter()
            .find(|peer| peer.id().public_key() == &leader)
            .ok_or_else(|| eyre::eyre!("the leader {leader} is not a peer"))?;
        rt.block_on(leader_peer.shutdown());
        let started = Instant::now();
        register_account_everywhere(&network, &[leader_peer])?;
        eprintln!(
            "committed without the crashed leader in {:?}",
            started.elapsed()
        );
        Ok(())
    })();
    rt.block_on(async { network.shutdown().await });
    result
}

#[cfg(unix)]
#[path = "nexus/atomic_private_settlement_transport.rs"]
mod transport_evidence;

#[cfg(unix)]
#[path = "support/rs16_local_state.rs"]
mod rs16_local_state;

/// Opaque inbound transport hold, not selective RS16 row withholding or a
/// Byzantine-node switch. Finality is verified independently from original
/// genesis; the actual observer process must subsequently acquire signed rows.
#[cfg(unix)]
#[test]
fn observer_transport_hold_preserves_signed_rs16_custody_and_paid_finality() -> Result<()> {
    use iroha_test_network::{ObserverP2pBootstrap, ObserverSlowReaderRelayConfig};
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use rs16_hold::{balances, certified_at, exact_processes, observer_held, supply, wait_applied};

    init_instruction_registry();
    let sink = BOB_ID.to_i105_for_discriminant(
        iroha_config::parameters::defaults::common::chain_discriminant(),
    )?;
    let recipe = NetworkBuilder::new()
        .with_peers(4)
        .with_base_seed(stringify!(
            observer_transport_hold_preserves_signed_rs16_custody_and_paid_finality
        ))
        .with_auto_populated_trusted_peers()
        .with_observer_p2p_bootstrap(ObserverP2pBootstrap::new(1)?)?
        .with_observer_slow_reader_relays(ObserverSlowReaderRelayConfig::new(
            1_024,
            Duration::from_millis(1),
        )?)?
        .with_config_layer(|layer| {
            layer
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                .write(["nexus", "fees", "base_fee"], "1")
                .write(["nexus", "fees", "per_byte_fee"], "0")
                .write(["nexus", "fees", "per_instruction_fee"], "0")
                .write(["nexus", "fees", "per_gas_unit_fee"], "0")
                .write(["nexus", "fees", "fee_sink_account_id"], sink)
                .write(["logger", "format"], "json");
        });
    let Some((network, rt)) = sandbox::start_network_blocking_or_skip(
        recipe,
        stringify!(observer_transport_hold_preserves_signed_rs16_custody_and_paid_finality),
    )?
    else {
        bail!("required real-process transport hold cannot skip network startup");
    };
    // Each receiver and PID belongs to one original peer/run, before paid work.
    let mut exits = network
        .all_peers()
        .map(NetworkPeer::events)
        .collect::<Vec<_>>();
    let result = (|| -> Result<()> {
        ensure!(
            network.validators().len() == 4
                && network.observers().len() == 1
                && network.all_peers().count() == 5
                && network.topology_entries().len() == 4,
            "hold fixture must be four voters plus one signed nonvoting replica"
        );
        let original = exact_processes(&network, &rt)?;
        let observer = &network.observers()[0];
        let fee_asset = iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse::<AssetDefinitionId>()?;
        let fee_ids = [
            AssetId::new(fee_asset.clone(), ALICE_ID.clone()),
            AssetId::new(fee_asset, BOB_ID.clone()),
        ];
        let warm_deadline = Instant::now() + Duration::from_secs(60);
        wait_applied(&network, 1, warm_deadline, true)?;
        let (warm, _) = gen_account_in("wonderland");
        network.validators()[0]
            .client()
            .with_request_deadline(warm_deadline)?
            .submit(
                Register::account(Account::new(warm.clone())),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )?;
        let baseline = network.validators()[0]
            .client()
            .with_request_deadline(warm_deadline)?
            .client()
            .get_sumeragi_status()?
            .applied_height;
        ensure!(baseline > 1, "warmup must execute nonempty paid work");
        wait_applied(&network, baseline, warm_deadline, true)?;
        let before = balances(&network, &fee_ids, warm_deadline)?;
        let supply_before = supply(&network, fee_ids[0].definition(), warm_deadline)?;
        let baseline_certified = certified_at(&network, observer, baseline, warm_deadline)?;
        ensure!(
            rs16_local_state::account_present(
                observer,
                &rt,
                &warm,
                &baseline_certified,
                warm_deadline
            )? && rs16_local_state::balances(
                observer,
                &rt,
                &fee_ids,
                &baseline_certified,
                warm_deadline
            )? == before,
            "warm observer must locally apply the warm account and funded fee ledger"
        );
        let established = network
            .observer_slow_reader_relay_stats_for(&observer.id())
            .ok_or_else(|| eyre!("observer relay source missing"))?;
        ensure!(
            established.accepted_connections > 0
                && established.upstream_connections > 0
                && established.delayed_reads > 0
                && established.forwarded_to_observers_bytes > 0,
            "hold requires established inbound ciphertext traffic"
        );
        observer_held(observer, baseline, warm_deadline)?;
        let deadline = Instant::now() + Duration::from_secs(60);
        // Acquisition, fresh paid execution, hold, release and finality retain
        // this one original transport deadline, including quiescence wait.
        let pause = rt
            .block_on(async {
                tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    network.pause_observer_slow_reader_relays(),
                )
                .await
            })?
            .ok_or_else(|| eyre!("observer relay hook missing"))?;
        let held_bytes = network
            .observer_slow_reader_relay_stats_for(&observer.id())
            .unwrap()
            .forwarded_to_observers_bytes;
        let held_at = Instant::now();
        let (fresh, _) = gen_account_in("wonderland");
        let transaction = network.validators()[0]
            .client()
            .with_request_deadline(deadline)?
            .submit(
                Register::account(Account::new(fresh.clone())),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )?;
        let target = baseline
            .checked_add(1)
            .ok_or_else(|| eyre!("height overflow"))?;
        wait_applied(&network, target, deadline, false)?;
        observer_held(observer, baseline, deadline)?;
        ensure!(
            !rs16_local_state::account_present(
                observer,
                &rt,
                &fresh,
                &baseline_certified,
                deadline
            )? && rs16_local_state::balances(
                observer,
                &rt,
                &fee_ids,
                &baseline_certified,
                deadline
            )? == before,
            "held observer locally applied fresh paid account work or its fee changes"
        );
        let after = balances(&network, &fee_ids, deadline)?;
        let supply_after = supply(&network, fee_ids[0].definition(), deadline)?;
        let fee = iroha_primitives::numeric::Quantity::from(1_u32);
        // Current direct Nexus settlement burns the real fee. A credited sink
        // would preserve supply and cannot qualify this monetary observation.
        ensure!(
            before[0].checked_sub(&after[0])? == fee
                && after[1] == before[1]
                && supply_before.checked_sub(&supply_after)? == fee,
            "fresh work must burn exactly one funded fee without crediting the sink: balances {before:?} -> {after:?}, supply {supply_before} -> {supply_after}"
        );
        let certified = certified_at(&network, &network.validators()[0], target, deadline)?;
        ensure!(
            certified.committed().block().has_results()
                && certified
                    .committed()
                    .block()
                    .external_transactions()
                    .any(|tx| tx.hash() == transaction),
            "certified held-height carrier must contain the actual paid transaction"
        );
        let block = certified.committed().block();
        let mut settled = 0;
        for index in 0..block.network_entrypoint_count() {
            let Some(TransactionEntrypoint::External(input)) = block.network_entrypoint_at(index)
            else {
                continue;
            };
            if input.hash() != transaction {
                continue;
            }
            let (_, output) = block
                .network_output_at(u32::try_from(index)?)
                .ok_or_else(|| eyre!("paid RS16 input has no original execution output"))?;
            let receipt = output
                .result
                .nexus_fee_receipt()
                .ok_or_else(|| eyre!("paid RS16 output omitted its actual fee receipt"))?;
            ensure!(
                output.result.0.is_ok()
                    && receipt.source_id
                        == *iroha_crypto::Hash::from(input.hash_as_entrypoint()).as_ref()
                    && receipt.block_height == target
                    && receipt.fee_asset_id == *fee_ids[0].definition()
                    && receipt.debit_source
                        == iroha_data_model::nexus::FeeDebitSource::Account(ALICE_ID.clone())
                    && receipt.fee_amount == fee
                    && matches!(
                        receipt.settlement,
                        iroha_data_model::block::consensus::NexusFeeSettlementV1::Burn
                    ),
                "certified RS16 execution must bind the same successful authority-paid fee burn"
            );
            settled += 1;
        }
        ensure!(
            settled == 1,
            "paid RS16 input must have exactly one fee output"
        );
        // A fixed bounded observation interval after committee finality confirms
        // the guard is still held; it never manufactures another block.
        let hold_end = Instant::now() + Duration::from_secs(1);
        ensure!(
            hold_end < deadline,
            "hold interval cannot extend the original deadline"
        );
        loop {
            observer_held(observer, baseline, deadline)?;
            ensure!(
                network
                    .observer_slow_reader_relay_stats_for(&observer.id())
                    .unwrap()
                    .forwarded_to_observers_bytes
                    == held_bytes,
                "acknowledged pause forwarded new ciphertext"
            );
            if Instant::now() >= hold_end {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        exact_processes(&network, &rt).and_then(|current| {
            ensure!(
                current == original,
                "original peer PID/run custody changed during hold"
            );
            Ok(())
        })?;
        let held_for = held_at.elapsed();
        drop(pause);
        wait_applied(&network, target, deadline, true)?;
        let observer_certified = certified_at(&network, observer, target, deadline)?;
        ensure!(
            balances(&network, &fee_ids, deadline)? == after
                && supply(&network, fee_ids[0].definition(), deadline)? == supply_after
                && rs16_local_state::balances(
                    observer,
                    &rt,
                    &fee_ids,
                    &observer_certified,
                    deadline
                )? == after,
            "released observer must locally apply the same fee debit and unchanged sink balance"
        );
        ensure!(
            rs16_local_state::account_present(
                observer,
                &rt,
                &fresh,
                &observer_certified,
                deadline
            )?,
            "released observer must locally apply that same account work"
        );
        ensure!(
            observer_certified.committed().block_hash() == certified.committed().block_hash()
                && observer_certified.committed().core_hash() == certified.committed().core_hash()
                && observer_certified.committed().result() == certified.committed().result()
                && observer_certified.committed().header() == certified.committed().header(),
            "observer substituted another certified block/result after release"
        );
        // Different honest exact-quorum certificate bytes are permissible; the
        // independently authenticated header, result and original body agree.
        let evidence = rs16_hold::verify_observer_rows(
            &network,
            observer,
            original[4].0,
            &observer_certified,
            deadline,
        )?;
        ensure!(
            exact_processes(&network, &rt)? == original,
            "peer process/run changed on release"
        );
        ensure!(
            network
                .observer_slow_reader_relay_stats_for(&observer.id())
                .unwrap()
                .forwarded_to_observers_bytes
                > held_bytes,
            "release did not resume actual forwarding"
        );
        eprintln!(
            "RS16_TRANSPORT_HOLD height={target} held_ms={} observer_pid={} admitted_rows={} audit_lines={}",
            held_for.as_millis(),
            original[4].0,
            evidence.admitted_rows,
            evidence.audit_lines.len()
        );
        Ok(())
    })();
    rt.block_on(network.shutdown());
    let closure = rs16_hold::clean_exits(&network, &rt, &mut exits);
    result.and(closure)
}

/// The shared native verifier supplies authority; these helpers retain bounded
/// diagnostic source reads and actual process/ledger observations only.
#[cfg(unix)]
mod rs16_hold {
    use super::*;
    use iroha_core::sumeragi::certified_chain::{CertifiedBlock, CertifiedPrefix};
    use iroha_model_base::peer::PeerId;
    use iroha_primitives::numeric::Quantity;
    use iroha_test_network::PeerLifecycleEvent;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs::{self, File},
        io::Read,
        num::NonZeroU64,
        path::Path,
    };
    use tokio::sync::broadcast;

    pub(super) fn exact_processes(network: &Network, rt: &Runtime) -> Result<Vec<(u32, usize)>> {
        let snapshots = network.startup_snapshot();
        network
            .all_peers()
            .zip(snapshots)
            .map(|(peer, snapshot)| {
                let pid = rt
                    .block_on(peer.process_id())
                    .ok_or_else(|| eyre!("original process missing"))?;
                ensure!(
                    peer.is_running() && snapshot.is_running,
                    "peer exited during transport control"
                );
                let stdout = snapshot
                    .logs
                    .stdout_log
                    .as_ref()
                    .ok_or_else(|| eyre!("stdout missing"))?;
                let stderr = snapshot
                    .logs
                    .stderr_log
                    .as_ref()
                    .ok_or_else(|| eyre!("stderr missing"))?;
                let run = transport_evidence::current_run_log(
                    &network.env_dir().join(peer.mnemonic()),
                    snapshot.logs.stderr_run_id,
                    stdout,
                    stderr,
                )?;
                Ok((pid, run))
            })
            .collect()
    }

    pub(super) fn observer_held(peer: &NetworkPeer, height: u64, deadline: Instant) -> Result<()> {
        let status = peer
            .client()
            .with_request_deadline(deadline)?
            .client()
            .get_sumeragi_status()?;
        ensure!(
            !status.is_signing() && !status.is_halted() && status.applied_height == height,
            "observer must remain nonvoting, healthy and unapplied at held height: {status:?}"
        );
        Ok(())
    }

    pub(super) fn wait_applied(
        network: &Network,
        height: u64,
        deadline: Instant,
        observer: bool,
    ) -> Result<()> {
        loop {
            ensure!(
                Instant::now() < deadline,
                "original transport deadline elapsed at {height}"
            );
            let mut ready = true;
            for peer in network
                .validators()
                .iter()
                .chain(network.observers().iter().filter(|_| observer))
            {
                let status = peer
                    .client()
                    .with_request_deadline(deadline)?
                    .client()
                    .get_sumeragi_status()?;
                ensure!(
                    !status.is_halted() && status.applied_height <= height,
                    "peer halted or applied unrequested work: {status:?}"
                );
                ensure!(
                    status.is_signing() == network.validators().contains(peer),
                    "observer/voter signing role changed: {status:?}"
                );
                ready &= status.committed_height >= height && status.applied_height == height;
            }
            if ready {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub(super) fn balances(
        network: &Network,
        ids: &[AssetId; 2],
        deadline: Instant,
    ) -> Result<[Quantity; 2]> {
        let mut original = None;
        for peer in network.validators() {
            let mut rows = BTreeMap::new();
            let client = peer.client().with_request_deadline(deadline)?;
            for id in ids {
                let asset = client
                    .client()
                    .query_single(FindAssetById::new(id.clone()))?;
                ensure!(asset.id() == id, "fee balance returned a different asset");
                ensure!(
                    rows.insert(asset.id().clone(), asset.value().clone())
                        .is_none(),
                    "duplicate asset row"
                );
            }
            let values = [
                rows.get(&ids[0])
                    .cloned()
                    .ok_or_else(|| eyre!("funded signer bucket missing"))?,
                rows.get(&ids[1])
                    .cloned()
                    .ok_or_else(|| eyre!("funded fee sink bucket missing"))?,
            ];
            if let Some(before) = &original {
                ensure!(before == &values, "validator paid ledgers disagree");
            }
            original = Some(values);
        }
        original.ok_or_else(|| eyre!("validator ledger observations absent"))
    }

    /// Observe the actual fee-asset supply on every validator within the original deadline.
    pub(super) fn supply(
        network: &Network,
        id: &AssetDefinitionId,
        deadline: Instant,
    ) -> Result<Quantity> {
        let mut original = None;
        for peer in network.validators() {
            let definition = peer
                .client()
                .with_request_deadline(deadline)?
                .client()
                .query_single(FindAssetDefinitionById::new(id.clone()))?;
            ensure!(
                definition.id() == id,
                "fee supply returned a different asset"
            );
            let value = definition.total_quantity();
            if let Some(previous) = &original {
                ensure!(previous == value, "validator fee supplies disagree");
            }
            original = Some(value.clone());
        }
        original.ok_or_else(|| eyre!("validator fee supply observations absent"))
    }

    pub(super) fn certified_at(
        network: &Network,
        peer: &NetworkPeer,
        height: u64,
        deadline: Instant,
    ) -> Result<CertifiedBlock> {
        ensure!(
            (2..=4_096).contains(&height),
            "non-genesis bounded prefix required"
        );
        let client = peer.client().with_request_deadline(deadline)?;
        let genesis = network.genesis().0;
        let budget = iroha_core::state::AllocationBudget::new(32 * 1024 * 1024);
        let mut prefix = None;
        let mut target = None;
        for at in 1..=height {
            ensure!(
                Instant::now() < deadline,
                "native prefix verification deadline elapsed"
            );
            let proof = client
                .client()
                .get_sumeragi_finality_proof(NonZeroU64::new(at).unwrap())?;
            ensure!(
                proof.height() == at,
                "finality source substituted requested height"
            );
            proof.decode_checked()?;
            let block = iroha_data_model::block::decode_framed_signed_block(&proof.block_wire)?;
            let block = iroha_data_model::block::SharedSignedBlock::try_new(block, &budget)
                .map_err(|(_, error)| error)?;
            if at == 1 {
                ensure!(
                    block.canonical_resultless_proposal()?.encode_wire()?
                        == genesis.canonical_resultless_proposal()?.encode_wire()?,
                    "finality source replaced independently signed genesis"
                );
                prefix = Some(CertifiedPrefix::new(
                    &network.chain_id(),
                    network.network_id(),
                    block,
                )?);
            } else {
                target = Some(prefix.as_mut().unwrap().push(block)?.into_parts().0);
            }
        }
        ensure!(
            Instant::now() < deadline,
            "native prefix verification deadline elapsed"
        );
        let target = target.ok_or_else(|| eyre!("nonempty certified successor absent"))?;
        let committee = &target.committed().commitment().schedule.current.committee;
        ensure!(
            committee.len() == 4
                && committee
                    .iter()
                    .map(|seat| seat.validator.clone())
                    .collect::<BTreeSet<_>>()
                    == network
                        .validators()
                        .iter()
                        .map(NetworkPeer::id)
                        .collect::<BTreeSet<_>>()
                && target
                    .commit_qc()
                    .is_some_and(|qc| qc.signers.count_ones() == 3),
            "finality must use the original four voters and exact three-vote quorum"
        );
        Ok(target)
    }

    #[cfg(unix)]
    fn transport_log_prefix(path: &Path) -> Result<Vec<u8>> {
        use std::os::unix::fs::MetadataExt as _;
        let before = fs::symlink_metadata(path)?;
        ensure!(
            before.is_file()
                && !before.file_type().is_symlink()
                && before.len() <= 64 * 1024 * 1024,
            "invalid bounded process log source"
        );
        let mut file = File::open(path)?;
        let opened = file.metadata()?;
        ensure!(
            before.dev() == opened.dev() && before.ino() == opened.ino(),
            "process log source replaced"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(before.len())
            .read_to_end(&mut bytes)?;
        let current = fs::symlink_metadata(path)?;
        ensure!(
            bytes.len() as u64 == before.len()
                && file.metadata()?.len() >= before.len()
                && current.dev() == before.dev()
                && current.ino() == before.ino(),
            "process log source changed"
        );
        if let Some(end) = bytes.iter().rposition(|byte| *byte == b'\n') {
            bytes.truncate(end + 1);
        } else {
            bytes.clear();
        }
        Ok(bytes)
    }

    pub(super) fn verify_observer_rows(
        network: &Network,
        peer: &NetworkPeer,
        pid: u32,
        certified: &CertifiedBlock,
        deadline: Instant,
    ) -> Result<transport_evidence::Verified> {
        let committed = certified.committed();
        let header = committed
            .header()
            .ok_or_else(|| eyre!("non-genesis native header missing"))?;
        let layout = committed.commitment().schedule.current.da_layout;
        let shape = layout.shape(u64::from(header.payload_len))?;
        let key = |peer: &PeerId| -> Result<String> {
            Ok(hex::encode(
                iroha_core::sumeragi::schedule::consensus_key(peer)?.as_bytes(),
            ))
        };
        let expected = transport_evidence::Expected {
            process_id: pid,
            instance: header.instance.to_string(),
            height: header.height,
            block: committed.core_hash().to_string(),
            result: committed.result().to_string(),
            availability: header.availability_digest.to_string(),
            payload: header.payload_hash.to_string(),
            bytes: u64::from(header.payload_len),
            epoch: header.epoch.epoch,
            context: header.epoch.context.to_string(),
            proposer: u64::from(header.proposer),
            local_is_author: false,
            local: key(&peer.id())?,
            peers: network
                .all_peers()
                .map(|peer| key(&peer.id()))
                .collect::<Result<_>>()?,
            k: usize::from(layout.data_shards),
            width: usize::from(layout.data_shards) + usize::from(layout.parity_shards),
            stripes: shape.stripe_count(),
        };
        let snapshot = network
            .startup_snapshot()
            .pop()
            .ok_or_else(|| eyre!("observer source snapshot absent"))?;
        ensure!(snapshot.is_running, "observer source exited");
        let path = snapshot
            .logs
            .stdout_log
            .as_ref()
            .ok_or_else(|| eyre!("observer stdout source absent"))?;
        let stderr = snapshot
            .logs
            .stderr_log
            .as_ref()
            .ok_or_else(|| eyre!("observer stderr source absent"))?;
        transport_evidence::current_run_log(
            &network.env_dir().join(peer.mnemonic()),
            snapshot.logs.stderr_run_id,
            path,
            stderr,
        )?;
        ensure!(
            Instant::now() < deadline,
            "transport evidence deadline elapsed"
        );
        let log = transport_log_prefix(path)?;
        let verified = transport_evidence::verify(&log, &expected)?;
        ensure!(
            verified.admitted_rows
                >= expected
                    .k
                    .checked_mul(expected.stripes)
                    .ok_or_else(|| eyre!("RS16 geometry overflow"))?,
            "observer lacks actual signed row custody"
        );
        ensure!(
            Instant::now() < deadline,
            "transport evidence deadline elapsed"
        );
        Ok(verified)
    }

    pub(super) fn clean_exits(
        network: &Network,
        rt: &Runtime,
        exits: &mut [broadcast::Receiver<PeerLifecycleEvent>],
    ) -> Result<()> {
        ensure!(
            exits.len() == 5 && network.all_peers().count() == 5,
            "exact five process owners required"
        );
        let mut total = 0;
        for (peer, events) in network.all_peers().zip(exits) {
            ensure!(
                !peer.is_running() && rt.block_on(peer.process_id()).is_none(),
                "process survived cleanup"
            );
            let mut terminated = 0;
            let mut count = 0;
            loop {
                count += 1;
                ensure!(
                    count <= 256,
                    "peer lifecycle stream exceeded bounded test work"
                );
                match events.try_recv() {
                    Ok(PeerLifecycleEvent::Terminated { status }) => {
                        ensure!(
                            status.success(),
                            "peer {} exited unsuccessfully: {status:?}",
                            peer.mnemonic()
                        );
                        terminated += 1;
                    }
                    Ok(PeerLifecycleEvent::Killed) => bail!("peer was forcibly killed"),
                    Ok(PeerLifecycleEvent::Spawned) => bail!("original peer process was replaced"),
                    Ok(_) => {}
                    Err(
                        broadcast::error::TryRecvError::Empty
                        | broadcast::error::TryRecvError::Closed,
                    ) => break,
                    Err(broadcast::error::TryRecvError::Lagged(_)) => {
                        bail!("lost lifecycle custody")
                    }
                }
            }
            ensure!(
                terminated == 1,
                "peer {} lacks exactly one clean exit",
                peer.mnemonic()
            );
            total += terminated;
        }
        ensure!(total == 5, "clean process closure omitted an original peer");
        eprintln!("RS16_TRANSPORT_HOLD_CLEAN_EXITS {total}");
        Ok(())
    }
}
