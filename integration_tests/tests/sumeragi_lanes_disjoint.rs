//! Native lane progress over disjoint real committees, including a stopped lane and restart.
//!
//! This consensus-only fixture uses universal transaction gossip and zero fee quotes. The paid
//! Nexus campaign separately exercises restricted dataspaces and monetary settlement.

use super::*;
use eyre::{ensure, eyre};
use iroha::data_model::{
    isi::{InstructionBox, register::RegisterCommitteePeerWithPop},
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
};
use iroha_model_base::peer::PeerId;
use iroha_test_network::{
    CommitteeValidatorP2pBootstrap, unexecuted_genesis_factory_with_post_topology,
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID, BOB_KEYPAIR};
use std::collections::BTreeSet;

const LANES: [LaneId; 2] = [LaneId::new(2), LaneId::new(3)];
const MEMBERS: usize = 4;

fn policy(entries: &[GenesisTopologyEntry]) -> SumeragiLanePolicy {
    assert_eq!(entries.len(), LANES.len() * MEMBERS);
    let mut policy = SumeragiLanePolicy::for_chain(
        SumeragiParameters::default(),
        iroha_sumeragi::availability::recommended_data_availability_layout(),
    );
    policy.stall_window = 10_000;
    policy.fixed = entries
        .chunks_exact(MEMBERS)
        .zip(LANES)
        .map(|(entries, lane)| {
            let mut committee = entries
                .iter()
                .map(|entry| SumeragiLaneMember {
                    peer: entry.peer.clone(),
                    pop: entry.pop_bytes().unwrap().expect("participant PoP"),
                })
                .collect::<Vec<_>>();
            committee.sort_by(|left, right| left.peer.cmp(&right.peer));
            SumeragiFixedLane {
                lane,
                dataspace: DataSpaceId::UNIVERSAL,
                committee,
            }
        })
        .collect();
    policy.routes = LANES
        .into_iter()
        .zip([&*ALICE_ID, &*BOB_ID])
        .map(|(lane, account)| SumeragiLaneRoute {
            lane,
            account: Some(account.canonical_i105().expect("canonical authority")),
            instruction: Some("Log".to_owned()),
        })
        .collect();
    policy.validate().expect("disjoint native lane policy");
    policy
}

fn disjoint_builder() -> Result<NetworkBuilder> {
    Ok(NetworkBuilder::new()
        .with_peers(MEMBERS)
        .with_committee_validator_p2p_bootstrap(CommitteeValidatorP2pBootstrap::new(
            LANES.len() * MEMBERS,
        )?)?
        .with_auto_populated_trusted_peers()
        .with_genesis_instruction(iroha_data_model::isi::SetParameter::new(
            iroha_data_model::parameter::Parameter::Custom({
                let mut fees = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
                fees.fee_sink_account_id = iroha_test_samples::ALICE_ID.clone();
                fees.base_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_byte_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_instruction_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_gas_unit_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.into_custom_parameter()
                    .expect("explicit signed fixture fee policy")
            }),
        ))
        .with_config_layer(|layer| {
            layer.write(
                ["nexus", "storage", "local_budget_bytes"],
                TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
            );
        })
        .with_genesis_block_and_committee_validator_entries(|global, voters, participants| {
            let mut instructions = participants
                .iter()
                .map(|entry| {
                    RegisterCommitteePeerWithPop::new(
                        entry.peer.clone(),
                        entry.pop_bytes().unwrap().expect("participant PoP"),
                    )
                    .into()
                })
                .collect::<Vec<InstructionBox>>();
            instructions.push(
                SetParameter::new(Parameter::Custom(
                    policy(&participants).into_custom_parameter(),
                ))
                .into(),
            );
            unexecuted_genesis_factory_with_post_topology(
                Vec::new(),
                vec![instructions],
                global,
                voters,
            )
        }))
}

/// Check signer ownership on the original observed processes, including global lane observers.
fn ready_frontiers(network: &Network, peers: &[&NetworkPeer]) -> Result<[u64; 2]> {
    ensure!(!peers.is_empty(), "no peers selected for lane progress");
    let mut minimum = [u64::MAX; 2];
    let mut maximum = [0; 2];
    for peer in peers {
        let key = peer
            .bls_public_key()
            .ok_or_else(|| eyre!("missing BLS key"))?;
        let statuses = peer.client().client().get_sumeragi_lanes()?;
        ensure!(statuses.len() == LANES.len(), "unexpected lane population");
        for (ordinal, lane) in LANES.into_iter().enumerate() {
            let status = statuses
                .iter()
                .find(|status| status.record.lane == lane)
                .ok_or_else(|| eyre!("missing lane {lane}"))?;
            let instance = status
                .instance
                .as_ref()
                .ok_or_else(|| eyre!("lane is not running"))?;
            ensure!(instance.halted.is_none(), "lane {lane} halted");
            let expected = network.committee_validators()
                [ordinal * MEMBERS..(ordinal + 1) * MEMBERS]
                .iter()
                .map(|member| PeerId::new(member.bls_public_key().unwrap().clone()))
                .collect::<BTreeSet<_>>();
            ensure!(
                status
                    .record
                    .committee
                    .iter()
                    .map(|member| member.peer.clone())
                    .collect::<BTreeSet<_>>()
                    == expected,
                "lane {lane} changed its pinned disjoint committee"
            );
            let is_member = expected.contains(&PeerId::new(key.clone()));
            ensure!(
                instance.signer.as_ref() == is_member.then_some(key),
                "wrong lane signer ownership"
            );
            minimum[ordinal] = minimum[ordinal].min(status.record.merged.height);
            maximum[ordinal] = maximum[ordinal].max(status.record.merged.height);
        }
    }
    ensure!(
        minimum == maximum,
        "peers have not converged on lane frontiers"
    );
    Ok(minimum)
}

fn wait_frontiers(network: &Network, at_least: [u64; 2]) -> Result<[u64; 2]> {
    wait_frontiers_with_stopped(network, at_least, &[])
}

/// Omit only the explicitly stopped seats, never a process that unexpectedly exited.
fn wait_frontiers_with_stopped(
    network: &Network,
    at_least: [u64; 2],
    stopped: &[NetworkPeer],
) -> Result<[u64; 2]> {
    let peers: Vec<_> = network
        .all_peers()
        .filter(|peer| !stopped.iter().any(|stopped| stopped.id() == peer.id()))
        .collect();
    ensure!(!peers.is_empty(), "no peers selected for lane progress");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match ready_frontiers(network, &peers) {
            Ok(frontiers)
                if frontiers
                    .iter()
                    .zip(at_least)
                    .all(|(actual, required)| *actual >= required) =>
            {
                return Ok(frontiers);
            }
            observation if Instant::now() >= deadline => {
                bail!("disjoint lane progress failed: {observation:?}; required {at_least:?}")
            }
            _ => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

fn submit_lane_work(network: &Network, ordinal: usize, message: &str) -> Result<SignedTransaction> {
    let (authority, key) = match ordinal {
        0 => (&*ALICE_ID, &*ALICE_KEYPAIR),
        1 => (&*BOB_ID, &*BOB_KEYPAIR),
        _ => bail!("unknown fixture lane"),
    };
    let transaction = TransactionBuilder::new(
        network.network_id(),
        authority.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, message.to_owned())])
    .sign(key.private_key());
    // Enter through a global validator outside both lane committees. The production queue,
    // gossip, lane consensus and global merge must carry the original signed transaction.
    running_peer(network)?
        .client()
        .submit_transaction(&transaction)?;
    Ok(transaction)
}

#[test]
fn disjoint_lane_committees_keep_progress_when_one_stops_and_all_restart() -> Result<()> {
    init_instruction_registry();
    let Some((network, rt)) = sandbox::start_network_blocking_or_skip(
        disjoint_builder()?,
        stringify!(disjoint_lane_committees_keep_progress_when_one_stops_and_all_restart),
    )?
    else {
        return Ok(());
    };
    let result = (|| -> Result<()> {
        ensure!(
            network.validators().len() == MEMBERS
                && network.committee_validators().len() == 2 * MEMBERS,
            "global quorum must remain exactly four"
        );
        register_account_everywhere(&network)?;
        register_account_everywhere(&network)?;
        wait_frontiers(&network, [0, 0])?;
        submit_lane_work(&network, 0, "first disjoint lane")?;
        submit_lane_work(&network, 1, "second disjoint lane")?;
        let before = wait_frontiers(&network, [1, 1])?;
        for peer in &network.committee_validators()[..MEMBERS] {
            rt.block_on(peer.shutdown());
        }
        let stalled = submit_lane_work(
            &network,
            0,
            "retained while its entire committee is stopped",
        )?;
        submit_lane_work(&network, 1, "continues with the other lane stopped")?;
        let after = wait_frontiers_with_stopped(
            &network,
            [before[0], before[1] + 1],
            &network.committee_validators()[..MEMBERS],
        )?;
        // Already certified lane blocks may still merge after shutdown. The new carrier
        // submitted after every member stopped must remain pending while the other lane runs.
        ensure!(
            matches!(
                running_peer(&network)?
                    .client()
                    .client()
                    .get_transaction_status(stalled.hash())?,
                None | Some(
                    iroha::client::TxConfirmationStatus::Queued
                        | iroha::client::TxConfirmationStatus::Approved(_)
                )
            ),
            "fresh work finalized or failed while its entire lane committee was stopped"
        );
        for peer in &network.committee_validators()[..MEMBERS] {
            let layers: Vec<_> = network.config_layers_for_peer(peer).collect();
            rt.block_on(peer.start_checked(layers.iter(), None))?;
        }
        let recovered = wait_frontiers(&network, [after[0] + 1, after[1]])?;
        // Finality is for the exact original pending carrier, with no replay submission.
        running_peer(&network)?
            .client()
            .client()
            .wait_for_transaction_applied(stalled.hash(), Default::default())?;
        let height = committed_height(&network)?;
        for peer in network.all_peers() {
            rt.block_on(peer.shutdown());
        }
        for peer in network.all_peers() {
            let layers: Vec<_> = network.config_layers_for_peer(peer).collect();
            rt.block_on(peer.start_checked(layers.iter(), None))?;
        }
        wait_for_committed(&network, height, Duration::from_secs(120))?;
        ensure!(
            wait_frontiers(&network, recovered)? == recovered,
            "restart changed a certified lane frontier"
        );
        submit_lane_work(&network, 0, "first lane after all-seat restart")?;
        submit_lane_work(&network, 1, "second lane after all-seat restart")?;
        wait_frontiers(&network, [recovered[0] + 1, recovered[1] + 1])?;
        Ok(())
    })();
    rt.block_on(network.shutdown());
    result
}
