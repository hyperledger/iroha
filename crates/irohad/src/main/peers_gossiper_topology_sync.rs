//! Committed validator-roster synchronization for peer-gossip authorization.

use std::{collections::HashSet, sync::Arc};

use iroha_core::{peers_gossiper::PeersGossiperHandle, state::State};
use iroha_data_model::events::{
    EventBox,
    pipeline::{BlockStatus, PipelineEventBox},
};
use iroha_futures::supervisor::ShutdownSignal;
use iroha_model_base::peer::PeerId;
use iroha_p2p::UpdateTopology;
use tokio::sync::broadcast;

#[derive(Debug, Default)]
struct TopologySyncState {
    last_published: Option<HashSet<PeerId>>,
}

impl TopologySyncState {
    fn update(
        &mut self,
        committed_height: usize,
        topology: impl IntoIterator<Item = PeerId>,
    ) -> Option<UpdateTopology> {
        // Before genesis (or the first replayed block) commits, the daemon's
        // configured validator roster remains the gossiper's startup authority.
        if committed_height == 0 {
            return None;
        }
        let topology: HashSet<_> = topology.into_iter().collect();
        if self.last_published.as_ref() == Some(&topology) {
            return None;
        }
        self.last_published = Some(topology.clone());
        Some(UpdateTopology(topology))
    }
}

fn reconcile_committed_topology(
    sync_state: &mut TopologySyncState,
    state: &State,
    peers_gossiper: &PeersGossiperHandle,
) {
    if let Some(update) =
        sync_state.update(state.committed_height(), state.commit_topology_snapshot())
    {
        peers_gossiper.update_topology(update);
    }
}

fn event_follows_state_commit(event: &EventBox) -> bool {
    // `StateBlock` stages `Applied` while building its overlay; the Sumeragi
    // executor broadcasts that event only after the overlay commits successfully.
    matches!(
        event,
        EventBox::Pipeline(PipelineEventBox::Block(block))
            if status_follows_state_commit(block.status)
    )
}

const fn status_follows_state_commit(status: BlockStatus) -> bool {
    matches!(status, BlockStatus::Applied)
}

/// Keep peer-gossip validator authority synchronized with committed state.
pub async fn run(
    state: Arc<State>,
    peers_gossiper: PeersGossiperHandle,
    mut events: broadcast::Receiver<EventBox>,
    shutdown_signal: ShutdownSignal,
) {
    let mut sync_state = TopologySyncState::default();
    // State replay completes before this worker starts. Reconcile it once so a
    // restarted node does not retain a stale configured voter roster.
    reconcile_committed_topology(&mut sync_state, &state, &peers_gossiper);

    loop {
        tokio::select! {
            biased;
            () = shutdown_signal.receive() => {
                iroha_logger::debug!("Shutting down peer-gossip topology synchronizer");
                break;
            }
            result = events.recv() => match result {
                Ok(event) if event_follows_state_commit(&event) => {
                    reconcile_committed_topology(&mut sync_state, &state, &peers_gossiper);
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    iroha_logger::warn!(
                        skipped,
                        "Peer-gossip topology synchronizer lagged; reconciling the latest committed state"
                    );
                    reconcile_committed_topology(&mut sync_state, &state, &peers_gossiper);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    iroha_logger::error!(
                        "Pipeline event channel closed before peer-gossip topology synchronizer shutdown"
                    );
                    break;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;

    fn peer_id() -> PeerId {
        PeerId::new(KeyPair::random().public_key().clone())
    }

    #[test]
    fn publishes_each_distinct_committed_roster_exactly_once() {
        let first = peer_id();
        let removed = peer_id();
        let mut state = TopologySyncState::default();

        assert!(
            state.update(0, [first.clone(), removed.clone()]).is_none(),
            "startup configuration remains authoritative before a commit"
        );
        let initial = state
            .update(1, [first.clone(), removed.clone()])
            .expect("first committed roster is published");
        assert_eq!(initial.0, HashSet::from([first.clone(), removed.clone()]));
        assert!(
            state.update(2, [removed.clone(), first.clone()]).is_none(),
            "a reordered but identical roster is not republished"
        );

        let demoted = state
            .update(3, [first.clone()])
            .expect("validator removal is published");
        assert_eq!(demoted.0, HashSet::from([first]));

        let fail_closed = state
            .update(4, [])
            .expect("an empty committed roster must revoke stale authority");
        assert!(fail_closed.0.is_empty());
    }

    #[test]
    fn only_applied_block_status_follows_state_commit() {
        assert!(!status_follows_state_commit(BlockStatus::Created));
        assert!(!status_follows_state_commit(BlockStatus::Approved));
        assert!(!status_follows_state_commit(BlockStatus::Committed));
        assert!(status_follows_state_commit(BlockStatus::Applied));
    }
}
