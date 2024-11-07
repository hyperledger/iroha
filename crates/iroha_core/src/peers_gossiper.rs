//! Peers gossiper is actor which is responsible for gossiping addresses of peers.
//!
//! E.g. peer A changes address, connects to peer B,
//! and then peer B will broadcast address of peer A to other peers.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use iroha_config::parameters::actual::TrustedPeers;
use iroha_data_model::peer::{Peer, PeerId};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_p2p::{Broadcast, UpdatePeers, UpdateTopology};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use iroha_version::{Decode, Encode};
use parity_scale_codec::{Error, Input};
use tokio::sync::mpsc;

use crate::{IrohaNetwork, NetworkMessage};

/// [`Gossiper`] actor handle.
#[derive(Clone)]
pub struct PeersGossiperHandle {
    message_sender: mpsc::Sender<(PeersGossip, Peer)>,
    update_topology_sender: mpsc::UnboundedSender<UpdateTopology>,
}

impl PeersGossiperHandle {
    /// Send [`PeersGossip`] to actor
    pub async fn gossip(&self, gossip: PeersGossip, peer: Peer) {
        self.message_sender
            .send((gossip, peer))
            .await
            .expect("Gossiper must handle messages until there is at least one handle to it")
    }

    /// Send [`UpdateTopology`] message on network actor.
    pub fn update_topology(&self, topology: UpdateTopology) {
        self.update_topology_sender
            .send(topology)
            .expect("Gossiper must accept messages until there is at least one handle to it")
    }
}

/// Actor which gossips peers addresses.
pub struct PeersGossiper {
    /// Peers provided at startup
    initial_peers: BTreeMap<PeerId, SocketAddr>,
    /// Peers received via gossiping from other peers
    /// First-level key corresponds to `SocketAddr`
    /// Second-level key - peer from which such `SocketAddr` was received
    gossip_peers: BTreeMap<PeerId, BTreeMap<PeerId, SocketAddr>>,
    current_topology: BTreeSet<PeerId>,
    network: IrohaNetwork,
}

/// Terminology:
/// * Topology - public keys of current network derived from blockchain (Register/Unregister Peer Isi)
/// * Peers addresses - currently known addresses for peers in topology. Might be unknown for some peer.
///
/// There are three sources of peers addresses:
/// 1. Provided at iroha startup (`TRUSTED_PEERS` env var)
/// 2. Currently connected online peers.
///    Some peer might change address and connect to our peer,
///    such connection will be accepted if peer public key is in topology.
/// 3. Received via gossiping from other peers.
impl PeersGossiper {
    /// Start actor.
    pub fn start(
        trusted_peers: TrustedPeers,
        network: IrohaNetwork,
        shutdown_signal: ShutdownSignal,
    ) -> (PeersGossiperHandle, Child) {
        let initial_peers = trusted_peers
            .others
            .into_iter()
            .map(|peer| (peer.id, peer.address))
            .collect();
        let gossiper = Self {
            initial_peers,
            gossip_peers: BTreeMap::new(),
            current_topology: BTreeSet::new(),
            network,
        };
        gossiper.network_update_peers_addresses();

        let (message_sender, message_receiver) = mpsc::channel(1);
        let (update_topology_sender, update_topology_receiver) = mpsc::unbounded_channel();
        (
            PeersGossiperHandle {
                message_sender,
                update_topology_sender,
            },
            Child::new(
                tokio::task::spawn(gossiper.run(
                    message_receiver,
                    update_topology_receiver,
                    shutdown_signal,
                )),
                OnShutdown::Abort,
            ),
        )
    }

    async fn run(
        mut self,
        mut message_receiver: mpsc::Receiver<(PeersGossip, Peer)>,
        mut update_topology_receiver: mpsc::UnboundedReceiver<UpdateTopology>,
        shutdown_signal: ShutdownSignal,
    ) {
        let mut gossip_period = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                Some(update_topology) = update_topology_receiver.recv() => {
                    self.set_current_topology(update_topology);
                }
                _ = gossip_period.tick() => {
                    self.gossip_peers()
                }
                () = self.network.wait_online_peers_update(|_| ()) => {
                    self.gossip_peers();
                }
                Some((peers_gossip, peer)) = message_receiver.recv() => {
                    self.handle_peers_gossip(peers_gossip, &peer);
                }
                () = shutdown_signal.receive() => {
                    iroha_logger::debug!("Shutting down peers gossiper");
                    break;
                },
            }
            tokio::task::yield_now().await;
        }
    }

    fn set_current_topology(&mut self, UpdateTopology(topology): UpdateTopology) {
        self.gossip_peers.retain(|peer, map| {
            if !topology.contains(peer) {
                return false;
            }

            map.retain(|peer, _| topology.contains(peer));
            !map.is_empty()
        });

        self.current_topology = topology.into_iter().collect();
    }

    fn gossip_peers(&self) {
        let online_peers = self.network.online_peers(Clone::clone);
        let online_peers = UniqueVec::from_iter(online_peers);
        let data = NetworkMessage::PeersGossiper(Box::new(PeersGossip(online_peers)));
        self.network.broadcast(Broadcast { data });
    }

    fn handle_peers_gossip(&mut self, PeersGossip(peers): PeersGossip, from_peer: &Peer) {
        if !self.current_topology.contains(&from_peer.id) {
            return;
        }
        for peer in peers {
            if self.current_topology.contains(&peer.id) {
                let map = self.gossip_peers.entry(peer.id).or_default();
                map.insert(from_peer.id.clone(), peer.address);
            }
        }
        self.network_update_peers_addresses();
    }

    fn network_update_peers_addresses(&self) {
        let online_peers = self.network.online_peers(Clone::clone);
        let online_peers_ids = online_peers
            .into_iter()
            .map(|peer| peer.id)
            .collect::<BTreeSet<_>>();

        let mut peers = Vec::new();
        for (id, address) in &self.initial_peers {
            if !online_peers_ids.contains(id) {
                peers.push((id.clone(), address.clone()));
            }
        }
        for (id, addresses) in &self.gossip_peers {
            if !online_peers_ids.contains(id) {
                peers.push((id.clone(), choose_address_majority_rule(addresses)));
            }
        }

        let update = UpdatePeers(peers);
        self.network.update_peers_addresses(update);
    }
}

fn choose_address_majority_rule(addresses: &BTreeMap<PeerId, SocketAddr>) -> SocketAddr {
    let mut count_map = BTreeMap::new();
    for address in addresses.values() {
        *count_map.entry(address).or_insert(0) += 1;
    }
    count_map
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(address, _)| address)
        .expect("There must be no empty inner map in addresses")
        .clone()
}

/// Message for gossiping peers addresses.
#[derive(Encode, Debug, Clone)]
pub struct PeersGossip(UniqueVec<Peer>);

impl Decode for PeersGossip {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let peers = Vec::<Peer>::decode(input)?;
        let peers_len = peers.len();
        let peers = UniqueVec::from_iter(peers);
        if peers.len() != peers_len {
            Err("Duplicated peers in the gossip message")?;
        }
        Ok(Self(peers))
    }
}
