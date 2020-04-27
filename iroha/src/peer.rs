use crate::prelude::*;
use crate::sumeragi;
use iroha_derive::*;
use parity_scale_codec::{Decode, Encode};
use std::collections::HashSet;

type PublicKey = [u8; 32];

#[derive(Io, Decode, Encode, Debug, Clone)]
pub enum Message {
    SumeragiMessage(sumeragi::Message),
}

#[derive(Encode, Decode, PartialEq, Eq, Debug, Clone, Hash, Io)]
pub struct PeerId {
    pub address: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub peers: HashSet<PeerId>,
    pub listen_address: String,
}

impl Peer {
    pub fn new(listen_address: String, trusted_peers: &[PeerId]) -> Peer {
        Peer {
            peers: trusted_peers
                .iter()
                .filter(|peer_id| listen_address != peer_id.address)
                .cloned()
                .collect(),
            listen_address,
        }
    }
}

pub mod isi {
    use super::*;

    /// The purpose of add peer command is to write into ledger the fact of peer addition into the
    /// peer network. After a transaction with AddPeer has been committed, consensus and
    /// synchronization components will start using it.
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct AddPeer {
        pub peer_id: PeerId,
    }

    impl Instruction for AddPeer {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            world_state_view.peer().peers.insert(self.peer_id.clone());
            Ok(())
        }
    }
}
