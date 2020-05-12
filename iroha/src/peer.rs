use crate::prelude::*;
use iroha_derive::*;
use parity_scale_codec::{Decode, Encode};
use std::collections::{HashMap, HashSet};

type PublicKey = [u8; 32];

#[derive(Encode, Decode, PartialEq, Eq, Debug, Clone, Hash, Io)]
pub struct PeerId {
    pub address: String,
    pub public_key: PublicKey,
}

impl PeerId {
    pub fn current() -> PeerId {
        PeerId {
            address: "Self".to_string(),
            public_key: [0; 32],
        }
    }
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub peers: HashSet<PeerId>,
    pub listen_address: String,
    pub domains: HashMap<String, Domain>,
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
            domains: HashMap::new(),
        }
    }
}

impl Identifiable for Peer {
    type Id = PeerId;
}

pub mod isi {
    use super::*;
    use crate::isi::Add;
    use std::ops::{AddAssign, Sub};

    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum PeerInstruction {
        AddDomain(String, PeerId),
    }

    impl PeerInstruction {
        pub fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            match self {
                PeerInstruction::AddDomain(domain_name, peer_id) => {
                    Add::new(Domain::new(domain_name.to_string()), peer_id.clone())
                        .execute(world_state_view)
                }
            }
        }
    }

    impl AddAssign<Domain> for Peer {
        fn add_assign(&mut self, domain: Domain) {
            self.domains.insert(domain.name.clone(), domain);
        }
    }

    impl Add<Peer, Domain> {
        pub fn execute(self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            *world_state_view.peer() += self.object;
            Ok(())
        }
    }

    impl From<Add<Peer, Domain>> for Instruction {
        fn from(add_instruction: Add<Peer, Domain>) -> Self {
            Instruction::Peer(PeerInstruction::AddDomain(
                add_instruction.object.name,
                add_instruction.destination_id,
            ))
        }
    }

    impl Sub<Domain> for Peer {
        type Output = Self;

        fn sub(mut self, domain: Domain) -> Self {
            self.domains.remove(&domain.name);
            self
        }
    }
}
