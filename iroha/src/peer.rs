use crate::isi::Contract;
use parity_scale_codec::{Decode, Encode};

type PublicKey = [u8; 32];

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct Peer {
    pub address: String,
    pub peer_key: PublicKey,
}

pub mod isi {
    use super::*;
    use iroha_derive::{IntoContract, Io};

    /// The purpose of add peer command is to write into ledger the fact of peer addition into the
    /// peer network. After a transaction with AddPeer has been committed, consensus and
    /// synchronization components will start using it.
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct AddPeer {
        pub peer: Peer,
    }
}
