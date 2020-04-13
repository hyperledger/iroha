pub mod account;
pub mod asset;
pub mod block;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod isi;
mod kura;
mod merkle;
pub mod peer;
pub mod query;
mod queue;
mod sumeragi;
pub mod torii;
pub mod tx;
pub mod wsv;

use crate::{
    block::Blockchain, config::Configuration, kura::Kura, sumeragi::Sumeragi, torii::Torii,
    wsv::World,
};
use futures::channel::mpsc;
use parity_scale_codec::{Decode, Encode};
use std::path::Path;

pub struct Iroha {
    torii: Torii,
}

impl Iroha {
    pub fn new(config: Configuration) -> Self {
        let (tx, rx) = mpsc::unbounded();
        let world = World::new(rx);
        let torii = Torii::new(
            &config.torii_url,
            Sumeragi::new(),
            Blockchain::new(Kura::new(
                config.mode,
                Path::new(&config.kura_block_store_path),
                tx,
            )),
            world,
        );
        Iroha { torii }
    }

    pub async fn start(&mut self) -> Result<(), String> {
        self.torii.start().await;
        Ok(())
    }
}

/// Identification of an Iroha's entites. Consists of Entity's name and Domain's name.
///
/// # Example
///
/// ```
/// use iroha::Id;
///
/// let id = Id::new("gold", "mine");
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, std::hash::Hash, Encode, Decode)]
pub struct Id {
    pub entity_name: String,
    pub domain_name: String,
}

impl Id {
    pub fn new(entity_name: &str, domain_name: &str) -> Self {
        Id {
            entity_name: entity_name.to_string(),
            domain_name: domain_name.to_string(),
        }
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.

    #[doc(inline)]
    pub use crate::{
        account::Account,
        asset::Asset,
        block::Block,
        config::Configuration,
        crypto::{Hash, Signature},
        domain::Domain,
        isi::{Contract, Instruction},
        peer::Peer,
        query::{Query, QueryResult, Request},
        tx::Transaction,
        wsv::WorldStateView,
        Id, Iroha,
    };
}
