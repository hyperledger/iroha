pub mod account;
pub mod asset;
pub mod block;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod isi;
mod kura;
pub mod peer;
pub mod query;
mod queue;
mod sumeragi;
pub mod torii;
pub mod tx;
pub mod validation;
pub mod wsv;

use crate::{
    block::Blockchain, config::Configuration, kura::Kura, sumeragi::Sumeragi, torii::Torii,
    wsv::World,
};
use futures::channel::mpsc;
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
            Sumeragi::new(Blockchain::new(Kura::new(
                config.mode,
                Path::new(&config.kura_block_store_path),
                tx,
            ))),
            world,
        );
        Iroha { torii }
    }

    pub async fn start(&mut self) -> Result<(), String> {
        self.torii.start().await;
        Ok(())
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
        isi::{Contract, Id, Instruction},
        peer::Peer,
        query::{Query, QueryResult, Request},
        tx::Transaction,
        wsv::WorldStateView,
        Iroha,
    };
}
