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
    wsv::WorldStateView,
};
use futures::channel::mpsc;

pub struct Iroha {
    torii: Torii,
}

impl Iroha {
    pub fn new(config: Configuration) -> Self {
        let (tx, rx) = mpsc::unbounded();
        let world_state_view = WorldStateView::new(rx);
        let torii = Torii::new(
            &config.torii_url,
            Sumeragi::new(Blockchain::new(Kura::new(config.mode, tx))),
            world_state_view,
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
        isi::{Id, Instruction},
        peer::Peer,
        tx::Transaction,
        wsv::WorldStateView,
        Iroha,
    };
}
