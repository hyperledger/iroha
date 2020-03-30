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
};

pub struct Iroha {
    torii: Torii,
}

impl Iroha {
    pub async fn new(config: Configuration) -> Result<Self, &'static str> {
        let kura = if &config.mode == "strict" {
            Kura::strict_init().await?
        } else {
            Kura::fast_init().await
        };
        Ok(Iroha {
            torii: Torii::new(&config.torii_url, Sumeragi::new(Blockchain::new(kura))),
        })
    }

    pub async fn start(&mut self) {
        self.torii.start().await;
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
        isi::Id,
        peer::Peer,
        tx::Transaction,
        Iroha,
    };
}
