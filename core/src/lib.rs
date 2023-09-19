//! Iroha — A simple, enterprise-grade decentralized ledger.

pub mod block;
pub mod block_sync;
pub mod gossiper;
pub mod kura;
pub mod modules;
pub mod queue;
pub mod smartcontracts;
pub mod snapshot;
pub mod sumeragi;
pub mod tx;
pub mod validator;
pub mod wsv;

use core::time::Duration;
use std::collections::{HashMap, HashSet};

use gossiper::TransactionGossip;
use iroha_data_model::{permission::Permissions, prelude::*};
use parity_scale_codec::{Decode, Encode};
use tokio::sync::broadcast;

use crate::{
    block_sync::message::Message as BlockSyncMessage, prelude::*,
    sumeragi::message::MessagePacket as SumeragiPacket,
};

/// The interval at which sumeragi checks if there are tx in the `queue`.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(100);

/// Specialized type of Iroha Network
pub type IrohaNetwork = iroha_p2p::NetworkHandle<NetworkMessage>;

/// Ids of peers.
pub type PeersIds = HashSet<PeerId>;

/// Parameters set.
pub type Parameters = HashSet<Parameter>;

/// API to work with collections of [`DomainId`] : [`Domain`] mappings.
pub type DomainsMap = HashMap<DomainId, Domain>;

/// API to work with a collections of [`RoleId`]: [`Role`] mappings.
pub type RolesMap = HashMap<RoleId, Role>;

/// API to work with a collections of [`AccountId`] [`Permissions`] mappings.
pub type PermissionTokensMap = HashMap<AccountId, Permissions>;

/// Type of `Sender<Event>` which should be used for channels of `Event` messages.
pub type EventsSender = broadcast::Sender<Event>;

/// The network message
#[derive(Clone, Debug, Encode, Decode)]
pub enum NetworkMessage {
    /// Blockchain message
    SumeragiPacket(Box<SumeragiPacket>),
    /// Block sync message
    BlockSync(Box<BlockSyncMessage>),
    /// Transaction gossiper message
    TransactionGossiper(Box<TransactionGossip>),
    /// Health check message
    Health,
}

pub mod handler {
    //! General purpose thread handler. It is responsible for RAII for
    //! threads started for Kura, Sumeragi and other core routines.
    use std::thread::JoinHandle;

    /// Call shutdown function and join thread on drop
    pub struct ThreadHandler {
        /// Shutdown function: after calling it, the thread must terminate in finite amount of time
        shutdown: Option<Box<dyn FnOnce() + Send + Sync>>,
        handle: Option<JoinHandle<()>>,
    }

    impl ThreadHandler {
        /// [`Self`] constructor
        #[must_use]
        #[inline]
        pub fn new(shutdown: Box<dyn FnOnce() + Send + Sync>, handle: JoinHandle<()>) -> Self {
            Self {
                shutdown: Some(shutdown),
                handle: Some(handle),
            }
        }
    }

    impl Drop for ThreadHandler {
        /// Join on drop to ensure that the thread is properly shut down.
        fn drop(&mut self) {
            (self.shutdown.take().expect("Always some after init"))();
            let handle = self.handle.take().expect("Always some after init");

            if let Err(error) = handle.join() {
                iroha_logger::error!(?error, "Fatal error: thread panicked");
            }
        }
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.

    #[doc(inline)]
    pub use iroha_crypto::{Algorithm, Hash, KeyPair, PrivateKey, PublicKey};

    #[doc(inline)]
    pub use crate::{
        smartcontracts::ValidQuery,
        tx::AcceptedTransaction,
        wsv::{World, WorldStateView},
    };
}
