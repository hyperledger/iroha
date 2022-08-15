//! Iroha - A simple, enterprise-grade decentralized ledger.

pub mod block;
pub mod block_sync;
pub mod genesis;
pub mod kura;
pub mod modules;
pub mod queue;
pub mod smartcontracts;
pub mod sumeragi;
pub mod tx;
pub mod validator;
pub mod wsv;

use core::time::Duration;

use dashmap::{DashMap, DashSet};
use iroha_data_model::prelude::*;
use parity_scale_codec::{Decode, Encode};
use tokio::sync::broadcast;

use crate::{
    block_sync::message::VersionedMessage as BlockSyncMessage, prelude::*,
    sumeragi::message::VersionedMessage as SumeragiMessage,
};

/// The interval at which sumeragi checks if there are tx in the `queue`.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(100);

/// Specialized type of Iroha Network
pub type IrohaNetwork = iroha_p2p::Network<NetworkMessage>;

/// Ids of peers.
pub type PeersIds = DashSet<<Peer as Identifiable>::Id>;

/// Provides an API to work with collection of key([`DomainId`]) - value([`Domain`]) pairs.
pub type DomainsMap = DashMap<<Domain as Identifiable>::Id, Domain>;

/// `RolesMap` provides an API to work with a collection of key(`RoleId`) - value(`Role`) pairs.
pub type RolesMap = DashMap<<Role as Identifiable>::Id, Role>;

/// `PermissionTokensMap` provides an API to work with a collection of key(`AccountId`) - value(`Set<PermissionToken>`) pairs.
pub type PermissionTokensMap = DashMap<<Account as Identifiable>::Id, Permissions>;

/// `PermissionTokenDefinitionsMap` provides an API to work with a collection of key(`PermissionTokenDefinitionId`) - value(`PermissionTokenDefinition`) pairs.
pub type PermissionTokenDefinitionsMap =
    DashMap<<PermissionTokenDefinition as Identifiable>::Id, PermissionTokenDefinition>;

/// Type of `Sender<Event>` which should be used for channels of `Event` messages.
pub type EventsSender = broadcast::Sender<Event>;
/// Type of `Receiver<Event>` which should be used for channels of `Event` messages.
pub type EventsReceiver = broadcast::Receiver<Event>;

/// Send `event` and log error if failure occurred.
fn send_event(events_sender: &EventsSender, event: Event) {
    if let Err(error) = events_sender.send(event) {
        iroha_logger::debug!(%error, event = ?error.0, "Failed send event");
    }
}

/// The network message
#[derive(Clone, Debug, Encode, Decode, iroha_actor::Message)]
pub enum NetworkMessage {
    /// Blockchain message
    SumeragiMessage(Box<SumeragiMessage>),
    /// Block sync message
    BlockSync(Box<BlockSyncMessage>),
    /// Health check message
    Health,
}

/// Check to see if the given item was included in the blockchain.
pub trait IsInBlockchain {
    /// Checks if this item has already been committed or rejected.
    fn is_in_blockchain(&self, wsv: &WorldStateView) -> bool;
}

/// Module constaining [`ThreadHandler`]
pub mod handler {
    #![allow(clippy::expect_used)]
    use std::thread::JoinHandle;

    /// Call shutdown function and join thread on drop
    pub struct ThreadHandler {
        /// Shutdown function: after calling it, the thread must terminate in finite amount of time
        shutdown: Option<Box<dyn FnOnce() + Send>>,
        handle: Option<JoinHandle<()>>,
    }

    impl ThreadHandler {
        /// Create new [`Self`]
        pub fn new(shutdown: Box<dyn FnOnce() + Send>, handle: JoinHandle<()>) -> Self {
            Self {
                shutdown: Some(shutdown),
                handle: Some(handle),
            }
        }
    }

    impl Drop for ThreadHandler {
        fn drop(&mut self) {
            (self.shutdown.take().expect("Always some after init"))();
            let handle = self.handle.take().expect("Always some after init");
            let _joined = handle.join();
        }
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.

    #[doc(inline)]
    pub use iroha_crypto::{Algorithm, Hash, KeyPair, PrivateKey, PublicKey};

    #[doc(inline)]
    pub use crate::{
        block::{
            CommittedBlock, PendingBlock, ValidBlock, VersionedCommittedBlock, VersionedValidBlock,
            DEFAULT_CONSENSUS_ESTIMATION_MS,
        },
        smartcontracts::permissions::prelude::*,
        smartcontracts::ValidQuery,
        tx::{
            AcceptedTransaction, ValidTransaction, VersionedAcceptedTransaction,
            VersionedValidTransaction,
        },
        wsv::{World, WorldStateView},
        IsInBlockchain,
    };
}
