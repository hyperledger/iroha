//! Iroha — A simple, enterprise-grade decentralized ledger.

pub mod block;
pub mod block_sync;
pub mod executor;
pub mod gossiper;
pub mod kiso;
pub mod kura;
pub mod metrics;
pub mod query;
pub mod queue;
pub mod smartcontracts;
pub mod snapshot;
pub mod state;
pub mod sumeragi;
pub mod tx;

use core::time::Duration;

use gossiper::TransactionGossip;
use indexmap::IndexSet;
use iroha_data_model::{events::EventBox, prelude::*};
use iroha_primitives::unique_vec::UniqueVec;
use parity_scale_codec::{Decode, Encode};
use tokio::sync::broadcast;

use crate::{
    block_sync::message::Message as BlockSyncMessage,
    prelude::*,
    sumeragi::message::{BlockMessage, ControlFlowMessage},
};

/// The interval at which sumeragi checks if there are tx in the `queue`.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(100);

/// Specialized type of Iroha Network
pub type IrohaNetwork = iroha_p2p::NetworkHandle<NetworkMessage>;

/// Ids of peers.
pub type PeersIds = UniqueVec<PeerId>;

/// Parameters set.
pub type Parameters = IndexSet<Parameter>;

/// Type of `Sender<EventBox>` which should be used for channels of `Event` messages.
pub type EventsSender = broadcast::Sender<EventBox>;

/// The network message
#[derive(Clone, Debug, Encode, Decode)]
pub enum NetworkMessage {
    /// Blockchain concensus data message
    SumeragiBlock(Box<BlockMessage>),
    /// Blockchain concensus control flow message
    SumeragiControlFlow(Box<ControlFlowMessage>),
    /// Block sync message
    BlockSync(Box<BlockSyncMessage>),
    /// Transaction gossiper message
    TransactionGossiper(Box<TransactionGossip>),
    /// Health check message
    Health,
}

pub mod role {
    //! Module with extension for [`RoleId`] to be stored inside state.

    use derive_more::Constructor;
    use iroha_primitives::impl_as_dyn_key;
    use serde::{Deserialize, Serialize};

    use super::*;

    /// [`RoleId`] with owner [`AccountId`] attached to it.
    #[derive(
        Debug,
        Clone,
        Constructor,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
    )]
    pub struct RoleIdWithOwner {
        /// [`AccountId`] of the owner.
        pub account: AccountId,
        /// [`RoleId`]  of the given role.
        pub id: RoleId,
    }

    /// Reference to [`RoleIdWithOwner`].
    #[derive(Debug, Clone, Copy, Constructor, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct RoleIdWithOwnerRef<'role> {
        /// [`AccountId`] of the owner.
        pub account: &'role AccountId,
        /// [`RoleId`]  of the given role.
        pub role: &'role RoleId,
    }

    impl AsRoleIdWithOwnerRef for RoleIdWithOwner {
        fn as_key(&self) -> RoleIdWithOwnerRef<'_> {
            RoleIdWithOwnerRef {
                account: &self.account,
                role: &self.id,
            }
        }
    }

    impl_as_dyn_key! {
        target: RoleIdWithOwner,
        key: RoleIdWithOwnerRef<'_>,
        trait: AsRoleIdWithOwnerRef
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.

    #[doc(inline)]
    pub use iroha_crypto::{Algorithm, Hash, KeyPair, PrivateKey, PublicKey};

    #[doc(inline)]
    pub use crate::{
        smartcontracts::ValidQuery,
        state::{StateReadOnly, StateView, World, WorldReadOnly},
        tx::AcceptedTransaction,
    };
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use iroha_data_model::role::RoleId;
    use test_samples::gen_account_in;

    use crate::role::RoleIdWithOwner;

    #[test]
    fn cmp_role_id_with_owner() {
        let role_id_a: RoleId = "a".parse().expect("failed to parse RoleId");
        let role_id_b: RoleId = "b".parse().expect("failed to parse RoleId");
        let (account_id_a, _account_keypair_a) = gen_account_in("domain");
        let (account_id_b, _account_keypair_b) = gen_account_in("domain");

        let mut role_ids_with_owner = Vec::new();
        for account_id in [&account_id_a, &account_id_b] {
            for role_id in [&role_id_a, &role_id_b] {
                role_ids_with_owner.push(RoleIdWithOwner {
                    id: role_id.clone(),
                    account: account_id.clone(),
                })
            }
        }

        for role_id_with_owner_1 in &role_ids_with_owner {
            for role_id_with_owner_2 in &role_ids_with_owner {
                match (
                    role_id_with_owner_1.account.cmp(&role_id_with_owner_2.account),
                    role_id_with_owner_1.id.cmp(&role_id_with_owner_2.id),
                ) {
                    // `AccountId` take precedence in comparison
                    // if `AccountId`s are equal than comparison based on `RoleId`s
                    (Ordering::Equal, ordering) | (ordering, _) => assert_eq!(
                        role_id_with_owner_1.cmp(role_id_with_owner_2),
                        ordering,
                        "{role_id_with_owner_1:?} and {role_id_with_owner_2:?} are expected to be {ordering:?}"
                    ),
                }
            }
        }
    }
}
