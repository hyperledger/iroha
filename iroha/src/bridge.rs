//! This module contains functionality related to `Bridge`.

use crate::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

/// Enumeration of all supported bridge kinds (types). Each variant represents some communication
/// protocol between blockchains which can be used within Iroha.
#[derive(Encode, Decode, PartialEq, Eq, Debug, Clone, Copy, Hash, Io)]
pub enum BridgeKind {
    /// XClaim-like protocol.
    IClaim,
}

/// Identification of a Bridge definition. Consists of Bridge's name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Encode, Decode)]
pub struct BridgeDefinitionId {
    /// Bridge's name.
    pub name: String,
}

impl BridgeDefinitionId {
    /// Default Bridge definition identifier constructor.
    pub fn new(name: &str) -> Self {
        BridgeDefinitionId {
            name: name.to_owned(),
        }
    }
}

/// A data required for `Bridge` entity initialization.
#[derive(Encode, Decode, PartialEq, Eq, Debug, Clone, Hash, Io)]
pub struct BridgeDefinition {
    /// An Identification of the `BridgeDefinition`.
    pub id: <BridgeDefinition as Identifiable>::Id,
    /// Bridge's kind (type).
    pub kind: BridgeKind,
    /// Bridge owner's account Identification. Only this account will be able to manipulate the bridge.
    pub owner_account_id: <Account as Identifiable>::Id,
}

impl Identifiable for BridgeDefinition {
    type Id = BridgeDefinitionId;
}

/// Identification of a Bridge. Consists of Bridge's definition Identification.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Encode, Decode)]
pub struct BridgeId {
    /// Entity Identification.
    definition_id: <BridgeDefinition as Identifiable>::Id,
}

impl BridgeId {
    /// Default Bridge identifier constructor.
    pub fn new(name: &str) -> Self {
        BridgeId {
            definition_id: BridgeDefinitionId::new(name),
        }
    }
}

/// An entity used for performing operations between Iroha and third-party blockchain.
#[derive(Debug, Clone)]
pub struct Bridge {
    /// Component Identification.
    id: <Bridge as Identifiable>::Id,
    /// Bridge's account ID.
    account_id: <Account as Identifiable>::Id,
}

impl Bridge {
    /// Default `Bridge` entity constructor.
    pub fn new(
        id: <Bridge as Identifiable>::Id,
        account_id: <Account as Identifiable>::Id,
    ) -> Self {
        Bridge { id, account_id }
    }

    /// A helper function for returning Bridge's name.
    pub fn name(&self) -> &str {
        &self.id.definition_id.name
    }
}

impl Identifiable for Bridge {
    type Id = BridgeId;
}

/// Iroha Special Instructions module provides extensions for `Peer` structure and an
/// implementation of the generic `Register` Iroha Special Instruction for `Bridge` registration.
pub mod isi {
    use super::*;
    use crate::isi::prelude::*;

    impl Peer {
        /// Constructor of `Register<Peer, BridgeDefinition>` Iroha Special Instruction.
        pub fn register_bridge(
            &self,
            object: BridgeDefinition,
        ) -> Register<Peer, BridgeDefinition> {
            Register {
                object,
                destination_id: self.id.clone(),
            }
        }
    }

    impl Register<Peer, BridgeDefinition> {
        /// Registers the `Bridge` by its definition on the given `WorldStateView`.
        ///
        /// Adds a `Domain` with the same name as in the `BridgeDefinition`, then registers an
        /// account with default name "bridge" and a public key generated from a seed, and finally
        /// constructs a `Bridge` entity from that data.
        pub(crate) fn execute(self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            let bridge_definition = self.object;
            let _owner_account = world_state_view
                .account(&bridge_definition.owner_account_id)
                .cloned()
                .ok_or("Account not found.")?;
            let seed = crate::crypto::hash(bridge_definition.encode());
            let public_key = crate::crypto::generate_key_pair_from_seed(seed)?.0;
            let domain = Domain::new(bridge_definition.id.name.clone());
            let account = Account::new("bridge", &bridge_definition.id.name, public_key);
            world_state_view
                .peer()
                .add_domain(domain.clone())
                .execute(bridge_definition.owner_account_id.clone(), world_state_view)?;
            domain
                .register_account(account.clone())
                .execute(bridge_definition.owner_account_id, world_state_view)?;
            let bridge_id = BridgeId::new(&bridge_definition.id.name);
            let bridge = Bridge::new(bridge_id, account.id);
            world_state_view.add_bridge(bridge);
            Ok(())
        }
    }

    impl From<Register<Peer, BridgeDefinition>> for Instruction {
        fn from(reg_instruction: Register<Peer, BridgeDefinition>) -> Self {
            Instruction::Peer(PeerInstruction::RegisterBridge(
                reg_instruction.object,
                reg_instruction.destination_id,
            ))
        }
    }
}

/// Iroha World State View module provides extensions for the `WorldStateView` for adding and
/// retrieving `Bridge` entities.
pub mod wsv {
    use super::*;

    impl WorldStateView {
        /// Add new `Bridge` entity.
        pub fn add_bridge(&mut self, bridge: Bridge) {
            self.peer().bridges.insert(bridge.name().to_owned(), bridge);
        }

        /// Get `Bridge` without an ability to modify it.
        pub fn read_bridge(&self, name: &str) -> Option<&Bridge> {
            self.read_peer().bridges.get(name)
        }

        /// Get `Bridge` with an ability to modify it.
        pub fn bridge(&mut self, name: &str) -> Option<&mut Bridge> {
            self.peer().bridges.get_mut(name)
        }
    }
}
