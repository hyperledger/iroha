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

fn owner_asset_definition_id() -> <AssetDefinition as Identifiable>::Id {
    AssetDefinitionId::new("owner_asset", "bridge")
}

fn bridge_asset_definition_id() -> <AssetDefinition as Identifiable>::Id {
    AssetDefinitionId::new("bridge_asset", "bridge")
}

/// Iroha Special Instructions module provides extensions for `Peer` structure and an
/// implementation of the generic `Register` Iroha Special Instruction for `Bridge` registration.
pub mod isi {
    use super::*;
    use crate::{account::query::*, isi::prelude::*, query::*};

    impl Peer {
        /// Constructor of `Register<Peer, BridgeDefinition>` Iroha Special Instruction.
        pub fn register_bridge(&self, bridge_definition: BridgeDefinition) -> Instruction {
            let seed = crate::crypto::hash(bridge_definition.encode());
            let public_key = crate::crypto::generate_key_pair_from_seed(seed)
                .expect("Failed to generate key pair.")
                .0;
            let domain = Domain::new(bridge_definition.id.name.clone());
            let account = Account::new("bridge", &domain.name, public_key);
            Instruction::If(
                Box::new(Instruction::ExecuteQuery(IrohaQuery::GetAccount(
                    GetAccount {
                        account_id: bridge_definition.owner_account_id.clone(),
                    },
                ))),
                Box::new(Instruction::Sequence(vec![
                    Add {
                        object: domain.clone(),
                        destination_id: self.id.clone(),
                    }
                    .into(),
                    Register {
                        object: account.clone(),
                        destination_id: domain.name,
                    }
                    .into(),
                    Mint {
                        object: (
                            "owner_id".to_string(),
                            bridge_definition.owner_account_id.to_string(),
                        ),
                        destination_id: AssetId {
                            definition_id: owner_asset_definition_id(),
                            account_id: account.id.clone(),
                        },
                    }
                    .into(),
                    Mint {
                        object: (
                            "bridge_definition".to_string(),
                            format!("{:?}", bridge_definition.encode()),
                        ),
                        destination_id: AssetId {
                            definition_id: bridge_asset_definition_id(),
                            account_id: account.id,
                        },
                    }
                    .into(),
                ])),
                None,
            )
        }
    }
}
