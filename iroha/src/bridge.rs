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
            let domain = Domain::new(bridge_definition.id.name.clone());
            let account = Account::new("bridge", &domain.name);
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
                Some(Box::new(Instruction::Fail(
                    "Account not found.".to_string(),
                ))),
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::peer::PeerId;
        use crate::permission::{permission_asset_definition_id, Permission};
        use std::collections::HashMap;

        struct TestKit {
            world_state_view: WorldStateView,
            root_account_id: <Account as Identifiable>::Id,
        }

        impl TestKit {
            pub fn new() -> Self {
                let domain_name = "Company".to_string();
                let public_key = [1; 32];
                let mut asset_definitions = HashMap::new();
                let asset_definition_id = permission_asset_definition_id();
                asset_definitions.insert(
                    asset_definition_id.clone(),
                    AssetDefinition::new(asset_definition_id.clone()),
                );
                let account_id = AccountId::new("root", &domain_name);
                let asset_id = AssetId {
                    definition_id: asset_definition_id,
                    account_id: account_id.clone(),
                };
                let asset = Asset::with_permission(asset_id.clone(), Permission::Anything);
                let mut account = Account::with_signatory(
                    &account_id.name,
                    &account_id.domain_name,
                    public_key.clone(),
                );
                account.assets.insert(asset_id.clone(), asset);
                let mut accounts = HashMap::new();
                accounts.insert(account_id.clone(), account);
                let domain = Domain {
                    name: domain_name.clone(),
                    accounts,
                    asset_definitions,
                };
                let bridge_domain_name = "bridge".to_string();
                let mut bridge_asset_definitions = HashMap::new();
                let bridge_asset_definition_id = bridge_asset_definition_id();
                bridge_asset_definitions.insert(
                    bridge_asset_definition_id.clone(),
                    AssetDefinition::new(bridge_asset_definition_id.clone()),
                );
                let bridge_asset_id = AssetId {
                    definition_id: bridge_asset_definition_id,
                    account_id: account_id.clone(),
                };
                let bridge_domain = Domain {
                    name: bridge_domain_name.clone(),
                    accounts: HashMap::new(),
                    asset_definitions: bridge_asset_definitions,
                };
                let mut domains = HashMap::new();
                domains.insert(domain_name.clone(), domain);
                domains.insert(bridge_domain_name.clone(), bridge_domain);
                let address = "127.0.0.1:8080".to_string();
                let world_state_view = WorldStateView::new(Peer::with_domains(
                    PeerId {
                        address: address.clone(),
                        public_key,
                    },
                    &Vec::new(),
                    domains,
                ));
                TestKit {
                    world_state_view,
                    root_account_id: account_id,
                }
            }
        }

        #[test]
        fn test_register_bridge_test_should_pass() {
            let mut testkit = TestKit::new();
            let bridge_owner_public_key = [2; 32];
            let bridge_owner_account =
                Account::with_signatory("bridge_owner", "Company", bridge_owner_public_key);
            let bridge_definition = BridgeDefinition {
                id: BridgeDefinitionId::new("Polkadot"),
                kind: BridgeKind::IClaim,
                owner_account_id: bridge_owner_account.id.clone(),
            };
            let world_state_view = &mut testkit.world_state_view;
            let domain = world_state_view.peer().domains.get_mut("Company").unwrap();
            let register_account = domain.register_account(bridge_owner_account);
            register_account
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register bridge owner account");
            let register_bridge = world_state_view.peer().register_bridge(bridge_definition);
            register_bridge
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register bridge");
        }

        #[test]
        fn test_register_bridge_should_fail_with_account_not_found() {
            let mut testkit = TestKit::new();
            let bridge_owner_public_key = [3; 32];
            let bridge_owner_account =
                Account::with_signatory("bridge_owner", "Company", bridge_owner_public_key);
            let bridge_definition = BridgeDefinition {
                id: BridgeDefinitionId::new("Polkadot"),
                kind: BridgeKind::IClaim,
                owner_account_id: bridge_owner_account.id.clone(),
            };
            let world_state_view = &mut testkit.world_state_view;
            let register_bridge = world_state_view.peer().register_bridge(bridge_definition);
            assert_eq!(
                register_bridge
                    .execute(testkit.root_account_id.clone(), world_state_view)
                    .unwrap_err(),
                "Account not found."
            );
        }
    }
}
