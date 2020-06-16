//! This module contains functionality related to `Bridge`.

use crate::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

const BRIDGE_ACCOUNT_NAME: &str = "bridge";
const BRIDGE_ASSET_BRIDGE_DEFINITION_PARAMETER_KEY: &str = "bridge_definition";

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

    /// Bridge name.
    pub fn name(&self) -> &str {
        &self.definition_id.name
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

#[inline]
fn bridge_asset_definition_id() -> <AssetDefinition as Identifiable>::Id {
    AssetDefinitionId::new("bridge_asset", "bridge")
}

#[inline]
fn bridge_external_assets_asset_definition_id() -> <AssetDefinition as Identifiable>::Id {
    AssetDefinitionId::new("bridge_external_assets_asset", "bridge")
}

/// This module provides structures for working with external assets.
///
/// # Note
/// `ExternalAsset` is incompatible with Iroha `Asset`.
pub mod asset {
    use super::*;

    /// External asset Identifier.
    pub type Id = String;

    /// A data required for `ExternalAsset` entity initialization.
    #[cfg_attr(test, derive(PartialEq, Eq))]
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct ExternalAsset {
        /// Component Identification.
        pub bridge_id: <Bridge as Identifiable>::Id,
        /// External asset's name in the Iroha.
        pub name: String,
        /// External asset ID.
        pub external_id: Id,
        /// The number of digits that come after the decimal place.
        /// Used in a value representation.
        pub decimals: u8,
    }

    impl Identifiable for ExternalAsset {
        type Id = Id;
    }
}

/// Iroha Special Instructions module provides helper-methods for `Peer` for registering bridges,
/// bridge clients and external assets.
pub mod isi {
    use super::*;
    use crate::account::query::*;
    use crate::bridge::asset::*;
    use crate::isi::prelude::*;
    use crate::query::*;

    impl Peer {
        /// Constructor of Iroha Special Instruction for bridge registration.
        pub fn register_bridge(&self, bridge_definition: &BridgeDefinition) -> Instruction {
            let domain = Domain::new(bridge_definition.id.name.clone());
            let account = Account::new(BRIDGE_ACCOUNT_NAME, &domain.name);
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
                            BRIDGE_ASSET_BRIDGE_DEFINITION_PARAMETER_KEY.to_string(),
                            bridge_definition.encode(),
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

        /// Constructor of Iroha Special Instruction for external asset registration.
        pub fn register_external_asset(&self, external_asset: &ExternalAsset) -> Instruction {
            let domain_id = &external_asset.bridge_id.definition_id.name;
            let account = Account::new(BRIDGE_ACCOUNT_NAME, domain_id);
            let asset_definition = AssetDefinition::new(AssetDefinitionId::new(
                &external_asset.name,
                &external_asset.bridge_id.definition_id.name,
            ));
            Instruction::Sequence(vec![
                Register {
                    object: asset_definition,
                    destination_id: domain_id.clone(),
                }
                .into(),
                Mint {
                    object: (external_asset.name.clone(), external_asset.encode()),
                    destination_id: AssetId {
                        definition_id: bridge_external_assets_asset_definition_id(),
                        account_id: account.id,
                    },
                }
                .into(),
            ])
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::bridge::query::*;
        use crate::peer::PeerId;
        use crate::permission::{permission_asset_definition_id, Permission};
        use std::collections::HashMap;

        const BRIDGE_NAME: &str = "Polkadot";

        struct TestKit {
            world_state_view: WorldStateView,
            root_account_id: <Account as Identifiable>::Id,
        }

        impl TestKit {
            pub fn new() -> Self {
                let domain_name = "Company".to_string();
                let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
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
                    key_pair.public_key.clone(),
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
                let bridge_external_assets_asset_definition_id =
                    bridge_external_assets_asset_definition_id();
                bridge_asset_definitions.insert(
                    bridge_external_assets_asset_definition_id.clone(),
                    AssetDefinition::new(bridge_external_assets_asset_definition_id.clone()),
                );
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
                        public_key: key_pair.public_key,
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
            let bridge_owner_public_key = KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key;
            let bridge_owner_account =
                Account::with_signatory("bridge_owner", "Company", bridge_owner_public_key);
            let bridge_definition = BridgeDefinition {
                id: BridgeDefinitionId::new(BRIDGE_NAME),
                kind: BridgeKind::IClaim,
                owner_account_id: bridge_owner_account.id.clone(),
            };
            let world_state_view = &mut testkit.world_state_view;
            let domain = world_state_view.peer().domains.get_mut("Company").unwrap();
            let register_account = domain.register_account(bridge_owner_account);
            register_account
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register bridge owner account");
            let register_bridge = world_state_view.peer().register_bridge(&bridge_definition);
            register_bridge
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register bridge");
            let bridge_query = query_bridge(BridgeId::new(&bridge_definition.id.name));
            let query_result = bridge_query
                .execute(&world_state_view)
                .expect("failed to query a bridge");
            let decoded_bridge_definition = decode_bridge_definition(&query_result)
                .expect("failed to decode a bridge definition");
            assert_eq!(decoded_bridge_definition, bridge_definition);
        }

        #[test]
        fn test_register_bridge_should_fail_with_account_not_found() {
            let mut testkit = TestKit::new();
            let bridge_owner_public_key = KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key;
            let bridge_owner_account =
                Account::with_signatory("bridge_owner", "Company", bridge_owner_public_key);
            let bridge_definition = BridgeDefinition {
                id: BridgeDefinitionId::new(BRIDGE_NAME),
                kind: BridgeKind::IClaim,
                owner_account_id: bridge_owner_account.id.clone(),
            };
            let world_state_view = &mut testkit.world_state_view;
            let register_bridge = world_state_view.peer().register_bridge(&bridge_definition);
            assert_eq!(
                register_bridge
                    .execute(testkit.root_account_id.clone(), world_state_view)
                    .unwrap_err(),
                "Account not found."
            );
        }

        #[test]
        fn test_register_external_asset_should_pass() {
            let mut testkit = TestKit::new();
            let bridge_owner_public_key = KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key;
            let bridge_owner_account =
                Account::with_signatory("bridge_owner", "Company", bridge_owner_public_key);
            let bridge_definition = BridgeDefinition {
                id: BridgeDefinitionId::new(BRIDGE_NAME),
                kind: BridgeKind::IClaim,
                owner_account_id: bridge_owner_account.id.clone(),
            };
            let world_state_view = &mut testkit.world_state_view;
            let domain = world_state_view.peer().domains.get_mut("Company").unwrap();
            domain
                .register_account(bridge_owner_account)
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register bridge owner account");
            world_state_view
                .peer()
                .register_bridge(&bridge_definition)
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register bridge");
            let external_asset = ExternalAsset {
                bridge_id: BridgeId::new(&bridge_definition.id.name),
                name: "DOT Token".to_string(),
                external_id: "DOT".to_string(),
                decimals: 12,
            };
            let register_external_asset = world_state_view
                .peer()
                .register_external_asset(&external_asset);
            register_external_asset
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register external asset");
            let bridge_query = query_bridge(BridgeId::new(&bridge_definition.id.name));
            let query_result = bridge_query
                .execute(&world_state_view)
                .expect("failed to query a bridge");
            let decoded_external_asset = decode_external_asset(&query_result, &external_asset.name)
                .expect("failed to decode an external asset");
            assert_eq!(decoded_external_asset, external_asset);
        }
    }
}

/// Query module provides functions for constructing bridge-related queries
/// and decoding the query results.
pub mod query {
    use super::asset::*;
    use super::*;
    use crate::query::*;

    /// Constructor of Iroha Query for retrieving information about the bridge.
    pub fn query_bridge(bridge_id: <Bridge as Identifiable>::Id) -> IrohaQuery {
        crate::asset::query::GetAccountAssets::build_request(AccountId::new(
            BRIDGE_ACCOUNT_NAME,
            bridge_id.name(),
        ))
        .query
    }

    /// A helper function for decoding bridge definition from the query result.
    ///
    /// The `BridgeDefinition` is encoded and stored in the bridge asset
    /// (`bridge_asset_definition_id`) store under the
    /// `BRIDGE_ASSET_BRIDGE_DEFINITION_PARAMETER_KEY` key. The given query result may not
    /// contain the above values, so this function can fail, returning `None`.
    pub fn decode_bridge_definition(query_result: &QueryResult) -> Option<BridgeDefinition> {
        let account_assets_result = match query_result {
            QueryResult::GetAccountAssets(v) => v,
            _ => return None,
        };
        account_assets_result
            .assets
            .iter()
            .filter(|asset| asset.id.definition_id == bridge_asset_definition_id())
            .filter_map(|asset| {
                asset
                    .store
                    .get(BRIDGE_ASSET_BRIDGE_DEFINITION_PARAMETER_KEY)
                    .cloned()
            })
            .filter_map(|data| BridgeDefinition::decode(&mut data.as_slice()).ok())
            .next()
    }

    /// A helper function for decoding information about external asset from the query result.
    ///
    /// Each `ExternalAsset` is encoded and stored in the bridge external assets asset
    /// (`bridge_external_assets_asset_definition_id`) store and indexed by a name of the asset.
    /// The given query result may not contain the above values, so this function can fail,
    /// returning `None`.
    pub fn decode_external_asset(
        query_result: &QueryResult,
        asset_name: &str,
    ) -> Option<ExternalAsset> {
        let account_assets_result = match query_result {
            QueryResult::GetAccountAssets(v) => v,
            _ => return None,
        };
        account_assets_result
            .assets
            .iter()
            .filter(|asset| asset.id.definition_id == bridge_external_assets_asset_definition_id())
            .filter_map(|asset| asset.store.get(asset_name).cloned())
            .filter_map(|data| ExternalAsset::decode(&mut data.as_slice()).ok())
            .next()
    }
}
