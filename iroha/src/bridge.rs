//! This module contains functionality related to `Bridge`.

use crate::asset::Bytes;
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

/// An entity used for storing data of any third-party transaction.
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug, Encode, Decode)]
pub struct ExternalTransaction {
    /// External transaction identifier. Not always can be calculated from the `payload`.
    pub hash: String,
    /// External transaction payload.
    pub payload: Bytes,
}

#[inline]
fn bridges_asset_definition_id() -> <AssetDefinition as Identifiable>::Id {
    AssetDefinitionId::new("bridges_asset", "bridge")
}

#[inline]
fn bridge_asset_definition_id() -> <AssetDefinition as Identifiable>::Id {
    AssetDefinitionId::new("bridge_asset", "bridge")
}

#[inline]
fn bridge_external_assets_asset_definition_id() -> <AssetDefinition as Identifiable>::Id {
    AssetDefinitionId::new("bridge_external_assets_asset", "bridge")
}

#[inline]
fn bridge_incoming_external_transactions_asset_definition_id(
) -> <AssetDefinition as Identifiable>::Id {
    AssetDefinitionId::new("bridge_incoming_external_transactions_asset", "bridge")
}

#[inline]
fn bridge_outgoing_external_transactions_asset_definition_id(
) -> <AssetDefinition as Identifiable>::Id {
    AssetDefinitionId::new("bridge_outgoing_external_transactions_asset", "bridge")
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
        pub id: Id,
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

    /// Constructor of Iroha Special Instruction for bridge registration.
    pub fn register_bridge(
        peer_id: <Peer as Identifiable>::Id,
        bridge_definition: &BridgeDefinition,
    ) -> Instruction {
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
                    destination_id: peer_id,
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
                Mint {
                    object: (
                        bridge_definition.id.name.clone(),
                        bridge_definition.encode(),
                    ),
                    destination_id: AssetId {
                        definition_id: bridges_asset_definition_id(),
                        account_id: bridge_definition.owner_account_id.clone(),
                    },
                }
                .into(),
                // TODO: add incoming transfer event listener
            ])),
            Some(Box::new(Instruction::Fail(
                "Account not found.".to_string(),
            ))),
        )
    }

    /// Constructor of Iroha Special Instruction for external asset registration.
    pub fn register_external_asset(external_asset: &ExternalAsset) -> Instruction {
        let domain_id = &external_asset.bridge_id.definition_id.name;
        let account_id = AccountId::new(BRIDGE_ACCOUNT_NAME, domain_id);
        let asset_definition = AssetDefinition::new(AssetDefinitionId::new(
            &external_asset.id,
            &external_asset.bridge_id.definition_id.name,
        ));
        Instruction::Sequence(vec![
            Register {
                object: asset_definition,
                destination_id: domain_id.clone(),
            }
            .into(),
            Mint {
                object: (external_asset.id.clone(), external_asset.encode()),
                destination_id: AssetId {
                    definition_id: bridge_external_assets_asset_definition_id(),
                    account_id,
                },
            }
            .into(),
        ])
    }

    /// Constructor of Iroha Special Instruction for adding bridge client.
    pub fn add_client(
        bridge_definition_id: &<BridgeDefinition as Identifiable>::Id,
        client_public_key: PublicKey,
    ) -> Instruction {
        let domain_id = &bridge_definition_id.name;
        let account_id = AccountId::new(BRIDGE_ACCOUNT_NAME, domain_id);
        Add {
            object: client_public_key,
            destination_id: account_id,
        }
        .into()
    }

    /// Constructor of Iroha Special Instruction for registering incoming transfer and minting
    /// the external asset to the recipient.
    pub fn handle_incoming_transfer(
        bridge_definition_id: &<BridgeDefinition as Identifiable>::Id,
        external_asset_id: &<ExternalAsset as Identifiable>::Id,
        quantity: u32,
        big_quantity: u128,
        recipient: <Account as Identifiable>::Id,
        transaction: &ExternalTransaction,
    ) -> Instruction {
        let domain_id = &bridge_definition_id.name;
        let account_id = AccountId::new(BRIDGE_ACCOUNT_NAME, domain_id);
        let asset_id = AssetId {
            definition_id: AssetDefinitionId::new(&external_asset_id, &bridge_definition_id.name),
            account_id: recipient,
        };
        Instruction::Sequence(vec![
            Mint::new(quantity, asset_id.clone()).into(),
            Mint::new(big_quantity, asset_id).into(),
            Mint::new(
                (transaction.hash.clone(), transaction.encode()),
                AssetId {
                    definition_id: bridge_incoming_external_transactions_asset_definition_id(),
                    account_id,
                },
            )
            .into(),
        ])
    }

    /// Constructor of Iroha Special Instruction for registering outgoing transfer and deminting
    /// received asset.
    pub fn handle_outgoing_transfer(
        bridge_definition_id: &<BridgeDefinition as Identifiable>::Id,
        external_asset_id: &<ExternalAsset as Identifiable>::Id,
        quantity: u32,
        big_quantity: u128,
        transaction: &ExternalTransaction,
    ) -> Instruction {
        let domain_id = &bridge_definition_id.name;
        let account_id = AccountId::new(BRIDGE_ACCOUNT_NAME, domain_id);
        let asset_id = AssetId {
            definition_id: AssetDefinitionId::new(&external_asset_id, &bridge_definition_id.name),
            account_id: account_id.clone(),
        };
        Instruction::Sequence(vec![
            Demint::new(quantity, asset_id.clone()).into(),
            Demint::new(big_quantity, asset_id).into(),
            Mint::new(
                (transaction.hash.clone(), transaction.encode()),
                AssetId {
                    definition_id: bridge_outgoing_external_transactions_asset_definition_id(),
                    account_id,
                },
            )
            .into(),
        ])
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
                let asset_definition_ids = [
                    bridges_asset_definition_id(),
                    bridge_asset_definition_id(),
                    bridge_external_assets_asset_definition_id(),
                    bridge_incoming_external_transactions_asset_definition_id(),
                    bridge_outgoing_external_transactions_asset_definition_id(),
                ];
                for asset_definition_id in &asset_definition_ids {
                    bridge_asset_definitions.insert(
                        asset_definition_id.clone(),
                        AssetDefinition::new(asset_definition_id.clone()),
                    );
                }
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
            let register_account = domain.register_account(bridge_owner_account.clone());
            register_account
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register bridge owner account");
            let register_bridge =
                register_bridge(world_state_view.read_peer().id.clone(), &bridge_definition);
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
            let bridge_query = query_bridges_list(bridge_owner_account.id.clone());
            let query_result = bridge_query
                .execute(&world_state_view)
                .expect("failed to query bridges list");
            let decoded_bridge_definitions: Vec<BridgeDefinition> =
                decode_bridges_list(&query_result)
                    .expect("failed to decode a bridge definitions")
                    .collect();
            assert_eq!(&decoded_bridge_definitions, &[bridge_definition]);
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
            let register_bridge =
                register_bridge(world_state_view.read_peer().id.clone(), &bridge_definition);
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
            register_bridge(world_state_view.read_peer().id.clone(), &bridge_definition)
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register bridge");
            let external_asset = ExternalAsset {
                bridge_id: BridgeId::new(&bridge_definition.id.name),
                name: "DOT Token".to_string(),
                id: "DOT".to_string(),
                decimals: 12,
            };
            register_external_asset(&external_asset)
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register external asset");
            let bridge_query = query_bridge(BridgeId::new(&bridge_definition.id.name));
            let query_result = bridge_query
                .execute(&world_state_view)
                .expect("failed to query a bridge");
            let decoded_external_asset = decode_external_asset(&query_result, &external_asset.id)
                .expect("failed to decode an external asset");
            assert_eq!(decoded_external_asset, external_asset);
            let decoded_external_assets: Vec<ExternalAsset> = decode_external_assets(&query_result)
                .expect("failed to decode an external asset")
                .collect();
            assert_eq!(&decoded_external_assets, &[external_asset]);
        }

        #[test]
        fn test_add_client_should_pass() {
            let mut testkit = TestKit::new();
            let bridge_owner_public_key = KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key;
            let bridge_owner_account =
                Account::with_signatory("bridge_owner", "Company", bridge_owner_public_key.clone());
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
            register_bridge(world_state_view.read_peer().id.clone(), &bridge_definition)
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register bridge");
            add_client(&bridge_definition.id, bridge_owner_public_key.clone())
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to add bridge client");
            let query_result = query_bridge(BridgeId::new(&bridge_definition.id.name))
                .execute(&world_state_view)
                .expect("failed to query a bridge");
            let clients = get_clients(&query_result).expect("failed to get bridge clients");
            assert_eq!(clients, &[bridge_owner_public_key]);
        }

        #[test]
        fn test_external_transfer_should_pass() {
            let mut testkit = TestKit::new();
            let bridge_owner_public_key = KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key;
            let bridge_owner_account =
                Account::with_signatory("bridge_owner", "Company", bridge_owner_public_key.clone());
            let recipient_public_key = KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key;
            let recipient_account =
                Account::with_signatory("recepient", "Company", recipient_public_key.clone());
            let bridge_definition = BridgeDefinition {
                id: BridgeDefinitionId::new(BRIDGE_NAME),
                kind: BridgeKind::IClaim,
                owner_account_id: bridge_owner_account.id.clone(),
            };
            let world_state_view = &mut testkit.world_state_view;
            let accounts = [&bridge_owner_account, &recipient_account];
            for account in &accounts {
                world_state_view
                    .peer()
                    .domains
                    .get_mut("Company")
                    .unwrap()
                    .register_account((*account).clone())
                    .execute(testkit.root_account_id.clone(), world_state_view)
                    .expect("failed to register bridge owner account");
            }
            register_bridge(world_state_view.read_peer().id.clone(), &bridge_definition)
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register bridge");
            let external_asset = ExternalAsset {
                bridge_id: BridgeId::new(&bridge_definition.id.name),
                name: "DOT Token".to_string(),
                id: "DOT".to_string(),
                decimals: 12,
            };
            register_external_asset(&external_asset)
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to register external asset");
            let external_incoming_transaction = ExternalTransaction {
                hash: "0x9e58e3c750a53475f8613f100c1ccfd81083fb5c8cc8d5ed149b8e877bd1123f".into(),
                payload: b"77bd1123fd5ed1750a53475f8619e58e3ccfd81083fb5c8cc849b8e83f100c1c"
                    .to_vec(),
            };
            handle_incoming_transfer(
                &bridge_definition.id,
                &external_asset.id,
                10,
                20,
                recipient_account.id.clone(),
                &external_incoming_transaction,
            )
            .execute(testkit.root_account_id.clone(), world_state_view)
            .expect("failed to handle incoming transaction");
            let asset_definition_id =
                AssetDefinitionId::new(&external_asset.id, &bridge_definition.id.name);
            let asset = world_state_view
                .read_asset(&AssetId {
                    definition_id: asset_definition_id.clone(),
                    account_id: recipient_account.id.clone(),
                })
                .expect("failed to read asset")
                .clone();
            assert_eq!(asset.quantity, 10);
            assert_eq!(asset.big_quantity, 20);
            let bridge_account_id = AccountId::new(BRIDGE_ACCOUNT_NAME, BRIDGE_NAME);
            recipient_account
                .transfer_asset_to(asset.clone(), bridge_account_id.clone())
                .execute(testkit.root_account_id.clone(), world_state_view)
                .expect("failed to transfer asset to the bridge");
            let external_outgoing_transaction = ExternalTransaction {
                hash: "0xb8e877bd1123fd5ed1c849f8613f100c1c750a534759e58e3ccfd81083fb5c8c".into(),
                payload: b"3475fa5cc849b8e83f100c1c8619e58e3ccfd81083fb5c877bd1123fd5ed1750"
                    .to_vec(),
            };
            handle_outgoing_transfer(
                &bridge_definition.id,
                &external_asset.id,
                asset.quantity,
                asset.big_quantity,
                &external_outgoing_transaction,
            )
            .execute(testkit.root_account_id.clone(), world_state_view)
            .expect("failed to handle outgoing transaction");
            let asset = world_state_view
                .read_asset(&AssetId {
                    definition_id: asset_definition_id,
                    account_id: bridge_account_id,
                })
                .expect("failed to read asset")
                .clone();
            assert_eq!(asset.quantity, 0);
            assert_eq!(asset.big_quantity, 0);
            let query_result = query_bridge(BridgeId::new(&bridge_definition.id.name))
                .execute(&world_state_view)
                .expect("failed to query a bridge");
            let transactions: Vec<_> = decode_incoming_external_transactions(&query_result)
                .expect("failed to decode incoming transactions")
                .collect();
            assert_eq!(transactions, &[external_incoming_transaction]);
            let transactions: Vec<_> = decode_outgoing_external_transactions(&query_result)
                .expect("failed to decode outgoing transactions")
                .collect();
            assert_eq!(transactions, &[external_outgoing_transaction]);
        }
    }
}

/// Query module provides functions for constructing bridge-related queries
/// and decoding the query results.
pub mod query {
    use super::asset::*;
    use super::*;

    /// Constructor of Iroha Query for retrieving list of all registered bridges.
    pub fn query_bridges_list(bridge_owner_id: <Account as Identifiable>::Id) -> IrohaQuery {
        crate::asset::query::GetAccountAssets::build_request(bridge_owner_id).query
    }

    /// A helper function for decoding a list of bridge definitions from the query result.
    ///
    /// Each `BridgeDefinition` is encoded and stored in the bridges asset
    /// (`bridges_asset_definition_id`) store indexed by a name of the bridge. The given query
    /// result may not contain the above values, so this function can fail, returning `None`.
    pub fn decode_bridges_list<'a>(
        query_result: &'a QueryResult,
    ) -> Option<impl Iterator<Item = BridgeDefinition> + 'a> {
        let account_assets_result = match query_result {
            QueryResult::GetAccountAssets(v) => v,
            _ => return None,
        };
        account_assets_result
            .assets
            .iter()
            .find(|asset| asset.id.definition_id == bridges_asset_definition_id())
            .map(|asset| {
                asset
                    .store
                    .values()
                    .filter_map(|data| BridgeDefinition::decode(&mut data.as_slice()).ok())
            })
    }

    /// Constructor of Iroha Query for retrieving information about the bridge.
    pub fn query_bridge(bridge_id: <Bridge as Identifiable>::Id) -> IrohaQuery {
        crate::account::query::GetAccount::build_request(AccountId::new(
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
        let account_result = match query_result {
            QueryResult::GetAccount(v) => v,
            _ => return None,
        };
        account_result
            .account
            .assets
            .iter()
            .find(|(id, _)| id.definition_id == bridge_asset_definition_id())
            .and_then(|(_, asset)| {
                asset
                    .store
                    .get(BRIDGE_ASSET_BRIDGE_DEFINITION_PARAMETER_KEY)
                    .and_then(|data| BridgeDefinition::decode(&mut data.as_slice()).ok())
            })
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
        let account_result = match query_result {
            QueryResult::GetAccount(v) => v,
            _ => return None,
        };
        account_result
            .account
            .assets
            .iter()
            .find(|(id, _)| id.definition_id == bridge_external_assets_asset_definition_id())
            .and_then(|(_, asset)| {
                asset
                    .store
                    .get(asset_name)
                    .cloned()
                    .and_then(|data| ExternalAsset::decode(&mut data.as_slice()).ok())
            })
    }

    /// A helper function for decoding information about external assets from the query result.
    ///
    /// Each `ExternalAsset` is encoded and stored in the bridge external assets asset
    /// (`bridge_external_assets_asset_definition_id`) store and indexed by a name of the asset.
    /// The given query result may not contain the above values, so this function can fail,
    /// returning `None`.
    pub fn decode_external_assets<'a>(
        query_result: &'a QueryResult,
    ) -> Option<impl Iterator<Item = ExternalAsset> + 'a> {
        let account_result = match query_result {
            QueryResult::GetAccount(v) => v,
            _ => return None,
        };
        account_result
            .account
            .assets
            .iter()
            .find(|(id, _)| id.definition_id == bridge_external_assets_asset_definition_id())
            .map(|(_, asset)| {
                asset
                    .store
                    .values()
                    .filter_map(|data| ExternalAsset::decode(&mut data.as_slice()).ok())
            })
    }

    /// A helper function for retrieving information about bridge clients.
    pub fn get_clients(query_result: &QueryResult) -> Option<&Vec<PublicKey>> {
        let account_result = match query_result {
            QueryResult::GetAccount(v) => v,
            _ => return None,
        };
        Some(&account_result.account.read_signatories())
    }

    fn decode_external_transactions<'a>(
        query_result: &'a QueryResult,
        is_incoming: bool,
    ) -> Option<impl Iterator<Item = ExternalTransaction> + 'a> {
        let account_result = match query_result {
            QueryResult::GetAccount(v) => v,
            _ => return None,
        };
        account_result
            .account
            .assets
            .iter()
            .find(|(id, _)| {
                let asset_definition_id = if is_incoming {
                    bridge_incoming_external_transactions_asset_definition_id()
                } else {
                    bridge_outgoing_external_transactions_asset_definition_id()
                };
                id.definition_id == asset_definition_id
            })
            .map(|(_, asset)| {
                asset
                    .store
                    .values()
                    .filter_map(|data| ExternalTransaction::decode(&mut data.as_slice()).ok())
            })
    }

    /// A helper function for decoding information about incoming external transactions
    /// from the query result.
    ///
    /// Each `ExternalTransaction` is encoded and stored in the bridge external assets asset
    /// (`bridge_incoming_external_transactions_asset_definition_id`) store and indexed by a
    /// transaction hash. The given query result may not contain the above values, so this
    /// function can fail, returning `None`.
    pub fn decode_incoming_external_transactions<'a>(
        query_result: &'a QueryResult,
    ) -> Option<impl Iterator<Item = ExternalTransaction> + 'a> {
        decode_external_transactions(query_result, true)
    }

    /// A helper function for decoding information about outgoing external transactions
    /// from the query result.
    ///
    /// Each `ExternalTransaction` is encoded and stored in the bridge external assets asset
    /// (`bridge_outgoing_external_transactions_asset_definition_id`) store and indexed by a
    /// transaction hash. The given query result may not contain the above values, so this
    /// function can fail, returning `None`.
    pub fn decode_outgoing_external_transactions<'a>(
        query_result: &'a QueryResult,
    ) -> Option<impl Iterator<Item = ExternalTransaction> + 'a> {
        decode_external_transactions(query_result, false)
    }
}
