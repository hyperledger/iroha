//! This module contains `Asset` structure, it's implementation and related traits and
//! instructions implementations.

use crate::{
    isi::prelude::*,
    permission::{Permission, Permissions},
    prelude::*,
};
use iroha_derive::log;
use parity_scale_codec::{Decode, Encode};
use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    hash::Hash,
};

/// Asset entity represents some sort of commodity or value.
#[derive(Clone, Debug, Encode, Decode)]
pub struct AssetDefinition {
    /// An Identification of the `Asset`.
    pub id: <AssetDefinition as Identifiable>::Id,
}

impl AssetDefinition {
    /// Constructor of the detached and empty `AssetDefinition` entity.
    ///
    /// This method can be used to create an `AssetDefinition` which should be registered in the domain.
    /// This method should not be used to create an `AssetDefinition` to work with as a part of the Iroha
    /// State.
    pub fn new(id: <AssetDefinition as Identifiable>::Id) -> Self {
        AssetDefinition { id }
    }
}

/// Represents a sequence of bytes. Used for storing encoded data.
pub type Bytes = Vec<u8>;

/// All possible variants of `Asset` entity's components.
#[derive(Clone, Debug, Encode, Decode)]
pub struct Asset {
    /// Component Identification.
    pub id: <Asset as Identifiable>::Id,
    /// Asset's Quantity associated with an `Account`.
    pub quantity: u32,
    /// Asset's Big Quantity associated with an `Account`.
    pub big_quantity: u128,
    /// Asset's key-value structured data associated with an `Account`.
    pub store: BTreeMap<String, Bytes>,
    /// Asset's key-value  (action, object_id) structured permissions associated with an `Account`.
    pub permissions: Permissions,
}

impl Asset {
    /// Constructor with filled `store` field.
    pub fn with_parameter(id: <Asset as Identifiable>::Id, parameter: (String, Bytes)) -> Self {
        let mut store = BTreeMap::new();
        store.insert(parameter.0, parameter.1);
        Self {
            id,
            quantity: 0,
            big_quantity: 0,
            store,
            permissions: Permissions::new(),
        }
    }

    /// Constructor with filled `quantity` field.
    pub fn with_quantity(id: <Asset as Identifiable>::Id, quantity: u32) -> Self {
        Self {
            id,
            quantity,
            big_quantity: 0,
            store: BTreeMap::new(),
            permissions: Permissions::new(),
        }
    }

    /// Constructor with filled `big_quantity` field.
    pub fn with_big_quantity(id: <Asset as Identifiable>::Id, big_quantity: u128) -> Self {
        Self {
            id,
            quantity: 0,
            big_quantity,
            store: BTreeMap::new(),
            permissions: Permissions::new(),
        }
    }

    /// Constructor with filled `permissions` field.
    pub fn with_permission(id: <Asset as Identifiable>::Id, permission: Permission) -> Self {
        let permissions = Permissions::single(permission);
        Self {
            id,
            quantity: 0,
            big_quantity: 0,
            store: BTreeMap::new(),
            permissions,
        }
    }

    /// Constructor of the `Mint<Asset, u32>` Iroha Special Instruction.
    pub fn mint(&self, object: u32) -> Mint<Asset, u32> {
        Mint {
            object,
            destination_id: self.id.clone(),
        }
    }

    /// Constructor of the `Mint<Asset, u128>` Iroha Special Instruction.
    pub fn mint_big(&self, object: u128) -> Mint<Asset, u128> {
        Mint {
            object,
            destination_id: self.id.clone(),
        }
    }
}

/// Identification of an Asset Definition. Consists of Asset's name and Domain's name.
///
/// # Example
///
/// ```
/// use iroha::asset::AssetDefinitionId as Id;
///
/// let id = Id::new("xor", "soramitsu");
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, std::hash::Hash, Encode, Decode)]
pub struct AssetDefinitionId {
    /// Asset's name.
    pub name: String,
    /// Domain's name.
    pub domain_name: String,
}

impl AssetDefinitionId {
    /// `Id` constructor used to easily create an `Id` from three string slices - one for the
    /// asset's name, another one for the domain's name.
    pub fn new(name: &str, domain_name: &str) -> Self {
        AssetDefinitionId {
            name: name.to_string(),
            domain_name: domain_name.to_string(),
        }
    }
}

/// Asset Identification is represented by `name#domain_name` string.
impl From<&str> for AssetDefinitionId {
    fn from(string: &str) -> AssetDefinitionId {
        let vector: Vec<&str> = string.split('#').collect();
        AssetDefinitionId {
            name: String::from(vector[0]),
            domain_name: String::from(vector[1]),
        }
    }
}

impl Display for AssetDefinitionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.name, self.domain_name)
    }
}

impl Identifiable for AssetDefinition {
    type Id = AssetDefinitionId;
}

/// Identification of an Asset's components include Entity Id (`Asset::Id`) and `Account::Id`.
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Encode, Decode)]
pub struct AssetId {
    /// Entity Identification.
    pub definition_id: <AssetDefinition as Identifiable>::Id,
    /// Account Identification.
    pub account_id: <Account as Identifiable>::Id,
}

impl AssetId {
    /// `AssetId` constructor used to easily create an `AssetId` from an `AssetDefinitionId` and
    /// an `AccountId`.
    pub fn new(
        definition_id: <AssetDefinition as Identifiable>::Id,
        account_id: <Account as Identifiable>::Id,
    ) -> Self {
        AssetId {
            definition_id,
            account_id,
        }
    }
}

impl Identifiable for Asset {
    type Id = AssetId;
}

/// Iroha Special Instructions module provides `AssetInstruction` enum with all legal types of
/// Asset related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AssetInstruction` variants into generic ISI.
pub mod isi {
    use super::*;
    use crate::permission::isi::PermissionInstruction;
    use iroha_derive::*;

    /// Enumeration of all legal Asset related Instructions.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum AssetInstruction {
        /// Variant of the generic `Mint` instruction for `u32` --> `Asset`.
        MintAsset(u32, <Asset as Identifiable>::Id),
        /// Variant of the generic `Mint` instruction for `u128` --> `Asset`.
        MintBigAsset(u128, <Asset as Identifiable>::Id),
        /// Variant of the generic `Mint` instruction for `(String, Bytes)` --> `Asset`.
        MintParameterAsset((String, Bytes), <Asset as Identifiable>::Id),
        /// Variant of the generic `Demint` instruction for `u32` --> `Asset`.
        DemintAsset(u32, <Asset as Identifiable>::Id),
        /// Variant of the generic `Demint` instruction for `u128` --> `Asset`.
        DemintBigAsset(u128, <Asset as Identifiable>::Id),
        /// Variant of the generic `Demint` instruction for `String` --> `Asset`.
        DemintParameterAsset(String, <Asset as Identifiable>::Id),
    }

    impl AssetInstruction {
        /// Executes `AssetInstruction` on the given `WorldStateView`.
        /// Returns `Ok(())` if execution succeeded and `Err(String)` with error message if not.
        pub fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            match self {
                AssetInstruction::MintAsset(quantity, asset_id) => {
                    Mint::new(*quantity, asset_id.clone()).execute(authority, world_state_view)
                }
                AssetInstruction::MintBigAsset(big_quantity, asset_id) => {
                    Mint::new(*big_quantity, asset_id.clone()).execute(authority, world_state_view)
                }
                AssetInstruction::MintParameterAsset(parameter, asset_id) => {
                    Mint::new(parameter.clone(), asset_id.clone())
                        .execute(authority, world_state_view)
                }
                AssetInstruction::DemintAsset(quantity, asset_id) => {
                    Demint::new(*quantity, asset_id.clone()).execute(authority, world_state_view)
                }
                AssetInstruction::DemintBigAsset(big_quantity, asset_id) => {
                    Demint::new(*big_quantity, asset_id.clone())
                        .execute(authority, world_state_view)
                }
                AssetInstruction::DemintParameterAsset(parameter, asset_id) => {
                    Demint::new(parameter.clone(), asset_id.clone())
                        .execute(authority, world_state_view)
                }
            }
        }
    }

    impl Mint<Asset, u32> {
        pub(crate) fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanMintAsset(
                authority,
                self.destination_id.definition_id.clone(),
                None,
            )
            .execute(world_state_view)?;
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset.quantity += self.object;
                }
                None => world_state_view.add_asset(Asset::with_quantity(
                    self.destination_id.clone(),
                    self.object,
                )),
            }
            Ok(())
        }
    }

    impl Mint<Asset, u128> {
        pub(crate) fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanMintAsset(
                authority,
                self.destination_id.definition_id.clone(),
                None,
            )
            .execute(world_state_view)?;
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset.big_quantity += self.object;
                }
                None => world_state_view.add_asset(Asset::with_big_quantity(
                    self.destination_id.clone(),
                    self.object,
                )),
            }
            Ok(())
        }
    }

    impl From<Mint<Asset, u32>> for Instruction {
        fn from(instruction: Mint<Asset, u32>) -> Self {
            Instruction::Asset(AssetInstruction::MintAsset(
                instruction.object,
                instruction.destination_id,
            ))
        }
    }

    impl From<Mint<Asset, u128>> for Instruction {
        fn from(instruction: Mint<Asset, u128>) -> Self {
            Instruction::Asset(AssetInstruction::MintBigAsset(
                instruction.object,
                instruction.destination_id,
            ))
        }
    }

    impl Mint<Asset, (String, Bytes)> {
        pub(crate) fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanMintAsset(
                authority,
                self.destination_id.definition_id.clone(),
                None,
            )
            .execute(world_state_view)?;
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or(format!(
                    "Failed to find asset definition. {:?}",
                    &self.destination_id.definition_id
                ))?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset
                        .store
                        .insert(self.object.0.clone(), self.object.1.clone());
                }
                None => world_state_view.add_asset(Asset::with_parameter(
                    self.destination_id.clone(),
                    self.object.clone(),
                )),
            }
            Ok(())
        }
    }

    impl From<Mint<Asset, (String, Bytes)>> for Instruction {
        fn from(instruction: Mint<Asset, (String, Bytes)>) -> Self {
            Instruction::Asset(AssetInstruction::MintParameterAsset(
                instruction.object,
                instruction.destination_id,
            ))
        }
    }

    impl Demint<Asset, u32> {
        pub(crate) fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanDemintAsset(
                authority,
                self.destination_id.definition_id.clone(),
                None,
            )
            .execute(world_state_view)?;
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or("Asset not found.")?;
            asset.quantity = asset
                .quantity
                .checked_sub(self.object)
                .ok_or("Not enough quantity to demint.")?;
            Ok(())
        }
    }

    impl Demint<Asset, u128> {
        pub(crate) fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanDemintAsset(
                authority,
                self.destination_id.definition_id.clone(),
                None,
            )
            .execute(world_state_view)?;
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or("Asset not found.")?;
            asset.big_quantity = asset
                .big_quantity
                .checked_sub(self.object)
                .ok_or("Not enough big quantity to demint.")?;
            Ok(())
        }
    }

    impl From<Demint<Asset, u32>> for Instruction {
        fn from(instruction: Demint<Asset, u32>) -> Self {
            Instruction::Asset(AssetInstruction::DemintAsset(
                instruction.object,
                instruction.destination_id,
            ))
        }
    }

    impl From<Demint<Asset, u128>> for Instruction {
        fn from(instruction: Demint<Asset, u128>) -> Self {
            Instruction::Asset(AssetInstruction::DemintBigAsset(
                instruction.object,
                instruction.destination_id,
            ))
        }
    }

    impl Demint<Asset, String> {
        pub(crate) fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanDemintAsset(
                authority,
                self.destination_id.definition_id.clone(),
                None,
            )
            .execute(world_state_view)?;
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset definition.")?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or("Asset not found.")?;
            asset.store.remove(&self.object).ok_or("Key not found.")?;
            Ok(())
        }
    }

    impl From<Demint<Asset, String>> for Instruction {
        fn from(instruction: Demint<Asset, String>) -> Self {
            Instruction::Asset(AssetInstruction::DemintParameterAsset(
                instruction.object,
                instruction.destination_id,
            ))
        }
    }
}

/// Query module provides `IrohaQuery` Asset related implementations.
pub mod query {
    use super::*;
    use crate::query::IrohaQuery;
    use iroha_derive::{IntoQuery, Io};
    use parity_scale_codec::{Decode, Encode};
    use std::time::SystemTime;

    /// To get the state of all assets in an account (a balance),
    /// GetAccountAssets query can be used.
    #[derive(Clone, Debug, Io, IntoQuery, Encode, Decode)]
    pub struct GetAccountAssets {
        account_id: <Account as Identifiable>::Id,
    }

    /// Result of the `GetAccountAssets` execution.
    #[derive(Clone, Debug, Encode, Decode)]
    pub struct GetAccountAssetsResult {
        /// Assets types which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    impl GetAccountAssets {
        /// Build a `GetAccountAssets` query in the form of a `QueryRequest`.
        pub fn build_request(account_id: <Account as Identifiable>::Id) -> QueryRequest {
            let query = GetAccountAssets { account_id };
            QueryRequest {
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get System Time.")
                    .as_millis()
                    .to_string(),
                signature: Option::None,
                query: query.into(),
            }
        }
    }

    impl Query for GetAccountAssets {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            let assets: Vec<Asset> = world_state_view
                .read_account(&self.account_id)
                .ok_or(format!(
                    "No account with id: {:?} found in the current world state: {:?}.",
                    &self.account_id, world_state_view
                ))?
                .assets
                .values()
                .cloned()
                .collect();
            Ok(QueryResult::GetAccountAssets(GetAccountAssetsResult {
                assets,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::peer::PeerId;
    use crate::permission::{permission_asset_definition_id, Permission};
    use crate::prelude::*;
    use parity_scale_codec::alloc::collections::BTreeMap;

    fn init() -> WorldStateView {
        let domain_name = "Company".to_string();
        let public_key = KeyPair::generate()
            .expect("Failed to generate KeyPair.")
            .public_key;
        let mut asset_definitions = BTreeMap::new();
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
        let mut accounts = BTreeMap::new();
        accounts.insert(account_id.clone(), account);
        let domain = Domain {
            name: domain_name.clone(),
            accounts,
            asset_definitions,
        };
        let mut domains = BTreeMap::new();
        domains.insert(domain_name.clone(), domain);
        let address = "127.0.0.1:8080".to_string();
        let mut world_state_view = WorldStateView::new(Peer::with_domains(
            PeerId {
                address: address.clone(),
                public_key: public_key.clone(),
            },
            &Vec::new(),
            domains,
        ));
        world_state_view
    }

    #[test]
    fn test_demint_asset_should_pass() {
        let domain_name = "Company";
        let mut world_state_view = init();
        let domain = world_state_view.domain(domain_name).unwrap();
        let account_id = AccountId::new("root", &domain_name);
        let asset_def = AssetDefinition::new(AssetDefinitionId::new("XOR", "Company"));
        domain
            .register_asset(asset_def.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to register asset");
        let asset_id = AssetId::new(asset_def.id, account_id.clone());
        Mint::new(10u32, asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to mint asset");
        Demint::new(10u32, asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to demint asset");
        assert_eq!(world_state_view.asset(&asset_id).unwrap().quantity, 0);
        Mint::new(20u128, asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to big mint asset");
        Demint::new(20u128, asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to big demint asset");
        assert_eq!(world_state_view.asset(&asset_id).unwrap().big_quantity, 0);
        Mint::new(("key".to_string(), b"value".to_vec()), asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to big mint asset");
        Demint::new("key".to_string(), asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to big demint asset");
        assert!(world_state_view
            .asset(&asset_id)
            .unwrap()
            .store
            .get("key")
            .is_none());
    }

    #[test]
    fn test_demint_asset_should_fail() {
        let domain_name = "Company";
        let mut world_state_view = init();
        let domain = world_state_view.domain(domain_name).unwrap();
        let account_id = AccountId::new("root", &domain_name);
        let asset_def = AssetDefinition::new(AssetDefinitionId::new("XOR", "Company"));
        domain
            .register_asset(asset_def.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to register asset");
        let asset_id = AssetId::new(asset_def.id, account_id.clone());
        Mint::new(10u32, asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to mint asset");
        assert_eq!(
            Demint::new(11u32, asset_id.clone())
                .execute(account_id.clone(), &mut world_state_view)
                .unwrap_err(),
            "Not enough quantity to demint.".to_string()
        );
        assert_eq!(world_state_view.asset(&asset_id).unwrap().quantity, 10);
        Mint::new(20u128, asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to big mint asset");
        assert_eq!(
            Demint::new(21u128, asset_id.clone())
                .execute(account_id.clone(), &mut world_state_view)
                .unwrap_err(),
            "Not enough big quantity to demint.".to_string()
        );
        assert_eq!(world_state_view.asset(&asset_id).unwrap().big_quantity, 20);
        Mint::new(("key".to_string(), b"value".to_vec()), asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .expect("failed to big mint asset");
        assert_eq!(
            Demint::new("other_key".to_string(), asset_id.clone())
                .execute(account_id.clone(), &mut world_state_view)
                .unwrap_err(),
            "Key not found.".to_string()
        );
        assert!(world_state_view
            .asset(&asset_id)
            .unwrap()
            .store
            .get("key")
            .is_some());
    }
}
