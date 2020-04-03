use crate::prelude::*;
use parity_scale_codec::{Decode, Encode};

#[derive(Clone, Debug, Encode, Decode)]
pub struct Asset {
    /// identifier of asset, formatted as asset_name#domain_id
    pub id: Id,
}

impl Asset {
    pub fn new(id: Id) -> Self {
        Asset { id }
    }
}

pub mod isi {
    use super::*;
    use crate::isi::Contract;
    use parity_scale_codec::{Decode, Encode};

    /// The purpose of add asset quantity command is to increase the quantity of an asset on account of
    /// transaction creator. Use case scenario is to increase the number of a mutable asset in the
    /// system, which can act as a claim on a commodity (e.g. money, gold, etc.).
    #[derive(Clone, Debug, PartialEq, Encode, Decode)]
    pub struct AddAssetQuantity {
        pub asset_id: Id,
        pub account_id: Id,
        pub amount: u128,
    }

    impl Instruction for AddAssetQuantity {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            world_state_view
                .account(&self.account_id)
                .unwrap()
                .assets
                .insert(self.asset_id.clone(), Asset::new(self.asset_id.clone()));
            Ok(())
        }
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, asset::isi::AddAssetQuantity};
    ///
    /// let command_payload = &AddAssetQuantity {
    ///     asset_id: Id::new("asset","domain"),
    ///     account_id: Id::new("account","domain"),
    ///     amount: 20002,
    /// };
    /// let result: Vec<u8> = command_payload.into();
    /// ```
    impl std::convert::From<&AddAssetQuantity> for Vec<u8> {
        fn from(command_payload: &AddAssetQuantity) -> Self {
            command_payload.encode()
        }
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, isi::Contract, asset::isi::AddAssetQuantity};
    ///
    /// let command_payload = AddAssetQuantity {
    ///     asset_id: Id::new("asset","domain"),
    ///     account_id: Id::new("account","domain"),
    ///     amount: 20002,
    /// };
    /// let result: Contract = command_payload.into();
    /// ```
    impl std::convert::From<AddAssetQuantity> for Contract {
        fn from(command_payload: AddAssetQuantity) -> Self {
            Contract::AddAssetQuantity(command_payload)
        }
    }

    /// # Example
    /// ```
    /// # use iroha::{prelude::*, asset::isi::AddAssetQuantity};
    /// # let command_payload = &AddAssetQuantity {
    /// #     asset_id: Id::new("asset","domain"),
    /// #     account_id: Id::new("account","domain"),
    /// #     amount: 20002,
    /// # };
    /// # let result: Vec<u8> = command_payload.into();
    /// let command_payload: AddAssetQuantity = result.into();
    /// ```
    impl std::convert::From<Vec<u8>> for AddAssetQuantity {
        fn from(command_payload: Vec<u8>) -> Self {
            AddAssetQuantity::decode(&mut command_payload.as_slice())
                .expect("Failed to deserialize payload.")
        }
    }

    /// The purpose of сreate asset command is to create a new type of asset, unique in a domain.
    /// An asset is a countable representation of a commodity.
    #[derive(Clone, Debug, PartialEq, Encode, Decode)]
    pub struct CreateAsset {
        pub asset_name: String,
        pub domain_id: String,
        pub decimals: u8,
    }

    /// # Example
    /// ```
    /// use iroha::asset::isi::CreateAsset;
    ///
    /// let command_payload = &CreateAsset {
    ///     asset_name: "asset".to_string(),
    ///     domain_id: "domain".to_string(),
    ///     decimals: 0,
    /// };
    /// let result: Vec<u8> = command_payload.into();
    /// ```
    impl std::convert::From<&CreateAsset> for Vec<u8> {
        fn from(command_payload: &CreateAsset) -> Self {
            command_payload.encode()
        }
    }

    /// # Example
    /// ```
    /// use iroha::{isi::Contract, asset::isi::CreateAsset};
    ///
    /// let command_payload = CreateAsset {
    ///     asset_name: "asset".to_string(),
    ///     domain_id: "domain".to_string(),
    ///     decimals: 0,
    /// };
    /// let result: Contract = command_payload.into();
    /// ```
    impl std::convert::From<CreateAsset> for Contract {
        fn from(command_payload: CreateAsset) -> Self {
            Contract::CreateAsset(command_payload)
        }
    }

    /// # Example
    /// ```
    /// # use iroha::asset::isi::CreateAsset;
    /// #
    /// # let command_payload = &CreateAsset {
    /// #    asset_name: "asset".to_string(),
    /// #    domain_id: "domain".to_string(),
    /// #    decimals: 0,
    /// # };
    /// # let result: Vec<u8> = command_payload.into();
    /// let command_payload: CreateAsset  = result.into();
    /// ```
    impl std::convert::From<Vec<u8>> for CreateAsset {
        fn from(command_payload: Vec<u8>) -> Self {
            CreateAsset::decode(&mut command_payload.as_slice())
                .expect("Failed to deserialize payload.")
        }
    }

    /// The purpose of transfer asset command is to share assets within the account in peer
    /// network: in the way that source account transfers assets to the target account.
    #[derive(Clone, Debug, PartialEq, Encode, Decode)]
    pub struct TransferAsset {
        pub source_account_id: Id,
        pub destination_account_id: Id,
        pub asset_id: Id,
        pub description: String,
        pub amount: u128,
    }

    impl Instruction for TransferAsset {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            let asset = world_state_view
                .account(&self.source_account_id)
                .unwrap()
                .assets
                .remove(&self.asset_id)
                .unwrap();
            world_state_view
                .account(&self.destination_account_id)
                .unwrap()
                .assets
                .insert(self.asset_id.clone(), asset);
            Ok(())
        }
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, asset::isi::TransferAsset};
    ///
    /// let command_payload = &TransferAsset {
    ///    source_account_id: Id::new("source","domain"),
    ///    destination_account_id: Id::new("destination","domain"),
    ///    asset_id: Id::new("xor","domain"),
    ///    description: "description".to_string(),
    ///    amount: 2002,
    /// };
    /// let result: Vec<u8> = command_payload.into();
    /// ```
    impl std::convert::From<&TransferAsset> for Vec<u8> {
        fn from(command_payload: &TransferAsset) -> Self {
            command_payload.encode()
        }
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, isi::Contract, asset::isi::TransferAsset};
    ///
    /// let command_payload = TransferAsset {
    ///    source_account_id: Id::new("source","domain"),
    ///    destination_account_id: Id::new("destination","domain"),
    ///    asset_id: Id::new("xor","domain"),
    ///    description: "description".to_string(),
    ///    amount: 2002,
    /// };
    /// let result: Contract = command_payload.into();
    /// ```
    impl std::convert::From<TransferAsset> for Contract {
        fn from(command_payload: TransferAsset) -> Self {
            Contract::TransferAsset(command_payload)
        }
    }

    /// # Example
    /// ```
    /// # use iroha::{prelude::*, asset::isi::TransferAsset};
    /// #
    /// # let command_payload = &TransferAsset {
    /// #   source_account_id: Id::new("source","domain"),
    /// #   destination_account_id: Id::new("destination","domain"),
    /// #   asset_id: Id::new("xor","domain"),
    /// #   description: "description".to_string(),
    /// #   amount: 2002,
    /// # };
    /// # let result: Vec<u8> = command_payload.into();
    /// let command_payload: TransferAsset  = result.into();
    /// ```
    impl std::convert::From<Vec<u8>> for TransferAsset {
        fn from(command_payload: Vec<u8>) -> Self {
            TransferAsset::decode(&mut command_payload.as_slice())
                .expect("Failed to deserialize payload.")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn add_asset_quantity_command_serialization_and_deserialization() {
            let expected = AddAssetQuantity {
                asset_id: Id::new("asset", "domain"),
                account_id: Id::new("account", "domain"),
                amount: 20002,
            };
            let actual = AddAssetQuantity::decode(&mut expected.encode().as_slice()).unwrap();
            assert_eq!(expected, actual);
        }

        #[test]
        fn create_asset_command_serialization_and_deserialization() {
            let expected = CreateAsset {
                asset_name: "asset".to_string(),
                domain_id: "domain".to_string(),
                decimals: 0,
            };
            let actual = CreateAsset::decode(&mut expected.encode().as_slice()).unwrap();
            assert_eq!(expected, actual);
        }

        #[test]
        fn transfer_asset_command_serialization_and_deserialization() {
            let expected = TransferAsset {
                source_account_id: Id::new("source", "domain"),
                destination_account_id: Id::new("destination", "domain"),
                asset_id: Id::new("xor", "domain"),
                description: "description".to_string(),
                amount: 2002,
            };
            let actual = TransferAsset::decode(&mut expected.encode().as_slice()).unwrap();
            assert_eq!(expected, actual);
        }

        #[test]
        fn transfer_asset_command_into_command() {
            let transfer_asset = TransferAsset {
                source_account_id: Id::new("source", "domain"),
                destination_account_id: Id::new("destination", "domain"),
                asset_id: Id::new("xor", "domain"),
                description: "description".to_string(),
                amount: 2002,
            };
            let expected = Contract::TransferAsset(transfer_asset.clone());
            let actual: Contract = transfer_asset.into();
            assert_eq!(expected, actual);
        }
    }
}

pub mod query {
    use super::*;
    use crate::{asset::Asset, query::IrohaQuery};
    use parity_scale_codec::{Decode, Encode};
    use std::time::SystemTime;

    /// To get the state of all assets in an account (a balance),
    /// GetAccountAssets query can be used.
    #[derive(Encode, Decode)]
    pub struct GetAccountAssets {
        account_id: Id,
    }

    #[derive(Debug, Encode, Decode)]
    pub struct GetAccountAssetsResult {
        pub assets: Vec<Asset>,
    }

    impl GetAccountAssets {
        pub fn new(account_id: Id) -> GetAccountAssets {
            GetAccountAssets { account_id }
        }

        pub fn build_request(account_id: Id) -> Request {
            let query = GetAccountAssets { account_id };
            Request {
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get System Time.")
                    .as_millis(),
                signature: Option::None,
                query: query.into(),
            }
        }
    }

    impl Query for GetAccountAssets {
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            let assets: Vec<Asset> = world_state_view
                .read_account(&self.account_id)
                .ok_or("No account found.")?
                .assets
                .values()
                .cloned()
                .collect();
            Ok(QueryResult::GetAccountAssets(GetAccountAssetsResult {
                assets,
            }))
        }
    }

    /// ```
    /// use iroha::{query::IrohaQuery, asset::query::GetAccountAssets, prelude::*};
    ///
    /// let query = GetAccountAssets::new(Id::new("account","domain"));
    /// let result: IrohaQuery = query.into();
    /// ```
    impl std::convert::From<GetAccountAssets> for IrohaQuery {
        fn from(query: GetAccountAssets) -> Self {
            IrohaQuery::GetAccountAssets(query)
        }
    }

    /// ```
    /// use iroha::{query::Request, asset::query::GetAccountAssets, prelude::*};
    ///
    /// let query_payload = &GetAccountAssets::new(Id::new("account","domain"));
    /// let result: Vec<u8> = query_payload.into();
    /// ```
    impl std::convert::From<&GetAccountAssets> for Vec<u8> {
        fn from(payload: &GetAccountAssets) -> Self {
            payload.encode()
        }
    }

    /// # Example
    /// ```
    /// # use iroha::{query::Request, asset::query::GetAccountAssets, prelude::*};
    ///
    /// # let query_payload = &GetAccountAssets::new(Id::new("account","domain"));
    /// # let result: Vec<u8> = query_payload.into();
    /// let query_payload: GetAccountAssets = result.into();
    /// ```
    impl std::convert::From<Vec<u8>> for GetAccountAssets {
        fn from(payload: Vec<u8>) -> Self {
            GetAccountAssets::decode(&mut payload.as_slice())
                .expect("Failed to deserialize payload.")
        }
    }
}
