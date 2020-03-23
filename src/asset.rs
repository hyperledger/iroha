use crate::prelude::*;

#[derive(Clone, Debug)]
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
    use crate::isi::Command;

    /// The purpose of add asset quantity command is to increase the quantity of an asset on account of
    /// transaction creator. Use case scenario is to increase the number of a mutable asset in the
    /// system, which can act as a claim on a commodity (e.g. money, gold, etc.).
    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct AddAssetQuantity {
        pub asset_id: Id,
        pub account_id: Id,
        pub amount: u128,
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
            bincode::serialize(command_payload).expect("Failed to serialize payload.")
        }
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, isi::Command, asset::isi::AddAssetQuantity};
    ///
    /// let command_payload = &AddAssetQuantity {
    ///     asset_id: Id::new("asset","domain"),
    ///     account_id: Id::new("account","domain"),
    ///     amount: 20002,
    /// };
    /// let result: Command = command_payload.into();
    /// ```
    impl std::convert::From<&AddAssetQuantity> for Command {
        fn from(command_payload: &AddAssetQuantity) -> Self {
            Command {
                version: 1,
                command_type: 1,
                payload: command_payload.into(),
            }
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
            bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
        }
    }

    /// The purpose of сreate asset command is to create a new type of asset, unique in a domain.
    /// An asset is a countable representation of a commodity.
    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
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
            bincode::serialize(command_payload).expect("Failed to serialize payload.")
        }
    }

    /// # Example
    /// ```
    /// use iroha::{isi::Command, asset::isi::CreateAsset};
    ///
    /// let command_payload = &CreateAsset {
    ///     asset_name: "asset".to_string(),
    ///     domain_id: "domain".to_string(),
    ///     decimals: 0,
    /// };
    /// let result: Command = command_payload.into();
    /// ```
    impl std::convert::From<&CreateAsset> for Command {
        fn from(command_payload: &CreateAsset) -> Self {
            Command {
                version: 1,
                command_type: 1,
                payload: command_payload.into(),
            }
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
            bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
        }
    }

    /// The purpose of transfer asset command is to share assets within the account in peer
    /// network: in the way that source account transfers assets to the target account.
    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct TransferAsset {
        pub source_account_id: Id,
        pub destination_account_id: Id,
        pub asset_id: Id,
        pub description: String,
        pub amount: u128,
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
            bincode::serialize(command_payload).expect("Failed to serialize payload.")
        }
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, isi::Command, asset::isi::TransferAsset};
    ///
    /// let command_payload = &TransferAsset {
    ///    source_account_id: Id::new("source","domain"),
    ///    destination_account_id: Id::new("destination","domain"),
    ///    asset_id: Id::new("xor","domain"),
    ///    description: "description".to_string(),
    ///    amount: 2002,
    /// };
    /// let result: Command = command_payload.into();
    /// ```
    impl std::convert::From<&TransferAsset> for Command {
        fn from(command_payload: &TransferAsset) -> Self {
            Command {
                version: 1,
                command_type: 17,
                payload: command_payload.into(),
            }
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
            bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
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
            let actual: AddAssetQuantity =
                bincode::deserialize(&bincode::serialize(&expected).unwrap()[..]).unwrap();
            assert_eq!(expected, actual);
        }

        #[test]
        fn create_asset_command_serialization_and_deserialization() {
            let expected = CreateAsset {
                asset_name: "asset".to_string(),
                domain_id: "domain".to_string(),
                decimals: 0,
            };
            let actual: CreateAsset =
                bincode::deserialize(&bincode::serialize(&expected).unwrap()[..]).unwrap();
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
            let actual: TransferAsset =
                bincode::deserialize(&bincode::serialize(&expected).unwrap()[..]).unwrap();
            assert_eq!(expected, actual);
        }

        #[test]
        fn transfer_asset_command_into_command() {
            let transfer_asset = &TransferAsset {
                source_account_id: Id::new("source", "domain"),
                destination_account_id: Id::new("destination", "domain"),
                asset_id: Id::new("xor", "domain"),
                description: "description".to_string(),
                amount: 2002,
            };
            let expected = Command {
                version: 1,
                command_type: 17,
                payload: transfer_asset.into(),
            };
            let actual: Command = transfer_asset.into();
            assert_eq!(expected.version, actual.version);
            assert_eq!(expected.command_type, actual.command_type);
            assert_eq!(expected.payload, actual.payload);
        }
    }
}
