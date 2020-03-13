use crate::model::commands::oob::Command;

/// The purpose of add asset quantity command is to increase the quantity of an asset on account of
/// transaction creator. Use case scenario is to increase the number of a mutable asset in the
/// system, which can act as a claim on a commodity (e.g. money, gold, etc.).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AddAssetQuantity {
    pub asset_id: String,
    //TODO[@humb1t:RH2-11]: decide which format to use in such a case
    //value can be non-integer, but should be precise.
    pub amount: f64,
}

/// # Example
/// ```
/// use iroha::model::commands::assets::AddAssetQuantity;
///
/// let command_payload = &AddAssetQuantity {
///     asset_id: "asset@domain".to_string(),
///     amount: 200.02,
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
/// use iroha::model::commands::{oob::Command,assets::AddAssetQuantity};
///
/// let command_payload = &AddAssetQuantity {
///     asset_id: "asset@domain".to_string(),
///     amount: 200.02,
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
/// # use iroha::model::commands::assets::AddAssetQuantity;
/// # let command_payload = &AddAssetQuantity {
/// #     asset_id: "asset@domain".to_string(),
/// #     amount: 200.02,
/// # };
/// # let result: Vec<u8> = command_payload.into();
/// let command_payload: AddAssetQuantity = result.into();
/// ```
impl std::convert::From<Vec<u8>> for AddAssetQuantity {
    fn from(command_payload: Vec<u8>) -> Self {
        bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
    }
}

#[test]
fn add_asset_quantity_command_serialization_and_deserialization() {
    let expected = AddAssetQuantity {
        asset_id: "asset@domain".to_string(),
        amount: 200.02,
    };
    let actual: AddAssetQuantity =
        bincode::deserialize(&bincode::serialize(&expected).unwrap()[..]).unwrap();
    assert_eq!(expected, actual);
}
/// The purpose of сreate asset command is to create a new type of asset, unique in a domain.
/// An asset is a countable representation of a commodity.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CreateAsset {
    pub asset_name: String,
    pub domain_id: String,
    pub precision: u8,
}

/// # Example
/// ```
/// use iroha::model::commands::assets::CreateAsset;
///
/// let command_payload = &CreateAsset {
///     asset_name: "asset".to_string(),
///     domain_id: "domain".to_string(),
///     precision: 0,
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
/// use iroha::model::commands::{oob::Command,assets::CreateAsset};
///
/// let command_payload = &CreateAsset {
///     asset_name: "asset".to_string(),
///     domain_id: "domain".to_string(),
///     precision: 0,
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
/// # use iroha::model::commands::assets::CreateAsset;
/// #
/// # let command_payload = &CreateAsset {
/// #    asset_name: "asset".to_string(),
/// #    domain_id: "domain".to_string(),
/// #    precision: 0,
/// # };
/// # let result: Vec<u8> = command_payload.into();
/// let command_payload: CreateAsset  = result.into();
/// ```
impl std::convert::From<Vec<u8>> for CreateAsset {
    fn from(command_payload: Vec<u8>) -> Self {
        bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
    }
}

#[test]
fn create_asset_command_serialization_and_deserialization() {
    let expected = CreateAsset {
        asset_name: "asset".to_string(),
        domain_id: "domain".to_string(),
        precision: 0,
    };
    let actual: CreateAsset =
        bincode::deserialize(&bincode::serialize(&expected).unwrap()[..]).unwrap();
    assert_eq!(expected, actual);
}

/// The purpose of transfer asset command is to share assets within the account in peer
/// network: in the way that source account transfers assets to the target account.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TransferAsset {
    pub source_account_id: String,
    pub destination_account_id: String,
    pub asset_id: String,
    pub description: String,
    pub amount: f64,
}

/// # Example
/// ```
/// use iroha::model::commands::assets::TransferAsset;
///
/// let command_payload = &TransferAsset {
///    source_account_id: "source@domain".to_string(),
///    destination_account_id: "destination@domain".to_string(),
///    asset_id: "xor".to_string(),
///    description: "description".to_string(),
///    amount: 200.2,
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
/// use iroha::model::commands::{oob::Command,assets::TransferAsset};
///
/// let command_payload = &TransferAsset {
///    source_account_id: "source@domain".to_string(),
///    destination_account_id: "destination@domain".to_string(),
///    asset_id: "xor".to_string(),
///    description: "description".to_string(),
///    amount: 200.2,
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
/// # use iroha::model::commands::assets::TransferAsset;
/// #
/// # let command_payload = &TransferAsset {
/// #   source_account_id: "source@domain".to_string(),
/// #   destination_account_id: "destination@domain".to_string(),
/// #   asset_id: "xor".to_string(),
/// #   description: "description".to_string(),
/// #   amount: 200.2,
/// # };
/// # let result: Vec<u8> = command_payload.into();
/// let command_payload: TransferAsset  = result.into();
/// ```
impl std::convert::From<Vec<u8>> for TransferAsset {
    fn from(command_payload: Vec<u8>) -> Self {
        bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
    }
}

#[test]
fn transfer_asset_command_serialization_and_deserialization() {
    let expected = TransferAsset {
        source_account_id: "source@domain".to_string(),
        destination_account_id: "destination@domain".to_string(),
        asset_id: "xor".to_string(),
        description: "description".to_string(),
        amount: 200.2,
    };
    let actual: TransferAsset =
        bincode::deserialize(&bincode::serialize(&expected).unwrap()[..]).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn transfer_asset_command_into_command() {
    use crate::model::commands::oob::Command;
    let transfer_asset = &TransferAsset {
        source_account_id: "source@domain".to_string(),
        destination_account_id: "destination@domain".to_string(),
        asset_id: "xor".to_string(),
        description: "description".to_string(),
        amount: 200.2,
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
