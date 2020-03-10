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
/// use iroha::model::commands::AddAssetQuantity;
///
/// let command_payload = AddAssetQuantity {
///     asset_id: "asset@domain".to_string(),
///     amount: 200.02,
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<AddAssetQuantity> for Vec<u8> {
    fn from(command_payload: AddAssetQuantity) -> Self {
        bincode::serialize(&command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::model::commands::AddAssetQuantity;
/// # let command_payload = AddAssetQuantity {
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
/// The purpose of add peer command is to write into ledger the fact of peer addition into the
/// peer network. After a transaction with AddPeer has been committed, consensus and
/// synchronization components will start using it.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AddPeer {
    pub peer: Peer,
}

/// # Example
/// ```
/// use iroha::model::commands::{AddPeer, Peer};
///
/// let command_payload = AddPeer {
///     peer: Peer{
///         address: "address".to_string(),
///         peer_key: [63; 32],
///     },
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<AddPeer> for Vec<u8> {
    fn from(command_payload: AddPeer) -> Self {
        bincode::serialize(&command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::model::commands::{AddPeer, Peer};
/// # let command_payload = AddPeer {
/// #     peer: Peer{
/// #         address: "address".to_string(),
/// #         peer_key: [63; 32],
/// #     },
/// # };
/// # let result: Vec<u8> = command_payload.into();
/// let command_payload: AddPeer = result.into();
/// ```
impl std::convert::From<Vec<u8>> for AddPeer {
    fn from(command_payload: Vec<u8>) -> Self {
        bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Peer {
    pub address: String,
    pub peer_key: [u8; 32],
}

#[test]
fn add_peer_command_serialization_and_deserialization() {
    let expected = AddPeer {
        peer: Peer {
            address: "address".to_string(),
            peer_key: [63; 32],
        },
    };
    let actual: AddPeer =
        bincode::deserialize(&bincode::serialize(&expected).unwrap()[..]).unwrap();
    assert_eq!(expected, actual);
}
/// The purpose of add signatory command is to add an identifier to the account. Such
/// identifier is a public key of another device or a public key of another user.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AddSignatory {
    pub account_id: String,
    pub public_key: [u8; 32],
}

/// # Example
/// ```
/// use iroha::model::commands::AddSignatory;
///
/// let command_payload = AddSignatory {
///     account_id: "account@domain".to_string(),
///     public_key: [63; 32],
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<AddSignatory> for Vec<u8> {
    fn from(command_payload: AddSignatory) -> Self {
        bincode::serialize(&command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::model::commands::AddSignatory;
/// #
/// # let command_payload = AddSignatory {
/// #     account_id: "account@domain".to_string(),
/// #     public_key: [63; 32],
/// # };
/// # let result: Vec<u8> = command_payload.into();
/// let command_payload: AddSignatory = result.into();
/// ```
impl std::convert::From<Vec<u8>> for AddSignatory {
    fn from(command_payload: Vec<u8>) -> Self {
        bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
    }
}

#[test]
fn add_signatory_command_serialization_and_deserialization() {
    let expected = AddSignatory {
        account_id: "account@domain".to_string(),
        public_key: [63; 32],
    };
    let actual: AddSignatory =
        bincode::deserialize(&bincode::serialize(&expected).unwrap()[..]).unwrap();
    assert_eq!(expected, actual);
}

/// The purpose of append role command is to promote an account to some created role in the
/// system, where a role is a set of permissions account has to perform an action (command or
/// query).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AppendRole {
    pub account_id: String,
    pub role_name: String,
}

/// # Example
/// ```
/// use iroha::model::commands::AppendRole;
///
/// let command_payload = AppendRole {
///     account_id: "account@domain".to_string(),
///     role_name: "role".to_string(),
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<AppendRole> for Vec<u8> {
    fn from(command_payload: AppendRole) -> Self {
        bincode::serialize(&command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::model::commands::AppendRole;
/// #
/// # let command_payload = AppendRole {
/// #     account_id: "account@domain".to_string(),
/// #     role_name: "role".to_string(),
/// # };
/// # let result: Vec<u8> = command_payload.into();
/// let command_payload: AppendRole  = result.into();
/// ```
impl std::convert::From<Vec<u8>> for AppendRole {
    fn from(command_payload: Vec<u8>) -> Self {
        bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
    }
}

#[test]
fn append_role_command_serialization_and_deserialization() {
    let expected = AppendRole {
        account_id: "account@domain".to_string(),
        role_name: "role".to_string(),
    };
    let actual: AppendRole =
        bincode::deserialize(&bincode::serialize(&expected).unwrap()[..]).unwrap();
    assert_eq!(expected, actual);
}

/// The purpose of create account command is to make entity in the system, capable of sending
/// transactions or queries, storing signatories, personal data and identifiers.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CreateAccount {
    pub account_name: String,
    pub domain_id: String,
    pub public_key: [u8; 32],
}

/// # Example
/// ```
/// use iroha::model::commands::CreateAccount;
///
/// let command_payload = CreateAccount {
///     account_name: "account".to_string(),
///     domain_id: "domain".to_string(),
///     public_key: [63; 32],
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<CreateAccount> for Vec<u8> {
    fn from(command_payload: CreateAccount) -> Self {
        bincode::serialize(&command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::model::commands::CreateAccount;
/// #
/// # let command_payload = CreateAccount {
/// #     account_name: "account".to_string(),
/// #     domain_id: "domain".to_string(),
/// #     public_key: [63; 32],
/// # };
/// # let result: Vec<u8> = command_payload.into();
/// let command_payload: CreateAccount  = result.into();
/// ```
impl std::convert::From<Vec<u8>> for CreateAccount {
    fn from(command_payload: Vec<u8>) -> Self {
        bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
    }
}

#[test]
fn create_account_command_serialization_and_deserialization() {
    let expected = CreateAccount {
        account_name: "account".to_string(),
        domain_id: "domain".to_string(),
        public_key: [63; 32],
    };
    let actual: CreateAccount =
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
/// use iroha::model::commands::CreateAsset;
///
/// let command_payload = CreateAsset {
///     asset_name: "asset".to_string(),
///     domain_id: "domain".to_string(),
///     precision: 0,
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<CreateAsset> for Vec<u8> {
    fn from(command_payload: CreateAsset) -> Self {
        bincode::serialize(&command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::model::commands::CreateAsset;
/// #
/// # let command_payload = CreateAsset {
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

/// The purpose of create domain command is to make new domain in Iroha network, which is a
/// group of accounts.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CreateDomain {
    pub domain_id: String,
    pub default_role: String,
}

/// # Example
/// ```
/// use iroha::model::commands::CreateDomain;
///
/// let command_payload = CreateDomain {
///     domain_id: "domain".to_string(),
///     default_role: "user".to_string(),
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<CreateDomain> for Vec<u8> {
    fn from(command_payload: CreateDomain) -> Self {
        bincode::serialize(&command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::model::commands::CreateDomain;
/// #
/// # let command_payload = CreateDomain {
/// #    domain_id: "domain".to_string(),
/// #   default_role: "user".to_string(),
/// # };
/// # let result: Vec<u8> = command_payload.into();
/// let command_payload: CreateDomain  = result.into();
/// ```
impl std::convert::From<Vec<u8>> for CreateDomain {
    fn from(command_payload: Vec<u8>) -> Self {
        bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
    }
}

#[test]
fn create_domain_command_serialization_and_deserialization() {
    let expected = CreateDomain {
        domain_id: "domain".to_string(),
        default_role: "user".to_string(),
    };
    let actual: CreateDomain =
        bincode::deserialize(&bincode::serialize(&expected).unwrap()[..]).unwrap();
    assert_eq!(expected, actual);
}

/// The purpose of create role command is to create a new role in the system from the set of
/// permissions. Combining different permissions into roles, maintainers of Iroha peer network
/// can create customized security model.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CreateRole {
    pub role_name: String,
    pub permissions: Vec<String>,
}

/// # Example
/// ```
/// use iroha::model::commands::CreateRole;
///
/// let command_payload = CreateRole {
///     role_name: "user".to_string(),
///     permissions: Vec::new(),
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<CreateRole> for Vec<u8> {
    fn from(command_payload: CreateRole) -> Self {
        bincode::serialize(&command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::model::commands::CreateRole;
/// #
/// # let command_payload = CreateRole {
/// #    role_name: "user".to_string(),
/// #    permissions: Vec::new(),
/// # };
/// # let result: Vec<u8> = command_payload.into();
/// let command_payload: CreateRole  = result.into();
/// ```
impl std::convert::From<Vec<u8>> for CreateRole {
    fn from(command_payload: Vec<u8>) -> Self {
        bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
    }
}

#[test]
fn create_role_command_serialization_and_deserialization() {
    let expected = CreateRole {
        role_name: "user".to_string(),
        permissions: Vec::new(),
    };
    let actual: CreateRole =
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
/// use iroha::model::commands::TransferAsset;
///
/// let command_payload = TransferAsset {
///    source_account_id: "source@domain".to_string(),
///    destination_account_id: "destination@domain".to_string(),
///    asset_id: "xor".to_string(),
///    description: "description".to_string(),
///    amount: 200.2,
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<TransferAsset> for Vec<u8> {
    fn from(command_payload: TransferAsset) -> Self {
        bincode::serialize(&command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// use iroha::model::Command;
/// use iroha::model::commands::TransferAsset;
///
/// let command_payload = TransferAsset {
///    source_account_id: "source@domain".to_string(),
///    destination_account_id: "destination@domain".to_string(),
///    asset_id: "xor".to_string(),
///    description: "description".to_string(),
///    amount: 200.2,
/// };
/// let result: Command = command_payload.into();
/// ```
impl std::convert::From<TransferAsset> for crate::model::Command {
    fn from(command_payload: TransferAsset) -> Self {
        crate::model::Command {
            version: 1,
            command_type: 17,
            payload: command_payload.into(),
        }
    }
}

/// # Example
/// ```
/// # use iroha::model::commands::TransferAsset;
/// #
/// # let command_payload = TransferAsset {
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
    use super::Command;
    let transfer_asset = TransferAsset {
        source_account_id: "source@domain".to_string(),
        destination_account_id: "destination@domain".to_string(),
        asset_id: "xor".to_string(),
        description: "description".to_string(),
        amount: 200.2,
    };
    let expected = Command {
        version: 1,
        command_type: 17,
        payload: transfer_asset.clone().into(),
    };
    let actual: Command = transfer_asset.into();
    assert_eq!(expected.version, actual.version);
    assert_eq!(expected.command_type, actual.command_type);
    assert_eq!(expected.payload, actual.payload);
}
