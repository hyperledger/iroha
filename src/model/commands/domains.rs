use crate::model::commands::isi::Command;

/// The purpose of create domain command is to make new domain in Iroha network, which is a
/// group of accounts.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CreateDomain {
    pub domain_id: String,
    pub default_role: String,
}

/// # Example
/// ```
/// use iroha::model::commands::domains::CreateDomain;
///
/// let command_payload = &CreateDomain {
///     domain_id: "domain".to_string(),
///     default_role: "user".to_string(),
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<&CreateDomain> for Vec<u8> {
    fn from(command_payload: &CreateDomain) -> Self {
        bincode::serialize(command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// use iroha::model::commands::{isi::Command,domains::CreateDomain};
///
/// let command_payload = &CreateDomain {
///     domain_id: "domain".to_string(),
///     default_role: "user".to_string(),
/// };
/// let result: Command = command_payload.into();
/// ```
impl std::convert::From<&CreateDomain> for Command {
    fn from(command_payload: &CreateDomain) -> Self {
        Command {
            version: 1,
            command_type: 7,
            payload: command_payload.into(),
        }
    }
}

/// # Example
/// ```
/// # use iroha::model::commands::domains::CreateDomain;
/// #
/// # let command_payload = &CreateDomain {
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
