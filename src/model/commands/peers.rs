/// The purpose of add peer command is to write into ledger the fact of peer addition into the
/// peer network. After a transaction with AddPeer has been committed, consensus and
/// synchronization components will start using it.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AddPeer {
    pub peer: Peer,
}

/// # Example
/// ```
/// use iroha::model::commands::peers::{AddPeer, Peer};
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
/// # use iroha::model::commands::peers::{AddPeer, Peer};
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
