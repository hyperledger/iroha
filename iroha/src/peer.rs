use crate::isi::Command;
use parity_scale_codec::{Decode, Encode};

/// The purpose of add peer command is to write into ledger the fact of peer addition into the
/// peer network. After a transaction with AddPeer has been committed, consensus and
/// synchronization components will start using it.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct AddPeer {
    pub peer: Peer,
}

/// # Example
/// ```
/// use iroha::{prelude::*, peer::AddPeer};
///
/// let command_payload = &AddPeer {
///     peer: Peer{
///         address: "address".to_string(),
///         peer_key: [63; 32],
///     },
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<&AddPeer> for Vec<u8> {
    fn from(command_payload: &AddPeer) -> Self {
        command_payload.encode()
    }
}

/// # Example
/// ```
/// use iroha::{prelude::*, isi::Command, peer::AddPeer};
///
/// let command_payload = &AddPeer {
///     peer: Peer{
///         address: "address".to_string(),
///         peer_key: [63; 32],
///     },
/// };
/// let result: Command = command_payload.into();
/// ```
impl std::convert::From<&AddPeer> for Command {
    fn from(command_payload: &AddPeer) -> Self {
        Command {
            version: 1,
            command_type: 2,
            payload: command_payload.into(),
        }
    }
}

/// # Example
/// ```
/// # use iroha::{prelude::*, isi::Command, peer::AddPeer};
/// # let command_payload = &AddPeer {
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
        AddPeer::decode(&mut command_payload.as_slice()).expect("Failed to deserialize payload.")
    }
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct Peer {
    pub address: String,
    pub peer_key: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_peer_command_serialization_and_deserialization() {
        let expected = AddPeer {
            peer: Peer {
                address: "address".to_string(),
                peer_key: [63; 32],
            },
        };
        let actual = <AddPeer>::decode(&mut expected.encode().as_slice()).unwrap();
        assert_eq!(expected, actual);
    }
}
