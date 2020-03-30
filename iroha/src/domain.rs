use crate::prelude::*;
use std::collections::HashMap;

type Name = String;

#[derive(Debug)]
pub struct Domain {
    pub name: Name,
    pub accounts: HashMap<Id, Account>,
}

impl Domain {
    pub fn new(name: Name) -> Self {
        Domain {
            name,
            accounts: HashMap::new(),
        }
    }
}

pub mod isi {
    use crate::isi::Command;
    use parity_scale_codec::{Decode, Encode};

    /// The purpose of create domain command is to make new domain in Iroha network, which is a
    /// group of accounts.
    #[derive(Clone, Debug, PartialEq, Encode, Decode)]
    pub struct CreateDomain {
        pub domain_name: String,
        pub default_role: String,
    }

    /// # Example
    /// ```
    /// use iroha::domain::isi::CreateDomain;
    ///
    /// let command_payload = &CreateDomain {
    ///     domain_name: "domain".to_string(),
    ///     default_role: "user".to_string(),
    /// };
    /// let result: Vec<u8> = command_payload.into();
    /// ```
    impl std::convert::From<&CreateDomain> for Vec<u8> {
        fn from(command_payload: &CreateDomain) -> Self {
            command_payload.encode()
        }
    }

    /// # Example
    /// ```
    /// use iroha::{isi::Command, domain::isi::CreateDomain};
    ///
    /// let command_payload = &CreateDomain {
    ///     domain_name: "domain".to_string(),
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
    /// # use iroha::domain::isi::CreateDomain;
    /// #
    /// # let command_payload = &CreateDomain {
    /// #    domain_name: "domain".to_string(),
    /// #   default_role: "user".to_string(),
    /// # };
    /// # let result: Vec<u8> = command_payload.into();
    /// let command_payload: CreateDomain  = result.into();
    /// ```
    impl std::convert::From<Vec<u8>> for CreateDomain {
        fn from(command_payload: Vec<u8>) -> Self {
            CreateDomain::decode(&mut command_payload.as_slice())
                .expect("Failed to deserialize payload.")
        }
    }

    #[test]
    fn create_domain_command_serialization_and_deserialization() {
        let expected = CreateDomain {
            domain_name: "domain".to_string(),
            default_role: "user".to_string(),
        };
        let actual = CreateDomain::decode(&mut expected.encode().as_slice()).unwrap();
        assert_eq!(expected, actual);
    }
}
