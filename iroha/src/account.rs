use crate::prelude::*;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Account {
    pub id: Id,
    pub assets: HashMap<Id, Asset>,
}

impl Account {
    pub fn new(account_id: Id) -> Self {
        Account {
            id: account_id,
            assets: HashMap::new(),
        }
    }
}

pub mod isi {
    use super::*;
    use crate::isi::Command;

    /// The purpose of add signatory command is to add an identifier to the account. Such
    /// identifier is a public key of another device or a public key of another user.
    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct AddSignatory {
        pub account_id: Id,
        pub public_key: [u8; 32],
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, account::isi::AddSignatory};
    ///
    /// let command_payload = &AddSignatory {
    ///     account_id: Id::new("account","domain"),
    ///     public_key: [63; 32],
    /// };
    /// let result: Vec<u8> = command_payload.into();
    /// ```
    impl std::convert::From<&AddSignatory> for Vec<u8> {
        fn from(command_payload: &AddSignatory) -> Self {
            bincode::serialize(command_payload).expect("Failed to serialize payload.")
        }
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, isi::Command, account::isi::AddSignatory};
    ///
    /// let command_payload = &AddSignatory {
    ///     account_id: Id::new("account","domain"),
    ///     public_key: [63; 32],
    /// };
    /// let result: Command = command_payload.into();
    /// ```
    impl std::convert::From<&AddSignatory> for Command {
        fn from(command_payload: &AddSignatory) -> Self {
            Command {
                version: 1,
                command_type: 3,
                payload: command_payload.into(),
            }
        }
    }

    /// # Example
    /// ```
    /// # use iroha::{prelude::*, account::isi::AddSignatory};
    /// #
    /// # let command_payload = &AddSignatory {
    /// #     account_id: Id::new("account","domain"),
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
            account_id: Id::new("account", "domain"),
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
        pub account_id: Id,
        pub role_name: String,
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, account::isi::AppendRole};
    ///
    /// let command_payload = &AppendRole {
    ///     account_id: Id::new("account","domain"),
    ///     role_name: "role".to_string(),
    /// };
    /// let result: Vec<u8> = command_payload.into();
    /// ```
    impl std::convert::From<&AppendRole> for Vec<u8> {
        fn from(command_payload: &AppendRole) -> Self {
            bincode::serialize(command_payload).expect("Failed to serialize payload.")
        }
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, isi::Command, account::isi::AppendRole};
    ///
    /// let command_payload = &AppendRole {
    ///     account_id: Id::new("account","domain"),
    ///     role_name: "role".to_string(),
    /// };
    /// let result: Command = command_payload.into();
    /// ```
    impl std::convert::From<&AppendRole> for Command {
        fn from(command_payload: &AppendRole) -> Self {
            Command {
                version: 1,
                command_type: 4,
                payload: command_payload.into(),
            }
        }
    }

    /// # Example
    /// ```
    /// # use iroha::{prelude::*, account::isi::AppendRole};
    /// #
    /// # let command_payload = &AppendRole {
    /// #     account_id: Id::new("account","domain"),
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
            account_id: Id::new("account", "domain"),
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
        pub account_id: Id,
        pub domain_name: String,
        pub public_key: [u8; 32],
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, account::isi::CreateAccount};
    ///
    /// let command_payload = &CreateAccount {
    ///     account_id: Id::new("account", "domain"),
    ///     domain_name: "domain".to_string(),
    ///     public_key: [63; 32],
    /// };
    /// let result: Vec<u8> = command_payload.into();
    /// ```
    impl std::convert::From<&CreateAccount> for Vec<u8> {
        fn from(command_payload: &CreateAccount) -> Self {
            bincode::serialize(command_payload).expect("Failed to serialize payload.")
        }
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, isi::Command, account::isi::CreateAccount};
    ///
    /// let command_payload = &CreateAccount {
    ///     account_id: Id::new("account", "domain"),
    ///     domain_name: "domain".to_string(),
    ///     public_key: [63; 32],
    /// };
    /// let result: Command = command_payload.into();
    /// ```
    impl std::convert::From<&CreateAccount> for Command {
        fn from(command_payload: &CreateAccount) -> Self {
            Command {
                version: 1,
                command_type: 5,
                payload: command_payload.into(),
            }
        }
    }

    /// # Example
    /// ```
    /// # use iroha::{prelude::*, account::isi::CreateAccount};
    /// #
    /// # let command_payload = &CreateAccount {
    /// #     account_id: Id::new("account", "domain"),
    /// #     domain_name: "domain".to_string(),
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
            account_id: Id::new("account", "domain"),
            domain_name: "domain".to_string(),
            public_key: [63; 32],
        };
        let actual: CreateAccount =
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
    /// use iroha::{prelude::*, account::isi::CreateRole};
    ///
    /// let command_payload = &CreateRole {
    ///     role_name: "user".to_string(),
    ///     permissions: Vec::new(),
    /// };
    /// let result: Vec<u8> = command_payload.into();
    /// ```
    impl std::convert::From<&CreateRole> for Vec<u8> {
        fn from(command_payload: &CreateRole) -> Self {
            bincode::serialize(command_payload).expect("Failed to serialize payload.")
        }
    }

    /// # Example
    /// ```
    /// use iroha::{prelude::*, isi::Command, account::isi::CreateRole};
    ///
    /// let command_payload = &CreateRole {
    ///     role_name: "user".to_string(),
    ///     permissions: Vec::new(),
    /// };
    /// let result: Command = command_payload.into();
    /// ```
    impl std::convert::From<&CreateRole> for Command {
        fn from(command_payload: &CreateRole) -> Self {
            Command {
                version: 1,
                command_type: 8,
                payload: command_payload.into(),
            }
        }
    }

    /// # Example
    /// ```
    /// # use iroha::{prelude::*, account::isi::CreateRole};
    /// #
    /// # let command_payload = &CreateRole {
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
}
