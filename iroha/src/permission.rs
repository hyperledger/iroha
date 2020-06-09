use crate::prelude::*;
use parity_scale_codec::{Decode, Encode};
const PERMISSION_NOT_FOUND: &str = "Permission not found.";

pub fn permission_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::new("permissions", "global")
}

#[derive(Clone, Debug, Default, Encode, Decode)]
pub struct Permissions {
    origin: Vec<Permission>,
}

#[derive(Clone, Debug, Encode, Decode, PartialEq)]
pub enum Permission {
    Anything,
    AddDomain,
    AddListener,
    RegisterAssetDefinition(Option<<Domain as Identifiable>::Id>),
    RegisterAccount(Option<<Domain as Identifiable>::Id>),
    MintAsset(
        Option<<Domain as Identifiable>::Id>,
        Option<<AssetDefinition as Identifiable>::Id>,
    ),
    TransferAsset(
        Option<<Domain as Identifiable>::Id>,
        Option<<AssetDefinition as Identifiable>::Id>,
    ),
}

impl Permissions {
    pub fn new() -> Self {
        Permissions::default()
    }

    pub fn single(permission: Permission) -> Self {
        Permissions {
            origin: vec![permission],
        }
    }

    fn check(&self, permission: Permission) -> Result<(), String> {
        if self.origin.contains(&Permission::Anything) || self.origin.contains(&permission) {
            Ok(())
        } else {
            Err(format!("Error: {}, {:?}", PERMISSION_NOT_FOUND, self))
        }
    }
}

pub mod isi {
    use super::*;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};

    /// Iroha special instructions related to `Permission`.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum PermissionInstruction {
        CanAnything(<Account as Identifiable>::Id),
        CanAddListener(<Account as Identifiable>::Id),
        CanAddDomain(<Account as Identifiable>::Id),
        CanRegisterAccount(
            <Account as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
        CanRegisterAssetDefinition(
            <Account as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
        CanTransferAsset(
            <Account as Identifiable>::Id,
            <AssetDefinition as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
        CanMintAsset(
            <Account as Identifiable>::Id,
            <AssetDefinition as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
    }

    impl PermissionInstruction {
        /// Defines the variant of the underlying instructions and executes them on `WorldStateView`.
        /// These Iroha Special Instructions should be used to check permissions prior to other
        /// instructions execution.
        /// If permission check is satysfied - `Result::Ok(())` will be return.
        /// If permission check results in failure - `Result::Err(String)` will be return.
        pub fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            use PermissionInstruction::*;
            match self {
                CanAnything(authority_account_id)
                | CanAddDomain(authority_account_id)
                | CanAddListener(authority_account_id)
                | CanRegisterAccount(authority_account_id, ..)
                | CanRegisterAssetDefinition(authority_account_id, ..)
                | CanTransferAsset(authority_account_id, ..)
                | CanMintAsset(authority_account_id, ..) => {
                    match world_state_view.read_asset(&AssetId {
                        definition_id: permission_asset_definition_id(),
                        account_id: authority_account_id.clone(),
                    }) {
                        Some(asset) => asset.permissions.check(self.into()),
                        None => Err(format!("Error: {}, {:?}", PERMISSION_NOT_FOUND, self)),
                    }
                }
            }
        }
    }

    impl From<&PermissionInstruction> for Permission {
        fn from(instruction: &PermissionInstruction) -> Self {
            match instruction {
                PermissionInstruction::CanAnything(_) => Permission::Anything,
                PermissionInstruction::CanAddDomain(_) => Permission::AddDomain,
                PermissionInstruction::CanAddListener(_) => Permission::AddListener,
                PermissionInstruction::CanRegisterAccount(_, option_domain_id) => {
                    Permission::RegisterAccount(option_domain_id.clone())
                }
                PermissionInstruction::CanRegisterAssetDefinition(_, option_domain_id) => {
                    Permission::RegisterAssetDefinition(option_domain_id.clone())
                }
                PermissionInstruction::CanTransferAsset(
                    _,
                    asset_definition_id,
                    option_domain_id,
                ) => Permission::TransferAsset(
                    option_domain_id.clone(),
                    Some(asset_definition_id.clone()),
                ),
                PermissionInstruction::CanMintAsset(_, asset_definition_id, option_domain_id) => {
                    Permission::MintAsset(
                        option_domain_id.clone(),
                        Some(asset_definition_id.clone()),
                    )
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::account::Id as AccountId;
        use crate::peer::PeerId;
        use std::collections::HashMap;

        #[test]
        fn test_can_anything_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
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
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanAnything(account_id).execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_anything_without_permission_should_fail_with_permission_not_found() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("NOT_ROOT", &domain_name);
            let account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert!(PermissionInstruction::CanAnything(account_id)
                .execute(&mut world_state_view)
                .unwrap_err()
                .contains(PERMISSION_NOT_FOUND));
        }

        #[test]
        fn test_can_anything_without_an_account_should_fail_with_permission_not_found() {
            assert!(
                PermissionInstruction::CanAnything(AccountId::new("NOT_ROOT", "Company"))
                    .execute(&mut WorldStateView::new(Peer::new(
                        PeerId {
                            address: "127.0.0.1:8080".to_string(),
                            public_key: [0; 32],
                        },
                        &Vec::new(),
                    )))
                    .unwrap_err()
                    .contains(PERMISSION_NOT_FOUND)
            );
        }

        #[test]
        fn test_can_add_domain_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset = Asset::with_permission(asset_id.clone(), Permission::AddDomain);
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanAddDomain(account_id).execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_add_domain_without_permission_should_fail_with_permission_not_found() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("NOT_ROOT", &domain_name);
            let account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert!(PermissionInstruction::CanAddDomain(account_id)
                .execute(&mut world_state_view)
                .unwrap_err()
                .contains(PERMISSION_NOT_FOUND));
        }

        #[test]
        fn test_can_add_domain_without_an_account_should_fail_with_permission_not_found() {
            assert!(
                PermissionInstruction::CanAddDomain(AccountId::new("NOT_ROOT", "Company"))
                    .execute(&mut WorldStateView::new(Peer::new(
                        PeerId {
                            address: "127.0.0.1:8080".to_string(),
                            public_key: [0; 32],
                        },
                        &Vec::new(),
                    )))
                    .unwrap_err()
                    .contains(PERMISSION_NOT_FOUND)
            );
        }

        #[test]
        fn test_can_add_listener_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset = Asset::with_permission(asset_id.clone(), Permission::AddListener);
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanAddListener(account_id).execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_add_listener_without_permission_should_fail_with_permission_not_found() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("NOT_ROOT", &domain_name);
            let account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert!(PermissionInstruction::CanAddListener(account_id)
                .execute(&mut world_state_view)
                .unwrap_err()
                .contains(PERMISSION_NOT_FOUND));
        }

        #[test]
        fn test_can_add_listener_without_an_account_should_fail_with_permission_not_found() {
            assert!(
                PermissionInstruction::CanAddListener(AccountId::new("NOT_ROOT", "Company"))
                    .execute(&mut WorldStateView::new(Peer::new(
                        PeerId {
                            address: "127.0.0.1:8080".to_string(),
                            public_key: [0; 32],
                        },
                        &Vec::new(),
                    )))
                    .unwrap_err()
                    .contains(PERMISSION_NOT_FOUND)
            );
        }

        #[test]
        fn test_can_register_account_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset = Asset::with_permission(asset_id.clone(), Permission::RegisterAccount(None));
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanRegisterAccount(account_id, None)
                    .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_register_account_in_domain_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset = Asset::with_permission(
                asset_id.clone(),
                Permission::RegisterAccount(Some(domain_name.clone())),
            );
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanRegisterAccount(account_id, Some(domain_name))
                    .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_register_account_without_permission_should_fail_with_permission_not_found() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert!(PermissionInstruction::CanRegisterAccount(account_id, None)
                .execute(&mut world_state_view)
                .unwrap_err()
                .contains(PERMISSION_NOT_FOUND));
        }

        #[test]
        fn test_can_register_account_without_an_account_fail_with_permission_not_found() {
            assert!(PermissionInstruction::CanRegisterAccount(
                AccountId::new("NOT_ROOT", "Company"),
                None
            )
            .execute(&mut WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:8080".to_string(),
                    public_key: [0; 32],
                },
                &Vec::new(),
            )))
            .unwrap_err()
            .contains(PERMISSION_NOT_FOUND));
        }

        #[test]
        fn test_can_register_asset_definition_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset =
                Asset::with_permission(asset_id.clone(), Permission::RegisterAssetDefinition(None));
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanRegisterAssetDefinition(account_id, None)
                    .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_register_asset_definition_in_domain_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset = Asset::with_permission(
                asset_id.clone(),
                Permission::RegisterAssetDefinition(Some(domain_name.clone())),
            );
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanRegisterAssetDefinition(account_id, Some(domain_name))
                    .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_register_asset_definition_without_permission_should_fail_with_permission_not_found(
        ) {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert!(
                PermissionInstruction::CanRegisterAssetDefinition(account_id, None)
                    .execute(&mut world_state_view)
                    .unwrap_err()
                    .contains(PERMISSION_NOT_FOUND)
            );
        }

        #[test]
        fn test_can_register_asset_definition_without_an_account_fail_with_permission_not_found() {
            assert!(PermissionInstruction::CanRegisterAssetDefinition(
                AccountId::new("NOT_ROOT", "Company"),
                None
            )
            .execute(&mut WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:8080".to_string(),
                    public_key: [0; 32],
                },
                &Vec::new(),
            )))
            .unwrap_err()
            .contains(PERMISSION_NOT_FOUND));
        }

        #[test]
        fn test_can_transfer_asset_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let transfer_asset_definition_id = AssetDefinitionId::new("XOR", "SORA");
            let asset = Asset::with_permission(
                asset_id.clone(),
                Permission::TransferAsset(None, Some(transfer_asset_definition_id.clone())),
            );
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanTransferAsset(
                    account_id,
                    transfer_asset_definition_id,
                    None
                )
                .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_transfer_asset_in_domain_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let transfer_asset_definition_id = AssetDefinitionId::new("XOR", "SORA");
            let asset = Asset::with_permission(
                asset_id.clone(),
                Permission::TransferAsset(
                    Some(domain_name.clone()),
                    Some(transfer_asset_definition_id.clone()),
                ),
            );
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanTransferAsset(
                    account_id,
                    transfer_asset_definition_id,
                    Some(domain_name)
                )
                .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_transfer_asset_without_permission_should_fail_with_permission_not_found() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert!(PermissionInstruction::CanTransferAsset(
                account_id,
                AssetDefinitionId::new("XOR", "SORA"),
                None
            )
            .execute(&mut world_state_view)
            .unwrap_err()
            .contains(PERMISSION_NOT_FOUND));
        }

        #[test]
        fn test_can_transfer_asset_without_an_account_fail_with_permission_not_found() {
            assert!(PermissionInstruction::CanTransferAsset(
                AccountId::new("NOT_ROOT", "Company"),
                AssetDefinitionId::new("XOR", "SORA"),
                None
            )
            .execute(&mut WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:8080".to_string(),
                    public_key: [0; 32],
                },
                &Vec::new(),
            )))
            .unwrap_err()
            .contains(PERMISSION_NOT_FOUND));
        }

        #[test]
        fn test_can_mint_asset_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let mint_asset_definition_id = AssetDefinitionId::new("XOR", "SORA");
            let asset = Asset::with_permission(
                asset_id.clone(),
                Permission::MintAsset(None, Some(mint_asset_definition_id.clone())),
            );
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanMintAsset(account_id, mint_asset_definition_id, None)
                    .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_mint_asset_in_domain_should_pass() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let mint_asset_definition_id = AssetDefinitionId::new("XOR", "SORA");
            let asset = Asset::with_permission(
                asset_id.clone(),
                Permission::MintAsset(
                    Some(domain_name.clone()),
                    Some(mint_asset_definition_id.clone()),
                ),
            );
            let mut account = Account::new(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: address.clone(),
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanMintAsset(
                    account_id,
                    mint_asset_definition_id,
                    Some(domain_name)
                )
                .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_mint_asset_without_permission_should_fail_with_permission_not_found() {
            let domain_name = "Company".to_string();
            let public_key = [0; 32];
            let mut asset_definitions = HashMap::new();
            let asset_definition_id = permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let account_id = AccountId::new("ROOT", &domain_name);
            let account = Account::new(&account_id.name, &account_id.domain_name, public_key);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name, domain);
            let address = "127.0.0.1:8080".to_string();
            let mut world_state_view = WorldStateView::new(Peer::with_domains(
                PeerId {
                    address,
                    public_key,
                },
                &Vec::new(),
                domains,
            ));
            assert!(PermissionInstruction::CanMintAsset(
                account_id,
                AssetDefinitionId::new("XOR", "SORA"),
                None
            )
            .execute(&mut world_state_view)
            .unwrap_err()
            .contains(PERMISSION_NOT_FOUND));
        }

        #[test]
        fn test_can_mint_asset_without_an_account_fail_with_permission_not_found() {
            assert!(PermissionInstruction::CanMintAsset(
                AccountId::new("NOT_ROOT", "Company"),
                AssetDefinitionId::new("XOR", "SORA"),
                None
            )
            .execute(&mut WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:8080".to_string(),
                    public_key: [0; 32],
                },
                &Vec::new(),
            )))
            .unwrap_err()
            .contains(PERMISSION_NOT_FOUND));
        }
    }
}
