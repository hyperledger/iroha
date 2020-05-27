use crate::prelude::*;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;
const PERMISSION_NOT_FOUND: &str = "Permission not found.";
const PERMISSION_OBJECT_NOT_SATISFIED: &str = "Permission object not satisfied.";

fn permission_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::new("permissions", "global")
}

#[derive(Clone, Debug, Default, Encode, Decode)]
pub struct Permissions {
    origin: BTreeMap<String, String>,
}

impl Permissions {
    pub fn new() -> Self {
        Permissions::default()
    }

    fn check_anything(&self) -> Result<(), String> {
        if self.origin.get("anything").is_some() {
            Ok(())
        } else {
            Err(PERMISSION_NOT_FOUND.to_string())
        }
    }

    fn check_add_domain(&self) -> Result<(), String> {
        if self.check_anything().is_ok() || self.origin.get("add_domain").is_some() {
            Ok(())
        } else {
            Err(PERMISSION_NOT_FOUND.to_string())
        }
    }

    fn check_register_account(&self, domain: &Option<String>) -> Result<(), String> {
        if self.check_anything().is_ok() {
            Ok(())
        } else {
            match self.origin.get("register_account") {
                Some(object) => {
                    if domain.as_ref().unwrap_or(&"any".to_string()) == object {
                        Ok(())
                    } else {
                        Err(format!("{}: {}", PERMISSION_OBJECT_NOT_SATISFIED, object))
                    }
                }
                None => Err(PERMISSION_NOT_FOUND.to_string()),
            }
        }
    }

    fn check_register_asset(&self, domain: &Option<String>) -> Result<(), String> {
        if self.check_anything().is_ok() {
            Ok(())
        } else {
            match self.origin.get("register_asset_definition") {
                Some(object) => {
                    if domain.as_ref().unwrap_or(&"any".to_string()) == object {
                        Ok(())
                    } else {
                        Err(format!("{}: {}", PERMISSION_OBJECT_NOT_SATISFIED, object))
                    }
                }
                None => Err(PERMISSION_NOT_FOUND.to_string()),
            }
        }
    }

    fn check_transfer_asset(
        &self,
        asset_definition_id: &AssetDefinitionId,
        domain: &Option<String>,
    ) -> Result<(), String> {
        if self.check_anything().is_ok() {
            Ok(())
        } else {
            match self.origin.get("transfer_asset") {
                Some(object) => {
                    if object
                        == &(asset_definition_id.to_string()
                            + domain.as_ref().unwrap_or(&"any".to_string()))
                    {
                        Ok(())
                    } else {
                        Err(format!("{}: {}", PERMISSION_OBJECT_NOT_SATISFIED, object))
                    }
                }
                None => Err(PERMISSION_NOT_FOUND.to_string()),
            }
        }
    }

    fn check_mint_asset(
        &self,
        asset_definition_id: &AssetDefinitionId,
        domain: &Option<String>,
    ) -> Result<(), String> {
        if self.check_anything().is_ok() {
            Ok(())
        } else {
            match self.origin.get("mint_asset") {
                Some(object) => {
                    if object
                        == &(asset_definition_id.to_string()
                            + domain.as_ref().unwrap_or(&"any".to_string()))
                    {
                        Ok(())
                    } else {
                        Err(format!("{}: {}", PERMISSION_OBJECT_NOT_SATISFIED, object))
                    }
                }
                None => Err(PERMISSION_NOT_FOUND.to_string()),
            }
        }
    }
}

impl From<(String, String)> for Permissions {
    fn from(permission: (String, String)) -> Self {
        let mut origin = BTreeMap::new();
        origin.insert(permission.0, permission.1);
        Permissions { origin }
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
            match self {
                PermissionInstruction::CanAnything(authority_account_id) => {
                    match world_state_view.read_asset(&AssetId {
                        definition_id: permission_asset_definition_id(),
                        account_id: authority_account_id.clone(),
                    }) {
                        Some(asset) => asset.permissions.check_anything(),
                        None => Err(PERMISSION_NOT_FOUND.to_string()),
                    }
                }
                PermissionInstruction::CanAddDomain(authority_account_id) => match world_state_view
                    .read_asset(&AssetId {
                        definition_id: permission_asset_definition_id(),
                        account_id: authority_account_id.clone(),
                    }) {
                    Some(asset) => asset.permissions.check_add_domain(),
                    None => Err(PERMISSION_NOT_FOUND.to_string()),
                },
                PermissionInstruction::CanRegisterAccount(
                    authority_account_id,
                    option_domain_id,
                ) => match world_state_view.read_asset(&AssetId {
                    definition_id: permission_asset_definition_id(),
                    account_id: authority_account_id.clone(),
                }) {
                    Some(asset) => asset.permissions.check_register_account(option_domain_id),
                    None => Err(PERMISSION_NOT_FOUND.to_string()),
                },
                PermissionInstruction::CanRegisterAssetDefinition(
                    authority_account_id,
                    option_domain_id,
                ) => match world_state_view.read_asset(&AssetId {
                    definition_id: permission_asset_definition_id(),
                    account_id: authority_account_id.clone(),
                }) {
                    Some(asset) => asset.permissions.check_register_asset(option_domain_id),
                    None => Err(PERMISSION_NOT_FOUND.to_string()),
                },
                PermissionInstruction::CanTransferAsset(
                    authority_account_id,
                    asset_definition_id,
                    option_domain_id,
                ) => match world_state_view.read_asset(&AssetId {
                    definition_id: permission_asset_definition_id(),
                    account_id: authority_account_id.clone(),
                }) {
                    Some(asset) => asset
                        .permissions
                        .check_transfer_asset(asset_definition_id, option_domain_id),
                    None => Err(PERMISSION_NOT_FOUND.to_string()),
                },
                PermissionInstruction::CanMintAsset(
                    authority_account_id,
                    asset_definition_id,
                    option_domain_id,
                ) => match world_state_view.read_asset(&AssetId {
                    definition_id: permission_asset_definition_id(),
                    account_id: authority_account_id.clone(),
                }) {
                    Some(asset) => asset
                        .permissions
                        .check_mint_asset(asset_definition_id, option_domain_id),
                    None => Err(PERMISSION_NOT_FOUND.to_string()),
                },
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::account::Id as AccountId;
        use crate::peer::PeerId;
        use std::collections::{HashMap, HashSet};

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
            let account_id = AccountId::new("ROOT", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset =
                Asset::with_permission(asset_id.clone(), ("anything".to_string(), "".to_string()));
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanAnything(account_id).execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_anything_without_an_account_should_fail_with_permission_not_found() {
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanAnything(AccountId::new("NOT_ROOT", "Company")).execute(
                    &mut WorldStateView::new(Peer::new(
                        PeerId {
                            address: "127.0.0.1:8080".to_string(),
                            public_key: [0; 32],
                        },
                        &Vec::new(),
                    ))
                )
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
            let asset = Asset::with_permission(
                asset_id.clone(),
                ("add_domain".to_string(), "".to_string()),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanAddDomain(account_id).execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_add_domain_without_an_account_should_fail_with_permission_not_found() {
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanAddDomain(AccountId::new("NOT_ROOT", "Company")).execute(
                    &mut WorldStateView::new(Peer::new(
                        PeerId {
                            address: "127.0.0.1:8080".to_string(),
                            public_key: [0; 32],
                        },
                        &Vec::new(),
                    ))
                )
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
            let asset = Asset::with_permission(
                asset_id.clone(),
                ("register_account".to_string(), "any".to_string()),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
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
                ("register_account".to_string(), domain_name.clone()),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanRegisterAccount(account_id, Some(domain_name))
                    .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_register_account_in_domain_should_fail_with_permission_object_not_found() {
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
            let wrong_domain_name = "AnotherCompany".to_string();
            let asset = Asset::with_permission(
                asset_id.clone(),
                ("register_account".to_string(), wrong_domain_name.clone()),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Err("Permission object not satisfied.: AnotherCompany".to_string()),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanRegisterAccount(account_id, None)
                    .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_register_account_without_an_account_fail_with_permission_not_found() {
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanRegisterAccount(
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
            );
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
            let asset = Asset::with_permission(
                asset_id.clone(),
                ("register_asset_definition".to_string(), "any".to_string()),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
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
                ("register_asset_definition".to_string(), domain_name.clone()),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Ok(()),
                PermissionInstruction::CanRegisterAssetDefinition(account_id, Some(domain_name))
                    .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_register_asset_definition_in_domain_should_fail_with_permission_object_not_found(
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
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let wrong_domain_name = "AnotherCompany".to_string();
            let asset = Asset::with_permission(
                asset_id.clone(),
                (
                    "register_asset_definition".to_string(),
                    wrong_domain_name.clone(),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Err("Permission object not satisfied.: AnotherCompany".to_string()),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanRegisterAssetDefinition(account_id, None)
                    .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_register_asset_definition_without_an_account_fail_with_permission_not_found() {
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanRegisterAssetDefinition(
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
            );
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
                (
                    "transfer_asset".to_string(),
                    transfer_asset_definition_id.to_string() + "any",
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
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
                (
                    "transfer_asset".to_string(),
                    transfer_asset_definition_id.to_string() + &domain_name,
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
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
        fn test_can_transfer_asset_in_domain_should_fail_with_permission_object_not_found() {
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
            let wrong_domain_name = "AnotherCompany".to_string();
            let asset = Asset::with_permission(
                asset_id.clone(),
                ("transfer_asset".to_string(), wrong_domain_name.clone()),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Err("Permission object not satisfied.: AnotherCompany".to_string()),
                PermissionInstruction::CanTransferAsset(
                    account_id,
                    AssetDefinitionId::new("XOR", "SORA"),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanTransferAsset(
                    account_id,
                    AssetDefinitionId::new("XOR", "SORA"),
                    None
                )
                .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_transfer_asset_without_an_account_fail_with_permission_not_found() {
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanTransferAsset(
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
            );
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
                (
                    "mint_asset".to_string(),
                    mint_asset_definition_id.to_string() + "any",
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
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
                (
                    "mint_asset".to_string(),
                    mint_asset_definition_id.to_string() + &domain_name,
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
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
        fn test_can_mint_asset_in_domain_should_fail_with_permission_object_not_found() {
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
            let wrong_domain_name = "AnotherCompany".to_string();
            let asset = Asset::with_permission(
                asset_id.clone(),
                ("mint_asset".to_string(), wrong_domain_name.clone()),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Err("Permission object not satisfied.: AnotherCompany".to_string()),
                PermissionInstruction::CanMintAsset(
                    account_id,
                    AssetDefinitionId::new("XOR", "SORA"),
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
            let mut world_state_view = WorldStateView::new(Peer {
                id: PeerId {
                    address: address.clone(),
                    public_key,
                },
                peers: HashSet::new(),
                listen_address: address,
                domains,
            });
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanMintAsset(
                    account_id,
                    AssetDefinitionId::new("XOR", "SORA"),
                    None
                )
                .execute(&mut world_state_view)
            );
        }

        #[test]
        fn test_can_mint_asset_without_an_account_fail_with_permission_not_found() {
            assert_eq!(
                Err(PERMISSION_NOT_FOUND.to_string()),
                PermissionInstruction::CanMintAsset(
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
            );
        }
    }
}
