use crate::permission::*;
use crate::prelude::*;
use iroha_crypto::KeyPair;
use iroha_data_model::prelude::*;
use std::collections::BTreeMap;

#[test]
fn test_can_anything_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(PermissionInstruction::CanAnything(account_id)
        .execute(&mut world_state_view)
        .is_ok());
}

#[test]
fn test_can_anything_without_permission_should_fail_with_permission_not_found() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id),
    );
    let account_id = AccountId::new("NOT_ROOT", &domain_name);
    let account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
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
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(PermissionInstruction::CanAddDomain(account_id)
        .execute(&mut world_state_view)
        .is_ok());
}

#[test]
fn test_can_add_domain_without_permission_should_fail_with_permission_not_found() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id),
    );
    let account_id = AccountId::new("NOT_ROOT", &domain_name);
    let account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
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
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let asset = Asset::with_permission(asset_id.clone(), Permission::AddTrigger);
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(PermissionInstruction::CanAddTrigger(account_id)
        .execute(&mut world_state_view)
        .is_ok());
}

#[test]
fn test_can_add_listener_without_permission_should_fail_with_permission_not_found() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id),
    );
    let account_id = AccountId::new("NOT_ROOT", &domain_name);
    let account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(PermissionInstruction::CanAddTrigger(account_id)
        .execute(&mut world_state_view)
        .unwrap_err()
        .contains(PERMISSION_NOT_FOUND));
}

#[test]
fn test_can_add_listener_without_an_account_should_fail_with_permission_not_found() {
    assert!(
        PermissionInstruction::CanAddTrigger(AccountId::new("NOT_ROOT", "Company"))
            .execute(&mut WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:8080".to_string(),
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
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
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(PermissionInstruction::CanRegisterAccount(account_id, None)
        .execute(&mut world_state_view)
        .is_ok());
}

#[test]
fn test_can_register_account_in_domain_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name.clone(), domain);
    let address = "127.0.0.1:8080".to_string();
    let mut world_state_view = WorldStateView::new(Peer::with_domains(
        PeerId {
            address,
            public_key,
        },
        &Vec::new(),
        domains,
    ));
    assert!(
        PermissionInstruction::CanRegisterAccount(account_id, Some(domain_name))
            .execute(&mut world_state_view)
            .is_ok()
    );
}

#[test]
fn test_can_register_account_without_permission_should_fail_with_permission_not_found() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id),
    );
    let account_id = AccountId::new("ROOT", &domain_name);
    let account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(PermissionInstruction::CanRegisterAccount(account_id, None)
        .execute(&mut world_state_view)
        .unwrap_err()
        .contains(PERMISSION_NOT_FOUND));
}

#[test]
fn test_can_register_account_without_an_account_fail_with_permission_not_found() {
    assert!(
        PermissionInstruction::CanRegisterAccount(AccountId::new("NOT_ROOT", "Company"), None)
            .execute(&mut WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:8080".to_string(),
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                },
                &Vec::new(),
            )))
            .unwrap_err()
            .contains(PERMISSION_NOT_FOUND)
    );
}

#[test]
fn test_can_register_asset_definition_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let asset = Asset::with_permission(asset_id.clone(), Permission::RegisterAssetDefinition(None));
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(
        PermissionInstruction::CanRegisterAssetDefinition(account_id, None)
            .execute(&mut world_state_view)
            .is_ok()
    );
}

#[test]
fn test_can_register_asset_definition_in_domain_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name.clone(), domain);
    let address = "127.0.0.1:8080".to_string();
    let mut world_state_view = WorldStateView::new(Peer::with_domains(
        PeerId {
            address,
            public_key,
        },
        &Vec::new(),
        domains,
    ));
    assert!(
        PermissionInstruction::CanRegisterAssetDefinition(account_id, Some(domain_name))
            .execute(&mut world_state_view)
            .is_ok()
    );
}

#[test]
fn test_can_register_asset_definition_without_permission_should_fail_with_permission_not_found() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id),
    );
    let account_id = AccountId::new("ROOT", &domain_name);
    let account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        },
        &Vec::new(),
    )))
    .unwrap_err()
    .contains(PERMISSION_NOT_FOUND));
}

#[test]
fn test_can_transfer_asset_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(PermissionInstruction::CanTransferAsset(
        account_id,
        transfer_asset_definition_id,
        None
    )
    .execute(&mut world_state_view)
    .is_ok());
}

#[test]
fn test_can_transfer_asset_in_domain_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name.clone(), domain);
    let address = "127.0.0.1:8080".to_string();
    let mut world_state_view = WorldStateView::new(Peer::with_domains(
        PeerId {
            address,
            public_key,
        },
        &Vec::new(),
        domains,
    ));
    assert!(PermissionInstruction::CanTransferAsset(
        account_id,
        transfer_asset_definition_id,
        Some(domain_name)
    )
    .execute(&mut world_state_view)
    .is_ok());
}

#[test]
fn test_can_transfer_asset_without_permission_should_fail_with_permission_not_found() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id),
    );
    let account_id = AccountId::new("ROOT", &domain_name);
    let account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        },
        &Vec::new(),
    )))
    .unwrap_err()
    .contains(PERMISSION_NOT_FOUND));
}

#[test]
fn test_can_add_signatory_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let multisignature_account_id = AccountId::new("NON_ROOT", &domain_name);
    let asset = Asset::with_permission(
        asset_id.clone(),
        Permission::AddSignatory(None, Some(multisignature_account_id.clone())),
    );
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(
        PermissionInstruction::CanAddSignatory(account_id, multisignature_account_id, None)
            .execute(&mut world_state_view)
            .is_ok()
    );
}

#[test]
fn test_add_signatory_in_domain_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let multisignature_account_id = AccountId::new("NON_ROOT", &domain_name);
    let asset = Asset::with_permission(
        asset_id.clone(),
        Permission::AddSignatory(
            Some(domain_name.clone()),
            Some(multisignature_account_id.clone()),
        ),
    );
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name.clone(), domain);
    let address = "127.0.0.1:8080".to_string();
    let mut world_state_view = WorldStateView::new(Peer::with_domains(
        PeerId {
            address,
            public_key,
        },
        &Vec::new(),
        domains,
    ));
    assert!(PermissionInstruction::CanAddSignatory(
        account_id,
        multisignature_account_id,
        Some(domain_name)
    )
    .execute(&mut world_state_view)
    .is_ok());
}

#[test]
fn test_add_signatory_without_permission_should_fail_with_permission_not_found() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id),
    );
    let account_id = AccountId::new("ROOT", &domain_name);
    let account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name.clone(), domain);
    let address = "127.0.0.1:8080".to_string();
    let mut world_state_view = WorldStateView::new(Peer::with_domains(
        PeerId {
            address,
            public_key,
        },
        &Vec::new(),
        domains,
    ));
    assert!(PermissionInstruction::CanAddSignatory(
        account_id,
        AccountId::new("NON_ROOT", &domain_name),
        None
    )
    .execute(&mut world_state_view)
    .unwrap_err()
    .contains(PERMISSION_NOT_FOUND));
}

#[test]
fn test_can_add_signatory_without_an_account_fail_with_permission_not_found() {
    assert!(PermissionInstruction::CanAddSignatory(
        AccountId::new("NOT_ROOT", "Company"),
        AccountId::new("ACCOUNT", "Company"),
        None
    )
    .execute(&mut WorldStateView::new(Peer::new(
        PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        },
        &Vec::new(),
    )))
    .unwrap_err()
    .contains(PERMISSION_NOT_FOUND));
}

#[test]
fn test_can_remove_signatory_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let multisignature_account_id = AccountId::new("NON_ROOT", &domain_name);
    let asset = Asset::with_permission(
        asset_id.clone(),
        Permission::RemoveSignatory(None, Some(multisignature_account_id.clone())),
    );
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(
        PermissionInstruction::CanRemoveSignatory(account_id, multisignature_account_id, None)
            .execute(&mut world_state_view)
            .is_ok()
    );
}

#[test]
fn test_remove_signatory_in_domain_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let multisignature_account_id = AccountId::new("NON_ROOT", &domain_name);
    let asset = Asset::with_permission(
        asset_id.clone(),
        Permission::RemoveSignatory(
            Some(domain_name.clone()),
            Some(multisignature_account_id.clone()),
        ),
    );
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name.clone(), domain);
    let address = "127.0.0.1:8080".to_string();
    let mut world_state_view = WorldStateView::new(Peer::with_domains(
        PeerId {
            address,
            public_key,
        },
        &Vec::new(),
        domains,
    ));
    assert!(PermissionInstruction::CanRemoveSignatory(
        account_id,
        multisignature_account_id,
        Some(domain_name)
    )
    .execute(&mut world_state_view)
    .is_ok());
}

#[test]
fn test_remove_signatory_without_permission_should_fail_with_permission_not_found() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id),
    );
    let account_id = AccountId::new("ROOT", &domain_name);
    let account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name.clone(), domain);
    let address = "127.0.0.1:8080".to_string();
    let mut world_state_view = WorldStateView::new(Peer::with_domains(
        PeerId {
            address,
            public_key,
        },
        &Vec::new(),
        domains,
    ));
    assert!(PermissionInstruction::CanRemoveSignatory(
        account_id,
        AccountId::new("NON_ROOT", &domain_name),
        None
    )
    .execute(&mut world_state_view)
    .unwrap_err()
    .contains(PERMISSION_NOT_FOUND));
}

#[test]
fn test_can_remove_signatory_without_an_account_fail_with_permission_not_found() {
    assert!(PermissionInstruction::CanRemoveSignatory(
        AccountId::new("NOT_ROOT", "Company"),
        AccountId::new("ACCOUNT", "Company"),
        None
    )
    .execute(&mut WorldStateView::new(Peer::new(
        PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        },
        &Vec::new(),
    )))
    .unwrap_err()
    .contains(PERMISSION_NOT_FOUND));
}

#[test]
fn test_can_mint_asset_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(
        PermissionInstruction::CanMintAsset(account_id, mint_asset_definition_id, None)
            .execute(&mut world_state_view)
            .is_ok()
    );
}

#[test]
fn test_can_mint_asset_in_domain_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name.clone(), domain);
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
        mint_asset_definition_id,
        Some(domain_name)
    )
    .execute(&mut world_state_view)
    .is_ok());
}

#[test]
fn test_can_mint_asset_without_permission_should_fail_with_permission_not_found() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id),
    );
    let account_id = AccountId::new("ROOT", &domain_name);
    let account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        },
        &Vec::new(),
    )))
    .unwrap_err()
    .contains(PERMISSION_NOT_FOUND));
}

#[test]
fn test_can_demint_asset_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let demint_asset_definition_id = AssetDefinitionId::new("XOR", "SORA");
    let asset = Asset::with_permission(
        asset_id.clone(),
        Permission::DemintAsset(None, Some(demint_asset_definition_id.clone())),
    );
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(
        PermissionInstruction::CanDemintAsset(account_id, demint_asset_definition_id, None)
            .execute(&mut world_state_view)
            .is_ok()
    );
}

#[test]
fn test_can_demint_asset_in_domain_should_pass() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
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
    let demint_asset_definition_id = AssetDefinitionId::new("XOR", "SORA");
    let asset = Asset::with_permission(
        asset_id.clone(),
        Permission::DemintAsset(
            Some(domain_name.clone()),
            Some(demint_asset_definition_id.clone()),
        ),
    );
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name.clone(), domain);
    let address = "127.0.0.1:8080".to_string();
    let mut world_state_view = WorldStateView::new(Peer::with_domains(
        PeerId {
            address,
            public_key,
        },
        &Vec::new(),
        domains,
    ));
    assert!(PermissionInstruction::CanDemintAsset(
        account_id,
        demint_asset_definition_id,
        Some(domain_name)
    )
    .execute(&mut world_state_view)
    .is_ok());
}

#[test]
fn test_can_demint_asset_without_permission_should_fail_with_permission_not_found() {
    let domain_name = "Company".to_string();
    let public_key = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .public_key;
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id),
    );
    let account_id = AccountId::new("ROOT", &domain_name);
    let account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id.clone(), account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
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
    assert!(PermissionInstruction::CanDemintAsset(
        account_id,
        AssetDefinitionId::new("XOR", "SORA"),
        None
    )
    .execute(&mut world_state_view)
    .unwrap_err()
    .contains(PERMISSION_NOT_FOUND));
}

#[test]
fn test_can_demint_asset_without_an_account_fail_with_permission_not_found() {
    assert!(PermissionInstruction::CanDemintAsset(
        AccountId::new("NOT_ROOT", "Company"),
        AssetDefinitionId::new("XOR", "SORA"),
        None
    )
    .execute(&mut WorldStateView::new(Peer::new(
        PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        },
        &Vec::new(),
    )))
    .unwrap_err()
    .contains(PERMISSION_NOT_FOUND));
}
