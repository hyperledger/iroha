use crate::permission::permission_asset_definition_id;
use crate::prelude::*;
use iroha_data_model::prelude::*;
use parity_scale_codec::alloc::collections::BTreeMap;

fn init() -> WorldStateView {
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
    let asset = Asset::with_permission(asset_id.clone(), Anything::new());
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        public_key.clone(),
    );
    account.assets.insert(asset_id, asset);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id, account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name, domain);
    let address = "127.0.0.1:8080".to_string();
    WorldStateView::new(Peer::with_domains(
        PeerId {
            address,
            public_key,
        },
        &Vec::new(),
        domains,
    ))
}

#[test]
fn test_demint_asset_should_pass() {
    let domain_name = "Company";
    let mut world_state_view = init();
    let domain = world_state_view.domain(domain_name).unwrap();
    let account_id = AccountId::new("root", &domain_name);
    let asset_def = AssetDefinition::new(AssetDefinitionId::new("XOR", "Company"));
    world_state_view = domain
        .register_asset(asset_def.clone())
        .execute(account_id.clone(), &mut world_state_view)
        .expect("failed to register asset")
        .world_state_view();
    let asset_id = AssetId::new(asset_def.id, account_id.clone());
    world_state_view = Mint::new(10u32, asset_id.clone())
        .execute(account_id.clone(), &mut world_state_view)
        .expect("failed to mint asset")
        .world_state_view();
    world_state_view = Demint::new(10u32, asset_id.clone())
        .execute(account_id.clone(), &mut world_state_view)
        .expect("failed to demint asset")
        .world_state_view();
    assert_eq!(world_state_view.asset(&asset_id).unwrap().quantity, 0);
    world_state_view = Mint::new(20u128, asset_id.clone())
        .execute(account_id.clone(), &mut world_state_view)
        .expect("failed to big mint asset")
        .world_state_view();
    world_state_view = Demint::new(20u128, asset_id.clone())
        .execute(account_id.clone(), &mut world_state_view)
        .expect("failed to big demint asset")
        .world_state_view();
    assert_eq!(world_state_view.asset(&asset_id).unwrap().big_quantity, 0);
    world_state_view = Mint::new(("key".to_string(), b"value".to_vec()), asset_id.clone())
        .execute(account_id.clone(), &mut world_state_view)
        .expect("failed to big mint asset")
        .world_state_view();
    world_state_view = Demint::new("key".to_string(), asset_id.clone())
        .execute(account_id, &mut world_state_view)
        .expect("failed to big demint asset")
        .world_state_view();
    assert!(world_state_view
        .asset(&asset_id)
        .unwrap()
        .store
        .get("key")
        .is_none());
}

#[test]
fn test_demint_asset_should_fail() {
    let domain_name = "Company";
    let mut world_state_view = init();
    let domain = world_state_view.domain(domain_name).unwrap();
    let account_id = AccountId::new("root", &domain_name);
    let asset_def = AssetDefinition::new(AssetDefinitionId::new("XOR", "Company"));
    world_state_view = domain
        .register_asset(asset_def.clone())
        .execute(account_id.clone(), &mut world_state_view)
        .expect("failed to register asset")
        .world_state_view();
    let asset_id = AssetId::new(asset_def.id, account_id.clone());
    world_state_view = Mint::new(10u32, asset_id.clone())
        .execute(account_id.clone(), &mut world_state_view)
        .expect("failed to mint asset")
        .world_state_view();
    assert_eq!(
        Demint::new(11u32, asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .unwrap_err(),
        "Not enough quantity to demint.".to_string()
    );
    assert_eq!(world_state_view.asset(&asset_id).unwrap().quantity, 10);
    world_state_view = Mint::new(20u128, asset_id.clone())
        .execute(account_id.clone(), &mut world_state_view)
        .expect("failed to big mint asset")
        .world_state_view();
    assert_eq!(
        Demint::new(21u128, asset_id.clone())
            .execute(account_id.clone(), &mut world_state_view)
            .unwrap_err(),
        "Not enough big quantity to demint.".to_string()
    );
    assert_eq!(world_state_view.asset(&asset_id).unwrap().big_quantity, 20);
    world_state_view = Mint::new(("key".to_string(), b"value".to_vec()), asset_id.clone())
        .execute(account_id.clone(), &mut world_state_view)
        .expect("failed to big mint asset")
        .world_state_view();
    assert_eq!(
        Demint::new("other_key".to_string(), asset_id.clone())
            .execute(account_id, &mut world_state_view)
            .unwrap_err(),
        "Key not found.".to_string()
    );
    assert!(world_state_view
        .asset(&asset_id)
        .unwrap()
        .store
        .get("key")
        .is_some());
}
