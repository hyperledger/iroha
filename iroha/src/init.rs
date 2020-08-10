use crate::{
    permission::{self, Permission},
    prelude::*,
};
use std::collections::BTreeMap;

/// The name of the initial root user.
pub const ROOT_USER_NAME: &str = "root";
/// The name of the initial global domain.
pub const GLOBAL_DOMAIN_NAME: &str = "global";

/// Returns the a map of a form domain_name -> domain, for initial domains.
/// `root_public_key` - the public key of a root account. Should be the same for all peers in the peer network.
pub fn domains(configuration: &config::InitConfiguration) -> BTreeMap<String, Domain> {
    let domain_name = GLOBAL_DOMAIN_NAME.to_string();
    let mut asset_definitions = BTreeMap::new();
    let asset_definition_id = permission::permission_asset_definition_id();
    asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::new(asset_definition_id.clone()),
    );
    let account_id = AccountId::new(ROOT_USER_NAME, &domain_name);
    let asset_id = AssetId {
        definition_id: asset_definition_id,
        account_id: account_id.clone(),
    };
    let asset = Asset::with_permission(asset_id.clone(), Permission::Anything);
    let mut account = Account::with_signatory(
        &account_id.name,
        &account_id.domain_name,
        configuration.root_public_key.clone(),
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
    domains
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_crypto::PublicKey;
    use serde::Deserialize;
    use std::env;

    const ROOT_PUBLIC_KEY: &str = "IROHA_ROOT_PUBLIC_KEY";

    #[derive(Clone, Deserialize, Debug)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct InitConfiguration {
        /// The public key of an initial "root@global" account
        pub root_public_key: PublicKey,
    }

    impl InitConfiguration {
        pub fn load_environment(&mut self) -> Result<(), String> {
            if let Ok(root_public_key) = env::var(ROOT_PUBLIC_KEY) {
                self.root_public_key = serde_json::from_value(serde_json::json!(root_public_key))
                    .map_err(|e| {
                    format!("Failed to parse Public Key of root account: {}", e)
                })?;
            }
            Ok(())
        }
    }
}
