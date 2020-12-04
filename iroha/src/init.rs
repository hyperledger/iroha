use iroha_data_model::prelude::*;
use std::collections::BTreeMap;

/// The name of the initial root user.
pub const ROOT_USER_NAME: &str = "root";
/// The name of the initial global domain.
pub const GLOBAL_DOMAIN_NAME: &str = "global";

/// Returns the a map of a form domain_name -> domain, for initial domains.
/// `root_public_key` - the public key of a root account. Should be the same for all peers in the peer network.
pub fn domains(configuration: &config::InitConfiguration) -> BTreeMap<String, Domain> {
    let domain_name = GLOBAL_DOMAIN_NAME.to_string();
    let asset_definitions = BTreeMap::new();
    let account_id = AccountId::new(ROOT_USER_NAME, &domain_name);
    let account = Account::with_signatory(
        AccountId::new(&account_id.name, &account_id.domain_name),
        configuration.root_public_key.clone(),
    );
    let mut accounts = BTreeMap::new();
    let _ = accounts.insert(account_id, account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    let _ = domains.insert(domain_name, domain);
    let _ = domains.insert(
        GENESIS_DOMAIN_NAME.to_string(),
        GenesisDomain::new(configuration.genesis_account_public_key.clone()).into(),
    );
    domains
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_crypto::{PrivateKey, PublicKey};
    use serde::Deserialize;
    use std::env;

    const ROOT_PUBLIC_KEY: &str = "IROHA_ROOT_PUBLIC_KEY";
    const GENESIS_ACCOUNT_PUBLIC_KEY: &str = "IROHA_GENESIS_ACCOUNT_PUBLIC_KEY";
    const GENESIS_ACCOUNT_PRIVATE_KEY: &str = "IROHA_GENESIS_ACCOUNT_PRIVATE_KEY";

    #[derive(Clone, Deserialize, Debug)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct InitConfiguration {
        /// The public key of an initial "root@global" account
        pub root_public_key: PublicKey,
        /// Genesis account public key, should be supplied to all the peers.
        pub genesis_account_public_key: PublicKey,
        /// Genesis account private key, only needed on the peer that submits the genesis block.
        #[serde(default)]
        pub genesis_account_private_key: Option<PrivateKey>,
    }

    impl InitConfiguration {
        pub fn load_environment(&mut self) -> Result<(), String> {
            if let Ok(root_public_key) = env::var(ROOT_PUBLIC_KEY) {
                self.root_public_key = serde_json::from_value(serde_json::json!(root_public_key))
                    .map_err(|e| {
                    format!("Failed to parse Public Key of root account: {}", e)
                })?;
            }
            if let Ok(genesis_account_public_key) = env::var(GENESIS_ACCOUNT_PUBLIC_KEY) {
                self.genesis_account_public_key = serde_json::from_value(serde_json::json!(
                    genesis_account_public_key
                ))
                .map_err(|e| format!("Failed to parse Public Key of genesis account: {}", e))?;
            }
            if let Ok(genesis_account_private_key) = env::var(GENESIS_ACCOUNT_PRIVATE_KEY) {
                self.genesis_account_private_key =
                    serde_json::from_value(serde_json::json!(genesis_account_private_key))
                        .map_err(|e| {
                            format!("Failed to parse Private Key of genesis account: {}", e)
                        })?;
            }
            Ok(())
        }
    }
}
