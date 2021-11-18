//! Crate contains iroha client which talks to iroha network via http

/// Module with iroha client itself
pub mod client;
/// Module with iroha client config
pub mod config;
pub use config::Configuration;
mod http_client;
pub mod samples {
	use super::Configuration;
	use iroha_core::prelude::KeyPair;
	/// Get sample client configuration. 
	pub fn get_client_config(key_pair: &KeyPair) -> Configuration {
		let (public_key, private_key) = key_pair.clone().into();
		Configuration {
			public_key,
			private_key,
			account_id: iroha_data_model::prelude::AccountId{
				name: "alice".to_string(),
				domain_name: "wonderland".to_string(),
			},
			torii_api_url: iroha_core::torii::config::DEFAULT_TORII_API_URL.to_string(),
			..Configuration::default()
		}
	}
}
