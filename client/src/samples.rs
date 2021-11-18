/// Get sample client configuration. 
pub fn get_client_config(key_pair: &KeyPair) -> ClientConfiguration {
	let (public_key, private_key) = key_pair.clone().into();
    ClientConfiguration {
		public_key,
		private_key,
		account_id: iroha_data_model::prelude::AccountId{
			name: "alice".to_string(),
			domain_name: "wonderland".to_string(),
		},
		torii_api_url: iroha_core::torii::config::DEFAULT_TORII_API_URL.to_string(),
		..ClientConfiguration::default()
	}
}
