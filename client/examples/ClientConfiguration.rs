// #region rust_config_crates
use iroha_core::prelude::*;
use iroha_data_model::prelude::*;
// #endregion rust_config_crates

fn construct_client_configuration_test() -> Result<(), Error> {
    // #region client_configuration_test
    let public_str = r#"ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"#;
    let private_hex = "9ac47abf59b356e0bd7dcbbbb4dec080e302156a48ca907e47cb6aea1d32719e7233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0";

    let kp = KeyPair::new(
        PublicKey::from_str(public_str)?,
        PrivateKey::from_hex(Algorithm::Ed25519, private_hex.into())?
    )?;
    
    let (public_key, private_key) = kp.clone().into();
    let account_id: AccountId = "alice@wonderland".parse()?;
    
    let config = ClientConfiguration {
        public_key,
        private_key,
        account_id,
        torii_api_url: SmallStr::from_string(iroha_config::torii::uri::DEFAULT_API_URL.to_owned()),
        ..ClientConfiguration::default()
    };
    // #endregion client_configuration_test

    // Finish the test successfully
    Ok(())
}

fn main() {
    construct_client_configuration_test()
        .expect("In-place client configuration example is expected to work correctly");
    println!("Success!");
}
