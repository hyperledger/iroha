use iroha_crypto::KeyPair;
use iroha_data_model::account::AccountId;

/// Create new account from a random keypair in the given domain
pub fn gen_account_in(domain: impl core::fmt::Display) -> (AccountId, KeyPair) {
    let key_pair = KeyPair::random();

    let account_id = format!("{}@{}", key_pair.public_key(), domain)
        .parse()
        .expect("domain name should be valid");

    (account_id, key_pair)
}
