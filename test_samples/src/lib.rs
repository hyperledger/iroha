//! Utility crate for standardized and random signatories.

use iroha_crypto::KeyPair;
use iroha_data_model::prelude::AccountId;
use once_cell::sync::Lazy;

/// Generate [`AccountId`](iroha_data_model::account::AccountId) in the given `domain`.
///
/// # Panics
///
/// Panics if the given `domain` is invalid as [`Name`](iroha_data_model::name::Name).
#[cfg(feature = "rand")]
pub fn gen_account_in(domain: impl core::fmt::Display) -> (AccountId, KeyPair) {
    let key_pair = KeyPair::random();
    let account_id = format!("{}@{}", key_pair.public_key(), domain)
        .parse()
        .expect("domain name should be valid");
    (account_id, key_pair)
}

macro_rules! declare_keypair {
    ( $key_pair:ident, $public_key:expr, $private_key:expr ) => {
        /// A standardized [`KeyPair`](iroha_crypto::KeyPair).
        pub static $key_pair: Lazy<KeyPair> = Lazy::new(|| {
            KeyPair::new(
                $public_key
                    .parse()
                    .expect(r#"public_key should be valid multihash e.g. "ed0120...""#),
                $private_key
                    .parse()
                    .expect(r#"private_key should be valid multihash e.g. "802640...""#),
            )
            .expect("public_key and private_key should be valid as a pair")
        });
    };
}

macro_rules! declare_account_with_keypair {
    ( $account_id:ident, $domain:literal, $key_pair:ident, $public_key:literal, $private_key:literal ) => {
        /// A standardized [`AccountId`](iroha_data_model::account::AccountId).
        pub static $account_id: Lazy<AccountId> = Lazy::new(|| {
            format!("{}@{}", $key_pair.public_key(), $domain)
                .parse()
                .expect("domain and public_key should be valid as name and multihash, respectively")
        });

        declare_keypair!($key_pair, $public_key, $private_key);
    };
}

declare_keypair!(PEER_KEYPAIR, "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0", "8026409AC47ABF59B356E0BD7DCBBBB4DEC080E302156A48CA907E47CB6AEA1D32719E7233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0");

declare_account_with_keypair!(ALICE_ID, "wonderland", ALICE_KEYPAIR, "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03", "802640CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03");
declare_account_with_keypair!(BOB_ID, "wonderland", BOB_KEYPAIR, "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016", "802640AF3F96DEEF44348FEB516C057558972CEC4C75C4DB9C5B3AAC843668854BF82804FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016");
declare_account_with_keypair!(CARPENTER_ID, "garden_of_live_flowers", CARPENTER_KEYPAIR, "ed0120E9F632D3034BAB6BB26D92AC8FD93EF878D9C5E69E01B61B4C47101884EE2F99", "802640B5DD003D106B273F3628A29E6087C31CE12C9F32223BE26DD1ADB85CEBB48E1DE9F632D3034BAB6BB26D92AC8FD93EF878D9C5E69E01B61B4C47101884EE2F99");
// kagami crypto --seed "Irohagenesis"
declare_account_with_keypair!(SAMPLE_GENESIS_ACCOUNT_ID, "genesis", SAMPLE_GENESIS_ACCOUNT_KEYPAIR, "ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4", "80264082B3BDE54AEBECA4146257DA0DE8D59D8E46D5FE34887DCD8072866792FCB3AD4164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4");
