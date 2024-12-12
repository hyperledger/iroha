//! Utility crate for standardized and random signatories.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use iroha_crypto::KeyPair;
use iroha_data_model::prelude::{AccountId, WasmSmartContract};
use iroha_wasm_builder::Profile;
use serde::Deserialize;

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
        pub static $key_pair: LazyLock<KeyPair> = LazyLock::new(|| {
            KeyPair::new(
                $public_key
                    .parse()
                    .expect(r#"public_key should be valid multihash e.g. "ed0120...""#),
                $private_key
                    .parse()
                    .expect(r#"private_key should be valid multihash e.g. "802620...""#),
            )
            .expect("public_key and private_key should be valid as a pair")
        });
    };
}

macro_rules! declare_account_with_keypair {
    ( $account_id:ident, $domain:literal, $key_pair:ident, $public_key:literal, $private_key:literal ) => {
        /// A standardized [`AccountId`](iroha_data_model::account::AccountId).
        pub static $account_id: LazyLock<AccountId> = LazyLock::new(|| {
            format!("{}@{}", $key_pair.public_key(), $domain)
                .parse()
                .expect("domain and public_key should be valid as name and multihash, respectively")
        });

        declare_keypair!($key_pair, $public_key, $private_key);
    };
}

declare_keypair!(
    PEER_KEYPAIR,
    "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0",
    "8026209AC47ABF59B356E0BD7DCBBBB4DEC080E302156A48CA907E47CB6AEA1D32719E"
);

declare_account_with_keypair!(
    ALICE_ID,
    "wonderland",
    ALICE_KEYPAIR,
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
);
declare_account_with_keypair!(
    BOB_ID,
    "wonderland",
    BOB_KEYPAIR,
    "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016",
    "802620AF3F96DEEF44348FEB516C057558972CEC4C75C4DB9C5B3AAC843668854BF828"
);
declare_account_with_keypair!(
    CARPENTER_ID,
    "garden_of_live_flowers",
    CARPENTER_KEYPAIR,
    "ed0120E9F632D3034BAB6BB26D92AC8FD93EF878D9C5E69E01B61B4C47101884EE2F99",
    "802620B5DD003D106B273F3628A29E6087C31CE12C9F32223BE26DD1ADB85CEBB48E1D"
);
// kagami crypto --seed "Irohagenesis"
declare_account_with_keypair!(
    SAMPLE_GENESIS_ACCOUNT_ID,
    "genesis",
    SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
    "ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4",
    "80262082B3BDE54AEBECA4146257DA0DE8D59D8E46D5FE34887DCD8072866792FCB3AD"
);

fn read_file(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
    let mut blob = vec![];
    std::fs::File::open(path.as_ref())?.read_to_end(&mut blob)?;
    Ok(blob)
}

const WASM_SAMPLES_PREBUILT_DIR: &str = "wasm/target/prebuilt/samples";
const WASM_BUILD_CONFIG_PATH: &str = "wasm/target/prebuilt/build_config.toml";

/// Load WASM smart contract from `wasm/samples` by the name of smart contract,
/// e.g. `default_executor`.
///
/// WASMs must be pre-built with the `build_wasm.sh` script
pub fn load_sample_wasm(name: impl AsRef<str>) -> WasmSmartContract {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .canonicalize()
        .expect("invoking from crates/iroha_test_samples, should be fine")
        .join(WASM_SAMPLES_PREBUILT_DIR)
        .join(name.as_ref())
        .with_extension("wasm");

    match read_file(&path) {
        Err(err) => {
            eprintln!(
                "ERROR: Could not load sample WASM `{}` from `{}`: {err}\n\
                    There are two possible reasons why:\n\
                    1. You haven't pre-built WASM samples before running tests. Make sure to run `build_wasm.sh` first.\n\
                    2. `{}` is not a valid name. Check the `wasm/samples` directory and make sure you haven't made a mistake.",
                name.as_ref(),
                path.display(),
                name.as_ref()
            );
            panic!("could not build WASM, see the message above");
        }
        Ok(blob) => WasmSmartContract::from_compiled(blob),
    }
}

#[derive(Deserialize)]
struct WasmBuildConfiguration {
    profile: Profile,
}

/// Load WASM smart contract build profile
///
/// WASMs must be pre-built with the `build_wasm.sh` script
pub fn load_wasm_build_profile() -> Profile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .canonicalize()
        .expect("invoking from crates/iroha_test_samples, should be fine")
        .join(WASM_BUILD_CONFIG_PATH);

    match fs::read_to_string(&path) {
        Err(err) => {
            eprintln!(
                "ERROR: Could not load WASM build configuration file from `{}`: {err}\n\
                Make sure to run `build_wasm.sh` first.",
                path.display(),
            );
            panic!("could not read WASM build profile");
        }
        Ok(content) => {
            let WasmBuildConfiguration { profile } = toml::from_str(content.as_str())
                .expect("a valid config must be written by `build_wasm.sh`");
            profile
        }
    }
}
