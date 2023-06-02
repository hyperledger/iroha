//! Module for client-related configuration and structs
use core::str::FromStr;

use derive_more::Display;
use eyre::Result;
use iroha_config_base::{Configuration, Documented};
use iroha_crypto::prelude::*;
use iroha_data_model::{account::AccountId, prelude::*};
use iroha_primitives::small::SmallStr;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::torii::Configuration as ToriiConfig;

/// Wrapper over `SmallStr` to provide basic auth login checking
#[derive(Debug, Display, Clone, Serialize, PartialEq, Eq)]
pub struct WebLogin(SmallStr);

impl WebLogin {
    /// Construct new [`Self`]
    ///
    /// # Errors
    /// Fails if `login` contains `:` character, which is the binary representation of the '\0'.
    pub fn new(login: &str) -> Result<Self> {
        Self::from_str(login)
    }
}

impl FromStr for WebLogin {
    type Err = eyre::ErrReport;
    fn from_str(login: &str) -> Result<Self> {
        if login.contains(':') {
            eyre::bail!("The `:` character, in `{login}` is not allowed");
        }

        Ok(Self(SmallStr::from_str(login)))
    }
}

/// Deserializing `WebLogin` with `FromStr` implementation
impl<'de> Deserialize<'de> for WebLogin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Basic Authentication credentials
#[derive(Clone, Deserialize, Serialize, Debug, Documented, PartialEq, Eq)]
pub struct BasicAuth {
    /// Login for Basic Authentication
    pub web_login: WebLogin,
    /// Password for Basic Authentication
    pub password: SmallStr,
}

/// `Configuration` provides an ability to define client parameters such as `TORII_URL`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Configuration, Documented)]
#[serde(try_from = "ConfigurationBuilder")]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "IROHA_")]
pub struct Configuration {
    /// Public key of the user account.
    #[config(serde_as_str)]
    public_key: PublicKey,
    /// Private key of the user account.
    private_key: PrivateKey,
    /// User account id.
    account_id: AccountId,
    /// Basic Authentication credentials
    #[config(default = "None")]
    basic_auth: Option<BasicAuth>,
    /// Torii URL.
    #[config(default = "format!(\"http://{}\", ToriiConfig::DEFAULT_API_URL()).parse().unwrap()")]
    torii_api_url: Url,
    /// Status URL.
    #[config(
        default = "format!(\"http://{}\", ToriiConfig::DEFAULT_TELEMETRY_URL()).parse().unwrap()"
    )]
    torii_telemetry_url: Url,
    /// Proposed transaction TTL in milliseconds.
    #[config(default = "100_000")]
    transaction_time_to_live_ms: u64,
    /// Transaction status wait timeout in milliseconds.
    #[config(default = "15_000")]
    transaction_status_timeout_ms: u64,
    /// The limits to which transactions must adhere to
    #[config(default = "crate::wsv::Configuration::DEFAULT_TRANSACTION_LIMITS()")]
    transaction_limits: TransactionLimits,
    /// If `true` add nonce, which make different hashes for transactions which occur repeatedly and simultaneously
    #[config(default = "false")]
    add_transaction_nonce: bool,
}

//const TTL_TOO_SMALL_THRESHOLD: u64 = 500;
//const WASM_SIZE_TOO_SMALL_THRESHOLD: u64 = 2_u64.pow(10); // 1 KiB
//
//impl ConfigurationBuilder {
//    /// Finalise Iroha client config proxy by checking that certain fields identify reasonable limits or
//    /// are well formatted.
//    ///
//    /// # Errors
//    /// - If the [`self.transaction_time_to_live_ms`] or [`self.transaction_limits.max_wasm_size_bytes`] fields were too small
//    /// - If the [`self.transaction_status_timeout_ms`] field was smaller than [`self.transaction_time_to_live_ms`]
//    /// - If the [`self.torii_api_url`] or [`self.torii_telemetry_url`] were malformed or had the wrong protocol
//    pub fn finish(&mut self) -> Result<()> {
//        if let tx_ttl = self.transaction_time_to_live_ms {
//            // Really small TTL would be detrimental to performance
//            if tx_ttl < TTL_TOO_SMALL_THRESHOLD {
//                eyre::bail!(ConfigError::InsaneValue {
//                    field: "TRANSACTION_TIME_TO_LIVE_MS",
//                    value: tx_ttl.to_string(),
//                    message: format!(", because if it's smaller than {TTL_TOO_SMALL_THRESHOLD}, Iroha wouldn't be able to produce blocks on time.")
//                });
//            }
//            // Timeouts bigger than transaction TTL don't make sense as then transaction would be discarded before this timeout
//            if let Some(timeout) = self.transaction_status_timeout_ms {
//                if timeout > tx_ttl {
//                    eyre::bail!(ConfigError::InsaneValue {
//                        field: "TRANSACTION_STATUS_TIMEOUT_MS",
//                        value: timeout.to_string(),
//                        message: format!(", because it should be smaller than `TRANSACTION_TIME_TO_LIVE_MS`, which is {tx_ttl}")
//                    })
//                }
//            }
//        }
//        if let Some(tx_limits) = self.transaction_limits {
//            if *tx_limits.max_wasm_size_bytes() < WASM_SIZE_TOO_SMALL_THRESHOLD {
//                eyre::bail!(ConfigError::InsaneValue {
//                    field: "TRANSACTION_LIMITS",
//                    value: format!("{}", tx_limits.max_wasm_size_bytes()),
//                    message: String::new()
//                });
//            }
//        }
//        if let Some(api_url) = &self.torii_api_url {
//            if api_url.scheme() != "http" {
//                eyre::bail!(ConfigError::InsaneValue {
//                    field: "TORII_API_URL",
//                    value: api_url.to_string(),
//                    message: ", because we only support HTTP".to_owned(),
//                });
//            }
//        }
//        if let Some(telemetry_url) = &self.torii_telemetry_url {
//            if telemetry_url.scheme() != "http" {
//                eyre::bail!(ConfigError::InsaneValue {
//                    value: telemetry_url.to_string(),
//                    field: "TORII_TELEMETRY_URL",
//                    message: ", because we only support HTTP".to_owned(),
//                });
//            }
//            if telemetry_url.port().is_none() {
//                eyre::bail!(ConfigError::InsaneValue{
//                            value: telemetry_url.to_string(),
//                            field: "TORII_TELEMETRY_URL",
//                            message: ". You haven't provided a connection port, e.g. `8180` in `http://127.0.0.1:8180`".to_owned(),
//                        });
//            }
//        }
//        Ok(())
//    }
//}

#[cfg(test)]
mod tests {
    use iroha_crypto::KeyGenConfiguration;
    use proptest::prelude::*;

    use super::*;
    use crate::wsv::Configuration as WsvConfiguration;

    const CONFIGURATION_PATH: &str = "../configs/client/config.json";

    prop_compose! {
        // TODO: make tests to check generated key validity
        fn arb_keys_from_seed()
            (seed in prop::collection::vec(any::<u8>(), 33..64)) -> (PublicKey, PrivateKey) {
                let (public_key, private_key) = KeyPair::generate_with_configuration(KeyGenConfiguration::default().use_seed(seed)).expect("Seed was invalid").into();
                (public_key, private_key)
            }
    }

    prop_compose! {
        fn arb_keys_with_option()
            (keys in arb_keys_from_seed())
            ((a, b) in (prop::option::of(Just(keys.0)), prop::option::of(Just(keys.1))))
            -> (Option<PublicKey>, Option<PrivateKey>) {
                (a, b)
            }
    }

    fn placeholder_account() -> <Account as Identifiable>::Id {
        AccountId::from_str("alice@wonderland").expect("Invalid account Id ")
    }

    prop_compose! {
        fn arb_proxy()
            (
                (public_key, private_key) in arb_keys_with_option(),
                account_id in prop::option::of(Just(placeholder_account())),
                basic_auth in prop::option::of(Just(Configuration::DEFAULT_BASIC_AUTH())),
                torii_api_url in prop::option::of(Just(Configuration::DEFAULT_TORII_API_URL())),
                torii_telemetry_url in prop::option::of(Just(Configuration::DEFAULT_TORII_TELEMETRY_URL())),
                transaction_time_to_live_ms in prop::option::of(Just(Configuration::DEFAULT_TRANSACTION_TIME_TO_LIVE_MS())),
                transaction_status_timeout_ms in prop::option::of(Just(Configuration::DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS())),
                transaction_limits in prop::option::of(Just(WsvConfiguration::DEFAULT_TRANSACTION_LIMITS())),
                add_transaction_nonce in prop::option::of(Just(Configuration::DEFAULT_ADD_TRANSACTION_NONCE())),
            )
            -> ConfigurationBuilder {
            ConfigurationBuilder { public_key, private_key, account_id, basic_auth, torii_api_url, torii_telemetry_url, transaction_time_to_live_ms, transaction_status_timeout_ms, transaction_limits, add_transaction_nonce }
        }
    }

    proptest! {
        #[test]
        fn client_proxy_build_fails_on_none(proxy in arb_proxy()) {
            let cfg = proxy.build();
            if cfg.is_ok() {
                let example_cfg = ConfigurationBuilder::from_path(CONFIGURATION_PATH).build().expect("Failed to build example Iroha config. \
                                                                                                    This probably means that some of the fields of the `CONFIGURATION PATH` \
                                                                                                    JSON were not updated properly with new changes.");
                let arb_cfg = cfg.expect("Config generated by proptest was checked to be ok by the surrounding if clause");
                // Skipping keys and `basic_auth` check as they're different from the file
                assert_eq!(arb_cfg.torii_api_url, example_cfg.torii_api_url);
                assert_eq!(arb_cfg.torii_telemetry_url, example_cfg.torii_telemetry_url);
                assert_eq!(arb_cfg.account_id, example_cfg.account_id);
                assert_eq!(arb_cfg.transaction_time_to_live_ms, example_cfg.transaction_time_to_live_ms);
                assert_eq!(arb_cfg.transaction_status_timeout_ms, example_cfg.transaction_status_timeout_ms);
                assert_eq!(arb_cfg.transaction_limits, example_cfg.transaction_limits);
                assert_eq!(arb_cfg.add_transaction_nonce, example_cfg.add_transaction_nonce);
            }
        }
    }
}
