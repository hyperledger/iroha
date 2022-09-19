//! Module with genesis configuration logic.
#![allow(clippy::std_instead_of_core)]

use iroha_config_base::derive::{view, Documented, LoadFromEnv, Proxy};
use iroha_crypto::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};

const DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT_LIMIT: u64 = 100;
const DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS: u64 = 500;
const DEFAULT_GENESIS_SUBMISSION_DELAY_MS: u64 = 1000;

// Generate `ConfigurationView` without the private key
view! {
    /// Configuration of the genesis block and the process of its submission.
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Documented, Proxy, LoadFromEnv)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "IROHA_GENESIS_")]
    pub struct Configuration {
        /// The public key of the genesis account, should be supplied to all peers.
        #[config(serde_as_str)]
        pub account_public_key: PublicKey,
        /// The private key of the genesis account, only needed for the peer that submits the genesis block.
        #[view(ignore)]
        pub account_private_key: Option<PrivateKey>,
        /// The number of attempts to connect to peers while waiting for them to submit genesis.
        pub wait_for_peers_retry_count_limit: u64,
        /// The period in milliseconds in which to retry connecting to peers while waiting for them to submit genesis.
        pub wait_for_peers_retry_period_ms: u64,
        /// The delay before genesis block submission after minimum number of peers were discovered to be online.
        /// The delay between submissions, which is used to ensure that other peers had time to connect to each other.
        pub genesis_submission_delay_ms: u64,
    }
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            account_public_key: None,
            account_private_key: Some(None),
            wait_for_peers_retry_count_limit: Some(DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT_LIMIT),
            wait_for_peers_retry_period_ms: Some(DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS),
            genesis_submission_delay_ms: Some(DEFAULT_GENESIS_SUBMISSION_DELAY_MS),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use iroha_crypto::KeyPair;
    use proptest::prelude::*;

    use super::*;

    /// Key-pair used by default for test purposes
    #[allow(clippy::expect_used)]
    fn placeholder_keypair() -> KeyPair {
        let public_key = "ed01204cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf"
            .parse()
            .expect("Public key not in mulithash format");
        let private_key = PrivateKey::from_hex(
            iroha_crypto::Algorithm::Ed25519,
            "d748e18ce60cb30dea3e73c9019b7af45a8d465e3d71bcc9a5ef99a008205e534cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf"
        ).expect("Private key not hex encoded");

        KeyPair::new(public_key, private_key).expect("Key pair mismatch")
    }

    #[allow(clippy::option_option)]
    fn arb_keys() -> BoxedStrategy<(Option<PublicKey>, Option<Option<PrivateKey>>)> {
        let (pub_key, _) = placeholder_keypair().into();
        (
            prop::option::of(Just(pub_key)),
            prop::option::of(Just(None)),
        )
            .boxed()
    }

    prop_compose! {
        pub fn arb_proxy()
            (
                (account_public_key, account_private_key) in arb_keys(),
                wait_for_peers_retry_count_limit in prop::option::of(Just(DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT_LIMIT)),
                wait_for_peers_retry_period_ms in prop::option::of(Just(DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS)),
                genesis_submission_delay_ms in prop::option::of(Just(DEFAULT_GENESIS_SUBMISSION_DELAY_MS)),
            )
            -> ConfigurationProxy {
            ConfigurationProxy { account_public_key, account_private_key, wait_for_peers_retry_count_limit, wait_for_peers_retry_period_ms, genesis_submission_delay_ms }
        }
    }
}
