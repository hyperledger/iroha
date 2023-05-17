//! Module with genesis configuration logic.
#![allow(clippy::std_instead_of_core)]

use iroha_config_base::derive::{view, Documented, Proxy};
use iroha_crypto::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};

// Generate `ConfigurationView` without the private key
view! {
    /// Configuration of the genesis block and the process of its submission.
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Documented, Proxy)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "IROHA_GENESIS_")]
    pub struct Configuration {
        /// The public key of the genesis account, should be supplied to all peers.
        #[config(serde_as_str)]
        pub account_public_key: PublicKey,
        /// The private key of the genesis account, only needed for the peer that submits the genesis block.
        #[view(ignore)]
        pub account_private_key: Option<PrivateKey>,
    }
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            account_public_key: None,
            account_private_key: Some(None),
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
        let public_key = "ed01204CFFD0EE429B1BDD36B3910EC570852B8BB63F18750341772FB46BC856C5CAAF"
            .parse()
            .expect("Public key not in multihash format");
        let private_key = PrivateKey::from_hex(
            iroha_crypto::Algorithm::Ed25519,
            "D748E18CE60CB30DEA3E73C9019B7AF45A8D465E3D71BCC9A5EF99A008205E534CFFD0EE429B1BDD36B3910EC570852B8BB63F18750341772FB46BC856C5CAAF".as_ref()
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
            )
            -> ConfigurationProxy {
            ConfigurationProxy { account_public_key, account_private_key }
        }
    }
}
