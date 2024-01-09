//! Basic parameters like the key pair and p2p address

use std::{error::Error, str::FromStr};

use eyre::{eyre, Context, Report};
use iroha_crypto::{Algorithm, PrivateKey, PublicKey};
use iroha_data_model::ChainId;
use iroha_primitives::addr::SocketAddr;
use serde::{Deserialize, Serialize};

use crate::{
    Complete, CompleteError, CompleteResult, Emitter, FromEnv, FromEnvResult, ParseEnvResult,
    ReadEnv,
};

#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct UserLayer {
    pub chain_id: Option<ChainId>,
    pub public_key: Option<PublicKey>,
    pub private_key: Option<PrivateKey>,
    pub p2p_address: Option<SocketAddr>,
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Config> {
        let mut emitter = super::Emitter::<CompleteError>::new();

        if let None = self.public_key {
            emitter.emit_missing_field("public_key");
        }

        if let None = self.private_key {
            emitter.emit_missing_field("private_key");
        }

        if let None = self.p2p_address {
            emitter.emit_missing_field("p2p_address");
        }

        emitter.finish()?;

        Ok(Config {
            public_key: self.public_key.unwrap(),
            private_key: self.private_key.unwrap(),
            p2p_address: self.p2p_address.unwrap(),
        })
    }
}

pub(crate) fn private_key_from_env(
    emitter: &mut Emitter<Report>,
    env: &impl ReadEnv,
    env_key_base: impl AsRef<str>,
    name_base: impl AsRef<str>,
) -> ParseEnvResult<PrivateKey> {
    let digest_env = format!("{}_DIGEST", env_key_base.as_ref());
    let digest_name = format!("{}.digest_function", name_base.as_ref());
    let payload_env = format!("{}_PAYLOAD", env_key_base.as_ref());
    let payload_name = format!("{}.payload", name_base.as_ref());

    let digest_function = ParseEnvResult::parse_simple(emitter, env, &digest_env, &digest_name);

    let payload = env.get(&payload_env).map(ToOwned::to_owned);

    match (digest_function, payload) {
        (ParseEnvResult::Value(digest_function), Some(payload)) => {
            PrivateKey::from_hex(digest_function, &payload)
                .wrap_err_with(|| {
                    eyre!(
                        "failed to construct `{}` from `{}` and `{}` environment variables",
                        name_base.as_ref(),
                        &digest_env,
                        &payload_env
                    )
                })
                .map(ParseEnvResult::Value)
                .unwrap_or_else(|report| {
                    emitter.emit(report);
                    ParseEnvResult::ParseError
                })
        }
        (ParseEnvResult::None, None) | (ParseEnvResult::ParseError, _) => ParseEnvResult::None,
        (ParseEnvResult::Value(_), None) => {
            emitter.emit(eyre!(
                "`{}` env was provided, but `{}` was not",
                &digest_env,
                &payload_env
            ));
            ParseEnvResult::ParseError
        }
        (ParseEnvResult::None, Some(_)) => {
            emitter.emit(eyre!(
                "`{}` env was provided, but `{}` was not",
                &payload_env,
                &digest_env
            ));
            ParseEnvResult::ParseError
        }
    }
}

impl FromEnv for UserLayer {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let chain_id =
            ParseEnvResult::parse_simple(&mut emitter, env, "CHAIN_ID", "iroha.chain_id").into();
        let public_key =
            ParseEnvResult::parse_simple(&mut emitter, env, "PUBLIC_KEY", "iroha.public_key")
                .into();
        let private_key =
            private_key_from_env(&mut emitter, env, "PRIVATE_KEY", "iroha.private_key").into();
        let p2p_address =
            ParseEnvResult::parse_simple(&mut emitter, env, "P2P_ADDRESS", "iroha.p2p_address")
                .into();

        emitter.finish()?;

        Ok(Self {
            chain_id,
            public_key,
            private_key,
            p2p_address,
        })
    }
}

#[derive(Debug)]
pub struct Config {
    pub chain_id: ChainId,
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
    pub p2p_address: SocketAddr,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestEnv;

    #[test]
    fn parses_private_key_from_env() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY_DIGEST", "ed25519")
            .set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");

        let private_key = UserLayer::from_env(&env)
            .expect("input is valid, should not fail")
            .private_key
            .expect("private key is provided, should not fail");

        assert_eq!(private_key.digest_function(), "ed25519".parse().unwrap());
        assert_eq!(hex::encode( private_key.payload()), "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");
    }

    #[test]
    fn fails_to_parse_private_key_in_env_without_digest() {
        let env = TestEnv::new().set("PRIVATE_KEY_DIGEST", "ed25519");
        let error = UserLayer::from_env(&env).expect_err("private key is incomplete, should fail");
        let expected = expect_test::expect![[r#"
            `PRIVATE_KEY_DIGEST` env was provided, but `PRIVATE_KEY_PAYLOAD` was not

            Location:
                config/src/parameters/iroha.rs:125:65"#]];
        expected.assert_eq(&format!("{error:?}"));
    }

    #[test]
    fn fails_to_parse_private_key_in_env_without_payload() {
        let env = TestEnv::new().set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");
        let error = UserLayer::from_env(&env).expect_err("private key is incomplete, should fail");
        let expected = expect_test::expect![[r#"
            `PRIVATE_KEY_PAYLOAD` env was provided, but `PRIVATE_KEY_DIGEST` was not

            Location:
                config/src/parameters/iroha.rs:126:64"#]];
        expected.assert_eq(&format!("{error:?}"));
    }

    #[test]
    fn fails_to_parse_private_key_from_env_with_invalid_payload() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY_DIGEST", "ed25519")
            .set("PRIVATE_KEY_PAYLOAD", "foo");

        let error = UserLayer::from_env(&env).expect_err("input is invalid, should fail");

        let expected = expect_test::expect![[r#"
            failed to construct `iroha.private_key` from `PRIVATE_KEY_DIGEST` and `PRIVATE_KEY_PAYLOAD` environment variables

            Caused by:
                Key could not be parsed. Odd number of digits

            Location:
                config/src/parameters/iroha.rs:118:26"#]];
        expected.assert_eq(&format!("{error:?}"));
    }

    #[test]
    fn when_payload_provided_but_digest_is_invalid() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY_DIGEST", "foo")
            .set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");

        let error = UserLayer::from_env(&env).expect_err("input is invalid, should fail");

        // TODO: print the bad value and supported ones
        let expected = expect_test::expect![[r#"
            failed to parse `iroha.private_key.digest_function` field from `PRIVATE_KEY_DIGEST` env variable

            Caused by:
                Algorithm not supported

            Location:
                config/src/parameters/iroha.rs:95:25"#]];
        expected.assert_eq(&format!("{error:?}"));
    }
}
