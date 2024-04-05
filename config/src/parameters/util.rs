use std::borrow::Cow;

use error_stack::{Result, ResultExt};
use iroha_config_base::{env::FromEnvStr, ParameterOrigin, WithOrigin};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub(crate) struct PrivateKeyInConfig(pub(crate) iroha_crypto::PrivateKey);

#[derive(Debug)]
pub struct PrivateKeyPayload(Vec<u8>);

impl FromEnvStr for PrivateKeyInConfig {
    type Error = serde_json::Error;

    fn from_env_str(value: Cow<'_, str>) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let key: iroha_crypto::PrivateKey = serde_json::from_str(value.as_ref())?;
        Ok(Self(key))
    }
}

//
// #[derive(Debug, thiserror::Error)]
// pub enum PrivateKeyParseError {
//     #[error("failed to construct a private key from environment variables")]
//     InvalidEnvComponents,
//     #[error("inconsistent configuration of environment variables")]
//     InconsistentEnvGroup,
// }
//
// pub fn parse_private_key(
//     from_file: Option<WithOrigin<iroha_crypto::PrivateKey>>,
//     from_env_algorithm: Option<WithOrigin<iroha_crypto::Algorithm>>,
//     from_env_payload: Option<WithOrigin<PrivateKeyPayload>>,
// ) -> Result<Option<WithOrigin<iroha_crypto::PrivateKey>>, PrivateKeyParseError> {
//     match (from_file, from_env_algorithm, from_env_payload) {
//         (Some(key), None, None) => Ok(Some(key)),
//         (_, Some(algorithm), Some(payload)) => {
//             let (alg, alg_origin) = algorithm.into_tuple();
//             let (payload, payload_origin) = payload.into_tuple();
//             let private_key = iroha_crypto::PrivateKey::from_bytes(alg, &payload.0)
//                 .change_context(PrivateKeyParseError::InvalidEnvComponents)
//                 .attach_printable_lazy(|| format!("used algorithm from: {}", alg_origin))
//                 .attach_printable_lazy(|| format!("used payload from: {}", payload_origin))?;
//             Ok(Some(WithOrigin::new(
//                 private_key,
//                 ParameterOrigin::custom(format!("{} and {}", alg_origin, payload_origin)),
//             )))
//         }
//         (None, None, None) => Ok(None),
//         (_, Some(alg), None) => {
//             Err(PrivateKeyParseError::InconsistentEnvGroup).attach_printable(format!(
//                 "algorithm is provided (origin: {}), but payload was not",
//                 alg.origin()
//             ))
//         }
//         (_, None, Some(payload)) => Err(PrivateKeyParseError::InconsistentEnvGroup)
//             .attach_printable(format!(
//                 "payload is provided (origin: {}), but algorithm was not",
//                 payload.origin()
//             )),
//     }
// }
