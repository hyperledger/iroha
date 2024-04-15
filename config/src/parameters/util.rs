use std::str::FromStr;

use error_stack::{Report, ResultExt};
use iroha_config_base::read::{CustomEnvFetcher, CustomEnvReadError};
use iroha_crypto::{Algorithm, PrivateKey};
use thiserror::Error;

#[derive(Error, Debug, Copy, Clone)]
pub enum PrivateKeyFromEnvError {
    #[error("Failed to construct the private key from components")]
    CannotConstruct,
    #[error("Invalid environment variables group")]
    InconsistentVars,
}

pub fn read_private_key_from_env(
    fetcher: &mut CustomEnvFetcher,
    env_prefix: &'static str,
) -> Result<Option<PrivateKey>, CustomEnvReadError<PrivateKeyFromEnvError>> {
    let env_algorithm = format!("{}ALGORITHM", env_prefix);
    let env_payload = format!("{}PAYLOAD", env_prefix);

    let algorithm = fetcher.fetch_env::<Algorithm>(&env_algorithm)?;
    let payload = fetcher.fetch_env::<Hex>(&env_payload)?;

    match (algorithm, payload) {
        (Some(alg), Some(payload)) => {
            let private_key = PrivateKey::from_bytes(alg.into_value(), &payload.into_value().0)
                .change_context(PrivateKeyFromEnvError::CannotConstruct)?;

            Ok(Some(private_key))
        }
        (None, None) => Ok(None),
        _ => Err(
            Report::new(PrivateKeyFromEnvError::InconsistentVars).attach_printable(format!(
                "vars `{env_algorithm}` and `{env_payload}` should be set together"
            )),
        )?,
    }
}

struct Hex(Vec<u8>);

impl FromStr for Hex {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = hex::decode(s)?;
        Ok(Self(value))
    }
}
