use std::str::FromStr;

use error_stack::{Report, ResultExt};
use iroha_config_base::{
    read::{ConfigValueFetcher, CustomValueReadError, Error as ReadError},
    ParameterId, ParameterOrigin, WithOrigin,
};
use iroha_crypto::{Algorithm, PrivateKey};

pub(crate) struct ReadPrivateKey<'a> {
    fetcher: &'a mut ConfigValueFetcher<'a>,
    env_prefix: &'static str,
    id: ParameterId,
}

impl<'a> ReadPrivateKey<'a> {
    pub fn new(
        fetcher: &'a mut ConfigValueFetcher<'a>,
        env_prefix: &'static str,
        id: impl Into<ParameterId>,
    ) -> Self {
        Self {
            fetcher,
            env_prefix,
            id: id.into(),
        }
    }

    pub fn optional(&mut self) -> Result<Option<WithOrigin<PrivateKey>>, CustomValueReadError> {
        let from_sources = self.fetcher.fetch_parameter(&self.id)?;

        let from_env = {
            let env_algorithm = format!("{}ALGORITHM", self.env_prefix);
            let env_payload = format!("{}PAYLOAD", self.env_prefix);

            let algorithm = self.fetcher.fetch_env::<Algorithm>(&env_algorithm)?;
            let payload = self.fetcher.fetch_env::<Hex>(&env_payload)?;

            match (algorithm, payload) {
                (Some(alg), Some(payload)) => {
                    let origin = ParameterOrigin::custom(format!(
                        "env vars `{}` and `{}`",
                        env_algorithm, env_payload
                    ));

                    let private_key =
                        PrivateKey::from_bytes(alg.into_value(), &payload.into_value().0)
                            .change_context_lazy(||
                                ReadError::custom(
                                    format!(
                                        "Failed to construct parameter `{}` private key from environment variables",
                                        self.id
                                    )
                                ))
                            .attach_printable_lazy(|| format!("read from {origin}"))?;

                    Some(WithOrigin::new(private_key, origin))
                }
                (None, None) => None,
                _ => Err(Report::new(ReadError::custom(format!("Failed to parse parameter `{}` from environment variables: `{env_algorithm}` and `{env_payload}` should be set together", self.id))))?,
            }
        };

        Ok(from_env.or(from_sources))
    }

    pub fn required(&mut self) -> Result<WithOrigin<PrivateKey>, CustomValueReadError> {
        let key = self.optional()?.ok_or_else(|| {
            Report::new(ReadError::custom(format!(
                "Missing parameter: `{}`",
                self.id
            )))
        })?;
        Ok(key)
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
