//! Functionality related to working with the configuration through client API.
//!
//! Intended usage:
//!
//! - Create [`ConfigDTO`] from [`crate::iroha::Configuration`] and serialize it for the client
//! - Deserialize [`ConfigDTO`] from the client and use [`ConfigDTO::apply_update()`] to update the configuration
// TODO: Currently logic here is not generalised and handles only `logger.level` parameter. In future, when
//       other parts of configuration are refactored and there is a solid foundation e.g. as a general
//       configuration-related crate, this part should be re-written in a clean way.
//       Track configuration refactoring here: https://github.com/hyperledger/iroha/issues/2585

use serde::{Deserialize, Serialize};

use crate::{
    logger::Directives,
    parameters::actual::{Logger as BaseLogger, Root as BaseConfig},
};

/// Subset of [`super::iroha`] configuration.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigDTO {
    #[allow(missing_docs)]
    pub logger: Logger,
}

impl From<&'_ BaseConfig> for ConfigDTO {
    fn from(value: &'_ BaseConfig) -> Self {
        Self {
            logger: (&value.logger).into(),
        }
    }
}

/// Subset of [`super::logger`] configuration.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Logger {
    #[allow(missing_docs)]
    pub level: Directives,
}

impl From<&'_ BaseLogger> for Logger {
    fn from(value: &'_ BaseLogger) -> Self {
        Self {
            level: value.level.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use iroha_data_model::Level;

    use super::*;

    #[test]
    fn snapshot_serialized_form() {
        let value = ConfigDTO {
            logger: Logger {
                level: Level::TRACE.into(),
            },
        };

        let actual = serde_json::to_string_pretty(&value).expect("The value is a valid JSON");

        // NOTE: whenever this is updated, make sure to update the documentation accordingly:
        //       https://hyperledger.github.io/iroha-2-docs/reference/torii-endpoints.html
        //       -> Configuration endpoints
        let expected = expect_test::expect![[r#"
                {
                  "logger": {
                    "level": "trace"
                  }
                }"#]];
        expected.assert_eq(&actual);
    }
}
