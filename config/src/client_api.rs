//! Functionality related to working with the configuration through client API.
//!
//! Intended usage:
//!
//! - Create [`ConfigurationDTO`] from [`crate::iroha::Configuration`] and serialize it for the client
//! - Deserialize [`ConfigurationDTO`] from the client and use [`ConfigurationDTO::apply_update()`] to update the configuration
// TODO: Currently logic here is not generalised and handles only `logger.max_log_level` parameter. In future, when
//       other parts of configuration are refactored and there is a solid foundation e.g. as a general
//       configuration-related crate, this part should be re-written in a clean way.
//       Track configuration refactoring here: https://github.com/hyperledger/iroha/issues/2585

use iroha_config_base::runtime_upgrades::{Reload, ReloadError};
use iroha_data_model::Level;
use serde::{Deserialize, Serialize};

use super::{iroha::Configuration as BaseConfiguration, logger::Configuration as BaseLogger};

/// Subset of [`super::iroha`] configuration.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct ConfigurationDTO {
    logger: Logger,
}

impl From<&'_ BaseConfiguration> for ConfigurationDTO {
    fn from(value: &'_ BaseConfiguration) -> Self {
        Self {
            logger: value.logger.as_ref().into(),
        }
    }
}

impl ConfigurationDTO {
    /// Update the base configuration with the values stored in [`Self`].
    pub fn update_base(&self, target: &BaseConfiguration) -> Result<(), ReloadError> {
        target
            .logger
            .max_log_level
            .reload(self.logger.max_log_level)
    }
}

/// Subset of [`super::logger`] configuration.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
struct Logger {
    #[allow(missing_docs)]
    max_log_level: Level,
}

impl From<&'_ BaseLogger> for Logger {
    fn from(value: &'_ BaseLogger) -> Self {
        Self {
            max_log_level: value.max_log_level.value(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn snapshot_serialized_form() {
        let value = ConfigurationDTO {
            logger: Logger {
                max_log_level: Level::TRACE,
            },
        };

        let actual = serde_json::to_string_pretty(&value).expect("The value is a valid JSON");

        // NOTE: whenever this is updated, make sure to update the documentation accordingly:
        //       https://hyperledger.github.io/iroha-2-docs/reference/torii-endpoints.html
        //       -> Configuration endpoints
        let expected = expect_test::expect![[r#"
                {
                  "logger": {
                    "max_log_level": "TRACE"
                  }
                }"#]];
        expected.assert_eq(&actual);
    }
}
