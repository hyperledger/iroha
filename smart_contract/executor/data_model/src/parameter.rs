//! Module with parameter related functionality.

pub use iroha_data_model::parameter::CustomParameter;
use iroha_data_model::parameter::CustomParameterId;
pub use iroha_executor_data_model_derive::Parameter;
use iroha_schema::IntoSchema;
use serde::{de::DeserializeOwned, Serialize};

/// Blockchain specific parameter
pub trait Parameter: Default + DeserializeOwned + Serialize + IntoSchema {
    /// Parameter id, according to [`IntoSchema`].
    fn id() -> CustomParameterId {
        CustomParameterId::new(
            Self::type_name()
                .parse()
                .expect("INTERNAL BUG: Failed to parse parameter id as `Name`"),
        )
    }
}
