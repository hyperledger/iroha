//! Module with parameter related functionality.

use iroha_schema::IntoSchema;
use iroha_smart_contract::{data_model::parameter::CustomParameterId, debug::DebugExpectExt};
use serde::{de::DeserializeOwned, Serialize};

/// Blockchain specific parameter
pub trait Parameter: Default + Serialize + DeserializeOwned + IntoSchema {
    /// Parameter id, according to [`IntoSchema`].
    fn id() -> CustomParameterId {
        CustomParameterId::new(
            <Self as iroha_schema::IntoSchema>::type_name()
                .parse()
                .dbg_expect("Failed to parse parameter id as `Name`"),
        )
    }
}
