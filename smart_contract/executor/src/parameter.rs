//! Executor-defined configuration parameters

use iroha_schema::IntoSchema;
use iroha_smart_contract_utils::debug::DebugExpectExt;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    data_model::JsonString,
    prelude::{Parameter as ParameterObject, *},
    TryFromDataModelObjectError,
};

/// Marker trait for parameters.
///
/// A parameter could be defined in the following way:
///
/// ```
/// use iroha_executor::parameter::Parameter;
/// use iroha_schema::IntoSchema;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(IntoSchema, Serialize, Deserialize)]
/// struct DomainPrefix {
///     prefix: String,
/// }
///
/// impl Parameter for DomainPrefix {}
/// ```
pub trait Parameter: Serialize + DeserializeOwned + IntoSchema {
    /// Parameter id, according to [`IntoSchema`].
    fn id() -> ParameterId {
        ParameterId::new(
            <Self as iroha_schema::IntoSchema>::type_name()
                .parse()
                .dbg_expect("Failed to parse parameter id as `Name`"),
        )
    }

    /// Try to convert from [`ParameterObject`]
    /// # Errors
    /// See [`TryFromDataModelObjectError`]
    fn try_from_object(object: &ParameterObject) -> Result<Self, TryFromDataModelObjectError> {
        if *object.id() != <Self as Parameter>::id() {
            return Err(TryFromDataModelObjectError::Id(object.id().name().clone()));
        }
        object
            .payload()
            .deserialize()
            .map_err(TryFromDataModelObjectError::Deserialize)
    }

    /// Convert into [`ParameterObject`]
    fn to_object(&self) -> ParameterObject {
        ParameterObject::new(
            <Self as Parameter>::id(),
            JsonString::serialize(&self)
                .expect("failed to serialize concrete data model entity; this is a bug"),
        )
    }
}
