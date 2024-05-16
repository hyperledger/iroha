//! Executor-defined configuration parameters

use iroha_executor::prelude::{Parameter as ParameterObject, ParameterId};
use iroha_schema::IntoSchema;
use iroha_smart_contract_utils::debug::DebugExpectExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    data_model::executor::ExecutorDataModelObject, ConvertDataModelObject,
    ConvertDataModelObjectError,
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
///
/// To convert to/from [`ParameterObject`], use [`ParameterConvertWrap`].
pub trait Parameter: Serialize + DeserializeOwned + IntoSchema {
    /// Parameter definition id, according to [`IntoSchema`].
    fn definition_id() -> ParameterId {
        ParameterId::new(
            <Self as iroha_schema::IntoSchema>::type_name()
                .parse()
                .dbg_expect("Failed to parse parameter id as `Name`"),
        )
    }

    /// Try to convert from [`ParameterObject`]
    /// # Errors
    /// See [`ConvertDataModelObject::try_from_object`]
    fn try_from_object(
        object: &ParameterObject,
    ) -> crate::prelude::Result<Self, ConvertDataModelObjectError> {
        ParameterConvertWrap::try_from_object(object).map(|x| x.0)
    }

    /// Convert into [`ParameterObject`]
    fn into_object(self) -> ParameterObject {
        ParameterConvertWrap(self).into_object()
    }
}

/// Utility to convert between `T`: [`Parameter`] and [`ParameterObject`].
///
/// Similar to [`crate::permission::TokenConvertWrap`].
#[derive(Serialize, Deserialize)]
pub(crate) struct ParameterConvertWrap<T>(pub T);

impl<T: Parameter> ConvertDataModelObject for ParameterConvertWrap<T> {
    type Object = ParameterObject;

    fn definition_id() -> <Self::Object as ExecutorDataModelObject>::DefinitionId {
        T::definition_id()
    }
}
