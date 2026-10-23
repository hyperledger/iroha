//! Custom parameter definitions.
use getset::Getters;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;

use norito::json::{self, JsonDeserialize, JsonSerialize};
mod collection;
pub use collection::{
    CustomParameters, CustomParametersAdmissionError, CustomParametersJsonAdmissionError,
};

pub mod json_helpers {
    //! JSON helper utilities for serializing and deserializing custom parameters.
    use super::*;
    use norito::json::{
        self, BoundedJsonError, JsonDeserialize, JsonSerialize, JsonWriteSink, Parser, Value,
    };
    /// Serialize a `CustomParameters` map into a JSON object written to `out`.
    pub fn serialize(parameters: &CustomParameters, out: &mut String) {
        out.push('{');
        let mut first = true;
        for (id, parameter) in parameters {
            if first {
                first = false;
            } else {
                out.push(',');
            }
            json::write_json_string(&id.to_string(), out);
            out.push(':');
            JsonSerialize::json_serialize(parameter, out);
        }
        out.push('}');
    }
    /// Serialize a `CustomParameters` map through a checked JSON sink.
    ///
    /// Unlike [`serialize`], this path never stages the map in a temporary
    /// `String`; it also accounts for the object in the sink's depth budget.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedJsonError`] when the configured output or nesting bound
    /// is exceeded, or when a nested parameter cannot use the checked writer.
    pub fn serialize_bounded(
        parameters: &CustomParameters,
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            let mut first = true;
            for (id, parameter) in parameters {
                if first {
                    first = false;
                } else {
                    out.push(',')?;
                }
                id.json_serialize_to(out)?;
                out.push(':')?;
                parameter.json_serialize_to(out)?;
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
    /// Deserialize a `CustomParameters` map from a JSON stream.
    ///
    /// # Errors
    ///
    /// Returns [`json::Error`] when the input is not an object or contains
    /// invalid parameter identifiers/payloads.
    pub fn deserialize(parser: &mut Parser<'_>) -> Result<CustomParameters, json::Error> {
        CustomParameters::json_deserialize(parser)
    }
    /// Convert an already owned JSON value through the sole strict collection decoder.
    ///
    /// # Errors
    /// Preserves original resource errors and rejects malformed, duplicate or mismatched entries.
    pub fn from_value(value: Value) -> Result<CustomParameters, json::Error> {
        norito::json::value::from_value(value)
    }
}

pub use self::model::*;
#[iroha_data_model_derive::model]
mod model {
    use super::*;
    use derive_more::{Constructor, Display, FromStr};
    use iroha_schema::IntoSchema;
    use norito::codec::{Decode, Encode};
    /// Id of a custom parameter
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::custom::model::CustomParameterId")]
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        FromStr,
        Constructor,
        Decode,
        Encode,
        IntoSchema,
    )]
    pub struct CustomParameterId(pub Name);
    /// A custom blockchain parameter
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::custom::model::CustomParameter")]
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema, Getters)]
    #[getset(get = "pub")]
    pub struct CustomParameter {
        /// Unique id of the parameter.
        pub id: CustomParameterId,
        /// Payload containing actual value.
        ///
        /// It is JSON-encoded, and its structure must correspond to the structure of
        /// the type defined in [`crate::executor::ExecutorDataModel`].
        pub payload: Json,
    }
}
impl CustomParameterId {
    /// Getter for name
    pub fn name(&self) -> &Name {
        &self.0
    }
}
impl CustomParameter {
    /// Constructor
    pub fn new(id: CustomParameterId, payload: impl Into<Json>) -> Self {
        Self {
            id,
            payload: payload.into(),
        }
    }
}
impl crate::Identifiable for CustomParameter {
    type Id = CustomParameterId;
    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl JsonSerialize for CustomParameterId {
    fn json_serialize(&self, out: &mut String) {
        self.0.json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.0.json_serialize_to(out)
    }
}

impl JsonDeserialize for CustomParameterId {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        Name::json_deserialize(parser).map(Self)
    }
}

impl json::JsonObjectKey for CustomParameterId {
    fn visit_json_key_text<E>(&self, visitor: impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
        json::JsonObjectKey::visit_json_key_text(&self.0, visitor)
    }
}

impl json::JsonObjectKeyOwned for CustomParameterId {
    fn from_json_key_text(key: &str) -> Result<Self, json::Error> {
        <Name as json::JsonObjectKeyOwned>::from_json_key_text(key).map(Self)
    }
}

impl JsonSerialize for CustomParameter {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        json::write_json_string("id", out);
        out.push(':');
        self.id.json_serialize(out);
        out.push(',');
        json::write_json_string("payload", out);
        out.push(':');
        self.payload.json_serialize(out);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"id\":")?;
            self.id.json_serialize_to(out)?;
            out.push_str(",\"payload\":")?;
            self.payload.json_serialize_to(out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for CustomParameter {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        collection::decode_parameter(parser)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr as _;
    use iroha_model_base::name::Name;
    #[test]
    fn id_name_returns_inner() {
        let id = CustomParameterId::new(Name::from_str("param").expect("Valid"));
        assert_eq!(id.name(), &Name::from_str("param").expect("Valid"));
    }
    #[test]
    fn new_parameter_stores_payload() {
        let id = CustomParameterId::new(Name::from_str("test").expect("Valid"));
        let json = Json::new(10u32);
        let param = CustomParameter::new(id.clone(), json.clone());
        assert_eq!(param.id, id);
        assert_eq!(param.payload(), &json);
    }
}
