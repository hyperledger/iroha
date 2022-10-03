#![allow(clippy::restriction)]

use iroha_config_base::{
    derive::{Documented, Error, FieldError, LoadFromEnv},
    proxy::{Documented as _, LoadFromEnv},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, Documented, LoadFromEnv)]
#[config(env_prefix = "CONF_")]
struct Configuration {
    /// Inner structure
    #[config(inner)]
    inner: InnerConfiguration,
    #[config(serde_as_str)]
    pub string_wrapper: StringWrapper,
    pub string: String,
    pub data: Data,
    #[config(inner)]
    optional_inner: Option<InnerConfiguration>,
    #[config(serde_as_str)]
    pub optional_string_wrapper: Option<StringWrapper>,
    pub optional_string: Option<String>,
    pub optional_data: Option<Data>,
}

impl Configuration {
    fn new() -> Self {
        Self {
            inner: InnerConfiguration {
                a: "".to_owned(),
                b: 0,
            },
            string_wrapper: StringWrapper("".to_owned()),
            string: "".to_owned(),
            data: Data {
                key: "".to_owned(),
                value: 0,
            },
            optional_inner: None,
            optional_string_wrapper: None,
            optional_string: None,
            optional_data: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Documented, LoadFromEnv)]
#[config(env_prefix = "CONF_INNER_")]
struct InnerConfiguration {
    pub a: String,
    // From expression
    /// Docs from b
    pub b: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct Data {
    key: String,
    value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct StringWrapper(String);

#[test]
fn test_docs() {
    assert_eq!(
        Configuration::get_doc_recursive(["inner", "b"]).unwrap(),
        Some(" Docs from b\n\nHas type `i32`[^1]. Can be configured via environment variable `CONF_INNER_B`".to_owned())
    );
    assert_eq!(
        Configuration::get_doc_recursive(["inner", "a"]).unwrap(),
        Some(
            "Has type `String`[^1]. Can be configured via environment variable `CONF_INNER_A`"
                .to_owned()
        )
    );
    assert_eq!(
        Configuration::get_doc_recursive(["inner"]).unwrap(),
        Some(" Inner structure\n\nHas type `InnerConfiguration`[^1]. Can be configured via environment variable `CONF_INNER`\n\nHas following fields:\n\na: Has type `String`[^1]. Can be configured via environment variable `CONF_INNER_A`\n\nb:  Docs from b\n\nHas type `i32`[^1]. Can be configured via environment variable `CONF_INNER_B`\n\n\n".to_owned())
    );
}

// In single test case because env variables is shared across process
#[test]
fn test_load_from_env() {
    let mut config = Configuration::new();
    // Test loading different types of fields from env
    let string_wrapper_json = "string";
    let string = "cool string";
    let data_json = "{\"key\": \"key\", \"value\": 34}";
    let inner_json = "{\"a\": \"\", \"b\": 0}";
    std::env::set_var("CONF_STRING_WRAPPER", string_wrapper_json);
    std::env::set_var("CONF_STRING", string);
    std::env::set_var("CONF_DATA", data_json);
    std::env::set_var("CONF_OPTIONAL_STRING_WRAPPER", string_wrapper_json);
    std::env::set_var("CONF_OPTIONAL_STRING", string);
    std::env::set_var("CONF_OPTIONAL_DATA", data_json);
    // TODO: There is limitation currently fields of optional `inner` configuration can't be loaded when this configuration is `None`
    std::env::set_var("CONF_OPTIONAL_INNER", inner_json);
    std::env::set_var("CONF_INNER_A", "string");
    std::env::set_var("CONF_INNER_B", "42");
    config.load_environment().expect("loaded from env");
    assert_eq!(Some(&config.data), config.optional_data.as_ref());
    assert_eq!(
        Some(&config.string_wrapper),
        config.optional_string_wrapper.as_ref()
    );
    assert_eq!(
        Some(config.string.as_str()),
        config.optional_string.as_deref()
    );
    assert_eq!(Some(&config.inner), config.optional_inner.as_ref());
    // Loading null from env is error
    std::env::set_var("CONF_OPTIONAL_DATA", "null");
    assert!(matches!(
        config.load_environment(),
        Err(Error::FieldError(FieldError {
            field: "optional_data",
            ..
        }))
    ));
}
