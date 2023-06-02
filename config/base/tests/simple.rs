#![allow(clippy::restriction)]

use iroha_config_base::{proxy::Documented as _, Configuration};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Configuration, Deserialize, Serialize)]
#[config(env_prefix = "CONF_")]
struct ConfigurationProxy {
    /// Inner structure
    #[config(inner)]
    optional_inner: Option<InnerConfigurationProxy>,
    #[config(serde_as_str)]
    pub optional_string_wrapper: Option<StringWrapper>,
    pub optional_string: Option<String>,
    pub optional_data: Option<Data>,
}

#[derive(Clone, Debug, Configuration, Documented, Deserialize, Serialize)]
#[config(env_prefix = "CONF_")]
struct Configuration {
    /// Inner structure
    #[config(inner)]
    inner: InnerConfiguration,
    #[config(serde_as_str)]
    pub string_wrapper: StringWrapper,
    pub string: String,
    pub data: Data,
}

impl ConfigurationProxy {
    fn new_with_placeholders() -> Self {
        Self {
            optional_inner: Some(InnerConfigurationProxy {
                a: Some("string".to_owned()),
                b: Some(42),
            }),
            optional_string_wrapper: Some(StringWrapper("string".to_owned())),
            optional_string: Some("cool string".to_owned()),
            optional_data: Some(Data {
                key: "key".to_owned(),
                value: 34,
            }),
        }
    }

    fn new_with_none() -> Self {
        Self {
            optional_inner: None,
            optional_string_wrapper: None,
            optional_string: None,
            optional_data: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Configuration, Deserialize, Serialize)]
#[config(env_prefix = "CONF_INNER_")]
struct InnerConfigurationProxy {
    pub a: Option<String>,
    // From expression
    /// Docs from b
    pub b: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Configuration, Documented, Deserialize, Serialize)]
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

fn env_var_setup() {
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
    std::env::set_var("CONF_OPTIONAL_INNER", inner_json);
    std::env::set_var("CONF_INNER_A", "string");
    std::env::set_var("CONF_INNER_B", "42");
}

#[test]
fn test_proxy_load_from_env() {
    env_var_setup();
    let config = ConfigurationProxy::new_with_placeholders();
    let env_config = ConfigurationProxy::from_env();
    assert_eq!(&env_config.optional_data, &config.optional_data);
    assert_eq!(
        &env_config.optional_string_wrapper,
        &config.optional_string_wrapper
    );
    assert_eq!(&env_config.optional_string, &config.optional_string);
    assert_eq!(&env_config.optional_inner, &config.optional_inner);
}

#[test]
fn test_can_load_inner_without_the_wrapping_config() {
    env_var_setup();
    std::env::remove_var("CONF_OPTIONAL_INNER");
    let config = ConfigurationProxy::new_with_placeholders();
    let env_config = ConfigurationProxy::from_env();
    assert_eq!(&env_config.optional_inner, &config.optional_inner)
}

#[test]
fn test_proxy_combine_does_not_overload_with_none() {
    env_var_setup();
    let config = ConfigurationProxy::new_with_none();
    dbg!(&config);
    let env_config = ConfigurationProxy::from_env();
    dbg!(&env_config);
    let combine_config = env_config.clone().override_with(config);
    dbg!(&combine_config);
    assert_eq!(&env_config.optional_data, &combine_config.optional_data);
}
