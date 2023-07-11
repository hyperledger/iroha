#![allow(clippy::restriction)]

use std::{collections::HashMap, env::VarError, ffi::OsStr};

use iroha_config_base::{
    derive::{Documented, LoadFromEnv, Override},
    proxy::{Documented as _, FetchEnv, LoadFromEnv as _, Override as _},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, LoadFromEnv, Override)]
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

#[derive(Clone, Debug, Deserialize, Serialize, Documented)]
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, LoadFromEnv, Override)]
#[config(env_prefix = "CONF_INNER_")]
struct InnerConfigurationProxy {
    pub a: Option<String>,
    // From expression
    /// Docs from b
    pub b: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Documented)]
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

struct TestEnv {
    map: HashMap<String, String>,
}

impl TestEnv {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    fn set_var(&mut self, key: impl AsRef<str>, value: impl AsRef<str>) {
        self.map
            .insert(key.as_ref().to_owned(), value.as_ref().to_owned());
    }

    fn remove_var(&mut self, key: impl AsRef<str>) {
        self.map.remove(key.as_ref());
    }
}

impl FetchEnv for TestEnv {
    fn fetch<K: AsRef<OsStr>>(&self, key: K) -> Result<String, VarError> {
        self.map
            .get(
                key.as_ref()
                    .to_str()
                    .ok_or_else(|| VarError::NotUnicode(key.as_ref().to_owned()))?,
            )
            .ok_or(VarError::NotPresent)
            .map(Clone::clone)
    }
}

fn test_env_factory() -> TestEnv {
    let string_wrapper_json = "string";
    let string = "cool string";
    let data_json = r#"{"key": "key", "value": 34}"#;
    let inner_json = r#"{"a": "", "b": 0}"#;
    let mut env = TestEnv::new();
    env.set_var("CONF_STRING_WRAPPER", string_wrapper_json);
    env.set_var("CONF_STRING", string);
    env.set_var("CONF_DATA", data_json);
    env.set_var("CONF_OPTIONAL_STRING_WRAPPER", string_wrapper_json);
    env.set_var("CONF_OPTIONAL_STRING", string);
    env.set_var("CONF_OPTIONAL_DATA", data_json);
    env.set_var("CONF_OPTIONAL_INNER", inner_json);
    env.set_var("CONF_INNER_A", "string");
    env.set_var("CONF_INNER_B", "42");
    env
}

#[test]
fn test_proxy_load_from_env() {
    let config = ConfigurationProxy::new_with_placeholders();
    let env_config = ConfigurationProxy::from_env(&test_env_factory()).expect("valid env");
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
    let mut env = test_env_factory();
    env.remove_var("CONF_OPTIONAL_INNER");
    let config = ConfigurationProxy::new_with_placeholders();
    let env_config = ConfigurationProxy::from_env(&env).expect("valid env");
    assert_eq!(&env_config.optional_inner, &config.optional_inner)
}

#[test]
fn test_proxy_combine_does_not_overload_with_none() {
    let config = ConfigurationProxy::new_with_none();
    dbg!(&config);
    let env_config = ConfigurationProxy::from_env(&test_env_factory()).expect("valid env");
    dbg!(&env_config);
    let combine_config = env_config.clone().override_with(config);
    dbg!(&combine_config);
    assert_eq!(&env_config.optional_data, &combine_config.optional_data);
}

#[test]
fn configuration_proxy_from_env_returns_err_on_parsing_error() {
    #[derive(LoadFromEnv, Debug)]
    #[config(env_prefix = "")]
    struct Target {
        #[allow(dead_code)]
        foo: Option<u64>,
    }

    struct Env;

    impl FetchEnv for Env {
        fn fetch<K: AsRef<OsStr>>(&self, key: K) -> Result<String, VarError> {
            match key.as_ref().to_str().unwrap() {
                "FOO" => Ok("not u64 for sure".to_owned()),
                _ => Err(VarError::NotPresent),
            }
        }
    }

    let err = Target::from_env(&Env).expect_err("Must not be parsed");
    let err = eyre::Report::new(err);
    assert_eq!(format!("{err:?}"), "Failed to deserialize the field `FOO`\n\nCaused by:\n    JSON5:  --> 1:1\n      |\n    1 | not u64 for sure\n      | ^---\n      |\n      = expected array, boolean, null, number, object, or string\n\nLocation:\n    config/base/tests/simple.rs:212:15");
}
