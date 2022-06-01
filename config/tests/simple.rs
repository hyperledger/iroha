#![allow(clippy::restriction)]

use iroha_config::{derive::Configurable, Configurable};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, Configurable)]
#[config(env_prefix = "CONF_")]
struct Configuration {
    /// Inner structure
    #[config(inner)]
    inner: InnerConfiguration,
}

#[derive(Clone, Debug, Deserialize, Serialize, Configurable, PartialEq, Eq)]
#[config(env_prefix = "CONF_INNER_")]
struct InnerConfiguration {
    pub a: String,
    // From expression
    /// Docs from b
    pub b: i32,
}

#[test]
fn test_docs() {
    assert_eq!(
        Configuration::get_doc_recursive(["inner", "b"]).unwrap(),
        Some(" Docs from b\n\nHas type `i32`. Can be configured via environment variable `CONF_INNER_B`".to_owned())
    );
    assert_eq!(
        Configuration::get_doc_recursive(["inner", "a"]).unwrap(),
        Some(
            "Has type `String`. Can be configured via environment variable `CONF_INNER_A`"
                .to_owned()
        )
    );
    assert_eq!(
        Configuration::get_doc_recursive(["inner"]).unwrap(),
        Some(" Inner structure\n\nHas type `InnerConfiguration`. Can be configured via environment variable `CONF_INNER`\n\nHas following fields:\n\na: Has type `String`. Can be configured via environment variable `CONF_INNER_A`\n\nb:  Docs from b\n\nHas type `i32`. Can be configured via environment variable `CONF_INNER_B`\n\n\n".to_owned())
    );
}
