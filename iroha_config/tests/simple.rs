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

#[async_std::test]
async fn test_inner() {
    let mut x = InnerConfiguration {
        a: "bc".to_owned(),
        b: 10,
    };
    assert!(x.set("b", serde_json::json!(200)).await.is_ok());
    assert!(x.set("a", serde_json::json!(200)).await.is_err());
    assert_eq!(x.b, 200);
}

#[async_std::test]
async fn test_outer() {
    let mut x = Configuration {
        inner: InnerConfiguration {
            a: "bc".to_owned(),
            b: 10,
        },
    };
    assert!(x
        .set_recursive(["inner", "b"], serde_json::json!(200))
        .await
        .is_ok());
    assert!(x
        .set_recursive(["inner", "a"], serde_json::json!(200))
        .await
        .is_err());
    assert_eq!(x.inner.b, 200);
    assert!(x
        .set_recursive(
            ["inner"],
            serde_json::json!({
                "a": "a",
                "b": 20,
            })
        )
        .await
        .is_ok());
    assert_eq!(
        x.inner,
        InnerConfiguration {
            a: "a".to_owned(),
            b: 20
        }
    );
}

#[test]
fn test_docs() {
    assert_eq!(
        Configuration::get_doc_recursive(["inner", "b"]).unwrap(),
        Some(" Docs from b\n\nHas type `i32`. Can be configured via environment variable `CONF_INNER_B`")
    );
    assert_eq!(
        Configuration::get_doc_recursive(["inner", "a"]).unwrap(),
        Some("Has type `String`. Can be configured via environment variable `CONF_INNER_A`")
    );
    assert_eq!(
        Configuration::get_doc_recursive(["inner"]).unwrap(),
        Some(" Inner structure\n\nHas type `InnerConfiguration`. Can be configured via environment variable `CONF_INNER`")
    );
}
