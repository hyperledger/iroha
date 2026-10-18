// Configuration admission only: identity files are loaded by Torii before binding.
fn torii_https_table_mut(table: &mut Table) -> &mut Table {
    table
        .get_mut("torii")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .entry("transport")
        .or_insert_with(|| Value::Table(Table::new()))
        .as_table_mut()
        .unwrap()
        .entry("https")
        .or_insert_with(|| Value::Table(Table::new()))
        .as_table_mut()
        .unwrap()
}
fn https_table() -> Table {
    let mut table = base_table();
    let address = table["torii"]["address"].clone();
    let https = torii_https_table_mut(&mut table);
    https.insert("address".into(), address);
    https.insert(
        "certificate_chain".into(),
        Value::Array(vec![Value::String("identity/leaf.der".into())]),
    );
    https.insert(
        "private_key".into(),
        Value::String("identity/key.der".into()),
    );
    table
}
#[test]
fn torii_https_is_disabled_by_default_and_keeps_http_copy_limits() {
    let config = load_root(base_table());
    assert!(config.torii.transport.https.is_none());
    let http = config.torii.transport.http;
    let copied = http;
    assert_eq!(http.max_connections, copied.max_connections);
    assert_eq!(
        super::ToriiHttpsTransport::default()
            .handshake_timeout_ms
            .get(),
        Duration::from_secs(10)
    );
}
#[test]
fn torii_https_complete_identity_preserves_paths_and_handshake_bound() {
    let temporary = TestDir::create("https-origin");
    let source = temporary.path().join("node.toml");
    fs::write(&source, toml::to_string(&https_table()).unwrap()).unwrap();
    let config = actual::Root::from_toml_source(TomlSource::from_file(&source).unwrap()).unwrap();
    let https = config.torii.transport.https.unwrap();
    assert_eq!(https.address.value(), config.torii.address.value());
    assert_eq!(
        https.certificate_chain,
        vec![temporary.path().join("identity/leaf.der")]
    );
    assert_eq!(https.private_key, temporary.path().join("identity/key.der"));
    assert_eq!(https.handshake_timeout, Duration::from_secs(10));
}
#[test]
fn torii_https_rejects_partial_identity_empty_paths_and_unbounded_handshake() {
    for field in ["address", "private_key", "certificate_chain"] {
        let mut table = https_table();
        torii_https_table_mut(&mut table).remove(field);
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "missing {field}"
        );
    }
    for (field, value) in [
        (
            "certificate_chain",
            Value::Array(vec![Value::String("leaf.der".into()); 5]),
        ),
        (
            "certificate_chain",
            Value::Array(vec![Value::String(String::new())]),
        ),
        ("private_key", Value::String(String::new())),
        ("handshake_timeout_ms", Value::Integer(0)),
        ("handshake_timeout_ms", Value::Integer(120_001)),
    ] {
        let mut table = https_table();
        torii_https_table_mut(&mut table).insert(field.into(), value);
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "invalid {field}"
        );
    }
}
#[test]
fn torii_https_identity_paths_resolve_from_each_config_origin() {
    use iroha_config_base::{ParameterOrigin, WithOrigin};
    let origin = || ParameterOrigin::custom("inline".into());
    let mut user = super::ToriiHttpsTransport {
        address: Some(WithOrigin::new(
            load_root(base_table()).torii.address.into_value(),
            origin(),
        )),
        ..super::ToriiHttpsTransport::default()
    };
    let path = |name: &str, source: &str| {
        WithOrigin::new(
            PathBuf::from(name),
            ParameterOrigin::file(
                iroha_config_base::ParameterId::from(["torii", "transport", "https"]),
                PathBuf::from(source),
            ),
        )
    };
    user.certificate_chain = path("leaf.der", "conf/node.toml").map(|path| vec![path]);
    user.private_key = Some(path("key.der", "secret/identity.toml"));
    let mut emitter = Emitter::new();
    let actual = user.parse(&mut emitter).unwrap();
    emitter.into_result().unwrap();
    assert_eq!(
        actual.certificate_chain,
        vec![PathBuf::from("conf/leaf.der")]
    );
    assert_eq!(actual.private_key, PathBuf::from("secret/key.der"));
}
