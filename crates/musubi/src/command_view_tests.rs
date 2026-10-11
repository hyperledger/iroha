//! Genuine compiler/schema fixtures at the authenticated stored-artifact/view boundary.
//! The HTTP peer supplies transport responses; this is not a remote execution/finality claim.
use super::*;
use std::{
    io::Write as _,
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

const SOURCE: &str = r#"
seiyaku Counter { permission Update;
    state int count;
    hajimari() { count = 0; }
    kotoage fn increment(int delta) authorize(Update) {
        count = count + delta;
    }
    view fn current() authorize(anyone) -> int { return count; }
    view fn plus(int delta) authorize(anyone) -> int { return count + delta; }
}
"#;

fn fixture_config(origin: &str) -> iroha::config::Config {
    let source = format!(
        r#"
chain = "00000000-0000-0000-0000-000000000000"
network_id = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
torii_url = "{origin}"
torii_request_timeout_ms = 2000
[account]
chain_discriminant = 753
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
"#
    );
    iroha::config::Config::load_bytes_with_musubi_publication(
        Path::new("unused-view-fixture.toml"),
        source.as_bytes(),
    )
    .expect("native fixture configuration")
    .0
}

fn artifact() -> Vec<u8> {
    kotodama_lang::compiler::Compiler::new()
        .compile_source(SOURCE)
        .expect("genuine initialized counter artifact")
}

fn address(config: &iroha::config::Config) -> ContractAddress {
    ContractAddress::derive(
        &config.network_id,
        &config.account,
        7,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("canonical fixture address")
}

fn read_request(stream: &mut TcpStream) -> (String, Value) {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 2048];
    let (body_start, length) = loop {
        let read = stream.read(&mut chunk).expect("request read");
        assert_ne!(read, 0);
        bytes.extend_from_slice(&chunk[..read]);
        assert!(bytes.len() <= 128 * 1024, "bounded fixture request");
        let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        assert!(length <= 64 * 1024 + 4096);
        break (end + 4, length);
    };
    while bytes.len() < body_start + length {
        let read = stream.read(&mut chunk).expect("body read");
        assert_ne!(read, 0);
        bytes.extend_from_slice(&chunk[..read]);
    }
    let body = &bytes[body_start..body_start + length];
    (
        std::str::from_utf8(&bytes[..body_start])
            .unwrap()
            .to_owned(),
        if body.is_empty() {
            Value::Null
        } else {
            norito::json::from_slice(body).unwrap()
        },
    )
}

fn server(
    listener: TcpListener,
    responses: Vec<Value>,
) -> thread::JoinHandle<Vec<(String, Value)>> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(socket) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture transport deadline");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("transport accept: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            requests.push(read_request(&mut stream));
            let response = norito::json::to_vec(&response).unwrap();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
            stream.write_all(&response).unwrap();
        }
        requests
    })
}

fn binding(address: &ContractAddress, artifact: &[u8]) -> Value {
    let verified = ivm::verify_contract_artifact(artifact).unwrap();
    let hash = hex::encode(verified.code_hash.as_ref());
    object([
        ("found", true.into()),
        ("active", true.into()),
        ("contract_address", norito::json::to_value(address).unwrap()),
        ("dataspace", "universal".into()),
        ("code_hash_hex", hash.clone().into()),
        (
            "abi_hash_hex",
            hex::encode(verified.abi_hash.as_ref()).into(),
        ),
        ("lifecycle", object([("active_code_hash_hex", hash.into())])),
    ])
}

fn view_response(address: &ContractAddress, artifact: &[u8], entrypoint: &str) -> Value {
    object([
        ("ok", true.into()),
        ("contract_address", norito::json::to_value(address).unwrap()),
        (
            "code_hash_hex",
            hex::encode(iroha_data_model::smart_contract::contract_code_hash(artifact).as_ref())
                .into(),
        ),
        ("entrypoint", entrypoint.into()),
        ("result", 7_u64.into()),
    ])
}

#[test]
fn verified_view_clean_client_reads_stored_artifact_and_omits_zero_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = fixture_config(&format!("http://{}/", listener.local_addr().unwrap()));
    let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    let address = address(&config);
    let alias: ContractAlias = "Counter::universal".parse().unwrap();
    let artifact = artifact();
    let artifact_id = ContractArtifactId::for_address(
        &address,
        iroha_data_model::smart_contract::contract_code_hash(&artifact),
    )
    .unwrap();
    let mut base64_json = String::new();
    norito::json::write_base64_json(&artifact, &mut base64_json);
    let code_response = object([
        (
            "network_id",
            norito::json::to_value(&config.network_id).unwrap(),
        ),
        ("artifact_id", norito::json::to_value(&artifact_id).unwrap()),
        ("code_b64", norito::json::from_str(&base64_json).unwrap()),
    ]);
    let handle = server(
        listener,
        vec![
            binding(&address, &artifact),
            code_response,
            view_response(&address, &artifact, "current"),
        ],
    );
    let client = iroha::blocking::Client::new(config.clone()).unwrap();
    // No workspace, compiler output, deployment journal or filesystem input is supplied.
    let stored = read_view_artifact(client.client(), &address, &alias).unwrap();
    assert_eq!(stored, artifact);
    post_verified_view(
        client.client(),
        &config.account,
        &stored,
        &address,
        "current",
        parse_view_payload("{}").unwrap(),
        1_000_000,
    )
    .unwrap();
    let requests = handle.join().unwrap();
    assert!(
        requests[0]
            .0
            .starts_with(&format!("GET /v1/gov/contracts/{address} "))
    );
    assert!(requests[1].0.starts_with(&format!(
        "GET /v1/contracts/artifacts/0/{}/bytes ",
        hex::encode(artifact_id.code_hash.as_ref())
    )));
    assert!(requests[2].0.starts_with("POST /v1/contracts/view "));
    for (headers, _) in &requests {
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("\r\nx-iroha-signature:")
        );
    }
    assert!(requests[2].1.get("payload").is_none());
    assert!(requests[2].1.get("contract_alias").is_none());
    assert_eq!(
        requests[2].1.get("contract_address"),
        Some(&norito::json::to_value(&address).unwrap())
    );
}

#[test]
fn verified_view_retains_parameterized_payload_and_rejects_schema_or_kind_mismatch_before_http() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = fixture_config(&format!("http://{}/", listener.local_addr().unwrap()));
    let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    let address = address(&config);
    let artifact = artifact();
    let handle = server(listener, vec![view_response(&address, &artifact, "plus")]);
    let client = iroha::blocking::Client::new(config.clone()).unwrap();
    post_verified_view(
        client.client(),
        &config.account,
        &artifact,
        &address,
        "plus",
        parse_view_payload(r#"{"delta":"7"}"#).unwrap(),
        1_000_000,
    )
    .unwrap();
    let requests = handle.join().unwrap();
    assert_eq!(
        requests[0].1.get("payload"),
        Some(&norito::json!({"delta": "7"}))
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = fixture_config(&format!("http://{}/", listener.local_addr().unwrap()));
    let client = iroha::blocking::Client::new(config.clone()).unwrap();
    for (entrypoint, payload) in [
        ("current", r#"{"delta":"7"}"#),
        ("plus", "{}"),
        ("plus", r#"{"wrong":"7"}"#),
        ("plus", r#"{"delta":"7","extra":"8"}"#),
        ("increment", r#"{"delta":"7"}"#),
        ("missing", "{}"),
    ] {
        let error = post_verified_view(
            client.client(),
            &config.account,
            &artifact,
            &address,
            entrypoint,
            parse_view_payload(payload).unwrap(),
            1_000_000,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Usage);
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn verified_view_refuses_changed_active_binding_and_changed_execution_artifact() {
    let artifact = artifact();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = fixture_config(&format!("http://{}/", listener.local_addr().unwrap()));
    let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    let address = address(&config);
    let alias: ContractAlias = "Counter::universal".parse().unwrap();
    let mut wrong = binding(&address, &artifact);
    wrong
        .as_object_mut()
        .unwrap()
        .insert("dataspace".into(), "dpn".into());
    let handle = server(listener, vec![wrong]);
    let client = iroha::blocking::Client::new(config.clone()).unwrap();
    assert!(read_view_artifact(client.client(), &address, &alias).is_err());
    assert_eq!(handle.join().unwrap().len(), 1);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut changed = view_response(&address, &artifact, "current");
    changed.as_object_mut().unwrap().insert(
        "code_hash_hex".into(),
        hex::encode(iroha::crypto::Hash::new(b"different installed artifact").as_ref()).into(),
    );
    let config = fixture_config(&format!("http://{}/", listener.local_addr().unwrap()));
    let handle = server(listener, vec![changed]);
    let client = iroha::blocking::Client::new(config.clone()).unwrap();
    assert!(
        post_verified_view(
            client.client(),
            &config.account,
            &artifact,
            &address,
            "current",
            parse_view_payload("{}").unwrap(),
            1_000_000
        )
        .is_err()
    );
    assert_eq!(handle.join().unwrap().len(), 1);
}
