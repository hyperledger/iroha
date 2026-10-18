//! One explicitly selected account-signed enrollment request for a disposable mobile campaign.
//!
//! Uses the canonical SDK transport once, retains exact originals, and never reads a mobile key.
//! Client configuration and account.key stay in their independently provisioned private directory.
use iroha::{
    Error,
    client::{
        Client,
        kagemusha::{
            EnrollmentServiceActionV1 as Action, EnrollmentServiceRequestV1 as Request,
            EnrollmentServiceResponseV1 as Response,
        },
    },
    config::{Config, HttpTransportPolicy},
};
use iroha_config_base::file_source::{ConfigFileAccess, ConfigFileRequest, ConfigFileSource};
use iroha_fs::{PrivateDirectory, PublishMode, RetainedFile};
use iroha_torii_shared::kagemusha_enrollment::{
    ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1, EnrollmentServiceOutcomeV1 as Outcome,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
const CONFIG_MAX: usize = 16 << 10;
const KEY_MAX: usize = 4096;
const HELP: &str = "kagemusha_enrollment_once ABSOLUTE_CONFIG_DIRECTORY pre-key|evidence|issue|deliver|expiry-proof ABSOLUTE_REQUEST REQUEST_SHA256 ABSOLUTE_OUTPUT_PARENT NEW_OUTPUT_NAME\nOne SDK account-signed POST; no automatic retries. Private client.toml selects actual network/endpoint and account.key. Output directory is created exclusively before dispatch. A missing completed outcome after dispatch.json is unknown; retain the exact request and recover deliberately.";

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn action(text: &str) -> Result<Action> {
    match text {
        "pre-key" => Ok(Action::PreKey),
        "evidence" => Ok(Action::Evidence),
        "issue" => Ok(Action::Issue),
        "deliver" => Ok(Action::Deliver),
        "expiry-proof" => Ok(Action::ExpiryProof),
        _ => Err("action"),
    }
}
fn action_name(value: Action) -> &'static str {
    match value {
        Action::PreKey => "pre-key",
        Action::Evidence => "evidence",
        Action::Issue => "issue",
        Action::Deliver => "deliver",
        Action::ExpiryProof => "expiry-proof",
    }
}
fn digest(text: &str) -> Result<()> {
    if text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err("digest")
    }
}
fn bounded(file: &RetainedFile, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    file.revalidate().map_err(|_| "custody")?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.file()
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "read")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("extent");
    }
    file.revalidate().map_err(|_| "custody")?;
    Ok(bytes)
}
fn exact_keys(table: &toml::Table, required: &[&str], optional: &[&str]) -> Result<()> {
    let keys = table.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if !required.iter().all(|key| keys.contains(key))
        || !keys
            .iter()
            .all(|key| required.contains(key) || optional.contains(key))
    {
        return Err("config-shape");
    }
    Ok(())
}
fn config_shape(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| "config")?;
    let table = text.parse::<toml::Table>().map_err(|_| "config")?;
    exact_keys(
        &table,
        &[
            "chain",
            "network_id",
            "torii_url",
            "http_transport_policy",
            "torii_request_timeout_ms",
            "account",
        ],
        &["api_token"],
    )?;
    let account = table["account"].as_table().ok_or("config-shape")?;
    exact_keys(
        account,
        &["public_key", "private_key_file", "chain_discriminant"],
        &[],
    )?;
    if account["private_key_file"].as_str() != Some("account.key") {
        return Err("config-key-selection");
    }
    match table["torii_request_timeout_ms"].as_integer() {
        Some(1..=120_000) => Ok(()),
        _ => Err("config-timeout"),
    }
}

struct Material {
    directory: PrivateDirectory,
    configuration: RetainedFile,
    key: RetainedFile,
    bytes: Zeroizing<Vec<u8>>,
    key_bytes: Zeroizing<Vec<u8>>,
    key_path: PathBuf,
}
impl Material {
    fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err("absolute-config");
        }
        let directory = PrivateDirectory::open(path).map_err(|_| "custody")?;
        let configuration = directory
            .open_retained_private("client.toml")
            .map_err(|_| "custody")?;
        let bytes = bounded(&configuration, CONFIG_MAX)?;
        // Reject indirect/inline/private key alternatives before accessing any key material.
        config_shape(&bytes)?;
        let key = directory
            .open_retained_private("account.key")
            .map_err(|_| "custody")?;
        let key_bytes = bounded(&key, KEY_MAX)?;
        let key_path = directory.path().join("account.key");
        Ok(Self {
            directory,
            configuration,
            key,
            bytes,
            key_bytes,
            key_path,
        })
    }
    fn revalidate(&self) -> Result<()> {
        self.directory
            .revalidate()
            .and_then(|()| self.configuration.revalidate())
            .and_then(|()| self.key.revalidate())
            .map_err(|_| "custody")
    }
    fn configuration(&self) -> Result<Config> {
        self.revalidate()?;
        let (config, _) = Config::load_bytes_with_musubi_publication_and_file_source(
            self.directory.path().join("client.toml"),
            &self.bytes,
            self,
        )
        .map_err(|_| "config")?;
        let url = &config.torii_api_url;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("endpoint");
        }
        // The canonical config owner validates DirectLoopback's actual host and URL scope.
        match (url.scheme(), config.http_transport_policy) {
            ("http", HttpTransportPolicy::DirectLoopback)
            | ("https", HttpTransportPolicy::Ordinary) => {}
            _ => return Err("endpoint-policy"),
        }
        self.revalidate()?;
        Ok(config)
    }
}
impl ConfigFileSource for Material {
    fn read(&self, path: &Path, request: ConfigFileRequest) -> io::Result<Zeroizing<Vec<u8>>> {
        if path != self.key_path
            || request.access != ConfigFileAccess::Private
            || self.key_bytes.len() > request.maximum
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.revalidate()
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
        Ok(Zeroizing::new(self.key_bytes.to_vec()))
    }
}
fn decode_request(original: &[u8], expected: Action, expected_sha: &str) -> Result<Request> {
    digest(expected_sha)?;
    if sha(original) != expected_sha {
        return Err("request-digest");
    }
    let request = Request::decode_canonical(original).map_err(|_| "request")?;
    if request.action != expected || request.canonical_wire().map_err(|_| "request")? != original {
        return Err("request-action");
    }
    Ok(request)
}
fn response_name(action: Action, value: &Response) -> Result<&'static str> {
    match (action, value) {
        (Action::PreKey, Response::Permit(_)) => Ok("permit"),
        (Action::Evidence, Response::EvidenceReady) => Ok("evidence-ready"),
        (Action::Evidence, Response::Pending) => Ok("pending"),
        (Action::Issue, Response::CredentialReady) => Ok("credential-ready"),
        (Action::Deliver, Response::Credential(_)) => Ok("credential"),
        (Action::ExpiryProof, Response::ExpiryProof(_)) => Ok("expiry-proof"),
        _ => Err("response-action"),
    }
}
fn error_outcome(error: &Error) -> (&'static str, Option<u16>, u8) {
    match error {
        Error::EnrollmentOutcome {
            outcome: Outcome::Refused(reason),
            ..
        } => ("refused", Some(reason.code()), 20),
        Error::EnrollmentOutcome {
            outcome: Outcome::DeliveryWithheld(reason),
            ..
        } => ("delivery-withheld", Some(reason.code()), 21),
        Error::EnrollmentOutcome {
            outcome: Outcome::OutcomeUnknown,
            ..
        } => ("outcome-unknown", None, 22),
        _ => ("transport-or-decode-unknown", None, 23),
    }
}
fn publish(directory: &PrivateDirectory, name: &str, bytes: &[u8]) -> Result<()> {
    directory
        .write_atomic(name, bytes, PublishMode::CreateNew)
        .map_err(|_| "output")?;
    directory.sync().map_err(|_| "output")
}
fn json(value: &norito::json::Value) -> Result<Vec<u8>> {
    norito::json::to_vec(value).map_err(|_| "output")
}
async fn run(args: &[String]) -> Result<u8> {
    if args.len() != 6 {
        return Err("arguments");
    }
    let selected_action = action(&args[1])?;
    digest(&args[3])?;
    let request_path = Path::new(&args[2]);
    let output_parent = Path::new(&args[4]);
    if !request_path.is_absolute() || !output_parent.is_absolute() {
        return Err("absolute-path");
    }
    let material = Material::open(Path::new(&args[0]))?;
    let configuration = material.configuration()?;
    let duration = configuration.torii_request_timeout;
    let client = Client::builder(configuration)
        .build()
        .map_err(|_| "client-context")?;
    let request_file = RetainedFile::open_private(request_path).map_err(|_| "custody")?;
    let original = bounded(&request_file, ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1)?;
    let request = decode_request(&original, selected_action, &args[3])?;
    let parent = PrivateDirectory::open(output_parent).map_err(|_| "custody")?;
    let output = parent
        .create_child(&args[5])
        .map_err(|_| "output-exclusive")?;
    publish(&output, "request.wire", &original)?;
    // This immutable marker precedes the only SDK call. Missing completion after it is uncertain.
    publish(
        &output,
        "dispatch.json",
        &json(&norito::json!({
            "schema":"iroha.kagemusha.enrollment-once-dispatch.v1","action":(action_name(selected_action)),
            "requestSha256":(&args[3]),"requestBytes":(original.len()),"automaticRetry":false
        }))?,
    )?;
    material.revalidate()?;
    request_file.revalidate().map_err(|_| "custody")?;
    let account = client
        .with_request_deadline(Instant::now() + duration)
        .account_client()
        .map_err(|_| "account-context")?;
    let result = account.kagemusha().enrollment(&request).await;
    material.revalidate()?;
    request_file.revalidate().map_err(|_| "custody")?;
    let (kind, refusal, response_sha, exit) = match result {
        Ok(value) => {
            let kind = response_name(selected_action, &value)?;
            let response = value.canonical_wire().map_err(|_| "response")?;
            publish(&output, "response.wire", &response)?;
            (kind, None, Some(sha(&response)), 0)
        }
        Err(error) => {
            let (kind, refusal, exit) = error_outcome(&error);
            (kind, refusal, None, exit)
        }
    };
    publish(
        &output,
        "complete.json",
        &json(&norito::json!({
            "schema":"iroha.kagemusha.enrollment-once-complete.v1","action":(action_name(selected_action)),
            "requestSha256":(&args[3]),"outcome":(kind),"refusalCode":(refusal),"responseSha256":(response_sha),
            "nativeAdmissionClaimed":false,"automaticRetry":false
        }))?,
    )?;
    Ok(exit)
}
fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("enrollment-once: panic; any dispatched outcome remains uncertain")
    }));
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["--help"] {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!("enrollment-once: runtime");
        return ExitCode::from(2);
    };
    match runtime.block_on(run(&args)) {
        Ok(code) => ExitCode::from(code),
        Err(code) => {
            eprintln!("enrollment-once: {code}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_retains_the_borrowed_output_value() {
        let value = norito::json!({"outcome": "outcome-unknown", "automaticRetry": false});
        let original = value.clone();
        let bytes = json(&value).expect("bounded output JSON");
        let decoded: norito::json::Value =
            norito::json::from_slice(&bytes).expect("canonical output JSON");
        assert_eq!(decoded, original);
        assert_eq!(value, original);
    }
    use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair};
    fn config(key: &KeyPair) -> Vec<u8> {
        format!("chain = \"component-test-only\"\nnetwork_id = \"hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0\"\ntorii_url = \"http://127.0.0.1:12345/\"\nhttp_transport_policy = \"direct_loopback\"\ntorii_request_timeout_ms = 1000\n[account]\nchain_discriminant = 753\npublic_key = \"{}\"\nprivate_key_file = \"account.key\"\n",key.public_key()).into_bytes()
    }
    fn material() -> (tempfile::TempDir, PrivateDirectory, KeyPair) {
        let temp = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::open_or_create(temp.path().join("private")).unwrap();
        let key = KeyPair::try_from_seed(vec![91; 32], Algorithm::Ed25519).unwrap();
        publish(&directory, "client.toml", &config(&key)).unwrap();
        publish(
            &directory,
            "account.key",
            format!("{}\n", ExposedPrivateKey(key.private_key().clone())).as_bytes(),
        )
        .unwrap();
        (temp, directory, key)
    }
    #[test]
    fn canonical_requests_bind_action_and_complete_originals() {
        for action in [
            Action::PreKey,
            Action::Evidence,
            Action::Issue,
            Action::Deliver,
            Action::ExpiryProof,
        ] {
            let value = Request {
                version: 1,
                action,
                dispatch_original: vec![1, 2, 3],
                evidence_original: if action == Action::Evidence {
                    vec![4]
                } else {
                    vec![]
                },
            };
            let bytes = value.canonical_wire().unwrap();
            assert_eq!(decode_request(&bytes, action, &sha(&bytes)).unwrap(), value);
            assert!(decode_request(&bytes, action, &"a".repeat(64)).is_err());
            let wrong = if action == Action::PreKey {
                Action::Issue
            } else {
                Action::PreKey
            };
            assert!(decode_request(&bytes, wrong, &sha(&bytes)).is_err());
            let mut trailing = bytes;
            trailing.push(0);
            assert!(decode_request(&trailing, action, &sha(&trailing)).is_err());
        }
        assert!(action("PRE_KEY").is_err());
        assert_eq!(action("expiry-proof"), Ok(Action::ExpiryProof));
        assert_eq!(action_name(Action::ExpiryProof), "expiry-proof");
        assert!(digest(&"A".repeat(64)).is_err());
    }
    #[test]
    fn all_success_response_shapes_require_the_actual_action() {
        for (action, value, name) in [
            (Action::PreKey, Response::Permit(vec![1]), "permit"),
            (Action::Evidence, Response::EvidenceReady, "evidence-ready"),
            (Action::Evidence, Response::Pending, "pending"),
            (Action::Issue, Response::CredentialReady, "credential-ready"),
            (Action::Deliver, Response::Credential(vec![1]), "credential"),
            (
                Action::ExpiryProof,
                Response::ExpiryProof(vec![1]),
                "expiry-proof",
            ),
        ] {
            assert_eq!(response_name(action, &value), Ok(name));
            let other = if action == Action::PreKey {
                Action::Issue
            } else {
                Action::PreKey
            };
            assert!(response_name(other, &value).is_err());
            let wire = value.canonical_wire().unwrap();
            assert_eq!(
                Response::decode_canonical(&wire)
                    .unwrap()
                    .canonical_wire()
                    .unwrap(),
                wire
            );
        }
    }
    #[test]
    fn config_shape_refuses_alternate_key_sources_without_echoing_input() {
        let (_, _, key) = material();
        let original = String::from_utf8(config(&key)).unwrap();
        for value in [
            original.replace("account.key", "../secret-marker"),
            original.replace(
                "private_key_file = \"account.key\"",
                "private_key = \"secret-marker\"",
            ),
            original.replace(
                "torii_request_timeout_ms = 1000",
                "torii_request_timeout_ms = 0",
            ),
            format!("unknown = \"secret-marker\"\n{original}"),
            "secret-marker = [".to_owned(),
        ] {
            let error = config_shape(value.as_bytes()).unwrap_err();
            assert!(!error.contains("secret-marker"));
        }
    }
    #[test]
    fn private_material_uses_selected_bytes_and_no_reference_fallback() {
        let (_temp, directory, key) = material();
        let selected = Material::open(directory.path()).unwrap();
        assert_eq!(
            selected.configuration().unwrap().key_pair.public_key(),
            key.public_key()
        );
        assert!(
            selected
                .read(
                    Path::new("/unselected/account.key"),
                    ConfigFileRequest {
                        access: ConfigFileAccess::Private,
                        maximum: KEY_MAX
                    }
                )
                .is_err()
        );
        assert!(
            selected
                .read(
                    &selected.key_path,
                    ConfigFileRequest {
                        access: ConfigFileAccess::Public,
                        maximum: KEY_MAX
                    }
                )
                .is_err()
        );
        assert!(
            selected
                .read(
                    &selected.key_path,
                    ConfigFileRequest {
                        access: ConfigFileAccess::Private,
                        maximum: 1
                    }
                )
                .is_err()
        );
        directory
            .write_atomic("account.key", b"changed", PublishMode::Replace)
            .unwrap();
        assert!(selected.configuration().is_err());
    }
    #[test]
    fn explicit_endpoint_policy_preserves_local_loopback_and_refuses_remote_http() {
        let (_temp, directory, key) = material();
        let original = config(&key);
        for (replace, with) in [
            ("127.0.0.1", "example.invalid"),
            ("direct_loopback", "ordinary"),
            (
                "http://127.0.0.1:12345/",
                "http://user:secret-marker@127.0.0.1:12345/",
            ),
        ] {
            let changed = String::from_utf8(original.clone())
                .unwrap()
                .replace(replace, with);
            directory
                .write_atomic("client.toml", changed.as_bytes(), PublishMode::Replace)
                .unwrap();
            assert!(
                Material::open(directory.path())
                    .unwrap()
                    .configuration()
                    .is_err()
            );
        }
    }
    #[test]
    fn output_requires_a_new_attempt_directory_and_never_overwrites() {
        let (_temp, directory, _) = material();
        let output = directory.create_child("attempt").unwrap();
        publish(&output, "request.wire", b"original").unwrap();
        assert!(publish(&output, "request.wire", b"changed").is_err());
        assert!(directory.create_child("attempt").is_err());
        assert_eq!(
            output.read("request.wire", 100).unwrap().as_slice(),
            b"original"
        );
    }
    #[test]
    fn closed_refusal_and_withheld_codes_never_collapse_into_generic_http() {
        use iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1 as Refusal;
        for code in 1..=12 {
            let error = Error::EnrollmentOutcome {
                operation: "secret-marker",
                outcome: Outcome::Refused(Refusal::from_code(code).unwrap()),
            };
            assert_eq!(error_outcome(&error), ("refused", Some(code), 20));
        }
        for code in [11, 12] {
            let error = Error::EnrollmentOutcome {
                operation: "secret-marker",
                outcome: Outcome::DeliveryWithheld(Refusal::from_code(code).unwrap()),
            };
            assert_eq!(error_outcome(&error), ("delivery-withheld", Some(code), 21));
        }
    }
    #[test]
    fn bounded_selected_original_refuses_empty_oversized_and_shared_files() {
        let (_temp, directory, _) = material();
        publish(&directory, "oversized", &[1; 8]).unwrap();
        let original = directory.open_retained_private("oversized").unwrap();
        assert!(bounded(&original, 7).is_err());
        directory
            .write_atomic("empty", &[], PublishMode::CreateNew)
            .unwrap();
        let empty = directory.open_retained_private("empty").unwrap();
        assert!(bounded(&empty, 7).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                directory.path().join("client.toml"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(Material::open(directory.path()).is_err());
        }
    }
    #[test]
    fn transport_and_server_diagnostics_do_not_enter_closed_outcomes() {
        let error = Error::InvalidRequest {
            operation: "secret-marker",
            details: "secret-marker".into(),
        };
        assert_eq!(
            error_outcome(&error),
            ("transport-or-decode-unknown", None, 23)
        );
        let error = Error::EnrollmentOutcome {
            operation: "secret-marker",
            outcome: Outcome::OutcomeUnknown,
        };
        assert_eq!(error_outcome(&error), ("outcome-unknown", None, 22));
    }
}
