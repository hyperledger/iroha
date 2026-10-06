//! Check or publish generator-owned repository IVM fixtures, with atomic replacement per path.
//!
//! Usage:
//! `cargo run --locked -p ivm --features dev-tools --bin ivm_fixture_export -- --check`
//! `cargo run --locked -p ivm --features dev-tools --bin ivm_fixture_export -- --write`
//! `cargo run --locked -p ivm --features dev-tools --bin ivm_fixture_export -- --write --output-root /tmp/ivm-fixtures`
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    events::{
        EventFilterBox,
        time::{ExecutionTime, TimeEventFilter},
    },
    smart_contract::manifest::{
        ContractErrorMessage, ContractErrorTypeDescriptor, ContractErrorVariantDescriptor,
        ContractManifest, EntryPointKind, EntrypointDescriptor, TriggerCallback, TriggerDescriptor,
    },
    trigger::action::Repeats,
};
use iroha_model_base::metadata::Metadata;
use ivm::prebuilt_fixtures::build_default_executor_program;
use norito::json::{FastJsonWrite, JsonSerialize};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};
// Public deterministic fixture material; this key must never authorize a real account.
const CONTRACT_MANIFEST_FIXTURE_SIGNER_SEED: [u8; 32] = [0x33; 32];
// Largest canonical signing frame the fixed contract-manifest fixture may encode.
const CONTRACT_MANIFEST_FIXTURE_FRAME_LIMIT: usize = 64 * 1024;
// Physical scratch funded for signing and verifying the fixed contract-manifest fixture.
const CONTRACT_MANIFEST_FIXTURE_SCRATCH_BYTES: usize = 8 * CONTRACT_MANIFEST_FIXTURE_FRAME_LIMIT;
/// Run `body` with the funded, bounded codec context the fixture manifest is signed under.
///
/// The pool owns the cumulative counter and the signing scratch for exactly this call; the
/// signed bytes do not depend on the context.
fn with_contract_manifest_fixture_signing_context<R>(
    body: impl FnOnce(&norito::core::DecodeBudgetContext) -> R,
) -> Result<R, String> {
    let pool = iroha_allocation::AllocationBudget::new(
        CONTRACT_MANIFEST_FIXTURE_SCRATCH_BYTES
            + norito::core::DecodeBudgetContext::allocation_layout().size(),
    );
    let _scratch = pool
        .try_reserve_bytes(CONTRACT_MANIFEST_FIXTURE_SCRATCH_BYTES)
        .map_err(|error| format!("fund contract-manifest fixture signing scratch: {error:?}"))?;
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(
            CONTRACT_MANIFEST_FIXTURE_FRAME_LIMIT,
            CONTRACT_MANIFEST_FIXTURE_FRAME_LIMIT,
            CONTRACT_MANIFEST_FIXTURE_FRAME_LIMIT,
            CONTRACT_MANIFEST_FIXTURE_SCRATCH_BYTES,
            256,
        ),
        &pool,
    )
    .map_err(|error| format!("fund contract-manifest fixture signing counter: {error}"))?;
    Ok(body(&context))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Check,
    Write,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Options {
    mode: Mode,
    output_root: PathBuf,
}
fn parse_options_from(arguments: &[String], default_output_root: &Path) -> Result<Options, String> {
    let mut mode = None;
    let mut output_root = None;
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--check" | "--write" => {
                let requested = if argument == "--check" {
                    Mode::Check
                } else {
                    Mode::Write
                };
                if mode.replace(requested).is_some() {
                    return Err("expected exactly one of --check or --write".to_owned());
                }
            }
            "--output-root" => {
                if output_root.is_some() {
                    return Err("--output-root was supplied more than once".to_owned());
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| "--output-root requires a directory path".to_owned())?;
                if value.is_empty() || value.starts_with('-') {
                    return Err("--output-root requires a non-empty directory path".to_owned());
                }
                output_root = Some(PathBuf::from(value));
            }
            _ => {
                return Err(format!(
                    "unknown argument `{argument}`; usage: --write|--check [--output-root <path>]"
                ));
            }
        }
    }
    Ok(Options {
        mode: mode.ok_or_else(|| "expected exactly one of --check or --write".to_owned())?,
        output_root: output_root.unwrap_or_else(|| default_output_root.to_path_buf()),
    })
}
fn parse_options() -> Result<Options, String> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    parse_options_from(&arguments, &repository_root())
}
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("IVM crate belongs to the workspace")
        .to_path_buf()
}
struct ContractManifestFixtureDocument<'a> {
    event_filter_frame_hex: String,
    manifest: &'a ContractManifest,
    manifest_compact_hex: String,
    registration_manifest: &'a ContractManifest,
    registration_manifest_compact_hex: String,
    signed_manifest: &'a ContractManifest,
    signed_manifest_compact_hex: String,
}
impl FastJsonWrite for ContractManifestFixtureDocument<'_> {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("fixture_version", out);
        out.push(':');
        1_u64.json_serialize(out);
        out.push(',');
        norito::json::write_json_string("generator", out);
        out.push(':');
        "iroha_data_model::Encode on the current Rust V1 types".json_serialize(out);
        out.push(',');
        norito::json::write_json_string("event_filter_box", out);
        out.push(':');
        out.push('{');
        norito::json::write_json_string("description", out);
        out.push(':');
        "EventFilterBox::Time(TimeEventFilter::new(ExecutionTime::PreCommit))".json_serialize(out);
        out.push(',');
        norito::json::write_json_string("norito_frame_hex", out);
        out.push(':');
        self.event_filter_frame_hex.json_serialize(out);
        out.push('}');
        out.push(',');
        norito::json::write_json_string("manifest", out);
        out.push(':');
        self.manifest.json_serialize(out);
        out.push(',');
        norito::json::write_json_string("manifest_compact_hex", out);
        out.push(':');
        self.manifest_compact_hex.json_serialize(out);
        out.push(',');
        norito::json::write_json_string("registration_manifest", out);
        out.push(':');
        self.registration_manifest.json_serialize(out);
        out.push(',');
        norito::json::write_json_string("registration_manifest_compact_hex", out);
        out.push(':');
        self.registration_manifest_compact_hex.json_serialize(out);
        out.push(',');
        norito::json::write_json_string("signed_provenance", out);
        out.push(':');
        self.signed_manifest
            .provenance
            .as_ref()
            .expect("fixture manifest provenance")
            .json_serialize(out);
        out.push(',');
        norito::json::write_json_string("signed_manifest_compact_hex", out);
        out.push(':');
        self.signed_manifest_compact_hex.json_serialize(out);
        out.push('}');
    }
}
fn contract_manifest_fixture_types()
-> Result<(EventFilterBox, ContractManifest, ContractManifest), String> {
    let event_filter = EventFilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit));
    let trigger = TriggerDescriptor {
        id: "wake"
            .parse()
            .map_err(|error| format!("build contract-manifest trigger ID: {error}"))?,
        repeats: Repeats::Indefinitely,
        filter: event_filter.clone(),
        authority: None,
        metadata: Metadata::default(),
        callback: TriggerCallback {
            namespace: None,
            entrypoint: "run".to_owned(),
        },
    };
    let manifest = ContractManifest {
        seiyaku_name: Some("Test".to_owned()),
        code_hash: None,
        abi_hash: None,
        compiler_fingerprint: None,
        features_bitmap: None,
        access_set_hints: None,
        entrypoints: Some(vec![EntrypointDescriptor {
            name: "run".to_owned(),
            kind: EntryPointKind::Kotoage,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit] }),
            permission: Some("Execute".to_owned()),
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: vec![trigger],
        }]),
        states: None,
        error_messages: Some(vec![ContractErrorMessage {
            error_type: "Test::Failure".into(),
            code: 7,
            message: "残高が不足しています".into(),
        }]),
        error_types: Some(vec![ContractErrorTypeDescriptor {
            identity: "Test::Failure".into(),
            variants: vec![ContractErrorVariantDescriptor {
                name: "Insufficient".into(),
                code: 7,
            }],
        }]),
        kotoba: None,
        provenance: None,
    };
    let key_pair = KeyPair::try_from_seed(
        CONTRACT_MANIFEST_FIXTURE_SIGNER_SEED.to_vec(),
        Algorithm::Ed25519,
    )
    .map_err(|error| format!("derive contract-manifest fixture signer: {error}"))?;
    let signed_manifest = with_contract_manifest_fixture_signing_context(|context| {
        manifest
            .clone()
            .try_signed(context, CONTRACT_MANIFEST_FIXTURE_FRAME_LIMIT, &key_pair)
            .map_err(|error| format!("sign contract-manifest fixture: {error}"))
    })??;
    Ok((event_filter, manifest, signed_manifest))
}
fn render_contract_manifest_v1_fixture() -> Result<String, String> {
    let (event_filter, manifest, signed_manifest) = contract_manifest_fixture_types()?;
    // Keep the schema-only null-hash fixture, and independently encode the complete
    // hash-bound manifest accepted by public artifact-registration builders.
    let mut registration_manifest = manifest.clone();
    registration_manifest.code_hash = Some(iroha_crypto::Hash::prehashed([0x11; 32]));
    let event_filter_frame = norito::encode_canonical(&event_filter)
        .map_err(|error| format!("encode canonical event-filter fixture frame: {error}"))?;
    let document = ContractManifestFixtureDocument {
        event_filter_frame_hex: hex::encode(event_filter_frame),
        manifest: &manifest,
        manifest_compact_hex: hex::encode(norito::codec::Encode::encode(&manifest)),
        registration_manifest: &registration_manifest,
        registration_manifest_compact_hex: hex::encode(norito::codec::Encode::encode(
            &registration_manifest,
        )),
        signed_manifest: &signed_manifest,
        signed_manifest_compact_hex: hex::encode(norito::codec::Encode::encode(&signed_manifest)),
    };
    let mut rendered = norito::json::to_json_pretty(&document)
        .map_err(|error| format!("render contract-manifest fixture JSON: {error}"))?;
    rendered.push('\n');
    Ok(rendered)
}
struct SmartContractCodeExecutorHashesFixtureDocument {
    artifact_length: u64,
    code_hash_hex: String,
    abi_hash_hex: String,
    abi_version: u8,
}
impl FastJsonWrite for SmartContractCodeExecutorHashesFixtureDocument {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("fixture_version", out);
        out.push(':');
        1_u64.json_serialize(out);
        out.push(',');
        norito::json::write_json_string("generator", out);
        out.push(':');
        "ivm_fixture_export from the metadata-validated defaults/executor.to artifact"
            .json_serialize(out);
        out.push(',');
        norito::json::write_json_string("artifact", out);
        out.push(':');
        "defaults/executor.to".json_serialize(out);
        out.push(',');
        norito::json::write_json_string("artifact_length", out);
        out.push(':');
        self.artifact_length.json_serialize(out);
        out.push(',');
        norito::json::write_json_string("code_hash_hex", out);
        out.push(':');
        self.code_hash_hex.json_serialize(out);
        out.push(',');
        norito::json::write_json_string("abi_hash_hex", out);
        out.push(':');
        self.abi_hash_hex.json_serialize(out);
        out.push(',');
        norito::json::write_json_string("abi_version", out);
        out.push(':');
        self.abi_version.json_serialize(out);
        out.push('}');
    }
}
fn render_smart_contract_code_executor_hashes_fixture(artifact: &[u8]) -> Result<String, String> {
    let parsed = ivm::ProgramMetadata::parse(artifact)
        .map_err(|error| format!("parse defaults/executor.to fixture: {error}"))?;
    let abi_hash_start = ivm::HEADER_SIZE - iroha_crypto::Hash::LENGTH;
    let abi_hash = artifact
        .get(abi_hash_start..ivm::HEADER_SIZE)
        .ok_or_else(|| "defaults/executor.to fixture is missing its ABI hash".to_owned())?;
    let document = SmartContractCodeExecutorHashesFixtureDocument {
        artifact_length: u64::try_from(artifact.len())
            .map_err(|_| "defaults/executor.to fixture length does not fit u64".to_owned())?,
        code_hash_hex: hex::encode(ivm::contract_code_hash(artifact).as_ref()),
        abi_hash_hex: hex::encode(abi_hash),
        abi_version: parsed.metadata.abi_version,
    };
    let mut rendered = norito::json::to_json_pretty(&document)
        .map_err(|error| format!("render smart-contract code hash fixture JSON: {error}"))?;
    rendered.push('\n');
    Ok(rendered)
}
fn publish(path: &Path, expected: &[u8], mode: Mode) -> Result<(), String> {
    if fs::read(path).ok().as_deref() == Some(expected) {
        eprintln!("fresh {}", path.display());
        return Ok(());
    }
    if mode == Mode::Check {
        return Err(format!(
            "stale or missing generated fixture {}",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("fixture has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("fixture name is not UTF-8: {}", path.display()))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", process::id()));
    fs::write(&temporary, expected)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!(
            "atomically replace {} with {}: {error}",
            path.display(),
            temporary.display()
        )
    })?;
    eprintln!("wrote {}", path.display());
    Ok(())
}
fn main() -> Result<(), String> {
    let Options {
        mode,
        output_root: root,
    } = parse_options()?;
    let contract_manifest_fixture = render_contract_manifest_v1_fixture()?;
    let default_executor = build_default_executor_program();
    let smart_contract_code_hashes_fixture =
        render_smart_contract_code_executor_hashes_fixture(&default_executor)?;
    publish(
        &root.join("javascript/iroha_js/test/fixtures/contract_manifest_v1.json"),
        contract_manifest_fixture.as_bytes(),
        mode,
    )?;
    publish(&root.join("defaults/executor.to"), &default_executor, mode)?;
    publish(
        &root.join("specs/sdk/android/generated/fixtures/smart_contract_code_executor_hashes.json"),
        smart_contract_code_hashes_fixture.as_bytes(),
        mode,
    )?;
    let stage = root
        .join("target/ivm-fixture-export")
        .join(process::id().to_string());
    if stage.exists() {
        fs::remove_dir_all(&stage)
            .map_err(|error| format!("clear staging directory {}: {error}", stage.display()))?;
    }
    ivm::predecoder_fixtures::generate_predecoder_mixed_fixtures(&stage)
        .map_err(|error| format!("generate staged predecoder fixtures: {error}"))?;
    let destination = root.join("crates/ivm/tests/fixtures/predecoder/mixed");
    for relative in [
        Path::new("code.bin"),
        Path::new("decoded.json"),
        Path::new("index.json"),
        Path::new("artifacts/artifact_v1_1_mode00_vlen0_cycles0_abi1.to"),
        Path::new("artifacts/artifact_v1_1_mode03_vlen8_cycles1000_abi1.to"),
    ] {
        let expected = fs::read(stage.join(relative))
            .map_err(|error| format!("read staged {}: {error}", relative.display()))?;
        publish(&destination.join(relative), &expected, mode)?;
    }
    fs::remove_dir_all(&stage)
        .map_err(|error| format!("remove staging directory {}: {error}", stage.display()))?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_requires_an_explicit_mode_and_accepts_a_staged_output_root() {
        let default_root = Path::new("/workspace");
        assert_eq!(
            parse_options_from(&["--check".to_owned()], default_root),
            Ok(Options {
                mode: Mode::Check,
                output_root: default_root.to_path_buf(),
            })
        );
        assert_eq!(
            parse_options_from(
                &[
                    "--output-root".to_owned(),
                    "/staged/fixtures".to_owned(),
                    "--write".to_owned(),
                ],
                default_root,
            ),
            Ok(Options {
                mode: Mode::Write,
                output_root: PathBuf::from("/staged/fixtures"),
            })
        );
        assert!(parse_options_from(&[], default_root).is_err());
        assert!(
            parse_options_from(&["--write".to_owned(), "--check".to_owned()], default_root,)
                .is_err()
        );
        assert!(
            parse_options_from(&["--write".to_owned(), "extra".to_owned()], default_root).is_err()
        );
    }
    #[test]
    fn command_rejects_malformed_output_root_options() {
        let default_root = Path::new("/workspace");
        for arguments in [
            vec!["--write".to_owned(), "--output-root".to_owned()],
            vec![
                "--write".to_owned(),
                "--output-root".to_owned(),
                String::new(),
            ],
            vec![
                "--write".to_owned(),
                "--output-root".to_owned(),
                "--check".to_owned(),
            ],
            vec![
                "--write".to_owned(),
                "--output-root".to_owned(),
                "-h".to_owned(),
            ],
            vec![
                "--write".to_owned(),
                "--output-root".to_owned(),
                "/first".to_owned(),
                "--output-root".to_owned(),
                "/second".to_owned(),
            ],
        ] {
            assert!(parse_options_from(&arguments, default_root).is_err());
        }
    }
    #[test]
    fn contract_manifest_fixture_is_type_derived_signed_and_deterministic() {
        let (_, manifest, signed_manifest) =
            contract_manifest_fixture_types().expect("build typed contract-manifest fixture");
        let payload_of = |manifest: &ContractManifest| {
            with_contract_manifest_fixture_signing_context(|context| {
                manifest.signature_payload_bytes(context, CONTRACT_MANIFEST_FIXTURE_FRAME_LIMIT)
            })
            .expect("fund fixture signing context")
            .expect("encode bounded fixture signature payload")
        };
        let signed_payload = payload_of(&signed_manifest);
        assert_eq!(
            payload_of(&manifest),
            signed_payload,
            "provenance must not change the signed payload"
        );
        let provenance = signed_manifest
            .provenance
            .as_ref()
            .expect("fixture manifest provenance");
        provenance
            .signature
            .verify(&provenance.signer, &signed_payload)
            .expect("fixture manifest signature");
        // The context only accounts for the frame: a frame limit below the payload refuses,
        // and no other limit changes the signed bytes.
        assert!(signed_payload.len() <= CONTRACT_MANIFEST_FIXTURE_FRAME_LIMIT);
        assert!(
            with_contract_manifest_fixture_signing_context(|context| {
                signed_manifest.signature_payload_bytes(context, signed_payload.len() - 1)
            })
            .expect("fund fixture signing context")
            .is_err(),
            "a frame limit below the canonical payload must refuse"
        );
        let rendered =
            render_contract_manifest_v1_fixture().expect("render contract-manifest fixture");
        assert_eq!(
            render_contract_manifest_v1_fixture().expect("render fixture again"),
            rendered
        );
        {
            let alternate_flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            assert_eq!(
                render_contract_manifest_v1_fixture()
                    .expect("render fixture under alternate ambient layout"),
                rendered
            );
        }
        assert!(rendered.ends_with('\n'));
        assert!(rendered.contains(&hex::encode(norito::codec::Encode::encode(&manifest))));
        assert!(manifest.code_hash.is_none());
        let mut registration_manifest = manifest.clone();
        registration_manifest.code_hash = Some(iroha_crypto::Hash::prehashed([0x11; 32]));
        let parsed: norito::json::Value =
            norito::json::from_str(&rendered).expect("fixture document");
        assert_eq!(
            parsed
                .get("registration_manifest_compact_hex")
                .and_then(norito::json::Value::as_str),
            Some(hex::encode(norito::codec::Encode::encode(&registration_manifest)).as_str()),
        );
        assert_eq!(
            parsed.get("registration_manifest"),
            Some(&norito::json::to_value(&registration_manifest).expect("registration manifest")),
        );
        assert!(
            rendered.contains(&hex::encode(norito::codec::Encode::encode(
                &signed_manifest
            )))
        );
    }
    #[test]
    fn smart_contract_code_hash_fixture_is_metadata_validated_and_deterministic() {
        let artifact = build_default_executor_program();
        let parsed =
            ivm::ProgramMetadata::parse(&artifact).expect("parse default executor fixture");
        let abi_hash_start = ivm::HEADER_SIZE - iroha_crypto::Hash::LENGTH;
        let abi_hash_hex = hex::encode(&artifact[abi_hash_start..ivm::HEADER_SIZE]);
        let rendered = render_smart_contract_code_executor_hashes_fixture(&artifact)
            .expect("render smart-contract code hash fixture");
        assert_eq!(
            render_smart_contract_code_executor_hashes_fixture(&artifact)
                .expect("render smart-contract code hash fixture again"),
            rendered
        );
        assert!(rendered.ends_with('\n'));
        assert!(rendered.contains("\"artifact\": \"defaults/executor.to\""));
        assert!(rendered.contains(&hex::encode(ivm::contract_code_hash(&artifact).as_ref())));
        assert!(rendered.contains(&abi_hash_hex));
        assert!(rendered.contains(&format!("\"artifact_length\": {}", artifact.len())));
        assert!(rendered.contains(&format!("\"abi_version\": {}", parsed.metadata.abi_version)));
    }
    #[test]
    fn publish_is_checkable_idempotent_and_replaces_stale_bytes() {
        let directory = env::temp_dir().join(format!(
            "ivm-fixture-export-test-{}-{}",
            process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let path = directory.join("fixture.to");
        let _ = fs::remove_dir_all(&directory);
        assert!(publish(&path, b"canonical", Mode::Check).is_err());
        publish(&path, b"canonical", Mode::Write).expect("publish fixture");
        publish(&path, b"canonical", Mode::Check).expect("fresh fixture passes check");
        fs::write(&path, b"stale").expect("make fixture stale");
        assert!(publish(&path, b"canonical", Mode::Check).is_err());
        publish(&path, b"canonical", Mode::Write).expect("replace stale fixture");
        assert_eq!(fs::read(&path).expect("read fixture"), b"canonical");
        fs::remove_dir_all(directory).expect("remove test directory");
    }
    #[test]
    fn repository_root_contains_the_ivm_crate() {
        assert!(repository_root().join("crates/ivm/Cargo.toml").is_file());
    }
}
