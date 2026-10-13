//! Canonical Norito RPC fixture generation and verification.
//!
//! This module owns the fixture bytes, schema-hash validation, and SDK manifest
//! parity checks. Repository-facing command wrappers should delegate here so
//! every caller exercises the same implementation.
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use blake2::{Blake2bVar, digest::VariableOutput};
use eyre::{Context, Result, bail, eyre};
use hex::encode as hex_encode;
use iroha_crypto::{Algorithm, KeyPair, PublicKey};
#[cfg(test)]
use iroha_data_model::isi::frame_instruction_payload;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::{AssetBalancePolicy, AssetDefinition},
    isi::{
        Instruction, InstructionBox, InstructionRegistry, Register, RegisterPeerWithPop,
        decode_instruction_from_pair, framed_instruction_payload,
    },
    sns::{NameControllerV1, NameRecordV1, NameSelectorV1, NameStatus, SuffixPolicyV1},
    transaction::{
        Executable, ExecutableBatchItem, FeePaymentIntent, IvmBytecode, SignedTransaction,
        TransactionBuilder, executable::ContractInvocation, signed::TransactionPayload,
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_primitives::json::Json;
use norito::{
    codec::Encode,
    json::{self, JsonDeserialize, JsonSerialize, Map, Number, Value},
};
use sha2::{Digest as ShaDigest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt as _;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    fs::File,
    io::{Read, Write},
    num::NonZeroU32,
    path::{Component, Path, PathBuf},
    time::Duration,
};
use tempfile::{TempDir, tempdir, tempdir_in};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
#[path = "norito_rpc/settlement_sources.rs"]
mod settlement_sources;
const CANONICAL_FIXTURE_DIRECTORY: &str = "fixtures/norito_rpc";
const LOCAL_INTEGRATION_PARENT: &str = "target/norito-rpc-local";
const CANONICAL_PAYLOADS: &str = "fixtures/norito_rpc/transaction_payloads.json";
const ALIAS_SETUP_FIXTURE_V1: &str = "fixtures/norito_rpc/alias_setup_v1/alias_setup_v1.json";
const PAYLOADS_BASENAME: &str = "transaction_payloads.json";
const CANONICAL_MANIFEST: &str = "fixtures/norito_rpc/transaction_fixtures.manifest.json";
const PUBLICATION_SEAL_PENDING_SUFFIX: &str = ".norito-rpc-seal.pending";
const SCHEMA_HASH_MANIFEST: &str = "fixtures/norito_rpc/schema_hashes.json";
const SCHEMA_HASH_MANIFEST_BASENAME: &str = "schema_hashes.json";
const MANIFEST_BASENAME: &str = "transaction_fixtures.manifest.json";
const COMPACT_HASH_VECTOR_BASENAME: &str = "iroha_compact_hash_vector.properties";
const COMPACT_HASH_VECTOR_SOURCE: &str = "transfer_asset";
const SIGNED_TRANSACTION_V1: u8 = 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalBlobPolicy {
    None,
    Canonical,
    SwiftPrefixed,
}
#[derive(Clone, Copy, Debug)]
struct SdkFixtureDirectory {
    label: &'static str,
    relative_directory: &'static str,
    local_blobs: LocalBlobPolicy,
}
const SDK_FIXTURE_DIRECTORIES: &[SdkFixtureDirectory] = &[
    SdkFixtureDirectory {
        label: "python",
        relative_directory: "python/iroha_python/tests/fixtures",
        local_blobs: LocalBlobPolicy::None,
    },
    SdkFixtureDirectory {
        label: "java",
        relative_directory: "java/iroha_android/src/test/resources",
        local_blobs: LocalBlobPolicy::Canonical,
    },
    SdkFixtureDirectory {
        label: "swift",
        relative_directory: "IrohaSwift/Fixtures",
        local_blobs: LocalBlobPolicy::SwiftPrefixed,
    },
];
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("exporter resides under the workspace tools directory")
        .to_path_buf()
}
#[derive(Debug, JsonSerialize, JsonDeserialize)]
struct NoritoRpcVerificationReport {
    generated_at: String,
    fixture_count: usize,
    alias_setup_fixture: ManifestDigestReport,
    canonical_manifest: ManifestDigestReport,
    schema_manifest: ManifestDigestReport,
    sdk_manifests: Vec<SdkManifestReport>,
}
#[derive(Debug, JsonSerialize, JsonDeserialize)]
struct ManifestDigestReport {
    path: String,
    sha256: String,
    blake3: String,
    bytes: u64,
}
#[derive(Debug, JsonSerialize, JsonDeserialize)]
struct SdkManifestReport {
    sdk: String,
    manifest: ManifestDigestReport,
}
/// Destination for the optional Norito RPC verification report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonOutput {
    /// Write the report to standard output.
    Stdout,
    /// Write the report to the provided file, creating parent directories.
    File(PathBuf),
}
/// Canonical JSON bytes for the independently typed V1 alias-setup fixture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliasSetupFixtureBytes {
    bytes: Vec<u8>,
}
impl AliasSetupFixtureBytes {
    /// Validate canonical publication framing and retired identity-key absence.
    ///
    /// # Errors
    /// Returns an error unless `bytes` is a newline-terminated, closed V1 alias-setup JSON object
    /// carrying one parseable exact `network_id` and no retired chain/genesis identity aliases.
    pub fn try_new(bytes: Vec<u8>) -> Result<Self> {
        validate_alias_setup_fixture_bytes(&bytes)?;
        Ok(Self { bytes })
    }
    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}
/// Root receiving the complete canonical and SDK fixture publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureOptions {
    output_root: Option<PathBuf>,
    local_integration: bool,
}
impl FixtureOptions {
    /// Create fixture-generation options rooted at an optional staging tree.
    pub fn new(output_root: Option<PathBuf>) -> Self {
        Self {
            output_root,
            local_integration: false,
        }
    }
    /// Select an ignored, checkout-local create-only test publication.
    ///
    /// This does not satisfy the external-root release publication contract.
    pub fn local_integration(output_root: PathBuf) -> Self {
        Self {
            output_root: Some(output_root),
            local_integration: true,
        }
    }
    fn resolve_paths(self) -> Result<ResolvedFixtureOptions> {
        let source_root = workspace_root()
            .canonicalize()
            .context("failed to resolve the fixture source workspace")?;
        let fixtures = source_root.join(CANONICAL_PAYLOADS);
        ensure_safe_owned_path(&source_root, &fixtures)?;
        let fixture_metadata = fs::symlink_metadata(&fixtures)
            .with_context(|| format!("canonical fixtures JSON missing: {}", fixtures.display()))?;
        if fixture_metadata.file_type().is_symlink() || !fixture_metadata.is_file() {
            return Err(eyre!(
                "canonical fixtures JSON must be a regular non-symlink file: {}",
                fixtures.display()
            ));
        }
        let (output_root, create_only, local_parent_identity) = match self.output_root {
            None => (source_root.clone(), false, None),
            Some(requested_root) => {
                reject_ambiguous_root(&requested_root)?;
                if !requested_root.is_absolute() {
                    bail!("fixture output root must be absolute and external");
                }
                if requested_root.parent().is_none() {
                    bail!("filesystem root is not a valid fixture output root");
                }
                match fs::symlink_metadata(&requested_root) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to inspect output root {}", requested_root.display())
                        });
                    }
                    Ok(_) => {
                        bail!(
                            "create-only fixture output root already exists: {}",
                            requested_root.display()
                        );
                    }
                }
                let parent = requested_root
                    .parent()
                    .expect("non-root output path has a parent");
                reject_symlink_components(parent)?;
                let parent_metadata = fs::symlink_metadata(parent).with_context(|| {
                    format!(
                        "create-only fixture output parent does not exist: {}",
                        parent.display()
                    )
                })?;
                if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
                    bail!(
                        "fixture output parent must be a regular non-symlink directory: {}",
                        parent.display()
                    );
                }
                let canonical_parent = parent.canonicalize().with_context(|| {
                    format!(
                        "failed to resolve fixture output parent {}",
                        parent.display()
                    )
                })?;
                let name = requested_root
                    .file_name()
                    .ok_or_else(|| eyre!("fixture output root must have a final path component"))?;
                let output_root = canonical_parent.join(name);
                let local_parent_identity = if self.local_integration {
                    let expected_parent = source_root.join(LOCAL_INTEGRATION_PARENT);
                    if canonical_parent != expected_parent {
                        bail!(
                            "local fixture output root must be a direct child of {}",
                            expected_parent.display()
                        );
                    }
                    require_private_local_parent(&parent_metadata, &source_root)?;
                    Some(directory_identity(&parent_metadata, parent)?)
                } else if output_root.starts_with(&source_root) {
                    bail!(
                        "fixture output root must be outside the source workspace: {}",
                        output_root.display()
                    );
                } else {
                    None
                };
                (output_root, true, local_parent_identity)
            }
        };
        Ok(ResolvedFixtureOptions {
            output_root,
            fixtures_json: fixtures,
            create_only,
            local_render_parent: self
                .local_integration
                .then(|| source_root.join(LOCAL_INTEGRATION_PARENT)),
            local_parent_identity,
        })
    }
}
struct ResolvedFixtureOptions {
    output_root: PathBuf,
    fixtures_json: PathBuf,
    create_only: bool,
    local_render_parent: Option<PathBuf>,
    local_parent_identity: Option<DirectoryIdentity>,
}
#[cfg(unix)]
fn require_private_local_parent(parent: &fs::Metadata, source_root: &Path) -> Result<()> {
    let workspace = fs::symlink_metadata(source_root)?;
    if canonical_mode(parent) != 0o700 || parent.uid() != workspace.uid() {
        bail!("local fixture output parent must be owner-owned mode 0700");
    }
    Ok(())
}
#[cfg(not(unix))]
fn require_private_local_parent(_parent: &fs::Metadata, _source_root: &Path) -> Result<()> {
    bail!("local fixture output requires an owner-private Unix mode-0700 parent")
}
fn require_local_render_parent(parent: &Path, identity: DirectoryIdentity) -> Result<()> {
    reject_symlink_components(parent)?;
    require_directory_identity(parent, identity)?;
    let metadata = fs::symlink_metadata(parent)?;
    require_private_local_parent(&metadata, &workspace_root().canonicalize()?)
}
fn reject_ambiguous_root(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path == Path::new(".")
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("fixture output root must be an unambiguous directory path");
    }
    Ok(())
}
fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("failed to inspect output ancestor {}", current.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "fixture output path must not traverse a symlink: {}",
                current.display()
            );
        }
    }
    Ok(())
}
fn ensure_safe_owned_path(root: &Path, target: &Path) -> Result<()> {
    let relative = target.strip_prefix(root).with_context(|| {
        format!(
            "fixture output {} escapes root {}",
            target.display(),
            root.display()
        )
    })?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("invalid fixture output path: {}", target.display());
    }
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "fixture output path contains a symlink: {}",
                    current.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", current.display()));
            }
        }
    }
    Ok(())
}
fn validate_alias_setup_fixture_bytes(bytes: &[u8]) -> Result<()> {
    let Some(body) = bytes.strip_suffix(b"\n") else {
        bail!("alias-setup fixture JSON must end with exactly one newline");
    };
    if body.last() != Some(&b'}') || bytes.contains(&b'\r') {
        bail!("alias-setup fixture JSON must use canonical LF-only object framing");
    }
    let value: Value = json::from_slice(bytes).context("invalid alias-setup fixture JSON")?;
    let root = value
        .as_object()
        .ok_or_else(|| eyre!("alias-setup fixture root must be an object"))?;
    require_exact_fields(
        root,
        &[
            "schema_version",
            "account_alias_cases",
            "resolved_name_json_vectors",
            "quote_guard_json_vector",
            "permission_scope_json_vector",
            "account_onboarding_receipt_vector",
            "plan_hash_vectors",
            "instruction_frame_vectors",
            "report_json_vector",
        ],
        "alias-setup fixture root",
    )?;
    if root.get("schema_version").and_then(Value::as_u64) != Some(1) {
        bail!("alias-setup fixture schema_version must be exactly 1");
    }
    reject_alias_setup_secret_and_retired_keys(&value, "alias-setup fixture")?;
    let onboarding = root
        .get("account_onboarding_receipt_vector")
        .and_then(Value::as_object)
        .and_then(|vector| vector.get("receipt_json"))
        .and_then(Value::as_object)
        .and_then(|receipt| receipt.get("body"))
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("alias-setup fixture is missing the typed onboarding receipt body"))?;
    let network_literal = onboarding
        .get("network_id")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("alias-setup fixture onboarding body requires network_id"))?;
    parse_network_id(network_literal)
        .context("alias-setup fixture onboarding network_id is not canonical")?;
    Ok(())
}
fn reject_alias_setup_secret_and_retired_keys(value: &Value, context: &str) -> Result<()> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "chain",
        "chainId",
        "chain_id",
        "genesis",
        "genesisHash",
        "genesis_hash",
        "privateKey",
        "private_key",
    ];
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if FORBIDDEN_KEYS.contains(&key.as_str()) {
                    bail!("{context} contains forbidden field `{key}`");
                }
                reject_alias_setup_secret_and_retired_keys(child, context)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_alias_setup_secret_and_retired_keys(child, context)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn write_alias_setup_fixture(
    publication_root: &Path,
    fixture: &AliasSetupFixtureBytes,
) -> Result<()> {
    let path = publication_root.join(ALIAS_SETUP_FIXTURE_V1);
    ensure_safe_owned_path(publication_root, &path)?;
    let parent = path
        .parent()
        .ok_or_else(|| eyre!("alias-setup fixture output has no parent"))?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    fs::write(&path, fixture.as_slice())
        .with_context(|| format!("failed to write {}", path.display()))
}
#[derive(Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SchemaHashManifest {
    version: u32,
    entries: Vec<SchemaHashEntry>,
}
impl SchemaHashManifest {
    fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        Ok(json::from_slice(&bytes)?)
    }
    fn new_current() -> Self {
        Self {
            version: 1,
            entries: schema_targets()
                .into_iter()
                .map(|target| SchemaHashEntry {
                    type_name: target.type_name,
                    alias: target.alias,
                    schema_hash: format_schema_hash(target.schema_hash),
                })
                .collect(),
        }
    }
    fn validate(&self) -> Result<()> {
        verify_schema_hash_manifest(self)
    }
}
#[derive(Debug, JsonSerialize, JsonDeserialize, PartialEq, Eq)]
#[norito(deny_unknown_fields)]
struct SchemaHashEntry {
    type_name: String,
    alias: String,
    schema_hash: String,
}
struct SchemaTarget {
    type_name: String,
    alias: String,
    schema_hash: [u8; 16],
}
impl SchemaTarget {
    fn of<T: norito::NoritoSchema>() -> Self {
        let type_name = T::nominal_name();
        let alias = type_name
            .rsplit("::")
            .next()
            .unwrap_or(&type_name)
            .to_owned();
        Self {
            type_name,
            alias,
            schema_hash: norito::schema::identity::frame_hash::<T>(),
        }
    }
}
fn schema_targets() -> Vec<SchemaTarget> {
    let mut targets = vec![
        SchemaTarget::of::<SignedTransaction>(),
        SchemaTarget::of::<TransactionPayload>(),
        SchemaTarget::of::<NameRecordV1>(),
        SchemaTarget::of::<NameControllerV1>(),
        SchemaTarget::of::<NameSelectorV1>(),
        SchemaTarget::of::<NameStatus>(),
        SchemaTarget::of::<SuffixPolicyV1>(),
    ];
    targets.sort_by(|a, b| a.alias.cmp(&b.alias));
    targets
}
fn write_schema_hash_manifest(path: &Path) -> Result<()> {
    let manifest = SchemaHashManifest::new_current();
    let json = json::to_json_pretty(&manifest)?;
    fs::write(path, format!("{json}\n"))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}
fn verify_schema_hash_manifest(manifest: &SchemaHashManifest) -> Result<()> {
    if manifest.version != 1 {
        bail!(
            "unsupported schema hash manifest version {}; expected 1",
            manifest.version
        );
    }
    let expected = schema_targets();
    if expected.len() != manifest.entries.len() {
        bail!(
            "schema hash manifest contains {} entries but {} were expected",
            manifest.entries.len(),
            expected.len()
        );
    }
    for (entry, target) in manifest.entries.iter().zip(expected.iter()) {
        if entry.type_name != target.type_name {
            bail!(
                "schema hash entry order mismatch: expected `{}`, found `{}`",
                target.type_name,
                entry.type_name
            );
        }
        if entry.alias != target.alias {
            bail!(
                "schema hash alias mismatch for `{}`: expected `{}`, found `{}`",
                entry.type_name,
                target.alias,
                entry.alias
            );
        }
        let parsed = parse_schema_hash_hex(&entry.schema_hash)?;
        if parsed != target.schema_hash {
            bail!(
                "schema hash mismatch for `{}`: expected {}, found {}",
                entry.type_name,
                format_schema_hash(target.schema_hash),
                entry.schema_hash
            );
        }
    }
    Ok(())
}
fn format_schema_hash(bytes: [u8; 16]) -> String {
    format!("0x{}", hex::encode(bytes))
}
fn parse_schema_hash_hex(input: &str) -> Result<[u8; 16]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed)?;
    if bytes.len() != 16 {
        bail!(
            "schema hash must be 16 bytes; entry `{input}` decodes to {} bytes",
            bytes.len()
        );
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}
/// Verify canonical fixture bytes, schema hashes, and SDK manifest parity.
///
/// # Errors
///
/// Returns an error when fixture rendering, canonical validation, SDK parity
/// checks, or optional report serialization and publication fails.
pub fn run_verify(
    alias_setup_fixture: &AliasSetupFixtureBytes,
    json_out: Option<JsonOutput>,
) -> Result<()> {
    let report = build_verification_report(alias_setup_fixture)?;
    println!(
        "norito-rpc fixtures verified ({} entries)",
        report.fixture_count
    );
    if let Some(target) = json_out {
        let value = json::to_value(&report)
            .map_err(|err| eyre!("failed to encode verification report: {err}"))?;
        write_json_output(&value, target)
            .map_err(|err| eyre!("failed to write verification report: {err}"))?;
    }
    Ok(())
}
fn write_json_output(value: &Value, target: JsonOutput) -> Result<()> {
    let mut json_text = json::to_string_pretty(value)?;
    json_text.push('\n');
    match target {
        JsonOutput::Stdout => print!("{json_text}"),
        JsonOutput::File(path) => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, json_text)?;
        }
    }
    Ok(())
}
fn build_verification_report(
    alias_setup_fixture: &AliasSetupFixtureBytes,
) -> Result<NoritoRpcVerificationReport> {
    let resolved = FixtureOptions::new(None).resolve_paths()?;
    let root = resolved.output_root.clone();
    let source = capture_required_guarded_file(&resolved.fixtures_json)?;
    let rendered = render_verified_publication_pair(&source.bytes, alias_setup_fixture, None)?;
    verify_preimage(&resolved.fixtures_json, Some(&source))
        .context("canonical fixture source changed during verification")?;
    let expected = &rendered.manifest;
    compare_owned_publication(
        rendered.root.path(),
        &root,
        &owned_publication_paths(&expected.fixtures)?,
    )?;
    verify_all_blob_policies(&root, &expected.fixtures, true)?;
    let canonical_path = root.join(CANONICAL_MANIFEST);
    let canonical = Manifest::load(&canonical_path)
        .with_context(|| format!("failed to read {}", canonical_path.display()))?;
    canonical
        .validate(Some(
            canonical_path
                .parent()
                .expect("manifest file should have parent directory"),
        ))
        .context("canonical manifest validation failed")?;
    let compact_hash_vector_path = canonical_path
        .parent()
        .expect("manifest file should have parent directory")
        .join(COMPACT_HASH_VECTOR_BASENAME);
    verify_compact_hash_vector(&compact_hash_vector_path, &canonical.fixtures)?;
    let canonical_manifest_bytes = fs::read(&canonical_path)?;
    let canonical_payloads_path = root.join(CANONICAL_PAYLOADS);
    let canonical_payloads_bytes = fs::read(&canonical_payloads_path)?;
    let mut sdk_manifests = Vec::new();
    for sdk in SDK_FIXTURE_DIRECTORIES {
        let manifest_dir = root.join(sdk.relative_directory);
        let manifest_path = manifest_dir.join(MANIFEST_BASENAME);
        let manifest = Manifest::load(&manifest_path).with_context(|| {
            format!(
                "{} manifest missing at {}",
                sdk.label,
                manifest_path.display()
            )
        })?;
        manifest
            .validate(
                (sdk.local_blobs == LocalBlobPolicy::Canonical).then_some(manifest_dir.as_path()),
            )
            .with_context(|| format!("{} manifest failed validation", sdk.label))?;
        if fs::read(&manifest_path)? != canonical_manifest_bytes {
            bail!(
                "{} manifest bytes differ from the canonical manifest",
                sdk.label
            );
        }
        let payloads_path = manifest_dir.join(PAYLOADS_BASENAME);
        if fs::read(&payloads_path)? != canonical_payloads_bytes {
            bail!(
                "{} payload descriptor bytes differ from the canonical descriptor",
                sdk.label
            );
        }
        sdk_manifests.push(SdkManifestReport {
            sdk: sdk.label.to_string(),
            manifest: manifest_digest(&manifest_path, &root)?,
        });
    }
    let schema_manifest_path = root.join(SCHEMA_HASH_MANIFEST);
    let schema_manifest = SchemaHashManifest::load(&schema_manifest_path)
        .with_context(|| format!("failed to read {}", schema_manifest_path.display()))?;
    schema_manifest
        .validate()
        .context("schema hash manifest validation failed")?;
    let canonical_manifest = manifest_digest(&canonical_path, &root)?;
    let schema_manifest = manifest_digest(&schema_manifest_path, &root)?;
    let alias_setup_fixture = manifest_digest(&root.join(ALIAS_SETUP_FIXTURE_V1), &root)?;
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("timestamp formatting must succeed");
    Ok(NoritoRpcVerificationReport {
        generated_at: timestamp,
        fixture_count: canonical.fixtures.len(),
        alias_setup_fixture,
        canonical_manifest,
        schema_manifest,
        sdk_manifests,
    })
}
/// Regenerate canonical Norito RPC fixtures from the configured source JSON.
///
/// # Errors
///
/// Returns an error when the configured paths or fixture source are invalid,
/// fixture rendering fails, or create-only publication cannot be committed under
/// the documented private-parent threat boundary.
pub fn generate_fixtures(
    options: FixtureOptions,
    alias_setup_fixture: &AliasSetupFixtureBytes,
) -> Result<()> {
    let resolved = options.resolve_paths()?;
    if !resolved.create_only {
        bail!("fixture generation requires an explicit create-only --output-root");
    }
    if let (Some(parent), Some(identity)) = (
        &resolved.local_render_parent,
        resolved.local_parent_identity,
    ) {
        require_local_render_parent(parent, identity)?;
    }
    let source = capture_required_guarded_file(&resolved.fixtures_json)?;
    let rendered = render_verified_publication_pair(
        &source.bytes,
        alias_setup_fixture,
        resolved.local_render_parent.as_deref(),
    )?;
    if let (Some(parent), Some(identity)) = (
        &resolved.local_render_parent,
        resolved.local_parent_identity,
    ) {
        require_local_render_parent(parent, identity)?;
    }
    verify_preimage(&resolved.fixtures_json, Some(&source))
        .context("canonical fixture source changed during deterministic rendering")?;
    let generated = &rendered.manifest;
    let owned_paths = owned_publication_paths(&generated.fixtures)?;
    publish_create_only_publication(
        &rendered.snapshot,
        &resolved.output_root,
        &owned_paths,
        || {
            if let (Some(parent), Some(identity)) = (
                &resolved.local_render_parent,
                resolved.local_parent_identity,
            ) {
                require_local_render_parent(parent, identity)?;
            }
            verify_preimage(&resolved.fixtures_json, Some(&source))
                .context("canonical fixture source drifted before publication")?;
            verify_all_blob_policies_without_seal(&resolved.output_root, &generated.fixtures, true)
        },
    )?;
    println!(
        "norito-rpc fixtures regenerated: {} entries written create-only to {}",
        generated.fixtures.len(),
        resolved.output_root.join(CANONICAL_MANIFEST).display()
    );
    Ok(())
}
struct VerifiedPublication {
    root: TempDir,
    manifest: Manifest,
    snapshot: PublicationSnapshot,
}
fn render_verified_publication_pair(
    fixtures_json: &[u8],
    alias_setup_fixture: &AliasSetupFixtureBytes,
    local_render_parent: Option<&Path>,
) -> Result<VerifiedPublication> {
    let first = create_render_tree(local_render_parent)
        .context("failed to create first private fixture publication tree")?;
    let second = create_render_tree(local_render_parent)
        .context("failed to create second private fixture publication tree")?;
    let first_manifest =
        render_fixture_publication(fixtures_json, alias_setup_fixture, first.path())?;
    let second_manifest =
        render_fixture_publication(fixtures_json, alias_setup_fixture, second.path())?;
    let first_paths = owned_publication_paths(&first_manifest.fixtures)?;
    let second_paths = owned_publication_paths(&second_manifest.fixtures)?;
    normalize_rendered_modes(first.path(), &first_paths)?;
    normalize_rendered_modes(second.path(), &second_paths)?;
    let first_snapshot = PublicationSnapshot::capture(first.path(), &first_paths)?;
    let second_snapshot = PublicationSnapshot::capture(second.path(), &second_paths)?;
    first_snapshot.require_identical(&second_snapshot)?;
    Ok(VerifiedPublication {
        root: first,
        manifest: first_manifest,
        snapshot: first_snapshot,
    })
}
fn create_render_tree(local_render_parent: Option<&Path>) -> Result<TempDir> {
    Ok(match local_render_parent {
        Some(parent) => tempdir_in(parent)?,
        None => tempdir()?,
    })
}
fn render_fixture_publication(
    fixtures_json: &[u8],
    alias_setup_fixture: &AliasSetupFixtureBytes,
    publication_root: &Path,
) -> Result<Manifest> {
    let canonical_dir = publication_root.join(CANONICAL_FIXTURE_DIRECTORY);
    fs::create_dir_all(&canonical_dir)
        .with_context(|| format!("failed to create {}", canonical_dir.display()))?;
    generate_fixture_artifacts(fixtures_json, &canonical_dir)?;
    write_alias_setup_fixture(publication_root, alias_setup_fixture)?;
    let manifest_path = canonical_dir.join(MANIFEST_BASENAME);
    let manifest = Manifest::load(&manifest_path).with_context(|| {
        format!(
            "failed to read generated manifest {}",
            manifest_path.display()
        )
    })?;
    manifest
        .validate(Some(&canonical_dir))
        .map_err(|error| eyre!("generated manifest failed validation: {error}"))?;
    let compact_hash_vector = render_compact_hash_vector(&manifest.fixtures)?;
    let schema_path = canonical_dir.join(SCHEMA_HASH_MANIFEST_BASENAME);
    write_schema_hash_manifest(&schema_path)
        .with_context(|| format!("failed to generate {}", schema_path.display()))?;
    let compact_hash_vector_path = canonical_dir.join(COMPACT_HASH_VECTOR_BASENAME);
    fs::write(&compact_hash_vector_path, compact_hash_vector)
        .with_context(|| format!("failed to generate {}", compact_hash_vector_path.display()))?;
    let manifest_json = json::to_json_pretty(&manifest)?;
    sync_sdk_fixture_mirrors(
        publication_root,
        &canonical_dir,
        &manifest.fixtures,
        &manifest_json,
    )?;
    verify_all_blob_policies(publication_root, &manifest.fixtures, true)?;
    Ok(manifest)
}
fn generate_fixture_artifacts(fixtures_json: &[u8], out_dir: &Path) -> Result<()> {
    let fixtures_value: Value =
        json::from_slice(fixtures_json).context("invalid transaction_payloads fixtures JSON")?;
    let raw_fixtures = parse_payload_fixtures(&fixtures_value)?;
    let keypair = signing_keypair()?;
    let mut fixtures = Vec::with_capacity(raw_fixtures.len());
    for raw in &raw_fixtures {
        fixtures.push(raw.generate_fixture(&keypair)?);
    }
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    for fixture in &fixtures {
        let norito_path = out_dir.join(format!("{}.norito", fixture.name));
        fs::write(&norito_path, &fixture.payload_bytes)
            .with_context(|| format!("failed to write {}", norito_path.display()))?;
    }
    let manifest = Manifest {
        fixtures: fixtures.iter().map(Fixture::to_entry).collect(),
    };
    let manifest_json = json::to_json_pretty(&manifest)?;
    fs::write(
        out_dir.join(MANIFEST_BASENAME),
        format!("{manifest_json}\n"),
    )
    .context("failed to write generated fixture manifest")?;
    // Render refreshed generated hints into the private publication tree.
    let updated_payloads = build_payload_fixtures_json(&raw_fixtures, &fixtures)?;
    let payloads_json = json::to_json_pretty(&updated_payloads)?;
    let rendered_payloads = out_dir.join(PAYLOADS_BASENAME);
    fs::write(&rendered_payloads, format!("{payloads_json}\n"))
        .with_context(|| format!("failed to write {}", rendered_payloads.display()))?;
    Ok(())
}
const SIGNING_SEED_HEX: &str = "616e64726f69642d666978747572652d7369676e696e672d6b65792d30313032";
fn signing_keypair() -> Result<KeyPair> {
    let seed = hex::decode(SIGNING_SEED_HEX).context("invalid signing seed hex")?;
    KeyPair::try_from_seed(seed, Algorithm::Ed25519)
        .map_err(|err| eyre!("failed to derive Norito RPC fixture signing key: {err}"))
}
#[derive(Clone)]
struct RawPayloadFixture {
    name: String,
    payload: RawPayload,
    payload_json: Value,
    network_id_hint: String,
    authority_hint: String,
    creation_time_ms_hint: u64,
    ttl_ms_hint: u64,
    nonce_hint: Option<u32>,
}
#[derive(Clone)]
struct RawPayload {
    network_id: String,
    authority: String,
    creation_time_ms: u64,
    executable: RawExecutable,
    ttl_ms: u64,
    nonce: Option<u32>,
    fee_payment: FeePaymentIntent,

    metadata: Vec<(Name, Json)>,
}
#[derive(Clone)]
enum RawExecutable {
    Ivm(Vec<u8>),
    Instructions(Vec<RawInstruction>),
    ContractCall(ContractInvocation),
    Batch(Vec<RawBatchItem>),
}
impl RawExecutable {
    fn requires_transaction_gas_limit(&self) -> bool {
        match self {
            Self::Ivm(_) | Self::ContractCall(_) => true,
            Self::Instructions(_) => false,
            Self::Batch(items) => items
                .iter()
                .any(|item| matches!(item, RawBatchItem::ContractCall(_))),
        }
    }
}
#[derive(Clone)]
enum RawBatchItem {
    Instruction(RawInstruction),
    ContractCall(ContractInvocation),
}
#[derive(Clone)]
struct RawInstruction {
    wire_name: String,
    payload_base64: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum InstructionSourceSlot {
    Instructions(usize),
    Batch(usize),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SemanticInstructionSource {
    fixture_name: &'static str,
    slot: InstructionSourceSlot,
    wire_name: &'static str,
}
const SEMANTIC_INSTRUCTION_SOURCES: &[SemanticInstructionSource] = &[
    SemanticInstructionSource {
        fixture_name: "mixed_executable_batch",
        slot: InstructionSourceSlot::Batch(0),
        wire_name: "iroha.register",
    },
    SemanticInstructionSource {
        fixture_name: "mixed_executable_batch",
        slot: InstructionSourceSlot::Batch(2),
        wire_name: "iroha.register",
    },
    SemanticInstructionSource {
        fixture_name: "register_asset_definition",
        slot: InstructionSourceSlot::Instructions(0),
        wire_name: "iroha.register",
    },
    SemanticInstructionSource {
        fixture_name: "register_peer_with_pop_demo",
        slot: InstructionSourceSlot::Instructions(0),
        wire_name: "iroha.register",
    },
    SemanticInstructionSource {
        fixture_name: "settlement_dvp_atomic",
        slot: InstructionSourceSlot::Instructions(0),
        wire_name: "iroha.settlement",
    },
    SemanticInstructionSource {
        fixture_name: "settlement_pvp_net",
        slot: InstructionSourceSlot::Instructions(0),
        wire_name: "iroha.settlement",
    },
];
struct Fixture {
    name: String,
    payload_bytes: Vec<u8>,
    signed_bytes: Vec<u8>,
    summary: PayloadSummary,
}
struct PayloadSummary {
    network_id: String,
    authority: String,
    creation_time_ms: u64,
    ttl_ms: u64,
    nonce: Option<u32>,
    payload_base64: String,
    signed_base64: String,
    payload_hash_hex: String,
    signed_hash_hex: String,
}
struct WireInstructionPayload {
    wire_name: String,
    payload_base64: String,
}
impl RawPayloadFixture {
    fn generate_fixture(&self, keypair: &KeyPair) -> Result<Fixture> {
        if self.network_id_hint != self.payload.network_id {
            bail!(
                "fixture '{}' network_id mismatch: expected {}, got {}",
                self.name,
                self.network_id_hint,
                self.payload.network_id
            );
        }
        if self.authority_hint != self.payload.authority {
            bail!(
                "fixture '{}' authority mismatch: expected {}, got {}",
                self.name,
                self.authority_hint,
                self.payload.authority
            );
        }
        if self.creation_time_ms_hint != self.payload.creation_time_ms {
            bail!(
                "fixture '{}' creation_time_ms mismatch: expected {}, got {}",
                self.name,
                self.creation_time_ms_hint,
                self.payload.creation_time_ms
            );
        }
        if self.ttl_ms_hint != self.payload.ttl_ms {
            bail!(
                "fixture '{}' time_to_live_ms mismatch: expected {}, got {}",
                self.name,
                self.ttl_ms_hint,
                self.payload.ttl_ms
            );
        }
        if self.nonce_hint != self.payload.nonce {
            bail!(
                "fixture '{}' nonce mismatch: expected {}, got {:?}",
                self.name,
                self.nonce_hint
                    .map_or_else(|| "null".to_owned(), |nonce| nonce.to_string()),
                self.payload.nonce
            );
        }
        let builder = self.payload.to_builder(&self.name).map_err(|err| {
            eyre!(
                "failed to build Norito RPC fixture '{}': {err:#}",
                self.name
            )
        })?;
        let signed = builder.try_sign(keypair.private_key()).map_err(|err| {
            eyre!(
                "failed to sign Norito RPC transaction fixture '{}': {err}",
                self.name
            )
        })?;
        let payload_value = signed.payload().clone();
        let actual_ttl = payload_value.time_to_live().ok_or_else(|| {
            eyre!(
                "fixture '{}' is missing time_to_live_ms after construction",
                self.name
            )
        })?;
        let actual_ttl_ms = u64::try_from(actual_ttl.as_millis()).map_err(|_| {
            eyre!(
                "fixture '{}' time_to_live_ms exceeds u64 after construction",
                self.name
            )
        })?;
        if actual_ttl_ms != self.payload.ttl_ms {
            bail!(
                "fixture '{}' time_to_live_ms changed during construction: expected {}, got {}",
                self.name,
                self.payload.ttl_ms,
                actual_ttl_ms
            );
        }
        let payload_bare = payload_value.encode();
        let payload_bytes = norito::encode_canonical(&payload_value).map_err(|err| {
            eyre!(
                "failed to frame Norito RPC payload fixture '{}': {err}",
                self.name
            )
        })?;
        let payload_base64 = BASE64.encode(&payload_bytes);
        let signed_bytes = norito::encode_canonical(&signed).map_err(|err| {
            eyre!(
                "failed to frame signed Norito RPC fixture '{}': {err}",
                self.name
            )
        })?;
        let signed_base64 = BASE64.encode(&signed_bytes);
        let payload_hash_hex = blake2b256_hex(&payload_bytes);
        let signed_hash_hex = signed_transaction_entrypoint_hash_hex(&signed_bytes)?;
        debug_assert_eq!(signed.payload().encode(), payload_bare);
        Ok(Fixture {
            name: self.name.clone(),
            payload_bytes,
            signed_bytes,
            summary: PayloadSummary {
                network_id: self.payload.network_id.clone(),
                authority: payload_value.authority().to_string(),
                creation_time_ms: self.payload.creation_time_ms,
                ttl_ms: actual_ttl_ms,
                nonce: self.payload.nonce,
                payload_base64,
                signed_base64,
                payload_hash_hex,
                signed_hash_hex,
            },
        })
    }
}
impl RawPayload {
    fn to_builder(&self, fixture_name: &str) -> Result<TransactionBuilder> {
        let network_id = parse_network_id(&self.network_id)?;
        let authority = parse_account_id(&self.authority)
            .with_context(|| format!("invalid authority id '{}'", self.authority))?;
        let mut builder = TransactionBuilder::new(network_id, authority, self.fee_payment.clone());
        builder.set_creation_time(Duration::from_millis(self.creation_time_ms));
        builder.set_ttl(Duration::from_millis(self.ttl_ms));
        if let Some(nonce) = self.nonce {
            let nz = NonZeroU32::new(nonce).ok_or_else(|| eyre!("nonce must be > 0"))?;
            builder.set_nonce(nz);
        }
        let mut metadata = Metadata::default();
        for (key, value) in &self.metadata {
            metadata.insert(key.clone(), value.clone());
        }
        builder = builder.with_metadata(metadata);
        validate_semantic_instruction_shape(fixture_name, &self.executable)?;
        builder = match &self.executable {
            RawExecutable::Ivm(bytes) => {
                builder.with_executable(Executable::Ivm(IvmBytecode::from_compiled(bytes.clone())))
            }
            RawExecutable::Instructions(raws) => {
                let instructions = raws
                    .iter()
                    .enumerate()
                    .map(|(index, raw)| {
                        build_fixture_instruction(
                            fixture_name,
                            InstructionSourceSlot::Instructions(index),
                            raw,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                builder.with_instructions(instructions)
            }
            RawExecutable::ContractCall(invocation) => {
                builder.with_executable(Executable::ContractCall(invocation.clone()))
            }
            RawExecutable::Batch(raws) => {
                let items = raws
                    .iter()
                    .enumerate()
                    .map(|(index, raw)| match raw {
                        RawBatchItem::Instruction(raw) => build_fixture_instruction(
                            fixture_name,
                            InstructionSourceSlot::Batch(index),
                            raw,
                        )
                        .map(ExecutableBatchItem::Instruction),
                        RawBatchItem::ContractCall(invocation) => {
                            Ok(ExecutableBatchItem::ContractCall(invocation.clone()))
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                if items.is_empty() {
                    bail!("mixed executable batch must not be empty");
                }
                builder.with_executable_batch(items)
            }
        };
        Ok(builder)
    }
}
impl Fixture {
    fn to_entry(&self) -> FixtureEntry {
        FixtureEntry {
            name: self.name.clone(),
            authority: self.summary.authority.clone(),
            network_id: self.summary.network_id.clone(),
            creation_time_ms: self.summary.creation_time_ms,
            encoded_file: format!("{}.norito", self.name),
            encoded_len: self.payload_bytes.len() as u64,
            signed_len: self.signed_bytes.len() as u64,
            payload_base64: self.summary.payload_base64.clone(),
            payload_hash: self.summary.payload_hash_hex.clone(),
            signed_base64: self.summary.signed_base64.clone(),
            signed_hash: self.summary.signed_hash_hex.clone(),
            nonce: self.summary.nonce,
            time_to_live_ms: self.summary.ttl_ms,
        }
    }
}
fn parse_payload_fixtures(value: &Value) -> Result<Vec<RawPayloadFixture>> {
    let arr = value
        .as_array()
        .ok_or_else(|| eyre!("fixture root must be an array"))?;
    let fixtures = arr
        .iter()
        .map(parse_payload_fixture)
        .collect::<Result<Vec<_>>>()?;
    let mut names = HashSet::with_capacity(fixtures.len());
    for fixture in &fixtures {
        validate_fixture_name(&fixture.name)?;
        if !names.insert(fixture.name.as_str()) {
            bail!("duplicate fixture name '{}'", fixture.name);
        }
    }
    Ok(fixtures)
}
fn parse_payload_fixture(value: &Value) -> Result<RawPayloadFixture> {
    const FIELDS: &[&str] = &[
        "name",
        "network_id",
        "authority",
        "creation_time_ms",
        "time_to_live_ms",
        "nonce",
        "payload_base64",
        "signed_base64",
        "payload_hash",
        "signed_hash",
        "payload",
    ];

    let obj = value
        .as_object()
        .ok_or_else(|| eyre!("fixture entries must be objects"))?;
    let name = expect_string(obj, "name")?.to_owned();
    require_exact_fields(obj, FIELDS, &format!("fixture '{name}'"))?;
    for field in [
        "payload_base64",
        "signed_base64",
        "payload_hash",
        "signed_hash",
    ] {
        expect_string(obj, field)
            .with_context(|| format!("invalid generated identity for fixture '{name}'"))?;
    }
    let payload_value = obj
        .get("payload")
        .ok_or_else(|| eyre!("fixture '{name}' missing payload"))?;
    let payload_json = payload_value.clone();
    let payload = parse_payload(payload_value)
        .with_context(|| format!("invalid payload for fixture '{name}'"))?;
    let network_id_hint = expect_string(obj, "network_id")?.to_owned();
    let authority_hint = expect_string(obj, "authority")?.to_owned();
    let creation_time_ms_hint = expect_u64(obj, "creation_time_ms")?;
    let ttl_ms_hint = expect_nonzero_u64(obj, "time_to_live_ms")
        .with_context(|| format!("invalid top-level lifetime for fixture '{name}'"))?;
    let nonce_hint = parse_optional_u32(obj, "nonce")
        .with_context(|| format!("invalid top-level nonce for fixture '{name}'"))?;
    Ok(RawPayloadFixture {
        name,
        payload,
        payload_json,
        network_id_hint,
        authority_hint,
        creation_time_ms_hint,
        ttl_ms_hint,
        nonce_hint,
    })
}
fn parse_payload(value: &Value) -> Result<RawPayload> {
    let obj = value
        .as_object()
        .ok_or_else(|| eyre!("payload entries must be objects"))?;
    require_exact_fields(
        obj,
        &[
            "network_id",
            "authority",
            "creation_time_ms",
            "executable",
            "time_to_live_ms",
            "nonce",
            "fee_payment",
            "metadata",
        ],
        "payload",
    )?;
    let network_id = expect_string(obj, "network_id")?.to_owned();
    let authority = expect_string(obj, "authority")?.to_owned();
    let creation_time_ms = expect_u64(obj, "creation_time_ms")?;
    let executable_value = obj
        .get("executable")
        .ok_or_else(|| eyre!("missing executable"))?;
    let executable = parse_executable(executable_value)?;
    let ttl_ms = expect_nonzero_u64(obj, "time_to_live_ms")?;
    let nonce = parse_optional_u32(obj, "nonce")?;
    let fee_payment = obj
        .get("fee_payment")
        .ok_or_else(|| eyre!("missing fee_payment"))
        .and_then(|value| {
            json::from_value::<FeePaymentIntent>(value.clone())
                .map_err(|err| eyre!(err.to_string()))
        })?;
    fee_payment
        .validate()
        .map_err(|err| eyre!(err.to_string()))?;
    if executable.requires_transaction_gas_limit() && fee_payment.gas_limit().is_none() {
        bail!(
            "IVM and contract-call fixture executables require an explicit fee_payment gas_limit"
        );
    }
    let metadata = parse_metadata_object(
        obj.get("metadata")
            .expect("exact payload field validation requires metadata"),
    )?;
    Ok(RawPayload {
        network_id,
        authority,
        creation_time_ms,
        executable,
        ttl_ms,
        nonce,
        fee_payment,
        metadata,
    })
}
fn parse_executable(value: &Value) -> Result<RawExecutable> {
    let obj = value
        .as_object()
        .ok_or_else(|| eyre!("executable must be an object"))?;
    if obj.len() != 1 {
        bail!("executable must contain exactly one variant");
    }
    let (variant, body) = obj.iter().next().expect("one executable variant");
    match variant.as_str() {
        "Ivm" => {
            let bytes = body
                .as_str()
                .ok_or_else(|| eyre!("Ivm value must be base64 string"))?;
            Ok(RawExecutable::Ivm(decode_canonical_base64(
                bytes,
                "Ivm payload",
            )?))
        }
        "Instructions" => {
            let arr = body
                .as_array()
                .ok_or_else(|| eyre!("Instructions must be an array"))?;
            let entries = arr
                .iter()
                .map(parse_instruction)
                .collect::<Result<Vec<_>>>()?;
            Ok(RawExecutable::Instructions(entries))
        }
        "ContractCall" => {
            let invocation = parse_contract_invocation(body, "ContractCall")?;
            Ok(RawExecutable::ContractCall(invocation))
        }
        "Batch" => {
            let arr = body
                .as_array()
                .ok_or_else(|| eyre!("Batch must be an array"))?;
            if arr.is_empty() {
                bail!("Batch must contain at least one item");
            }
            let mut entries = Vec::with_capacity(arr.len());
            for entry in arr {
                let item = entry
                    .as_object()
                    .ok_or_else(|| eyre!("Batch items must be externally tagged objects"))?;
                if item.len() != 1 {
                    bail!("Batch items must contain exactly one variant");
                }
                let (item_variant, item_body) = item.iter().next().expect("one Batch item variant");
                match item_variant.as_str() {
                    "Instruction" => {
                        entries.push(RawBatchItem::Instruction(parse_instruction(item_body)?));
                    }
                    "ContractCall" => {
                        let invocation =
                            parse_contract_invocation(item_body, "Batch ContractCall")?;
                        entries.push(RawBatchItem::ContractCall(invocation));
                    }
                    _ => bail!("unknown Batch item variant '{item_variant}'"),
                }
            }
            Ok(RawExecutable::Batch(entries))
        }
        _ => bail!("unknown executable variant '{variant}'"),
    }
}
fn parse_contract_invocation(value: &Value, label: &str) -> Result<ContractInvocation> {
    let object = value
        .as_object()
        .ok_or_else(|| eyre!("{label} body must be an object"))?;
    require_exact_fields(
        object,
        &[
            "contract_address",
            "expected_code_hash",
            "entrypoint",
            "arguments",
        ],
        &format!("{label} body"),
    )?;
    json::from_value::<ContractInvocation>(value.clone())
        .map_err(|err| eyre!(err.to_string()))
        .with_context(|| format!("invalid {label}"))
}
fn parse_instruction(value: &Value) -> Result<RawInstruction> {
    let obj = value
        .as_object()
        .ok_or_else(|| eyre!("instruction entries must be objects"))?;
    require_exact_fields(
        obj,
        &["wire_name", "payload_base64"],
        "instruction wire payload",
    )?;
    let wire_name = obj
        .get("wire_name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| eyre!("instruction wire payload requires wire_name"))?;
    let payload_base64 = obj
        .get("payload_base64")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| eyre!("instruction wire payload requires payload_base64"))?;
    decode_canonical_base64(&payload_base64, "instruction payload_base64")?;
    Ok(RawInstruction {
        wire_name,
        payload_base64,
    })
}
fn parse_metadata_object(value: &Value) -> Result<Vec<(Name, Json)>> {
    let obj = value
        .as_object()
        .ok_or_else(|| eyre!("metadata must be an object"))?;
    let mut entries = Vec::with_capacity(obj.len());
    for (key, value) in obj {
        let name: Name = key.parse().context("invalid metadata key")?;
        let json_value = Json::from_norito_value_ref(value)
            .map_err(|err| eyre!("invalid metadata json value for '{key}': {err}"))?;
        entries.push((name, json_value));
    }
    Ok(entries)
}
fn observed_instruction_sources(executable: &RawExecutable) -> Vec<(InstructionSourceSlot, &str)> {
    match executable {
        RawExecutable::Instructions(raws) => raws
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                (
                    InstructionSourceSlot::Instructions(index),
                    raw.wire_name.as_str(),
                )
            })
            .collect(),
        RawExecutable::Batch(items) => items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| match item {
                RawBatchItem::Instruction(raw) => {
                    Some((InstructionSourceSlot::Batch(index), raw.wire_name.as_str()))
                }
                RawBatchItem::ContractCall(_) => None,
            })
            .collect(),
        RawExecutable::Ivm(_) | RawExecutable::ContractCall(_) => Vec::new(),
    }
}
fn validate_semantic_instruction_shape(
    fixture_name: &str,
    executable: &RawExecutable,
) -> Result<()> {
    let observed = observed_instruction_sources(executable);
    validate_semantic_instruction_observations(fixture_name, &observed)
}
fn validate_semantic_instruction_observations(
    fixture_name: &str,
    observed: &[(InstructionSourceSlot, &str)],
) -> Result<()> {
    let expected = SEMANTIC_INSTRUCTION_SOURCES
        .iter()
        .filter(|source| source.fixture_name == fixture_name)
        .map(|source| (source.slot, source.wire_name))
        .collect::<Vec<_>>();
    if expected.is_empty() {
        return Ok(());
    }
    if observed != expected.as_slice() {
        bail!(
            "fixture '{fixture_name}' semantic instruction shape mismatch: expected {expected:?}, got {observed:?}"
        );
    }
    Ok(())
}
fn semantic_register_asset_definition() -> Result<Register<AssetDefinition>> {
    let id = "6pEP9RjNoZ7beWkT3pLfKoM1dyfi"
        .parse()
        .context("invalid code-owned register_asset_definition id")?;
    Ok(Register::asset_definition(AssetDefinition::numeric(
        id,
        "Rose Token",
        AssetBalancePolicy::Global,
        None,
    )))
}
fn semantic_register_peer_with_pop() -> Result<RegisterPeerWithPop> {
    // Preserve the published demo's BLS peer and PoP while constructing the
    // current four-field registration from its semantic source.
    let public_key_bytes = hex::decode(
        "ac5b394734cb93ddfcdf5ac499e0940a20b39a3573c4f04cba2619c5071da6de43fddf6001d87868fa06651bfd46d9d7",
    )
    .context("invalid code-owned register_peer_with_pop public key bytes")?;
    let public_key = PublicKey::from_bytes(Algorithm::BlsNormal, &public_key_bytes)
        .context("invalid code-owned register_peer_with_pop public key")?;
    let pop = hex::decode(concat!(
        "acca373bb1c936c5631c3b183f2ca882cb369ffadabe600f1bacddb18c0bd62958756afb659eb7e52af2ea7ffb61e683",
        "04d649b904dcecce8fdba3451412ad76c02b18e5a42b860c55c73340935a3ad42b85e757e55f90cf62d9df7bee9f13e1",
    ))
    .context("invalid code-owned register_peer_with_pop proof bytes")?;
    Ok(RegisterPeerWithPop::new(PeerId::new(public_key), pop))
}
fn build_fixture_instruction(
    fixture_name: &str,
    slot: InstructionSourceSlot,
    raw: &RawInstruction,
) -> Result<InstructionBox> {
    let source = SEMANTIC_INSTRUCTION_SOURCES
        .iter()
        .find(|source| source.fixture_name == fixture_name && source.slot == slot);
    if let Some(source) = source {
        if raw.wire_name != source.wire_name {
            bail!(
                "fixture '{fixture_name}' semantic instruction at {slot:?} requires wire '{}', got '{}'",
                source.wire_name,
                raw.wire_name
            );
        }
        return match source.fixture_name {
            "mixed_executable_batch" | "register_asset_definition" => {
                Ok(semantic_register_asset_definition()?.into())
            }
            "register_peer_with_pop_demo" => Ok(semantic_register_peer_with_pop()?.into()),
            "settlement_dvp_atomic" | "settlement_pvp_net" => {
                Ok(settlement_sources::instruction(source.fixture_name)?.into())
            }
            _ => bail!("fixture '{fixture_name}' has no semantic instruction constructor"),
        };
    }
    if SEMANTIC_INSTRUCTION_SOURCES
        .iter()
        .any(|source| source.fixture_name == fixture_name)
    {
        bail!("fixture '{fixture_name}' has an unowned semantic instruction at {slot:?}");
    }
    build_instruction(raw)
}
fn build_instruction(raw: &RawInstruction) -> Result<InstructionBox> {
    let payload_bytes = BASE64
        .decode(raw.payload_base64.as_bytes())
        .with_context(|| format!("invalid instruction payload_base64 for {}", raw.wire_name))?;
    if payload_bytes.is_empty() {
        bail!("instruction payload_base64 must not decode to empty bytes");
    }
    decode_instruction_from_pair(&raw.wire_name, &payload_bytes)
        .map_err(|err| eyre!(err.to_string()))
        .with_context(|| format!("failed to decode wire instruction '{}'", raw.wire_name))
}
fn parse_account_id(value: &str) -> Result<AccountId> {
    let account = AccountId::parse_encoded(value).with_context(|| {
        format!("account id '{value}' must be a canonical I105-encoded literal")
    })?;
    if account.to_string() != value {
        bail!("account id '{value}' must use its exact canonical I105 encoding");
    }
    Ok(account)
}
fn parse_network_id(value: &str) -> Result<NetworkId> {
    let encoded = Value::String(value.to_owned());
    let network_id = json::from_value::<NetworkId>(encoded.clone())
        .with_context(|| format!("invalid canonical network id '{value}'"))?;
    let canonical = json::to_value(&network_id)
        .context("failed to render the canonical network id JSON literal")?;
    if canonical != encoded {
        bail!("network id '{value}' must use its exact canonical hash encoding");
    }
    Ok(network_id)
}
fn optional_u32_value(value: Option<u32>) -> Value {
    value.map_or(Value::Null, |value| {
        Value::Number(Number::U64(u64::from(value)))
    })
}
fn build_payload_fixtures_json(
    raw_fixtures: &[RawPayloadFixture],
    fixtures: &[Fixture],
) -> Result<Value> {
    let fixtures_by_name: BTreeMap<&str, &Fixture> = fixtures
        .iter()
        .map(|fixture| (fixture.name.as_str(), fixture))
        .collect();
    let mut out = Vec::with_capacity(raw_fixtures.len());
    for raw in raw_fixtures {
        let fixture = fixtures_by_name
            .get(raw.name.as_str())
            .copied()
            .ok_or_else(|| eyre!("fixture '{}' missing generated payload", raw.name))?;
        let mut entry = Map::new();
        entry.insert("name".to_owned(), Value::String(fixture.name.clone()));
        entry.insert(
            "network_id".to_owned(),
            Value::String(fixture.summary.network_id.clone()),
        );
        entry.insert(
            "authority".to_owned(),
            Value::String(fixture.summary.authority.clone()),
        );
        entry.insert(
            "creation_time_ms".to_owned(),
            Value::Number(Number::U64(fixture.summary.creation_time_ms)),
        );
        entry.insert(
            "time_to_live_ms".to_owned(),
            Value::Number(Number::U64(fixture.summary.ttl_ms)),
        );
        entry.insert(
            "nonce".to_owned(),
            optional_u32_value(fixture.summary.nonce),
        );
        entry.insert(
            "payload_base64".to_owned(),
            Value::String(fixture.summary.payload_base64.clone()),
        );
        entry.insert(
            "signed_base64".to_owned(),
            Value::String(fixture.summary.signed_base64.clone()),
        );
        entry.insert(
            "payload_hash".to_owned(),
            Value::String(fixture.summary.payload_hash_hex.clone()),
        );
        entry.insert(
            "signed_hash".to_owned(),
            Value::String(fixture.summary.signed_hash_hex.clone()),
        );
        let mut payload = raw.payload_json.clone();
        if let Some(payload_obj) = payload.as_object_mut() {
            payload_obj.insert(
                "authority".to_owned(),
                Value::String(fixture.summary.authority.clone()),
            );
        }
        let wire_payloads = wire_payloads_from_encoded(&fixture.payload_bytes)?;
        if !wire_payloads.is_empty() {
            apply_wire_payloads_to_payload_json(&mut payload, &wire_payloads)?;
        }
        entry.insert("payload".to_owned(), payload);
        out.push(Value::Object(entry));
    }
    Ok(Value::Array(out))
}
fn wire_payloads_from_encoded(encoded: &[u8]) -> Result<Vec<WireInstructionPayload>> {
    let payload: TransactionPayload =
        norito::decode_canonical(encoded).context("decode canonical framed TransactionPayload")?;
    let registry = iroha_data_model::instruction_registry::default();
    let mut out = Vec::new();
    for instruction in payload.instructions().explicit_instructions() {
        let type_name = Instruction::id(&**instruction);
        let wire_name = required_instruction_wire_id(&registry, type_name)?;
        let (framed_wire_name, framed) = framed_instruction_payload(instruction)
            .ok_or_else(|| eyre!("instruction type `{type_name}` cannot be framed"))?;
        if framed_wire_name != wire_name {
            bail!("instruction registry returned inconsistent V1 wire identifiers");
        }
        out.push(WireInstructionPayload {
            wire_name: wire_name.to_owned(),
            payload_base64: BASE64.encode(framed),
        });
    }
    Ok(out)
}
fn required_instruction_wire_id(
    registry: &InstructionRegistry,
    type_name: &'static str,
) -> Result<&'static str> {
    registry
        .wire_id(type_name)
        .ok_or_else(|| eyre!("instruction type `{type_name}` has no registered V1 wire identifier"))
}
fn apply_wire_payloads_to_payload_json(
    payload: &mut Value,
    wire_payloads: &[WireInstructionPayload],
) -> Result<()> {
    let payload_obj = payload
        .as_object_mut()
        .ok_or_else(|| eyre!("payload must be an object"))?;
    let executable_value = payload_obj
        .get_mut("executable")
        .ok_or_else(|| eyre!("payload missing executable"))?;
    let executable_obj = executable_value
        .as_object_mut()
        .ok_or_else(|| eyre!("payload executable must be an object"))?;
    if let Some(instructions_value) = executable_obj.get_mut("Instructions") {
        let instructions = instructions_value
            .as_array_mut()
            .ok_or_else(|| eyre!("payload Instructions must be an array"))?;
        if instructions.len() != wire_payloads.len() {
            bail!(
                "payload instructions length mismatch: expected {}, got {}",
                wire_payloads.len(),
                instructions.len()
            );
        }
        for (entry, wire) in instructions.iter_mut().zip(wire_payloads) {
            apply_wire_payload_to_instruction(entry, wire)?;
        }
        return Ok(());
    }
    let items = executable_obj
        .get_mut("Batch")
        .ok_or_else(|| eyre!("payload executable missing Instructions or Batch"))?
        .as_array_mut()
        .ok_or_else(|| eyre!("payload Batch must be an array"))?;
    let mut wires = wire_payloads.iter();
    let mut instruction_count = 0_usize;
    for item in items {
        let item = item
            .as_object_mut()
            .ok_or_else(|| eyre!("batch entries must be objects"))?;
        let Some(instruction) = item.get_mut("Instruction") else {
            continue;
        };
        let wire = wires
            .next()
            .ok_or_else(|| eyre!("batch contains more instructions than decoded payload"))?;
        apply_wire_payload_to_instruction(instruction, wire)?;
        instruction_count += 1;
    }
    if wires.next().is_some() || instruction_count != wire_payloads.len() {
        bail!(
            "payload batch instruction length mismatch: expected {}, got {}",
            wire_payloads.len(),
            instruction_count
        );
    }
    Ok(())
}
fn apply_wire_payload_to_instruction(
    entry: &mut Value,
    wire: &WireInstructionPayload,
) -> Result<()> {
    let obj = entry
        .as_object_mut()
        .ok_or_else(|| eyre!("instruction entries must be objects"))?;
    if obj.contains_key("kind") || obj.contains_key("arguments") {
        bail!("instruction entries must not include legacy kind/arguments fields");
    }
    obj.insert("wire_name".into(), Value::String(wire.wire_name.clone()));
    obj.insert(
        "payload_base64".into(),
        Value::String(wire.payload_base64.clone()),
    );
    Ok(())
}
fn expect_string<'a>(obj: &'a Map, key: &str) -> Result<&'a str> {
    obj.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("missing '{key}' string"))
}
fn require_exact_fields(obj: &Map, expected: &[&str], label: &str) -> Result<()> {
    for field in expected {
        if !obj.contains_key(*field) {
            bail!("{label} is missing required field '{field}'");
        }
    }
    for field in obj.keys() {
        if !expected.contains(&field.as_str()) {
            bail!("{label} contains unknown field '{field}'");
        }
    }
    Ok(())
}
fn decode_canonical_base64(encoded: &str, label: &str) -> Result<Vec<u8>> {
    let decoded = BASE64
        .decode(encoded.as_bytes())
        .with_context(|| format!("{label} is not valid base64"))?;
    if BASE64.encode(&decoded) != encoded {
        bail!("{label} must use canonical base64");
    }
    Ok(decoded)
}
fn expect_u64(obj: &Map, key: &str) -> Result<u64> {
    obj.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("missing '{key}' integer"))
}
fn expect_nonzero_u64(obj: &Map, key: &str) -> Result<u64> {
    let value = expect_u64(obj, key)?;
    if value == 0 {
        bail!("'{key}' must be greater than zero");
    }
    Ok(value)
}
fn parse_optional_u32(obj: &Map, key: &str) -> Result<Option<u32>> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => {
            let value = number
                .as_u64()
                .ok_or_else(|| eyre!("'{key}' must be an integer or null"))?;
            let value_u32 = u32::try_from(value)
                .with_context(|| format!("'{key}' must fit in u32 (got {value})"))?;
            if value_u32 == 0 {
                bail!("'{key}' must be greater than zero when present");
            }
            Ok(Some(value_u32))
        }
        Some(other) => bail!("'{key}' must be an integer or null, got {other:?}"),
    }
}
fn validate_fixture_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        bail!("fixture name must not be empty");
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        bail!("fixture name '{name}' must start with a lowercase ASCII letter or digit");
    }
    if !bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
    }) {
        bail!(
            "fixture name '{name}' must contain only lowercase ASCII letters, digits, '_' or '-'"
        );
    }
    Ok(())
}
fn validate_fixture_identity(name: &str, encoded_file: &str) -> Result<()> {
    validate_fixture_name(name)?;
    let expected = format!("{name}.norito");
    if encoded_file != expected {
        bail!("fixture '{name}' encoded_file must be exactly '{expected}', got '{encoded_file}'");
    }
    Ok(())
}
fn sync_norito_files(
    fixtures: &[FixtureEntry],
    source_dir: &Path,
    target_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;
    for fixture in fixtures {
        let src = source_dir.join(&fixture.encoded_file);
        if !src.is_file() {
            return Err(eyre!(
                "fixture '{}' missing generated payload at {}",
                fixture.name,
                src.display()
            ));
        }
        let dst = target_dir.join(&fixture.encoded_file);
        fs::copy(&src, &dst)
            .with_context(|| format!("failed to copy {} to {}", src.display(), dst.display()))?;
    }
    Ok(())
}
fn sync_sdk_fixture_mirrors(
    publication_root: &Path,
    canonical_dir: &Path,
    fixtures: &[FixtureEntry],
    manifest_json: &str,
) -> Result<()> {
    let canonical_payloads = canonical_dir.join(PAYLOADS_BASENAME);
    let payloads = fs::read(&canonical_payloads)
        .with_context(|| format!("failed to read {}", canonical_payloads.display()))?;
    let manifest = format!("{manifest_json}\n");
    for sdk in SDK_FIXTURE_DIRECTORIES {
        let target_dir = publication_root.join(sdk.relative_directory);
        fs::create_dir_all(&target_dir)
            .with_context(|| format!("failed to create {} fixture directory", sdk.label))?;
        if sdk.local_blobs == LocalBlobPolicy::Canonical {
            sync_norito_files(fixtures, canonical_dir, &target_dir)?;
        }
        fs::write(target_dir.join(PAYLOADS_BASENAME), &payloads)
            .with_context(|| format!("failed to write {} payload descriptor", sdk.label))?;
        fs::write(target_dir.join(MANIFEST_BASENAME), manifest.as_bytes())
            .with_context(|| format!("failed to write {} fixture manifest", sdk.label))?;
    }
    Ok(())
}
fn owned_publication_paths(fixtures: &[FixtureEntry]) -> Result<Vec<PathBuf>> {
    let canonical_dir = PathBuf::from(CANONICAL_FIXTURE_DIRECTORY);
    let mut paths = vec![
        PathBuf::from(ALIAS_SETUP_FIXTURE_V1),
        canonical_dir.join(PAYLOADS_BASENAME),
        canonical_dir.join(MANIFEST_BASENAME),
        canonical_dir.join(SCHEMA_HASH_MANIFEST_BASENAME),
        canonical_dir.join(COMPACT_HASH_VECTOR_BASENAME),
    ];
    for fixture in fixtures {
        validate_fixture_identity(&fixture.name, &fixture.encoded_file)?;
        paths.push(canonical_dir.join(&fixture.encoded_file));
    }
    for sdk in SDK_FIXTURE_DIRECTORIES {
        let sdk_dir = PathBuf::from(sdk.relative_directory);
        paths.push(sdk_dir.join(PAYLOADS_BASENAME));
        paths.push(sdk_dir.join(MANIFEST_BASENAME));
        if sdk.local_blobs == LocalBlobPolicy::Canonical {
            for fixture in fixtures {
                paths.push(sdk_dir.join(&fixture.encoded_file));
            }
        }
    }
    let mut normalized = BTreeMap::new();
    for path in paths {
        let logical_path = normalize_publication_path(&path)?;
        let identity = publication_path_identity(&logical_path);
        if let Some((previous_logical, previous)) =
            normalized.insert(identity.clone(), (logical_path.clone(), path))
        {
            bail!(
                "duplicate generated fixture output identity `{identity}` from `{previous_logical}` ({}) and `{logical_path}`",
                previous.display(),
            );
        }
    }
    Ok(normalized.into_values().map(|(_, path)| path).collect())
}
fn normalize_publication_path(path: &Path) -> Result<String> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("generated fixture path must be a non-empty relative path");
    }
    let mut normalized = String::new();
    for component in path.components() {
        let Component::Normal(segment) = component else {
            bail!("generated fixture path is ambiguous: {}", path.display());
        };
        let segment = segment
            .to_str()
            .ok_or_else(|| eyre!("generated fixture path is not UTF-8: {}", path.display()))?;
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || !segment.is_ascii()
            || segment
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
        {
            bail!(
                "generated fixture path contains a non-canonical segment: {}",
                path.display()
            );
        }
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(segment);
    }
    if normalized.is_empty() {
        bail!("generated fixture path must not normalize to empty");
    }
    Ok(normalized)
}
fn publication_path_identity(normalized_path: &str) -> String {
    // Publication names are ASCII-only, so lower-casing fully covers both the
    // case-insensitive filesystem alias class and the NFC-equivalent class.
    normalized_path.to_ascii_lowercase()
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicationSnapshot {
    root_mode: u32,
    directories: Vec<PublicationDirectory>,
    files: Vec<PublicationFile>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicationDirectory {
    logical_path: String,
    mode: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicationFile {
    logical_path: String,
    relative_path: PathBuf,
    mode: u32,
    bytes: Vec<u8>,
}
impl PublicationSnapshot {
    fn capture_complete_tree(root: &Path) -> Result<Self> {
        let root_metadata = fs::symlink_metadata(root)
            .with_context(|| format!("failed to inspect publication root {}", root.display()))?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            bail!(
                "publication root must be a regular non-symlink directory: {}",
                root.display()
            );
        }
        let mut directories = BTreeMap::new();
        let mut files = BTreeMap::new();
        collect_publication_tree(root, Path::new(""), &mut directories, &mut files)?;
        if let Some(identity) = files
            .keys()
            .find(|identity| directories.contains_key(*identity))
        {
            bail!("publication identity `{identity}` is both a file and a directory");
        }
        Ok(Self {
            root_mode: canonical_mode(&root_metadata),
            directories: directories.into_values().collect(),
            files: files.into_values().collect(),
        })
    }

    fn without_file(&self, relative_path: &Path) -> Result<Self> {
        let mut unsealed = self.clone();
        let original_len = unsealed.files.len();
        unsealed
            .files
            .retain(|file| file.relative_path != relative_path);
        if original_len != unsealed.files.len() + 1 {
            bail!(
                "publication must contain exactly one commit file at {}",
                relative_path.display()
            );
        }
        Ok(unsealed)
    }

    fn capture(root: &Path, expected_paths: &[PathBuf]) -> Result<Self> {
        let root_metadata = fs::symlink_metadata(root)
            .with_context(|| format!("failed to inspect publication root {}", root.display()))?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            bail!(
                "publication root must be a regular non-symlink directory: {}",
                root.display()
            );
        }
        let mut expected_files = BTreeMap::new();
        let mut expected_directories = BTreeMap::new();
        for relative in expected_paths {
            let logical = normalize_publication_path(relative)?;
            let identity = publication_path_identity(&logical);
            if expected_files
                .insert(identity.clone(), (logical.clone(), relative.clone()))
                .is_some()
            {
                bail!("duplicate publication logical identity `{identity}`");
            }
            let mut parent = relative.parent();
            while let Some(path) = parent {
                if path.as_os_str().is_empty() {
                    break;
                }
                let logical = normalize_publication_path(path)?;
                let identity = publication_path_identity(&logical);
                if let Some(previous) =
                    expected_directories.insert(identity.clone(), logical.clone())
                    && previous != logical
                {
                    bail!(
                        "duplicate publication directory identity `{identity}` from `{previous}` and `{logical}`"
                    );
                }
                parent = path.parent();
            }
        }
        if let Some(identity) = expected_files
            .keys()
            .find(|identity| expected_directories.contains_key(*identity))
        {
            bail!("publication identity `{identity}` is both a file and a directory");
        }
        let mut actual_directories = BTreeMap::new();
        let mut actual_files = BTreeMap::new();
        collect_publication_tree(
            root,
            Path::new(""),
            &mut actual_directories,
            &mut actual_files,
        )?;
        if let Some(identity) = actual_files
            .keys()
            .find(|identity| actual_directories.contains_key(*identity))
        {
            bail!("publication identity `{identity}` is both a file and a directory");
        }
        let actual_file_paths = actual_files.keys().cloned().collect::<BTreeSet<_>>();
        let expected_file_paths = expected_files.keys().cloned().collect::<BTreeSet<_>>();
        if actual_file_paths != expected_file_paths {
            let missing = expected_file_paths
                .difference(&actual_file_paths)
                .cloned()
                .collect::<Vec<_>>();
            let unexpected = actual_file_paths
                .difference(&expected_file_paths)
                .cloned()
                .collect::<Vec<_>>();
            bail!(
                "publication file path set mismatch (missing={missing:?}, unexpected={unexpected:?})"
            );
        }
        for (identity, (expected_logical, expected_relative)) in &expected_files {
            let actual = actual_files
                .get(identity)
                .expect("equal publication file sets contain the expected identity");
            if &actual.logical_path != expected_logical
                || &actual.relative_path != expected_relative
            {
                bail!(
                    "publication path spelling mismatch for identity `{identity}`: expected `{expected_logical}`, found `{}`",
                    actual.logical_path
                );
            }
        }
        let actual_directory_paths = actual_directories.keys().cloned().collect::<BTreeSet<_>>();
        let expected_directory_paths = expected_directories
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        if actual_directory_paths != expected_directory_paths {
            let missing = expected_directory_paths
                .difference(&actual_directory_paths)
                .cloned()
                .collect::<Vec<_>>();
            let unexpected = actual_directory_paths
                .difference(&expected_directory_paths)
                .cloned()
                .collect::<Vec<_>>();
            bail!(
                "publication directory path set mismatch (missing={missing:?}, unexpected={unexpected:?})"
            );
        }
        for (identity, expected_logical) in &expected_directories {
            let actual = actual_directories
                .get(identity)
                .expect("equal publication directory sets contain the expected identity");
            if &actual.logical_path != expected_logical {
                bail!(
                    "publication directory spelling mismatch for identity `{identity}`: expected `{expected_logical}`, found `{}`",
                    actual.logical_path
                );
            }
        }
        Ok(Self {
            root_mode: canonical_mode(&root_metadata),
            directories: actual_directories.into_values().collect(),
            files: actual_files.into_values().collect(),
        })
    }
    fn require_identical(&self, other: &Self) -> Result<()> {
        if self.root_mode != other.root_mode {
            bail!("independent fixture renders have different root directory modes");
        }
        if self.directories != other.directories {
            bail!("independent fixture renders have different directory paths or modes");
        }
        if self.files.len() != other.files.len() {
            bail!(
                "independent fixture renders have different file counts ({} != {})",
                self.files.len(),
                other.files.len()
            );
        }
        for (first, second) in self.files.iter().zip(&other.files) {
            if first.logical_path != second.logical_path
                || first.relative_path != second.relative_path
                || first.mode != second.mode
            {
                bail!(
                    "independent fixture renders have different path or mode at `{}`",
                    first.logical_path
                );
            }
            if first.bytes != second.bytes {
                bail!(
                    "independent fixture renders differ byte-for-byte at `{}`",
                    first.logical_path
                );
            }
        }
        Ok(())
    }
}
fn collect_publication_tree(
    root: &Path,
    relative_directory: &Path,
    directories: &mut BTreeMap<String, PublicationDirectory>,
    files: &mut BTreeMap<String, PublicationFile>,
) -> Result<()> {
    let directory = root.join(relative_directory);
    let mut entries = fs::read_dir(&directory)
        .with_context(|| format!("failed to enumerate {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let relative = relative_directory.join(entry.file_name());
        let logical = normalize_publication_path(&relative)?;
        let identity = publication_path_identity(&logical);
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect generated output {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "generated publication contains a symlink: {}",
                path.display()
            );
        }
        if metadata.is_dir() {
            let directory = PublicationDirectory {
                logical_path: logical.clone(),
                mode: canonical_mode(&metadata),
            };
            if directories.insert(identity.clone(), directory).is_some() {
                bail!("duplicate publication directory identity `{identity}`");
            }
            collect_publication_tree(root, &relative, directories, files)?;
        } else if metadata.is_file() {
            let guarded_identity = file_identity(&metadata, &path)?;
            let bytes = read_guarded_file(&path, guarded_identity)?;
            let file = PublicationFile {
                logical_path: logical.clone(),
                relative_path: relative,
                mode: canonical_mode(&metadata),
                bytes,
            };
            if files.insert(identity.clone(), file).is_some() {
                bail!("duplicate publication file identity `{identity}`");
            }
        } else {
            bail!(
                "generated publication contains a non-regular entry: {}",
                path.display()
            );
        }
    }
    Ok(())
}
#[cfg(unix)]
fn canonical_mode(metadata: &fs::Metadata) -> u32 {
    metadata.mode() & 0o777
}
#[cfg(windows)]
fn canonical_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}
#[cfg(not(any(unix, windows)))]
fn canonical_mode(_metadata: &fs::Metadata) -> u32 {
    0
}
fn normalize_rendered_modes(root: &Path, owned_paths: &[PathBuf]) -> Result<()> {
    set_canonical_directory_mode(root)?;
    let mut directories = BTreeSet::new();
    for relative in owned_paths {
        let path = root.join(relative);
        set_canonical_file_mode(&path)?;
        let mut parent = relative.parent();
        while let Some(relative_parent) = parent {
            if relative_parent.as_os_str().is_empty() {
                break;
            }
            directories.insert(relative_parent.to_path_buf());
            parent = relative_parent.parent();
        }
    }
    for relative in directories {
        set_canonical_directory_mode(&root.join(relative))?;
    }
    Ok(())
}
#[cfg(unix)]
fn set_canonical_file_mode(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to set canonical mode on {}", path.display()))
}
#[cfg(windows)]
fn set_canonical_file_mode(path: &Path) -> Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to set canonical mode on {}", path.display()))
}
#[cfg(not(any(unix, windows)))]
fn set_canonical_file_mode(path: &Path) -> Result<()> {
    bail!("cannot prove canonical file mode for {}", path.display())
}
#[cfg(unix)]
fn set_canonical_directory_mode(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("failed to set canonical mode on {}", path.display()))
}
#[cfg(windows)]
fn set_canonical_directory_mode(path: &Path) -> Result<()> {
    set_canonical_file_mode(path)
}
#[cfg(not(any(unix, windows)))]
fn set_canonical_directory_mode(path: &Path) -> Result<()> {
    bail!(
        "cannot prove canonical directory mode for {}",
        path.display()
    )
}
fn publish_create_only_publication<F>(
    snapshot: &PublicationSnapshot,
    destination_root: &Path,
    owned_paths: &[PathBuf],
    validate: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    // Stable `std` has no portable handle-relative create/link API. Release
    // callers must therefore supply a private parent directory that no hostile
    // same-UID process can rename or replace while lexical operations run. The
    // identity checks below detect ordinary namespace drift; they do not claim
    // to close an adversarial check/use race outside that documented boundary.
    let parent = destination_root
        .parent()
        .ok_or_else(|| eyre!("create-only fixture output root has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect output parent {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!(
            "create-only fixture output parent must be a regular non-symlink directory: {}",
            parent.display()
        );
    }
    let parent_identity = directory_identity(&parent_metadata, parent)?;
    let seal = snapshot
        .files
        .iter()
        .find(|file| file.relative_path == Path::new(CANONICAL_MANIFEST))
        .ok_or_else(|| eyre!("fixture publication is missing its canonical manifest seal"))?;
    if snapshot
        .files
        .iter()
        .filter(|file| file.relative_path == Path::new(CANONICAL_MANIFEST))
        .count()
        != 1
    {
        bail!("fixture publication must contain exactly one canonical manifest seal");
    }
    let snapshot_paths = snapshot
        .files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let owned_path_set = owned_paths.iter().cloned().collect::<BTreeSet<_>>();
    if snapshot_paths != owned_path_set || snapshot_paths.len() != owned_paths.len() {
        bail!("fixture publication snapshot does not match its owned path inventory");
    }
    let unsealed_snapshot = snapshot.without_file(Path::new(CANONICAL_MANIFEST))?;
    require_directory_identity(parent, parent_identity)?;
    fs::create_dir(destination_root).with_context(|| {
        format!(
            "create-only fixture output root already exists or cannot be reserved: {}",
            destination_root.display()
        )
    })?;
    let published = (|| {
        require_directory_identity(parent, parent_identity)?;
        set_canonical_directory_mode(destination_root)?;
        let mut directory_identities = BTreeMap::new();
        directory_identities.insert(
            PathBuf::new(),
            capture_directory_identity(destination_root)?,
        );
        sync_directory(parent)?;
        for directory in &snapshot.directories {
            let relative = PathBuf::from(
                directory
                    .logical_path
                    .replace('/', std::path::MAIN_SEPARATOR_STR),
            );
            let path = destination_root.join(relative);
            verify_publication_namespace(
                parent,
                parent_identity,
                destination_root,
                &directory_identities,
            )?;
            ensure_safe_owned_path(destination_root, &path)?;
            fs::create_dir(&path)
                .with_context(|| format!("failed to create output directory {}", path.display()))?;
            set_canonical_directory_mode(&path)?;
            if canonical_mode(&fs::symlink_metadata(&path)?) != directory.mode {
                bail!(
                    "published directory mode drifted at `{}`",
                    directory.logical_path
                );
            }
            let relative = path
                .strip_prefix(destination_root)
                .expect("published directory remains beneath its root")
                .to_path_buf();
            directory_identities.insert(relative, capture_directory_identity(&path)?);
            sync_directory(
                path.parent()
                    .expect("published directory always has a parent"),
            )?;
        }
        for file in snapshot
            .files
            .iter()
            .filter(|file| file.relative_path != Path::new(CANONICAL_MANIFEST))
        {
            verify_publication_namespace(
                parent,
                parent_identity,
                destination_root,
                &directory_identities,
            )?;
            let path = destination_root.join(&file.relative_path);
            ensure_safe_owned_path(destination_root, &path)?;
            write_create_only_file(&path, &file.bytes)?;
            sync_directory(path.parent().expect("published file always has a parent"))?;
        }
        verify_publication_namespace(
            parent,
            parent_identity,
            destination_root,
            &directory_identities,
        )?;
        let published_unsealed = PublicationSnapshot::capture_complete_tree(destination_root)?;
        unsealed_snapshot.require_identical(&published_unsealed)?;
        validate()?;
        verify_publication_namespace(
            parent,
            parent_identity,
            destination_root,
            &directory_identities,
        )?;
        publish_manifest_seal(
            seal,
            parent,
            parent_identity,
            destination_root,
            &directory_identities,
        )?;
        Ok(())
    })();
    published.with_context(|| {
        format!(
            "create-only fixture publication failed; the rejected reservation was left in place at {}",
            destination_root.display()
        )
    })
}

fn write_create_only_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    output.write_all(bytes)?;
    output.flush()?;
    output.sync_all()?;
    drop(output);
    set_canonical_file_mode(path)?;
    let actual = read_canonical_owned_file(path)?;
    if actual != bytes {
        bail!("published file bytes drifted at {}", path.display());
    }
    Ok(())
}

fn publish_manifest_seal(
    seal: &PublicationFile,
    parent: &Path,
    parent_identity: DirectoryIdentity,
    destination_root: &Path,
    directory_identities: &BTreeMap<PathBuf, DirectoryIdentity>,
) -> Result<()> {
    let seal_path = destination_root.join(&seal.relative_path);
    ensure_safe_owned_path(destination_root, &seal_path)?;
    let root_name = destination_root
        .file_name()
        .ok_or_else(|| eyre!("fixture publication root has no final component"))?
        .to_string_lossy();
    let pending_path = parent.join(format!(".{root_name}{PUBLICATION_SEAL_PENDING_SUFFIX}"));
    if pending_path == seal_path {
        bail!("fixture publication seal staging path aliases its final path");
    }
    require_directory_identity(parent, parent_identity)?;
    write_create_only_file(&pending_path, &seal.bytes)
        .context("failed to stage the canonical manifest seal")?;
    sync_directory(parent)?;
    verify_publication_namespace(
        parent,
        parent_identity,
        destination_root,
        directory_identities,
    )?;
    fs::hard_link(&pending_path, &seal_path).with_context(|| {
        format!(
            "failed to publish the canonical manifest seal without clobbering {}",
            seal_path.display()
        )
    })?;
    sync_directory(
        seal_path
            .parent()
            .expect("canonical manifest seal has a parent"),
    )?;
    verify_publication_namespace(
        parent,
        parent_identity,
        destination_root,
        directory_identities,
    )?;
    require_staged_manifest_link(&pending_path, &seal_path, &seal.bytes)?;
    // Removing the staging name is the commit point: before this succeeds the
    // final seal has two links and every verifier rejects it. Nothing fallible
    // may run after this operation, or an error could expose a valid-looking
    // seal for a publication that the caller was told had failed.
    fs::remove_file(&pending_path).with_context(|| {
        format!(
            "failed to retire canonical manifest seal staging file {}",
            pending_path.display()
        )
    })?;
    Ok(())
}

fn require_staged_manifest_link(pending_path: &Path, seal_path: &Path, bytes: &[u8]) -> Result<()> {
    let pending_before = linked_file_identity(pending_path)?;
    let seal_before = linked_file_identity(seal_path)?;
    if pending_before != seal_before || pending_before.links != 2 {
        bail!("canonical manifest seal is not the expected two-link staged file");
    }
    if pending_before.mode != 0o644 {
        bail!("canonical manifest seal staging file does not use mode 0644");
    }
    let actual = fs::read(seal_path)
        .with_context(|| format!("failed to read staged seal {}", seal_path.display()))?;
    if actual != bytes {
        bail!("canonical manifest seal bytes changed before commit");
    }
    let pending_after = linked_file_identity(pending_path)?;
    let seal_after = linked_file_identity(seal_path)?;
    if pending_after != pending_before || seal_after != seal_before {
        bail!("canonical manifest seal identity changed before commit");
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    // Stable std does not expose a portable directory-sync handle. File bytes
    // are synced before the seal is linked; namespace identities are still
    // checked before and after each operation.
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_time_seconds: i64,
    #[cfg(unix)]
    change_time_nanoseconds: i64,
    #[cfg(windows)]
    volume_serial_number: u32,
    #[cfg(windows)]
    file_index: u64,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    last_write_time: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u32,
    #[cfg(windows)]
    file_index: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinkedFileIdentity {
    links: u64,
    mode: u32,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u32,
    #[cfg(windows)]
    file_index: u64,
}
#[derive(Clone, Debug)]
struct GuardedFile {
    identity: FileIdentity,
    bytes: Vec<u8>,
}
#[cfg(unix)]
fn directory_identity(metadata: &fs::Metadata, path: &Path) -> Result<DirectoryIdentity> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "fixture publication namespace must be a regular non-symlink directory: {}",
            path.display()
        );
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}
#[cfg(windows)]
fn directory_identity(metadata: &fs::Metadata, path: &Path) -> Result<DirectoryIdentity> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "fixture publication namespace must be a regular non-symlink directory: {}",
            path.display()
        );
    }
    Ok(DirectoryIdentity {
        volume_serial_number: metadata.volume_serial_number().ok_or_else(|| {
            eyre!(
                "missing volume identity for fixture publication directory {}",
                path.display()
            )
        })?,
        file_index: metadata.file_index().ok_or_else(|| {
            eyre!(
                "missing file identity for fixture publication directory {}",
                path.display()
            )
        })?,
    })
}
#[cfg(not(any(unix, windows)))]
fn directory_identity(_metadata: &fs::Metadata, path: &Path) -> Result<DirectoryIdentity> {
    bail!(
        "fixture publication is unavailable because directory identity cannot be proven on this platform: {}",
        path.display()
    )
}
fn capture_directory_identity(path: &Path) -> Result<DirectoryIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect publication directory {}", path.display()))?;
    directory_identity(&metadata, path)
}
fn require_directory_identity(path: &Path, expected: DirectoryIdentity) -> Result<()> {
    let actual = capture_directory_identity(path)?;
    if actual != expected {
        bail!(
            "fixture publication directory identity changed: {}",
            path.display()
        );
    }
    Ok(())
}
#[cfg(unix)]
fn linked_file_identity(path: &Path) -> Result<LinkedFileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect staged fixture seal {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "staged fixture seal must be a regular non-symlink file: {}",
            path.display()
        );
    }
    Ok(LinkedFileIdentity {
        links: metadata.nlink(),
        mode: canonical_mode(&metadata),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}
#[cfg(windows)]
fn linked_file_identity(path: &Path) -> Result<LinkedFileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect staged fixture seal {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "staged fixture seal must be a regular non-symlink file: {}",
            path.display()
        );
    }
    Ok(LinkedFileIdentity {
        links: u64::from(metadata.number_of_links().ok_or_else(|| {
            eyre!(
                "missing link count for staged fixture seal {}",
                path.display()
            )
        })?),
        mode: canonical_mode(&metadata),
        volume_serial_number: metadata.volume_serial_number().ok_or_else(|| {
            eyre!(
                "missing volume identity for staged fixture seal {}",
                path.display()
            )
        })?,
        file_index: metadata.file_index().ok_or_else(|| {
            eyre!(
                "missing file identity for staged fixture seal {}",
                path.display()
            )
        })?,
    })
}
#[cfg(not(any(unix, windows)))]
fn linked_file_identity(path: &Path) -> Result<LinkedFileIdentity> {
    bail!(
        "cannot prove staged fixture seal identity on this platform: {}",
        path.display()
    )
}
fn verify_publication_namespace(
    parent: &Path,
    parent_identity: DirectoryIdentity,
    root: &Path,
    directories: &BTreeMap<PathBuf, DirectoryIdentity>,
) -> Result<()> {
    require_directory_identity(parent, parent_identity)?;
    for (relative, identity) in directories {
        let path = if relative.as_os_str().is_empty() {
            root.to_path_buf()
        } else {
            root.join(relative)
        };
        require_directory_identity(&path, *identity)?;
    }
    Ok(())
}
#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata, path: &Path) -> Result<FileIdentity> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "fixture publication preimage must be a regular non-symlink file: {}",
            path.display()
        );
    }
    if metadata.nlink() != 1 {
        bail!(
            "fixture publication preimage must not be hard-linked: {}",
            path.display()
        );
    }
    Ok(FileIdentity {
        len: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
        change_time_seconds: metadata.ctime(),
        change_time_nanoseconds: metadata.ctime_nsec(),
    })
}
#[cfg(windows)]
fn file_identity(metadata: &fs::Metadata, path: &Path) -> Result<FileIdentity> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "fixture publication preimage must be a regular non-symlink file: {}",
            path.display()
        );
    }
    let links = metadata.number_of_links().ok_or_else(|| {
        eyre!(
            "failed to prove hard-link count for fixture publication preimage {}",
            path.display()
        )
    })?;
    if links != 1 {
        bail!(
            "fixture publication preimage must not be hard-linked: {}",
            path.display()
        );
    }
    Ok(FileIdentity {
        len: metadata.len(),
        volume_serial_number: metadata.volume_serial_number().ok_or_else(|| {
            eyre!(
                "missing volume identity for fixture preimage {}",
                path.display()
            )
        })?,
        file_index: metadata.file_index().ok_or_else(|| {
            eyre!(
                "missing file identity for fixture preimage {}",
                path.display()
            )
        })?,
        creation_time: metadata.creation_time(),
        last_write_time: metadata.last_write_time(),
    })
}
#[cfg(not(any(unix, windows)))]
fn file_identity(_metadata: &fs::Metadata, path: &Path) -> Result<FileIdentity> {
    bail!(
        "fixture publication is unavailable because file identity cannot be proven on this platform: {}",
        path.display()
    )
}
fn read_guarded_file(path: &Path, expected_identity: FileIdentity) -> Result<Vec<u8>> {
    let path_identity = file_identity(&fs::symlink_metadata(path)?, path)?;
    if path_identity != expected_identity {
        bail!(
            "fixture publication preimage identity changed: {}",
            path.display()
        );
    }
    let mut file = File::open(path)
        .with_context(|| format!("failed to open guarded fixture preimage {}", path.display()))?;
    let handle_identity = file_identity(&file.metadata()?, path)?;
    if handle_identity != expected_identity {
        bail!(
            "fixture publication preimage handle changed: {}",
            path.display()
        );
    }
    let expected_len = usize::try_from(expected_identity.len).map_err(|_| {
        eyre!(
            "fixture publication preimage is too large to address on this platform: {} bytes at {}",
            expected_identity.len,
            path.display()
        )
    })?;
    let mut bytes = Vec::with_capacity(expected_len);
    file.read_to_end(&mut bytes)?;
    let final_identity = file_identity(&fs::symlink_metadata(path)?, path)?;
    if final_identity != expected_identity {
        bail!(
            "fixture publication preimage changed while reading: {}",
            path.display()
        );
    }
    Ok(bytes)
}
fn capture_optional_guarded_file(path: &Path) -> Result<Option<GuardedFile>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect fixture preimage {}", path.display()));
        }
    };
    let identity = file_identity(&metadata, path)?;
    let bytes = read_guarded_file(path, identity)?;
    Ok(Some(GuardedFile { identity, bytes }))
}
fn capture_required_guarded_file(path: &Path) -> Result<GuardedFile> {
    capture_optional_guarded_file(path)?.ok_or_else(|| {
        eyre!(
            "canonical fixture source must be a regular non-symlink file: {}",
            path.display()
        )
    })
}
fn verify_preimage(path: &Path, expected: Option<&GuardedFile>) -> Result<()> {
    match expected {
        Some(expected) => {
            let actual = read_guarded_file(path, expected.identity).with_context(|| {
                format!("fixture publication preimage changed: {}", path.display())
            })?;
            if actual != expected.bytes {
                bail!(
                    "fixture publication preimage bytes changed: {}",
                    path.display()
                );
            }
        }
        None => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect absent fixture preimage {}",
                        path.display()
                    )
                });
            }
            Ok(_) => {
                bail!(
                    "fixture publication preimage appeared after planning: {}",
                    path.display()
                );
            }
        },
    }
    Ok(())
}
fn compare_owned_publication(
    rendered_root: &Path,
    destination_root: &Path,
    owned_paths: &[PathBuf],
) -> Result<()> {
    require_publication_seal(rendered_root).context("rendered fixture publication is unsealed")?;
    require_publication_seal(destination_root)
        .context("tracked fixture publication is unsealed")?;
    for relative in owned_paths {
        let rendered = rendered_root.join(relative);
        ensure_safe_owned_path(rendered_root, &rendered)?;
        let expected = read_canonical_owned_file(&rendered)?;
        let destination = destination_root.join(relative);
        ensure_safe_owned_path(destination_root, &destination)?;
        let actual = read_canonical_owned_file(&destination).with_context(|| {
            format!(
                "invalid generated fixture output: {}",
                destination.display()
            )
        })?;
        if actual != expected {
            bail!(
                "generated fixture output is stale: {}",
                destination.display()
            );
        }
    }
    Ok(())
}
fn read_canonical_owned_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect owned fixture {}", path.display()))?;
    let identity = file_identity(&metadata, path)?;
    let mode = canonical_mode(&metadata);
    if mode != 0o644 {
        bail!(
            "owned fixture must use canonical mode 0644 (found {mode:04o}): {}",
            path.display()
        );
    }
    read_guarded_file(path, identity)
        .with_context(|| format!("failed to read owned fixture {}", path.display()))
}
fn require_publication_seal(root: &Path) -> Result<Manifest> {
    let seal_path = root.join(CANONICAL_MANIFEST);
    ensure_safe_owned_path(root, &seal_path)?;
    let bytes = read_canonical_owned_file(&seal_path).with_context(|| {
        format!(
            "canonical manifest seal is missing: {}",
            seal_path.display()
        )
    })?;
    let manifest = Manifest::from_bytes(&bytes).context("invalid canonical manifest seal")?;
    manifest
        .validate(None)
        .context("canonical manifest seal failed validation")?;
    Ok(manifest)
}
fn verify_all_blob_policies(
    publication_root: &Path,
    fixtures: &[FixtureEntry],
    require_canonical_set: bool,
) -> Result<()> {
    require_publication_seal(publication_root)
        .context("fixture publication has no valid completion seal")?;
    verify_all_blob_policies_without_seal(publication_root, fixtures, require_canonical_set)
}
fn verify_all_blob_policies_without_seal(
    publication_root: &Path,
    fixtures: &[FixtureEntry],
    require_canonical_set: bool,
) -> Result<()> {
    verify_blob_policy(
        &publication_root.join(CANONICAL_FIXTURE_DIRECTORY),
        fixtures,
        LocalBlobPolicy::Canonical,
        require_canonical_set,
    )?;
    for sdk in SDK_FIXTURE_DIRECTORIES {
        let directory = publication_root.join(sdk.relative_directory);
        if !directory.exists() && !require_canonical_set {
            continue;
        }
        verify_blob_policy(&directory, fixtures, sdk.local_blobs, require_canonical_set)
            .with_context(|| format!("{} local fixture policy failed", sdk.label))?;
    }
    Ok(())
}
fn verify_blob_policy(
    directory: &Path,
    fixtures: &[FixtureEntry],
    policy: LocalBlobPolicy,
    require_canonical_set: bool,
) -> Result<()> {
    let actual = collect_norito_paths(directory)?;
    let expected: BTreeSet<PathBuf> = fixtures
        .iter()
        .map(|fixture| PathBuf::from(&fixture.encoded_file))
        .collect();
    match policy {
        LocalBlobPolicy::None if !actual.is_empty() => {
            bail!(
                "fixture directory {} contains redundant Norito blobs: {:?}",
                directory.display(),
                actual
            );
        }
        LocalBlobPolicy::Canonical => {
            let unexpected: Vec<_> = actual.difference(&expected).cloned().collect();
            if !unexpected.is_empty() {
                bail!(
                    "fixture directory {} contains unowned Norito blobs: {:?}",
                    directory.display(),
                    unexpected
                );
            }
            if require_canonical_set && actual != expected {
                let missing: Vec<_> = expected.difference(&actual).cloned().collect();
                bail!(
                    "fixture directory {} is missing canonical Norito blobs: {:?}",
                    directory.display(),
                    missing
                );
            }
        }
        LocalBlobPolicy::SwiftPrefixed => {
            let unexpected: Vec<_> = actual
                .iter()
                .filter(|relative| {
                    relative.parent() != Some(Path::new(""))
                        || !relative
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name.starts_with("swift_"))
                })
                .cloned()
                .collect();
            if !unexpected.is_empty() {
                bail!(
                    "Swift fixture directory {} contains unowned Norito blobs: {:?}",
                    directory.display(),
                    unexpected
                );
            }
        }
        LocalBlobPolicy::None => {}
    }
    Ok(())
}
fn collect_norito_paths(directory: &Path) -> Result<BTreeSet<PathBuf>> {
    if !directory.is_dir() {
        bail!("fixture directory missing: {}", directory.display());
    }
    let mut found = BTreeSet::new();
    let mut pending = BTreeSet::from([directory.to_path_buf()]);
    while let Some(current) = pending.pop_first() {
        let mut entries = fs::read_dir(&current)
            .with_context(|| format!("failed to read {}", current.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                bail!(
                    "fixture directory must not contain symlinks: {}",
                    entry.path().display()
                );
            }
            if file_type.is_dir() {
                pending.insert(entry.path());
                continue;
            }
            if entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("norito")
            {
                continue;
            }
            if !file_type.is_file() {
                bail!(
                    "Norito fixture must be a regular file: {}",
                    entry.path().display()
                );
            }
            found.insert(entry.path().strip_prefix(directory)?.to_path_buf());
        }
    }
    Ok(found)
}
fn manifest_digest(path: &Path, root: &Path) -> Result<ManifestDigestReport> {
    let digest = compute_file_digest(path)?;
    Ok(ManifestDigestReport {
        path: relative_path(root, path),
        sha256: digest.sha256,
        blake3: digest.blake3,
        bytes: digest.bytes,
    })
}
struct FileDigest {
    sha256: String,
    blake3: String,
    bytes: u64,
}
fn compute_file_digest(path: &Path) -> Result<FileDigest> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open {} for digesting", path.display()))?;
    let mut sha = Sha256::new();
    let mut blake = blake3::Hasher::new();
    let mut buf = [0u8; 8192];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        sha.update(&buf[..read]);
        blake.update(&buf[..read]);
        total = total.saturating_add(read as u64);
    }
    Ok(FileDigest {
        sha256: hex_encode(sha.finalize()),
        blake3: blake.finalize().to_hex().to_string(),
        bytes: total,
    })
}
fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Manifest {
    fixtures: Vec<FixtureEntry>,
}
impl Manifest {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value: Value = json::from_slice(bytes)?;
        validate_manifest_shape(&value)?;
        Ok(json::from_value(value)?)
    }
    fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }
    fn validate(&self, base_dir: Option<&Path>) -> Result<()> {
        let mut names = HashSet::with_capacity(self.fixtures.len());
        let mut encoded_files = HashSet::with_capacity(self.fixtures.len());
        let mut payload_hashes = HashSet::with_capacity(self.fixtures.len());
        let mut payload_bytes_values = HashSet::with_capacity(self.fixtures.len());
        let mut signed_hashes = HashSet::with_capacity(self.fixtures.len());
        let mut signed_bytes_values = HashSet::with_capacity(self.fixtures.len());
        for fixture in &self.fixtures {
            validate_fixture_identity(&fixture.name, &fixture.encoded_file)?;
            if !names.insert(fixture.name.as_str()) {
                bail!("duplicate fixture name '{}'", fixture.name);
            }
            if !encoded_files.insert(fixture.encoded_file.as_str()) {
                bail!("duplicate fixture encoded_file '{}'", fixture.encoded_file);
            }
            if !payload_hashes.insert(fixture.payload_hash.as_str()) {
                bail!("duplicate fixture payload_hash '{}'", fixture.payload_hash);
            }
            let payload_bytes = BASE64
                .decode(fixture.payload_base64.as_bytes())
                .with_context(|| format!("fixture '{}' payload base64 invalid", fixture.name))?;
            if BASE64.encode(&payload_bytes) != fixture.payload_base64 {
                bail!("fixture '{}' payload base64 is non-canonical", fixture.name);
            }
            if !payload_bytes_values.insert(payload_bytes) {
                bail!("duplicate fixture payload bytes for '{}'", fixture.name);
            }
            if !signed_hashes.insert(fixture.signed_hash.as_str()) {
                bail!("duplicate fixture signed_hash '{}'", fixture.signed_hash);
            }
            let signed_bytes = BASE64
                .decode(fixture.signed_base64.as_bytes())
                .with_context(|| format!("fixture '{}' signed base64 invalid", fixture.name))?;
            if BASE64.encode(&signed_bytes) != fixture.signed_base64 {
                bail!("fixture '{}' signed base64 is non-canonical", fixture.name);
            }
            if !signed_bytes_values.insert(signed_bytes) {
                bail!("duplicate fixture signed bytes for '{}'", fixture.name);
            }
        }
        for fixture in &self.fixtures {
            fixture.validate(base_dir)?;
        }
        Ok(())
    }
}
fn validate_manifest_shape(value: &Value) -> Result<()> {
    const ENTRY_FIELDS: &[&str] = &[
        "name",
        "authority",
        "network_id",
        "creation_time_ms",
        "encoded_file",
        "encoded_len",
        "signed_len",
        "payload_base64",
        "payload_hash",
        "signed_base64",
        "signed_hash",
        "nonce",
        "time_to_live_ms",
    ];

    let root = value
        .as_object()
        .ok_or_else(|| eyre!("fixture manifest root must be an object"))?;
    require_exact_fields(root, &["fixtures"], "fixture manifest root")?;
    let fixtures = root
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("fixture manifest field 'fixtures' must be an array"))?;
    for (index, fixture) in fixtures.iter().enumerate() {
        let object = fixture
            .as_object()
            .ok_or_else(|| eyre!("fixture manifest entry {index} must be an object"))?;
        require_exact_fields(
            object,
            ENTRY_FIELDS,
            &format!("fixture manifest entry {index}"),
        )?;
    }
    Ok(())
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct FixtureEntry {
    name: String,
    authority: String,
    network_id: String,
    creation_time_ms: u64,
    encoded_file: String,
    encoded_len: u64,
    signed_len: u64,
    payload_base64: String,
    payload_hash: String,
    signed_base64: String,
    signed_hash: String,
    nonce: Option<u32>,
    time_to_live_ms: u64,
}
impl FixtureEntry {
    fn validate(&self, base_dir: Option<&Path>) -> Result<()> {
        validate_fixture_identity(&self.name, &self.encoded_file)?;
        if self.time_to_live_ms == 0 {
            bail!(
                "fixture '{}' time_to_live_ms must be greater than zero",
                self.name
            );
        }
        let payload_bytes = BASE64
            .decode(&self.payload_base64)
            .with_context(|| format!("fixture '{}' payload base64 invalid", self.name))?;
        let encoded_len = usize::try_from(self.encoded_len).map_err(|_| {
            eyre!(
                "fixture '{}' encoded_len {} cannot be addressed on this platform",
                self.name,
                self.encoded_len
            )
        })?;
        if payload_bytes.len() != encoded_len {
            bail!(
                "fixture '{}' payload length mismatch (manifest={}, decoded={})",
                self.name,
                self.encoded_len,
                payload_bytes.len()
            );
        }
        let payload: TransactionPayload =
            norito::decode_canonical(&payload_bytes).with_context(|| {
                format!(
                    "fixture '{}' payload is not an exact canonical Norito frame",
                    self.name
                )
            })?;
        let payload_bare = payload.encode();
        let payload_hash = blake2b256_hex(&payload_bytes);
        if payload_hash != self.payload_hash {
            bail!(
                "fixture '{}' payload hash mismatch (manifest={}, computed={})",
                self.name,
                self.payload_hash,
                payload_hash
            );
        }
        let signed_bytes = BASE64
            .decode(&self.signed_base64)
            .with_context(|| format!("fixture '{}' signed base64 invalid", self.name))?;
        let signed_len = usize::try_from(self.signed_len).map_err(|_| {
            eyre!(
                "fixture '{}' signed_len {} cannot be addressed on this platform",
                self.name,
                self.signed_len
            )
        })?;
        if signed_bytes.len() != signed_len {
            bail!(
                "fixture '{}' signed payload length mismatch (manifest={}, decoded={})",
                self.name,
                self.signed_len,
                signed_bytes.len()
            );
        }
        let signed = decode_canonical_signed_transaction(&signed_bytes)?;
        let signed_hash = hex_encode(signed.hash_as_entrypoint().as_ref());
        if signed_hash != self.signed_hash {
            bail!(
                "fixture '{}' signed hash mismatch (manifest={}, computed={})",
                self.name,
                self.signed_hash,
                signed_hash
            );
        }
        if signed.payload().encode() != payload_bare {
            bail!(
                "fixture '{}' signed payload differs from the canonical payload bytes",
                self.name
            );
        }
        let expected_network_id = parse_network_id(&self.network_id)
            .with_context(|| format!("fixture '{}' has invalid network_id", self.name))?;
        let actual_network_id = signed.network_id().copied().ok_or_else(|| {
            eyre!(
                "fixture '{}' signed payload uses the genesis-only transaction domain",
                self.name
            )
        })?;
        let actual_creation_time_ms =
            u64::try_from(signed.creation_time().as_millis()).map_err(|_| {
                eyre!(
                    "fixture '{}' creation_time_ms exceeds u64 in signed payload",
                    self.name
                )
            })?;
        let actual_ttl_ms = signed
            .time_to_live()
            .map(|ttl| u64::try_from(ttl.as_millis()))
            .transpose()
            .map_err(|_| {
                eyre!(
                    "fixture '{}' time_to_live_ms exceeds u64 in signed payload",
                    self.name
                )
            })?;
        let actual_nonce = signed.nonce().map(NonZeroU32::get);
        let actual_authority = signed.authority().to_string();
        if actual_network_id != expected_network_id
            || actual_authority != self.authority
            || actual_creation_time_ms != self.creation_time_ms
            || actual_ttl_ms != Some(self.time_to_live_ms)
            || actual_nonce != self.nonce
        {
            bail!(
                "fixture '{}' manifest summary differs from signed payload",
                self.name
            );
        }
        if let Some(dir) = base_dir {
            let path = dir.join(&self.encoded_file);
            let file_bytes =
                fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
            if file_bytes != payload_bytes {
                bail!(
                    "fixture '{}' encoded file '{}' differs from manifest payload",
                    self.name,
                    path.display()
                );
            }
        }
        Ok(())
    }
}
fn blake2b256_hex(bytes: &[u8]) -> String {
    let mut hasher = Blake2bVar::new(32).expect("32-byte BLAKE2b digest");
    blake2::digest::Update::update(&mut hasher, bytes);
    let mut out = [0_u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("finalize BLAKE2b digest");
    out[out.len() - 1] |= 1;
    hex_encode(out)
}
fn signed_transaction_entrypoint_hash_hex(
    canonical_framed_signed_transaction: &[u8],
) -> Result<String> {
    let signed = decode_canonical_signed_transaction(canonical_framed_signed_transaction)?;
    Ok(hex_encode(signed.hash_as_entrypoint().as_ref()))
}
fn decode_canonical_signed_transaction(
    canonical_framed_signed_transaction: &[u8],
) -> Result<SignedTransaction> {
    norito::decode_canonical(canonical_framed_signed_transaction)
        .map_err(|err| eyre!("invalid canonical framed SignedTransaction bytes: {err}"))
}
fn render_compact_hash_vector(fixtures: &[FixtureEntry]) -> Result<String> {
    let source = fixtures
        .iter()
        .find(|fixture| fixture.name == COMPACT_HASH_VECTOR_SOURCE)
        .ok_or_else(|| {
            eyre!(
                "compact hash vector source fixture '{}' is missing from the selected manifest",
                COMPACT_HASH_VECTOR_SOURCE
            )
        })?;
    source
        .validate(None)
        .context("compact hash vector source fixture failed validation")?;
    let framed = BASE64
        .decode(&source.signed_base64)
        .context("compact hash vector signed bytes are not valid base64")?;
    if BASE64.encode(&framed) != source.signed_base64 {
        bail!("compact hash vector signed bytes are not canonical base64");
    }
    let signed = decode_canonical_signed_transaction(&framed)?;
    let bare = signed.encode();
    let payload = signed.payload().encode();
    let mut canonical = 0_u32.to_le_bytes().to_vec();
    norito::core::write_len_to_vec(&mut canonical, payload.len() as u64);
    let prefix_len = canonical.len();
    canonical.extend_from_slice(&payload);
    let prefix = &canonical[..prefix_len];
    let (discriminant, compact_length) = prefix
        .split_at_checked(core::mem::size_of::<u32>())
        .ok_or_else(|| eyre!("compact entrypoint prefix is missing its discriminant"))?;
    if discriminant != 0_u32.to_le_bytes() {
        bail!("compact hash vector source is not the External transaction entrypoint");
    }
    if compact_length.is_empty() {
        bail!("compact entrypoint prefix is missing its canonical length");
    }
    if compact_length.len() != 2 {
        bail!(
            "compact hash vector source must exercise a two-byte length, got {} bytes",
            compact_length.len()
        );
    }
    let canonical_hash = blake2b256_hex(&canonical);
    if canonical_hash != source.signed_hash {
        bail!("compact hash vector does not match the manifest signed hash");
    }
    let payload_hash = blake2b256_hex(&payload);
    let mut versioned = Vec::with_capacity(1 + bare.len());
    versioned.push(SIGNED_TRANSACTION_V1);
    versioned.extend_from_slice(&bare);
    Ok(format!(
        concat!(
            "schema.version=2\n",
            "source.fixture={source_fixture}\n",
            "versioned.bytes={versioned_bytes}\n",
            "versioned.sha256={versioned_sha256}\n",
            "bare.bytes={bare_bytes}\n",
            "compact.length.hex={compact_length}\n",
            "canonical.prefix.hex={canonical_prefix}\n",
            "canonical.hash={canonical_hash}\n",
            "payload.prehash={payload_prehash}\n",
            "versioned.base64={versioned_base64}\n",
        ),
        source_fixture = source.name,
        versioned_bytes = versioned.len(),
        versioned_sha256 = hex_encode(Sha256::digest(&versioned)),
        bare_bytes = bare.len(),
        compact_length = hex_encode(compact_length),
        canonical_prefix = hex_encode(prefix),
        canonical_hash = canonical_hash,
        payload_prehash = payload_hash,
        versioned_base64 = BASE64.encode(versioned),
    ))
}
fn verify_compact_hash_vector(path: &Path, fixtures: &[FixtureEntry]) -> Result<()> {
    let expected = render_compact_hash_vector(fixtures)?;
    let actual = fs::read_to_string(path)
        .with_context(|| format!("failed to read compact hash vector {}", path.display()))?;
    if actual != expected {
        bail!(
            "compact hash vector {} is stale; regenerate Norito RPC fixtures",
            path.display()
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::asset::Mintable;
    use iroha_primitives::numeric::NumericSpec;
    use std::fs;
    const TEST_NETWORK_ID: &str =
        "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";
    fn checked_in_alias_setup_fixture() -> AliasSetupFixtureBytes {
        let path = workspace_root().join(ALIAS_SETUP_FIXTURE_V1);
        AliasSetupFixtureBytes::try_new(fs::read(&path).expect("read alias-setup fixture"))
            .expect("validate alias-setup fixture")
    }
    #[test]
    fn register_asset_definition_fixture_source_is_current_and_semantic() {
        let register = semantic_register_asset_definition().expect("semantic register source");
        assert_eq!(
            register.object().id.to_string(),
            "6pEP9RjNoZ7beWkT3pLfKoM1dyfi"
        );
        assert_eq!(register.object().name, "Rose Token");
        assert_eq!(register.object().spec, NumericSpec::default());
        assert_eq!(register.object().mintable, Mintable::Infinitely);
        assert_eq!(
            register.object().balance_scope_policy,
            AssetBalancePolicy::Global
        );
        assert!(register.object().owning_domain.is_none());
        let value = json::to_value(register.object()).expect("serialize semantic source");
        let object = value.as_object().expect("NewAssetDefinition JSON object");
        assert_eq!(object.get("owning_domain"), Some(&Value::Null));
        assert!(!object.contains_key("confidential_policy"));
    }
    #[test]
    fn register_semantic_owner_table_is_exact() {
        assert_eq!(
            SEMANTIC_INSTRUCTION_SOURCES,
            &[
                SemanticInstructionSource {
                    fixture_name: "mixed_executable_batch",
                    slot: InstructionSourceSlot::Batch(0),
                    wire_name: "iroha.register",
                },
                SemanticInstructionSource {
                    fixture_name: "mixed_executable_batch",
                    slot: InstructionSourceSlot::Batch(2),
                    wire_name: "iroha.register",
                },
                SemanticInstructionSource {
                    fixture_name: "register_asset_definition",
                    slot: InstructionSourceSlot::Instructions(0),
                    wire_name: "iroha.register",
                },
                SemanticInstructionSource {
                    fixture_name: "register_peer_with_pop_demo",
                    slot: InstructionSourceSlot::Instructions(0),
                    wire_name: "iroha.register",
                },
                SemanticInstructionSource {
                    fixture_name: "settlement_dvp_atomic",
                    slot: InstructionSourceSlot::Instructions(0),
                    wire_name: "iroha.settlement",
                },
                SemanticInstructionSource {
                    fixture_name: "settlement_pvp_net",
                    slot: InstructionSourceSlot::Instructions(0),
                    wire_name: "iroha.settlement",
                },
            ]
        );
        for fixture_name in [
            "register_role_demo",
            "register_nft_demo",
            "register_time_trigger_demo",
            "unknown_fixture",
        ] {
            validate_semantic_instruction_observations(fixture_name, &[])
                .expect("non-owned fixtures retain strict framed decoding");
        }
    }
    #[test]
    fn register_asset_definition_semantic_source_rejects_wrong_wire_or_ordinal() {
        let exact = [(InstructionSourceSlot::Instructions(0), "iroha.register")];
        validate_semantic_instruction_observations("register_asset_definition", &exact)
            .expect("exact source identity");
        for malformed in [
            Vec::new(),
            vec![(InstructionSourceSlot::Instructions(0), "iroha.transfer")],
            vec![(InstructionSourceSlot::Instructions(1), "iroha.register")],
            vec![
                (InstructionSourceSlot::Instructions(0), "iroha.register"),
                (InstructionSourceSlot::Instructions(1), "iroha.register"),
            ],
        ] {
            let _error =
                validate_semantic_instruction_observations("register_asset_definition", &malformed)
                    .expect_err("semantic source shape must fail closed");
        }
        let shifted_batch = [
            (InstructionSourceSlot::Batch(0), "iroha.register"),
            (InstructionSourceSlot::Batch(1), "iroha.register"),
        ];
        let _error =
            validate_semantic_instruction_observations("mixed_executable_batch", &shifted_batch)
                .expect_err("mixed-batch semantic instruction slots are exact");
    }
    #[test]
    fn generated_register_asset_definition_roundtrips_current_register_box() {
        let instruction: InstructionBox = semantic_register_asset_definition()
            .expect("semantic register source")
            .into();
        let type_name = Instruction::id(&*instruction).to_owned();
        let payload = Instruction::dyn_encode(&*instruction);
        let framed = frame_instruction_payload("iroha.register", &payload)
            .expect("frame instruction by canonical wire identifier");
        let decoded =
            decode_instruction_from_pair("iroha.register", &framed).expect("decode instruction");
        assert_eq!(Instruction::id(&*decoded), type_name);
        assert_eq!(Instruction::dyn_encode(&*decoded), payload);
    }
    #[test]
    fn register_peer_with_pop_fixture_source_is_current_and_semantic() {
        let register = semantic_register_peer_with_pop().expect("semantic peer source");
        assert_eq!(register.peer.public_key().algorithm(), Algorithm::BlsNormal);
        assert_eq!(register.pop.len(), 96);
        iroha_crypto::bls_normal_pop_verify(register.peer.public_key(), &register.pop)
            .expect("published peer and proof-of-possession agree");
        assert_eq!(register.activation_at, None);
        assert_eq!(register.expiry_at, None);
        let instruction: InstructionBox = register.into();
        let (wire_name, payload) =
            framed_instruction_payload(&instruction).expect("frame semantic peer");
        assert_eq!(wire_name, "iroha.register");
        let decoded = decode_instruction_from_pair(wire_name, &payload)
            .expect("current peer registration decodes without trailing fields");
        assert_eq!(decoded, instruction);
    }
    #[test]
    fn register_peer_with_pop_semantic_source_rejects_wrong_wire_or_ordinal() {
        let exact = [(InstructionSourceSlot::Instructions(0), "iroha.register")];
        validate_semantic_instruction_observations("register_peer_with_pop_demo", &exact)
            .expect("exact peer source identity");
        for malformed in [
            Vec::new(),
            vec![(InstructionSourceSlot::Instructions(0), "iroha.transfer")],
            vec![(InstructionSourceSlot::Instructions(1), "iroha.register")],
            vec![
                (InstructionSourceSlot::Instructions(0), "iroha.register"),
                (InstructionSourceSlot::Instructions(1), "iroha.register"),
            ],
        ] {
            let error = validate_semantic_instruction_observations(
                "register_peer_with_pop_demo",
                &malformed,
            )
            .expect_err("peer semantic source shape must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("semantic instruction shape mismatch")
            );
        }
    }
    #[test]
    fn fixture_export_rejects_type_name_fallback() {
        let registry = iroha_data_model::instruction_registry::default();
        let error = required_instruction_wire_id(&registry, "legacy::UnregisteredInstruction")
            .expect_err("an unregistered type must not become its own wire identifier");
        assert!(
            error
                .to_string()
                .contains("has no registered V1 wire identifier")
        );
    }
    fn sample_manifest() -> Manifest {
        Manifest {
            fixtures: vec![fixture("alpha"), fixture("beta"), fixture("gamma")],
        }
    }
    fn write_test_publication_seal(root: &Path) {
        let seal = root.join(CANONICAL_MANIFEST);
        fs::create_dir_all(seal.parent().expect("test seal parent"))
            .expect("create test seal parent");
        fs::write(seal, b"{\n  \"fixtures\": []\n}\n").expect("write test publication seal");
    }
    fn test_owned_publication_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("fixture.json"),
            PathBuf::from(CANONICAL_MANIFEST),
        ]
    }
    fn fixture(name: &str) -> FixtureEntry {
        FixtureEntry {
            name: name.to_string(),
            authority: "sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53".into(),
            network_id: TEST_NETWORK_ID.into(),
            creation_time_ms: 1_735_000_000_000,
            encoded_file: format!("{name}.norito"),
            encoded_len: 1,
            signed_len: 1,
            payload_base64: "AA==".into(),
            signed_base64: "AA==".into(),
            payload_hash: format!("payload-{name}"),
            signed_hash: format!("signed-{name}"),
            nonce: None,
            time_to_live_ms: 1,
        }
    }
    #[test]
    fn canonical_manifest_schema_is_closed_and_nonce_is_explicit() {
        let canonical = json::to_value(&sample_manifest()).expect("serialize sample manifest");
        validate_manifest_shape(&canonical).expect("canonical manifest shape");
        let mut unknown_root = canonical.clone();
        unknown_root
            .as_object_mut()
            .expect("manifest root object")
            .insert("legacy_schema".to_owned(), Value::Null);
        let error = validate_manifest_shape(&unknown_root)
            .expect_err("unknown manifest root fields must fail closed");
        assert!(error.to_string().contains("unknown field 'legacy_schema'"));
        let mut missing_nonce = canonical.clone();
        missing_nonce
            .as_object_mut()
            .and_then(|root| root.get_mut("fixtures"))
            .and_then(Value::as_array_mut)
            .and_then(|fixtures| fixtures.first_mut())
            .and_then(Value::as_object_mut)
            .expect("first manifest entry")
            .remove("nonce");
        let error = validate_manifest_shape(&missing_nonce)
            .expect_err("manifest nonce must be present even when null");
        assert!(error.to_string().contains("missing required field 'nonce'"));
        let mut legacy_chain = canonical.clone();
        legacy_chain
            .as_object_mut()
            .and_then(|root| root.get_mut("fixtures"))
            .and_then(Value::as_array_mut)
            .and_then(|fixtures| fixtures.first_mut())
            .and_then(Value::as_object_mut)
            .expect("first manifest entry")
            .insert("chain".to_owned(), Value::String("legacy".to_owned()));
        let error = validate_manifest_shape(&legacy_chain)
            .expect_err("the legacy manifest chain field must fail closed");
        assert!(error.to_string().contains("unknown field 'chain'"));
        let mut unknown_entry = canonical;
        unknown_entry
            .as_object_mut()
            .and_then(|root| root.get_mut("fixtures"))
            .and_then(Value::as_array_mut)
            .and_then(|fixtures| fixtures.first_mut())
            .and_then(Value::as_object_mut)
            .expect("first manifest entry")
            .insert("encoded".to_owned(), Value::String("legacy".to_owned()));
        let error = validate_manifest_shape(&unknown_entry)
            .expect_err("unknown manifest entry fields must fail closed");
        assert!(error.to_string().contains("unknown field 'encoded'"));
    }
    fn canonical_descriptor_fixture(name: &str) -> Value {
        let source = fs::read_to_string(workspace_root().join(CANONICAL_PAYLOADS))
            .expect("canonical payload descriptor");
        let descriptor: Value = json::from_str(&source).expect("canonical payload descriptor JSON");
        descriptor
            .as_array()
            .expect("fixture descriptor array")
            .iter()
            .find(|entry| {
                entry
                    .as_object()
                    .and_then(|object| object.get("name"))
                    .and_then(Value::as_str)
                    == Some(name)
            })
            .unwrap_or_else(|| panic!("canonical fixture {name:?}"))
            .clone()
    }
    #[test]
    fn mixed_batch_fixture_parser_preserves_item_order() {
        let mut instruction = Map::new();
        instruction.insert(
            "wire_name".to_owned(),
            Value::String("iroha.log".to_owned()),
        );
        instruction.insert(
            "payload_base64".to_owned(),
            Value::String("AA==".to_owned()),
        );
        let mut instruction_item = Map::new();
        instruction_item.insert("Instruction".to_owned(), Value::Object(instruction));
        let mut invocation = Map::new();
        invocation.insert(
            "contract_address".to_owned(),
            Value::String(
                "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh".to_owned(),
            ),
        );
        invocation.insert(
            "expected_code_hash".to_owned(),
            Value::String(
                "hash:0E5751C026E543B2E8AB2EB06099DAA1D1E5DF47778F7787FAAB45CDF12FE3A9#6A22"
                    .to_owned(),
            ),
        );
        invocation.insert("entrypoint".to_owned(), Value::String("run".to_owned()));
        invocation.insert("arguments".to_owned(), Value::Null);
        let mut contract_item = Map::new();
        contract_item.insert("ContractCall".to_owned(), Value::Object(invocation));
        let mut executable = Map::new();
        executable.insert(
            "Batch".to_owned(),
            Value::Array(vec![
                Value::Object(instruction_item),
                Value::Object(contract_item),
            ]),
        );
        let parsed = parse_executable(&Value::Object(executable)).expect("parse mixed batch");
        let RawExecutable::Batch(items) = parsed else {
            panic!("expected mixed batch");
        };
        assert!(matches!(items[0], RawBatchItem::Instruction(_)));
        assert!(matches!(items[1], RawBatchItem::ContractCall(_)));
    }
    #[test]
    fn mixed_batch_fixture_parser_rejects_empty_batch() {
        let mut executable = Map::new();
        executable.insert("Batch".to_owned(), Value::Array(Vec::new()));
        let Err(err) = parse_executable(&Value::Object(executable)) else {
            panic!("empty mixed batch must be rejected");
        };
        assert!(err.to_string().contains("at least one item"));
    }
    #[test]
    fn signed_hash_uses_compact_external_entrypoint_domain() {
        let keypair = signing_keypair().expect("fixture signing key");
        let signed = TransactionBuilder::new(
            parse_network_id(TEST_NETWORK_ID).expect("fixture network id"),
            AccountId::new(keypair.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .try_sign(keypair.private_key())
        .expect("sign fixture transaction");
        let signed_bytes =
            norito::encode_canonical(&signed).expect("encode canonical signed transaction frame");
        let payload_bytes = signed.payload().encode();
        let mut entrypoint = 0_u32.to_le_bytes().to_vec();
        norito::core::write_len_to_vec(&mut entrypoint, payload_bytes.len() as u64);
        entrypoint.extend_from_slice(&payload_bytes);
        assert_eq!(
            signed_transaction_entrypoint_hash_hex(&signed_bytes)
                .expect("hash canonical signed transaction"),
            blake2b256_hex(&entrypoint)
        );
        assert_ne!(
            signed_transaction_entrypoint_hash_hex(&signed_bytes)
                .expect("hash canonical signed transaction"),
            blake2b256_hex(&signed_bytes)
        );
    }
    #[test]
    fn compact_hash_vector_is_descriptor_owned_and_deterministic() {
        let root = workspace_root();
        let manifest =
            Manifest::load(&root.join(CANONICAL_MANIFEST)).expect("canonical manifest loads");
        let first = render_compact_hash_vector(&manifest.fixtures).expect("render compact vector");
        let second = render_compact_hash_vector(&manifest.fixtures).expect("render compact vector");
        assert_eq!(
            first, second,
            "compact vector rendering must be deterministic"
        );
        assert_eq!(
            fs::read_to_string(
                root.join("fixtures/norito_rpc")
                    .join(COMPACT_HASH_VECTOR_BASENAME)
            )
            .expect("read checked-in compact vector"),
            first,
            "checked-in compact vector must be generated from the canonical manifest"
        );
        let properties: BTreeMap<_, _> = first
            .lines()
            .map(|line| line.split_once('=').expect("generated property"))
            .collect();
        assert_eq!(properties["schema.version"], "2");
        assert_eq!(properties["source.fixture"], COMPACT_HASH_VECTOR_SOURCE);
        assert_eq!(
            properties["versioned.bytes"]
                .parse::<usize>()
                .expect("versioned byte count"),
            properties["bare.bytes"]
                .parse::<usize>()
                .expect("bare byte count")
                + 1
        );
        assert_eq!(
            properties["canonical.prefix.hex"],
            format!("00000000{}", properties["compact.length.hex"])
        );
        assert_eq!(properties["versioned.bytes"], "619");
        assert_eq!(
            properties["versioned.sha256"],
            "f8a4e12f40d0d5d92d74a032a4b782b6b3361363a1a313161f2336b68006087f"
        );
        assert_eq!(properties["bare.bytes"], "618");
        assert_eq!(properties["compact.length.hex"], "da03");
        assert_eq!(properties["canonical.prefix.hex"], "00000000da03");
        assert_eq!(
            properties["canonical.hash"],
            "76ca8143ab4fc3697dd755576ceb33c82086af30d69d77b030f9817a8e9c2fc3"
        );
        assert_eq!(
            properties["payload.prehash"],
            "36b2c7537acc2c100743039539ed28612e5f34e1ecf6df2e2afb4ad55fcebe43"
        );
    }
    #[test]
    fn compact_hash_vector_requires_the_canonical_source_fixture() {
        let error = render_compact_hash_vector(&sample_manifest().fixtures)
            .expect_err("missing canonical source fixture must fail closed");
        assert!(
            error.to_string().contains(COMPACT_HASH_VECTOR_SOURCE),
            "error must identify the missing source fixture: {error}"
        );
    }
    #[test]
    fn manifest_validation_rejects_duplicate_fixture_names() {
        let manifest = Manifest {
            fixtures: vec![fixture("alpha"), fixture("alpha")],
        };
        let err = manifest
            .validate(None)
            .expect_err("duplicate fixture names must fail closed");
        assert!(
            err.to_string().contains("duplicate fixture name 'alpha'"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn manifest_validation_rejects_noncanonical_encoded_file() {
        let mut entry = fixture("alpha");
        entry.encoded_file = "renamed.norito".into();
        let manifest = Manifest {
            fixtures: vec![entry],
        };
        let err = manifest
            .validate(None)
            .expect_err("renamed encoded files must fail closed");
        assert!(
            err.to_string()
                .contains("encoded_file must be exactly 'alpha.norito'"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn fixture_names_reject_path_and_nonportable_forms() {
        for name in [
            "",
            "../escape",
            "/absolute",
            "nested/name",
            "nested\\name",
            "Upper",
        ] {
            let error = validate_fixture_name(name)
                .expect_err("nonportable fixture names must fail closed");
            assert!(
                error.to_string().contains("fixture name"),
                "unexpected error for {name:?}: {error}"
            );
        }
        for name in ["alpha", "0-alpha", "typed_fee_payment_gas_limit"] {
            validate_fixture_name(name).expect("portable fixture name");
        }
    }
    #[test]
    fn fixture_output_root_must_be_absolute_and_outside_workspace() {
        let relative_error =
            match FixtureOptions::new(Some(PathBuf::from("norito-stage"))).resolve_paths() {
                Ok(_) => panic!("relative publication root must fail closed"),
                Err(error) => error,
            };
        assert!(
            relative_error.to_string().contains("absolute and external"),
            "unexpected relative-root error: {relative_error}"
        );

        let source_root = workspace_root()
            .canonicalize()
            .expect("canonical source workspace");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock follows Unix epoch")
            .as_nanos();
        let inside = source_root.join(format!(".norito-rpc-forbidden-{unique}"));
        assert!(!inside.exists(), "test output path must begin absent");
        let inside_error = match FixtureOptions::new(Some(inside)).resolve_paths() {
            Ok(_) => panic!("in-workspace publication root must fail closed"),
            Err(error) => error,
        };
        assert!(
            inside_error
                .to_string()
                .contains("outside the source workspace"),
            "unexpected in-workspace error: {inside_error}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn local_fixture_mode_is_confined_to_private_target_lane() {
        use std::{io::ErrorKind, os::unix::fs::DirBuilderExt as _};

        let source_root = workspace_root().canonicalize().expect("workspace root");
        let target = source_root.join("target");
        match fs::symlink_metadata(&target) {
            Ok(metadata) => assert!(metadata.is_dir() && !metadata.file_type().is_symlink()),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                fs::create_dir(&target).expect("create ignored target directory");
            }
            Err(error) => panic!("inspect target directory: {error}"),
        }
        reject_symlink_components(&target).expect("target ancestors are not symbolic");
        let parent = source_root.join(LOCAL_INTEGRATION_PARENT);
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&parent) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create local fixture parent: {error}"),
        }
        let output = parent.join("absent-fixture-publication-test");
        assert!(
            !output.exists(),
            "local publication test root must be absent"
        );
        let resolved = FixtureOptions::local_integration(output.clone())
            .resolve_paths()
            .expect("private fixed target lane is allowed locally");
        assert_eq!(resolved.output_root, output);
        assert_eq!(
            resolved.local_render_parent.as_deref(),
            Some(parent.as_path())
        );
        let identity = resolved
            .local_parent_identity
            .expect("local parent identity");
        require_local_render_parent(&parent, identity).expect("unchanged parent remains private");
        let rendered = create_render_tree(Some(&parent)).expect("repo-local render tree");
        assert!(rendered.path().starts_with(&parent));
        let existing_error = match FixtureOptions::local_integration(rendered.path().to_path_buf())
            .resolve_paths()
        {
            Ok(_) => panic!("local mode must refuse an existing destination"),
            Err(error) => error,
        };
        assert!(existing_error.to_string().contains("already exists"));

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock follows Unix epoch")
            .as_nanos();
        let alias = target.join(format!("norito-rpc-local-alias-{unique}"));
        std::os::unix::fs::symlink(&parent, &alias).expect("create in-target test symlink");
        let alias_error =
            match FixtureOptions::local_integration(alias.join("absent")).resolve_paths() {
                Ok(_) => panic!("local mode must refuse a symbolic parent"),
                Err(error) => error,
            };
        assert!(
            alias_error
                .to_string()
                .contains("must not traverse a symlink")
        );
        fs::remove_file(&alias).expect("remove in-target test symlink");

        let external_error = match FixtureOptions::new(Some(output)).resolve_paths() {
            Ok(_) => panic!("external release mode must still refuse this workspace"),
            Err(error) => error,
        };
        assert!(
            external_error
                .to_string()
                .contains("outside the source workspace")
        );
        let wrong_lane = target.join("absent-norito-rpc-publication-test");
        let wrong_error = match FixtureOptions::local_integration(wrong_lane).resolve_paths() {
            Ok(_) => panic!("local mode must not accept an arbitrary target child"),
            Err(error) => error,
        };
        assert!(wrong_error.to_string().contains("direct child"));
        let wrong_identity = capture_directory_identity(&target).expect("target identity");
        assert!(require_local_render_parent(&parent, wrong_identity).is_err());
    }
    #[test]
    fn publication_path_policy_rejects_case_and_unicode_alias_classes() {
        assert_eq!(
            publication_path_identity(
                &normalize_publication_path(Path::new("SDK/File.json")).unwrap()
            ),
            publication_path_identity(
                &normalize_publication_path(Path::new("sdk/file.json")).unwrap()
            ),
        );
        assert!(normalize_publication_path(Path::new("fixtures/cafe\u{301}.json")).is_err());
        let root = tempdir().expect("publication root");
        let error = PublicationSnapshot::capture(
            root.path(),
            &[
                PathBuf::from("SDK/File.json"),
                PathBuf::from("sdk/file.json"),
            ],
        )
        .expect_err("case-equivalent publication identities must fail closed");
        assert!(
            error
                .to_string()
                .contains("duplicate publication logical identity")
        );
        let error = PublicationSnapshot::capture(
            root.path(),
            &[PathBuf::from("SDK"), PathBuf::from("sdk/file.json")],
        )
        .expect_err("case-equivalent file/directory identities must fail closed");
        assert!(error.to_string().contains("both a file and a directory"));
    }
    #[test]
    fn create_only_publication_cannot_clobber_a_racing_directory() {
        let rendered = tempdir().expect("rendered publication");
        let owned = test_owned_publication_paths();
        fs::write(rendered.path().join("fixture.json"), b"rendered").expect("write rendered file");
        write_test_publication_seal(rendered.path());
        normalize_rendered_modes(rendered.path(), &owned).expect("normalize rendered modes");
        let snapshot = PublicationSnapshot::capture(rendered.path(), &owned)
            .expect("capture rendered snapshot");
        let parent = tempdir().expect("destination parent");
        let destination = parent.path().join("publication");
        fs::create_dir(&destination).expect("simulate racing directory reservation");
        fs::write(destination.join("owner-marker"), b"not ours")
            .expect("write competing owner marker");
        let error = publish_create_only_publication(&snapshot, &destination, &owned, || Ok(()))
            .expect_err("an existing racing directory must not be replaced");
        assert!(
            error
                .to_string()
                .contains("already exists or cannot be reserved")
        );
        assert_eq!(
            fs::read(destination.join("owner-marker")).expect("competing marker remains"),
            b"not ours"
        );
        assert!(!destination.join("fixture.json").exists());
    }
    #[test]
    fn create_only_publication_commits_exact_tree_with_manifest_seal_last() {
        let rendered = tempdir().expect("rendered publication");
        let owned = test_owned_publication_paths();
        fs::write(rendered.path().join("fixture.json"), b"rendered").expect("write rendered file");
        write_test_publication_seal(rendered.path());
        normalize_rendered_modes(rendered.path(), &owned).expect("normalize rendered modes");
        let expected = PublicationSnapshot::capture(rendered.path(), &owned)
            .expect("capture rendered snapshot");
        let parent = tempdir().expect("destination parent");
        let destination = parent.path().join("publication");
        let validation_calls = std::cell::Cell::new(0_u8);

        publish_create_only_publication(&expected, &destination, &owned, || {
            validation_calls.set(validation_calls.get() + 1);
            assert!(destination.is_dir());
            assert_eq!(
                fs::read(destination.join("fixture.json")).expect("read unsealed fixture"),
                b"rendered"
            );
            assert!(
                !destination.join(CANONICAL_MANIFEST).exists(),
                "pre-seal validation must observe an incomplete publication"
            );
            Ok(())
        })
        .expect("publish exact create-only fixture tree");

        assert_eq!(validation_calls.get(), 1);
        require_publication_seal(&destination).expect("final manifest seals publication");
        let published = PublicationSnapshot::capture_complete_tree(&destination)
            .expect("capture complete publication");
        expected
            .require_identical(&published)
            .expect("published tree remains byte-, path-, type-, and mode-exact");
        assert!(
            !parent
                .path()
                .join(format!(".publication{PUBLICATION_SEAL_PENDING_SUFFIX}"))
                .exists(),
            "seal staging link must be retired at the commit point"
        );
    }
    #[test]
    fn create_only_publication_leaves_unsealed_residue_after_failed_validation() {
        let rendered = tempdir().expect("rendered publication");
        let owned = test_owned_publication_paths();
        fs::write(rendered.path().join("fixture.json"), b"rendered").expect("write rendered file");
        write_test_publication_seal(rendered.path());
        normalize_rendered_modes(rendered.path(), &owned).expect("normalize rendered modes");
        let snapshot = PublicationSnapshot::capture(rendered.path(), &owned)
            .expect("capture rendered snapshot");
        let parent = tempdir().expect("destination parent");
        let destination = parent.path().join("publication");
        let error = publish_create_only_publication(&snapshot, &destination, &owned, || {
            bail!("injected pre-seal validation failure")
        })
        .expect_err("validation failure must abort publication");
        assert!(
            error
                .to_string()
                .contains("rejected reservation was left in place")
        );
        assert!(
            destination.is_dir(),
            "failure residue must remain reserved instead of risking deletion of a concurrent replacement"
        );
        assert_eq!(
            fs::read(destination.join("fixture.json"))
                .expect("rejected output remains inspectable"),
            b"rendered"
        );
        assert!(
            !destination.join(CANONICAL_MANIFEST).exists(),
            "failed pre-seal validation must not leave a completion seal"
        );
        let _ = require_publication_seal(&destination)
            .expect_err("failed publication residue must remain unsealed");
    }
    #[test]
    fn publication_without_final_manifest_seal_is_rejected() {
        let publication = tempdir().expect("partial publication");
        fs::create_dir_all(publication.path().join(CANONICAL_FIXTURE_DIRECTORY))
            .expect("create partial publication directory");
        fs::write(publication.path().join("fixture.json"), b"partial")
            .expect("write partial fixture");
        let error = require_publication_seal(publication.path())
            .expect_err("a partial publication without its final seal must fail closed");
        assert!(format!("{error:?}").contains("canonical manifest seal is missing"));
    }
    #[cfg(unix)]
    #[test]
    fn tracked_publication_rejects_wrong_modes_hard_links_and_symlinks() {
        let rendered = tempdir().expect("rendered publication");
        let tracked = tempdir().expect("tracked publication");
        let owned = test_owned_publication_paths();
        fs::write(rendered.path().join("fixture.json"), b"fixture")
            .expect("write rendered fixture");
        fs::write(tracked.path().join("fixture.json"), b"fixture").expect("write tracked fixture");
        write_test_publication_seal(rendered.path());
        write_test_publication_seal(tracked.path());
        normalize_rendered_modes(rendered.path(), &owned).expect("normalize rendered modes");
        normalize_rendered_modes(tracked.path(), &owned).expect("normalize tracked modes");
        compare_owned_publication(rendered.path(), tracked.path(), &owned)
            .expect("canonical tracked fixture");

        fs::set_permissions(
            tracked.path().join("fixture.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("set wrong tracked mode");
        let error = compare_owned_publication(rendered.path(), tracked.path(), &owned)
            .expect_err("wrong tracked mode must fail closed");
        assert!(format!("{error:?}").contains("canonical mode 0644"));

        set_canonical_file_mode(&tracked.path().join("fixture.json"))
            .expect("restore canonical mode");
        fs::hard_link(
            tracked.path().join("fixture.json"),
            tracked.path().join("fixture-hard-link.json"),
        )
        .expect("create tracked hard link");
        let error = compare_owned_publication(rendered.path(), tracked.path(), &owned)
            .expect_err("hard-linked tracked fixture must fail closed");
        assert!(format!("{error:?}").contains("must not be hard-linked"));

        fs::remove_file(tracked.path().join("fixture-hard-link.json"))
            .expect("remove test hard link");
        fs::remove_file(tracked.path().join("fixture.json")).expect("remove tracked fixture");
        std::os::unix::fs::symlink(
            rendered.path().join("fixture.json"),
            tracked.path().join("fixture.json"),
        )
        .expect("create tracked symlink");
        let error = compare_owned_publication(rendered.path(), tracked.path(), &owned)
            .expect_err("symlinked tracked fixture must fail closed");
        assert!(format!("{error:?}").contains("contains a symlink"));
    }
    #[test]
    fn manifest_validation_rejects_renamed_cloned_payloads() {
        let first = fixture("alpha");
        let mut second = fixture("beta");
        second.payload_hash = first.payload_hash.clone();
        second.payload_base64 = first.payload_base64.clone();
        second.signed_hash = first.signed_hash.clone();
        second.signed_base64 = first.signed_base64.clone();
        let manifest = Manifest {
            fixtures: vec![first, second],
        };
        let err = manifest
            .validate(None)
            .expect_err("renamed cloned fixture payloads must fail closed");
        assert!(
            err.to_string()
                .contains("duplicate fixture payload_hash 'payload-alpha'"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn manifest_validation_rejects_noncanonical_base64() {
        for malformed in ["YQ!!", "Y Q==", "YQ=", "YQ===", "YR=="] {
            let mut entry = fixture("alpha");
            entry.payload_base64 = malformed.to_string();
            let manifest = Manifest {
                fixtures: vec![entry],
            };
            let err = manifest
                .validate(None)
                .expect_err("invalid or non-canonical base64 must fail closed");
            let message = err.to_string();
            assert!(
                message.contains("base64 invalid") || message.contains("base64 is non-canonical"),
                "unexpected error for {malformed:?}: {err}"
            );
        }
    }
    #[test]
    fn schema_targets_are_sorted_and_unique() {
        let targets = schema_targets();
        assert!(
            !targets.is_empty(),
            "expected schema target list to be non-empty"
        );
        for pair in targets.windows(2) {
            assert!(
                pair[0].alias <= pair[1].alias,
                "schema targets must be sorted by alias"
            );
        }
        let mut seen = HashSet::new();
        for target in &targets {
            assert!(
                seen.insert(&target.type_name),
                "duplicate schema target `{}` detected",
                target.type_name
            );
        }
    }
    #[test]
    fn schema_targets_exclude_retired_sns_mutation_requests() {
        let aliases = schema_targets()
            .into_iter()
            .map(|target| target.alias)
            .collect::<HashSet<_>>();
        for retired in [
            "FreezeNameRequestV1",
            "GovernanceHookV1",
            "PaymentProofV1",
            "RegisterNameRequestV1",
            "RegisterNameResponseV1",
            "RenewNameRequestV1",
            "ReservedAssignmentRequestV1",
            "TransferNameRequestV1",
            "UpdateControllersRequestV1",
        ] {
            assert!(
                !aliases.contains(retired),
                "retired SNS mutation schema `{retired}` must not be advertised"
            );
        }
    }
    #[test]
    fn schema_manifest_round_trip_validates() {
        let manifest = SchemaHashManifest::new_current();
        manifest.validate().expect("generated manifest validates");
    }
    #[test]
    fn schema_manifest_generation_is_deterministic() {
        let first =
            json::to_json_pretty(&SchemaHashManifest::new_current()).expect("serialize manifest");
        let second =
            json::to_json_pretty(&SchemaHashManifest::new_current()).expect("serialize manifest");
        assert_eq!(first, second);
        assert!(
            !first.contains("generated_at"),
            "checked-in schema manifests must not contain wall-clock state"
        );
    }
    #[test]
    fn schema_hash_hex_round_trip() {
        let target_binding = schema_targets();
        let target = target_binding.first().expect("at least one schema target");
        let encoded = format_schema_hash(target.schema_hash);
        let decoded = parse_schema_hash_hex(&encoded).expect("decode succeeds");
        assert_eq!(decoded, target.schema_hash);
    }
    #[test]
    fn workspace_root_points_to_repository() {
        let root = workspace_root();
        assert!(root.join("Cargo.toml").is_file());
        assert!(root.join("xtask/Cargo.toml").is_file());
        assert!(root.join(CANONICAL_MANIFEST).is_file());
    }
    #[test]
    fn json_report_writer_creates_parent_directory() {
        let temp_dir = tempdir().expect("temp dir");
        let output = temp_dir.path().join("nested/report.json");
        let value = Value::String("fixture-report".to_owned());
        write_json_output(&value, JsonOutput::File(output.clone())).expect("write JSON report");
        assert_eq!(
            fs::read_to_string(output).expect("read JSON report"),
            "\"fixture-report\"\n"
        );
    }
    #[test]
    fn generated_transaction_fixture_uses_checked_signing() {
        let keypair = signing_keypair().expect("checked signing keypair");
        let account_id = AccountId::new(keypair.public_key().clone());
        let raw = RawPayloadFixture {
            name: "checked-signing".to_string(),
            payload: RawPayload {
                network_id: TEST_NETWORK_ID.to_string(),
                authority: account_id.to_string(),
                creation_time_ms: 1_735_000_000_000,
                executable: RawExecutable::Instructions(Vec::new()),
                ttl_ms: 60_000,
                nonce: Some(1),
                fee_payment: FeePaymentIntent::authority(Vec::new(), None),

                metadata: Vec::new(),
            },
            payload_json: Value::Null,
            network_id_hint: TEST_NETWORK_ID.to_owned(),
            authority_hint: account_id.to_string(),
            creation_time_ms_hint: 1_735_000_000_000,
            ttl_ms_hint: 60_000,
            nonce_hint: Some(1),
        };
        let fixture = raw
            .generate_fixture(&keypair)
            .expect("generate checked signed fixture");
        assert!(fixture.payload_bytes.starts_with(b"NRT0"));
        let payload: TransactionPayload = norito::decode_canonical(&fixture.payload_bytes)
            .expect("decode checked payload fixture frame");
        assert!(norito::decode_canonical::<TransactionPayload>(&payload.encode()).is_err());
        assert_eq!(
            fixture.summary.payload_hash_hex,
            blake2b256_hex(&fixture.payload_bytes),
            "payload_hash authenticates the published framed bytes"
        );
        let signed = decode_canonical_signed_transaction(&fixture.signed_bytes)
            .expect("decode checked signed fixture frame");
        assert!(fixture.signed_bytes.starts_with(b"NRT0"));
        assert!(norito::decode_canonical::<SignedTransaction>(&signed.encode()).is_err());
        signed
            .verify_signature()
            .expect("checked fixture transaction signature verifies");
    }
    #[test]
    fn raw_payload_rejects_invalid_network_id() {
        let payload = RawPayload {
            network_id: String::new(),
            authority: String::new(),
            creation_time_ms: 0,
            executable: RawExecutable::Instructions(Vec::new()),
            ttl_ms: 1,
            nonce: None,
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),

            metadata: Vec::new(),
        };
        let error = payload
            .to_builder("invalid-network-id")
            .expect_err("an empty network id must be rejected");
        assert!(
            error
                .to_string()
                .contains("invalid canonical network id ''"),
            "unexpected network id error: {error}"
        );
    }
    #[test]
    fn network_id_parser_requires_exact_canonical_hash_encoding() {
        let parsed = parse_network_id(TEST_NETWORK_ID).expect("canonical network id");
        assert_eq!(
            json::to_value(&parsed).expect("render canonical network id"),
            Value::String(TEST_NETWORK_ID.to_owned())
        );
        for rejected in [
            TEST_NETWORK_ID.to_ascii_lowercase(),
            TEST_NETWORK_ID[5..69].to_owned(),
            TEST_NETWORK_ID.replace("#A2F0", "#0000"),
        ] {
            assert!(
                parse_network_id(&rejected).is_err(),
                "non-canonical network id '{rejected}' must fail closed"
            );
        }
    }
    #[test]
    fn payload_ttl_is_required_and_nonzero() {
        for value in [None, Some(Value::Null), Some(Value::from(0_u64))] {
            let mut object = Map::new();
            if let Some(value) = value {
                object.insert("time_to_live_ms".to_owned(), value);
            }
            let error = expect_nonzero_u64(&object, "time_to_live_ms")
                .expect_err("missing, null, and zero lifetimes must be rejected");
            assert!(
                error.to_string().contains("time_to_live_ms"),
                "unexpected lifetime error: {error}"
            );
        }
        let mut object = Map::new();
        object.insert("time_to_live_ms".to_owned(), Value::from(100_000_u64));
        assert_eq!(
            expect_nonzero_u64(&object, "time_to_live_ms").expect("positive lifetime"),
            100_000
        );
    }
    #[test]
    fn payload_descriptor_rejects_the_encoded_alias() {
        let mut fixture = canonical_descriptor_fixture("typed_fee_payment_gas_limit");
        let entry = fixture
            .as_object_mut()
            .expect("typed runtime fixture descriptor");
        entry.remove("encoded");
        parse_payload_fixture(&Value::Object(entry.clone()))
            .expect("canonical fields without alias parse");
        let encoded = entry
            .get("payload_base64")
            .expect("canonical payload_base64")
            .clone();
        entry.insert("encoded".to_owned(), encoded);
        let Err(error) = parse_payload_fixture(&Value::Object(entry.clone())) else {
            panic!("encoded alias must be rejected");
        };
        assert!(
            error.to_string().contains("unknown field 'encoded'"),
            "unexpected alias error: {error}"
        );
    }
    #[test]
    fn payload_descriptor_requires_exact_top_level_and_payload_fields() {
        let mut fixture = canonical_descriptor_fixture("typed_fee_payment_gas_limit");
        let entry = fixture
            .as_object_mut()
            .expect("fixture descriptor entry is an object");
        entry.remove("encoded");
        let mut unknown_top_level = entry.clone();
        unknown_top_level.insert("legacy_hint".to_owned(), Value::Null);
        let Err(error) = parse_payload_fixture(&Value::Object(unknown_top_level)) else {
            panic!("unknown top-level fields must fail closed");
        };
        assert!(error.to_string().contains("unknown field 'legacy_hint'"));
        let mut missing_top_level = entry.clone();
        missing_top_level.remove("network_id");
        let Err(error) = parse_payload_fixture(&Value::Object(missing_top_level)) else {
            panic!("missing top-level identity fields must fail closed");
        };
        assert!(
            error
                .to_string()
                .contains("missing required field 'network_id'")
        );
        let mut legacy_top_level = entry.clone();
        legacy_top_level.insert("chain".to_owned(), Value::String("legacy".to_owned()));
        let Err(error) = parse_payload_fixture(&Value::Object(legacy_top_level)) else {
            panic!("the legacy top-level chain field must fail closed");
        };
        assert!(error.to_string().contains("unknown field 'chain'"));
        let mut unknown_payload = entry
            .get("payload")
            .and_then(Value::as_object)
            .expect("nested payload object")
            .clone();
        unknown_payload.insert("legacy_metadata".to_owned(), Value::Null);
        let Err(error) = parse_payload(&Value::Object(unknown_payload)) else {
            panic!("unknown payload fields must fail closed");
        };
        assert!(
            error
                .to_string()
                .contains("unknown field 'legacy_metadata'")
        );
        let mut legacy_payload = entry
            .get("payload")
            .and_then(Value::as_object)
            .expect("nested payload object")
            .clone();
        legacy_payload.insert("chain".to_owned(), Value::String("legacy".to_owned()));
        let Err(error) = parse_payload(&Value::Object(legacy_payload)) else {
            panic!("the legacy payload chain field must fail closed");
        };
        assert!(error.to_string().contains("unknown field 'chain'"));
        let mut missing_payload = entry
            .get("payload")
            .and_then(Value::as_object)
            .expect("nested payload object")
            .clone();
        missing_payload.remove("metadata");
        let Err(error) = parse_payload(&Value::Object(missing_payload)) else {
            panic!("metadata must be explicit");
        };
        assert!(
            error
                .to_string()
                .contains("missing required field 'metadata'")
        );
        for field in ["admission_intent", "admissionIntent"] {
            for label in ["ordinary", "queue_plan_synced"] {
                let mut retired = entry
                    .get("payload")
                    .and_then(Value::as_object)
                    .expect("nested payload object")
                    .clone();
                retired.insert(
                    field.to_owned(),
                    norito::json!({"intent": label, "value": null}),
                );
                let error = parse_payload(&Value::Object(retired))
                    .err()
                    .expect("retired admission field must fail closed");
                assert!(error.to_string().contains(field), "{error}");
            }
        }
    }
    #[test]
    fn executable_and_instruction_objects_are_closed_and_unambiguous() {
        let mut ambiguous = Map::new();
        ambiguous.insert("Ivm".to_owned(), Value::String("AA==".to_owned()));
        ambiguous.insert("Instructions".to_owned(), Value::Array(Vec::new()));
        let Err(error) = parse_executable(&Value::Object(ambiguous)) else {
            panic!("multiple executable variants must fail closed");
        };
        assert!(error.to_string().contains("exactly one variant"));
        let mut unknown = Map::new();
        unknown.insert("Legacy".to_owned(), Value::Null);
        let Err(error) = parse_executable(&Value::Object(unknown)) else {
            panic!("unknown executable variants must fail closed");
        };
        assert!(
            error
                .to_string()
                .contains("unknown executable variant 'Legacy'")
        );
        let mut instruction = Map::new();
        instruction.insert(
            "wire_name".to_owned(),
            Value::String("iroha.log".to_owned()),
        );
        instruction.insert(
            "payload_base64".to_owned(),
            Value::String("AA==".to_owned()),
        );
        instruction.insert("kind".to_owned(), Value::String("legacy".to_owned()));
        let Err(error) = parse_instruction(&Value::Object(instruction)) else {
            panic!("unknown instruction fields must fail closed");
        };
        assert!(error.to_string().contains("unknown field 'kind'"));
    }
    #[test]
    fn direct_contract_call_is_supported_and_requires_signed_gas() {
        let fixture = canonical_descriptor_fixture("mixed_executable_batch");
        let mut payload = fixture
            .as_object()
            .and_then(|object| object.get("payload"))
            .expect("mixed fixture payload")
            .clone();
        let invocation = payload
            .as_object()
            .and_then(|object| object.get("executable"))
            .and_then(Value::as_object)
            .and_then(|object| object.get("Batch"))
            .and_then(Value::as_array)
            .and_then(|items| items.get(1))
            .and_then(Value::as_object)
            .and_then(|item| item.get("ContractCall"))
            .expect("mixed fixture contract call")
            .clone();
        let mut unknown_invocation = invocation.clone();
        unknown_invocation
            .as_object_mut()
            .expect("contract invocation object")
            .insert("legacy_gas_limit".to_owned(), Value::from(1_u64));
        let mut unknown_executable = Map::new();
        unknown_executable.insert("ContractCall".to_owned(), unknown_invocation);
        let error = parse_executable(&Value::Object(unknown_executable))
            .err()
            .expect("unknown ContractCall fields must fail closed");
        assert!(
            error
                .to_string()
                .contains("unknown field 'legacy_gas_limit'")
        );
        let mut missing_invocation = invocation.clone();
        missing_invocation
            .as_object_mut()
            .expect("contract invocation object")
            .remove("arguments");
        let mut missing_executable = Map::new();
        missing_executable.insert("ContractCall".to_owned(), missing_invocation);
        let error = parse_executable(&Value::Object(missing_executable))
            .err()
            .expect("every ContractCall field must be explicit");
        assert!(
            error
                .to_string()
                .contains("missing required field 'arguments'")
        );
        let mut executable = Map::new();
        executable.insert("ContractCall".to_owned(), invocation);
        payload
            .as_object_mut()
            .expect("payload object")
            .insert("executable".to_owned(), Value::Object(executable));
        let parsed = parse_payload(&payload).expect("direct contract call fixture parses");
        assert!(matches!(parsed.executable, RawExecutable::ContractCall(_)));
        assert!(parsed.executable.requires_transaction_gas_limit());
        payload
            .as_object_mut()
            .and_then(|object| object.get_mut("fee_payment"))
            .and_then(Value::as_object_mut)
            .and_then(|object| object.get_mut("value"))
            .and_then(Value::as_object_mut)
            .expect("authority fee payment")
            .remove("gas_limit");
        let Err(error) = parse_payload(&payload) else {
            panic!("direct contract calls without the required gas field must fail closed");
        };
        assert!(
            error.to_string().contains("gas_limit"),
            "unexpected missing-gas error: {error}"
        );
    }
    #[test]
    fn runtime_executable_fixtures_require_signed_gas_bounds() {
        for name in ["typed_fee_payment_gas_limit", "mixed_executable_batch"] {
            let fixture = canonical_descriptor_fixture(name);
            let mut payload = fixture
                .as_object()
                .and_then(|object| object.get("payload"))
                .expect("fixture payload")
                .clone();
            payload
                .as_object_mut()
                .and_then(|object| object.get_mut("fee_payment"))
                .and_then(Value::as_object_mut)
                .and_then(|object| object.get_mut("value"))
                .and_then(Value::as_object_mut)
                .expect("authority fee payment")
                .remove("gas_limit");
            let Err(error) = parse_payload(&payload) else {
                panic!("runtime fixture {name:?} without gas_limit must be rejected");
            };
            assert!(
                error.to_string().contains("gas_limit"),
                "unexpected gas-bound error for {name:?}: {error}"
            );
        }
    }
    #[test]
    fn canonical_runtime_fixture_is_active_and_exactly_gas_bounded() {
        let source = fs::read_to_string(workspace_root().join(CANONICAL_PAYLOADS))
            .expect("canonical payload descriptor");
        let descriptor: Value = json::from_str(&source).expect("canonical payload descriptor JSON");
        assert!(
            descriptor
                .as_array()
                .expect("fixture descriptor array")
                .iter()
                .all(|entry| {
                    entry
                        .as_object()
                        .and_then(|object| object.get("name"))
                        .and_then(Value::as_str)
                        != Some("ivm_transfer")
                }),
            "the gasless compatibility-only ivm_transfer fixture must be absent"
        );
        let fixture = canonical_descriptor_fixture("typed_fee_payment_gas_limit");
        let payload = fixture
            .as_object()
            .and_then(|object| object.get("payload"))
            .and_then(Value::as_object)
            .expect("typed runtime payload");
        assert!(
            payload
                .get("executable")
                .and_then(Value::as_object)
                .is_some_and(|object| object.contains_key("Ivm")),
            "typed fee-payment fixture must exercise IVM admission"
        );
        let fee_payment = payload
            .get("fee_payment")
            .and_then(Value::as_object)
            .expect("typed authority fee payment");
        assert_eq!(
            fee_payment.get("payer").and_then(Value::as_str),
            Some("authority")
        );
        let payment = fee_payment
            .get("value")
            .and_then(Value::as_object)
            .expect("typed fee payment value");
        assert_eq!(payment.get("gas_limit").and_then(Value::as_u64), Some(1000));
        let limits = payment
            .get("charge_limits")
            .and_then(Value::as_array)
            .expect("typed charge limits");
        assert_eq!(limits.len(), 1);
        let limit = limits[0].as_object().expect("typed charge limit");
        assert_eq!(
            limit.get("asset_definition_id").and_then(Value::as_str),
            Some("7EAD8EFYUx1aVKZPUU1fyKvr8dF1")
        );
        assert_eq!(
            limit.get("max_amount").and_then(Value::as_str),
            Some("1000")
        );
        assert_eq!(
            limit
                .get("kind")
                .and_then(Value::as_object)
                .and_then(|kind| kind.get("kind"))
                .and_then(Value::as_str),
            Some("pipeline_gas")
        );
        assert!(
            payload
                .get("metadata")
                .and_then(Value::as_object)
                .is_some_and(|metadata| !metadata.contains_key("gas_limit")),
            "gas authorization must be signed in fee_payment, not legacy metadata"
        );
    }
    #[test]
    fn fixture_manifest_requires_explicit_ttl() {
        let manifest = Manifest {
            fixtures: vec![fixture("required-ttl")],
        };
        let encoded = json::to_json_pretty(&manifest).expect("serialize fixture manifest");
        let base: Value = json::from_str(&encoded).expect("parse fixture manifest value");
        for replacement in [None, Some(Value::Null)] {
            let mut candidate = base.clone();
            let entry = candidate
                .as_object_mut()
                .and_then(|object| object.get_mut("fixtures"))
                .and_then(Value::as_array_mut)
                .and_then(|fixtures| fixtures.first_mut())
                .and_then(Value::as_object_mut)
                .expect("fixture manifest entry");
            if let Some(value) = replacement {
                entry.insert("time_to_live_ms".to_owned(), value);
            } else {
                entry.remove("time_to_live_ms");
            }
            json::from_value::<Manifest>(candidate)
                .expect_err("missing and null fixture lifetimes must be rejected");
        }
        let mut zero = base;
        zero.as_object_mut()
            .and_then(|object| object.get_mut("fixtures"))
            .and_then(Value::as_array_mut)
            .and_then(|fixtures| fixtures.first_mut())
            .and_then(Value::as_object_mut)
            .expect("fixture manifest entry")
            .insert("time_to_live_ms".to_owned(), Value::from(0_u64));
        let zero_manifest: Manifest = json::from_value(zero).expect("zero is structurally numeric");
        let _ = zero_manifest
            .validate(None)
            .expect_err("zero fixture lifetime must be rejected");
    }
    #[test]
    fn verification_report_lists_expected_sdks() {
        let alias_setup_fixture = checked_in_alias_setup_fixture();
        let report = build_verification_report(&alias_setup_fixture).expect("report");
        assert!(report.fixture_count > 0);
        let mut labels: Vec<&str> = report
            .sdk_manifests
            .iter()
            .map(|entry| entry.sdk.as_str())
            .collect();
        labels.sort_unstable();
        for expected in ["java", "python", "swift"] {
            assert!(
                labels.contains(&expected),
                "expected SDK label {expected:?} to appear in verification report"
            );
        }
    }
    #[test]
    fn manifest_validation_checks_encoded_files_with_base_dir() {
        let root = workspace_root();
        let canonical_path = root.join(CANONICAL_MANIFEST);
        let canonical = Manifest::load(&canonical_path).expect("canonical manifest loads");
        let template = canonical
            .fixtures
            .first()
            .expect("at least one fixture in canonical manifest")
            .clone();
        // Happy path: write the fixture at its identity-bound canonical basename.
        let temp_dir = tempdir().expect("temp dir");
        let entry = template.clone();
        let payload_bytes = BASE64
            .decode(&entry.payload_base64)
            .expect("payload payload_base64 decodes");
        let encoded_path = temp_dir.path().join(&entry.encoded_file);
        fs::write(&encoded_path, &payload_bytes).expect("write encoded payload");
        let manifest = Manifest {
            fixtures: vec![entry.clone()],
        };
        manifest
            .validate(Some(temp_dir.path()))
            .expect("validation succeeds when encoded file matches payload");
        // Corrupt the file and ensure validation fails.
        fs::write(&encoded_path, b"corrupt-payload").expect("corrupt encoded payload");
        let err = manifest
            .validate(Some(temp_dir.path()))
            .expect_err("corrupted payloads should be rejected");
        assert!(
            err.to_string().contains("differs from manifest payload"),
            "error should mention payload mismatch: {err}"
        );
        // Remove the file entirely to verify missing file errors.
        fs::remove_file(&encoded_path).expect("remove encoded payload");
        let err = manifest
            .validate(Some(temp_dir.path()))
            .expect_err("missing encoded payloads should be rejected");
        assert!(
            err.to_string().contains(&entry.encoded_file),
            "error should mention missing encoded file name: {err}"
        );
    }
    #[test]
    fn manifest_validation_rejects_ttl_summary_drift() {
        let root = workspace_root();
        let canonical_path = root.join(CANONICAL_MANIFEST);
        let canonical = Manifest::load(&canonical_path).expect("canonical manifest loads");
        let mut entry = canonical
            .fixtures
            .first()
            .expect("at least one fixture in canonical manifest")
            .clone();
        entry.time_to_live_ms = entry
            .time_to_live_ms
            .checked_add(1)
            .expect("fixture lifetime can be incremented");
        let error = Manifest {
            fixtures: vec![entry],
        }
        .validate(None)
        .expect_err("manifest lifetime drift must be rejected");
        assert!(
            error
                .to_string()
                .contains("manifest summary differs from signed payload"),
            "unexpected lifetime drift error: {error}"
        );
    }
}
