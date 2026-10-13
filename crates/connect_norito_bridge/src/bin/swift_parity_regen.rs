//! Check or regenerate the closed Swift parity fixture set with the current encoder.
//!
//! Usage:
//! `cargo run --locked --offline -p connect_norito_bridge --features dev-tools --bin swift_parity_regen -- --check`
//! `cargo run --locked --offline -p connect_norito_bridge --features dev-tools --bin swift_parity_regen -- --write`
//! `cargo run --locked --offline -p connect_norito_bridge --features dev-tools --bin swift_parity_regen -- --write --output-root /tmp/swift-parity-stage`
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::{AccountId, address},
    asset::{AssetId, id::AssetDefinitionId},
    isi::{Burn, InstructionBox, Mint, Transfer},
    transaction::{FeePaymentIntent, TransactionBuilder, signed::TransactionPayload},
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::{json::Json, numeric::Quantity};
use norito::{
    codec::Encode,
    json::{self, Map, Value},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Read as _, Write as _},
    num::{NonZeroU32, NonZeroU64},
    path::{Component, Path, PathBuf},
    str::FromStr,
    time::Duration,
};
const DEFAULT_FIXTURES_PATH: &str = "IrohaSwift/Fixtures/swift_parity_payloads.json";
const DEFAULT_OUT_DIR: &str = "IrohaSwift/Fixtures";
const DEFAULT_MANIFEST_NAME: &str = "swift_parity_manifest.json";
const SIGNING_SEED_HEX: &str = "616e64726f69642d666978747572652d7369676e696e672d6b65792d30313032";
const DEFAULT_CHAIN_DISCRIMINANT: u16 = 369;
const CANONICAL_DEV_NETWORK_ID: &str =
    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";
const EXPECTED_FIXTURE_NAMES: [&str; 3] = [
    "swift_burn_asset_basic",
    "swift_mint_asset_basic",
    "swift_transfer_asset_basic",
];
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
#[derive(Debug, norito::json::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PayloadFileEntry {
    name: String,
    payload: PayloadSpec,
}
#[derive(Debug, norito::json::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PayloadSpec {
    network_id: NetworkId,
    authority: String,
    creation_time_ms: u64,
    executable: ExecutableSpec,
    time_to_live_ms: u64,
    nonce: u32,
    fee_payment: FeePaymentSpec,

    metadata: BTreeMap<String, Value>,
}
#[derive(Debug, norito::json::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct ExecutableSpec {
    #[norito(rename = "Instructions")]
    instructions: Vec<InstructionSpec>,
}
#[derive(Debug, norito::json::JsonDeserialize, norito::json::JsonSerialize)]
#[norito(deny_unknown_fields)]
struct InstructionSpec {
    kind: String,
    arguments: InstructionArguments,
}
#[derive(Debug, norito::json::JsonDeserialize, norito::json::JsonSerialize)]
#[norito(deny_unknown_fields)]
struct InstructionArguments {
    action: String,
    asset_definition_id: String,
    quantity: String,
    destination: String,
}
#[derive(Debug, norito::json::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct FeePaymentSpec {
    payer: String,
    value: FeePaymentValueSpec,
}
#[derive(Debug, norito::json::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct FeePaymentValueSpec {
    charge_limits: Vec<Value>,
    #[norito(required)]
    gas_limit: Option<NonZeroU64>,
}
#[derive(Clone)]
struct FixtureOutput {
    name: String,
    payload_bytes: Vec<u8>,
    signed_bytes: Vec<u8>,
    payload_base64: String,
    signed_base64: String,
    payload_hash: String,
    signed_hash: String,
}
struct RenderedFixtures {
    files: BTreeMap<PathBuf, Vec<u8>>,
    source_bytes: Vec<u8>,
}
#[derive(Debug)]
struct PublishFailure {
    message: String,
    intended_landed: bool,
}
impl PublishFailure {
    fn before_publication(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            intended_landed: false,
        }
    }
}
fn parse_asset_definition_argument(raw: &str) -> Result<AssetDefinitionId, String> {
    let parsed = AssetDefinitionId::parse_address_literal(raw)
        .map_err(|err| format!("invalid asset definition '{raw}': {err}"))?;
    if parsed.to_string() != raw {
        return Err(format!("noncanonical asset definition '{raw}'"));
    }
    Ok(parsed)
}
fn parse_canonical_account(raw: &str, label: &str) -> Result<AccountId, String> {
    let account =
        AccountId::parse_encoded(raw).map_err(|_| format!("invalid {label} account '{raw}'"))?;
    if account.to_string() != raw {
        return Err(format!("noncanonical {label} account '{raw}'"));
    }
    Ok(account)
}
fn canonical_dev_network_id() -> NetworkId {
    json::from_value(Value::String(CANONICAL_DEV_NETWORK_ID.to_owned()))
        .expect("the canonical Iroha3 dev network identity must remain valid")
}
impl FeePaymentSpec {
    fn to_intent(&self) -> Result<FeePaymentIntent, String> {
        if self.payer != "authority" {
            return Err(format!(
                "unsupported fee-payment payer '{}'; expected 'authority'",
                self.payer
            ));
        }
        if !self.value.charge_limits.is_empty() {
            return Err("Swift parity fee-payment charge_limits must be empty".to_owned());
        }
        Ok(FeePaymentIntent::authority(
            Vec::new(),
            self.value.gas_limit,
        ))
    }
}
impl PayloadSpec {
    fn to_builder(&self) -> Result<TransactionBuilder, String> {
        if self.network_id != canonical_dev_network_id() {
            return Err(format!(
                "network_id must be the canonical Iroha3 dev genesis identity '{CANONICAL_DEV_NETWORK_ID}'"
            ));
        }
        let authority = parse_canonical_account(&self.authority, "authority")?;
        let mut builder = TransactionBuilder::new(
            self.network_id,
            authority.clone(),
            self.fee_payment.to_intent()?,
        );
        builder.set_creation_time(Duration::from_millis(self.creation_time_ms));
        if self.time_to_live_ms == 0 {
            return Err("time_to_live_ms must be > 0".to_owned());
        }
        builder.set_ttl(Duration::from_millis(self.time_to_live_ms));
        let nonce = NonZeroU32::new(self.nonce).ok_or_else(|| "nonce must be > 0".to_string())?;
        builder.set_nonce(nonce);
        let mut metadata = Metadata::default();
        for (key, value) in &self.metadata {
            let name = Name::from_str(key).map_err(|_| format!("invalid metadata key '{key}'"))?;
            metadata.insert(name, Json::new(value.clone()));
        }
        builder = builder.with_metadata(metadata);
        if self.executable.instructions.len() != 1 {
            return Err("Swift parity fixtures require exactly one instruction".to_owned());
        }
        let instruction = self.executable.instructions[0].to_instruction(&authority)?;
        builder = builder.with_instructions([instruction]);
        Ok(builder)
    }
}
impl InstructionSpec {
    fn to_instruction(&self, authority: &AccountId) -> Result<InstructionBox, String> {
        let arguments = &self.arguments;
        match arguments.action.as_str() {
            "TransferAsset" => {
                if self.kind != "Transfer" {
                    return Err(format!(
                        "expected Transfer kind for TransferAsset, got '{}'",
                        self.kind
                    ));
                }
                let asset_definition =
                    parse_asset_definition_argument(&arguments.asset_definition_id)?;
                let quantity = parse_canonical_quantity(&arguments.quantity)?;
                let destination = parse_canonical_account(&arguments.destination, "destination")?;
                let asset_id = AssetId::new(asset_definition, authority.clone());
                Ok(Transfer::asset_quantity(asset_id, quantity, destination).into())
            }
            "MintAsset" => {
                if self.kind != "Mint" {
                    return Err(format!(
                        "expected Mint kind for MintAsset, got '{}'",
                        self.kind
                    ));
                }
                let asset_definition =
                    parse_asset_definition_argument(&arguments.asset_definition_id)?;
                let quantity = parse_canonical_quantity(&arguments.quantity)?;
                let destination = parse_canonical_account(&arguments.destination, "destination")?;
                let asset_id = AssetId::new(asset_definition, destination);
                Ok(Mint::asset_quantity(quantity, asset_id).into())
            }
            "BurnAsset" => {
                if self.kind != "Burn" {
                    return Err(format!(
                        "expected Burn kind for BurnAsset, got '{}'",
                        self.kind
                    ));
                }
                let asset_definition =
                    parse_asset_definition_argument(&arguments.asset_definition_id)?;
                let quantity = parse_canonical_quantity(&arguments.quantity)?;
                let destination = parse_canonical_account(&arguments.destination, "destination")?;
                let asset_id = AssetId::new(asset_definition, destination);
                Ok(Burn::asset_quantity(quantity, asset_id).into())
            }
            other => Err(format!("unsupported instruction action '{other}'")),
        }
    }
}
fn parse_canonical_quantity(input: &str) -> Result<Quantity, String> {
    let quantity: Quantity = input
        .parse()
        .map_err(|err| format!("invalid quantity '{input}': {err}"))?;
    if quantity.to_string() != input {
        return Err(format!("noncanonical quantity '{input}'"));
    }
    Ok(quantity)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(err) = run() {
        return Err(std::io::Error::other(err).into());
    }
    Ok(())
}
fn run() -> Result<(), String> {
    let repository_root = repository_root();
    let options = parse_options_from(&env::args().skip(1).collect::<Vec<_>>(), &repository_root)?;
    run_with_options(&repository_root.join(DEFAULT_FIXTURES_PATH), &options)
}
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("connect_norito_bridge belongs to the workspace")
        .to_path_buf()
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
fn reject_symlinked_ancestry(path: &Path) -> Result<(), String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|err| format!("resolve current directory: {err}"))?
            .join(path)
    };
    if absolute
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!(
            "output root must not contain parent traversal: {}",
            path.display()
        ));
    }
    let mut ancestors: Vec<_> = absolute.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|err| format!("inspect output-root ancestry {}: {err}", ancestor.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "output-root ancestry must not contain symlinks: {}",
                ancestor.display()
            ));
        }
    }
    Ok(())
}
fn validate_output_root(root: &Path) -> Result<PathBuf, String> {
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|err| format!("resolve current directory: {err}"))?
            .join(root)
    };
    reject_symlinked_ancestry(&absolute)?;
    let metadata = fs::symlink_metadata(&absolute)
        .map_err(|err| format!("inspect output root {}: {err}", root.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "output root must not be a symlink: {}",
            root.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "output root must be an existing directory: {}",
            root.display()
        ));
    }
    let canonical = fs::canonicalize(&absolute)
        .map_err(|err| format!("canonicalize output root {}: {err}", root.display()))?;
    reject_symlinked_ancestry(&canonical)?;
    if canonical.parent().is_none() {
        return Err(format!(
            "output root must not be the filesystem root: {}",
            root.display()
        ));
    }
    Ok(canonical)
}
fn validate_fixture_inventory(entries: &mut [PayloadFileEntry]) -> Result<(), String> {
    let mut actual = BTreeSet::new();
    for entry in entries.iter() {
        if !actual.insert(entry.name.as_str()) {
            return Err(format!(
                "duplicate Swift parity fixture name '{}'",
                entry.name
            ));
        }
    }
    let expected: BTreeSet<_> = EXPECTED_FIXTURE_NAMES.into_iter().collect();
    if actual != expected {
        return Err(format!(
            "Swift parity fixture inventory must be exactly {expected:?}; got {actual:?}"
        ));
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(())
}
fn validate_fixture_semantics(entry: &PayloadFileEntry) -> Result<(), String> {
    let instruction = entry
        .payload
        .executable
        .instructions
        .first()
        .ok_or_else(|| format!("fixture '{}' has no instruction", entry.name))?;
    let expected = match entry.name.as_str() {
        "swift_burn_asset_basic" => ("Burn", "BurnAsset"),
        "swift_mint_asset_basic" => ("Mint", "MintAsset"),
        "swift_transfer_asset_basic" => ("Transfer", "TransferAsset"),
        _ => return Err(format!("unsupported Swift parity fixture '{}'", entry.name)),
    };
    if instruction.kind != expected.0 || instruction.arguments.action != expected.1 {
        return Err(format!(
            "fixture '{}' must contain {} / {}, got {} / {}",
            entry.name, expected.0, expected.1, instruction.kind, instruction.arguments.action
        ));
    }
    Ok(())
}
fn validate_distinct_fixture_identities(fixtures: &[FixtureOutput]) -> Result<(), String> {
    if fixtures.len() != EXPECTED_FIXTURE_NAMES.len() {
        return Err(format!(
            "Swift parity renderer must produce exactly {} identities, got {}",
            EXPECTED_FIXTURE_NAMES.len(),
            fixtures.len()
        ));
    }
    let mut payload_bytes = BTreeMap::<&[u8], &str>::new();
    let mut signed_bytes = BTreeMap::<&[u8], &str>::new();
    let mut payload_hashes = BTreeMap::<&str, &str>::new();
    let mut signed_hashes = BTreeMap::<&str, &str>::new();
    for fixture in fixtures {
        for (label, duplicate) in [
            (
                "payload bytes",
                payload_bytes.insert(&fixture.payload_bytes, fixture.name.as_str()),
            ),
            (
                "signed bytes",
                signed_bytes.insert(&fixture.signed_bytes, fixture.name.as_str()),
            ),
            (
                "payload hash",
                payload_hashes.insert(&fixture.payload_hash, fixture.name.as_str()),
            ),
            (
                "signed hash",
                signed_hashes.insert(&fixture.signed_hash, fixture.name.as_str()),
            ),
        ] {
            if let Some(first) = duplicate {
                return Err(format!(
                    "Swift parity fixtures '{}' and '{}' have duplicate {label}",
                    first, fixture.name
                ));
            }
        }
    }
    Ok(())
}
fn render_fixtures(fixtures_path: &Path) -> Result<RenderedFixtures, String> {
    let _chain_guard = address::ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
    let source_bytes = fs::read(fixtures_path)
        .map_err(|err| format!("failed to read {}: {err}", fixtures_path.display()))?;
    let mut entries: Vec<PayloadFileEntry> = norito::json::from_slice(&source_bytes)
        .map_err(|err| format!("invalid payload JSON: {err}"))?;
    validate_fixture_inventory(&mut entries)?;
    let seed = hex::decode(SIGNING_SEED_HEX).map_err(|err| err.to_string())?;
    let keypair = KeyPair::try_from_seed(seed, Algorithm::Ed25519)
        .map_err(|err| format!("failed to derive fixture signing key: {err}"))?;
    let mut fixtures = Vec::with_capacity(entries.len());
    for entry in entries {
        validate_fixture_semantics(&entry)?;
        let builder = entry.payload.to_builder()?;
        let signed = builder.try_sign(keypair.private_key()).map_err(|err| {
            format!(
                "failed to sign Swift parity fixture `{}`: {err}",
                entry.name
            )
        })?;
        let payload = signed.payload().clone();
        let payload_bytes = payload.encode();
        let signed_bytes = signed.encode();
        let payload_base64 = BASE64.encode(&payload_bytes);
        let signed_base64 = BASE64.encode(&signed_bytes);
        let payload_hash = format!("{}", HashOf::<TransactionPayload>::new(&payload));
        let signed_hash = signed.hash().to_string();
        if payload.time_to_live_ms.map(|value| value.get()) != Some(entry.payload.time_to_live_ms) {
            return Err(format!(
                "fixture '{}' did not preserve its required TTL",
                entry.name
            ));
        }
        if payload.nonce.map(|value| value.get()) != Some(entry.payload.nonce) {
            return Err(format!(
                "fixture '{}' did not preserve its required nonce",
                entry.name
            ));
        }
        let fixture = FixtureOutput {
            name: entry.name,
            payload_bytes,
            signed_bytes,
            payload_base64,
            signed_base64,
            payload_hash,
            signed_hash,
        };
        fixtures.push(fixture);
    }
    validate_distinct_fixture_identities(&fixtures)?;
    let manifest_entries: Vec<Value> = fixtures
        .iter()
        .map(|fixture| {
            let mut map = Map::new();
            map.insert("name".into(), Value::String(fixture.name.clone()));
            map.insert(
                "payload_base64".into(),
                Value::String(fixture.payload_base64.clone()),
            );
            map.insert(
                "signed_base64".into(),
                Value::String(fixture.signed_base64.clone()),
            );
            map.insert(
                "payload_hash".into(),
                Value::String(fixture.payload_hash.clone()),
            );
            map.insert(
                "signed_hash".into(),
                Value::String(fixture.signed_hash.clone()),
            );
            Value::Object(map)
        })
        .collect();
    let mut root = Map::new();
    root.insert("fixtures".into(), Value::Array(manifest_entries));
    let manifest_json = json::to_json_pretty(&Value::Object(root))
        .map_err(|err| format!("failed to serialize manifest: {err}"))?;
    let mut files = BTreeMap::new();
    for fixture in fixtures {
        files.insert(
            Path::new(DEFAULT_OUT_DIR).join(format!("{}.norito", fixture.name)),
            fixture.payload_bytes,
        );
    }
    files.insert(
        Path::new(DEFAULT_OUT_DIR).join(DEFAULT_MANIFEST_NAME),
        format!("{manifest_json}\n").into_bytes(),
    );
    Ok(RenderedFixtures {
        files,
        source_bytes,
    })
}
fn owned_relative_paths() -> [PathBuf; 4] {
    [
        Path::new(DEFAULT_OUT_DIR).join("swift_burn_asset_basic.norito"),
        Path::new(DEFAULT_OUT_DIR).join("swift_mint_asset_basic.norito"),
        Path::new(DEFAULT_OUT_DIR).join("swift_transfer_asset_basic.norito"),
        Path::new(DEFAULT_OUT_DIR).join(DEFAULT_MANIFEST_NAME),
    ]
}
fn validate_relative_output(relative: &Path) -> Result<(), String> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "generated output must be a non-empty normalized relative path: {}",
            relative.display()
        ));
    }
    Ok(())
}
fn ensure_safe_parent(
    root: &Path,
    relative: &Path,
    created_directories: &mut Vec<PathBuf>,
) -> Result<(), String> {
    validate_relative_output(relative)?;
    let mut current = root.to_path_buf();
    let parent = relative
        .parent()
        .ok_or_else(|| format!("generated output has no parent: {}", relative.display()))?;
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(format!(
                "generated output parent is not normalized: {}",
                relative.display()
            ));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "generated output parent must be a real directory: {}",
                        current.display()
                    ));
                }
                let canonical = fs::canonicalize(&current)
                    .map_err(|err| format!("canonicalize {}: {err}", current.display()))?;
                if canonical != current {
                    return Err(format!(
                        "generated output parent must be canonical: {} resolves to {}",
                        current.display(),
                        canonical.display()
                    ));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .map_err(|err| format!("create {}: {err}", current.display()))?;
                created_directories.push(current.clone());
                let metadata = fs::symlink_metadata(&current).map_err(|err| {
                    format!("inspect created directory {}: {err}", current.display())
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "created output parent is not a real directory: {}",
                        current.display()
                    ));
                }
                let canonical = fs::canonicalize(&current).map_err(|err| {
                    format!(
                        "canonicalize created directory {}: {err}",
                        current.display()
                    )
                })?;
                if canonical != current {
                    return Err(format!(
                        "created output parent must be canonical: {} resolves to {}",
                        current.display(),
                        canonical.display()
                    ));
                }
            }
            Err(err) => return Err(format!("inspect {}: {err}", current.display())),
        }
    }
    Ok(())
}
fn validate_existing_parent_chain(root: &Path, relative: &Path) -> Result<(), String> {
    validate_relative_output(relative)?;
    let mut current = root.to_path_buf();
    let parent = relative
        .parent()
        .ok_or_else(|| format!("generated output has no parent: {}", relative.display()))?;
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(format!(
                "generated output parent is not normalized: {}",
                relative.display()
            ));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "generated output parent must be a real directory: {}",
                        current.display()
                    ));
                }
                let canonical = fs::canonicalize(&current)
                    .map_err(|err| format!("canonicalize {}: {err}", current.display()))?;
                if canonical != current {
                    return Err(format!(
                        "generated output parent must be canonical: {} resolves to {}",
                        current.display(),
                        canonical.display()
                    ));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(format!("inspect {}: {err}", current.display())),
        }
    }
    Ok(())
}
fn validate_regular_file_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "generated output must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(format!(
                "generated output must have exactly one hard link: {} has {}",
                path.display(),
                metadata.nlink()
            ));
        }
    }
    Ok(())
}
#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}
fn read_regular_file(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let path_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("inspect {}: {err}", path.display())),
    };
    validate_regular_file_metadata(path, &path_metadata)?;
    let mut file = fs::File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .map_err(|err| format!("inspect opened output {}: {err}", path.display()))?;
    validate_regular_file_metadata(path, &opened_metadata)?;
    #[cfg(unix)]
    if !same_file_identity(&path_metadata, &opened_metadata) {
        return Err(format!(
            "generated output changed while opening it: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| format!("read {}: {err}", path.display()))?;
    let final_path_metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("reinspect {} after read: {err}", path.display()))?;
    validate_regular_file_metadata(path, &final_path_metadata)?;
    #[cfg(unix)]
    if !same_file_identity(&opened_metadata, &final_path_metadata) {
        return Err(format!(
            "generated output changed while reading it: {}",
            path.display()
        ));
    }
    Ok(Some(bytes))
}
fn fixture_entry_name(
    file_name: std::ffi::OsString,
    directory_path: &Path,
) -> Result<String, String> {
    file_name.into_string().map_err(|_| {
        format!(
            "Swift fixture tree contains a non-UTF-8 entry under {}",
            directory_path.display()
        )
    })
}
fn reject_orphan_swift_blobs(root: &Path) -> Result<(), String> {
    let fixtures_dir = root.join(DEFAULT_OUT_DIR);
    let metadata = match fs::symlink_metadata(&fixtures_dir) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("inspect {}: {err}", fixtures_dir.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "Swift fixture directory must be a real directory: {}",
            fixtures_dir.display()
        ));
    }
    let canonical_fixtures_dir = fs::canonicalize(&fixtures_dir)
        .map_err(|err| format!("canonicalize {}: {err}", fixtures_dir.display()))?;
    if canonical_fixtures_dir != fixtures_dir {
        return Err(format!(
            "Swift fixture directory must be canonical: {} resolves to {}",
            fixtures_dir.display(),
            canonical_fixtures_dir.display()
        ));
    }
    let expected: BTreeSet<_> = EXPECTED_FIXTURE_NAMES
        .into_iter()
        .map(|name| PathBuf::from(format!("{name}.norito")))
        .collect();
    let mut unexpected = BTreeSet::new();
    let mut pending = vec![(fixtures_dir.clone(), PathBuf::new())];
    while let Some((directory_path, relative_directory)) = pending.pop() {
        let directory_metadata = fs::symlink_metadata(&directory_path)
            .map_err(|err| format!("reinspect {}: {err}", directory_path.display()))?;
        if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
            return Err(format!(
                "Swift fixture traversal requires a real directory: {}",
                directory_path.display()
            ));
        }
        let canonical_directory = fs::canonicalize(&directory_path)
            .map_err(|err| format!("canonicalize {}: {err}", directory_path.display()))?;
        if canonical_directory != directory_path {
            return Err(format!(
                "Swift fixture traversal escaped its canonical path: {} resolves to {}",
                directory_path.display(),
                canonical_directory.display()
            ));
        }
        let directory = fs::read_dir(&directory_path)
            .map_err(|err| format!("read {}: {err}", directory_path.display()))?;
        for entry in directory {
            let entry =
                entry.map_err(|err| format!("read {} entry: {err}", directory_path.display()))?;
            let entry_path = entry.path();
            let file_name = fixture_entry_name(entry.file_name(), &directory_path)?;
            let relative = relative_directory.join(&file_name);
            let entry_metadata = fs::symlink_metadata(&entry_path)
                .map_err(|err| format!("inspect {}: {err}", entry_path.display()))?;
            let file_type = entry_metadata.file_type();
            if file_type.is_symlink() {
                return Err(format!(
                    "Swift fixture tree must not contain symlinks: {}",
                    entry_path.display()
                ));
            }
            if !file_type.is_file() && !file_type.is_dir() {
                return Err(format!(
                    "Swift fixture tree contains an unsupported filesystem entry: {}",
                    entry_path.display()
                ));
            }
            if file_name.starts_with("swift_")
                && file_name.ends_with(".norito")
                && (!file_type.is_file() || !expected.contains(&relative))
            {
                unexpected.insert(relative.display().to_string());
            }
            if file_type.is_dir() {
                pending.push((entry_path, relative));
            }
        }
    }
    if unexpected.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "unexpected Swift parity blobs in {}: {}",
            fixtures_dir.display(),
            unexpected.into_iter().collect::<Vec<_>>().join(", ")
        ))
    }
}
fn verify_preimage(path: &Path, expected: Option<&[u8]>) -> Result<(), String> {
    let actual = read_regular_file(path)?;
    if actual.as_deref() != expected {
        return Err(format!(
            "generated output changed since its preimage was captured: {}",
            path.display()
        ));
    }
    Ok(())
}
fn verify_source_preimage(fixtures_path: &Path, expected: &[u8]) -> Result<(), String> {
    let actual = fs::read(fixtures_path)
        .map_err(|err| format!("re-read source fixture {}: {err}", fixtures_path.display()))?;
    if actual != expected {
        return Err(format!(
            "source fixture changed after rendering: {}",
            fixtures_path.display()
        ));
    }
    Ok(())
}
fn atomic_publish(
    root: &Path,
    relative: &Path,
    replacement: &[u8],
    expected_preimage: Option<&[u8]>,
) -> Result<(), PublishFailure> {
    validate_relative_output(relative).map_err(PublishFailure::before_publication)?;
    validate_existing_parent_chain(root, relative).map_err(PublishFailure::before_publication)?;
    let path = root.join(relative);
    let parent = path.parent().ok_or_else(|| {
        PublishFailure::before_publication(format!(
            "generated output has no parent: {}",
            path.display()
        ))
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|err| {
        PublishFailure::before_publication(format!(
            "create temporary output in {}: {err}",
            parent.display()
        ))
    })?;
    temporary.write_all(replacement).map_err(|err| {
        PublishFailure::before_publication(format!(
            "write temporary output for {}: {err}",
            path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|err| {
                PublishFailure::before_publication(format!(
                    "set deterministic permissions for {}: {err}",
                    path.display()
                ))
            })?;
    }
    temporary.as_file().sync_all().map_err(|err| {
        PublishFailure::before_publication(format!(
            "sync temporary output for {}: {err}",
            path.display()
        ))
    })?;
    validate_existing_parent_chain(root, relative).map_err(PublishFailure::before_publication)?;
    let canonical_parent = fs::canonicalize(parent).map_err(|err| {
        PublishFailure::before_publication(format!(
            "canonicalize output parent {}: {err}",
            parent.display()
        ))
    })?;
    if canonical_parent != parent {
        return Err(PublishFailure::before_publication(format!(
            "output parent changed before publication: {} resolves to {}",
            parent.display(),
            canonical_parent.display()
        )));
    }
    verify_preimage(&path, expected_preimage).map_err(PublishFailure::before_publication)?;
    match temporary.persist(&path) {
        Ok(_) => Ok(()),
        Err(err) => {
            let mut message = format!(
                "atomically publish generated output {}: {}",
                path.display(),
                err.error
            );
            let intended_landed = match read_regular_file(&path) {
                Ok(Some(actual)) => actual == replacement,
                Ok(None) => false,
                Err(inspect) => {
                    message.push_str(&format!("; could not inspect persist outcome: {inspect}"));
                    false
                }
            };
            Err(PublishFailure {
                message,
                intended_landed,
            })
        }
    }
}
fn guarded_remove(root: &Path, relative: &Path, expected_preimage: &[u8]) -> Result<(), String> {
    validate_existing_parent_chain(root, relative)?;
    let path = root.join(relative);
    verify_preimage(&path, Some(expected_preimage))?;
    fs::remove_file(&path)
        .map_err(|err| format!("remove {} during rollback: {err}", path.display()))?;
    verify_preimage(&path, None)
}
fn compare_or_publish(
    root: &Path,
    relative: &Path,
    expected: &[u8],
    preimage: Option<&[u8]>,
    mode: Mode,
) -> Result<bool, PublishFailure> {
    validate_relative_output(relative).map_err(PublishFailure::before_publication)?;
    validate_existing_parent_chain(root, relative).map_err(PublishFailure::before_publication)?;
    let path = root.join(relative);
    if preimage == Some(expected) {
        eprintln!("fresh {}", path.display());
        return Ok(false);
    }
    if mode == Mode::Check {
        return Err(PublishFailure::before_publication(format!(
            "stale or missing generated Swift parity fixture {}",
            path.display()
        )));
    }
    atomic_publish(root, relative, expected, preimage)?;
    eprintln!("wrote {}", path.display());
    Ok(true)
}
fn capture_preimages(
    root: &Path,
    owned: &[PathBuf],
) -> Result<BTreeMap<PathBuf, Option<Vec<u8>>>, String> {
    let mut preimages = BTreeMap::new();
    for relative in owned {
        validate_existing_parent_chain(root, relative)?;
        preimages.insert(relative.clone(), read_regular_file(&root.join(relative))?);
    }
    Ok(preimages)
}
fn remove_created_directories(created_directories: &[PathBuf]) -> Result<(), String> {
    let mut failures = Vec::new();
    for directory in created_directories.iter().rev() {
        match fs::remove_dir(directory) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => failures.push(format!("{}: {err}", directory.display())),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}
fn error_after_directory_cleanup(created_directories: &[PathBuf], cause: String) -> String {
    if created_directories.is_empty() {
        return cause;
    }
    match remove_created_directories(created_directories) {
        Ok(()) => format!(
            "{cause}; removed {} empty task-created directories",
            created_directories.len()
        ),
        Err(cleanup) => format!("{cause}; task-created directory cleanup incomplete: {cleanup}"),
    }
}
fn rollback_published(
    root: &Path,
    rendered: &RenderedFixtures,
    preimages: &BTreeMap<PathBuf, Option<Vec<u8>>>,
    published: &[PathBuf],
) -> Result<(), String> {
    let mut failures = Vec::new();
    for relative in published.iter().rev() {
        let intended = rendered
            .files
            .get(relative)
            .expect("published output belongs to rendered inventory");
        let preimage = preimages
            .get(relative)
            .expect("published output has a captured preimage");
        let result: Result<(), String> = match preimage.as_deref() {
            Some(bytes) => match atomic_publish(root, relative, bytes, Some(intended)) {
                Ok(()) => verify_preimage(&root.join(relative), Some(bytes)),
                Err(failure) if failure.intended_landed => {
                    verify_preimage(&root.join(relative), Some(bytes)).map_err(|verify| {
                        format!(
                            "{}; landed restoration verification failed: {verify}",
                            failure.message
                        )
                    })
                }
                Err(failure) => Err(failure.message),
            },
            None => guarded_remove(root, relative, intended),
        };
        if let Err(err) = result {
            failures.push(format!("{}: {err}", relative.display()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}
fn error_after_rollback(
    root: &Path,
    rendered: &RenderedFixtures,
    preimages: &BTreeMap<PathBuf, Option<Vec<u8>>>,
    published: &[PathBuf],
    created_directories: &[PathBuf],
    cause: String,
) -> String {
    let mut notes = Vec::new();
    let mut failures = Vec::new();
    if !published.is_empty() {
        match rollback_published(root, rendered, preimages, published) {
            Ok(()) => notes.push(format!(
                "restored {} previously published output(s)",
                published.len()
            )),
            Err(rollback) => failures.push(format!("output rollback: {rollback}")),
        }
    }
    if !created_directories.is_empty() {
        match remove_created_directories(created_directories) {
            Ok(()) => notes.push(format!(
                "removed {} empty task-created directories",
                created_directories.len()
            )),
            Err(cleanup) => failures.push(format!("directory cleanup: {cleanup}")),
        }
    }
    if failures.is_empty() {
        if notes.is_empty() {
            cause
        } else {
            format!("{cause}; {}", notes.join("; "))
        }
    } else {
        format!("{cause}; rollback incomplete: {}", failures.join("; "))
    }
}
fn publish_outputs_with_hook<F>(
    root: &Path,
    rendered: &RenderedFixtures,
    owned: &[PathBuf],
    preimages: &BTreeMap<PathBuf, Option<Vec<u8>>>,
    created_directories: &[PathBuf],
    mut before_publish: F,
) -> Result<Vec<PathBuf>, String>
where
    F: FnMut(usize, &Path) -> Result<(), String>,
{
    let mut published = Vec::new();
    for relative in owned {
        let expected = rendered
            .files
            .get(relative)
            .expect("owned output was validated before publication");
        let preimage = preimages
            .get(relative)
            .expect("owned output has a captured preimage");
        if preimage.as_deref() == Some(expected) {
            eprintln!("fresh {}", root.join(relative).display());
            continue;
        }
        if let Err(err) = before_publish(published.len(), relative) {
            return Err(error_after_rollback(
                root,
                rendered,
                preimages,
                &published,
                created_directories,
                format!("publication stopped before {}: {err}", relative.display()),
            ));
        }
        match compare_or_publish(root, relative, expected, preimage.as_deref(), Mode::Write) {
            Ok(true) => {
                published.push(relative.clone());
                if let Err(err) = verify_preimage(&root.join(relative), Some(expected)) {
                    return Err(error_after_rollback(
                        root,
                        rendered,
                        preimages,
                        &published,
                        created_directories,
                        err,
                    ));
                }
            }
            Ok(false) => {}
            Err(failure) => {
                if failure.intended_landed {
                    published.push(relative.clone());
                }
                return Err(error_after_rollback(
                    root,
                    rendered,
                    preimages,
                    &published,
                    created_directories,
                    failure.message,
                ));
            }
        }
    }
    Ok(published)
}
fn verify_rendered_outputs(
    root: &Path,
    rendered: &RenderedFixtures,
    owned: &[PathBuf],
) -> Result<(), String> {
    reject_orphan_swift_blobs(root)?;
    for relative in owned {
        let path = root.join(relative);
        let actual = read_regular_file(&path)?
            .ok_or_else(|| format!("generated output disappeared: {}", path.display()))?;
        if actual != rendered.files[relative] {
            return Err(format!(
                "generated output changed during verification: {}",
                path.display()
            ));
        }
    }
    Ok(())
}
fn run_with_options(fixtures_path: &Path, options: &Options) -> Result<(), String> {
    let output_root = validate_output_root(&options.output_root)?;
    let rendered = render_fixtures(fixtures_path)?;
    let owned = owned_relative_paths();
    let manifest = Path::new(DEFAULT_OUT_DIR).join(DEFAULT_MANIFEST_NAME);
    if owned.last() != Some(&manifest) || owned[..owned.len() - 1].contains(&manifest) {
        return Err(
            "Swift parity publication order must contain three blobs then the manifest".into(),
        );
    }
    for relative in &owned {
        validate_existing_parent_chain(&output_root, relative)?;
    }
    reject_orphan_swift_blobs(&output_root)?;
    if rendered.files.len() != owned.len()
        || owned
            .iter()
            .any(|relative| !rendered.files.contains_key(relative))
    {
        return Err("Swift parity renderer produced the wrong exact output inventory".to_owned());
    }
    if options.mode == Mode::Check {
        let preimages = capture_preimages(&output_root, &owned)?;
        for relative in &owned {
            compare_or_publish(
                &output_root,
                relative,
                rendered
                    .files
                    .get(relative)
                    .expect("owned output was validated above"),
                preimages
                    .get(relative)
                    .expect("owned output has a captured preimage")
                    .as_deref(),
                Mode::Check,
            )
            .map_err(|failure| failure.message)?;
        }
        verify_source_preimage(fixtures_path, &rendered.source_bytes)?;
        return verify_rendered_outputs(&output_root, &rendered, &owned);
    }
    let mut created_directories = Vec::new();
    for relative in &owned {
        if let Err(err) = ensure_safe_parent(&output_root, relative, &mut created_directories) {
            return Err(error_after_directory_cleanup(&created_directories, err));
        }
    }
    let preimages = match capture_preimages(&output_root, &owned) {
        Ok(preimages) => preimages,
        Err(err) => return Err(error_after_directory_cleanup(&created_directories, err)),
    };
    if let Err(err) = verify_source_preimage(fixtures_path, &rendered.source_bytes) {
        return Err(error_after_directory_cleanup(&created_directories, err));
    }
    // Blobs are published before the manifest and ordinary errors roll every changed path back.
    // This is not crash-atomic: a process or machine crash between fixed-path renames can leave a
    // mixed set. True cross-file atomicity requires generation-specific paths plus one pointer swap.
    let published = publish_outputs_with_hook(
        &output_root,
        &rendered,
        &owned,
        &preimages,
        &created_directories,
        |_, _| Ok(()),
    )?;
    let final_verification = verify_source_preimage(fixtures_path, &rendered.source_bytes)
        .and_then(|()| verify_rendered_outputs(&output_root, &rendered, &owned));
    if let Err(err) = final_verification {
        return Err(error_after_rollback(
            &output_root,
            &rendered,
            &preimages,
            &published,
            &created_directories,
            err,
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::Hash;
    use iroha_data_model::transaction::Executable;
    use iroha_model_base::domain::DomainId;
    use norito::json::Number;
    fn canonical_temp_root(directory: &tempfile::TempDir) -> PathBuf {
        fs::canonicalize(directory.path()).expect("canonical temporary directory")
    }
    fn identity_fixtures() -> Vec<FixtureOutput> {
        (0_u8..3)
            .map(|index| FixtureOutput {
                name: format!("fixture-{index}"),
                payload_bytes: vec![index],
                signed_bytes: vec![index + 10],
                payload_base64: BASE64.encode([index]),
                signed_base64: BASE64.encode([index + 10]),
                payload_hash: format!("payload-{index}"),
                signed_hash: format!("signed-{index}"),
            })
            .collect()
    }
    fn account_literal(account: &AccountId) -> String {
        account.to_string()
    }
    fn asset_definition_literal(domain: &str, name: &str) -> String {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new(domain, "universal").expect("domain"),
            name.parse().expect("name"),
        )
        .to_string()
    }
    fn instruction_arguments(destination: &AccountId) -> InstructionArguments {
        InstructionArguments {
            action: "TransferAsset".into(),
            asset_definition_id: asset_definition_literal("wonderland", "rose"),
            quantity: "1.25".into(),
            destination: account_literal(destination),
        }
    }
    fn payload_spec(authority: &AccountId, destination: &AccountId) -> PayloadSpec {
        PayloadSpec {
            network_id: canonical_dev_network_id(),
            authority: account_literal(authority),
            creation_time_ms: 123,
            executable: ExecutableSpec {
                instructions: vec![InstructionSpec {
                    kind: "Transfer".into(),
                    arguments: instruction_arguments(destination),
                }],
            },
            time_to_live_ms: 3500,
            nonce: 17,
            fee_payment: FeePaymentSpec {
                payer: "authority".into(),
                value: FeePaymentValueSpec {
                    charge_limits: Vec::new(),
                    gas_limit: None,
                },
            },

            metadata: BTreeMap::new(),
        }
    }
    fn source_document() -> Value {
        let bytes = fs::read(repository_root().join(DEFAULT_FIXTURES_PATH))
            .expect("read canonical Swift parity source");
        json::from_slice(&bytes).expect("decode canonical Swift parity source")
    }
    fn first_entry(document: &mut Value) -> &mut Map {
        document
            .as_array_mut()
            .expect("source array")
            .first_mut()
            .expect("source entry")
            .as_object_mut()
            .expect("source entry object")
    }
    fn first_payload(document: &mut Value) -> &mut Map {
        first_entry(document)
            .get_mut("payload")
            .expect("payload")
            .as_object_mut()
            .expect("payload object")
    }
    fn decode_document(document: Value) -> Result<Vec<PayloadFileEntry>, String> {
        json::from_value(document).map_err(|err| err.to_string())
    }
    #[test]
    fn command_requires_exactly_one_mode_and_accepts_a_staged_output_root() {
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
                    "/stage".to_owned(),
                    "--write".to_owned(),
                ],
                default_root,
            ),
            Ok(Options {
                mode: Mode::Write,
                output_root: PathBuf::from("/stage"),
            })
        );
        for invalid in [
            Vec::new(),
            vec!["--write".to_owned(), "--check".to_owned()],
            vec!["--write".to_owned(), "extra".to_owned()],
            vec!["--write".to_owned(), "--output-root".to_owned()],
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
        ] {
            assert!(parse_options_from(&invalid, default_root).is_err());
        }
    }
    #[test]
    fn payload_builder_sets_nonce_and_ttl() {
        let keypair = KeyPair::try_from_seed(vec![0xCD; 32], Algorithm::Ed25519)
            .expect("seeded fixture key should derive");
        let authority = AccountId::new(keypair.public_key().clone());
        let destination = AccountId::new(keypair.public_key().clone());
        let payload = payload_spec(&authority, &destination);
        let builder = payload.to_builder().expect("builder");
        let signed = builder
            .try_sign(keypair.private_key())
            .expect("checked fixture transaction signing should succeed");
        signed
            .verify_signature()
            .expect("checked fixture transaction signature should verify");
        assert_eq!(signed.payload().nonce.map(|v| v.get()), Some(17));
        assert_eq!(
            signed.payload().time_to_live_ms.map(|v| v.get()),
            Some(3500)
        );
        match signed.instructions() {
            Executable::Instructions(instructions) => assert_eq!(instructions.len(), 1),
            _ => panic!("expected instruction executable"),
        }
    }
    #[test]
    fn payload_builder_rejects_zero_ttl_and_nonce() {
        let keypair = KeyPair::try_from_seed(vec![0xCE; 32], Algorithm::Ed25519)
            .expect("seeded fixture key should derive");
        let authority = AccountId::new(keypair.public_key().clone());
        let mut payload = payload_spec(&authority, &authority);
        payload.time_to_live_ms = 0;
        assert_eq!(
            payload.to_builder().err().as_deref(),
            Some("time_to_live_ms must be > 0")
        );
        payload.time_to_live_ms = 1;
        payload.nonce = 0;
        assert_eq!(
            payload.to_builder().err().as_deref(),
            Some("nonce must be > 0")
        );
    }
    #[test]
    fn source_schema_rejects_missing_null_and_zero_ttl() {
        let _chain_guard = address::ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
        let mut missing = source_document();
        first_payload(&mut missing).remove("time_to_live_ms");
        assert!(decode_document(missing).is_err());
        let mut null = source_document();
        first_payload(&mut null).insert("time_to_live_ms".into(), Value::Null);
        assert!(decode_document(null).is_err());
        let mut zero = source_document();
        first_payload(&mut zero).insert("time_to_live_ms".into(), Value::Number(Number::U64(0)));
        let entries = decode_document(zero).expect("zero TTL is structurally an integer");
        assert_eq!(
            entries[0].payload.to_builder().err().as_deref(),
            Some("time_to_live_ms must be > 0")
        );
    }
    #[test]
    fn source_schema_requires_canonical_network_id_and_rejects_chain() {
        let mut missing = source_document();
        first_payload(&mut missing).remove("network_id");
        assert!(decode_document(missing).is_err());
        let mut null = source_document();
        first_payload(&mut null).insert("network_id".into(), Value::Null);
        assert!(decode_document(null).is_err());
        let mut legacy = source_document();
        first_payload(&mut legacy).remove("network_id");
        first_payload(&mut legacy).insert("chain".into(), Value::String("00000042".into()));
        assert!(decode_document(legacy).is_err());
        let mut aliased = source_document();
        first_payload(&mut aliased).insert("chain".into(), Value::String("00000042".into()));
        assert!(decode_document(aliased).is_err());
        let mut label = source_document();
        first_payload(&mut label).insert("network_id".into(), Value::String("00000042".into()));
        assert!(decode_document(label).is_err());
        let mut noncanonical = source_document();
        first_payload(&mut noncanonical).insert(
            "network_id".into(),
            Value::String(CANONICAL_DEV_NETWORK_ID.to_ascii_lowercase()),
        );
        assert!(decode_document(noncanonical).is_err());
    }
    #[test]
    fn payload_builder_rejects_a_different_canonical_network_identity() {
        let keypair = KeyPair::try_from_seed(vec![0xCF; 32], Algorithm::Ed25519)
            .expect("seeded fixture key should derive");
        let authority = AccountId::new(keypair.public_key().clone());
        let mut payload = payload_spec(&authority, &authority);
        payload.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::prehashed([0xAB; Hash::LENGTH]),
        ));
        assert_eq!(
            payload.to_builder().err().as_deref(),
            Some(
                "network_id must be the canonical Iroha3 dev genesis identity 'hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0'"
            )
        );
    }
    #[test]
    fn source_schema_requires_metadata_object() {
        let mut missing = source_document();
        first_payload(&mut missing).remove("metadata");
        assert!(decode_document(missing).is_err());
        let mut null = source_document();
        first_payload(&mut null).insert("metadata".into(), Value::Null);
        assert!(decode_document(null).is_err());
    }
    #[test]
    fn source_schema_rejects_retired_admission_fields() {
        let _chain_guard = address::ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
        assert!(decode_document(source_document()).is_ok());
        for field in ["admission_intent", "admissionIntent"] {
            for label in ["ordinary", "queue_plan_synced"] {
                let mut retired = source_document();
                first_payload(&mut retired).insert(
                    field.into(),
                    norito::json!({"intent": label, "value": null}),
                );
                assert!(decode_document(retired).is_err(), "retired field {field}");
            }
        }
    }

    #[test]
    fn source_schema_requires_nullable_fee_gas_limit() {
        let mut missing = source_document();
        first_payload(&mut missing)
            .get_mut("fee_payment")
            .expect("fee payment")
            .as_object_mut()
            .expect("fee-payment object")
            .get_mut("value")
            .expect("fee-payment value")
            .as_object_mut()
            .expect("fee-payment value object")
            .remove("gas_limit");
        assert!(decode_document(missing).is_err());
    }
    #[test]
    fn source_executable_and_instruction_schemas_are_closed() {
        let mut source_unknown = source_document();
        first_entry(&mut source_unknown).insert("encoded".into(), Value::String("legacy".into()));
        assert!(decode_document(source_unknown).is_err());
        let mut payload_unknown = source_document();
        first_payload(&mut payload_unknown).insert("amount".into(), Value::String("1".into()));
        assert!(decode_document(payload_unknown).is_err());
        let mut fee_unknown = source_document();
        first_payload(&mut fee_unknown)
            .get_mut("fee_payment")
            .expect("fee payment")
            .as_object_mut()
            .expect("fee-payment object")
            .insert("gas_limit".into(), Value::Number(Number::U64(1)));
        assert!(decode_document(fee_unknown).is_err());
        let mut legacy_executable = source_document();
        first_payload(&mut legacy_executable)
            .get_mut("executable")
            .expect("executable")
            .as_object_mut()
            .expect("executable object")
            .insert("Ivm".into(), Value::String("AA==".into()));
        assert!(decode_document(legacy_executable).is_err());
        let mut legacy_instruction = source_document();
        first_payload(&mut legacy_instruction)
            .get_mut("executable")
            .expect("executable")
            .as_object_mut()
            .expect("executable object")
            .get_mut("Instructions")
            .expect("instructions")
            .as_array_mut()
            .expect("instructions array")[0]
            .as_object_mut()
            .expect("instruction object")
            .get_mut("arguments")
            .expect("arguments")
            .as_object_mut()
            .expect("arguments object")
            .insert("amount".into(), Value::String("1".into()));
        assert!(decode_document(legacy_instruction).is_err());
    }
    #[test]
    fn source_inventory_is_exact_and_deterministically_sorted() {
        let mut entries = decode_document(source_document()).expect("canonical source");
        entries.reverse();
        validate_fixture_inventory(&mut entries).expect("exact fixture inventory");
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            EXPECTED_FIXTURE_NAMES
        );
        entries.pop();
        assert!(validate_fixture_inventory(&mut entries).is_err());
    }
    #[test]
    fn rendering_is_deterministic_and_owns_only_manifest_and_three_blobs() {
        let _caller_chain = address::ChainDiscriminantGuard::enter(733);
        let fixtures_path = repository_root().join(DEFAULT_FIXTURES_PATH);
        let first = render_fixtures(&fixtures_path).expect("first render");
        let second = render_fixtures(&fixtures_path).expect("second render");
        assert_eq!(address::chain_discriminant(), 733);
        assert_eq!(first.files, second.files);
        assert_eq!(first.files.len(), 4);
        for relative in owned_relative_paths() {
            assert!(first.files.contains_key(&relative), "missing {relative:?}");
        }
        assert!(!first.files.contains_key(Path::new(DEFAULT_FIXTURES_PATH)));
        let manifest: Value =
            json::from_slice(&first.files[&Path::new(DEFAULT_OUT_DIR).join(DEFAULT_MANIFEST_NAME)])
                .expect("rendered manifest JSON");
        let manifest = manifest.as_object().expect("manifest object");
        assert_eq!(
            manifest.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["fixtures"]),
            "the first-release manifest has no timestamp/schema/signing-key compatibility shell"
        );
        let fixtures = manifest
            .get("fixtures")
            .expect("fixtures")
            .as_array()
            .expect("fixtures array");
        assert_eq!(fixtures.len(), 3);
        for fixture in fixtures {
            let fixture = fixture.as_object().expect("fixture object");
            assert_eq!(
                fixture.keys().map(String::as_str).collect::<BTreeSet<_>>(),
                BTreeSet::from([
                    "name",
                    "payload_base64",
                    "payload_hash",
                    "signed_base64",
                    "signed_hash",
                ]),
                "manifest entries contain only identity, canonical bytes, and their hashes"
            );
            for field in ["payload_base64", "signed_base64"] {
                let encoded = fixture[field].as_str().expect("base64 string");
                let decoded = BASE64.decode(encoded.as_bytes()).expect("canonical base64");
                assert_eq!(BASE64.encode(decoded), encoded);
            }
        }
    }
    #[test]
    fn renderer_rejects_duplicate_payload_and_signed_identities() {
        validate_distinct_fixture_identities(&identity_fixtures()).expect("distinct identities");
        let mut duplicate = identity_fixtures();
        duplicate[1].payload_bytes = duplicate[0].payload_bytes.clone();
        assert!(
            validate_distinct_fixture_identities(&duplicate)
                .unwrap_err()
                .contains("payload bytes")
        );
        let mut duplicate = identity_fixtures();
        duplicate[1].signed_bytes = duplicate[0].signed_bytes.clone();
        assert!(
            validate_distinct_fixture_identities(&duplicate)
                .unwrap_err()
                .contains("signed bytes")
        );
        let mut duplicate = identity_fixtures();
        duplicate[1].payload_hash = duplicate[0].payload_hash.clone();
        assert!(
            validate_distinct_fixture_identities(&duplicate)
                .unwrap_err()
                .contains("payload hash")
        );
        let mut duplicate = identity_fixtures();
        duplicate[1].signed_hash = duplicate[0].signed_hash.clone();
        assert!(
            validate_distinct_fixture_identities(&duplicate)
                .unwrap_err()
                .contains("signed hash")
        );
    }
    #[test]
    fn staged_write_and_read_only_check_cover_every_owned_output() {
        let stage = tempfile::tempdir().expect("stage root");
        let stage_root = canonical_temp_root(&stage);
        let source = repository_root().join(DEFAULT_FIXTURES_PATH);
        let write = Options {
            mode: Mode::Write,
            output_root: stage_root.clone(),
        };
        run_with_options(&source, &write).expect("staged write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for relative in owned_relative_paths() {
                let mode = fs::metadata(stage_root.join(relative))
                    .expect("inspect generated permissions")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o644);
            }
        }
        let check = Options {
            mode: Mode::Check,
            output_root: stage_root.clone(),
        };
        run_with_options(&source, &check).expect("staged check");
        let manifest_path = stage_root.join(Path::new(DEFAULT_OUT_DIR).join(DEFAULT_MANIFEST_NAME));
        let mut legacy_manifest: Value =
            json::from_slice(&fs::read(&manifest_path).expect("read staged manifest"))
                .expect("decode staged manifest");
        legacy_manifest
            .as_object_mut()
            .expect("manifest object")
            .insert("generated_at".into(), Value::String("legacy".into()));
        fs::write(
            &manifest_path,
            json::to_json_pretty(&legacy_manifest).expect("encode altered manifest"),
        )
        .expect("write altered manifest");
        assert!(run_with_options(&source, &check).is_err());
        run_with_options(&source, &write).expect("repair legacy manifest drift");
        let blob = stage_root.join(owned_relative_paths()[0].clone());
        fs::write(&blob, b"stale").expect("tamper staged blob");
        assert!(run_with_options(&source, &check).is_err());
    }
    #[test]
    fn check_mode_does_not_create_missing_output_directories() {
        let stage = tempfile::tempdir().expect("stage root");
        let stage_root = canonical_temp_root(&stage);
        let check = Options {
            mode: Mode::Check,
            output_root: stage_root.clone(),
        };
        assert!(run_with_options(&repository_root().join(DEFAULT_FIXTURES_PATH), &check).is_err());
        assert_eq!(fs::read_dir(stage_root).expect("read stage").count(), 0);
    }
    #[test]
    fn unexpected_owned_blob_is_rejected_and_preserved() {
        let stage = tempfile::tempdir().expect("stage root");
        let stage_root = canonical_temp_root(&stage);
        let fixtures_dir = stage_root.join(DEFAULT_OUT_DIR);
        fs::create_dir_all(&fixtures_dir).expect("create staged fixtures directory");
        let orphan = fixtures_dir.join("swift_legacy.norito");
        fs::write(&orphan, b"legacy").expect("write orphan fixture");
        let options = Options {
            mode: Mode::Write,
            output_root: stage_root,
        };
        assert!(
            run_with_options(&repository_root().join(DEFAULT_FIXTURES_PATH), &options).is_err()
        );
        assert_eq!(fs::read(orphan).expect("orphan remains"), b"legacy");
    }
    #[cfg(unix)]
    #[test]
    fn output_root_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let parent = tempfile::tempdir().expect("parent");
        let target = tempfile::tempdir().expect("target");
        let link = canonical_temp_root(&parent).join("stage-link");
        symlink(target.path(), &link).expect("create stage symlink");
        assert!(validate_output_root(&link).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn output_root_with_symlinked_ancestor_is_rejected() {
        use std::os::unix::fs::symlink;
        let parent = tempfile::tempdir().expect("parent");
        let parent_root = canonical_temp_root(&parent);
        let real = parent_root.join("real");
        let stage = real.join("stage");
        fs::create_dir_all(&stage).expect("create real staged root");
        let link = parent_root.join("alias");
        symlink(&real, &link).expect("create ancestor symlink");
        assert!(validate_output_root(&link.join("stage")).is_err());
        assert_eq!(
            validate_output_root(&stage).expect("canonical real root"),
            fs::canonicalize(stage).expect("canonical stage")
        );
    }
    #[cfg(unix)]
    #[test]
    fn nested_output_parent_symlink_is_rejected_without_external_writes() {
        use std::os::unix::fs::symlink;
        let stage = tempfile::tempdir().expect("stage root");
        let external = tempfile::tempdir().expect("external root");
        let stage_root = canonical_temp_root(&stage);
        symlink(external.path(), stage_root.join("IrohaSwift"))
            .expect("create nested output symlink");
        let options = Options {
            mode: Mode::Write,
            output_root: stage_root,
        };
        assert!(
            run_with_options(&repository_root().join(DEFAULT_FIXTURES_PATH), &options).is_err()
        );
        assert_eq!(
            fs::read_dir(external.path())
                .expect("read external root")
                .count(),
            0
        );
    }
    #[test]
    fn nested_owned_blob_is_rejected_and_preserved() {
        let stage = tempfile::tempdir().expect("stage root");
        let stage_root = canonical_temp_root(&stage);
        let nested = stage_root
            .join(DEFAULT_OUT_DIR)
            .join("nested/swift_legacy.norito");
        fs::create_dir_all(nested.parent().expect("nested parent")).expect("create nested parent");
        fs::write(&nested, b"legacy").expect("write nested orphan");
        let options = Options {
            mode: Mode::Write,
            output_root: stage_root,
        };
        assert!(
            run_with_options(&repository_root().join(DEFAULT_FIXTURES_PATH), &options).is_err()
        );
        assert_eq!(fs::read(nested).expect("nested orphan remains"), b"legacy");
    }
    #[cfg(unix)]
    #[test]
    fn orphan_scan_rejects_symlinked_subtrees_without_following_them() {
        use std::os::unix::fs::symlink;
        let stage = tempfile::tempdir().expect("stage root");
        let external = tempfile::tempdir().expect("external root");
        let stage_root = canonical_temp_root(&stage);
        let fixtures = stage_root.join(DEFAULT_OUT_DIR);
        fs::create_dir_all(&fixtures).expect("create fixtures");
        let external_orphan = external.path().join("swift_legacy.norito");
        fs::write(&external_orphan, b"external").expect("write external orphan");
        symlink(external.path(), fixtures.join("nested")).expect("create subtree symlink");
        assert!(reject_orphan_swift_blobs(&stage_root).is_err());
        assert_eq!(
            fs::read(external_orphan).expect("external orphan remains"),
            b"external"
        );
    }
    #[cfg(unix)]
    #[test]
    fn hardlinked_owned_output_is_rejected_without_replacement() {
        let stage = tempfile::tempdir().expect("stage root");
        let stage_root = canonical_temp_root(&stage);
        let source = repository_root().join(DEFAULT_FIXTURES_PATH);
        let write = Options {
            mode: Mode::Write,
            output_root: stage_root.clone(),
        };
        run_with_options(&source, &write).expect("initial staged write");
        let blob = stage_root.join(owned_relative_paths()[0].clone());
        let alias = stage_root.join("hardlink-alias.bin");
        fs::hard_link(&blob, &alias).expect("create hardlink");
        let before = fs::read(&blob).expect("read linked blob");
        let check = Options {
            mode: Mode::Check,
            output_root: stage_root.clone(),
        };
        assert!(run_with_options(&source, &check).is_err());
        assert!(run_with_options(&source, &write).is_err());
        assert_eq!(fs::read(&blob).expect("blob preserved"), before);
        assert_eq!(fs::read(alias).expect("alias preserved"), before);
    }
    #[cfg(unix)]
    #[test]
    fn orphan_scan_rejects_non_utf8_entry_names() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};
        let stage = tempfile::tempdir().expect("stage root");
        let stage_root = canonical_temp_root(&stage);
        let fixtures = stage_root.join(DEFAULT_OUT_DIR);
        fs::create_dir_all(&fixtures).expect("create fixtures");
        let invalid = OsString::from_vec(b"swift_\xff.norito".to_vec());
        let error = fixture_entry_name(invalid, &fixtures)
            .expect_err("the production name boundary must reject non-UTF-8 bytes");
        assert!(error.contains("non-UTF-8 entry"));
        let representable = OsString::from("swift_ß.norito");
        assert_eq!(
            fixture_entry_name(representable.clone(), &fixtures).expect("valid UTF-8 name"),
            "swift_ß.norito"
        );
        let unexpected = fixtures.join(representable);
        fs::write(&unexpected, b"unexpected fixture").expect("write representable entry");
        assert!(reject_orphan_swift_blobs(&stage_root).is_err());
        assert_eq!(
            fs::read(unexpected).expect("unexpected entry is preserved"),
            b"unexpected fixture"
        );
    }
    #[test]
    fn failed_publication_rolls_back_existing_and_new_outputs() {
        let stage = tempfile::tempdir().expect("stage root");
        let stage_root = canonical_temp_root(&stage);
        let rendered = render_fixtures(&repository_root().join(DEFAULT_FIXTURES_PATH))
            .expect("render fixtures");
        let owned = owned_relative_paths();
        let mut setup_directories = Vec::new();
        for relative in &owned {
            ensure_safe_parent(&stage_root, relative, &mut setup_directories)
                .expect("create output parent");
        }
        let first = stage_root.join(&owned[0]);
        fs::write(&first, b"old first output").expect("write existing preimage");
        let preimages = capture_preimages(&stage_root, &owned).expect("capture preimages");
        let error = publish_outputs_with_hook(
            &stage_root,
            &rendered,
            &owned,
            &preimages,
            &[],
            |published, _| {
                if published == 1 {
                    Err("injected second-output failure".into())
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("publication must fail");
        assert!(error.contains("restored 1 previously published output"));
        assert_eq!(
            fs::read(first).expect("old preimage restored"),
            b"old first output"
        );
        for relative in &owned[1..] {
            assert!(!stage_root.join(relative).exists());
        }
    }
    #[test]
    fn changed_preimage_is_preserved_instead_of_overwritten() {
        let stage = tempfile::tempdir().expect("stage root");
        let stage_root = canonical_temp_root(&stage);
        let relative = owned_relative_paths()[0].clone();
        let mut setup_directories = Vec::new();
        ensure_safe_parent(&stage_root, &relative, &mut setup_directories)
            .expect("create output parent");
        let path = stage_root.join(&relative);
        fs::write(&path, b"captured").expect("write captured preimage");
        let captured = read_regular_file(&path)
            .expect("read preimage")
            .expect("present");
        fs::write(&path, b"concurrent").expect("write concurrent change");
        assert!(atomic_publish(&stage_root, &relative, b"intended", Some(&captured)).is_err());
        assert_eq!(
            fs::read(path).expect("concurrent change remains"),
            b"concurrent"
        );
    }
    #[test]
    fn source_preimage_change_is_rejected_before_publication() {
        let stage = tempfile::tempdir().expect("stage root");
        let source = canonical_temp_root(&stage).join("swift-source.json");
        fs::copy(repository_root().join(DEFAULT_FIXTURES_PATH), &source)
            .expect("copy fixture source");
        let rendered = render_fixtures(&source).expect("render copied source");
        let mut changed = rendered.source_bytes.clone();
        changed.push(b'\n');
        fs::write(&source, changed).expect("change source after rendering");
        assert!(verify_source_preimage(&source, &rendered.source_bytes).is_err());
    }
    #[test]
    fn failed_publication_removes_empty_task_created_directories() {
        let stage = tempfile::tempdir().expect("stage root");
        let stage_root = canonical_temp_root(&stage);
        let rendered = render_fixtures(&repository_root().join(DEFAULT_FIXTURES_PATH))
            .expect("render fixtures");
        let owned = owned_relative_paths();
        let mut created_directories = Vec::new();
        for relative in &owned {
            ensure_safe_parent(&stage_root, relative, &mut created_directories)
                .expect("create output parents");
        }
        let preimages = capture_preimages(&stage_root, &owned).expect("capture missing preimages");
        publish_outputs_with_hook(
            &stage_root,
            &rendered,
            &owned,
            &preimages,
            &created_directories,
            |_, _| Err("injected pre-publication failure".into()),
        )
        .expect_err("publication must fail");
        assert_eq!(
            fs::read_dir(&stage_root).expect("read stage root").count(),
            0
        );
    }
    #[test]
    fn quantity_parser_rejects_noncanonical_text() {
        assert_eq!(
            parse_canonical_quantity("1.2500"),
            Err("noncanonical quantity '1.2500'".to_owned())
        );
    }
    #[test]
    fn parse_asset_definition_argument_accepts_canonical_literal() {
        let canonical = asset_definition_literal("wonderland", "rose");
        let parsed =
            parse_asset_definition_argument(&canonical).expect("canonical base58 should parse");
        assert_eq!(parsed.to_string(), canonical);
        assert!(parse_asset_definition_argument(&format!(" {canonical}")).is_err());
    }
}
