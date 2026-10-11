//! Generate canned Kagami profile bundles (genesis + PoPs + snippets) for Iroha 3 profiles.
use crate::workspace_root;
use blake2::{Blake2b512, digest::Digest};
use iroha_crypto::{Algorithm, ExposedPrivateKey, Hash, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::AssetDefinitionId,
    block::consensus::is_valid_committee_size,
    isi::SetParameter,
    parameter::{
        Parameter,
        system::{ConsensusHandshakeMetadata, SumeragiConsensusMode, consensus_metadata},
    },
    transaction::{Executable, TransactionDomain},
};
use iroha_genesis::{GenesisTopologyEntry, RawGenesisTransaction, decode_signed_genesis};
use iroha_model_base::peer::PeerId;
use iroha_primitives::addr::{SocketAddr, SocketAddrV4};
use norito::json;
use sha2::Sha256;
use std::{
    error::Error,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
};
use zeroize::Zeroizing;
#[derive(Debug, Clone)]
pub(crate) struct KagamiProfileOptions {
    pub output: PathBuf,
    pub profiles: Vec<String>,
    pub kagami_override: Option<PathBuf>,
    pub nexus_xor_asset_definition_id: Option<String>,
    pub xor_allocations_dir: PathBuf,
    pub genesis_creation_time_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProfileSpec {
    slug: &'static str,
    profile_flag: &'static str,
    chain_id: &'static str,
    chain_discriminant: Option<u16>,
    min_peers: usize,
    requires_seed: bool,
}
impl ProfileSpec {
    fn vrf_seed_hex(&self) -> String {
        hex::encode_upper(Hash::new(self.chain_id).as_ref())
    }
}
#[derive(Debug, Clone)]
struct PeerMaterial {
    peer_id: PeerId,
    address: String,
    public_key: String,
    private_key: String,
    soranet_transport_public_key: String,
    soranet_transport_private_key: String,
    streaming_public_key: String,
    streaming_private_key: String,
    pop: Vec<u8>,
    pop_hex: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateKeyRendering {
    Inline,
    RuntimeFiles,
}
fn published_private_key_rendering(spec: &ProfileSpec) -> PrivateKeyRendering {
    if spec.slug == "iroha3-dev" {
        PrivateKeyRendering::Inline
    } else {
        PrivateKeyRendering::RuntimeFiles
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenesisIdentityRendering<'a> {
    Unpublished,
    Inline(&'a str),
    SiblingFile,
    RuntimeFile,
}
fn published_genesis_identity_rendering(spec: &ProfileSpec) -> GenesisIdentityRendering<'static> {
    if spec.slug == "iroha3-dev" {
        GenesisIdentityRendering::SiblingFile
    } else {
        GenesisIdentityRendering::RuntimeFile
    }
}
struct StagedGenesis {
    manifest: RawGenesisTransaction,
    signed_wire: Vec<u8>,
    network_id: NetworkId,
}
type AnyResult<T> = Result<T, Box<dyn Error>>;
const DEFAULT_TORII_MAX_CONTENT_LEN: u64 =
    iroha_config::parameters::defaults::torii::MAX_CONTENT_LEN.0;
#[cfg(test)]
const PROFILE_GENESIS_CREATION_TIME_MS: u64 = 1_700_000_000_000;
#[cfg(test)]
const GENESIS_EXPECTED_HASH_PLACEHOLDER: &str = "REPLACE_WITH_GENESIS_EXPECTED_HASH";
const NEXUS_XOR_ASSET_DEFINITION_ID_REQUIRED: &str =
    "iroha3-nexus profile generation requires --nexus-xor-asset-definition-id <BASE58>";
fn format_toml_integer_u64(value: u64) -> String {
    let digits = value.to_string();
    let mut reversed = String::with_capacity(digits.len() + digits.len() / 3);
    for (idx, ch) in digits.chars().rev().enumerate() {
        if idx != 0 && idx % 3 == 0 {
            reversed.push('_');
        }
        reversed.push(ch);
    }
    reversed.chars().rev().collect()
}
fn account_literal_for_chain_discriminant(
    account_id: &iroha_data_model::account::AccountId,
    chain_discriminant: u16,
) -> String {
    account_id
        .to_i105_for_discriminant(chain_discriminant)
        .expect("known governance account id must render for the requested chain discriminant")
}
fn account_literal_string_for_chain_discriminant(raw: &str, chain_discriminant: u16) -> String {
    let _default_chain = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        iroha_config::parameters::defaults::common::chain_discriminant(),
    );
    let account_id = iroha_data_model::account::AccountId::parse_encoded(raw)
        .expect("known account literal must parse");
    account_literal_for_chain_discriminant(&account_id, chain_discriminant)
}
fn rendered_nexus_topology(spec: &ProfileSpec) -> &'static str {
    match spec.slug {
        "iroha3-nexus" => {
            include_str!("kagami_profiles/nexus_topology.toml")
        }
        _ => {
            include_str!("kagami_profiles/default_topology.toml")
        }
    }
}

#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct ProfileXorAllocationV1 {
    account: AccountId,
    amount: iroha_primitives::numeric::Quantity,
}
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct ProfileXorAllocationsV1 {
    version: u8,
    asset_definition_id: AssetDefinitionId,
    allocations: Vec<ProfileXorAllocationV1>,
}
fn load_profile_xor_allocations(
    spec: &ProfileSpec,
    peers: &[PeerMaterial],
    directory: &Path,
    nexus_asset: Option<&str>,
) -> AnyResult<ProfileXorAllocationsV1> {
    let path = directory.join(format!("{}.json", spec.slug));
    let metadata = fs::metadata(&path).map_err(|error| {
        format!(
            "explicit XOR genesis allocations required at {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err("XOR allocations must be a regular file no larger than 1MiB".into());
    }
    let allocations: ProfileXorAllocationsV1 = json::from_slice(&fs::read(&path)?)?;
    let expected =
        AssetDefinitionId::parse_address_literal(if spec.profile_flag == "iroha3-nexus" {
            nexus_asset.ok_or(NEXUS_XOR_ASSET_DEFINITION_ID_REQUIRED)?
        } else {
            "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
        })?;
    if allocations.version != 1
        || allocations.asset_definition_id != expected
        || allocations.allocations.is_empty()
        || allocations.allocations.len() > 4096
        || allocations
            .allocations
            .iter()
            .any(|entry| entry.amount.is_zero())
        || allocations
            .allocations
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err("XOR allocations require version1, exact network asset, and positive strictly ordered unique accounts".into());
    }
    for peer in peers {
        let account = AccountId::new(peer.peer_id.public_key().clone());
        if allocations
            .allocations
            .iter()
            .find(|entry| entry.account == account)
            .is_none_or(|entry| entry.amount < 10_000_u32.into())
        {
            return Err(format!("explicit XOR allocation for validator {account} must cover the 10000 genesis self bond").into());
        }
    }
    Ok(allocations)
}
fn apply_explicit_xor_allocations(
    manifest: RawGenesisTransaction,
    allocations: &ProfileXorAllocationsV1,
) -> AnyResult<RawGenesisTransaction> {
    use iroha_data_model::{
        account::Account,
        asset::{AssetBalancePolicy, AssetDefinition, AssetId},
        isi::{Mint, Register, RegisterBox},
        parameter::system::SumeragiNposParameters,
    };
    let effective = manifest.effective_parameters()?;
    let pinned = effective
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .ok_or("profile manifest requires committed NPoS XOR identity")?
        .xor_asset_definition_id;
    if allocations.asset_definition_id != pinned {
        return Err("explicit allocations disagree with committed XOR identity".into());
    }
    let mut accounts = std::collections::BTreeSet::new();
    let mut has_definition = false;
    for instruction in manifest.instructions() {
        if let Some(register) = instruction.as_any().downcast_ref::<RegisterBox>() {
            match register {
                RegisterBox::Account(value) => {
                    accounts.insert(value.object.id.clone());
                }
                RegisterBox::AssetDefinition(value) if value.object.id == pinned => {
                    has_definition = true;
                }
                _ => {}
            }
        }
    }
    let mut builder = manifest.into_builder().next_transaction();
    if !has_definition {
        builder = builder.append_instruction(Register::asset_definition(AssetDefinition::new(
            pinned.clone(),
            "XOR".to_owned(),
            iroha_primitives::numeric::NumericSpec::fractional(9),
            AssetBalancePolicy::Global,
            None,
        )));
    }
    for allocation in &allocations.allocations {
        if accounts.insert(allocation.account.clone()) {
            builder = builder
                .append_instruction(Register::account(Account::new(allocation.account.clone())));
        }
        builder = builder.append_instruction(Mint::asset_quantity(
            allocation.amount.clone(),
            AssetId::new(pinned.clone(), allocation.account.clone()),
        ));
    }
    Ok(builder.build_raw()?.with_consensus_meta()?)
}

pub(crate) fn generate(options: KagamiProfileOptions) -> AnyResult<()> {
    let specs = resolve_requested_profiles(&options.profiles)?;
    preflight_required_profile_inputs(
        &specs,
        options.nexus_xor_asset_definition_id.as_deref(),
        &options.xor_allocations_dir,
    )?;
    if options.genesis_creation_time_ms == 0 {
        return Err("profile genesis requires an explicit nonzero creation time".into());
    }
    let kagami_bin = resolve_kagami_path(options.kagami_override.as_deref())?;
    fs::create_dir_all(&options.output)?;
    for spec in specs {
        write_profile_bundle(
            &spec,
            &kagami_bin,
            &options.output,
            options.nexus_xor_asset_definition_id.as_deref(),
            &options.xor_allocations_dir,
            options.genesis_creation_time_ms,
        )?;
    }
    Ok(())
}
fn preflight_required_profile_inputs(
    specs: &[ProfileSpec],
    nexus_xor_asset_definition_id: Option<&str>,
    xor_allocations_dir: &Path,
) -> AnyResult<()> {
    if specs.iter().any(|spec| spec.profile_flag == "iroha3-nexus") {
        let Some(asset_definition_id) = nexus_xor_asset_definition_id else {
            return Err(NEXUS_XOR_ASSET_DEFINITION_ID_REQUIRED.into());
        };
        if asset_definition_id == "6TEAJqbb8oEPmLncoNiMRbLEK6tw" {
            return Err("public Nexus requires operator-provisioned mainnet XOR; Taira testnet identity is forbidden".into());
        }
        AssetDefinitionId::parse_address_literal(asset_definition_id).map_err(|err| {
            format!(
                "invalid --nexus-xor-asset-definition-id `{asset_definition_id}`: {err}; \
                 expected a canonical unprefixed Base58 asset definition id"
            )
        })?;
    }
    for spec in specs {
        let peers = build_peers(spec)?;
        load_profile_xor_allocations(
            spec,
            &peers,
            xor_allocations_dir,
            nexus_xor_asset_definition_id,
        )?;
    }
    Ok(())
}
fn resolve_requested_profiles(names: &[String]) -> AnyResult<Vec<ProfileSpec>> {
    if names.is_empty() {
        return Ok(PROFILES.to_vec());
    }
    let mut out = Vec::new();
    for name in names {
        if name == "all" {
            return Ok(PROFILES.to_vec());
        }
        let Some(spec) = PROFILES.iter().find(|spec| spec.slug == name.as_str()) else {
            return Err(format!(
                "unknown profile `{name}` (expected one of all,{})",
                profile_slug_list()
            )
            .into());
        };
        out.push(*spec);
    }
    Ok(out)
}
struct CapturedProfileFile {
    path: PathBuf,
    original: iroha_fs::RetainedFile,
    bytes: Zeroizing<Vec<u8>>,
}
impl CapturedProfileFile {
    fn capture(path: PathBuf, maximum: usize) -> AnyResult<Self> {
        let original = iroha_fs::RetainedFile::open_private(&path)?;
        Self::capture_opened(path, original, maximum)
    }
    fn capture_regular(path: PathBuf, maximum: usize) -> AnyResult<Self> {
        let original = iroha_fs::RetainedFile::open_regular(&path)?;
        Self::capture_opened(path, original, maximum)
    }
    fn capture_opened(
        path: PathBuf,
        mut original: iroha_fs::RetainedFile,
        maximum: usize,
    ) -> AnyResult<Self> {
        use std::io::Read as _;
        original.revalidate()?;
        let length = usize::try_from(original.file().metadata()?.len())?;
        if length == 0 || length > maximum {
            return Err("profile original is empty or exceeds its fixed bound".into());
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(length));
        original
            .file_mut()
            .take(u64::try_from(maximum)? + 1)
            .read_to_end(&mut bytes)?;
        original.revalidate()?;
        if bytes.len() != length {
            return Err("profile original changed during bounded capture".into());
        }
        Ok(Self {
            path,
            original,
            bytes,
        })
    }
    fn revalidate(&self) -> AnyResult<()> {
        self.original.revalidate()?;
        Ok(())
    }
}
struct ProfileConfigFiles<'a> {
    spec: &'a ProfileSpec,
    index: usize,
    peer: &'a PeerMaterial,
    expected_hash: &'a CapturedProfileFile,
}
impl iroha_config::base::file_source::ConfigFileSource for ProfileConfigFiles<'_> {
    fn read(
        &self,
        path: &Path,
        request: iroha_config::base::file_source::ConfigFileRequest,
    ) -> std::io::Result<Zeroizing<Vec<u8>>> {
        use iroha_config::base::file_source::ConfigFileAccess;
        let refusal = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unselected profile configuration file binding",
            )
        };
        let bytes = if path == self.expected_hash.path
            || path == Path::new("/run/iroha/genesis.expected_hash")
        {
            if request.access != ConfigFileAccess::Public {
                return Err(refusal());
            }
            self.expected_hash.original.revalidate()?;
            Zeroizing::new(self.expected_hash.bytes.to_vec())
        } else {
            // Validate the runtime projection using the exact generated transport and
            // consensus identity records. Runtime provisioning remains mandatory.
            if request.access != ConfigFileAccess::Private {
                return Err(refusal());
            }
            let prefix = format!("/run/secrets/iroha/{}-peer-{}", self.spec.slug, self.index);
            let value = if path == Path::new(&format!("{prefix}-validator-private-key")) {
                &self.peer.private_key
            } else if path == Path::new(&format!("{prefix}-soranet-private-key")) {
                &self.peer.soranet_transport_private_key
            } else if path == Path::new(&format!("{prefix}-streaming-private-key")) {
                &self.peer.streaming_private_key
            } else {
                return Err(refusal());
            };
            Zeroizing::new(value.as_bytes().to_vec())
        };
        if bytes.len() > request.maximum {
            return Err(refusal());
        }
        Ok(bytes)
    }
}
fn validate_final_profile_configs(
    spec: &ProfileSpec,
    peers: &[PeerMaterial],
    directory: &iroha_fs::PrivateDirectory,
    network: NetworkId,
) -> AnyResult<()> {
    use iroha_config::base::{read::ConfigReader, toml::TomlSource};
    // Identity bytes are from the exact newly signed artifact, not a replacement test table.
    let expected_hash =
        CapturedProfileFile::capture(directory.path().join("genesis.expected_hash"), 512)?;
    let signed = CapturedProfileFile::capture_regular(
        directory.path().join("genesis.signed.nrt"),
        iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1,
    )?;
    let manifest_original = CapturedProfileFile::capture_regular(
        directory.path().join("genesis.json"),
        iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1,
    )?;
    let manifest = RawGenesisTransaction::from_json_slice_at_path(
        &manifest_original.bytes,
        &manifest_original.path,
    )?;
    manifest_original.revalidate()?;
    for (index, peer) in peers.iter().enumerate() {
        let source = CapturedProfileFile::capture(
            directory.path().join(peer_config_file_name(index)),
            1024 * 1024,
        )?;
        let table = iroha_deploy::secret_toml::parse_table(
            std::str::from_utf8(&source.bytes)?,
            "final profile config",
        )
        .map_err(|_| "final profile config is invalid TOML")?;
        let files = ProfileConfigFiles {
            spec,
            index,
            peer,
            expected_hash: &expected_hash,
        };
        let root = ConfigReader::new()
            .without_env()
            .with_toml_source(TomlSource::new_sensitive(
                source.path.clone(),
                table,
                iroha_deploy::secret_toml::zeroize_table,
            ))
            .read_and_complete::<iroha_config::parameters::user::Root>()
            .map_err(|_| "final profile config has invalid schema")?
            .parse_with_file_source(&files)
            .map_err(|_| "final profile config has invalid node policy or selected originals")?;
        if NetworkId::from_genesis_hash(root.genesis.expected_hash) != network {
            return Err("final profile config and signed genesis identities differ".into());
        }
        iroha_deploy::genesis::staging::staged_signed_native_genesis(
            &manifest,
            &signed.bytes,
            &root,
        )
        .map_err(|_| "final profile config does not reproduce authenticated signed genesis")?;
        source.revalidate()?;
    }
    manifest_original.revalidate()?;
    signed.revalidate()?;
    expected_hash.revalidate()?;
    Ok(())
}
// tempfile 3.27 has no public constructor for adopting a natively created directory.
// Retain only this uniquely created, unpublished staging directory; keep/drop mirror
// the existing TempDir publication and automatic-cleanup lifetime.
struct PrivateProfileStaging {
    directory: Option<iroha_fs::PrivateDirectory>,
}
impl PrivateProfileStaging {
    fn directory(&self) -> &iroha_fs::PrivateDirectory {
        self.directory
            .as_ref()
            .expect("unpublished profile staging")
    }
    fn path(&self) -> &Path {
        self.directory().path()
    }
    #[must_use]
    fn keep(mut self) -> PathBuf {
        let directory = self.directory.take().expect("unpublished profile staging");
        let path = directory.path().to_path_buf();
        // Windows ancestor handles intentionally prevent directory replacement.
        // Release them before the existing publication/backup rename corridor.
        drop(directory);
        path
    }
}
impl Drop for PrivateProfileStaging {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take() {
            // Refuse cleanup when native revalidation detects substituted custody.
            if directory.revalidate().is_err() {
                return;
            }
            let path = directory.path().to_path_buf();
            drop(directory);
            // Like TempDir, failed cleanup is ignored; committed bundles are kept.
            let _ = fs::remove_dir_all(path);
        }
    }
}
fn create_profile_staging(output_root: &Path, slug: &str) -> AnyResult<PrivateProfileStaging> {
    let parent = iroha_fs::OwnerDirectory::open_or_create(output_root)?;
    let mut rng = rand_core_06::OsRng;
    for _ in 0..32 {
        let mut entropy = [0_u8; 16];
        rand_core_06::RngCore::try_fill_bytes(&mut rng, &mut entropy).map_err(|error| {
            std::io::Error::other(format!("profile staging entropy unavailable: {error}"))
        })?;
        let name = format!(".{slug}-staging-{}", hex::encode(entropy));
        match parent.create_private_child(name) {
            Ok(directory) => {
                return Ok(PrivateProfileStaging {
                    directory: Some(directory),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "profile private staging names exhausted",
    )
    .into())
}
fn write_profile_bundle(
    spec: &ProfileSpec,
    kagami_bin: &Path,
    output_root: &Path,
    nexus_xor_asset_definition_id: Option<&str>,
    xor_allocations_dir: &Path,
    genesis_creation_time_ms: u64,
) -> AnyResult<()> {
    let staging = create_profile_staging(output_root, spec.slug)?;
    let bundle_root = staging.path().to_path_buf();
    let genesis_key =
        deterministic_keypair(&format!("{}-genesis-key", spec.slug), Algorithm::Ed25519)?;
    let peers = build_peers(spec)?;
    let genesis_json = generate_genesis(
        spec,
        kagami_bin,
        genesis_key.public_key(),
        &bundle_root,
        nexus_xor_asset_definition_id,
    )?;
    let allocations = load_profile_xor_allocations(
        spec,
        &peers,
        xor_allocations_dir,
        nexus_xor_asset_definition_id,
    )?;
    let genesis_json = apply_explicit_xor_allocations(genesis_json, &allocations)?;
    let patched_genesis = inject_topology(genesis_json, &peers)?;
    let genesis_path = bundle_root.join("genesis.json");
    write_json(&genesis_path, &patched_genesis)?;
    write_peer_configs(
        spec,
        &peers,
        genesis_key.public_key(),
        staging.directory(),
        GenesisIdentityRendering::Unpublished,
        PrivateKeyRendering::Inline,
    )?;
    let config_path = bundle_root.join(peer_config_file_name(0));
    let staged_genesis = bind_staged_context(
        spec,
        kagami_bin,
        &genesis_path,
        &config_path,
        &genesis_key,
        patched_genesis,
        genesis_creation_time_ms,
    )?;
    write_json(&genesis_path, &staged_genesis.manifest)?;
    let network_id = staged_genesis.network_id.to_string();
    fs::write(
        bundle_root.join("genesis.signed.nrt"),
        staged_genesis.signed_wire,
    )?;
    fs::write(
        bundle_root.join("genesis.public_key"),
        format!("{}\n", genesis_key.public_key()),
    )?;
    staging.directory().write_atomic(
        "genesis.expected_hash",
        format!("{network_id}\n").as_bytes(),
        iroha_fs::PublishMode::Replace,
    )?;
    write_peer_configs(
        spec,
        &peers,
        genesis_key.public_key(),
        staging.directory(),
        published_genesis_identity_rendering(spec),
        published_private_key_rendering(spec),
    )?;
    validate_final_profile_configs(spec, &peers, staging.directory(), staged_genesis.network_id)?;
    let vrf_seed_hex = if spec.requires_seed {
        Some(spec.vrf_seed_hex())
    } else {
        None
    };
    let verify_out = run_verify(spec, kagami_bin, &genesis_path, vrf_seed_hex.as_deref())?;
    fs::write(bundle_root.join("verify.txt"), verify_out)?;
    let compose = render_docker_compose(spec, &peers);
    fs::write(bundle_root.join("docker-compose.yml"), compose)?;
    let readme = render_readme_with_creation_time(
        spec,
        &peers,
        genesis_key.public_key(),
        vrf_seed_hex.as_deref(),
        nexus_xor_asset_definition_id,
        genesis_creation_time_ms,
    );
    fs::write(bundle_root.join("README.md"), readme)?;
    publish_profile_bundle(staging, &output_root.join(spec.slug))?;
    Ok(())
}
fn publish_profile_bundle(staging: PrivateProfileStaging, destination: &Path) -> AnyResult<()> {
    if !destination.exists() {
        let staged_path = staging.keep();
        fs::rename(&staged_path, destination)?;
        return Ok(());
    }
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("profile destination filename is not UTF-8")?;
    let backup = destination.with_file_name(format!(".{name}.backup-{}", std::process::id()));
    if backup.exists() {
        return Err(format!(
            "refusing to replace {} while recovery backup {} exists",
            destination.display(),
            backup.display()
        )
        .into());
    }
    fs::rename(destination, &backup)?;
    let staged_path = staging.keep();
    if let Err(publish_error) = fs::rename(&staged_path, destination) {
        let restore = fs::rename(&backup, destination);
        let _ = fs::remove_dir_all(&staged_path);
        return match restore {
            Ok(()) => Err(format!(
                "failed to publish validated profile bundle {}: {publish_error}; restored previous bundle",
                destination.display()
            )
            .into()),
            Err(restore_error) => Err(format!(
                "failed to publish validated profile bundle {}: {publish_error}; previous bundle remains at {} because restoration failed: {restore_error}",
                destination.display(),
                backup.display()
            )
            .into()),
        };
    }
    fs::remove_dir_all(&backup).map_err(|err| {
        format!(
            "published {} but failed to remove recovery backup {}: {err}",
            destination.display(),
            backup.display()
        )
        .into()
    })
}
fn generate_genesis(
    spec: &ProfileSpec,
    kagami_bin: &Path,
    genesis_public_key: &iroha_crypto::PublicKey,
    workdir: &Path,
    nexus_xor_asset_definition_id: Option<&str>,
) -> AnyResult<RawGenesisTransaction> {
    let mut command = Command::new(kagami_bin);
    command.args([
        "genesis",
        "generate",
        "--profile",
        spec.profile_flag,
        "--ivm-dir",
        ".",
        "--genesis-public-key",
        &genesis_public_key.to_string(),
        "--consensus-mode",
        "npos",
    ]);
    if spec.requires_seed {
        command.args(["--vrf-seed-hex", &spec.vrf_seed_hex()]);
    }
    if spec.profile_flag == "iroha3-nexus" {
        let Some(asset_definition_id) = nexus_xor_asset_definition_id else {
            return Err(NEXUS_XOR_ASSET_DEFINITION_ID_REQUIRED.into());
        };
        command.args(["--xor-asset-definition-id", asset_definition_id]);
    }
    let output = command
        .current_dir(workdir)
        .output()
        .map_err(|err| format!("failed to run kagami: {err}"))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "kagami genesis generate failed (status {:?}):\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        )
        .into());
    }
    json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse genesis JSON: {err}").into())
}
fn inject_topology(
    manifest: RawGenesisTransaction,
    peers: &[PeerMaterial],
) -> AnyResult<RawGenesisTransaction> {
    let consensus_mode = manifest.consensus_mode();
    let chain_discriminant = manifest.chain_discriminant();
    let topology: Vec<GenesisTopologyEntry> = peers
        .iter()
        .map(|peer| GenesisTopologyEntry::new(peer.peer_id.clone(), peer.pop.clone()))
        .collect();
    let manifest = manifest
        .into_builder()
        .set_topology(topology)
        .build_raw()?
        .with_consensus_mode(consensus_mode)
        .with_consensus_meta()?
        .with_chain_discriminant(chain_discriminant);
    Ok(manifest)
}

fn write_json(path: &Path, value: &RawGenesisTransaction) -> AnyResult<()> {
    let _chain_discriminant = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        value.chain_discriminant(),
    );
    let mut rendered = json::to_json_pretty(value)?;
    rendered.push('\n');
    fs::write(path, rendered)?;
    Ok(())
}
fn bind_staged_context(
    spec: &ProfileSpec,
    kagami_bin: &Path,
    genesis_path: &Path,
    config_path: &Path,
    genesis_key: &KeyPair,
    portable_manifest: RawGenesisTransaction,
    genesis_creation_time_ms: u64,
) -> AnyResult<StagedGenesis> {
    let workdir = genesis_path
        .parent()
        .ok_or_else(|| format!("{} genesis path has no parent", spec.slug))?;
    if config_path.parent() != Some(workdir) {
        return Err(format!(
            "{} genesis and config paths must share one staging directory",
            spec.slug
        )
        .into());
    }
    let genesis_file = genesis_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} genesis filename is not UTF-8", spec.slug))?;
    let config_file = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} config filename is not UTF-8", spec.slug))?;
    let mut private_key_file = tempfile::Builder::new()
        .prefix(".kagami-genesis-key-")
        .tempfile_in(workdir)
        .map_err(|err| {
            format!(
                "failed to create owner-only {} genesis signing key: {err}",
                spec.slug
            )
        })?;
    let private_key_record = Zeroizing::new(
        format!("{}\n", ExposedPrivateKey(genesis_key.private_key().clone())).into_bytes(),
    );
    private_key_file
        .write_all(private_key_record.as_slice())
        .and_then(|()| private_key_file.as_file_mut().sync_all())
        .map_err(|err| {
            format!(
                "failed to persist owner-only {} genesis signing key: {err}",
                spec.slug
            )
        })?;
    let expected_public_key = genesis_key.public_key().to_string();
    let creation_time_ms = genesis_creation_time_ms.to_string();
    let output = Command::new(kagami_bin)
        .args(["genesis", "sign", genesis_file, "--private-key-file"])
        .arg(private_key_file.path())
        .args([
            "--expected-public-key",
            &expected_public_key,
            "--creation-time-ms",
            &creation_time_ms,
            "--config",
            config_file,
            "--bound-manifest-out",
            genesis_file,
        ])
        .current_dir(workdir)
        .output()
        .map_err(|err| format!("failed to stage {} genesis: {err}", spec.slug))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "kagami genesis sign failed while staging {} (status {:?}):\nstdout:\n{}\nstderr:\n{}",
            spec.slug,
            output.status.code(),
            stdout,
            stderr
        )
        .into());
    }
    let signed_wire = output.stdout;
    let block = decode_signed_genesis(&signed_wire)
        .map_err(|err| format!("failed to decode staged {} genesis: {err}", spec.slug))?;
    let canonical_wire = block
        .encode_wire()
        .map_err(|err| format!("failed to re-encode staged {} genesis: {err}", spec.slug))?;
    if canonical_wire != signed_wire {
        return Err(format!(
            "staged {} genesis is not canonical framed Norito",
            spec.slug
        )
        .into());
    }
    drop(canonical_wire);
    {
        let mut signatures = block.signatures();
        let signature = signatures
            .next()
            .ok_or_else(|| format!("staged {} genesis has no block signature", spec.slug))?;
        if signature.index() != 0 || signatures.next().is_some() {
            return Err(format!(
                "staged {} genesis must have exactly one block signature at index 0",
                spec.slug
            )
            .into());
        }
        signature
            .signature()
            .verify_hash(genesis_key.public_key(), block.hash())
            .map_err(|err| {
                format!(
                    "staged {} genesis block signature does not match its configured signer: {err}",
                    spec.slug
                )
            })?;
    }
    for transaction in block.external_transactions() {
        transaction.verify_signature().map_err(|err| {
            format!(
                "staged {} genesis contains an invalid transaction signature: {err}",
                spec.slug
            )
        })?;
    }
    let mut metadata = None;
    for transaction in block.external_transactions() {
        if let Executable::Instructions(batch) = transaction.instructions() {
            for instruction in batch {
                if let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>()
                    && let Parameter::Custom(custom) = set_parameter.inner()
                    && custom.id() == &consensus_metadata::handshake_meta_id()
                {
                    let decoded = custom
                        .payload()
                        .try_into_any::<ConsensusHandshakeMetadata>()
                        .map_err(|err| {
                            format!(
                                "failed to decode staged {} consensus metadata: {err}",
                                spec.slug
                            )
                        })?;
                    if metadata.replace(decoded).is_some() {
                        return Err(format!(
                            "staged {} genesis contains duplicate consensus metadata",
                            spec.slug
                        )
                        .into());
                    }
                }
            }
        }
    }
    let metadata = metadata
        .ok_or_else(|| format!("staged {} genesis omitted consensus metadata", spec.slug))?;
    if metadata.mode != SumeragiConsensusMode::Npos {
        return Err(format!(
            "staged {} genesis reported mode {}, expected NPoS",
            spec.slug, metadata.mode
        )
        .into());
    }
    if metadata.wire_protocol_version != u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION) {
        return Err(format!(
            "staged {} genesis advertised {}, expected protocol v{}",
            spec.slug,
            metadata.wire_protocol_version,
            iroha_data_model::sumeragi::PROTOCOL_VERSION
        )
        .into());
    }
    let bound_manifest = RawGenesisTransaction::from_path(genesis_path)
        .map_err(|err| format!("failed to parse bound {} genesis: {err}", spec.slug))?;
    if bound_manifest.consensus_fingerprint() != Some(metadata.consensus_fingerprint) {
        return Err(format!(
            "staged {} consensus fingerprint did not cover the bound Nexus/AMX context",
            spec.slug
        )
        .into());
    }
    let expected_batches = bound_manifest
        .clone()
        .parse()
        .map_err(|err| format!("failed to expand bound {} genesis: {err}", spec.slug))?;
    let actual_len = block.external_transactions().len();
    if expected_batches.len() != actual_len {
        return Err(format!(
            "staged {} signed transaction count differs from its bound manifest",
            spec.slug
        )
        .into());
    }
    let genesis_account = AccountId::new(genesis_key.public_key().clone());
    for (index, (expected_batch, transaction)) in expected_batches
        .iter()
        .zip(block.external_transactions())
        .enumerate()
    {
        if transaction.domain() != &TransactionDomain::Genesis
            || transaction.authority() != &genesis_account
        {
            return Err(format!(
                "staged {} transaction {index} has the wrong genesis domain or authority",
                spec.slug
            )
            .into());
        }
        let Executable::Instructions(actual_batch) = transaction.instructions() else {
            return Err(format!(
                "staged {} transaction {index} is not an instruction batch",
                spec.slug
            )
            .into());
        };
        let mut expected = expected_batch.iter();
        let mut actual = actual_batch.iter();
        loop {
            match (expected.next(), actual.next()) {
                (Some(expected), Some(actual))
                    if iroha_data_model::Encode::encode(expected)
                        == iroha_data_model::Encode::encode(actual) => {}
                (None, None) => break,
                _ => {
                    return Err(format!(
                        "staged {} transaction {index} differs from its bound manifest",
                        spec.slug
                    )
                    .into());
                }
            }
        }
    }
    iroha_core::validate_genesis_block(&block, &genesis_account)
        .map_err(|err| format!("staged {} genesis failed full validation: {err}", spec.slug))?;
    let portable_manifest =
        portable_bound_profile_manifest(portable_manifest, &bound_manifest, workdir)?;
    Ok(StagedGenesis {
        manifest: portable_manifest,
        signed_wire,
        network_id: NetworkId::from_genesis_hash(block.hash()),
    })
}
fn portable_bound_profile_manifest(
    generated_manifest: RawGenesisTransaction,
    resolved_bound_manifest: &RawGenesisTransaction,
    staging_dir: &Path,
) -> AnyResult<RawGenesisTransaction> {
    // `kagami genesis sign` resolves relative IVM paths before returning the bound manifest.
    // Keep the exact bound transactions (including deterministic NPoS bootstrap injection), but
    // restore the generated portable IVM base before publishing the prepared profile.
    if generated_manifest.chain_id() != resolved_bound_manifest.chain_id()
        || generated_manifest.chain_discriminant() != resolved_bound_manifest.chain_discriminant()
    {
        return Err(
            "generated and signer-bound profile manifests identify different chains".into(),
        );
    }
    let _chain_discriminant = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        resolved_bound_manifest.chain_discriminant(),
    );
    let generated_value = json::to_value(&generated_manifest)?;
    let generated_ivm_dir = generated_value
        .as_object()
        .and_then(|manifest| manifest.get("ivm_dir"))
        .and_then(json::Value::as_str);
    if generated_ivm_dir != Some(".") {
        return Err("generated profile manifest must use the portable `ivm_dir` value `.`".into());
    }
    let expected_fingerprint = generated_manifest
        .with_sumeragi_context_parameters(resolved_bound_manifest.sumeragi_context_parameters())
        .with_consensus_meta()?
        .consensus_fingerprint();
    if expected_fingerprint != resolved_bound_manifest.consensus_fingerprint() {
        return Err(
            "portable profile manifest fingerprint differs from the signed bound manifest".into(),
        );
    }
    let mut portable_value = json::to_value(resolved_bound_manifest)?;
    let json::Value::Object(fields) = &mut portable_value else {
        return Err("bound profile manifest must serialize as a JSON object".into());
    };
    fields.insert("ivm_dir".to_owned(), json::Value::String(".".to_owned()));
    let portable_manifest: RawGenesisTransaction = json::value::from_value(portable_value)?;
    let portable_transactions = portable_manifest.transactions();
    let resolved_transactions = resolved_bound_manifest.transactions();
    if portable_transactions.len() != resolved_transactions.len()
        || portable_transactions
            .iter()
            .zip(resolved_transactions)
            .any(|(portable, resolved)| {
                iroha_data_model::Encode::encode(portable)
                    != iroha_data_model::Encode::encode(resolved)
            })
    {
        return Err(
            "portable profile manifest transactions differ from the signed bound manifest".into(),
        );
    }
    let portable_value = json::to_value(&portable_manifest)?;
    if json_value_references_path(&portable_value, staging_dir) {
        return Err(format!(
            "portable profile manifest still references ephemeral staging directory {}",
            staging_dir.display()
        )
        .into());
    }
    Ok(portable_manifest)
}
fn json_value_references_path(value: &json::Value, directory: &Path) -> bool {
    match value {
        json::Value::String(candidate) => Path::new(candidate).starts_with(directory),
        json::Value::Array(values) => values
            .iter()
            .any(|value| json_value_references_path(value, directory)),
        json::Value::Object(fields) => fields
            .values()
            .any(|value| json_value_references_path(value, directory)),
        _ => false,
    }
}
fn run_verify(
    spec: &ProfileSpec,
    kagami_bin: &Path,
    genesis_path: &Path,
    vrf_seed_hex: Option<&str>,
) -> AnyResult<String> {
    let workdir = genesis_path
        .parent()
        .ok_or_else(|| format!("{} genesis path has no parent", spec.slug))?;
    let genesis_file = genesis_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} genesis filename is not UTF-8", spec.slug))?;
    let mut command = Command::new(kagami_bin);
    command.args([
        "verify",
        "--profile",
        spec.profile_flag,
        "--genesis",
        genesis_file,
    ]);
    if let Some(seed) = vrf_seed_hex {
        command.args(["--vrf-seed-hex", seed]);
    }
    let output = command
        .current_dir(workdir)
        .output()
        .map_err(|err| format!("failed to run kagami verify: {err}"))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "kagami verify failed (status {:?}):\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
#[cfg(test)]
fn render_config(
    spec: &ProfileSpec,
    peers: &[PeerMaterial],
    genesis_public_key: &iroha_crypto::PublicKey,
) -> String {
    render_peer_config_with_private_keys(
        spec,
        peers,
        0,
        genesis_public_key,
        published_genesis_identity_rendering(spec),
        published_private_key_rendering(spec),
    )
}
#[cfg(test)]
fn render_peer_config(
    spec: &ProfileSpec,
    peers: &[PeerMaterial],
    peer_index: usize,
    genesis_public_key: &iroha_crypto::PublicKey,
) -> String {
    render_peer_config_with_private_keys(
        spec,
        peers,
        peer_index,
        genesis_public_key,
        published_genesis_identity_rendering(spec),
        published_private_key_rendering(spec),
    )
}
fn render_peer_config_with_private_keys(
    spec: &ProfileSpec,
    peers: &[PeerMaterial],
    peer_index: usize,
    genesis_public_key: &iroha_crypto::PublicKey,
    genesis_identity_rendering: GenesisIdentityRendering<'_>,
    private_key_rendering: PrivateKeyRendering,
) -> String {
    let genesis_identity_source = match genesis_identity_rendering {
        // Unpublished authoring policy cannot claim a runtime identity. The signer binds it
        // through a genuine original provisional block, then generation validates the final cut.
        GenesisIdentityRendering::Unpublished => String::new(),
        GenesisIdentityRendering::Inline(expected_hash) => {
            format!("expected_hash = \"{expected_hash}\"")
        }
        // Published host-run profiles resolve this path relative to the generated config itself.
        GenesisIdentityRendering::SiblingFile => {
            "expected_hash_file = \"genesis.expected_hash\"".to_owned()
        }
        // Container/runtime profiles mount the independently provisioned identity at one fixed
        // public path, distinct from their private signing-key mounts.
        GenesisIdentityRendering::RuntimeFile => {
            "expected_hash_file = \"/run/iroha/genesis.expected_hash\"".to_owned()
        }
    };
    let node = peers
        .get(peer_index)
        .expect("peer config index must address signed topology");
    let (node_private_key, soranet_transport_private_key, streaming_private_key) =
        match private_key_rendering {
            PrivateKeyRendering::Inline => (
                format!("private_key = \"{}\"", node.private_key),
                format!(
                    "soranet_transport_private_key = \"{}\"",
                    node.soranet_transport_private_key
                ),
                format!("identity_private_key = \"{}\"", node.streaming_private_key),
            ),
            PrivateKeyRendering::RuntimeFiles => {
                let prefix = format!("/run/secrets/iroha/{}-peer-{peer_index}", spec.slug);
                (
                    format!("private_key_file = \"{prefix}-validator-private-key\""),
                    format!(
                        "soranet_transport_private_key_file = \"{prefix}-soranet-private-key\""
                    ),
                    format!("identity_private_key_file = \"{prefix}-streaming-private-key\""),
                )
            }
        };
    let trusted_peers = peers
        .iter()
        .map(|peer| format!("  \"{}@{}\"", peer.public_key, peer.address))
        .collect::<Vec<_>>()
        .join(",\n");
    let trusted_peers_pop = peers
        .iter()
        .map(|peer| {
            format!(
                "  {{ public_key = \"{}\", pop_hex = \"{}\" }}",
                peer.public_key, peer.pop_hex
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let chain_discriminant = spec
        .chain_discriminant
        .map_or_else(String::new, |discriminant| {
            format!("chain_discriminant = {discriminant}\n")
        });
    let governance_overrides = spec
        .chain_discriminant
        .map_or_else(String::new, |discriminant| {
            let citizenship_escrow_account = account_literal_for_chain_discriminant(
                &iroha_config::parameters::defaults::governance::citizenship_escrow_account_id(),
                discriminant,
            );
            let bond_escrow_account = account_literal_for_chain_discriminant(
                &iroha_config::parameters::defaults::governance::bond_escrow_account_id(),
                discriminant,
            );
            let slash_receiver_account = account_literal_for_chain_discriminant(
                &iroha_config::parameters::defaults::governance::slash_receiver_account_id(),
                discriminant,
            );
            let telemetry_submitters =
                iroha_config::parameters::defaults::governance::sorafs_telemetry::submitters()
                    .into_iter()
                    .map(|literal| {
                        format!(
                            "\"{}\"",
                            account_literal_string_for_chain_discriminant(&literal, discriminant)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
            format!(
                r#"
[gov]
citizenship_escrow_account = "{citizenship_escrow_account}"
bond_escrow_account = "{bond_escrow_account}"
slash_receiver_account = "{slash_receiver_account}"
viral_incentive_pool_account = "{slash_receiver_account}"
viral_escrow_account = "{slash_receiver_account}"

[gov.sorafs_telemetry]
submitters = [{telemetry_submitters}]
"#,
            )
        });
    let torii_max_content_len = format_toml_integer_u64(DEFAULT_TORII_MAX_CONTENT_LEN);
    let nexus_topology = rendered_nexus_topology(spec);
    let genesis_section_spacing = if spec.chain_discriminant.is_some() {
        "\n\n"
    } else {
        "\n"
    };
    let p2p_port = node
        .address
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .expect("generated peer material must contain a valid IPv4 port");
    let network_address =
        SocketAddr::Ipv4(SocketAddrV4::from(([0, 0, 0, 0], p2p_port))).to_literal();
    let public_ip = node
        .address
        .rsplit_once(':')
        .and_then(|(ip, _)| ip.parse::<std::net::Ipv4Addr>().ok())
        .expect("generated peer material must contain a valid IPv4 address")
        .octets();
    let network_public_address =
        SocketAddr::Ipv4(SocketAddrV4::from((public_ip, p2p_port))).to_literal();
    let torii_port = 8080_u16
        .checked_add(u16::try_from(peer_index).expect("profile peer index must fit u16"))
        .expect("profile Torii port must fit u16");
    let torii_address =
        SocketAddr::Ipv4(SocketAddrV4::from(([0, 0, 0, 0], torii_port))).to_literal();
    format!(
        r#"# Sample config for {slug} (generated via cargo xtask kagami-profiles)
chain = "{chain}"
{chain_discriminant}public_key = "{node_pk}"
{node_private_key}
soranet_transport_public_key = "{soranet_transport_pk}"
{soranet_transport_private_key}

trusted_peers = [
{trusted_peers}
]
trusted_peers_pop = [
{trusted_peers_pop}
]

[sumeragi]
role = "validator"

[network]
address = "{network_address}"
public_address = "{network_public_address}"

[torii]
address = "{torii_address}"
max_content_len = {torii_max_content_len}

[streaming]
identity_public_key = "{stream_pub}"
{streaming_private_key}

{nexus_topology}
{governance_overrides}{genesis_section_spacing}[genesis]
public_key = "{genesis_pk}"
file = "genesis.signed.nrt"
{genesis_identity_source}
"#,
        slug = spec.slug,
        chain = spec.chain_id,
        chain_discriminant = chain_discriminant,
        node_pk = node.public_key,
        node_private_key = node_private_key,
        soranet_transport_pk = node.soranet_transport_public_key,
        soranet_transport_private_key = soranet_transport_private_key,
        trusted_peers = trusted_peers,
        trusted_peers_pop = trusted_peers_pop,
        network_address = network_address,
        network_public_address = network_public_address,
        torii_address = torii_address,
        torii_max_content_len = torii_max_content_len,
        nexus_topology = nexus_topology,
        governance_overrides = governance_overrides,
        genesis_section_spacing = genesis_section_spacing,
        genesis_pk = genesis_public_key,
        genesis_identity_source = genesis_identity_source,
        stream_pub = node.streaming_public_key,
        streaming_private_key = streaming_private_key,
    )
}
fn write_peer_configs(
    spec: &ProfileSpec,
    peers: &[PeerMaterial],
    genesis_public_key: &iroha_crypto::PublicKey,
    directory: &iroha_fs::PrivateDirectory,
    genesis_identity_rendering: GenesisIdentityRendering<'_>,
    private_key_rendering: PrivateKeyRendering,
) -> AnyResult<()> {
    // The signing projection and published developer configs carry private originals.
    // Retain native private directory custody and publish mode-0600 files atomically.
    for peer_index in 0..peers.len() {
        let rendered = render_peer_config_with_private_keys(
            spec,
            peers,
            peer_index,
            genesis_public_key,
            genesis_identity_rendering,
            private_key_rendering,
        );
        directory.write_atomic(
            peer_config_file_name(peer_index),
            rendered.as_bytes(),
            iroha_fs::PublishMode::Replace,
        )?;
    }
    Ok(())
}
fn render_docker_compose(spec: &ProfileSpec, peers: &[PeerMaterial]) -> String {
    let genesis_identity_volume = match published_genesis_identity_rendering(spec) {
        GenesisIdentityRendering::SiblingFile => {
            "\n      - ./genesis.expected_hash:/config/genesis.expected_hash:ro"
        }
        GenesisIdentityRendering::RuntimeFile => {
            "\n      - ./genesis.expected_hash:/run/iroha/genesis.expected_hash:ro"
        }
        GenesisIdentityRendering::Unpublished | GenesisIdentityRendering::Inline(_) => {
            unreachable!("published profiles never carry an inline genesis identity")
        }
    };
    let runtime_secrets_volume =
        if published_private_key_rendering(spec) == PrivateKeyRendering::RuntimeFiles {
            "\n      - /run/secrets/iroha:/run/secrets/iroha:ro"
        } else {
            ""
        };
    let services = peers
        .iter()
        .enumerate()
        .map(|(peer_index, peer)| {
            let service = format!("iroha-{}-{peer_index}", spec.slug);
            let config_file = peer_config_file_name(peer_index);
            let command = r#"["iroha3d", "--sora", "--config", "/config/config.toml"]"#;
            let p2p_port = peer
                .address
                .rsplit_once(':')
                .map(|(_, port)| port)
                .expect("generated peer address must contain a port");
            let peer_ip = peer
                .address
                .rsplit_once(':')
                .map(|(ip, _)| ip)
                .expect("generated peer address must contain an IP");
            let torii_port = 8080_u16
                .checked_add(
                    u16::try_from(peer_index).expect("profile peer index must fit into u16"),
                )
                .expect("profile Torii port must fit into u16");
            format!(
                r#"  {service}:
    image: hyperledger/iroha:latest
    command: {command}
    volumes:
      - ./{config_file}:/config/config.toml:ro
      - ./genesis.json:/config/genesis.json:ro
      - ./genesis.signed.nrt:/config/genesis.signed.nrt:ro{genesis_identity_volume}{runtime_secrets_volume}
    ports:
      - "{torii_port}:{torii_port}"
      - "{p2p_port}:{p2p_port}"
    networks:
      profile:
        ipv4_address: {peer_ip}
"#,
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"version: "3.9"
services:
{services}
networks:
  profile:
    ipam:
      config:
        - subnet: 172.28.0.0/24
"#,
    )
}
fn peer_config_file_name(peer_index: usize) -> String {
    format!("peer{peer_index}.toml")
}
#[cfg(test)]
fn render_readme(
    spec: &ProfileSpec,
    peers: &[PeerMaterial],
    genesis_public_key: &iroha_crypto::PublicKey,
    vrf_seed_hex: Option<&str>,
    nexus_xor_asset_definition_id: Option<&str>,
) -> String {
    render_readme_with_creation_time(
        spec,
        peers,
        genesis_public_key,
        vrf_seed_hex,
        nexus_xor_asset_definition_id,
        PROFILE_GENESIS_CREATION_TIME_MS,
    )
}
fn render_readme_with_creation_time(
    spec: &ProfileSpec,
    peers: &[PeerMaterial],
    genesis_public_key: &iroha_crypto::PublicKey,
    vrf_seed_hex: Option<&str>,
    nexus_xor_asset_definition_id: Option<&str>,
    genesis_creation_time_ms: u64,
) -> String {
    let peer_rows = peers
        .iter()
        .enumerate()
        .map(|(idx, peer)| {
            format!(
                "- peer {idx}: public_key={pk} address={addr} pop_hex={pop}",
                idx = idx + 1,
                pk = peer.public_key,
                addr = peer.address,
                pop = peer.pop_hex
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let vrf_line = if let Some(seed) = vrf_seed_hex {
        format!("VRF seed (hex): {seed}")
    } else {
        "VRF seed: derived from chain id".to_string()
    };
    let verify_vrf_seed_arg = vrf_seed_hex
        .map(|seed| format!(" --vrf-seed-hex {seed}"))
        .unwrap_or_default();
    let chain_discriminant_line = spec.chain_discriminant.map_or_else(String::new, |value| {
        format!("- chain discriminant: {value}\n")
    });
    let nexus_regeneration_arg = if spec.profile_flag == "iroha3-nexus" {
        format!(
            " --nexus-xor-asset-definition-id {}",
            nexus_xor_asset_definition_id.unwrap_or("<BASE58>")
        )
    } else {
        String::new()
    };
    let runtime_key_note = if published_private_key_rendering(spec)
        == PrivateKeyRendering::RuntimeFiles
    {
        "\nRuntime keys:\n- Validator, SoraNet transport, and streaming private keys are not embedded. Provision the per-peer files named by each config under `/run/secrets/iroha` before starting a validator. The compose file mounts that host directory read-only and startup fails closed when a required configured file is absent.\n"
    } else {
        ""
    };
    let topology_note = match spec.slug {
        "iroha3-nexus" => {
            "- topology: 3 logical lanes (`core`, `governance`, `zk`) in the single physical `universal` dataspace\n"
        }
        _ => "",
    };

    format!(
        r#"# {slug} sample bundle

- chain id: {chain}
{chain_discriminant_line}
- {vrf_line}
- operator-provided exact genesis creation time (ms): {creation_time_ms}
- genesis public key: {genesis_pk}
{topology_note}- peers:
{peer_rows}

Files:
- genesis.json — generated with `kagami genesis generate --profile {profile}`, patched with deterministic topology+PoPs, and rebound to the exact staged Nexus/AMX context through `kagami genesis sign`
- genesis.signed.nrt — canonical signed genesis wire artifact consumed by every validator
- genesis.public_key — canonical one-line verifier key for the signed genesis artifact
- genesis.expected_hash — canonical checked `hash:<64 uppercase hex>#<CRC16>` NetworkId encoding the independently provisioned signed-header hash
- verify.txt — stdout from `kagami verify --profile {profile} --genesis genesis.json{verify_vrf_seed_arg}`
- peer0.toml through peerN.toml — canonical prepared-bundle validator configs
- docker-compose.yml — full validator committee mounting the shared genesis and per-peer configs
{runtime_key_note}
Regenerate:
- cargo xtask kagami-profiles --profile {profile}{nexus_regeneration_arg} --xor-allocations-dir <DIR> --genesis-creation-time-ms {genesis_creation_time_ms}

Kagemusha Load:
- Load is submitted through normal block transactions. This bundle provisions no separate publisher service or issuer keys.
"#,
        slug = spec.slug,
        chain = spec.chain_id,
        chain_discriminant_line = chain_discriminant_line,
        vrf_line = vrf_line,
        creation_time_ms = genesis_creation_time_ms,
        genesis_pk = genesis_public_key,
        topology_note = topology_note,
        peer_rows = peer_rows,
        profile = spec.profile_flag,
        verify_vrf_seed_arg = verify_vrf_seed_arg,
        nexus_regeneration_arg = nexus_regeneration_arg,
        runtime_key_note = runtime_key_note,
    )
}
fn build_peers(spec: &ProfileSpec) -> AnyResult<Vec<PeerMaterial>> {
    if !is_valid_committee_size(spec.min_peers) {
        return Err(format!(
            "profile {} peer count {} is not an exact Sumeragi `3f + 1` committee",
            spec.slug, spec.min_peers
        )
        .into());
    }
    (0..spec.min_peers)
        .map(|idx| {
            let seed = format!("{}-peer-{idx}", spec.slug);
            let kp = deterministic_keypair(&seed, Algorithm::BlsNormal)?;
            let streaming_kp = deterministic_keypair(
                &format!("{}-streaming-{idx}", spec.slug),
                Algorithm::Ed25519,
            )?;
            let soranet_transport_kp = deterministic_soranet_transport_keypair(spec, idx)?;
            let pop = iroha_crypto::bls_normal_pop_prove(kp.private_key()).map_err(|err| {
                format!("failed to generate deterministic BLS PoP for `{seed}`: {err}")
            })?;
            let peer_offset =
                u16::try_from(idx).map_err(|_| "profile peer index does not fit into u16")?;
            let port = 1337_u16
                .checked_add(peer_offset)
                .ok_or("profile P2P port does not fit into u16")?;
            let host_octet = 10_usize
                .checked_add(idx)
                .filter(|octet| *octet <= usize::from(u8::MAX))
                .ok_or("profile peer index does not fit into the compose subnet")?;
            let address = format!("172.28.0.{host_octet}:{port}");
            Ok(PeerMaterial {
                peer_id: PeerId::from(kp.public_key().clone()),
                address,
                public_key: kp.public_key().to_string(),
                private_key: ExposedPrivateKey(kp.private_key().clone()).to_string(),
                soranet_transport_public_key: soranet_transport_kp.public_key().to_string(),
                soranet_transport_private_key: ExposedPrivateKey(
                    soranet_transport_kp.private_key().clone(),
                )
                .to_string(),
                streaming_public_key: streaming_kp.public_key().to_string(),
                streaming_private_key: ExposedPrivateKey(streaming_kp.private_key().clone())
                    .to_string(),
                pop: pop.clone(),
                pop_hex: hex::encode(&pop),
            })
        })
        .collect()
}
fn deterministic_soranet_transport_keypair(
    spec: &ProfileSpec,
    peer_index: usize,
) -> AnyResult<KeyPair> {
    let seed_label = if peer_index == 0 {
        format!("kagami-{}-soranet-transport-v1", spec.slug)
    } else {
        format!(
            "kagami-{}-soranet-transport-v1-peer-{peer_index}",
            spec.slug
        )
    };
    let seed = Sha256::digest(seed_label.as_bytes()).to_vec();
    KeyPair::try_from_seed(seed, Algorithm::Ed25519).map_err(|err| {
        format!(
            "failed to derive deterministic Ed25519 SoraNet transport keypair for `{seed_label}`: {err}"
        )
        .into()
    })
}
fn deterministic_keypair(seed_label: &str, algorithm: Algorithm) -> AnyResult<KeyPair> {
    let mut hasher = Blake2b512::new();
    hasher.update(seed_label.as_bytes());
    let hash = hasher.finalize();
    let mut seed = Vec::with_capacity(32);
    seed.extend_from_slice(&hash[..32]);
    KeyPair::try_from_seed(seed, algorithm).map_err(|err| {
        format!(
            "failed to derive deterministic {} keypair for `{seed_label}`: {err}",
            algorithm.as_static_str()
        )
        .into()
    })
}
fn resolve_kagami_path(override_path: Option<&Path>) -> AnyResult<PathBuf> {
    if let Some(path) = override_path {
        if !path.exists() {
            return Err(format!("kagami override {} does not exist", path.display()).into());
        }
        if !path.is_file() {
            return Err(format!("kagami override {} is not a file", path.display()).into());
        }
        return path.canonicalize().map_err(|err| {
            format!("canonicalize kagami override {}: {err}", path.display()).into()
        });
    }
    let target_dir = cargo_target_dir();
    let release_candidate = target_dir
        .join("release")
        .join(format!("kagami{}", std::env::consts::EXE_SUFFIX));
    if release_candidate.exists() {
        return release_candidate.canonicalize().map_err(|err| {
            format!(
                "canonicalize release kagami binary {}: {err}",
                release_candidate.display()
            )
            .into()
        });
    }
    let debug_candidate = target_dir
        .join("debug")
        .join(format!("kagami{}", std::env::consts::EXE_SUFFIX));
    if debug_candidate.exists() {
        return debug_candidate.canonicalize().map_err(|err| {
            format!(
                "canonicalize debug kagami binary {}: {err}",
                debug_candidate.display()
            )
            .into()
        });
    }
    let status = Command::new("cargo")
        .args(["build", "-p", "iroha_kagami", "--release"])
        .status()?;
    if !status.success() {
        return Err(format!("cargo build -p iroha_kagami --release failed with {status:?}").into());
    }
    let release_candidate = target_dir
        .join("release")
        .join(format!("kagami{}", std::env::consts::EXE_SUFFIX));
    if release_candidate.exists() {
        release_candidate.canonicalize().map_err(|err| {
            format!(
                "canonicalize built kagami binary {}: {err}",
                release_candidate.display()
            )
            .into()
        })
    } else {
        Err(format!(
            "expected kagami binary at {} after build",
            release_candidate.display()
        )
        .into())
    }
}
fn cargo_target_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        let path = PathBuf::from(dir);
        if path.is_absolute() {
            path
        } else {
            workspace_root().join(path)
        }
    } else {
        workspace_root().join("target")
    }
}
const PROFILES: &[ProfileSpec] = &[
    ProfileSpec {
        slug: "iroha3-dev",
        profile_flag: "iroha3-dev",
        chain_id: "iroha3-dev.local",
        chain_discriminant: None,
        min_peers: 4,
        requires_seed: false,
    },
    ProfileSpec {
        slug: "iroha3-nexus",
        profile_flag: "iroha3-nexus",
        chain_id: "00000000-0000-0000-0000-000000000753",
        chain_discriminant: Some(753),
        min_peers: 4,
        requires_seed: true,
    },
];
fn profile_slug_list() -> String {
    PROFILES
        .iter()
        .map(|spec| spec.slug)
        .collect::<Vec<_>>()
        .join(",")
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::base::toml::TomlSource;
    use iroha_crypto::{HashOf, Signature};
    use iroha_data_model::{account::address::ChainDiscriminantGuard, block::BlockHeader};
    use tempfile::tempdir;
    trait CompleteTestGenesisBuilder {
        fn complete_for_test(self) -> Self;
    }
    impl CompleteTestGenesisBuilder for iroha_genesis::GenesisBuilder {
        fn complete_for_test(self) -> Self {
            self.with_sumeragi_context_parameters(
                iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended(),
            )
        }
    }
    fn stub_genesis() -> RawGenesisTransaction {
        iroha_genesis::GenesisBuilder::new_without_executor(
            iroha_model_base::chain::ChainId::from("stub"),
            ".",
        )
        .complete_for_test()
        .build_raw()
        .expect("complete stub genesis")
    }
    #[test]
    fn portable_bound_profile_manifest_does_not_publish_the_staging_path() {
        let staging = tempdir().expect("profile staging directory");
        let resolved_bound_manifest = iroha_genesis::GenesisBuilder::new_without_executor(
            iroha_model_base::chain::ChainId::from("stub"),
            staging.path(),
        )
        .complete_for_test()
        .build_raw()
        .expect("complete portable bound-manifest fixture")
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let portable = portable_bound_profile_manifest(
            stub_genesis(),
            &resolved_bound_manifest,
            staging.path(),
        )
        .expect("transfer signed context to portable manifest");
        let resolved_json = json::to_json_pretty(&resolved_bound_manifest)
            .expect("serialize resolved bound manifest");
        let portable_json =
            json::to_json_pretty(&portable).expect("serialize portable bound manifest");
        assert!(resolved_json.contains(&staging.path().display().to_string()));
        assert!(portable_json.contains(r#""ivm_dir": ".""#));
        assert!(!portable_json.contains(&staging.path().display().to_string()));
        let error = portable_bound_profile_manifest(
            resolved_bound_manifest.clone(),
            &resolved_bound_manifest,
            staging.path(),
        )
        .expect_err("absolute staging path must fail closed");
        assert!(error.to_string().contains("portable `ivm_dir` value `.`"));
        let leaking_bound_manifest = iroha_genesis::GenesisBuilder::new(
            iroha_model_base::chain::ChainId::from("stub"),
            staging.path().join("executor.to"),
            staging.path(),
        )
        .complete_for_test()
        .build_raw()
        .expect("complete leaking bound-manifest fixture")
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let error = portable_bound_profile_manifest(
            stub_genesis(),
            &leaking_bound_manifest,
            staging.path(),
        )
        .expect_err("any remaining staging path must fail closed");
        assert!(
            error
                .to_string()
                .contains("still references ephemeral staging directory")
        );

        let non_default_discriminant = 369;
        let generated_manifest = stub_genesis().with_chain_discriminant(non_default_discriminant);
        let resolved_bound_manifest = iroha_genesis::GenesisBuilder::new_without_executor(
            iroha_model_base::chain::ChainId::from("stub"),
            staging.path(),
        )
        .complete_for_test()
        .build_raw()
        .expect("complete non-default-discriminant fixture")
        .with_chain_discriminant(non_default_discriminant)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        portable_bound_profile_manifest(
            generated_manifest,
            &resolved_bound_manifest,
            staging.path(),
        )
        .expect("non-default chain discriminant must survive the portable projection");
    }
    fn profile_npos_manifest(
        custom: Option<iroha_data_model::parameter::CustomParameter>,
    ) -> RawGenesisTransaction {
        let mut builder = stub_genesis().into_builder();
        if let Some(custom) = custom {
            builder = builder.append_parameter(Parameter::Custom(custom));
        }
        builder
            .build_raw()
            .expect("complete NPoS profile fixture")
            .with_consensus_mode(SumeragiConsensusMode::Npos)
    }

    #[test]
    fn explicit_xor_allocations_preserve_the_committed_asset_and_consensus() {
        use iroha_data_model::{
            account::Account,
            asset::{AssetBalancePolicy, AssetDefinition, AssetId},
            isi::{InstructionBox, Mint, Register},
            parameter::system::SumeragiNposParameters,
        };
        let parameters = SumeragiNposParameters::default();
        let asset = parameters.xor_asset_definition_id.clone();
        let account = AccountId::new(
            deterministic_keypair("profile-xor-allocation", Algorithm::Ed25519)
                .expect("derive allocation fixture account")
                .public_key()
                .clone(),
        );
        let amount = iroha_primitives::numeric::Quantity::from(123_u32);
        let allocations = ProfileXorAllocationsV1 {
            version: 1,
            asset_definition_id: asset.clone(),
            allocations: vec![ProfileXorAllocationV1 {
                account: account.clone(),
                amount: amount.clone(),
            }],
        };
        let source = profile_npos_manifest(Some(parameters.into_custom_parameter()));
        let expected_consensus = source
            .clone()
            .with_consensus_meta()
            .expect("valid committed NPoS parameters")
            .consensus_fingerprint();
        let patched = apply_explicit_xor_allocations(source.clone(), &allocations)
            .expect("apply canonical XOR allocation");
        assert_eq!(patched.consensus_mode(), SumeragiConsensusMode::Npos);
        assert_eq!(patched.consensus_fingerprint(), expected_consensus);
        assert_eq!(
            patched
                .effective_parameters()
                .expect("effective patched parameters"),
            source
                .effective_parameters()
                .expect("effective source parameters")
        );
        let transactions = patched.transactions();
        assert_eq!(transactions.len(), 2);
        let expected: Vec<InstructionBox> = vec![
            Register::asset_definition(AssetDefinition::new(
                asset.clone(),
                "XOR".to_owned(),
                iroha_primitives::numeric::NumericSpec::fractional(9),
                AssetBalancePolicy::Global,
                None,
            ))
            .into(),
            Register::account(Account::new(account.clone())).into(),
            Mint::asset_quantity(amount, AssetId::new(asset, account)).into(),
        ];
        assert_eq!(
            transactions
                .last()
                .expect("allocation transaction")
                .instructions(),
            expected.as_slice()
        );
        let mut mismatched = allocations;
        mismatched.asset_definition_id = AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::parse_fully_qualified("allocation.universal")
                .expect("valid fixture asset domain"),
            "other".parse().expect("valid fixture asset name"),
        );
        let error = apply_explicit_xor_allocations(source, &mismatched)
            .expect_err("allocation asset must match the committed XOR identity");
        assert_eq!(
            error.to_string(),
            "explicit allocations disagree with committed XOR identity"
        );
    }

    #[test]
    fn profile_edits_preserve_matching_npos_payload_errors() {
        use iroha_data_model::parameter::{CustomParameter, system::SumeragiNposParameters};
        let peers = build_peers(&PROFILES[0]).expect("build deterministic profile peers");
        let staging = tempdir().expect("profile staging directory");
        let bound = stub_genesis()
            .with_consensus_meta()
            .expect("valid bound fixture consensus");
        let allocations = ProfileXorAllocationsV1 {
            version: 1,
            asset_definition_id: SumeragiNposParameters::default().xor_asset_definition_id,
            allocations: Vec::new(),
        };
        let invalid = SumeragiNposParameters {
            max_validators: 5,
            ..SumeragiNposParameters::default()
        };
        for custom in [
            CustomParameter::new(
                SumeragiNposParameters::parameter_id(),
                iroha_primitives::json::Json::new(false),
            ),
            invalid.into_custom_parameter(),
        ] {
            let expected = SumeragiNposParameters::from_custom_parameter(&custom)
                .expect_err("matching malformed or invalid NPoS payload must reject")
                .to_string();
            let manifest = profile_npos_manifest(Some(custom));
            let errors = [
                apply_explicit_xor_allocations(manifest.clone(), &allocations)
                    .expect_err("allocation edit must retain decoder error"),
                inject_topology(manifest.clone(), &peers)
                    .expect_err("topology edit must retain decoder error"),
                portable_bound_profile_manifest(manifest, &bound, staging.path())
                    .expect_err("portable edit must retain decoder error"),
            ];
            for error in errors {
                assert_eq!(
                    error.to_string(),
                    expected,
                    "an invalid matching payload cannot become missing metadata"
                );
            }
        }
    }

    #[test]
    fn profile_edits_reject_missing_committed_npos_parameters() {
        use iroha_data_model::parameter::system::SumeragiNposParameters;
        let manifest = profile_npos_manifest(None);
        let peers = build_peers(&PROFILES[0]).expect("build deterministic profile peers");
        let staging = tempdir().expect("profile staging directory");
        let bound = stub_genesis()
            .with_consensus_meta()
            .expect("valid bound fixture consensus");
        let allocations = ProfileXorAllocationsV1 {
            version: 1,
            asset_definition_id: SumeragiNposParameters::default().xor_asset_definition_id,
            allocations: Vec::new(),
        };
        assert_eq!(
            apply_explicit_xor_allocations(manifest.clone(), &allocations)
                .expect_err("allocations require an explicit committed XOR identity")
                .to_string(),
            "profile manifest requires committed NPoS XOR identity"
        );
        for error in [
            inject_topology(manifest.clone(), &peers)
                .expect_err("topology cannot invent NPoS policy"),
            portable_bound_profile_manifest(manifest, &bound, staging.path())
                .expect_err("portable projection cannot invent NPoS policy"),
        ] {
            assert_eq!(
                error.to_string(),
                "NPoS genesis requires `sumeragi_npos_parameters`"
            );
        }
    }

    #[test]
    fn peers_are_deterministic_and_populated() {
        let peers = build_peers(&PROFILES[1]).expect("build deterministic peers");
        assert_eq!(peers.len(), PROFILES[1].min_peers);
        assert!(peers.iter().all(|p| !p.pop_hex.is_empty()));
        assert_eq!(
            peers[0].peer_id.public_key(),
            build_peers(&PROFILES[1]).expect("rebuild deterministic peers")[0]
                .peer_id
                .public_key()
        );
    }
    #[test]
    fn profile_peer_builder_rejects_non_committee_sizes() {
        for count in [1_usize, 2, 3, 5, 32] {
            let spec = ProfileSpec {
                min_peers: count,
                ..PROFILES[0]
            };
            let error = build_peers(&spec).expect_err("non-committee profile must fail");
            assert!(
                error.to_string().contains("exact Sumeragi `3f + 1`"),
                "unexpected error for {count} peers: {error}"
            );
        }
    }
    #[test]
    fn topology_is_injected_into_genesis() {
        let peers = build_peers(&PROFILES[0]).expect("build deterministic peers");
        let source = stub_genesis().with_chain_discriminant(369);
        let _wrong_discriminant = ChainDiscriminantGuard::enter(753);
        let patched = inject_topology(source, &peers).expect("inject topology");
        assert_eq!(patched.chain_discriminant(), 369);
        let txs = patched.transactions();
        assert_eq!(txs.len(), 1, "stub genesis should carry one transaction");
        let tx0 = &txs[0];
        assert_eq!(
            tx0.topology().len(),
            peers.len(),
            "topology should be populated inside the manifest"
        );
        let pop_count = tx0
            .topology()
            .iter()
            .filter(|entry| entry.pop_hex.as_deref().is_some_and(|hex| !hex.is_empty()))
            .count();
        assert_eq!(
            pop_count,
            peers.len(),
            "pop_hex should be embedded for every topology entry"
        );
        let value = json::to_value(&patched).expect("serialize patched genesis");
        let tx0 = value
            .get("transactions")
            .and_then(norito::json::Value::as_array)
            .and_then(|txs| txs.first())
            .and_then(norito::json::Value::as_object)
            .expect("first transaction present");
        let topo = tx0["topology"].as_array().expect("topology array present");
        assert_eq!(topo.len(), peers.len());
        let first = topo[0].as_object().expect("topology entry object");
        assert!(first.get("pop_hex").is_some(), "pop_hex embedded");
    }
    #[test]
    fn write_json_uses_manifest_chain_discriminant_for_account_literals() {
        let account_key =
            deterministic_keypair("manifest-chain-discriminant-account", Algorithm::Ed25519)
                .expect("derive deterministic account key");
        let manifest = iroha_genesis::GenesisBuilder::new_without_executor(
            iroha_model_base::chain::ChainId::from("manifest-chain-discriminant"),
            ".",
        )
        .domain(
            iroha_model_base::domain::DomainId::try_new("accounts", "universal")
                .expect("valid fixture domain"),
        )
        .account(account_key.public_key().clone())
        .finish_domain()
        .complete_for_test()
        .build_raw()
        .expect("complete chain-discriminant fixture")
        .with_chain_discriminant(369);
        let bundle = tempdir().expect("manifest serialization directory");
        let path = bundle.path().join("genesis.json");
        let _wrong_discriminant = ChainDiscriminantGuard::enter(753);
        write_json(&path, &manifest).expect("serialize manifest with its own discriminant");
        let reloaded = RawGenesisTransaction::from_path(&path)
            .expect("account literals must decode under the manifest discriminant");
        assert_eq!(reloaded.chain_discriminant(), 369);
        assert_eq!(reloaded.instructions().count(), 2);
    }
    #[test]
    fn config_contains_expected_keys() {
        let peers = build_peers(&PROFILES[1]).expect("build deterministic peers");
        let genesis_key = deterministic_keypair("config-genesis", Algorithm::Ed25519)
            .expect("derive deterministic genesis key");
        let rendered = render_config(&PROFILES[1], &peers, genesis_key.public_key());
        assert!(rendered.contains(PROFILES[1].chain_id));
        assert!(rendered.contains("chain_discriminant = 753"));
        assert!(rendered.contains("viral_incentive_pool_account"));
        assert!(rendered.contains(peers[0].public_key.as_str()));
        assert!(rendered.contains(&genesis_key.public_key().to_string()));
        assert!(rendered.contains(&peers[0].streaming_public_key));
        assert!(!rendered.contains(&peers[0].private_key));
        assert!(!rendered.contains(&peers[0].soranet_transport_private_key));
        assert!(!rendered.contains(&peers[0].streaming_private_key));
        assert!(rendered.contains(
            "private_key_file = \"/run/secrets/iroha/iroha3-nexus-peer-0-validator-private-key\""
        ));
        assert!(rendered.contains(
            "soranet_transport_private_key_file = \"/run/secrets/iroha/iroha3-nexus-peer-0-soranet-private-key\""
        ));
        assert!(rendered.contains(
            "identity_private_key_file = \"/run/secrets/iroha/iroha3-nexus-peer-0-streaming-private-key\""
        ));
        assert!(
            !rendered.contains("round_timeout_ms"),
            "round timing is derived from the signed genesis cadence"
        );
        assert!(
            !rendered.contains("[sumeragi.npos]"),
            "NPoS policy belongs in the signed genesis parameter snapshot"
        );
        assert!(
            !rendered.contains("protocol_version"),
            "wire protocol version is derived from the signed consensus metadata"
        );
        assert!(
            !rendered.contains("[sumeragi.da]"),
            "mandatory DA policy is derived from the signed consensus metadata"
        );
    }
    #[test]
    fn rendered_profile_topologies_separate_lanes_from_dataspaces() {
        type ParsedTopology = (
            i64,
            Vec<(i64, String, String)>,
            Vec<(String, i64)>,
            Vec<(i64, String, Option<String>, Option<String>)>,
        );

        fn parsed_topology(spec: &ProfileSpec) -> ParsedTopology {
            let table = rendered_nexus_topology(spec)
                .parse::<toml::Table>()
                .expect("rendered Nexus topology must be valid TOML");
            let nexus = table
                .get("nexus")
                .and_then(toml::Value::as_table)
                .expect("rendered topology must contain [nexus]");
            let lane_count = nexus
                .get("lane_count")
                .and_then(toml::Value::as_integer)
                .expect("rendered topology must declare lane_count");
            let lanes = nexus
                .get("lane_catalog")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .map(|lane| {
                    let lane = lane.as_table().expect("lane catalog entry must be a table");
                    (
                        lane.get("index")
                            .and_then(toml::Value::as_integer)
                            .expect("lane entry must have an index"),
                        lane.get("alias")
                            .and_then(toml::Value::as_str)
                            .expect("lane entry must have an alias")
                            .to_owned(),
                        lane.get("dataspace")
                            .and_then(toml::Value::as_str)
                            .expect("lane entry must bind a dataspace")
                            .to_owned(),
                    )
                })
                .collect();
            let dataspaces = nexus
                .get("dataspace_catalog")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .map(|dataspace| {
                    let dataspace = dataspace
                        .as_table()
                        .expect("dataspace catalog entry must be a table");
                    (
                        dataspace
                            .get("alias")
                            .and_then(toml::Value::as_str)
                            .expect("dataspace entry must have an alias")
                            .to_owned(),
                        dataspace
                            .get("id")
                            .and_then(toml::Value::as_integer)
                            .expect("dataspace entry must have an id"),
                    )
                })
                .collect();
            let rules = nexus
                .get("routing_policy")
                .and_then(toml::Value::as_table)
                .and_then(|routing| routing.get("rules"))
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .map(|rule| {
                    let rule = rule.as_table().expect("routing rule must be a table");
                    let matcher = rule
                        .get("matcher")
                        .and_then(toml::Value::as_table)
                        .expect("routing rule must contain a matcher");
                    (
                        rule.get("lane")
                            .and_then(toml::Value::as_integer)
                            .expect("routing rule must name a lane"),
                        rule.get("dataspace")
                            .and_then(toml::Value::as_str)
                            .expect("routing rule must name a dataspace")
                            .to_owned(),
                        matcher
                            .get("account")
                            .and_then(toml::Value::as_str)
                            .map(str::to_owned),
                        matcher
                            .get("instruction")
                            .and_then(toml::Value::as_str)
                            .map(str::to_owned),
                    )
                })
                .collect();
            (lane_count, lanes, dataspaces, rules)
        }

        let (lane_count, lanes, dataspaces, rules) = parsed_topology(&PROFILES[1]);
        assert_eq!(lane_count, 3);
        assert_eq!(
            lanes,
            [
                (0, "core".to_owned(), "universal".to_owned()),
                (1, "governance".to_owned(), "universal".to_owned()),
                (2, "zk".to_owned(), "universal".to_owned()),
            ]
        );
        assert_eq!(dataspaces, [("universal".to_owned(), 0)]);
        assert_eq!(
            rules,
            [
                (
                    1,
                    "universal".to_owned(),
                    None,
                    Some("governance".to_owned()),
                ),
                (
                    2,
                    "universal".to_owned(),
                    None,
                    Some("smartcontract::deploy".to_owned()),
                ),
            ]
        );

        let (lane_count, lanes, dataspaces, rules) = parsed_topology(&PROFILES[0]);
        assert_eq!(lane_count, 3);
        assert!(lanes.is_empty());
        assert!(dataspaces.is_empty());
        assert!(rules.is_empty());
    }

    #[test]
    fn checked_in_dev_profile_peer_configs_match_the_generator() {
        let spec = &PROFILES[0];
        assert_eq!(spec.slug, "iroha3-dev");
        let peers = build_peers(spec).expect("build deterministic dev peers");
        let genesis_key =
            deterministic_keypair(&format!("{}-genesis-key", spec.slug), Algorithm::Ed25519)
                .expect("derive the dev profile genesis key");
        for peer_index in 0..peers.len() {
            let path = workspace_root()
                .join("defaults/kagami")
                .join(spec.slug)
                .join(peer_config_file_name(peer_index));
            let checked_in = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            assert_eq!(
                checked_in,
                render_peer_config(spec, &peers, peer_index, genesis_key.public_key()),
                "{} must equal its `cargo xtask kagami-profiles` rendering",
                path.display()
            );
        }
    }

    #[test]
    fn checked_in_profile_topologies_match_the_generator() {
        for spec in [&PROFILES[1]] {
            let expected = rendered_nexus_topology(spec)
                .parse::<toml::Table>()
                .expect("rendered topology must be valid TOML");
            let checked_in_path = workspace_root()
                .join("defaults/kagami")
                .join(spec.slug)
                .join("config.toml");
            let checked_in = fs::read_to_string(&checked_in_path)
                .unwrap_or_else(|error| panic!("read {}: {error}", checked_in_path.display()))
                .parse::<toml::Table>()
                .unwrap_or_else(|error| panic!("parse {}: {error}", checked_in_path.display()));
            let expected_nexus = expected
                .get("nexus")
                .and_then(toml::Value::as_table)
                .expect("rendered topology must contain [nexus]");
            let checked_in_nexus = checked_in
                .get("nexus")
                .and_then(toml::Value::as_table)
                .expect("checked-in profile must contain [nexus]");
            for key in [
                "lane_count",
                "lane_catalog",
                "dataspace_catalog",
                "routing_policy",
            ] {
                assert_eq!(
                    checked_in_nexus.get(key),
                    expected_nexus.get(key),
                    "checked-in {} {key} must match its generator",
                    spec.slug
                );
            }
        }
    }

    #[test]
    fn rendered_profile_configs_pass_actual_config_admission() {
        use iroha_config::base::{
            file_source::{ConfigFileAccess, ConfigFileRequest, ConfigFileSource},
            read::ConfigReader,
        };
        use iroha_config::parameters::user::Root as UserConfig;

        // Fully inline authoring policy must not open any external private file.
        struct UnavailableProfileFiles {
            calls: std::cell::Cell<usize>,
        }
        impl ConfigFileSource for UnavailableProfileFiles {
            fn read(
                &self,
                _path: &Path,
                request: ConfigFileRequest,
            ) -> std::io::Result<Zeroizing<Vec<u8>>> {
                self.calls.set(self.calls.get() + 1);
                assert_eq!(request.access, ConfigFileAccess::Private);
                Err(std::io::ErrorKind::PermissionDenied.into())
            }
        }
        let expected_hash =
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"xtask profile config admission",
            )))
            .to_string();
        for profile in PROFILES {
            let peers = build_peers(profile).expect("build deterministic peers");
            let genesis_key = deterministic_keypair(
                &format!("config-{}-admission-genesis", profile.slug),
                Algorithm::Ed25519,
            )
            .expect("derive deterministic genesis key");
            let rendered = render_peer_config_with_private_keys(
                profile,
                &peers,
                0,
                genesis_key.public_key(),
                GenesisIdentityRendering::Inline(&expected_hash),
                PrivateKeyRendering::Inline,
            );
            let table = rendered
                .parse::<toml::Table>()
                .expect("rendered profile config is valid TOML");
            let bundle = tempdir().expect("profile config admission directory");
            let path = bundle.path().join("peer0.toml");
            assert!(
                !table.contains_key("kagemusha_load_authorizer"),
                "ordinary profile {} must not select an issuer role",
                profile.slug
            );
            let parser_files = UnavailableProfileFiles {
                calls: std::cell::Cell::new(0),
            };
            let parse = |table: toml::Table| {
                ConfigReader::new()
                    .without_env()
                    .with_toml_source(TomlSource::new(path.clone(), table))
                    .read_and_complete::<UserConfig>()
                    .map_err(|error| format!("{error:?}"))?
                    .parse_with_file_source(&parser_files)
                    .map_err(|error| format!("{error:?}"))
            };
            let _chain_discriminant = profile
                .chain_discriminant
                .map(ChainDiscriminantGuard::enter);
            parse(table.clone()).unwrap_or_else(|error| {
                panic!(
                    "rendered profile {} must pass bounded config parsing: {error:?}",
                    profile.slug
                )
            });
            assert_eq!(parser_files.calls.get(), 0);
            for retired in ["block", "queues"] {
                let mut retired_config = table.clone();
                retired_config
                    .get_mut("sumeragi")
                    .and_then(toml::Value::as_table_mut)
                    .expect("node-local Sumeragi config")
                    .insert(retired.to_owned(), toml::Value::Table(toml::Table::new()));
                assert!(
                    parse(retired_config).is_err(),
                    "profile {} must reject retired sumeragi.{retired} configuration",
                    profile.slug
                );
            }
            assert_eq!(parser_files.calls.get(), 0);
            parse(table).expect("same inline config must remain admissible");
        }
    }
    #[test]
    fn unpublished_configs_do_not_claim_a_runtime_genesis_identity() {
        for profile in PROFILES {
            let peers = build_peers(profile).expect("build deterministic peers");
            let genesis_key = deterministic_keypair(
                &format!("config-{}-bootstrap-genesis", profile.slug),
                Algorithm::Ed25519,
            )
            .expect("derive deterministic genesis key");
            let rendered = render_peer_config_with_private_keys(
                profile,
                &peers,
                0,
                genesis_key.public_key(),
                GenesisIdentityRendering::Unpublished,
                PrivateKeyRendering::Inline,
            );
            assert!(!rendered.contains("expected_hash ="));
            assert!(!rendered.contains("expected_hash_file"));
        }
    }
    #[test]
    fn published_profiles_decouple_genesis_identity_from_private_key_sources() {
        for profile in PROFILES {
            let peers = build_peers(profile).expect("build deterministic peers");
            let genesis_key = deterministic_keypair(
                &format!("config-{}-published-genesis", profile.slug),
                Algorithm::Ed25519,
            )
            .expect("derive deterministic genesis key");
            let rendered = render_config(profile, &peers, genesis_key.public_key());
            assert!(!rendered.contains("expected_hash ="));
            assert!(!rendered.contains(GENESIS_EXPECTED_HASH_PLACEHOLDER));
            if profile.slug == "iroha3-dev" {
                assert!(rendered.contains("expected_hash_file = \"genesis.expected_hash\""));
                assert!(rendered.contains(&peers[0].private_key));
                assert!(rendered.contains(&peers[0].soranet_transport_private_key));
                assert!(rendered.contains(&peers[0].streaming_private_key));
                assert!(!rendered.contains("private_key_file"));
            } else {
                assert!(
                    rendered.contains("expected_hash_file = \"/run/iroha/genesis.expected_hash\"")
                );
                for peer in &peers {
                    assert!(!rendered.contains(&peer.private_key));
                    assert!(!rendered.contains(&peer.soranet_transport_private_key));
                    assert!(!rendered.contains(&peer.streaming_private_key));
                }
                assert!(rendered.contains("private_key_file = \"/run/secrets/iroha/"));
                assert!(
                    rendered.contains("soranet_transport_private_key_file = \"/run/secrets/iroha/")
                );
                assert!(rendered.contains("identity_private_key_file = \"/run/secrets/iroha/"));
            }
        }
    }
    #[test]
    fn final_peer_configs_use_only_canonical_prepared_names() {
        let peers = build_peers(&PROFILES[0]).expect("build deterministic peers");
        let genesis_key = deterministic_keypair("prepared-config-genesis", Algorithm::Ed25519)
            .expect("derive deterministic genesis key");
        let parent = tempdir().expect("prepared config parent");
        let bundle = create_profile_staging(parent.path(), "prepared-config")
            .expect("create native private config bundle");
        write_peer_configs(
            &PROFILES[0],
            &peers,
            genesis_key.public_key(),
            bundle.directory(),
            GenesisIdentityRendering::SiblingFile,
            PrivateKeyRendering::Inline,
        )
        .expect("write prepared validator configs");
        for peer_index in 0..peers.len() {
            let prepared =
                fs::read_to_string(bundle.path().join(peer_config_file_name(peer_index)))
                    .expect("read prepared config");
            assert!(prepared.contains("expected_hash_file = \"genesis.expected_hash\""));
            assert!(!prepared.contains("expected_hash ="));
            assert!(!prepared.contains(GENESIS_EXPECTED_HASH_PLACEHOLDER));
        }
        assert!(
            fs::read_dir(bundle.path())
                .expect("list prepared config bundle")
                .all(|entry| !entry
                    .expect("read prepared entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with("config")),
            "compatibility config names must not be emitted"
        );
    }
    #[test]
    fn native_profile_staging_keeps_both_config_passes_private_and_cleans_unpublished_files() {
        let parent = tempdir().expect("ordinary profile parent");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // An ordinary existing reader-accessible parent must never be hardened.
            fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let bundle = create_profile_staging(parent.path(), "native-staging-test")
            .expect("create native private staging under ordinary parent");
        bundle
            .directory()
            .revalidate()
            .expect("native private custody");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(parent.path()).unwrap().permissions().mode() & 0o7777,
                0o755
            );
            assert_eq!(
                fs::metadata(bundle.path()).unwrap().permissions().mode() & 0o7777,
                0o700
            );
        }
        let peers = build_peers(&PROFILES[0]).expect("build existing test peers");
        let genesis_key = deterministic_keypair("native-staging-genesis", Algorithm::Ed25519)
            .expect("derive existing test genesis key");
        for identity in [
            GenesisIdentityRendering::Unpublished,
            GenesisIdentityRendering::SiblingFile,
        ] {
            write_peer_configs(
                &PROFILES[0],
                &peers,
                genesis_key.public_key(),
                bundle.directory(),
                identity,
                PrivateKeyRendering::Inline,
            )
            .expect("write first and second private config passes");
            for peer_index in 0..peers.len() {
                let path = bundle.path().join(peer_config_file_name(peer_index));
                assert_eq!(
                    fs::read_to_string(&path).unwrap(),
                    render_peer_config_with_private_keys(
                        &PROFILES[0],
                        &peers,
                        peer_index,
                        genesis_key.public_key(),
                        identity,
                        PrivateKeyRendering::Inline,
                    ),
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    assert_eq!(
                        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
                        0o600
                    );
                }
            }
        }
        let unpublished = bundle.path().to_path_buf();
        drop(bundle);
        assert!(
            !unpublished.exists(),
            "unpublished staging must be cleaned on drop"
        );
        assert!(parent.path().exists(), "existing parent must be preserved");
    }
    #[test]
    fn native_profile_staging_publication_keeps_committed_files_after_handle_release() {
        let parent = tempdir().expect("native publication parent");
        let destination = parent.path().join("published-native-profile");
        let staging = create_profile_staging(parent.path(), "native-publication-test")
            .expect("create native private stage");
        staging
            .directory()
            .write_atomic(
                "published-data",
                b"kept published DATA",
                iroha_fs::PublishMode::CreateNew,
            )
            .expect("write native publication DATA");
        let old_staging = staging.path().to_path_buf();
        publish_profile_bundle(staging, &destination)
            .expect("publish after native handles release");
        assert!(!old_staging.exists());
        assert_eq!(
            fs::read(destination.join("published-data")).unwrap(),
            b"kept published DATA"
        );
        iroha_fs::PrivateDirectory::open(&destination)
            .expect("committed directory retains native private custody");
    }

    #[cfg(unix)]
    #[test]
    fn peer_config_writer_keeps_private_modes_and_refuses_aliases() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let peers = build_peers(&PROFILES[0]).expect("build deterministic peers");
        let genesis_key = deterministic_keypair("private-config-genesis", Algorithm::Ed25519)
            .expect("derive existing test genesis key");
        let parent = tempdir().expect("private config parent");
        let bundle = create_profile_staging(parent.path(), "private-config")
            .expect("create native private config bundle");
        let write = || {
            write_peer_configs(
                &PROFILES[0],
                &peers,
                genesis_key.public_key(),
                bundle.directory(),
                GenesisIdentityRendering::SiblingFile,
                PrivateKeyRendering::Inline,
            )
        };
        for _ in 0..2 {
            write().expect("create or atomically replace private configs");
            for peer_index in 0..peers.len() {
                let path = bundle.path().join(peer_config_file_name(peer_index));
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                assert_eq!(
                    fs::read_to_string(&path).unwrap(),
                    render_peer_config_with_private_keys(
                        &PROFILES[0],
                        &peers,
                        peer_index,
                        genesis_key.public_key(),
                        GenesisIdentityRendering::SiblingFile,
                        PrivateKeyRendering::Inline,
                    ),
                );
            }
        }
        let original = bundle.path().join("original-custody");
        fs::write(&original, b"retained parser-test original").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        let target = bundle.path().join(peer_config_file_name(0));
        fs::remove_file(&target).unwrap();
        symlink(&original, &target).unwrap();
        assert!(
            write().is_err(),
            "a config symlink must not replace original custody"
        );
        assert_eq!(
            fs::read(&original).unwrap(),
            b"retained parser-test original"
        );
        assert!(
            fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&target).unwrap();
        fs::hard_link(&original, &target).unwrap();
        assert!(write().is_err(), "shared originals must not be replaced");
        assert_eq!(
            fs::read(&original).unwrap(),
            b"retained parser-test original"
        );
        assert_eq!(fs::read(&target).unwrap(), b"retained parser-test original");
        fs::remove_file(&target).unwrap();
        fs::write(&target, b"existing public config").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            write().is_err(),
            "public private-config custody must be refused"
        );
        assert_eq!(fs::read(&target).unwrap(), b"existing public config");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn readme_carries_profile_metadata() {
        let peers = build_peers(&PROFILES[0]).expect("build deterministic peers");
        let genesis_key = deterministic_keypair("readme-genesis", Algorithm::Ed25519)
            .expect("derive deterministic genesis key");
        let readme = render_readme(&PROFILES[0], &peers, genesis_key.public_key(), None, None);
        assert!(readme.contains(PROFILES[0].slug));
        assert!(readme.contains("Regenerate"));
        assert!(readme.contains("genesis.public_key"));
        assert!(readme.contains("genesis.expected_hash"));
        assert!(readme.contains("peer0.toml through peerN.toml"));
        assert!(readme.contains(&format!(
            "cargo xtask kagami-profiles --profile iroha3-dev --xor-allocations-dir <DIR> --genesis-creation-time-ms {PROFILE_GENESIS_CREATION_TIME_MS}\n"
        )));
        assert!(!readme.contains("--nexus-xor-asset-definition-id"));
        assert!(readme.contains("Load is submitted through normal block transactions"));
    }
    #[test]
    fn rendered_dev_text_preserves_canonical_spacing() {
        let genesis_key = deterministic_keypair("canonical-spacing-genesis", Algorithm::Ed25519)
            .expect("derive deterministic genesis key");
        let dev_peers = build_peers(&PROFILES[0]).expect("build deterministic dev peers");
        let dev_readme = render_readme(
            &PROFILES[0],
            &dev_peers,
            genesis_key.public_key(),
            None,
            None,
        );
        assert!(dev_readme.contains(&format!(
            "- genesis public key: {}\n- peers:\n",
            genesis_key.public_key()
        )));
        assert!(dev_readme.contains(
            "- docker-compose.yml — full validator committee mounting the shared genesis and per-peer configs\n\nRegenerate:"
        ));
        let dev_config = render_config(&PROFILES[0], &dev_peers, genesis_key.public_key());
        assert!(dev_config.contains("lane_count = 3\n\n\n[genesis]"));
        assert!(!dev_config.contains("lane_count = 3\n\n\n\n[genesis]"));
    }
    #[test]
    fn nexus_readme_regeneration_includes_asset_definition_id() {
        let peers = build_peers(&PROFILES[1]).expect("build deterministic peers");
        let genesis_key = deterministic_keypair("readme-nexus-genesis", Algorithm::Ed25519)
            .expect("derive deterministic genesis key");
        let readme = render_readme(
            &PROFILES[1],
            &peers,
            genesis_key.public_key(),
            Some("ABCD"),
            Some("xor-definition-id"),
        );
        assert!(readme.contains(
            "cargo xtask kagami-profiles --profile iroha3-nexus \
             --nexus-xor-asset-definition-id xor-definition-id --xor-allocations-dir <DIR>"
        ));
        assert!(readme.contains("3 logical lanes (`core`, `governance`, `zk`)"));
        assert!(readme.contains("single physical `universal` dataspace"));
    }
    #[test]
    fn nexus_requirement_is_preflighted_before_all_profile_mutation() {
        let temp = tempdir().expect("temp dir");
        let output = temp.path().join("profiles");
        let kagami = temp.path().join("kagami");
        fs::write(&kagami, b"unused test executable").expect("write dummy kagami file");
        for profile in PROFILES {
            let bundle = output.join(profile.slug);
            fs::create_dir_all(&bundle).expect("create existing profile bundle");
            fs::write(bundle.join("sentinel"), profile.slug).expect("write profile sentinel");
        }
        let error = generate(KagamiProfileOptions {
            output: output.clone(),
            profiles: vec!["all".to_owned()],
            kagami_override: Some(kagami),
            nexus_xor_asset_definition_id: None,
            xor_allocations_dir: temp.path().join("missing-allocations"),
            genesis_creation_time_ms: PROFILE_GENESIS_CREATION_TIME_MS,
        })
        .expect_err("all-profile generation without the Nexus XOR id must fail");
        assert_eq!(error.to_string(), NEXUS_XOR_ASSET_DEFINITION_ID_REQUIRED);
        for profile in PROFILES {
            assert_eq!(
                fs::read_to_string(output.join(profile.slug).join("sentinel"))
                    .expect("pre-existing profile sentinel must remain"),
                profile.slug
            );
        }
    }
    #[test]
    fn validated_profile_publication_replaces_the_directory_without_mixing_files() {
        let temp = tempdir().expect("profile publication root");
        let destination = temp.path().join("iroha3-dev");
        fs::create_dir(&destination).expect("create previous bundle");
        fs::write(destination.join("old-only"), b"old").expect("write previous bundle");
        let staging = create_profile_staging(temp.path(), "profile-publication-test")
            .expect("create native private staged bundle");
        fs::write(staging.path().join("new-only"), b"new").expect("write staged bundle");
        publish_profile_bundle(staging, &destination).expect("publish validated bundle");
        assert_eq!(
            fs::read(destination.join("new-only")).expect("read published file"),
            b"new"
        );
        assert!(!destination.join("old-only").exists());
        assert!(
            fs::read_dir(temp.path())
                .expect("read publication root")
                .all(|entry| {
                    !entry
                        .expect("read publication entry")
                        .file_name()
                        .to_string_lossy()
                        .contains(".backup-")
                }),
            "successful publication must remove its recovery backup"
        );
    }
    #[cfg(unix)]
    #[test]
    fn retained_profile_original_rejects_empty_oversize_public_links_and_replacement() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let parent = tempdir().unwrap();
        let directory =
            iroha_fs::PrivateDirectory::open_or_create(parent.path().join("private-inputs"))
                .unwrap();
        let path = directory.path().join("profile-DATA");
        directory
            .write_atomic(
                "profile-DATA",
                b"DATA-only",
                iroha_fs::PublishMode::CreateNew,
            )
            .unwrap();
        let retained = CapturedProfileFile::capture(path.clone(), 16).unwrap();
        assert_eq!(retained.bytes.as_slice(), b"DATA-only");
        assert!(CapturedProfileFile::capture(path.clone(), 8).is_err());
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(CapturedProfileFile::capture(link, 16).is_err());
        let hardlink = directory.path().join("hardlink");
        fs::hard_link(&path, &hardlink).unwrap();
        assert!(CapturedProfileFile::capture(path.clone(), 16).is_err());
        fs::remove_file(hardlink).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(CapturedProfileFile::capture(path.clone(), 16).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        directory
            .write_atomic("profile-DATA", b"replaced", iroha_fs::PublishMode::Replace)
            .unwrap();
        assert!(retained.revalidate().is_err());
        directory
            .write_atomic("empty", b"", iroha_fs::PublishMode::CreateNew)
            .unwrap();
        assert!(CapturedProfileFile::capture(directory.path().join("empty"), 16).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn retained_profile_original_refuses_same_inode_same_length_content_change() {
        let parent = tempdir().unwrap();
        let directory =
            iroha_fs::PrivateDirectory::open_or_create(parent.path().join("private-inputs"))
                .unwrap();
        directory
            .write_atomic(
                "original-DATA",
                b"ORIG-DATA",
                iroha_fs::PublishMode::CreateNew,
            )
            .unwrap();
        let path = directory.path().join("original-DATA");
        let retained = CapturedProfileFile::capture_opened(
            path.clone(),
            directory.open_retained_private("original-DATA").unwrap(),
            16,
        )
        .unwrap();
        retained.revalidate().unwrap();
        let identity = retained.original.identity().unwrap();
        let mut writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all(b"EDIT-DATA").unwrap();
        writer.sync_all().unwrap();
        assert_eq!(retained.original.identity().unwrap(), identity);
        assert_eq!(retained.original.file().metadata().unwrap().len(), 9);
        assert_eq!(retained.bytes.as_slice(), b"ORIG-DATA");
        assert!(retained.revalidate().is_err());
    }
    #[test]
    fn invalid_nexus_identity_is_preflighted_before_profile_mutation() {
        let temp = tempdir().expect("temp dir");
        let output = temp.path().join("profiles");
        let bundle = output.join(PROFILES[1].slug);
        fs::create_dir_all(&bundle).expect("create existing Nexus bundle");
        fs::write(bundle.join("sentinel"), b"preserve").expect("write Nexus sentinel");
        let error = generate(KagamiProfileOptions {
            output: output.clone(),
            profiles: vec![PROFILES[1].slug.to_owned()],
            kagami_override: Some(temp.path().join("unused-kagami")),
            nexus_xor_asset_definition_id: Some("xor#universal".to_owned()),
            xor_allocations_dir: temp.path().join("missing-allocations"),
            genesis_creation_time_ms: PROFILE_GENESIS_CREATION_TIME_MS,
        })
        .expect_err("invalid Nexus XOR identity must fail before output mutation");
        assert!(
            error
                .to_string()
                .contains("invalid --nexus-xor-asset-definition-id"),
            "unexpected preflight error: {error}"
        );
        assert_eq!(
            fs::read(bundle.join("sentinel")).expect("Nexus sentinel must remain"),
            b"preserve"
        );
    }
    #[test]
    fn deterministic_keypair_uses_checked_seed_expansion() {
        let keypair = deterministic_keypair("checked-seed-expansion", Algorithm::Ed25519)
            .expect("derive deterministic keypair");
        let signature = Signature::try_new(keypair.private_key(), b"kagami profile fixture")
            .expect("checked deterministic key signs fixture message");
        signature
            .verify(keypair.public_key(), b"kagami profile fixture")
            .expect("checked deterministic signature verifies");
    }
    #[test]
    fn relative_kagami_override_is_canonicalized_before_staged_chdir() {
        let current_dir = std::env::current_dir().expect("current directory");
        let temp = tempfile::tempdir_in(&current_dir).expect("temp dir under current directory");
        let kagami = temp.path().join("kagami-test-bin");
        fs::write(&kagami, b"test executable placeholder").expect("write kagami placeholder");
        let relative = kagami
            .strip_prefix(&current_dir)
            .expect("temporary kagami is below current directory");
        let resolved = resolve_kagami_path(Some(relative)).expect("resolve relative override");
        assert!(resolved.is_absolute());
        assert_eq!(
            resolved,
            kagami.canonicalize().expect("canonical temporary kagami")
        );
    }
    #[test]
    fn all_profile_configs_pin_default_torii_max_content_len() {
        let expected = format!(
            "max_content_len = {}",
            format_toml_integer_u64(DEFAULT_TORII_MAX_CONTENT_LEN)
        );
        for profile in PROFILES {
            let peers = build_peers(profile).expect("build deterministic peers");
            let seed = format!("config-{}-genesis", profile.slug);
            let genesis_key = deterministic_keypair(&seed, Algorithm::Ed25519)
                .expect("derive deterministic genesis key");
            let rendered = render_config(profile, &peers, genesis_key.public_key());
            assert!(
                rendered.contains(&expected),
                "profile {} should pin the Torii body-cap default explicitly",
                profile.slug
            );
        }
    }
    #[test]
    fn all_profile_configs_use_canonical_socket_literals() {
        let expected_listen =
            SocketAddr::Ipv4(SocketAddrV4::from(([0, 0, 0, 0], 1337))).to_literal();
        let expected_public =
            SocketAddr::Ipv4(SocketAddrV4::from(([172, 28, 0, 10], 1337))).to_literal();
        let expected_torii =
            SocketAddr::Ipv4(SocketAddrV4::from(([0, 0, 0, 0], 8080))).to_literal();
        for profile in PROFILES {
            let peers = build_peers(profile).expect("build deterministic peers");
            let seed = format!("config-{}-address-genesis", profile.slug);
            let genesis_key = deterministic_keypair(&seed, Algorithm::Ed25519)
                .expect("derive deterministic genesis key");
            let rendered = render_config(profile, &peers, genesis_key.public_key());
            assert!(
                rendered.contains(&format!("address = \"{expected_listen}\"")),
                "profile {} must render the canonical network listen literal",
                profile.slug
            );
            assert!(
                rendered.contains(&format!("public_address = \"{expected_public}\"")),
                "profile {} must render the canonical advertised network literal",
                profile.slug
            );
            assert!(
                rendered.contains(&format!("address = \"{expected_torii}\"")),
                "profile {} must render the canonical Torii listen literal",
                profile.slug
            );
        }
    }
    #[test]
    fn all_profile_configs_render_only_node_local_sumeragi_settings() {
        for profile in PROFILES {
            let peers = build_peers(profile).expect("build deterministic peers");
            let genesis_key = deterministic_keypair(
                &format!("config-{}-sumeragi-genesis", profile.slug),
                Algorithm::Ed25519,
            )
            .expect("derive deterministic genesis key");
            let rendered = render_config(profile, &peers, genesis_key.public_key());
            let config = rendered.parse::<toml::Table>().expect("profile TOML");
            let sumeragi = config["sumeragi"]
                .as_table()
                .expect("node-local Sumeragi config");
            assert_eq!(
                sumeragi.keys().map(String::as_str).collect::<Vec<_>>(),
                ["role"],
                "profile {} must render only the node-local Sumeragi role; block limits come from chain parameters",
                profile.slug
            );
            assert_eq!(sumeragi["role"].as_str(), Some("validator"));
        }
    }
    #[test]
    fn checked_in_dev_peers_use_the_current_sumeragi_node_parameters() {
        for peer in 0..PROFILES[0].min_peers {
            let path = workspace_root()
                .join("defaults/kagami/iroha3-dev")
                .join(peer_config_file_name(peer));
            let config = fs::read_to_string(&path)
                .expect("checked-in peer config")
                .parse::<toml::Table>()
                .expect("checked-in peer TOML");
            let sumeragi = config["sumeragi"]
                .as_table()
                .expect("node-local Sumeragi config");
            assert_eq!(
                sumeragi.len(),
                1,
                "{} retains retired local policy",
                path.display()
            );
            assert_eq!(sumeragi["role"].as_str(), Some("validator"));
        }
    }
    #[test]
    fn profiles_do_not_emit_backend_offline_capability_switches() {
        for profile in PROFILES {
            let peers = build_peers(profile).expect("build deterministic generic peers");
            let seed = format!("config-{}-universal-offline-genesis", profile.slug);
            let genesis_key = deterministic_keypair(&seed, Algorithm::Ed25519)
                .expect("derive deterministic generic genesis key");
            let rendered = render_config(profile, &peers, genesis_key.public_key());
            let config: toml::Value =
                toml::from_str(&rendered).expect("parse rendered generic config");
            assert!(
                config
                    .get("settlement")
                    .and_then(toml::Value::as_table)
                    .and_then(|settlement| settlement.get("offline"))
                    .is_none(),
                "profile {} must not model universal offline support as a backend opt-in",
                profile.slug
            );
            for retired in ["escrow_required", "escrow_accounts", "offline.enabled"] {
                assert!(
                    !rendered.contains(retired),
                    "profile {} emitted retired offline setting {retired}",
                    profile.slug
                );
            }
        }
    }
    #[test]
    fn compose_launches_every_signed_topology_member_with_unique_config() {
        let peers = build_peers(&PROFILES[0]).expect("build deterministic dev peers");
        let rendered = render_docker_compose(&PROFILES[0], &peers);
        assert_eq!(
            rendered
                .matches("    image: hyperledger/iroha:latest")
                .count(),
            peers.len()
        );
        assert_eq!(
            rendered.matches(r#"command: ["iroha3d", "--sora""#).count(),
            peers.len(),
            "every prepared profile service must launch the canonical iroha3d binary"
        );
        assert!(!rendered.contains(r#"command: ["irohad""#));
        assert_eq!(
            rendered.matches("ipv4_address: 172.28.0.").count(),
            peers.len()
        );
        assert!(rendered.contains("./peer0.toml:/config/config.toml:ro"));
        assert_eq!(
            rendered
                .matches("./genesis.signed.nrt:/config/genesis.signed.nrt:ro")
                .count(),
            peers.len()
        );
        assert_eq!(
            rendered
                .matches("./genesis.expected_hash:/config/genesis.expected_hash:ro")
                .count(),
            peers.len(),
            "every dev validator must receive the identity beside its config"
        );
        assert!(!rendered.contains("/run/iroha/genesis.expected_hash"));
        assert!(!rendered.contains("--genesis"));
        assert!(!rendered.contains("kagemusha-load-authorizer"));
        assert_eq!(rendered.matches("create_host_path: false").count(), 0);
        for peer_index in 1..peers.len() {
            assert!(rendered.contains(&format!("./peer{peer_index}.toml:/config/config.toml:ro")));
        }

        let runtime_peers = build_peers(&PROFILES[1]).expect("build deterministic Nexus peers");
        let runtime_rendered = render_docker_compose(&PROFILES[1], &runtime_peers);
        assert_eq!(
            runtime_rendered
                .matches("./genesis.expected_hash:/run/iroha/genesis.expected_hash:ro")
                .count(),
            runtime_peers.len(),
            "every runtime validator must receive the identity at its configured public path"
        );
        assert!(
            !runtime_rendered.contains("./genesis.expected_hash:/config/genesis.expected_hash:ro")
        );
        assert_eq!(
            runtime_rendered
                .matches("/run/secrets/iroha:/run/secrets/iroha:ro")
                .count(),
            runtime_peers.len(),
            "runtime peers receive their required validator signing files in the secret directory"
        );
        assert_eq!(
            runtime_rendered.matches("create_host_path: false").count(),
            0
        );
        assert!(!runtime_rendered.contains("kagemusha-load-authorizer"));
    }
    #[test]
    fn peer_configs_use_distinct_consensus_streaming_and_port_material() {
        let peers = build_peers(&PROFILES[0]).expect("build deterministic dev peers");
        let genesis_key = deterministic_keypair("distinct-peer-configs", Algorithm::Ed25519)
            .expect("derive deterministic genesis key");
        let mut transport_public_keys = std::collections::BTreeSet::new();
        for (peer_index, peer) in peers.iter().enumerate() {
            let rendered =
                render_peer_config(&PROFILES[0], &peers, peer_index, genesis_key.public_key());
            let torii_port = 8080 + peer_index;
            assert!(rendered.contains(&format!("private_key = \"{}\"", peer.private_key)));
            assert!(rendered.contains(&format!(
                "soranet_transport_public_key = \"{}\"",
                peer.soranet_transport_public_key
            )));
            assert!(rendered.contains(&format!(
                "soranet_transport_private_key = \"{}\"",
                peer.soranet_transport_private_key
            )));
            assert!(rendered.contains(&peer.streaming_public_key));
            assert!(rendered.contains(&peer.streaming_private_key));
            assert_ne!(peer.soranet_transport_public_key, peer.public_key);
            assert_ne!(peer.soranet_transport_private_key, peer.private_key);
            assert_ne!(peer.soranet_transport_public_key, peer.streaming_public_key);
            assert_ne!(
                peer.soranet_transport_private_key,
                peer.streaming_private_key
            );
            let transport_public = peer
                .soranet_transport_public_key
                .parse::<iroha_crypto::PublicKey>()
                .expect("transport public key");
            let transport_private = peer
                .soranet_transport_private_key
                .parse::<ExposedPrivateKey>()
                .expect("transport private key");
            let transport_key_pair = KeyPair::new(transport_public.clone(), transport_private.0)
                .expect("transport public/private key pair must match");
            assert_eq!(transport_key_pair.algorithm(), Algorithm::Ed25519);
            assert!(
                transport_public_keys.insert(transport_public),
                "profile peers must not share a SoraNet transport identity"
            );
            assert!(rendered.contains(&format!("0.0.0.0:{torii_port}")));
            assert!(rendered.contains("file = \"genesis.signed.nrt\""));
            assert!(!rendered.contains("manifest_json"));
            for (other_index, other) in peers.iter().enumerate() {
                if peer_index != other_index {
                    assert!(
                        !rendered.contains(&format!("private_key = \"{}\"", other.private_key))
                    );
                    assert!(!rendered.contains(&other.soranet_transport_private_key));
                    assert!(!rendered.contains(&other.streaming_private_key));
                }
            }
        }
    }
    #[test]
    fn ordinary_profile_renderings_and_checked_in_templates_omit_issuer_custody() {
        for profile in PROFILES {
            let peers = build_peers(profile).expect("build deterministic profile peers");
            let genesis_key = deterministic_keypair("ordinary-profile-genesis", Algorithm::Ed25519)
                .expect("derive deterministic genesis verifier");
            for peer_index in 0..peers.len() {
                for private_keys in [
                    PrivateKeyRendering::Inline,
                    PrivateKeyRendering::RuntimeFiles,
                ] {
                    for genesis_identity in [
                        GenesisIdentityRendering::Unpublished,
                        published_genesis_identity_rendering(profile),
                    ] {
                        let rendered = render_peer_config_with_private_keys(
                            profile,
                            &peers,
                            peer_index,
                            genesis_key.public_key(),
                            genesis_identity,
                            private_keys,
                        );
                        let config: toml::Table = rendered.parse().expect("profile TOML");
                        assert!(!config.contains_key("kagemusha_load_authorizer"));
                        assert!(!rendered.contains("kagemusha-load-authorizer"));
                    }
                }
            }
        }
        for path in [
            "defaults/kagami/iroha3-dev/peer0.toml",
            "defaults/kagami/iroha3-dev/peer1.toml",
            "defaults/kagami/iroha3-dev/peer2.toml",
            "defaults/kagami/iroha3-dev/peer3.toml",
            "defaults/kagami/iroha3-nexus/config.toml",
            "defaults/nexus/config.toml",
        ] {
            let source =
                fs::read_to_string(workspace_root().join(path)).expect("ordinary template");
            let config: toml::Table = source.parse().expect("ordinary template TOML");
            assert!(!config.contains_key("kagemusha_load_authorizer"), "{path}");
            assert!(!source.contains("kagemusha-load-authorizer"), "{path}");
        }
    }
    #[test]
    fn checked_in_profile_transport_identities_are_reproducible() {
        let expected = [
            (
                "iroha3-dev",
                "ed01205A4FF1E3840273F79909F02BA854FE9394DE6FBAEF06B87397B059C16BAD6ADC",
                "802620BBEB9930B26B2CFB85EF7683349DAB2921927F0EA1F5E5BFF89C7E60A7D1700B",
            ),
            (
                "iroha3-nexus",
                "ed01201F60DE7C82F77FF1EA9AA2DFC60166A0DF904A771DCBFF36186EFAE8AC8324D3",
                "802620720B9507E31A382E02FF4523D0E22071E19D39974C9AE907492EEAE616F23E15",
            ),
        ];
        assert_eq!(
            PROFILES.len(),
            expected.len(),
            "every current profile has a vector"
        );
        for (slug, public_key, private_key) in expected {
            let spec = PROFILES
                .iter()
                .find(|spec| spec.slug == slug)
                .expect("current profile");
            let peers = build_peers(spec).expect("build deterministic profile peers");
            assert_eq!(peers[0].soranet_transport_public_key, public_key);
            assert_eq!(peers[0].soranet_transport_private_key, private_key);
        }
    }
    #[test]
    fn verify_output_captured_on_success() {
        if std::env::var("XTASK_TEST_KAGAMI_BIN").is_err() {
            return;
        }
        let kagami_path = PathBuf::from(std::env::var("XTASK_TEST_KAGAMI_BIN").unwrap());
        let temp = tempdir().expect("temp dir");
        let genesis_path = temp.path().join("genesis.json");
        let profile = &PROFILES[0];
        let defaults = iroha_deploy::genesis::profile::profile_defaults(
            iroha_deploy::genesis::profile::GenesisProfile::Iroha3Dev,
        );
        let peers = build_peers(profile).expect("build four development-profile validators");
        assert_eq!(peers.len(), 4);
        let mut topology = peers
            .iter()
            .map(|peer| GenesisTopologyEntry::new(peer.peer_id.clone(), peer.pop.clone()))
            .collect::<Vec<_>>();
        topology.sort_by(|left, right| left.peer.cmp(&right.peer));
        let genesis_key = deterministic_keypair("verify-dev-profile-genesis", Algorithm::Ed25519)
            .expect("derive development genesis authority");
        let builder = iroha_genesis::GenesisBuilder::new_without_executor(
            defaults.chain_id.clone(),
            ".",
        )
        .set_topology(topology)
        .with_sumeragi_context_parameters(
            iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended(),
        );
        let genesis = iroha_deploy::genesis::generate_default(
            builder,
            genesis_key.public_key(),
            None,
            SumeragiConsensusMode::Permissioned,
            Some(&defaults),
            None,
        )
        .expect("generate complete development-profile genesis");
        let mut rendered = json::to_json_pretty(&genesis).expect("render development genesis");
        rendered.push('\n');
        fs::write(&genesis_path, rendered).expect("write development genesis");
        let out = run_verify(&PROFILES[0], &kagami_path, &genesis_path, None);
        assert!(
            out.is_ok(),
            "verify should succeed when kagami binary is supplied: {out:?}"
        );
    }
}
