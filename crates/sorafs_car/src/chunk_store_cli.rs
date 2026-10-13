//! Shared implementation for the SoraFS chunk-store developer CLIs.
#[cfg(feature = "cli")]
use crate::FilePayload;
use crate::set_no_follow_flag;
use crate::{
    CarBuildPlan, CarChunk, ChunkStore, DirectoryChunkSinkOutput, DirectoryPublicationStatus,
    FileEntry, FilePlan, InMemoryPayload, ProfileId, chunker_registry,
    fetch_plan::{
        CHUNK_STORE_REPORT_SCHEMA_V1, chunk_fetch_plan_to_string, try_chunk_fetch_specs_to_json,
    },
    por_json::{parse_proof_spec, proof_from_value, proof_to_value, sample_to_map, tree_to_value},
};
use norito::json::{Map, Value, to_string_pretty};
use sorafs_chunker::ChunkProfile;
use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavor {
    ChunkStore,
    #[cfg(feature = "cli")]
    ManifestChunkStore,
}
impl Flavor {
    fn is_manifest(self) -> bool {
        #[cfg(feature = "cli")]
        {
            self == Self::ManifestChunkStore
        }
        #[cfg(not(feature = "cli"))]
        {
            false
        }
    }
}
#[derive(Default)]
struct Options {
    profile_id: Option<u32>,
    profile_handle: Option<String>,
    json_out: Option<PathBuf>,
    por_json_out: Option<PathBuf>,
    chunk_fetch_plan_out: Option<PathBuf>,
    chunk_dir_out: Option<PathBuf>,
    payload_path: Option<PathBuf>,
    list_profiles: bool,
    promote_profile: Option<String>,
    proof_spec: Option<(usize, usize, usize)>,
    proof_out: Option<PathBuf>,
    proof_verify: Option<PathBuf>,
    sample_count: Option<usize>,
    sample_seed: Option<u64>,
    sample_out: Option<PathBuf>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Descriptor {
    id: u32,
    namespace: &'static str,
    name: &'static str,
    semver: &'static str,
    profile: ChunkProfile,
    multihash_code: u64,
    aliases: &'static [&'static str],
}
impl From<&chunker_registry::ChunkerProfileDescriptor> for Descriptor {
    fn from(descriptor: &chunker_registry::ChunkerProfileDescriptor) -> Self {
        Self {
            id: descriptor.id.0,
            namespace: descriptor.namespace,
            name: descriptor.name,
            semver: descriptor.semver,
            profile: descriptor.profile,
            multihash_code: descriptor.multihash_code,
            aliases: descriptor.aliases,
        }
    }
}
#[cfg(feature = "cli")]
impl From<&sorafs_manifest::chunker_registry::ChunkerProfileDescriptor> for Descriptor {
    fn from(descriptor: &sorafs_manifest::chunker_registry::ChunkerProfileDescriptor) -> Self {
        Self {
            id: descriptor.id.0,
            namespace: descriptor.namespace,
            name: descriptor.name,
            semver: descriptor.semver,
            profile: descriptor.profile,
            multihash_code: descriptor.multihash_code,
            aliases: descriptor.aliases,
        }
    }
}
/// Run the `sorafs_chunk_store` developer command.
pub fn run_chunk_store() -> Result<(), String> {
    run(Flavor::ChunkStore)
}
/// Run the `sorafs_manifest_chunk_store` developer command.
#[cfg(feature = "cli")]
pub fn run_manifest_chunk_store() -> Result<(), String> {
    run(Flavor::ManifestChunkStore)
}
fn run(flavor: Flavor) -> Result<(), String> {
    let mut options = parse_options(flavor)?;
    if options.list_profiles {
        return list_profiles(flavor, &options);
    }
    if let Some(candidate) = options.promote_profile.take() {
        return promote_profile(flavor, &options, &candidate);
    }
    let path = options.payload_path.take().ok_or_else(|| usage(flavor))?;
    if options.profile_id.is_some() && options.profile_handle.is_some() {
        return Err("use either --profile-id or --profile, not both".to_string());
    }
    let descriptor = select_descriptor(flavor, &options)?;
    let bytes =
        fs::read(&path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let mut store = ChunkStore::with_profile(descriptor.profile);
    let persisted_chunks = if let Some(directory) = options.chunk_dir_out.as_deref() {
        preflight_chunk_dir_out(directory)?;
        let output = if bytes.is_empty() {
            persist_empty_payload_chunk_dir(directory, &mut store)?
        } else {
            let plan = CarBuildPlan::single_file_with_profile(&bytes, descriptor.profile)
                .map_err(|err| format!("failed to build chunk plan for persistence: {err}"))?;
            let mut source = InMemoryPayload::new(&bytes);
            store
                .ingest_plan_to_directory(&plan, &mut source, directory)
                .map_err(|err| {
                    format!("failed to persist chunks to {}: {err}", directory.display())
                })?
        };
        Some(persisted_chunks_to_value(directory, output))
    } else {
        store
            .ingest_bytes(&bytes)
            .map_err(|err| format!("failed to ingest payload: {err}"))?;
        None
    };
    let chunks = store
        .chunks()
        .iter()
        .map(|chunk| {
            let mut object = Map::new();
            object.insert("offset".into(), Value::from(chunk.offset));
            object.insert("length".into(), Value::from(chunk.length));
            object.insert(
                "digest_blake3".into(),
                Value::from(hex::encode(chunk.blake3)),
            );
            Value::Object(object)
        })
        .collect::<Vec<_>>();
    let mut report = Map::new();
    if flavor == Flavor::ChunkStore {
        report.insert("schema".into(), Value::from(CHUNK_STORE_REPORT_SCHEMA_V1));
    }
    report.insert("input_bytes".into(), Value::from(store.payload_len()));
    report.insert(
        "payload_digest_blake3".into(),
        Value::from(hex::encode(store.payload_digest().as_bytes())),
    );
    report.insert("chunk_count".into(), Value::from(chunks.len() as u64));
    report.insert(
        "por_root_hex".into(),
        Value::from(hex::encode(store.por_tree().root())),
    );
    report.insert(
        "por_chunk_count".into(),
        Value::from(store.por_tree().chunks().len() as u64),
    );
    report.insert(
        "profile".into(),
        Value::Object(descriptor_to_json(descriptor)),
    );
    report.insert("chunks".into(), Value::Array(chunks));
    if let Some(persisted) = persisted_chunks {
        report.insert("persisted_chunks".into(), persisted);
    }
    let plan = if flavor == Flavor::ChunkStore {
        let plan = plan_from_store(&store);
        let specs = try_chunk_fetch_specs_to_json(&plan).map_err(|err| err.to_string())?;
        report.insert("chunk_fetch_specs".into(), specs);
        Some(plan)
    } else {
        None
    };
    #[cfg(feature = "cli")]
    let mut file_payload = if flavor.is_manifest() {
        FilePayload::open(&path).ok()
    } else {
        None
    };
    let mut proof_json = None;
    if let Some((chunk_idx, segment_idx, leaf_idx)) = options.proof_spec {
        let proof = match flavor {
            Flavor::ChunkStore => store
                .por_tree()
                .try_prove_leaf(chunk_idx, segment_idx, leaf_idx, &bytes)
                .map_err(|err| err.to_string())?,
            #[cfg(feature = "cli")]
            Flavor::ManifestChunkStore => {
                let result = if let Some(source) = file_payload.as_mut() {
                    store
                        .por_tree()
                        .prove_leaf_with(chunk_idx, segment_idx, leaf_idx, source)
                } else {
                    let mut source = InMemoryPayload::new(&bytes);
                    store
                        .por_tree()
                        .prove_leaf_with(chunk_idx, segment_idx, leaf_idx, &mut source)
                };
                result.map_err(|err| format!("failed to build PoR proof: {err}"))?
            }
        }
        .ok_or_else(|| {
            format!(
                "invalid --por-proof indices chunk={chunk_idx} segment={segment_idx} leaf={leaf_idx}"
            )
        })?;
        let value = proof_to_value(&proof);
        if let Some(path) = options.proof_out.as_deref() {
            write_pretty_json(flavor, path, &value)?;
        }
        proof_json = Some(value);
    }
    if let Some(path) = options.proof_verify.take() {
        let proof_bytes =
            fs::read(&path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let proof_value: Value =
            norito::json::from_slice(&proof_bytes).map_err(|err| err.to_string())?;
        let proof = proof_from_value(&proof_value)?;
        if !proof.verify(store.por_tree().root()) {
            return Err("provided PoR proof does not verify against computed root".into());
        }
        report.insert("por_proof_verified".into(), Value::from(true));
        if proof_json.is_none() {
            proof_json = Some(proof_value);
        }
    }
    if let Some(value) = proof_json {
        report.insert("por_proof".into(), value);
    }
    if let Some(count) = options.sample_count {
        let total_leaves = store.por_tree().leaf_count();
        if total_leaves == 0 {
            return Err("cannot sample PoR leaves from an empty tree".into());
        }
        let seed = options.sample_seed.unwrap_or(0x9e3779b97f4a7c15);
        let samples = match flavor {
            Flavor::ChunkStore => {
                let samples = store
                    .sample_leaves(count, seed, &bytes)
                    .map_err(|err| err.to_string())?;
                if samples.is_empty() {
                    return Err("cannot sample PoR leaves from an empty tree".into());
                }
                if count > total_leaves || samples.len() < count {
                    report.insert("por_samples_truncated".into(), Value::from(true));
                }
                samples
            }
            #[cfg(feature = "cli")]
            Flavor::ManifestChunkStore => {
                let samples = if let Some(source) = file_payload.as_mut() {
                    store.sample_leaves_with(count, seed, source)
                } else {
                    let mut source = InMemoryPayload::new(&bytes);
                    store.sample_leaves_with(count, seed, &mut source)
                }
                .map_err(|err| format!("failed to sample PoR leaves: {err}"))?;
                if samples.len() < count.min(total_leaves) {
                    report.insert("por_samples_truncated".into(), Value::from(true));
                }
                samples
            }
        };
        let proofs = samples
            .into_iter()
            .map(|(index, proof)| Value::Object(sample_to_map(index, &proof)))
            .collect::<Vec<_>>();
        if let Some(path) = options.sample_out.take() {
            write_pretty_json(flavor, &path, &Value::Array(proofs.clone()))?;
        }
        report.insert("por_samples".into(), Value::Array(proofs));
    }
    let json = to_string_pretty(&Value::Object(report))
        .map_err(|err| format!("failed to serialise JSON: {err}"))?
        + "\n";
    let mut report_written_to_stdout = false;
    if let Some(path) = options.json_out.as_deref() {
        report_written_to_stdout = write_text(flavor, path, &json)?;
    }
    if let Some(path) = options.chunk_fetch_plan_out.as_deref() {
        let plan = plan.as_ref().ok_or_else(|| {
            "--chunk-fetch-plan-out is unavailable for the manifest chunk store".to_string()
        })?;
        let text = chunk_fetch_plan_to_string(plan)
            .map_err(|err| format!("failed to serialise chunk fetch plan: {err}"))?;
        report_written_to_stdout |= write_text(flavor, path, &text)?;
    }
    if let Some(path) = options.por_json_out.as_deref() {
        let json = to_string_pretty(&tree_to_value(store.por_tree()))
            .map_err(|err| format!("failed to serialise PoR JSON: {err}"))?
            + "\n";
        let wrote_stdout = write_text(flavor, path, &json)?;
        if flavor == Flavor::ChunkStore {
            report_written_to_stdout |= wrote_stdout;
        }
    }
    if !report_written_to_stdout {
        print!("{json}");
    }
    Ok(())
}
fn parse_options(flavor: Flavor) -> Result<Options, String> {
    let mut options = Options::default();
    for arg in env::args().skip(1) {
        if let Some(value) = arg.strip_prefix("--profile-id=") {
            options.profile_id = Some(parse_u32_decimal(value, "--profile-id")?);
        } else if arg == "--list-profiles" {
            options.list_profiles = true;
        } else if let Some(value) = arg.strip_prefix("--promote-profile=") {
            if !flavor.is_manifest() {
                return Err(format!("unknown option: {arg}"));
            }
            options.promote_profile = Some(parse_profile_handle_arg(value, "--promote-profile")?);
        } else if let Some(value) = arg.strip_prefix("--profile=") {
            options.profile_handle = Some(parse_profile_handle_arg(value, "--profile")?);
        } else if let Some(value) = arg.strip_prefix("--json-out=") {
            options.json_out = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--por-json-out=") {
            options.por_json_out = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--chunk-fetch-plan-out=") {
            if flavor.is_manifest() {
                return Err(format!("unknown option: {arg}"));
            }
            options.chunk_fetch_plan_out = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--chunk-dir-out=") {
            options.chunk_dir_out = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--por-proof=") {
            options.proof_spec = Some(parse_proof_spec(value)?);
        } else if let Some(value) = arg.strip_prefix("--por-proof-out=") {
            options.proof_out = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--por-proof-verify=") {
            options.proof_verify = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--por-sample=") {
            options.sample_count = Some(parse_nonzero_usize_decimal(value, "--por-sample")?);
        } else if let Some(value) = arg.strip_prefix("--por-sample-seed=") {
            options.sample_seed = Some(parse_u64(value, "--por-sample-seed")?);
        } else if let Some(value) = arg.strip_prefix("--por-sample-out=") {
            options.sample_out = Some(PathBuf::from(value));
        } else if arg.starts_with("--") {
            return Err(format!("unknown option: {arg}"));
        } else if options.payload_path.is_none() {
            options.payload_path = Some(PathBuf::from(arg));
        } else {
            return Err(format!("unexpected argument: {arg}"));
        }
    }
    Ok(options)
}
fn list_profiles(flavor: Flavor, options: &Options) -> Result<(), String> {
    if options.payload_path.is_some() {
        return Err("cannot supply a payload path when using --list-profiles".to_string());
    }
    if flavor.is_manifest() {
        if options.promote_profile.is_some() {
            return Err("cannot combine --list-profiles with --promote-profile".to_string());
        }
        if options.chunk_dir_out.is_some() {
            return Err("cannot combine --list-profiles with --chunk-dir-out".to_string());
        }
    }
    let values = descriptors(flavor)
        .into_iter()
        .map(|descriptor| Value::Object(descriptor_to_json(descriptor)))
        .collect();
    let json = to_string_pretty(&Value::Array(values)).map_err(|err| err.to_string())? + "\n";
    match flavor {
        Flavor::ChunkStore => {
            if let Some(path) = options.json_out.as_deref() {
                write_text(flavor, path, &json)?;
            }
            print!("{json}");
        }
        #[cfg(feature = "cli")]
        Flavor::ManifestChunkStore => {
            let wrote_stdout = if let Some(path) = options.json_out.as_deref() {
                write_text(flavor, path, &json)?
            } else {
                false
            };
            if !wrote_stdout {
                print!("{json}");
            }
        }
    }
    Ok(())
}
fn promote_profile(flavor: Flavor, options: &Options, candidate: &str) -> Result<(), String> {
    if !flavor.is_manifest() {
        return Err(format!("unknown option: --promote-profile={candidate}"));
    }
    if options.payload_path.is_some()
        || options.profile_id.is_some()
        || options.profile_handle.is_some()
        || options.por_json_out.is_some()
        || options.chunk_dir_out.is_some()
        || options.proof_spec.is_some()
        || options.proof_out.is_some()
        || options.proof_verify.is_some()
        || options.sample_count.is_some()
        || options.sample_out.is_some()
    {
        return Err(
            "--promote-profile cannot be combined with payload processing or PoR options".into(),
        );
    }
    #[cfg(feature = "cli")]
    sorafs_manifest::chunker_registry::ensure_charter_compliance()
        .map_err(|err| format!("registry charter violation: {err}"))?;
    let canonical = resolve_profile_handle(flavor, candidate)?;
    let descriptor = lookup_by_handle(flavor, &canonical).ok_or_else(|| {
        format!(
            "unknown chunker profile handle: {canonical}. use --list-profiles to inspect registered entries"
        )
    })?;
    let mut metadata = descriptor_to_json(descriptor);
    metadata.remove("handle");
    metadata.insert("canonical_handle".into(), Value::from(canonical));
    metadata.insert(
        "break_mask".into(),
        Value::from(format!("0x{:04x}", descriptor.profile.break_mask)),
    );
    metadata.insert(
        "multihash_code".into(),
        Value::from(format!("0x{:x}", descriptor.multihash_code)),
    );
    metadata.insert(
        "aliases".into(),
        Value::Array(
            descriptor
                .aliases
                .iter()
                .map(|alias| Value::from(*alias))
                .collect(),
        ),
    );
    metadata.insert(
        "promotion_hint".into(),
        Value::from(
            "Move this descriptor to the front of RAW_REGISTRY in crates/sorafs_car/src/chunker_registry_data.rs to make it the default profile.",
        ),
    );
    let json = to_string_pretty(&Value::Object(metadata)).map_err(|err| err.to_string())? + "\n";
    let wrote_stdout = if let Some(path) = options.json_out.as_deref() {
        write_text(flavor, path, &json)?
    } else {
        false
    };
    if !wrote_stdout {
        print!("{json}");
    }
    Ok(())
}
fn usage(flavor: Flavor) -> String {
    match flavor {
        Flavor::ChunkStore => "usage: sorafs-chunk-store [--profile-id=<id>] [--profile=<namespace.name@semver>] [--json-out=path] [--chunk-fetch-plan-out=path] [--chunk-dir-out=dir] [--por-json-out=path] [--por-proof=chunk:segment:leaf] [--por-proof-out=path] [--por-proof-verify=path] [--por-sample=count] [--por-sample-seed=value] [--por-sample-out=path] <payload>".to_string(),
        #[cfg(feature = "cli")]
        Flavor::ManifestChunkStore => "usage: sorafs_manifest_chunk_store [--profile-id=<id>] [--profile=<namespace.name@semver>] [--json-out=path] [--chunk-dir-out=dir] [--por-json-out=path] [--promote-profile=<handle>] [--por-proof=chunk:segment:leaf] [--por-proof-out=path] [--por-proof-verify=path] [--por-sample=count] [--por-sample-seed=value] [--por-sample-out=path] <payload>".to_string(),
    }
}
fn descriptors(flavor: Flavor) -> Vec<Descriptor> {
    match flavor {
        Flavor::ChunkStore => chunker_registry::registry()
            .iter()
            .map(Descriptor::from)
            .collect(),
        #[cfg(feature = "cli")]
        Flavor::ManifestChunkStore => sorafs_manifest::chunker_registry::registry()
            .iter()
            .map(Descriptor::from)
            .collect(),
    }
}
fn lookup_by_handle(flavor: Flavor, handle: &str) -> Option<Descriptor> {
    match flavor {
        Flavor::ChunkStore => chunker_registry::lookup_by_handle(handle).map(Descriptor::from),
        #[cfg(feature = "cli")]
        Flavor::ManifestChunkStore => {
            sorafs_manifest::chunker_registry::lookup_by_handle(handle).map(Descriptor::from)
        }
    }
}
fn lookup_by_id(flavor: Flavor, id: u32) -> Option<Descriptor> {
    match flavor {
        Flavor::ChunkStore => chunker_registry::lookup(ProfileId(id)).map(Descriptor::from),
        #[cfg(feature = "cli")]
        Flavor::ManifestChunkStore => {
            sorafs_manifest::chunker_registry::lookup(sorafs_manifest::ProfileId(id))
                .map(Descriptor::from)
        }
    }
}
fn default_descriptor(flavor: Flavor) -> Descriptor {
    match flavor {
        Flavor::ChunkStore => Descriptor::from(chunker_registry::default_descriptor()),
        #[cfg(feature = "cli")]
        Flavor::ManifestChunkStore => {
            Descriptor::from(sorafs_manifest::chunker_registry::default_descriptor())
        }
    }
}
fn select_descriptor(flavor: Flavor, options: &Options) -> Result<Descriptor, String> {
    if let Some(handle) = options.profile_handle.as_deref() {
        lookup_by_handle(flavor, handle).ok_or_else(|| {
            format!("unknown chunker profile handle: {handle}. expected namespace.name@semver")
        })
    } else if let Some(id) = options.profile_id {
        lookup_by_id(flavor, id).ok_or_else(|| {
            format!(
                "unknown chunker profile id: {id}. use --list-profiles to inspect registered entries"
            )
        })
    } else {
        Ok(default_descriptor(flavor))
    }
}
fn resolve_profile_handle(flavor: Flavor, input: &str) -> Result<String, String> {
    if input.is_empty() {
        return Err("chunker profile cannot be empty".into());
    }
    if input != input.trim() {
        return Err("chunker profile must not contain leading or trailing whitespace".into());
    }
    if let Some(descriptor) = lookup_by_handle(flavor, input) {
        return Ok(canonical_handle(descriptor));
    }
    if input.as_bytes().iter().all(u8::is_ascii_digit) {
        let id = parse_u32_decimal(input, "chunker profile id")?;
        return lookup_by_id(flavor, id)
            .map(canonical_handle)
            .ok_or_else(|| {
                format!(
                    "unknown chunker profile id: {id}. Use --list-profiles to inspect the registry"
                )
            });
    }
    descriptors(flavor)
        .into_iter()
        .find(|descriptor| {
            descriptor
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(input))
        })
        .map(canonical_handle)
        .ok_or_else(|| {
            format!("unknown chunker profile handle '{input}'. expected namespace.name@semver")
        })
}
fn canonical_handle(descriptor: Descriptor) -> String {
    format!(
        "{}.{}@{}",
        descriptor.namespace, descriptor.name, descriptor.semver
    )
}
fn descriptor_to_json(descriptor: Descriptor) -> Map {
    let mut map = Map::new();
    map.insert("namespace".into(), Value::from(descriptor.namespace));
    map.insert("name".into(), Value::from(descriptor.name));
    map.insert("semver".into(), Value::from(descriptor.semver));
    map.insert("handle".into(), Value::from(canonical_handle(descriptor)));
    map.insert("profile_id".into(), Value::from(descriptor.id as u64));
    map.insert(
        "min_size".into(),
        Value::from(descriptor.profile.min_size as u64),
    );
    map.insert(
        "target_size".into(),
        Value::from(descriptor.profile.target_size as u64),
    );
    map.insert(
        "max_size".into(),
        Value::from(descriptor.profile.max_size as u64),
    );
    map.insert(
        "break_mask".into(),
        Value::from(format!("0x{:04x}", descriptor.profile.break_mask)),
    );
    map.insert(
        "multihash_code".into(),
        Value::from(descriptor.multihash_code),
    );
    map
}
fn preflight_chunk_dir_out(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("--chunk-dir-out must not be empty".to_string());
    }
    if path == Path::new("-") {
        return Err("--chunk-dir-out must be a directory path, not stdout".to_string());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "--chunk-dir-out {} must not be a symlink",
                    path.display()
                ));
            }
            if !metadata.is_dir() {
                return Err(format!(
                    "--chunk-dir-out {} must be a directory when it exists",
                    path.display()
                ));
            }
            Err(format!(
                "--chunk-dir-out {} must be absent for immutable publication",
                path.display()
            ))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to inspect {}: {err}", path.display())),
    }
}
fn persisted_chunks_to_value(directory: &Path, output: DirectoryChunkSinkOutput) -> Value {
    let mut root = Map::new();
    root.insert(
        "directory".into(),
        Value::from(directory.display().to_string()),
    );
    root.insert("total_bytes".into(), Value::from(output.total_bytes));
    root.insert(
        "publication".into(),
        Value::from(match output.publication {
            DirectoryPublicationStatus::Durable => "durable",
            DirectoryPublicationStatus::PublishedButDurabilityUncertain => {
                "published_but_durability_uncertain"
            }
        }),
    );
    root.insert(
        "records".into(),
        Value::Array(
            output
                .records
                .into_iter()
                .map(|record| {
                    let mut object = Map::new();
                    object.insert("file_name".into(), Value::from(record.file_name));
                    object.insert("offset".into(), Value::from(record.offset));
                    object.insert("length".into(), Value::from(record.length));
                    object.insert(
                        "digest_blake3".into(),
                        Value::from(hex::encode(record.digest)),
                    );
                    Value::Object(object)
                })
                .collect(),
        ),
    );
    Value::Object(root)
}
fn persist_empty_payload_chunk_dir(
    directory: &Path,
    store: &mut ChunkStore,
) -> Result<DirectoryChunkSinkOutput, String> {
    let (plan, payload) = CarBuildPlan::from_files_with_profile(
        vec![FileEntry {
            path: vec!["payload.bin".to_owned()],
            data: Vec::new(),
        }],
        store.profile(),
    )
    .map_err(|err| format!("failed to build empty chunk plan: {err}"))?;
    let mut source = InMemoryPayload::new(&payload);
    store
        .ingest_plan_to_directory(&plan, &mut source, directory)
        .map_err(|err| {
            format!(
                "failed to persist empty chunks to {}: {err}",
                directory.display()
            )
        })
}
fn plan_from_store(store: &ChunkStore) -> CarBuildPlan {
    let chunk_count = store.chunks().len();
    CarBuildPlan {
        chunk_profile: store.profile(),
        payload_digest: *store.payload_digest(),
        content_length: store.payload_len(),
        chunks: store
            .chunks()
            .iter()
            .map(|chunk| CarChunk {
                offset: chunk.offset,
                length: chunk.length,
                digest: chunk.blake3,
            })
            .collect(),
        files: vec![FilePlan {
            path: Vec::new(),
            first_chunk: 0,
            chunk_count,
            size: store.payload_len(),
        }],
    }
}
fn write_pretty_json(flavor: Flavor, path: &Path, value: &Value) -> Result<(), String> {
    let mut text = to_string_pretty(value).map_err(|err| err.to_string())?;
    text.push('\n');
    write_text(flavor, path, &text).map(|_| ())
}
fn write_text(flavor: Flavor, path: &Path, text: &str) -> Result<bool, String> {
    if path == Path::new("-") {
        return io::stdout()
            .write_all(text.as_bytes())
            .map(|_| true)
            .map_err(|err| {
                if flavor == Flavor::ChunkStore {
                    format!("failed to write text to stdout: {err}")
                } else {
                    format!("failed to write to stdout: {err}")
                }
            });
    }
    let mut file = open_output_file(path, "text output")?;
    file.write_all(text.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(false)
}
fn open_output_file(path: &Path, label: &str) -> Result<fs::File, String> {
    validate_output_path(path)?;
    ensure_parent_dir(path)?;
    validate_output_path(path)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    set_no_follow_flag(&mut options);
    let file = options
        .open(path)
        .map_err(|err| format!("failed to open {label} {}: {err}", path.display()))?;
    let metadata = file.metadata().map_err(|err| {
        format!(
            "failed to inspect {label} {} after open: {err}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "failed to write {label} {}: output must be a regular file",
            path.display()
        ));
    }
    Ok(file)
}
fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    Ok(())
}
fn validate_output_path(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!("output {} must not be a symlink", path.display()));
            }
            if metadata.is_dir() {
                return Err(format!("output {} must not be a directory", path.display()));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to inspect output {}: {err}",
                path.display()
            ));
        }
    }
    if let Some(parent) = path.parent() {
        for ancestor in std::iter::once(parent).chain(parent.ancestors().skip(1)) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            match fs::symlink_metadata(ancestor) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(format!(
                            "output parent {} must not be a symlink",
                            ancestor.display()
                        ));
                    }
                    if !metadata.is_dir() {
                        return Err(format!(
                            "output parent {} must be a directory",
                            ancestor.display()
                        ));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(format!(
                        "failed to inspect output parent {}: {err}",
                        ancestor.display()
                    ));
                }
            }
        }
    }
    Ok(())
}
fn parse_profile_handle_arg(value: &str, label: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value != value.trim() {
        return Err(format!(
            "{label} must not contain leading or trailing whitespace"
        ));
    }
    Ok(value.to_string())
}
fn parse_u32_decimal(value: &str, label: &str) -> Result<u32, String> {
    require_canonical_unsigned_decimal(value, label)?;
    value
        .parse::<u32>()
        .map_err(|err| format!("{label} value out of range: {err}"))
}
fn parse_nonzero_usize_decimal(value: &str, label: &str) -> Result<usize, String> {
    let parsed = parse_usize_decimal(value, label)?;
    if parsed == 0 {
        return Err(format!("{label} must be greater than zero"));
    }
    Ok(parsed)
}
fn parse_usize_decimal(value: &str, label: &str) -> Result<usize, String> {
    require_canonical_unsigned_decimal(value, label)?;
    value
        .parse::<usize>()
        .map_err(|err| format!("{label} value out of range: {err}"))
}
fn parse_u64(value: &str, label: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        require_canonical_hex_unsigned(hex, label)?;
        u64::from_str_radix(hex, 16).map_err(|err| format!("{label} value out of range: {err}"))
    } else {
        require_canonical_unsigned_decimal(value, label)?;
        value
            .parse::<u64>()
            .map_err(|err| format!("{label} value out of range: {err}"))
    }
}
fn require_canonical_unsigned_decimal(value: &str, label: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if !bytes.is_empty()
        && bytes.iter().all(u8::is_ascii_digit)
        && (bytes.len() == 1 || bytes[0] != b'0')
    {
        Ok(())
    } else {
        Err(format!(
            "{label} must be a canonical unsigned decimal integer"
        ))
    }
}
fn require_canonical_hex_unsigned(value: &str, label: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        && (bytes.len() == 1 || bytes[0] != b'0')
    {
        Ok(())
    } else {
        Err(format!(
            "{label} must be a canonical unsigned decimal integer or lowercase 0x-prefixed hex"
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::PersistedChunkRecord;
    use norito::json::Value;
    use tempfile::tempdir;
    fn assert_write_text_creates_parent(flavor: Flavor) {
        let temp = tempdir().expect("tempdir");
        let output = temp
            .path()
            .canonicalize()
            .expect("canonical tempdir")
            .join("nested/report.json");
        assert!(!write_text(flavor, &output, "{\"ok\":true}\n").expect("write text"));
        assert_eq!(fs::read(output).expect("read output"), b"{\"ok\":true}\n");
    }
    #[cfg(unix)]
    fn assert_write_text_rejects_symlink_output(flavor: Flavor) {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical tempdir");
        let target = root.join("target.json");
        fs::write(&target, b"unchanged\n").expect("write target");
        let output = root.join("report.json");
        std::os::unix::fs::symlink(&target, &output).expect("create symlink");
        let error = write_text(flavor, &output, "changed\n").expect_err("reject symlink output");
        assert!(
            error.contains("must not be a symlink"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(target).expect("read target"), b"unchanged\n");
    }
    #[cfg(unix)]
    fn assert_write_text_rejects_symlink_parent(flavor: Flavor) {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical tempdir");
        let real = root.join("real");
        fs::create_dir(&real).expect("create real dir");
        let linked = root.join("linked");
        std::os::unix::fs::symlink(&real, &linked).expect("create symlink");
        let error = write_text(flavor, &linked.join("report.json"), "changed\n")
            .expect_err("reject symlink parent");
        assert!(
            error.contains("parent") && error.contains("must not be a symlink"),
            "unexpected error: {error}"
        );
        assert!(!real.join("report.json").exists());
    }
    fn assert_parse_profile_handle_arg() {
        assert_eq!(
            parse_profile_handle_arg("sorafs.sf1@1.0.0", "--profile").expect("canonical profile"),
            "sorafs.sf1@1.0.0"
        );
        for value in ["", " sorafs.sf1@1.0.0", "sorafs.sf1@1.0.0 "] {
            let error = parse_profile_handle_arg(value, "--profile").expect_err("invalid handle");
            assert!(
                error.contains("empty") || error.contains("whitespace"),
                "unexpected error for {value:?}: {error}"
            );
        }
    }
    fn assert_parse_decimal_flags() {
        assert_eq!(parse_u32_decimal("1", "--profile-id").expect("id"), 1);
        assert_eq!(
            parse_nonzero_usize_decimal("3", "--por-sample").expect("count"),
            3
        );
        for value in ["", "01", "00", "+1", " 1", "1 ", "0x1"] {
            let error = parse_u32_decimal(value, "--profile-id").expect_err("invalid token");
            assert!(
                error.contains("canonical unsigned decimal"),
                "unexpected error for {value:?}: {error}"
            );
        }
        let error = parse_nonzero_usize_decimal("0", "--por-sample").expect_err("zero must fail");
        assert!(error.contains("greater than zero"));
    }
    fn assert_parse_u64_seed() {
        assert_eq!(parse_u64("0", "--por-sample-seed").expect("zero"), 0);
        assert_eq!(parse_u64("42", "--por-sample-seed").expect("decimal"), 42);
        assert_eq!(parse_u64("0x0", "--por-sample-seed").expect("hex zero"), 0);
        assert_eq!(parse_u64("0xff", "--por-sample-seed").expect("hex"), 255);
        for value in [
            "",
            "00",
            "01",
            "+1",
            " 1",
            "1 ",
            "0Xff",
            "0x",
            "0x0f",
            "0xFF",
            "18446744073709551616",
        ] {
            let error = parse_u64(value, "--por-sample-seed").expect_err("invalid seed");
            assert!(
                error.contains("canonical unsigned")
                    || error.contains("out of range")
                    || error.contains("too large"),
                "unexpected error for {value:?}: {error}"
            );
        }
    }
    fn assert_descriptor_json(flavor: Flavor) {
        let descriptor = default_descriptor(flavor);
        let map = descriptor_to_json(descriptor);
        assert_eq!(
            map.get("namespace").and_then(Value::as_str),
            Some(descriptor.namespace)
        );
        assert_eq!(
            map.get("name").and_then(Value::as_str),
            Some(descriptor.name)
        );
        assert_eq!(
            map.get("semver").and_then(Value::as_str),
            Some(descriptor.semver)
        );
        assert_eq!(
            map.get("profile_id").and_then(Value::as_u64),
            Some(descriptor.id as u64)
        );
        assert_eq!(
            map.get("handle").and_then(Value::as_str),
            Some("sorafs.sf1@1.0.0")
        );
    }
    fn assert_preflight_rejects_empty_path() {
        let error = preflight_chunk_dir_out(Path::new("")).expect_err("empty path rejected");
        assert!(error.contains("must not be empty"));
    }
    fn assert_persisted_chunks_value() {
        let value = persisted_chunks_to_value(
            Path::new("chunks"),
            DirectoryChunkSinkOutput {
                records: vec![PersistedChunkRecord {
                    file_name: "chunk_00000.bin".to_string(),
                    offset: 0,
                    length: 3,
                    digest: [7; 32],
                }],
                total_bytes: 3,
                publication: DirectoryPublicationStatus::Durable,
            },
        );
        let object = value.as_object().expect("persisted chunks object");
        assert_eq!(
            object.get("directory").and_then(Value::as_str),
            Some("chunks")
        );
        assert_eq!(object.get("total_bytes").and_then(Value::as_u64), Some(3));
        assert_eq!(
            object.get("publication").and_then(Value::as_str),
            Some("durable")
        );
        let records = object
            .get("records")
            .and_then(Value::as_array)
            .expect("records array");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0]
                .as_object()
                .expect("record object")
                .get("file_name")
                .and_then(Value::as_str),
            Some("chunk_00000.bin")
        );
    }
    fn assert_lookup_by_handle(flavor: Flavor) {
        let descriptor = default_descriptor(flavor);
        let resolved = lookup_by_handle(flavor, &canonical_handle(descriptor)).expect("resolve");
        assert_eq!(resolved.id, descriptor.id);
        assert_eq!(resolved.profile, descriptor.profile);
    }
    mod chunk_store {
        use super::*;
        #[test]
        fn write_text_creates_parent_and_writes_all_bytes() {
            assert_write_text_creates_parent(Flavor::ChunkStore);
        }
        #[cfg(unix)]
        #[test]
        fn write_text_rejects_symlink_output() {
            assert_write_text_rejects_symlink_output(Flavor::ChunkStore);
        }
        #[cfg(unix)]
        #[test]
        fn write_text_rejects_symlink_parent() {
            assert_write_text_rejects_symlink_parent(Flavor::ChunkStore);
        }
        #[test]
        fn default_descriptor_matches_known_values() {
            let descriptor = default_descriptor(Flavor::ChunkStore);
            assert_eq!(descriptor.id, 1);
            assert_eq!(descriptor.namespace, "sorafs");
            assert_eq!(descriptor.name, "sf1");
            assert_eq!(descriptor.semver, "1.0.0");
            assert_eq!(descriptor.profile, ChunkProfile::DEFAULT);
            assert_eq!(descriptor.multihash_code, 0x1f);
        }
        #[test]
        fn lookup_descriptor_resolves_registry_entries() {
            let descriptor = chunker_registry::default_descriptor();
            let looked_up = chunker_registry::lookup(descriptor.id).expect("descriptor present");
            assert_eq!(Descriptor::from(descriptor), Descriptor::from(looked_up));
            assert!(chunker_registry::lookup(ProfileId(9999)).is_none());
        }
        #[test]
        fn parse_profile_handle_arg_rejects_empty_and_padded_handles() {
            assert_parse_profile_handle_arg();
        }
        #[test]
        fn parse_decimal_flags_reject_noncanonical_tokens() {
            assert_parse_decimal_flags();
        }
        #[test]
        fn parse_u64_seed_rejects_noncanonical_tokens() {
            assert_parse_u64_seed();
        }
        #[test]
        fn descriptor_to_json_includes_core_fields() {
            assert_descriptor_json(Flavor::ChunkStore);
        }
        #[test]
        fn preflight_chunk_dir_out_rejects_empty_path() {
            assert_preflight_rejects_empty_path();
        }
        #[test]
        fn persisted_chunks_to_value_includes_records() {
            assert_persisted_chunks_value();
        }
        #[test]
        fn lookup_by_handle_matches_registry_descriptor() {
            assert_lookup_by_handle(Flavor::ChunkStore);
        }
    }
    #[cfg(feature = "cli")]
    mod manifest_chunk_store {
        use super::*;
        const FLAVOR: Flavor = Flavor::ManifestChunkStore;
        #[test]
        fn write_text_creates_parent_and_writes_all_bytes() {
            assert_write_text_creates_parent(FLAVOR);
        }
        #[cfg(unix)]
        #[test]
        fn write_text_rejects_symlink_output() {
            assert_write_text_rejects_symlink_output(FLAVOR);
        }
        #[cfg(unix)]
        #[test]
        fn write_text_rejects_symlink_parent() {
            assert_write_text_rejects_symlink_parent(FLAVOR);
        }
        #[test]
        fn registry_lookup_round_trips_profile_id() {
            let descriptor = sorafs_manifest::chunker_registry::default_descriptor();
            let looked_up = sorafs_manifest::chunker_registry::lookup(descriptor.id)
                .expect("descriptor present");
            assert!(std::ptr::eq(descriptor, looked_up));
        }
        #[test]
        fn parse_profile_handle_arg_rejects_empty_and_padded_handles() {
            assert_parse_profile_handle_arg();
        }
        #[test]
        fn parse_decimal_flags_reject_noncanonical_tokens() {
            assert_parse_decimal_flags();
        }
        #[test]
        fn parse_u64_seed_rejects_noncanonical_tokens() {
            assert_parse_u64_seed();
        }
        #[test]
        fn resolve_profile_handle_requires_canonical_numeric_ids() {
            assert_eq!(
                resolve_profile_handle(FLAVOR, "sorafs.sf1@1.0.0").expect("handle"),
                "sorafs.sf1@1.0.0"
            );
            assert_eq!(
                resolve_profile_handle(FLAVOR, "1").expect("id"),
                "sorafs.sf1@1.0.0"
            );
            assert_eq!(
                resolve_profile_handle(FLAVOR, "sorafs-sf1").expect("alias"),
                "sorafs.sf1@1.0.0"
            );
            assert!(
                resolve_profile_handle(FLAVOR, "01")
                    .expect_err("padded id")
                    .contains("canonical unsigned decimal")
            );
            assert!(
                resolve_profile_handle(FLAVOR, " sorafs.sf1@1.0.0")
                    .expect_err("whitespace")
                    .contains("whitespace")
            );
        }
        #[test]
        fn descriptor_to_json_exposes_core_metadata() {
            assert_descriptor_json(FLAVOR);
        }
        #[test]
        fn preflight_chunk_dir_out_rejects_empty_path() {
            assert_preflight_rejects_empty_path();
        }
        #[test]
        fn persisted_chunks_to_value_includes_records() {
            assert_persisted_chunks_value();
        }
        #[test]
        fn lookup_by_handle_resolves_registered_descriptor() {
            assert_lookup_by_handle(FLAVOR);
        }
    }
}
