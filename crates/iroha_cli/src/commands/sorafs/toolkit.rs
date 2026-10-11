//! Local SoraFS artifact compilation, validation, signing and archive packaging.

pub mod instruction;
pub mod validation;

use super::ensure_parent_dir;
use crate::{Run, RunContext};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use eyre::{Result, WrapErr as _, eyre};
use hex::{decode, encode};
use iroha_crypto::{HybridPublicKey, HybridSuite};
use kotodama_lang::{
    driver::{
        BuildDriver, LinkedSourceBuildRequest, PublishLayout, PublishMode, SourceBuildRequest,
    },
    session::CompilerSession,
};
use norito::json::{Map, Value};
use rand::rngs::OsRng;
use sorafs_car::{
    CarBuildPlan, CarChunk, CarWriteStats, CarWriter, ChunkStore, PorMerkleTree,
    fetch_plan::{TOOLKIT_PACK_REPORT_SCHEMA_V1, try_chunk_fetch_specs_to_json},
};
use sorafs_chunker::ChunkProfile;
use sorafs_manifest::{
    ChunkingProfileV1, DagCodecId, GovernanceProofs, ManifestBuilder, ManifestV1, PinPolicy,
    StorageClass as ManifestStorageClass, chunker_registry,
    hybrid_envelope::{HybridPayloadEnvelopeV1, encrypt_payload},
};
use std::{
    fs,
    io::{self, Read, Write as _},
    path::{Path, PathBuf},
};
use tiny_keccak::{Hasher as _, Sha3};

/// Local compiler and archive operations.
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Compile a Kotodama source into an IVM artifact for publication.
    Compile(CompileArgs),
    /// Package a payload into a CAR and manifest bundle.
    Pack(PackArgs),
    /// Prepare one offline instruction as transaction-stdin JSON.
    #[command(subcommand)]
    Instruction(instruction::Command),
    /// Validate local adverts, orders, proofs, governance and fixture bundles.
    #[command(subcommand)]
    Validate(validation::Command),
    /// Sign an advert, order, orderbook payload or governance node.
    Sign(validation::SignArgs),
    /// Verify a release signature, or explicitly sign a development release.
    ReleaseManifest(validation::ReleaseManifestArgs),
    /// Verify release evidence against independently pinned policy and trust inputs.
    ReleaseManifestReceipt(validation::release_manifest_receipt::Args),
    /// Verify final-promotion signing evidence against independent custody and state trust.
    FinalPromotionReceipt(validation::final_promotion_receipt::Args),
    /// Validate the complete official timed-OVN release audit artifact set.
    TimedOvnReleaseAudit(validation::TimedOvnReleaseAuditArgs),
}

impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Compile(args) => args.run(context),
            Self::Pack(args) => args.run(context),
            command => {
                let status = command.run_artifact().map_err(|error| eyre!(error))?;
                if status == std::process::ExitCode::SUCCESS {
                    Ok(())
                } else {
                    Err(eyre!("artifact validation failed"))
                }
            }
        }
    }
}

impl Command {
    /// Whether this command runs before any client configuration is loaded.
    pub(crate) fn is_artifact_tool(&self) -> bool {
        matches!(
            self,
            Self::Instruction(_)
                | Self::Validate(_)
                | Self::Sign(_)
                | Self::ReleaseManifest(_)
                | Self::ReleaseManifestReceipt(_)
                | Self::FinalPromotionReceipt(_)
                | Self::TimedOvnReleaseAudit(_)
        )
    }

    /// Execute the artifact operation with its documented validation exit status.
    pub(crate) fn run_artifact(
        self,
    ) -> std::result::Result<std::process::ExitCode, validation::CliError> {
        match self {
            Self::Instruction(command) => Ok(command.run()),
            Self::Validate(command) => command.run(),
            Self::Sign(args) => validation::run_sign(args),
            Self::ReleaseManifest(args) => validation::run_release_manifest(args),
            Self::ReleaseManifestReceipt(args) => validation::release_manifest_receipt::run(args),
            Self::FinalPromotionReceipt(args) => validation::final_promotion_receipt::run(args),
            Self::TimedOvnReleaseAudit(args) => validation::run_timed_ovn_release_audit(args),
            Self::Compile(_) | Self::Pack(_) => Err(validation::CliError::Config(
                "compile and pack are separate toolkit operations".to_owned(),
            )),
        }
    }
}

/// Inputs and outputs for a locally compiled publication artifact.
#[derive(clap::Args, Debug)]
pub struct CompileArgs {
    /// Kotodama source path, or `-` to read source from stdin.
    #[arg(long, value_name = "PATH")]
    pub source: PathBuf,
    /// Boundary for relative includes and imports; defaults to the source file's directory.
    #[arg(long, value_name = "DIRECTORY")]
    pub source_root: Option<PathBuf>,
    /// Output path for the IVM `.to` artifact.
    #[arg(long, value_name = "PATH")]
    pub bytecode_out: PathBuf,
    /// Also write the artifact summary as JSON to this path.
    #[arg(long, value_name = "PATH")]
    pub json_out: Option<PathBuf>,
}

#[derive(Debug, norito::json::JsonSerialize, norito::json::JsonDeserialize)]
struct CompileSummary {
    bytecode_path: String,
    bytecode_len: u64,
    bytecode_blake3_hex: String,
    abi_version: u64,
    source_kind: String,
    source_path: Option<String>,
}

impl CompileArgs {
    fn compile(&self, mut stdin: impl Read) -> Result<CompileSummary> {
        let (source, source_name, source_path) = if self.source == Path::new("-") {
            let mut source = String::new();
            stdin
                .read_to_string(&mut source)
                .wrap_err("failed to read Kotodama source from stdin")?;
            (source, "<stdin>".to_owned(), None)
        } else {
            let source = fs::read_to_string(&self.source).wrap_err_with(|| {
                format!("failed to read Kotodama source `{}`", self.source.display())
            })?;
            let name = self.source.display().to_string();
            (source, name.clone(), Some(name))
        };
        let layout = PublishLayout::for_artifact(self.bytecode_out.clone(), None, None)
            .map_err(|error| eyre!(error))?;
        if source_path.is_some() {
            let source = fs::canonicalize(&self.source)?;
            for output in [&self.bytecode_out, &layout.manifest] {
                if source == output_identity(output)? {
                    return Err(eyre!(
                        "compiler output must not replace the Kotodama source"
                    ));
                }
            }
        }
        if let Some(summary) = &self.json_out {
            let summary = output_identity(summary)?;
            for protected in [&self.bytecode_out, &layout.manifest] {
                if summary == output_identity(protected)? {
                    return Err(eyre!("JSON summary must not replace a compiler output"));
                }
            }
            if source_path.is_some() && summary == fs::canonicalize(&self.source)? {
                return Err(eyre!("JSON summary must not replace the Kotodama source"));
            }
        }
        let driver = BuildDriver::for_current_executable(CompilerSession::default())
            .map_err(|error| eyre!(error))?;
        let output = if self.source != Path::new("-") {
            let physical = self.source.canonicalize()?;
            let default_root = self
                .source
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .canonicalize()?;
            let root = self.source_root.as_deref().unwrap_or(&default_root);
            let loaded = kotodama_lang::driver::load_source_project(
                &physical,
                root,
                &std::collections::BTreeMap::new(),
            )
            .map_err(|error| eyre!(error))?;
            for input in loaded.source_paths.values() {
                for output in [&self.bytecode_out, &layout.manifest] {
                    if input == &output_identity(output)? {
                        return Err(eyre!(
                            "compiler output must not replace a Kotodama source file"
                        ));
                    }
                }
                if let Some(summary) = &self.json_out {
                    if input == &output_identity(summary)? {
                        return Err(eyre!(
                            "JSON summary must not replace a Kotodama source file"
                        ));
                    }
                }
            }
            driver.build_project(LinkedSourceBuildRequest {
                source_name: loaded
                    .graph
                    .as_source()
                    .expect("source loader returns a source graph")
                    .root
                    .source_name
                    .clone(),
                graph: match loaded.graph {
                    kotodama_lang::driver::LoadedProjectGraph::Source(graph) => graph,
                    kotodama_lang::driver::LoadedProjectGraph::Package(_) => {
                        unreachable!("source loader returns a source graph")
                    }
                },
                profile: "sorafs".into(),
                layout,
                mode: PublishMode::Write,
            })
        } else {
            if self.source_root.is_some() {
                return Err(eyre!("--source-root requires a file input"));
            }
            driver.build_source(SourceBuildRequest {
                source,
                source_name,
                profile: "sorafs".to_owned(),
                layout,
                mode: PublishMode::Write,
            })
        }
        .map_err(|error| eyre!(error))?;
        let abi_version = ivm::ProgramMetadata::parse(&output.artifact)
            .wrap_err("compiler produced an invalid IVM artifact")?
            .metadata
            .abi_version;
        Ok(CompileSummary {
            bytecode_path: self.bytecode_out.display().to_string(),
            bytecode_len: output.artifact.len() as u64,
            bytecode_blake3_hex: encode(blake3::hash(&output.artifact).as_bytes()),
            abi_version: u64::from(abi_version),
            source_kind: if source_path.is_some() {
                "file"
            } else {
                "stdin"
            }
            .to_owned(),
            source_path,
        })
    }
}

impl Run for CompileArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let summary = self.compile(io::stdin().lock())?;
        if let Some(path) = &self.json_out {
            ensure_parent_dir(path)?;
            let bytes = norito::json::to_vec_pretty(&summary)?;
            let mut output = tempfile::NamedTempFile::new_in(
                path.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?;
            output.write_all(&bytes)?;
            output.persist(path).wrap_err_with(|| {
                format!("failed to write artifact summary `{}`", path.display())
            })?;
        }
        context.print_data(&summary)
    }
}

fn output_identity(path: &Path) -> Result<PathBuf> {
    ensure_parent_dir(path)?;
    if path.exists() {
        return fs::canonicalize(path).map_err(Into::into);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| eyre!("output path must name a file"))?;
    Ok(fs::canonicalize(parent)?.join(name))
}

/// Archive, manifest, and optional hybrid-envelope publication outputs.
#[derive(clap::Args, Debug)]
pub struct PackArgs {
    /// Payload path (file or directory) to package into a CAR archive.
    pub input: PathBuf,
    /// Path to write the Norito manifest (`.to`). If omitted, no manifest file is emitted.
    #[arg(long = "manifest-out", value_name = "PATH")]
    pub manifest_out: Option<PathBuf>,
    /// Path to write the CAR archive.
    #[arg(long = "car-out", value_name = "PATH")]
    pub car_out: Option<PathBuf>,
    /// Path to write the JSON report (defaults to stdout).
    #[arg(long = "json-out", value_name = "PATH")]
    pub json_out: Option<PathBuf>,
    /// Path to write the hybrid payload envelope (binary).
    #[arg(long = "hybrid-envelope-out", value_name = "PATH")]
    pub hybrid_envelope_out: Option<PathBuf>,
    /// Path to write the hybrid payload envelope (JSON).
    #[arg(long = "hybrid-envelope-json-out", value_name = "PATH")]
    pub hybrid_envelope_json_out: Option<PathBuf>,
    /// Hex-encoded X25519 public key used for hybrid envelope encryption.
    #[arg(long = "hybrid-recipient-x25519", value_name = "HEX")]
    pub hybrid_recipient_x25519: Option<String>,
    /// Hex-encoded Kyber public key used for hybrid envelope encryption.
    #[arg(long = "hybrid-recipient-kyber", value_name = "HEX")]
    pub hybrid_recipient_kyber: Option<String>,
}
impl Run for PackArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        context.println(self.pack()?.trim_end())
    }
}
impl PackArgs {
    /// Package local public assets without loading client configuration or custody keys.
    pub fn run_without_client_config(self, mut output: impl std::io::Write) -> Result<()> {
        output.write_all(self.pack()?.as_bytes())?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn pack(self) -> Result<String> {
        let PackArgs {
            input,
            manifest_out,
            car_out,
            json_out,
            hybrid_envelope_out,
            hybrid_envelope_json_out,
            hybrid_recipient_x25519,
            hybrid_recipient_kyber,
        } = self;
        let descriptor = chunker_registry::default_descriptor();
        let (plan, payload) = build_pack_plan(&input, descriptor.profile)?;
        if plan.chunk_profile != descriptor.profile {
            return Err(eyre!("computed chunk plan used unexpected profile"));
        }
        let mut chunk_store = ChunkStore::with_profile(descriptor.profile);
        chunk_store
            .ingest_plan(&payload, &plan)
            .wrap_err("failed to ingest the validated CAR plan into the PoR chunk store")?;
        if chunk_store.por_tree().chunks().len() != plan.chunks.len() {
            return Err(eyre!("chunk store PoR layout diverged from CAR plan"));
        }
        let car_stats = write_pack_car(car_out.as_ref(), &plan, &payload)?;
        if car_stats.chunk_profile != descriptor.profile {
            return Err(eyre!("computed CAR used unexpected chunking profile"));
        }
        let root_cid = car_stats
            .root_cids
            .first()
            .cloned()
            .ok_or_else(|| eyre!("CAR emission produced no root CID"))?;
        let car_archive_digest = *car_stats.car_archive_digest.as_bytes();
        let produce_hybrid_envelope = hybrid_envelope_out.is_some()
            || hybrid_envelope_json_out.is_some()
            || hybrid_recipient_x25519.is_some()
            || hybrid_recipient_kyber.is_some();
        let mut metadata: Vec<(String, String)> = Vec::new();
        let hybrid_recipient = if produce_hybrid_envelope {
            let x25519_hex = hybrid_recipient_x25519.as_deref().ok_or_else(|| {
                eyre!("hybrid manifest envelopes require --hybrid-recipient-x25519")
            })?;
            let kyber_hex = hybrid_recipient_kyber.as_deref().ok_or_else(|| {
                eyre!("hybrid manifest envelopes require --hybrid-recipient-kyber")
            })?;
            let x25519_bytes =
                decode(x25519_hex).wrap_err("invalid hex for --hybrid-recipient-x25519")?;
            let kyber_bytes =
                decode(kyber_hex).wrap_err("invalid hex for --hybrid-recipient-kyber")?;
            ensure_metadata_entry(&mut metadata, "manifest.requires_envelope", "true");
            let suite_label = HybridSuite::X25519MlKem768ChaCha20Poly1305.to_string();
            ensure_metadata_entry(&mut metadata, "manifest.hybrid_suite", &suite_label);
            Some(
                HybridPublicKey::from_bytes(&x25519_bytes, &kyber_bytes)
                    .wrap_err("invalid hybrid recipient key material")?,
            )
        } else {
            None
        };
        let chunk_profile = ChunkingProfileV1::from_descriptor(descriptor);
        let chunk_digest_sha3 = compute_chunk_digest_sha3(&plan.chunks);
        let mut builder = ManifestBuilder::new()
            .root_cid(root_cid.clone())
            .dag_codec(DagCodecId(car_stats.dag_codec))
            .chunking_profile(chunk_profile.clone())
            .chunk_digest_sha3_256(chunk_digest_sha3)
            .por_root(*chunk_store.por_tree().root())
            .content_length(plan.content_length)
            .car_digest(car_archive_digest)
            .car_size(car_stats.car_size)
            .pin_policy(PinPolicy {
                min_replicas: 3,
                storage_class: ManifestStorageClass::Hot,
                retention_epoch: 86_400,
            })
            .governance(GovernanceProofs::default());
        if !metadata.is_empty() {
            builder = builder.extend_metadata(metadata);
        }
        let manifest = builder.build().wrap_err("failed to build manifest")?;
        let manifest_bytes = manifest.encode().wrap_err("failed to encode manifest")?;
        let manifest_digest = manifest
            .digest()
            .wrap_err("failed to compute manifest digest")?;
        let manifest_filename = manifest_out.as_ref().and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        });
        let hybrid_output = if let Some(recipient) = hybrid_recipient {
            let aad = build_hybrid_manifest_aad(
                &manifest_digest,
                chunk_digest_sha3,
                manifest_filename.as_deref(),
            );
            let mut rng = OsRng;
            let envelope = encrypt_payload(&manifest_bytes, &aad, &recipient, &mut rng)
                .wrap_err("failed to encrypt hybrid payload envelope")?;
            let envelope_bytes =
                norito::to_bytes(&envelope).wrap_err("failed to encode hybrid payload envelope")?;
            Some(HybridEnvelopeArtefact {
                envelope,
                bytes: envelope_bytes,
                aad,
            })
        } else {
            None
        };
        if let Some(path) = manifest_out.as_ref() {
            ensure_parent_dir(path)?;
            fs::write(path, &manifest_bytes)
                .wrap_err_with(|| format!("failed to write manifest to `{}`", path.display()))?;
        }
        if let Some(hybrid) = hybrid_output.as_ref() {
            if let Some(path) = hybrid_envelope_out.as_ref() {
                ensure_parent_dir(path)?;
                fs::write(path, &hybrid.bytes).wrap_err_with(|| {
                    format!("failed to write hybrid envelope to `{}`", path.display())
                })?;
            }
            if let Some(path) = hybrid_envelope_json_out.as_ref() {
                ensure_parent_dir(path)?;
                let json_value = norito::json::to_value(&hybrid.envelope)
                    .wrap_err("failed to encode hybrid envelope JSON")?;
                let mut json_string = norito::json::to_string_pretty(&json_value)
                    .wrap_err("failed to render hybrid envelope JSON")?;
                json_string.push('\n');
                fs::write(path, json_string.as_bytes()).wrap_err_with(|| {
                    format!(
                        "failed to write hybrid envelope JSON to `{}`",
                        path.display()
                    )
                })?;
            }
        }
        let mut report = build_pack_report(&PackReportContext {
            profile: &chunk_profile,
            plan: &plan,
            car_stats: &car_stats,
            root_cid: &root_cid,
            manifest: &manifest,
            manifest_bytes: &manifest_bytes,
            manifest_digest: &manifest_digest,
            por_tree: chunk_store.por_tree(),
        })?;
        let report_object = report
            .as_object_mut()
            .ok_or_else(|| eyre!("internal error: report root is not a JSON object"))?;
        if let Some(hybrid) = hybrid_output.as_ref() {
            let mut obj = Map::new();
            obj.insert("suite".into(), Value::from(hybrid.envelope.suite.clone()));
            obj.insert(
                "nonce_hex".into(),
                Value::from(encode(hybrid.envelope.nonce)),
            );
            obj.insert(
                "ciphertext_len".into(),
                Value::from(hybrid.envelope.ciphertext.len() as u64),
            );
            obj.insert(
                "ciphertext_blake3".into(),
                Value::from(encode(blake3::hash(&hybrid.envelope.ciphertext).as_bytes())),
            );
            obj.insert("aad_hex".into(), Value::from(encode(&hybrid.aad)));
            obj.insert(
                "encoded_base64".into(),
                Value::from(STANDARD.encode(&hybrid.bytes)),
            );
            if let Some(path) = hybrid_envelope_out.as_ref() {
                obj.insert("binary_out".into(), Value::from(path.display().to_string()));
            }
            if let Some(path) = hybrid_envelope_json_out.as_ref() {
                obj.insert("json_out".into(), Value::from(path.display().to_string()));
            }
            report_object.insert("hybrid_envelope".into(), Value::Object(obj));
        }
        let mut report_string =
            norito::json::to_string_pretty(&report).wrap_err("failed to render JSON report")?;
        if !report_string.ends_with('\n') {
            report_string.push('\n');
        }
        if let Some(path) = json_out.as_ref()
            && path != Path::new("-")
        {
            ensure_parent_dir(path)?;
            fs::write(path, report_string.as_bytes())
                .wrap_err_with(|| format!("failed to write JSON report to `{}`", path.display()))?;
        }
        Ok(report_string)
    }
}
const HYBRID_MANIFEST_AAD_DOMAIN: &[u8] = b"sorafs.hybrid.manifest.v1";
struct HybridEnvelopeArtefact {
    envelope: HybridPayloadEnvelopeV1,
    bytes: Vec<u8>,
    aad: Vec<u8>,
}
struct PackReportContext<'a> {
    profile: &'a ChunkingProfileV1,
    plan: &'a CarBuildPlan,
    car_stats: &'a CarWriteStats,
    root_cid: &'a [u8],
    manifest: &'a ManifestV1,
    manifest_bytes: &'a [u8],
    manifest_digest: &'a blake3::Hash,
    por_tree: &'a PorMerkleTree,
}
fn build_pack_plan(input: &Path, profile: ChunkProfile) -> Result<(CarBuildPlan, Vec<u8>)> {
    let metadata =
        fs::metadata(input).wrap_err_with(|| format!("failed to access `{}`", input.display()))?;
    if metadata.is_dir() {
        CarBuildPlan::from_directory_with_profile(input, profile)
            .map_err(|err| eyre!("car planning failed: {err}"))
    } else if metadata.is_file() {
        let payload = fs::read(input)
            .wrap_err_with(|| format!("failed to read input `{}`", input.display()))?;
        let plan = CarBuildPlan::single_file_with_profile(&payload, profile)
            .map_err(|err| eyre!("car planning failed: {err}"))?;
        Ok((plan, payload))
    } else {
        Err(eyre!("input must be a file or directory"))
    }
}
fn write_pack_car(
    car_out: Option<&PathBuf>,
    plan: &CarBuildPlan,
    payload: &[u8],
) -> Result<CarWriteStats> {
    let writer = CarWriter::new(plan, payload).wrap_err("failed to prepare CAR writer")?;
    if let Some(path) = car_out {
        ensure_parent_dir(path)?;
        let file = fs::File::create(path)
            .wrap_err_with(|| format!("failed to create `{}`", path.display()))?;
        let mut buf = io::BufWriter::new(file);
        let stats = writer.write_to(&mut buf).wrap_err("failed to write CAR")?;
        buf.flush()
            .wrap_err_with(|| format!("failed to flush `{}`", path.display()))?;
        Ok(stats)
    } else {
        let mut sink = io::sink();
        writer
            .write_to(&mut sink)
            .wrap_err("failed to compute CAR metadata")
    }
}
fn ensure_metadata_entry(metadata: &mut Vec<(String, String)>, key: &str, value: &str) {
    if metadata
        .iter()
        .any(|(existing_key, _)| existing_key.eq_ignore_ascii_case(key))
    {
        return;
    }
    metadata.push((key.to_string(), value.to_string()));
}
fn compute_chunk_digest_sha3(chunks: &[CarChunk]) -> [u8; 32] {
    let mut hasher = Sha3::v256();
    for chunk in chunks {
        hasher.update(&chunk.offset.to_le_bytes());
        hasher.update(&u64::from(chunk.length).to_le_bytes());
        hasher.update(&chunk.digest);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}
fn build_hybrid_manifest_aad(
    manifest_digest: &blake3::Hash,
    chunk_digest_sha3: [u8; 32],
    manifest_filename: Option<&str>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        HYBRID_MANIFEST_AAD_DOMAIN.len()
            + manifest_digest.as_bytes().len()
            + chunk_digest_sha3.len()
            + manifest_filename.map_or(0, |name| 4 + name.len()),
    );
    aad.extend_from_slice(HYBRID_MANIFEST_AAD_DOMAIN);
    aad.extend_from_slice(manifest_digest.as_bytes());
    aad.extend_from_slice(&chunk_digest_sha3);
    if let Some(name) = manifest_filename {
        let name_bytes = name.as_bytes();
        let name_len = u32::try_from(name_bytes.len()).expect("manifest filename length fits u32");
        aad.extend_from_slice(&name_len.to_be_bytes());
        aad.extend_from_slice(name_bytes);
    }
    aad
}
#[allow(clippy::too_many_lines)]
fn build_pack_report(ctx: &PackReportContext<'_>) -> Result<Value> {
    let chunk_digests: Vec<Value> = ctx
        .plan
        .chunks
        .iter()
        .map(|chunk| {
            let mut obj = Map::new();
            obj.insert("offset".into(), Value::from(chunk.offset));
            obj.insert("length".into(), Value::from(chunk.length));
            obj.insert("digest_blake3".into(), Value::from(encode(chunk.digest)));
            Value::Object(obj)
        })
        .collect();
    let chunk_fetch_specs = try_chunk_fetch_specs_to_json(ctx.plan)
        .map_err(|err| eyre!("failed to derive chunk fetch plan: {err}"))?;
    let mut chunking_obj = Map::new();
    chunking_obj.insert(
        "namespace".into(),
        Value::from(ctx.profile.namespace.clone()),
    );
    chunking_obj.insert("name".into(), Value::from(ctx.profile.name.clone()));
    chunking_obj.insert("semver".into(), Value::from(ctx.profile.semver.clone()));
    chunking_obj.insert(
        "handle".into(),
        Value::from(format!(
            "{}.{}@{}",
            ctx.profile.namespace, ctx.profile.name, ctx.profile.semver
        )),
    );
    chunking_obj.insert("profile_id".into(), Value::from(ctx.profile.profile_id.0));
    let alias_values: Vec<Value> = ctx
        .profile
        .aliases
        .iter()
        .cloned()
        .map(Value::from)
        .collect();
    chunking_obj.insert("profile_aliases".into(), Value::Array(alias_values.clone()));
    chunking_obj.insert(
        "min_size".into(),
        Value::from(u64::from(ctx.profile.min_size)),
    );
    chunking_obj.insert(
        "target_size".into(),
        Value::from(u64::from(ctx.profile.target_size)),
    );
    chunking_obj.insert(
        "max_size".into(),
        Value::from(u64::from(ctx.profile.max_size)),
    );
    chunking_obj.insert(
        "break_mask".into(),
        Value::from(format!("0x{:04x}", ctx.profile.break_mask)),
    );
    chunking_obj.insert(
        "multihash_code".into(),
        Value::from(ctx.profile.multihash_code),
    );
    let mut pin_policy_obj = Map::new();
    pin_policy_obj.insert(
        "min_replicas".into(),
        Value::from(u64::from(ctx.manifest.pin_policy.min_replicas)),
    );
    pin_policy_obj.insert(
        "storage_class".into(),
        Value::from(format!("{:?}", ctx.manifest.pin_policy.storage_class)),
    );
    pin_policy_obj.insert(
        "retention_epoch".into(),
        Value::from(ctx.manifest.pin_policy.retention_epoch),
    );
    let alias_claims: Vec<Value> = ctx
        .manifest
        .alias_claims
        .iter()
        .map(|alias| {
            let mut obj = Map::new();
            obj.insert("name".into(), Value::from(alias.name.clone()));
            obj.insert("namespace".into(), Value::from(alias.namespace.clone()));
            obj.insert("proof_hex".into(), Value::from(encode(&alias.proof)));
            Value::Object(obj)
        })
        .collect();
    let metadata_entries: Vec<Value> = ctx
        .manifest
        .metadata
        .iter()
        .map(|entry| {
            let mut obj = Map::new();
            obj.insert("key".into(), Value::from(entry.key.clone()));
            obj.insert("value".into(), Value::from(entry.value.clone()));
            Value::Object(obj)
        })
        .collect();
    let mut manifest_obj = Map::new();
    manifest_obj.insert("version".into(), Value::from(ctx.manifest.version));
    manifest_obj.insert(
        "root_cid_hex".into(),
        Value::from(encode(&ctx.manifest.root_cid)),
    );
    manifest_obj.insert("dag_codec".into(), Value::from(ctx.manifest.dag_codec.0));
    manifest_obj.insert(
        "handle".into(),
        Value::from(format!(
            "{}.{}@{}",
            ctx.profile.namespace, ctx.profile.name, ctx.profile.semver
        )),
    );
    manifest_obj.insert("profile_aliases".into(), Value::Array(alias_values));
    manifest_obj.insert(
        "content_length".into(),
        Value::from(ctx.manifest.content_length),
    );
    manifest_obj.insert(
        "por_root_hex".into(),
        Value::from(encode(ctx.manifest.por_root)),
    );
    manifest_obj.insert(
        "car_digest_hex".into(),
        Value::from(encode(ctx.manifest.car_digest)),
    );
    manifest_obj.insert(
        "car_cid_hex".into(),
        Value::from(encode(&ctx.car_stats.car_cid)),
    );
    manifest_obj.insert("car_size".into(), Value::from(ctx.manifest.car_size));
    manifest_obj.insert("pin_policy".into(), Value::Object(pin_policy_obj));
    manifest_obj.insert(
        "digest_hex".into(),
        Value::from(encode(ctx.manifest_digest.as_bytes())),
    );
    manifest_obj.insert(
        "manifest_hex".into(),
        Value::from(encode(ctx.manifest_bytes)),
    );
    manifest_obj.insert(
        "manifest_len".into(),
        Value::from(ctx.manifest_bytes.len() as u64),
    );
    manifest_obj.insert("alias_claims".into(), Value::Array(alias_claims));
    manifest_obj.insert("metadata".into(), Value::Array(metadata_entries));
    let council_entries: Vec<Value> = ctx
        .manifest
        .governance
        .council_signatures
        .iter()
        .map(|sig| {
            let mut obj = Map::new();
            obj.insert("signer_hex".into(), Value::from(encode(sig.signer)));
            obj.insert("signature_hex".into(), Value::from(encode(&sig.signature)));
            Value::Object(obj)
        })
        .collect();
    manifest_obj.insert("council_signatures".into(), Value::Array(council_entries));
    let mut report_obj = Map::new();
    report_obj.insert("schema".into(), Value::from(TOOLKIT_PACK_REPORT_SCHEMA_V1));
    report_obj.insert("chunking".into(), Value::Object(chunking_obj));
    report_obj.insert("chunk_digests".into(), Value::Array(chunk_digests));
    report_obj.insert("chunk_fetch_specs".into(), chunk_fetch_specs);
    report_obj.insert(
        "payload_digest_hex".into(),
        Value::from(encode(ctx.plan.payload_digest.as_bytes())),
    );
    report_obj.insert("car_size".into(), Value::from(ctx.car_stats.car_size));
    report_obj.insert(
        "car_payload_digest_hex".into(),
        Value::from(encode(ctx.car_stats.car_payload_digest.as_bytes())),
    );
    report_obj.insert(
        "car_archive_digest_hex".into(),
        Value::from(encode(ctx.car_stats.car_archive_digest.as_bytes())),
    );
    report_obj.insert(
        "car_cid_hex".into(),
        Value::from(encode(&ctx.car_stats.car_cid)),
    );
    report_obj.insert("car_root_hex".into(), Value::from(encode(ctx.root_cid)));
    report_obj.insert("dag_codec".into(), Value::from(ctx.car_stats.dag_codec));
    report_obj.insert("manifest".into(), Value::Object(manifest_obj));
    report_obj.insert(
        "manifest_digest_hex".into(),
        Value::from(encode(ctx.manifest_digest.as_bytes())),
    );
    report_obj.insert(
        "manifest_size".into(),
        Value::from(ctx.manifest_bytes.len() as u64),
    );
    report_obj.insert(
        "chunk_count".into(),
        Value::from(ctx.plan.chunks.len() as u64),
    );
    report_obj.insert(
        "por_root_hex".into(),
        Value::from(encode(ctx.por_tree.root())),
    );
    report_obj.insert(
        "por_chunk_count".into(),
        Value::from(ctx.por_tree.chunks().len() as u64),
    );
    Ok(Value::Object(report_obj))
}

#[cfg(test)]
mod tests {
    use super::super::tests::TestContext;
    use super::*;
    use clap::Parser as _;
    use norito::decode_from_bytes;
    use tempfile::TempDir;

    const SOURCE: &str = include_str!("../../../../kotodama_lang/src/samples/kotodama_swap.ko");

    #[test]
    fn compile_file_publishes_exact_artifact_and_matching_summaries() {
        let temp = TempDir::new().expect("temp dir");
        let source = temp.path().join("contract.ko");
        fs::write(&source, SOURCE).expect("source");
        let args = CompileArgs {
            source_root: None,
            source: source.clone(),
            bytecode_out: temp.path().join("contract.to"),
            json_out: Some(temp.path().join("summary.json")),
        };
        let mut context = TestContext::new();
        let expected = CompilerSession::default()
            .build(kotodama_lang::session::CompileRequest {
                source: SOURCE,
                source_name: source.to_str(),
            })
            .expect("reference compilation")
            .artifact;
        args.run(&mut context).expect("compile file");
        let bytes = fs::read(temp.path().join("contract.to")).expect("artifact");
        assert_eq!(bytes, expected);
        let output: Value = norito::json::from_str(&context.outputs()[0]).expect("stdout JSON");
        let saved: Value =
            norito::json::from_slice(&fs::read(temp.path().join("summary.json")).expect("summary"))
                .expect("file JSON");
        assert_eq!(output, saved);
        assert_eq!(output.get("abi_version").and_then(Value::as_u64), Some(1));
        assert_eq!(
            output.get("bytecode_len").and_then(Value::as_u64),
            Some(bytes.len() as u64)
        );
        let digest = encode(blake3::hash(&bytes).as_bytes());
        assert_eq!(
            output.get("bytecode_blake3_hex").and_then(Value::as_str),
            Some(digest.as_str())
        );
        assert_eq!(
            output.get("source_kind").and_then(Value::as_str),
            Some("file")
        );
        assert!(temp.path().join("contract.manifest.json").is_file());
    }

    #[test]
    fn compile_stdin_reports_its_origin_and_rejects_invalid_source_without_artifacts() {
        let temp = TempDir::new().expect("temp dir");
        let args = CompileArgs {
            source_root: None,
            source: "-".into(),
            bytecode_out: temp.path().join("contract.to"),
            json_out: None,
        };
        assert!(args.compile(b"invalid Kotodama source".as_slice()).is_err());
        assert!(!args.bytecode_out.exists());
        let summary = args.compile(SOURCE.as_bytes()).expect("compile stdin");
        assert_eq!(summary.source_kind, "stdin");
        assert_eq!(summary.source_path, None);
        assert_eq!(summary.abi_version, 1);
        assert_eq!(
            summary.bytecode_path,
            args.bytecode_out.display().to_string()
        );
        let expected = CompilerSession::default()
            .build(kotodama_lang::session::CompileRequest {
                source: SOURCE,
                source_name: Some("<stdin>"),
            })
            .expect("reference")
            .artifact;
        assert_eq!(fs::read(&args.bytecode_out).expect("artifact"), expected);
    }

    #[test]
    fn compile_summary_cannot_overwrite_source_artifact_or_manifest() {
        let temp = TempDir::new().expect("temp dir");
        let source = temp.path().join("contract.ko");
        fs::write(&source, SOURCE).expect("source");
        let bytecode_out = temp.path().join("contract.to");
        for name in ["contract.ko", "contract.to", "contract.manifest.json"] {
            let args = CompileArgs {
                source_root: None,
                source: source.clone(),
                bytecode_out: bytecode_out.clone(),
                json_out: Some(temp.path().join(name)),
            };
            assert!(
                args.compile(io::empty())
                    .expect_err("conflicting outputs")
                    .to_string()
                    .contains("must not replace")
            );
            assert!(!bytecode_out.exists());
            assert_eq!(
                fs::read_to_string(&source).expect("preserved source"),
                SOURCE
            );
        }
    }

    #[test]
    fn compiler_outputs_cannot_replace_the_source() {
        let temp = TempDir::new().expect("temp dir");
        for source_name in ["contract.to", "contract.manifest.json"] {
            let source = temp.path().join(source_name);
            fs::write(&source, SOURCE).expect("source");
            let args = CompileArgs {
                source_root: None,
                source: source.clone(),
                bytecode_out: temp.path().join("contract.to"),
                json_out: None,
            };
            assert!(
                args.compile(io::empty())
                    .expect_err("source collision")
                    .to_string()
                    .contains("must not replace")
            );
            assert_eq!(
                fs::read_to_string(&source).expect("preserved source"),
                SOURCE
            );
            fs::remove_file(source).expect("remove fixture");
        }
    }

    #[cfg(unix)]
    #[test]
    fn compiler_output_collision_resolves_symlink_directories() {
        let temp = TempDir::new().expect("temp dir");
        let physical = temp.path().join("physical");
        fs::create_dir(&physical).expect("directory");
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&physical, &alias).expect("alias");
        let source = physical.join("contract.to");
        fs::write(&source, SOURCE).expect("source");
        let args = CompileArgs {
            source_root: None,
            source: source.clone(),
            bytecode_out: alias.join("contract.to"),
            json_out: None,
        };
        assert!(
            args.compile(io::empty())
                .expect_err("aliased source collision")
                .to_string()
                .contains("must not replace")
        );
        assert_eq!(
            fs::read_to_string(&source).expect("preserved source"),
            SOURCE
        );
    }

    #[test]
    fn toolkit_is_local_and_has_one_compiler_argument_surface() {
        let command = [
            "iroha",
            "--machine",
            "app",
            "sorafs",
            "toolkit",
            "compile",
            "--source",
            "-",
            "--bytecode-out",
            "contract.to",
        ];
        let parsed = crate::Args::try_parse_from(command).expect("parse compiler");
        assert!(parsed.command.allows_fallback_config());
        assert!(parsed.command.allows_fallback_config_in_machine_mode());
        for rejected in ["--abi-version=1", "--summary-out=summary.json"] {
            assert!(crate::Args::try_parse_from(command.into_iter().chain([rejected])).is_err());
        }
    }

    #[test]
    fn toolkit_pack_emits_manifest_and_report() {
        let temp = TempDir::new().expect("temp dir");
        let payload_path = temp.path().join("payload.bin");
        fs::write(&payload_path, b"payload-bytes").expect("write payload");
        let manifest_path = temp.path().join("manifest.to");
        let car_path = temp.path().join("payload.car");
        let json_path = temp.path().join("report.json");
        let args = PackArgs {
            input: payload_path,
            manifest_out: Some(manifest_path.clone()),
            car_out: Some(car_path.clone()),
            json_out: Some(json_path.clone()),
            hybrid_envelope_out: None,
            hybrid_envelope_json_out: None,
            hybrid_recipient_x25519: None,
            hybrid_recipient_kyber: None,
        };
        let mut stdout = Vec::new();
        args.run_without_client_config(&mut stdout)
            .expect("credential-free pack");
        let manifest_bytes = fs::read(&manifest_path).expect("read manifest");
        let manifest: ManifestV1 = decode_from_bytes(&manifest_bytes).expect("decode manifest");
        assert_eq!(manifest.content_length, 13);
        let car_bytes = fs::read(&car_path).expect("read CAR archive");
        assert_eq!(manifest.car_size, car_bytes.len() as u64);
        let archive_digest = *blake3::hash(&car_bytes).as_bytes();
        let archive_digest_hex = hex::encode(archive_digest);
        assert_eq!(
            manifest.car_digest, archive_digest,
            "manifest must bind every byte of the canonical CARv2 archive"
        );
        let report_bytes = fs::read(&json_path).expect("read report");
        assert_eq!(
            stdout, report_bytes,
            "local pack prints the exact report without a client context"
        );
        let report: Value = norito::json::from_slice(&report_bytes).expect("decode report");
        assert_eq!(
            report.get("car_archive_digest_hex").and_then(Value::as_str),
            Some(archive_digest_hex.as_str())
        );
        assert_eq!(
            report
                .get("manifest")
                .and_then(|manifest| manifest.get("car_digest_hex"))
                .and_then(Value::as_str),
            Some(archive_digest_hex.as_str())
        );
        assert_ne!(
            report.get("car_payload_digest_hex").and_then(Value::as_str),
            Some(archive_digest_hex.as_str()),
            "CARv1 payload-section digest must remain diagnostic-only"
        );
        let digest_hex = hex::encode(manifest.digest().expect("manifest digest").as_bytes());
        assert_eq!(
            report.get("manifest_digest_hex").and_then(Value::as_str),
            Some(digest_hex.as_str())
        );
        let por_root_hex = hex::encode(manifest.por_root);
        assert_eq!(
            report.get("por_root_hex").and_then(Value::as_str),
            Some(por_root_hex.as_str())
        );
        assert_eq!(
            report
                .get("manifest")
                .and_then(|manifest| manifest.get("por_root_hex"))
                .and_then(Value::as_str),
            Some(por_root_hex.as_str())
        );
    }
    #[test]
    fn hybrid_manifest_aad_appends_filename() {
        let digest = blake3::hash(b"manifest");
        let chunk_digest = [0x11; 32];
        let aad = build_hybrid_manifest_aad(&digest, chunk_digest, Some("manifest.to"));
        let name_len_offset = HYBRID_MANIFEST_AAD_DOMAIN.len() + 32 + 32;
        let length_bytes: [u8; 4] = aad[name_len_offset..name_len_offset + 4]
            .try_into()
            .expect("length bytes");
        let length = u32::from_be_bytes(length_bytes);
        assert_eq!(length as usize, "manifest.to".len());
        assert_eq!(&aad[name_len_offset + 4..], b"manifest.to");
    }
    #[test]
    fn chunk_digest_sha3_matches_manual_hash() {
        let payload = b"hello-world".to_vec();
        let plan =
            CarBuildPlan::single_file_with_profile(&payload, ChunkProfile::DEFAULT).expect("plan");
        let computed = compute_chunk_digest_sha3(&plan.chunks);
        let mut hasher = Sha3::v256();
        for chunk in &plan.chunks {
            hasher.update(&chunk.offset.to_le_bytes());
            hasher.update(&u64::from(chunk.length).to_le_bytes());
            hasher.update(&chunk.digest);
        }
        let mut expected = [0u8; 32];
        hasher.finalize(&mut expected);
        assert_eq!(computed, expected);
    }
    #[test]
    fn ensure_metadata_entry_dedupes_case_insensitive() {
        let mut metadata = vec![("manifest.requires_envelope".to_string(), "true".to_string())];
        ensure_metadata_entry(&mut metadata, "Manifest.Requires_Envelope", "false");
        assert_eq!(metadata.len(), 1);
        ensure_metadata_entry(&mut metadata, "manifest.hybrid_suite", "suite");
        assert_eq!(metadata.len(), 2);
    }
}
