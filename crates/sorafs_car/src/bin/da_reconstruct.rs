#![allow(clippy::missing_panics_doc)]
use clap::Parser;
use eyre::{Result, WrapErr, eyre};
use iroha_data_model::da::manifest::DaManifestV1;
use norito::{
    decode_from_bytes,
    json::{Map, Value},
};
use sorafs_car::set_no_follow_flag;
use std::{
    fs::{self, File},
    io::{self, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
};
const DEFAULT_CHUNK_TEMPLATE: &str = "chunk_{index:05}.bin";
const MAX_CHUNK_TEMPLATE_WIDTH: usize = 20;
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Deterministic DA chunk reconstruction harness"
)]
struct Args {
    /// Path to the Norito-encoded DA manifest (binary or hex).
    #[arg(long = "manifest", value_name = "PATH")]
    manifest_path: PathBuf,
    /// Directory containing chunk_{index:05}.bin files produced by the chunk store.
    #[arg(long = "chunks-dir", value_name = "DIR")]
    chunks_dir: PathBuf,
    /// Output path for the reconstructed payload (defaults to <chunks-dir>/payload.bin).
    #[arg(long = "output", value_name = "PATH")]
    output: Option<PathBuf>,
    /// Optional JSON summary output path.
    #[arg(long = "json-out", value_name = "PATH")]
    json_out: Option<PathBuf>,
    /// Filename template for chunk files (must contain {index} or {index:width}).
    #[arg(long = "chunk-template", default_value = DEFAULT_CHUNK_TEMPLATE)]
    chunk_template: String,
}
fn main() {
    if let Err(err) = run(Args::parse()) {
        eprintln!("error: {err:?}");
        std::process::exit(1);
    }
}
fn run(args: Args) -> Result<()> {
    let manifest = load_manifest(&args.manifest_path)
        .wrap_err_with(|| format!("failed to load manifest `{}`", args.manifest_path.display()))?;
    let output_path = args
        .output
        .unwrap_or_else(|| args.chunks_dir.join("payload.bin"));
    let summary = reconstruct_payload(
        &manifest,
        &args.chunks_dir,
        &output_path,
        &args.chunk_template,
    )?;
    if let Some(path) = args.json_out {
        write_summary_json(&summary, &manifest, &path)?;
        println!(
            "reconstructed {} bytes to {} (hash {}, data {}, parity {}) [summary: {}]",
            summary.payload_bytes,
            summary.output_path,
            summary.expected_blob_hash_hex,
            summary.data_chunks,
            summary.parity_chunks,
            path.display()
        );
    } else {
        println!(
            "reconstructed {} bytes to {} (hash {}, data {}, parity {})",
            summary.payload_bytes,
            summary.output_path,
            summary.expected_blob_hash_hex,
            summary.data_chunks,
            summary.parity_chunks
        );
    }
    Ok(())
}
#[derive(Debug, Clone)]
struct ReconstructionSummary {
    chunk_count: usize,
    data_chunks: usize,
    parity_chunks: usize,
    payload_bytes: u64,
    expected_blob_hash_hex: String,
    output_path: String,
}
fn reconstruct_payload(
    manifest: &DaManifestV1,
    chunk_dir: &Path,
    output_path: &Path,
    chunk_template: &str,
) -> Result<ReconstructionSummary> {
    if !chunk_dir.is_dir() {
        return Err(eyre!(
            "chunk directory `{}` does not exist or is not a directory",
            chunk_dir.display()
        ));
    }
    if manifest.chunks.is_empty() {
        return Err(eyre!("manifest does not contain any chunk commitments"));
    }
    render_chunk_template(chunk_template, 0)?;
    let mut ordered_chunks = manifest.chunks.iter().collect::<Vec<_>>();
    ordered_chunks.sort_by_key(|chunk| chunk.index);
    let mut writer = BufWriter::new(open_output_file(output_path, "reconstructed payload")?);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = Vec::new();
    let mut total_bytes = 0u64;
    let mut data_chunks = 0usize;
    let mut parity_chunks = 0usize;
    for chunk in ordered_chunks {
        let file_name = render_chunk_template(chunk_template, chunk.index as usize)?;
        let path = chunk_dir.join(file_name);
        let mut file = File::open(&path)
            .wrap_err_with(|| format!("failed to open chunk `{}`", path.display()))?;
        let mut metadata_len = file
            .metadata()
            .map(|meta| meta.len())
            .unwrap_or(chunk.length as u64);
        if metadata_len == 0 {
            metadata_len = chunk.length as u64;
        }
        if metadata_len != chunk.length as u64 {
            return Err(eyre!(
                "chunk {} expected length {} bytes but file `{}` is {} bytes",
                chunk.index,
                chunk.length,
                path.display(),
                metadata_len
            ));
        }
        buffer.resize(chunk.length as usize, 0);
        file.read_exact(&mut buffer).wrap_err_with(|| {
            format!(
                "failed to read {} bytes from `{}`",
                chunk.length,
                path.display()
            )
        })?;
        let digest = blake3::hash(&buffer);
        if digest.as_bytes() != chunk.commitment.as_ref() {
            return Err(eyre!(
                "chunk {} digest mismatch (expected {}, computed {})",
                chunk.index,
                hex::encode(chunk.commitment.as_ref()),
                hex::encode(digest.as_bytes())
            ));
        }
        if chunk.parity {
            parity_chunks = parity_chunks
                .checked_add(1)
                .ok_or_else(|| eyre!("parity chunk counter overflow"))?;
            continue;
        }
        if chunk.offset != total_bytes {
            return Err(eyre!(
                "chunk {} offset {} does not match reconstructed cursor {}",
                chunk.index,
                chunk.offset,
                total_bytes
            ));
        }
        writer
            .write_all(&buffer)
            .wrap_err("failed to write reconstructed payload")?;
        hasher.update(&buffer);
        total_bytes = total_bytes
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| eyre!("payload length overflow"))?;
        data_chunks = data_chunks
            .checked_add(1)
            .ok_or_else(|| eyre!("data chunk counter overflow"))?;
    }
    writer
        .flush()
        .wrap_err("failed to flush reconstructed payload")?;
    if total_bytes != manifest.total_size {
        return Err(eyre!(
            "reconstructed length {} does not match manifest content_length {}",
            total_bytes,
            manifest.total_size
        ));
    }
    let expected = manifest.blob_hash.as_bytes();
    let computed = hasher.finalize();
    if expected != computed.as_bytes() {
        return Err(eyre!(
            "payload digest mismatch (manifest {}, reconstructed {})",
            hex::encode(expected),
            hex::encode(computed.as_bytes())
        ));
    }
    Ok(ReconstructionSummary {
        chunk_count: manifest.chunks.len(),
        data_chunks,
        parity_chunks,
        payload_bytes: total_bytes,
        expected_blob_hash_hex: hex::encode(expected),
        output_path: output_path.display().to_string(),
    })
}
fn load_manifest(path: &Path) -> Result<DaManifestV1> {
    let bytes =
        fs::read(path).wrap_err_with(|| format!("failed to read manifest `{}`", path.display()))?;
    let decoded = decode_manifest_bytes(&bytes)?;
    decode_from_bytes(&decoded).wrap_err("failed to decode Norito manifest")
}
fn decode_manifest_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(raw) else {
        return Ok(raw.to_vec());
    };
    if text.is_empty() {
        return Err(eyre!("manifest file is empty"));
    }
    let compact = text
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>();
    if compact.is_empty() {
        return Err(eyre!("manifest file is empty"));
    }
    let compact_without_prefix = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .unwrap_or(compact.as_str());
    let looks_like_hex = !compact_without_prefix.is_empty()
        && compact_without_prefix
            .chars()
            .all(|c| c.is_ascii_hexdigit());
    if !looks_like_hex {
        return Ok(raw.to_vec());
    }
    if compact != text {
        return Err(eyre!(
            "manifest hex payload must be canonical lowercase hex without whitespace"
        ));
    }
    if text.starts_with("0x") || text.starts_with("0X") {
        return Err(eyre!("manifest hex payload must not use a 0x prefix"));
    }
    if !text
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
    {
        return Err(eyre!("manifest hex payload must use lowercase hex"));
    }
    if text.len() % 2 != 0 {
        return Err(eyre!(
            "manifest hex payload must contain an even number of digits"
        ));
    }
    hex::decode(text).wrap_err("failed to decode manifest hex payload")
}
fn render_chunk_template(template: &str, index: usize) -> Result<String> {
    let mut output = String::new();
    let mut cursor = template;
    let mut replaced = false;
    while let Some(pos) = cursor.find("{index") {
        output.push_str(&cursor[..pos]);
        cursor = &cursor[pos + "{index".len()..];
        let mut width: Option<usize> = None;
        if let Some(rest) = cursor.strip_prefix(':') {
            let end = rest
                .find('}')
                .ok_or_else(|| eyre!("chunk template missing closing `}}`"))?;
            let spec = &rest[..end];
            width = Some(parse_chunk_template_width(spec)?);
            cursor = &rest[end..];
        }
        if !cursor.starts_with('}') {
            return Err(eyre!(
                "chunk template must contain `{{index}}` or `{{index:<width>}}`"
            ));
        }
        cursor = &cursor[1..];
        replaced = true;
        let formatted = if let Some(w) = width {
            format!("{index:0width$}", width = w)
        } else {
            index.to_string()
        };
        output.push_str(&formatted);
    }
    output.push_str(cursor);
    if !replaced {
        return Err(eyre!(
            "chunk template `{template}` must contain `{{index}}` placeholder"
        ));
    }
    validate_chunk_file_name(&output)?;
    Ok(output)
}
fn parse_chunk_template_width(spec: &str) -> Result<usize> {
    if spec.is_empty() {
        return Err(eyre!("chunk template width must not be empty"));
    }
    if spec.as_bytes().iter().any(u8::is_ascii_whitespace) {
        return Err(eyre!("chunk template width must not contain whitespace"));
    }
    let digits = spec.strip_prefix('0').unwrap_or(spec);
    if digits.is_empty() {
        return Err(eyre!("chunk template width must be greater than zero"));
    }
    if digits.starts_with('0') {
        return Err(eyre!(
            "chunk template width must use at most one zero-padding marker"
        ));
    }
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(eyre!(
            "chunk template width must be canonical decimal digits"
        ));
    }
    let width = digits
        .parse::<usize>()
        .map_err(|err| eyre!("invalid chunk template width `{spec}`: {err}"))?;
    if width == 0 || width > MAX_CHUNK_TEMPLATE_WIDTH {
        return Err(eyre!(
            "chunk template width {width} is out of range 1..={MAX_CHUNK_TEMPLATE_WIDTH}"
        ));
    }
    Ok(width)
}
fn validate_chunk_file_name(file_name: &str) -> Result<()> {
    if file_name.is_empty() {
        return Err(eyre!("rendered chunk filename must not be empty"));
    }
    if file_name.chars().any(char::is_control) {
        return Err(eyre!(
            "rendered chunk filename must not contain control characters"
        ));
    }
    if file_name.contains('/') || file_name.contains('\\') {
        return Err(eyre!(
            "rendered chunk filename `{file_name}` must be a single path component"
        ));
    }
    let mut components = Path::new(file_name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(eyre!(
            "rendered chunk filename `{file_name}` must be a regular filename"
        )),
    }
}
fn write_summary_json(
    summary: &ReconstructionSummary,
    manifest: &DaManifestV1,
    path: &Path,
) -> Result<()> {
    let mut obj = Map::new();
    obj.insert(
        "chunk_count".into(),
        Value::from(summary.chunk_count as u64),
    );
    obj.insert(
        "data_chunks".into(),
        Value::from(summary.data_chunks as u64),
    );
    obj.insert(
        "parity_chunks".into(),
        Value::from(summary.parity_chunks as u64),
    );
    obj.insert("payload_bytes".into(), Value::from(summary.payload_bytes));
    obj.insert(
        "blob_hash_hex".into(),
        Value::from(summary.expected_blob_hash_hex.clone()),
    );
    obj.insert(
        "storage_ticket_hex".into(),
        Value::from(hex::encode(manifest.storage_ticket.as_bytes())),
    );
    obj.insert(
        "output_path".into(),
        Value::from(summary.output_path.clone()),
    );
    let rendered = norito::json::to_json_pretty(&Value::Object(obj))
        .wrap_err("failed to render summary JSON")?;
    let mut file = open_output_file(path, "summary JSON")?;
    file.write_all(rendered.as_bytes())
        .wrap_err_with(|| format!("failed to write summary `{}`", path.display()))
}
fn open_output_file(path: &Path, label: &str) -> Result<File> {
    validate_output_path(path)?;
    ensure_parent_dir(path)?;
    validate_output_path(path)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    set_no_follow_flag(&mut options);
    let file = options
        .open(path)
        .wrap_err_with(|| format!("failed to open {label} `{}`", path.display()))?;
    let metadata = file
        .metadata()
        .wrap_err_with(|| format!("failed to inspect {label} `{}` after open", path.display()))?;
    if !metadata.is_file() {
        return Err(eyre!(
            "failed to write {label} `{}`: output must be a regular file",
            path.display()
        ));
    }
    Ok(file)
}
fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create output parent `{}`", parent.display()))?;
    }
    Ok(())
}
fn validate_output_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(eyre!("output `{}` must not be a symlink", path.display()));
            }
            if metadata.is_dir() {
                return Err(eyre!("output `{}` must not be a directory", path.display()));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .wrap_err_with(|| format!("failed to inspect output `{}`", path.display()));
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
                        return Err(eyre!(
                            "output parent `{}` must not be a symlink",
                            ancestor.display()
                        ));
                    }
                    if !metadata.is_dir() {
                        return Err(eyre!(
                            "output parent `{}` must be a directory",
                            ancestor.display()
                        ));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).wrap_err_with(|| {
                        format!("failed to inspect output parent `{}`", ancestor.display())
                    });
                }
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, Signature};
    use iroha_data_model::{
        da::{
            commitment::{DaCommitmentBundle, DaCommitmentRecord, DaProofScheme},
            manifest::{ChunkCommitment, ChunkRole, DaManifestV1},
            types::{
                BlobClass, BlobCodec, BlobDigest, ChunkDigest, DaRentQuote, ErasureProfile,
                ExtraMetadata, FecScheme, RetentionPolicy, StorageTicketId,
            },
        },
        sorafs::pin_registry::ManifestDigest,
    };
    use iroha_model_base::topology::LaneId;
    use iroha_primitives::erasure::rs16;
    use norito::{
        json::{self as norito_json, Map as JsonMap, Value as JsonValue},
        to_bytes,
    };
    use sorafs_car::{CarBuildPlan, ChunkStore, build_plan_from_da_manifest};
    use sorafs_chunker::ChunkProfile;
    use std::path::PathBuf;
    use tempfile::{TempDir, tempdir};
    fn canonical_tempdir() -> (TempDir, PathBuf) {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().canonicalize().expect("canonical tempdir");
        (temp, path)
    }
    #[test]
    fn render_chunk_template_supports_width() {
        assert_eq!(
            render_chunk_template("chunk_{index:03}.bin", 7).expect("render"),
            "chunk_007.bin"
        );
        assert_eq!(
            render_chunk_template("chunk_{index:3}.bin", 7).expect("render"),
            "chunk_007.bin"
        );
        assert_eq!(
            render_chunk_template("prefix_{index}_suffix", 42).expect("render"),
            "prefix_42_suffix"
        );
        assert!(render_chunk_template("no-placeholder", 1).is_err());
    }
    #[test]
    fn render_chunk_template_rejects_unsafe_or_noncanonical_forms() {
        for template in [
            "chunk_{index:}.bin",
            "chunk_{index:0005}.bin",
            "chunk_{index:21}.bin",
            "chunk_{index:+5}.bin",
            "chunk_{index: 5}.bin",
            "../chunk_{index}.bin",
            "/tmp/chunk_{index}.bin",
            "nested/chunk_{index}.bin",
            "nested\\chunk_{index}.bin",
            "chunk_{index}\n.bin",
        ] {
            let err = render_chunk_template(template, 1).expect_err("invalid template must fail");
            let message = err.to_string();
            assert!(
                message.contains("width")
                    || message.contains("single path component")
                    || message.contains("regular filename")
                    || message.contains("control characters"),
                "unexpected error for {template:?}: {message}"
            );
        }
    }
    #[test]
    fn decode_manifest_accepts_canonical_hex_payloads() {
        let (manifest, _, _) = sample_manifest();
        let bytes = to_bytes(&manifest).expect("encode manifest");
        let encoded = hex::encode(&bytes);
        let decoded = decode_manifest_bytes(encoded.as_bytes()).expect("decode hex");
        assert_eq!(decoded, bytes);
        let parsed: DaManifestV1 = decode_from_bytes(&decoded).expect("decode manifest");
        assert_eq!(parsed.chunks.len(), manifest.chunks.len());
    }
    #[test]
    fn decode_manifest_rejects_noncanonical_hex_payloads() {
        for payload in ["", "0x4e52", "4E52", "4e52\n", "4e 52", "4e5"] {
            let err = decode_manifest_bytes(payload.as_bytes()).expect_err("invalid hex must fail");
            let message = err.to_string();
            assert!(
                message.contains("empty")
                    || message.contains("0x prefix")
                    || message.contains("lowercase")
                    || message.contains("whitespace")
                    || message.contains("even number"),
                "unexpected error for {payload:?}: {message}"
            );
        }
    }
    #[test]
    fn reconstructs_payload_from_chunks() {
        let (manifest, payload, parity_payloads) = sample_manifest();
        let plan = build_plan_from_da_manifest(&manifest).expect("plan");
        let (_dir, dir_path) = canonical_tempdir();
        for (index, chunk) in plan.chunks.iter().enumerate() {
            let path = dir_path
                .join(render_chunk_template(DEFAULT_CHUNK_TEMPLATE, index).expect("render"));
            let start = chunk.offset as usize;
            let end = start + chunk.length as usize;
            fs::write(path, &payload[start..end]).expect("write chunk");
        }
        for (index, bytes) in parity_payloads {
            let path = dir_path.join(
                render_chunk_template(DEFAULT_CHUNK_TEMPLATE, index as usize)
                    .expect("render parity"),
            );
            fs::write(path, bytes).expect("write parity chunk");
        }
        let out_path = dir_path.join("reconstructed.bin");
        let summary = reconstruct_payload(&manifest, &dir_path, &out_path, DEFAULT_CHUNK_TEMPLATE)
            .expect("reconstruct");
        let reconstructed = fs::read(&out_path).expect("read reconstructed");
        assert_eq!(reconstructed, payload);
        assert_eq!(summary.chunk_count, manifest.chunks.len());
        assert_eq!(summary.data_chunks, plan.chunks.len());
        assert_eq!(
            summary.parity_chunks,
            usize::from(manifest.erasure_profile.parity_shards)
        );
        assert_eq!(summary.payload_bytes, payload.len() as u64);
    }
    #[test]
    fn reconstructs_fixture_with_parity_chunks() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("workspace root")
            .join("fixtures/da/reconstruct/rs_parity_v1");
        let manifest_path = fixture_root.join("manifest.norito.hex");
        let manifest = load_manifest(&manifest_path).expect("fixture manifest");
        build_plan_from_da_manifest(&manifest)
            .expect("fixture manifest must produce a valid DA plan");
        let chunks_src = fixture_root.join("chunks");
        let (_temp_dir, temp_path) = canonical_tempdir();
        for entry in fs::read_dir(&chunks_src).expect("chunks dir") {
            let entry = entry.expect("chunk entry");
            let dst = temp_path.join(entry.file_name());
            fs::copy(entry.path(), dst).expect("copy chunk file");
        }
        let out_path = temp_path.join("reconstructed.bin");
        let summary = reconstruct_payload(&manifest, &temp_path, &out_path, DEFAULT_CHUNK_TEMPLATE)
            .expect("reconstruct fixture");
        assert_eq!(
            summary.parity_chunks,
            manifest.chunks.iter().filter(|chunk| chunk.parity).count()
        );
        assert_eq!(
            summary.data_chunks,
            manifest.chunks.iter().filter(|chunk| !chunk.parity).count()
        );
        let reconstructed = fs::read(&out_path).expect("read reconstructed");
        let expected = fs::read(fixture_root.join("payload.bin")).expect("read fixture payload");
        assert_eq!(reconstructed, expected);
    }
    #[test]
    fn open_output_file_creates_parent_and_writes_all_bytes() {
        let (_temp, temp_path) = canonical_tempdir();
        let output_path = temp_path.join("nested").join("payload.bin");
        let mut file = open_output_file(&output_path, "test output").expect("open output");
        file.write_all(b"da-reconstruct").expect("write output");
        drop(file);
        assert_eq!(
            fs::read(&output_path).expect("read output"),
            b"da-reconstruct"
        );
    }
    #[cfg(unix)]
    #[test]
    fn write_summary_json_rejects_symlink_output() {
        let (_temp, temp_path) = canonical_tempdir();
        let target_path = temp_path.join("target.json");
        fs::write(&target_path, b"unchanged\n").expect("write target");
        let output_path = temp_path.join("summary.json");
        std::os::unix::fs::symlink(&target_path, &output_path).expect("create symlink");
        let (manifest, _, _) = sample_manifest();
        let summary = sample_summary();
        let err = write_summary_json(&summary, &manifest, &output_path)
            .expect_err("reject symlink output");
        let message = err.to_string();
        assert!(
            message.contains("must not be a symlink"),
            "unexpected error: {message}"
        );
        assert_eq!(fs::read(&target_path).expect("read target"), b"unchanged\n");
    }
    #[cfg(unix)]
    #[test]
    fn open_output_file_rejects_symlink_parent() {
        let (_temp, temp_path) = canonical_tempdir();
        let real_dir = temp_path.join("real");
        fs::create_dir(&real_dir).expect("create real dir");
        let linked_dir = temp_path.join("linked");
        std::os::unix::fs::symlink(&real_dir, &linked_dir).expect("create symlink");
        let output_path = linked_dir.join("payload.bin");
        let err = match open_output_file(&output_path, "test output") {
            Ok(_) => panic!("symlink parent should be rejected"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("parent") && message.contains("must not be a symlink"),
            "unexpected error: {message}"
        );
        assert!(
            !real_dir.join("payload.bin").exists(),
            "symlink parent should not receive output"
        );
    }
    #[test]
    #[ignore = "regenerates DA reconstruction fixtures on disk"]
    fn regenerate_da_reconstruct_fixture_assets() {
        const STRIPES: usize = 3;
        const DATA_SHARDS: u16 = 2;
        const PARITY_SHARDS: u16 = 2;
        const CHUNK_SIZE: u32 = 32;
        let payload =
            build_fixture_payload(STRIPES * usize::from(DATA_SHARDS) * CHUNK_SIZE as usize);
        let chunk_profile = ChunkProfile {
            min_size: CHUNK_SIZE as usize,
            target_size: CHUNK_SIZE as usize,
            max_size: CHUNK_SIZE as usize,
            break_mask: 1,
        };
        let plan = CarBuildPlan::single_file_with_profile(&payload, chunk_profile)
            .expect("plan derivation succeeds");
        let mut chunk_store = ChunkStore::with_profile(chunk_profile);
        let (_chunk_temp_root, chunk_temp_path) = canonical_tempdir();
        let chunk_dir = chunk_temp_path.join("chunks");
        let mut reader: &[u8] = payload.as_slice();
        let chunk_output = chunk_store
            .ingest_plan_stream_to_directory(&plan, &mut reader, &chunk_dir)
            .expect("persist chunk files");
        let (manifest, data_chunk_indexes, parity_payloads) = build_fixture_manifest(
            &payload,
            &chunk_store,
            CHUNK_SIZE,
            DATA_SHARDS,
            PARITY_SHARDS,
        );
        let fixture_root = fixture_root_path();
        if fixture_root.exists() {
            fs::remove_dir_all(&fixture_root).expect("clean existing fixture directory");
        }
        let chunks_dir = fixture_root.join("chunks");
        fs::create_dir_all(&chunks_dir).expect("create chunks directory");
        assert_eq!(chunk_output.records.len(), data_chunk_indexes.len());
        for (record, manifest_index) in chunk_output.records.iter().zip(data_chunk_indexes) {
            let src = chunk_dir.join(&record.file_name);
            let dst = chunks_dir.join(format!("chunk_{manifest_index:05}.bin"));
            fs::copy(&src, &dst).expect("copy chunk file");
        }
        for (index, payload_bytes) in parity_payloads {
            let dst = chunks_dir.join(format!("chunk_{index:05}.bin"));
            fs::write(&dst, &payload_bytes).expect("write parity chunk");
        }
        let manifest_bytes = to_bytes(&manifest).expect("encode manifest");
        fs::write(
            fixture_root.join("manifest.norito.hex"),
            hex::encode(&manifest_bytes),
        )
        .expect("write manifest hex");
        let manifest_json = norito_json::to_json_pretty(&manifest).expect("manifest json");
        fs::write(fixture_root.join("manifest.json"), manifest_json.as_bytes())
            .expect("write manifest json");
        write_chunk_matrix_json(&manifest, &fixture_root.join("chunk_matrix.json"));
        fs::write(fixture_root.join("payload.bin"), &payload).expect("write payload copy");
        let manifest_digest = ManifestDigest::new(*blake3::hash(&manifest_bytes).as_bytes());
        let chunk_root_hash = Hash::prehashed(*manifest.chunk_root.as_ref());
        let proof_digest = Hash::prehashed(*blake3::hash(b"da-fixture-proof").as_bytes());
        let acknowledgement_sig = Signature::try_from_bytes(&[0xA5; 64])
            .expect("DA reconstruction fixture acknowledgement signature is nonzero");
        let record = DaCommitmentRecord::new(
            manifest.lane_id,
            manifest.epoch,
            42,
            manifest.client_blob_id,
            manifest_digest,
            DaProofScheme::MerkleSha256,
            chunk_root_hash,
            Some(proof_digest),
            manifest.retention_policy.clone(),
            manifest.storage_ticket,
            acknowledgement_sig,
        );
        let bundle = DaCommitmentBundle::new(vec![record]);
        let bundle_bytes = to_bytes(&bundle).expect("encode bundle");
        fs::write(
            fixture_root.join("commitment_bundle.norito.hex"),
            hex::encode(&bundle_bytes),
        )
        .expect("write bundle hex");
        let bundle_json = norito_json::to_json_pretty(&bundle).expect("bundle json");
        fs::write(
            fixture_root.join("commitment_bundle.json"),
            bundle_json.as_bytes(),
        )
        .expect("write bundle json");
        println!(
            "refreshed reconstruction fixture at {}",
            fixture_root.display()
        );
    }
    fn build_fixture_payload(total_bytes: usize) -> Vec<u8> {
        let mut payload = Vec::with_capacity(total_bytes);
        for idx in 0..total_bytes {
            let byte = (idx as u8).wrapping_mul(37).wrapping_add(11);
            payload.push(byte);
        }
        payload
    }
    type IndexedChunkPayloads = Vec<(u32, Vec<u8>)>;

    fn build_fixture_manifest(
        payload: &[u8],
        chunk_store: &ChunkStore,
        chunk_size: u32,
        data_shards: u16,
        parity_shards: u16,
    ) -> (DaManifestV1, Vec<u32>, IndexedChunkPayloads) {
        let stored = chunk_store.chunks();
        let data_shards_usize = usize::from(data_shards);
        let parity_shards_usize = usize::from(parity_shards);
        let stripe_count = stored.len().div_ceil(data_shards_usize);
        let commitment_count = stored
            .len()
            .checked_add(
                stripe_count
                    .checked_mul(parity_shards_usize)
                    .expect("fixture parity count"),
            )
            .expect("fixture commitment count");
        let mut chunk_commitments = Vec::with_capacity(commitment_count);
        let mut data_chunk_indexes = Vec::with_capacity(stored.len());
        let mut parity_payloads = Vec::with_capacity(
            stripe_count
                .checked_mul(parity_shards_usize)
                .expect("fixture parity count"),
        );
        let symbol_count = (chunk_size as usize / 2).max(1);
        let mut next_index = 0u32;
        for (stripe_idx, chunk_group) in stored.chunks(data_shards_usize).enumerate() {
            let stripe_id = u32::try_from(stripe_idx).expect("fixture stripe id");
            let mut stripe_symbols = Vec::with_capacity(data_shards_usize);
            for chunk in chunk_group {
                let start = usize::try_from(chunk.offset).expect("fixture chunk offset");
                let length = usize::try_from(chunk.length).expect("fixture chunk length");
                let end = start.checked_add(length).expect("fixture chunk range");
                let symbols = rs16::symbols_from_chunk(symbol_count, &payload[start..end]);
                stripe_symbols.push(symbols);
                let index = next_index;
                next_index = next_index.checked_add(1).expect("chunk index overflow");
                data_chunk_indexes.push(index);
                chunk_commitments.push(ChunkCommitment::new_with_role(
                    index,
                    chunk.offset,
                    chunk.length,
                    ChunkDigest::new(chunk.blake3),
                    ChunkRole::Data,
                    stripe_id,
                ));
            }
            while stripe_symbols.len() < data_shards_usize {
                stripe_symbols.push(vec![0u16; symbol_count]);
            }
            let parity_vectors = rs16::encode_parity(&stripe_symbols, parity_shards_usize)
                .expect("encode parity vectors");
            for (parity_idx, symbols) in parity_vectors.into_iter().enumerate() {
                let mut bytes = Vec::with_capacity(chunk_size as usize);
                for symbol in symbols {
                    bytes.extend_from_slice(&symbol.to_le_bytes());
                }
                let digest = blake3::hash(&bytes);
                let offset = rs16::parity_offset(
                    payload.len() as u64,
                    stripe_idx,
                    parity_idx,
                    parity_shards_usize,
                    chunk_size,
                )
                .expect("parity offset");
                let index = next_index;
                next_index = next_index.checked_add(1).expect("chunk index overflow");
                chunk_commitments.push(ChunkCommitment::new_with_role(
                    index,
                    offset,
                    chunk_size,
                    ChunkDigest::new(*digest.as_bytes()),
                    ChunkRole::GlobalParity,
                    stripe_id,
                ));
                parity_payloads.push((index, bytes));
            }
        }
        let total_stripes = u32::try_from(stripe_count).expect("fixture stripe count");
        let shards_per_stripe = u32::from(data_shards.saturating_add(parity_shards));
        let manifest = DaManifestV1 {
            version: DaManifestV1::VERSION,
            client_blob_id: BlobDigest::from_hash(blake3::hash(b"fixture-client")),
            lane_id: LaneId::new(9),
            epoch: 7,
            blob_class: BlobClass::NexusLaneSidecar,
            codec: BlobCodec::new("fixture.binary"),
            blob_hash: BlobDigest::from_hash(blake3::hash(payload)),
            chunk_root: BlobDigest::new(*chunk_store.por_tree().root()),
            storage_ticket: StorageTicketId::new(*blake3::hash(b"fixture-ticket").as_bytes()),
            total_size: payload.len() as u64,
            chunk_size,
            total_stripes,
            shards_per_stripe,
            erasure_profile: ErasureProfile {
                data_shards,
                parity_shards,
                row_parity_stripes: 0,
                chunk_alignment: data_shards,
                fec_scheme: FecScheme::Rs12_10,
            },
            retention_policy: RetentionPolicy::default(),
            rent_quote: DaRentQuote::default(),
            chunks: chunk_commitments,
            ipa_commitment: BlobDigest::new(*chunk_store.por_tree().root()),
            metadata: ExtraMetadata::default(),
            issued_at_unix: 1_701_111_111,
        };
        (manifest, data_chunk_indexes, parity_payloads)
    }
    fn fixture_root_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("workspace root")
            .join("fixtures/da/reconstruct/rs_parity_v1")
    }
    fn write_chunk_matrix_json(manifest: &DaManifestV1, output: &Path) {
        let mut rows = Vec::with_capacity(manifest.chunks.len());
        for chunk in &manifest.chunks {
            let mut obj = JsonMap::new();
            obj.insert("index".into(), JsonValue::from(u64::from(chunk.index)));
            obj.insert("offset".into(), JsonValue::from(chunk.offset));
            obj.insert("length".into(), JsonValue::from(chunk.length));
            obj.insert("parity".into(), JsonValue::from(chunk.parity));
            obj.insert(
                "digest_hex".into(),
                JsonValue::from(hex::encode(chunk.commitment.as_ref())),
            );
            rows.push(JsonValue::Object(obj));
        }
        let rendered =
            norito_json::to_json_pretty(&JsonValue::Array(rows)).expect("render chunk matrix json");
        fs::write(output, rendered.as_bytes()).expect("write chunk matrix json");
    }
    fn sample_summary() -> ReconstructionSummary {
        ReconstructionSummary {
            chunk_count: 1,
            data_chunks: 1,
            parity_chunks: 0,
            payload_bytes: 16,
            expected_blob_hash_hex: hex::encode([0x11; 32]),
            output_path: "payload.bin".to_owned(),
        }
    }
    fn sample_manifest() -> (DaManifestV1, Vec<u8>, IndexedChunkPayloads) {
        let payload = b"chunked payload example bytes for reconstruction harness".to_vec();
        let plan = CarBuildPlan::single_file(&payload).expect("plan");
        let mut chunk_store = ChunkStore::with_profile(ChunkProfile::DEFAULT);
        chunk_store
            .ingest_plan(&payload, &plan)
            .expect("ingest plan");
        let profile = ErasureProfile::default();
        let (manifest, _, parity_payloads) = build_fixture_manifest(
            &payload,
            &chunk_store,
            64,
            profile.data_shards,
            profile.parity_shards,
        );
        (manifest, payload, parity_payloads)
    }
}
