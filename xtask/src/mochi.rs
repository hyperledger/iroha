//! Build and inspect a complete native developer runtime bundle.

use crate::{
    kagami_bundle::{
        admit_published_output, collect_native_programs, copy_program, digest,
        retain_created_output, retain_output,
    },
    network_profiles, workspace_root,
};
use iroha_deploy::managed::{NativeBundleLayout, admit_native_build_input, macos_info_plist};
use iroha_fs::{
    FileSnapshot, OwnerDirectory, PrivateDirectory, PublishMode, ReaderDirectory,
    RetainedBuildInput, RetainedFile, SealedPrivateFile,
};
use norito::json::{self, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    ffi::OsString,
    fs,
    io::{BufReader, Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use walkdir::WalkDir;
mod developer_smoke;
#[cfg(test)]
mod network_profile_tests;
#[cfg(test)]
use iroha_deploy::bootstrap::InstalledNetworkProfiles;
pub(crate) mod latency;
const MOCHI_UI_MANIFEST_REL: &str = "mochi/mochi-ui-egui/Cargo.toml";
const MOCHI_BIN_NAME: &str = "mochi";
const MOCHI_HELP_HEADER: &str = "Usage: mochi [--workspace <DIRECTORY>]";
const RUNTIME_BINARIES: [&str; 3] = ["mochi", "kagami", "iroha3d"];
pub(crate) struct MochiBundleResult {
    pub target: String,
    pub profile: String,
    pub bundle_name: String,
    pub output_root: PathBuf,
    pub bundle_root: PathBuf,
    pub manifest_path: PathBuf,
    pub archive_path: Option<PathBuf>,
    archive_sha256: Option<String>,
    network_profiles: Option<network_profiles::Selection>,
    custody: Mutex<BundleResultCustody>,
}

impl std::fmt::Debug for MochiBundleResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MochiBundleResult")
            .field("target", &self.target)
            .field("profile", &self.profile)
            .field("bundle_root", &self.bundle_root)
            .field("archive_path", &self.archive_path)
            .finish_non_exhaustive()
    }
}

pub(crate) fn bundle_mochi(
    output_root: &Path,
    profile: &str,
    archive: bool,
    network_profiles: Option<&Path>,
) -> Result<MochiBundleResult, Box<dyn Error>> {
    validate_bundle_profile(profile)?;
    let host = format!("{}-{}", env::consts::OS, env::consts::ARCH);
    let bundle_name = format!("mochi-{host}-{profile}");
    let bundle_root = output_root.join(&bundle_name);
    let archive_path = archive.then(|| output_root.join(format!("{bundle_name}.tar.gz")));
    // Refuse every existing entry, including broken links, before profiles, Cargo or output
    // creation. Successful builds and invalid foreign inputs cannot erase a prior package.
    refuse_existing(&bundle_root)?;
    if let Some(path) = &archive_path {
        refuse_existing(path)?;
    }
    let network_profiles = network_profiles::select(&workspace_root(), profile, network_profiles)?;
    let programs = build_runtime(profile)?;
    let publication = publish_bundle(
        &programs,
        &bundle_root,
        profile,
        network_profiles.as_ref(),
        &mut |_| {
            if let Some(path) = &archive_path {
                refuse_existing(path)?;
            }
            Ok(())
        },
    )?;
    let bundle_root = publication.directory.path().to_path_buf();
    let output_root = bundle_root
        .parent()
        .ok_or("published bundle has no parent")?
        .to_path_buf();
    let archive = if archive {
        Some(create_archive(&output_root, &bundle_name, &bundle_root)?)
    } else {
        None
    };
    let result = completed_bundle(publication, archive, network_profiles)?;
    drop(retained_bundle(&result)?);
    Ok(result)
}

fn completed_bundle(
    publication: BundlePublication,
    archive: Option<(PathBuf, RetainedImage)>,
    network_profiles: Option<network_profiles::Selection>,
) -> Result<MochiBundleResult, Box<dyn Error>> {
    let bundle_root = publication.directory.path().to_path_buf();
    let output_root = bundle_root
        .parent()
        .ok_or("published bundle has no parent")?
        .to_path_buf();
    let bundle_name = bundle_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("published bundle has no canonical name")?
        .to_owned();
    let target = publication.manifest["target"]
        .as_str()
        .ok_or("published bundle has no target")?
        .to_owned();
    Ok(MochiBundleResult {
        target,
        profile: publication.profile.clone(),
        bundle_name,
        output_root,
        manifest_path: bundle_root.join("manifest.json"),
        bundle_root,
        archive_path: archive.as_ref().map(|(path, _)| path.clone()),
        archive_sha256: archive.as_ref().map(|(_, (_, _, hash))| hash.clone()),
        network_profiles,
        custody: Mutex::new(BundleResultCustody {
            publication,
            archive,
        }),
    })
}

fn refuse_existing(path: &Path) -> Result<(), Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!(
            "bundle output already exists: {}; select a fresh --out directory",
            path.display()
        )
        .into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

type RetainedImage = (RetainedFile, FileSnapshot, String);

struct BundleCustody {
    inputs: Vec<RetainedImage>,
    build_inputs: Vec<(RetainedBuildInput, FileSnapshot, String)>,
    outputs: Vec<(PathBuf, RetainedImage)>,
    created: Vec<(Option<fs::File>, FileSnapshot)>,
}

impl BundleCustody {
    fn verify(&mut self) -> Result<(), Box<dyn Error>> {
        for (file, snapshot, hash) in &mut self.build_inputs {
            if file.snapshot()? != *snapshot
                || digest(file)? != *hash
                || file.snapshot()? != *snapshot
            {
                return Err("Mochi build input changed before publication".into());
            }
        }
        for (file, snapshot, hash) in self
            .inputs
            .iter_mut()
            .chain(self.outputs.iter_mut().map(|(_, image)| image))
        {
            if file.snapshot()? != *snapshot
                || digest(file)? != *hash
                || file.snapshot()? != *snapshot
            {
                return Err("Mochi bundle input or output changed before publication".into());
            }
        }
        for (file, snapshot) in &self.created {
            if let Some(file) = file {
                if FileSnapshot::of(file, false)? != *snapshot {
                    return Err("created Mochi program changed before publication".into());
                }
            }
        }
        Ok(())
    }
}

struct BundlePublication {
    directory: PrivateDirectory,
    namespaces: Vec<(ReaderDirectory, FileSnapshot)>,
    custody: BundleCustody,
    manifest: Value,
    profile: String,
}

impl BundlePublication {
    fn verify(&mut self) -> Result<(), Box<dyn Error>> {
        self.directory.revalidate()?;
        for (directory, snapshot) in &self.namespaces {
            if directory.snapshot()? != *snapshot {
                return Err("Mochi published directory namespace changed".into());
            }
        }
        self.custody.verify()?;
        let current = generate_manifest_json(self.directory.path(), &self.profile)?;
        for field in ["target", "profile", "files"] {
            if current[field] != self.manifest[field] {
                return Err("Mochi published inventory changed during archive creation".into());
            }
        }
        self.custody.verify()?;
        for (directory, snapshot) in &self.namespaces {
            if directory.snapshot()? != *snapshot {
                return Err(
                    "Mochi published directory namespace changed during final checks".into(),
                );
            }
        }
        self.directory.revalidate()?;
        Ok(())
    }
}

fn publish_bundle(
    programs: &BTreeMap<String, PathBuf>,
    bundle_root: &Path,
    profile: &str,
    profiles: Option<&network_profiles::Selection>,
    before_publication: &mut dyn FnMut(&Path) -> Result<(), Box<dyn Error>>,
) -> Result<BundlePublication, Box<dyn Error>> {
    validate_bundle_profile(profile)?;
    network_profiles::require_for_profile(profile, profiles)?;
    refuse_existing(bundle_root)?;
    let parent =
        OwnerDirectory::open_or_create(bundle_root.parent().ok_or("Mochi bundle has no parent")?)?;
    let staging = parent.create_private_child(format!(
        ".mochi-stage-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    ))?;
    let mut custody = copy_runtime_binaries(programs, staging.path())?;
    if let Some((input, output)) = stage_application_metadata(staging.path())? {
        custody.inputs.push(input);
        custody
            .outputs
            .push((PathBuf::from("Mochi.app/Contents/Info.plist"), output));
    }
    if let Some(profiles) = profiles {
        custody.outputs.push((
            NativeBundleLayout::current().profiles_path(Path::new("")),
            write_bundle_file(
                &NativeBundleLayout::current().profiles_path(staging.path()),
                profiles.bytes(),
            )?,
        ));
        profiles.verify_installed(&NativeBundleLayout::current().profiles_path(staging.path()))?;
    }
    for (source, relative) in [
        ("LICENSE", "LICENSE"),
        ("mochi/BUNDLE_README.md", "docs/README.md"),
    ] {
        let (input, output) = copy_into_bundle(source, &staging.path().join(relative))?;
        custody.inputs.push(input);
        custody.outputs.push((PathBuf::from(relative), output));
    }
    let manifest = generate_manifest_json(staging.path(), profile)?;
    let mut manifest_text = json::to_string_pretty(&manifest)?;
    manifest_text.push('\n');
    custody.outputs.push((
        PathBuf::from("manifest.json"),
        write_bundle_file(
            &staging.path().join("manifest.json"),
            manifest_text.as_bytes(),
        )?,
    ));
    finalize_bundle(
        staging,
        custody,
        manifest,
        bundle_root,
        profile,
        profiles,
        before_publication,
    )
}

// Both original packaging and distribution copies use the same close/reopen publication gate.
fn finalize_bundle(
    staging: PrivateDirectory,
    mut custody: BundleCustody,
    manifest: Value,
    bundle_root: &Path,
    profile: &str,
    profiles: Option<&network_profiles::Selection>,
    before_publication: &mut dyn FnMut(&Path) -> Result<(), Box<dyn Error>>,
) -> Result<BundlePublication, Box<dyn Error>> {
    sync_tree(staging.path())?;
    staging.sync()?;
    before_publication(staging.path())?;
    custody.verify()?;
    if let Some(profiles) = profiles {
        profiles.verify_installed(&NativeBundleLayout::current().profiles_path(staging.path()))?;
    }
    let current = generate_manifest_json(staging.path(), profile)?;
    for field in ["target", "profile", "files"] {
        if current[field] != manifest[field] {
            return Err("Mochi bundle inventory changed before publication".into());
        }
    }
    // Windows cannot rename a directory with any open descendant file. Close path-sensitive
    // output readers, retaining the exact snapshots and original Cargo source authority.
    // Unix also keeps the raw exclusively created program descriptors. Final outputs are
    // independently admitted against both exact native snapshots and original content hashes.
    let output_snapshots: Vec<_> = std::mem::take(&mut custody.outputs)
        .into_iter()
        .map(|(relative, (file, snapshot, hash))| {
            drop(file);
            (relative, snapshot, hash)
        })
        .collect();
    let directory = staging.rename_to_sibling(
        bundle_root.file_name().ok_or("Mochi bundle has no name")?,
        PublishMode::CreateNew,
    )?;
    // Retain one original directory graph and share it across every output and namespace.
    // Reopening the entire native ancestor chain for each file otherwise exhausts the native
    // descriptor limit for ordinary macOS application layouts and nested workspace paths.
    let root_reader = ReaderDirectory::open(directory.path())?;
    let root_snapshot = root_reader.snapshot()?;
    let mut namespaces = BTreeMap::from([(PathBuf::new(), (root_reader, root_snapshot))]);
    for (relative, snapshot, hash) in output_snapshots {
        let program = RUNTIME_BINARIES
            .iter()
            .any(|name| NativeBundleLayout::current().executable(Path::new(""), name) == relative);
        let parent = retain_bundle_directory(
            &mut namespaces,
            relative
                .parent()
                .ok_or("published bundle file has no parent")?,
        )?;
        let file = parent.open_retained_regular(
            relative
                .file_name()
                .ok_or("published bundle file has no name")?,
        )?;
        let output = admit_published_output(file, snapshot, hash, program)?;
        custody.outputs.push((relative, output));
    }
    for entry in WalkDir::new(directory.path()).follow_root_links(false) {
        let entry = entry.map_err(std::io::Error::other)?;
        if entry.file_type().is_dir() {
            retain_bundle_directory(
                &mut namespaces,
                entry.path().strip_prefix(directory.path())?,
            )?;
        }
    }
    let namespaces = namespaces.into_values().collect();
    let mut publication = BundlePublication {
        directory,
        namespaces,
        custody,
        manifest,
        profile: profile.into(),
    };
    publication.verify()?;
    Ok(publication)
}

// A namespace is opened once through its already-retained original parent. A later lookup
// rechecks both its exact snapshot and all original native ancestors before borrowing it.
fn retain_bundle_directory<'a>(
    namespaces: &'a mut BTreeMap<PathBuf, (ReaderDirectory, FileSnapshot)>,
    relative: &Path,
) -> Result<&'a ReaderDirectory, Box<dyn Error>> {
    if !relative
        .components()
        .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return Err("bundle namespace requires a direct relative path".into());
    }
    if !namespaces.contains_key(relative) {
        let parent = relative
            .parent()
            .ok_or("bundle namespace has no retained parent")?;
        let name = relative.file_name().ok_or("bundle namespace has no name")?;
        let child = retain_bundle_directory(namespaces, parent)?.open_child(name)?;
        let snapshot = child.snapshot()?;
        namespaces.insert(relative.to_path_buf(), (child, snapshot));
    }
    let (directory, snapshot) = namespaces
        .get(relative)
        .ok_or("bundle namespace root is absent")?;
    if directory.snapshot()? != *snapshot {
        return Err("Mochi published directory namespace changed".into());
    }
    Ok(directory)
}

fn sync_tree(root: &Path) -> Result<(), Box<dyn Error>> {
    for entry in WalkDir::new(root)
        .follow_root_links(false)
        .contents_first(true)
    {
        let entry = entry?;
        if entry.file_type().is_dir() {
            OwnerDirectory::open(entry.path())?.sync()?;
        } else if !entry.file_type().is_file() {
            return Err("Mochi tree contains an indirect or nonregular entry".into());
        }
    }
    Ok(())
}

const MAX_BUNDLE_TEXT_BYTES: u64 = 1024 * 1024;

fn read_bundle_source(path: &Path) -> Result<(Vec<u8>, RetainedImage), Box<dyn Error>> {
    let mut file = RetainedFile::open_regular(path)?;
    let snapshot = file.snapshot()?;
    let mut bytes = Vec::new();
    file.file_mut()
        .take(MAX_BUNDLE_TEXT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BUNDLE_TEXT_BYTES || file.snapshot()? != snapshot {
        return Err("Mochi metadata source exceeds its bound or changed while reading".into());
    }
    let hash = sha256_hex(&bytes);
    Ok((bytes, (file, snapshot, hash)))
}

fn write_bundle_file(path: &Path, bytes: &[u8]) -> Result<RetainedImage, Box<dyn Error>> {
    let parent =
        OwnerDirectory::open_or_create(path.parent().ok_or("Mochi output has no parent")?)?;
    parent.write_atomic(
        path.file_name().ok_or("Mochi output has no name")?,
        bytes,
        PublishMode::CreateNew,
    )?;
    retain_output(path, sha256_hex(bytes))
}

/// Refuse the workspace's explicitly non-packaging profile before doing any work.
pub(crate) fn validate_bundle_profile(profile: &str) -> Result<(), &'static str> {
    if profile == "local-release" {
        return Err(
            "local-release is only for local runnable builds; it cannot package or qualify a developer runtime",
        );
    }
    Ok(())
}

#[cfg(test)]
fn load_network_profiles(
    source: Option<&Path>,
) -> Result<Option<network_profiles::Selection>, Box<dyn Error>> {
    network_profiles::select(&workspace_root(), "debug", source)
}

fn stage_application_metadata(
    bundle_root: &Path,
) -> Result<Option<(RetainedImage, RetainedImage)>, Box<dyn Error>> {
    if NativeBundleLayout::current() != NativeBundleLayout::MacOs {
        return Ok(None);
    }
    let (source, input) = read_bundle_source(&mochi_ui_manifest_path())?;
    let manifest: toml::Value = toml::from_str(std::str::from_utf8(&source)?)?;
    let version = manifest
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or("Mochi package has no explicit release version")?;
    OwnerDirectory::open_or_create(NativeBundleLayout::MacOs.resources_directory(bundle_root))?;
    let output = write_bundle_file(
        &bundle_root.join("Mochi.app/Contents/Info.plist"),
        macos_info_plist(version)?.as_bytes(),
    )?;
    Ok(Some((input, output)))
}

#[cfg(test)]
fn stage_network_profiles(
    profiles: Option<&InstalledNetworkProfiles>,
    bundle_root: &Path,
) -> Result<(), Box<dyn Error>> {
    if let Some(profiles) = profiles {
        network_profiles::development(profiles)?
            .stage(&NativeBundleLayout::current().profiles_path(bundle_root))?;
    }
    Ok(())
}

pub(crate) fn run_bundle_smoke(result: &MochiBundleResult) -> Result<(), Box<dyn Error>> {
    drop(retained_bundle(result)?);
    if let Some(profiles) = &result.network_profiles {
        let kagami = NativeBundleLayout::current().executable(&result.bundle_root, "kagami");
        let mut probe = developer_smoke::Harness::new(&kagami)?;
        profiles.require_cli_names(&json::to_vec(&probe.network_names()?)?)?;
        drop(retained_bundle(result)?);
    }
    let mochi_bin = NativeBundleLayout::current().executable(&result.bundle_root, "mochi");
    if !mochi_bin.exists() {
        return Err(format!("missing mochi binary at {}", mochi_bin.display()).into());
    }
    let output = Command::new(&mochi_bin).arg("--help").output()?;
    if !output.status.success() {
        Err(format!(
            "`{}` --help exited with status {:?}: {}",
            mochi_bin.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into())
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Err(reason) = validate_mochi_help_output(&stdout) {
            return Err(format!(
                "`{}` --help did not expose the packaged Mochi CLI: {reason}; stdout: {}",
                mochi_bin.display(),
                stdout.trim()
            )
            .into());
        }
        drop(retained_bundle(result)?);
        developer_smoke::run(
            &NativeBundleLayout::current().executable(&result.bundle_root, "kagami"),
        )?;
        drop(retained_bundle(result)?);
        developer_smoke::cold_start_smoke::run(
            &NativeBundleLayout::current().executable(&result.bundle_root, "kagami"),
        )?;
        drop(retained_bundle(result)?);
        Ok(())
    }
}
struct BundleResultCustody {
    publication: BundlePublication,
    archive: Option<(PathBuf, RetainedImage)>,
}

impl BundleResultCustody {
    fn verify(&mut self, result: &MochiBundleResult) -> Result<(), Box<dyn Error>> {
        let publication = &mut self.publication;
        if result.bundle_root != publication.directory.path()
            || result.output_root
                != publication
                    .directory
                    .path()
                    .parent()
                    .ok_or("bundle parent absent")?
            || result.manifest_path != publication.directory.path().join("manifest.json")
            || publication
                .directory
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                != Some(result.bundle_name.as_str())
            || result.profile != publication.profile
            || publication.manifest["target"].as_str() != Some(result.target.as_str())
        {
            return Err("reported bundle differs from its retained publication".into());
        }
        publication.verify()?;
        match (
            &result.archive_path,
            &result.archive_sha256,
            &mut self.archive,
        ) {
            (Some(path), Some(expected), Some((original, (file, snapshot, hash))))
                if path == original && expected == hash =>
            {
                if file.snapshot()? != *snapshot
                    || archive_digest_retained(file)? != *hash
                    || file.snapshot()? != *snapshot
                {
                    return Err("bundle archive differs from its retained completed output".into());
                }
            }
            (None, None, None) => {}
            _ => return Err("reported archive differs from its retained publication".into()),
        }
        network_profiles::require_for_profile(&result.profile, result.network_profiles.as_ref())?;
        match &result.network_profiles {
            Some(profiles) => profiles.verify_installed(
                &NativeBundleLayout::current().profiles_path(&result.bundle_root),
            )?,
            None => match fs::symlink_metadata(
                NativeBundleLayout::current().profiles_path(&result.bundle_root),
            ) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(
                        "unexpected network profile in profile-free development bundle".into(),
                    );
                }
            },
        }
        publication.verify()?;
        Ok(())
    }
}

fn retained_bundle(
    result: &MochiBundleResult,
) -> Result<MutexGuard<'_, BundleResultCustody>, Box<dyn Error>> {
    let mut custody = result
        .custody
        .lock()
        .map_err(|_| "bundle verification owner is poisoned")?;
    custody.verify(result)?;
    Ok(custody)
}

fn validate_mochi_help_output(stdout: &str) -> Result<(), String> {
    if !stdout.contains(MOCHI_HELP_HEADER) {
        return Err(format!("missing `{MOCHI_HELP_HEADER}`"));
    }
    Ok(())
}
pub(crate) fn update_bundle_matrix(
    result: &MochiBundleResult,
    matrix_path: &Path,
    smoke_passed: bool,
) -> Result<(), Box<dyn Error>> {
    let mut original = retained_bundle(result)?;
    let resolved_matrix = resolve_stage_root(matrix_path)?;
    if resolved_matrix.starts_with(original.publication.directory.path()) {
        return Err("matrix output must be outside the retained source bundle".into());
    }
    let matrix_path = resolved_matrix.as_path();
    if let Some(parent) = matrix_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let timestamp = u64::try_from(timestamp_ms).unwrap_or(u64::MAX);
    let mut root_map = if matrix_path.exists() {
        let raw = fs::read_to_string(matrix_path)?;
        let value: Value = json::from_str(&raw)?;
        value.as_object().cloned().unwrap_or_else(Map::new)
    } else {
        Map::new()
    };
    if !root_map.contains_key("generated_unix_ms") {
        root_map.insert("generated_unix_ms".into(), Value::from(timestamp));
    }
    root_map.insert("updated_unix_ms".into(), Value::from(timestamp));
    let mut entries = match root_map.remove("entries") {
        Some(Value::Array(entries)) => entries,
        Some(other) => {
            return Err(format!(
                "expected `entries` to be an array in {} but found {other:?}",
                matrix_path.display()
            )
            .into());
        }
        None => Vec::new(),
    };
    let target_value = Value::from(result.target.clone());
    let profile_value = Value::from(result.profile.clone());
    entries.retain(|entry| {
        entry
            .as_object()
            .map(|object| {
                let target_matches = object.get("target") == Some(&target_value);
                let profile_matches = object.get("profile") == Some(&profile_value);
                !(target_matches && profile_matches)
            })
            .unwrap_or(true)
    });
    let manifest_sha256 = original
        .publication
        .custody
        .outputs
        .iter()
        .find(|(path, _)| path == Path::new("manifest.json"))
        .ok_or("retained bundle manifest absent")?
        .1
        .2
        .clone();
    let mut entry = Map::new();
    entry.insert("target".into(), Value::from(result.target.clone()));
    entry.insert("profile".into(), Value::from(result.profile.clone()));
    entry.insert("bundle".into(), Value::from(result.bundle_name.clone()));
    entry.insert("bundle_dir".into(), Value::from(result.bundle_name.clone()));
    entry.insert(
        "manifest".into(),
        Value::from(format!("{}/manifest.json", result.bundle_name)),
    );
    entry.insert("manifest_sha256".into(), Value::from(manifest_sha256));
    if let Some(archive) = &result.archive_path {
        if let Ok(relative) = archive.strip_prefix(&result.output_root) {
            entry.insert(
                "archive".into(),
                Value::from(relative.to_string_lossy().into_owned()),
            );
        } else if let Some(file_name) = archive.file_name() {
            entry.insert(
                "archive".into(),
                Value::from(file_name.to_string_lossy().into_owned()),
            );
        }
    }
    if let Some(digest) = &result.archive_sha256 {
        entry.insert("archive_sha256".into(), Value::from(digest.clone()));
    }
    entry.insert("generated_unix_ms".into(), Value::from(timestamp));
    entry.insert("smoke_passed".into(), Value::from(smoke_passed));
    entry.insert(
        "network_profiles".into(),
        result
            .network_profiles
            .as_ref()
            .map_or(Value::Null, network_profiles::Selection::provenance),
    );
    entry.insert(
        "qualification".into(),
        Value::from("local_native_diagnostic"),
    );
    entry.insert(
        "official_taira_attachment_qualified".into(),
        Value::from(false),
    );
    entries.push(Value::Object(entry));
    root_map.insert("entries".into(), Value::Array(entries));
    let mut text = json::to_string_pretty(&Value::Object(root_map))?;
    text.push('\n');
    original.verify(result)?;
    fs::write(matrix_path, text)?;
    original.verify(result)?;
    Ok(())
}
pub(crate) fn stage_bundle(
    result: &MochiBundleResult,
    stage_root: &Path,
) -> Result<(), Box<dyn Error>> {
    stage_bundle_checked(result, stage_root, &mut |_| Ok(()), &mut |_| Ok(()))
}

fn stage_bundle_checked(
    result: &MochiBundleResult,
    stage_root: &Path,
    before_publication: &mut dyn FnMut(&Path) -> Result<(), Box<dyn Error>>,
    after_bundle_publication: &mut dyn FnMut(&Path) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let stage_root = resolve_stage_root(stage_root)?;
    if stage_root.starts_with(&result.bundle_root) {
        return Err("staging root must be outside the retained source bundle".into());
    }
    let destination = stage_root.join(&result.bundle_name);
    let archive_name = result
        .archive_path
        .as_ref()
        .map(|path| path.file_name().ok_or("archive filename absent"))
        .transpose()?;
    refuse_existing(&destination)?;
    if let Some(name) = archive_name {
        refuse_existing(&stage_root.join(name))?;
    }
    let mut original = retained_bundle(result)?;
    // Existing public or unsafe roots are refused, never hardened or emptied in place.
    let parent = PrivateDirectory::open_or_create(&stage_root)?;
    let staging = parent.create_child(format!(
        ".mochi-stage-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    ))?;
    let mut archive = if let Some((_, source)) = &mut original.archive {
        Some(copy_staged_archive(source, &parent)?)
    } else {
        None
    };
    let mut copied = BundleCustody {
        inputs: Vec::new(),
        build_inputs: Vec::new(),
        outputs: Vec::new(),
        created: Vec::new(),
    };
    for (relative, (source, snapshot, hash)) in &mut original.publication.custody.outputs {
        let destination = staging.path().join(relative.as_path());
        let program = RUNTIME_BINARIES
            .iter()
            .any(|name| NativeBundleLayout::current().executable(Path::new(""), name) == *relative);
        OwnerDirectory::open_or_create(destination.parent().ok_or("staged file parent absent")?)?;
        let (file, snapshot, hash) = if program {
            let (file, copied_snapshot, copied_hash, created) =
                copy_program(source, *snapshot, hash, &destination)?;
            copied.created.push((created, copied_snapshot));
            (file, copied_snapshot, copied_hash)
        } else {
            let bytes = read_retained_bundle_text(source, *snapshot, hash)?;
            write_bundle_file(&destination, &bytes)?
        };
        copied
            .outputs
            .push((relative.clone(), (file, snapshot, hash)));
    }
    original.verify(result)?;
    if let Some(archive) = &mut archive {
        archive.verify()?;
    }
    let manifest = original.publication.manifest.clone();
    let mut publication = finalize_bundle(
        staging,
        copied,
        manifest,
        &destination,
        &result.profile,
        result.network_profiles.as_ref(),
        &mut |path| {
            before_publication(path)?;
            original.verify(result)?;
            if let Some(archive) = &mut archive {
                archive.verify()?;
            }
            if let Some(name) = archive_name {
                refuse_existing(&parent.path().join(name))?;
            }
            Ok(())
        },
    )?;
    // The directory and archive publish separately. Refresh the expected namespace immediately
    // after the known directory rename, before any later operation. Subsequent foreign changes
    // must not be absorbed into a new baseline. Neither a partial pair nor either single output
    // is success, and every later failure reports the originally created recovery names.
    let pending_archive = archive
        .as_ref()
        .map(|archive| parent.path().join(&archive.pending_name));
    let archive_destination = archive_name.map(|name| parent.path().join(name));
    let completion = (|| -> Result<(), Box<dyn Error>> {
        if let Some(archive) = &mut archive {
            archive.refresh_namespace()?;
        }
        after_bundle_publication(publication.directory.path())?;
        publication.verify()?;
        original.verify(result)?;
        let mut published_archive =
            if let (Some(mut archive), Some(name)) = (archive.take(), archive_name) {
                archive.verify()?;
                let file = archive.file.publish_new_name(name)?;
                let snapshot = file.snapshot()?;
                Some((file, snapshot, archive.hash))
            } else {
                None
            };
        let namespace = ReaderDirectory::open(parent.path())?;
        let namespace_snapshot = namespace.snapshot()?;
        publication.verify()?;
        original.verify(result)?;
        if let Some((file, snapshot, hash)) = &mut published_archive {
            if file.snapshot()? != *snapshot
                || sealed_archive_digest(file)? != *hash
                || file.snapshot()? != *snapshot
            {
                return Err("staged archive changed before reporting completion".into());
            }
        }
        publication.verify()?;
        original.verify(result)?;
        if namespace.snapshot()? != namespace_snapshot {
            return Err("staging namespace changed during final completion checks".into());
        }
        parent.revalidate()?;
        Ok(())
    })();
    completion.map_err(|error| {
        let archive_recovery = match (&pending_archive, &archive_destination) {
            (Some(pending), Some(destination)) => format!(
                "; pending archive {}; archive destination {}",
                pending.display(), destination.display()
            ),
            _ => String::new(),
        };
        format!(
            "bundle directory was published at {}; staging did not complete{archive_recovery}: {error}; retain names for reconciliation",
            publication.directory.path().display(),
        ).into()
    })
}

// Resolve the nearest existing ancestor before creating anything, including indirect aliases.
fn resolve_stage_root(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let mut ancestor = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(&ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor
                    .file_name()
                    .ok_or("staging path has no existing ancestor")?
                    .to_owned();
                suffix.push(name);
                if !ancestor.pop() {
                    return Err("staging path has no existing ancestor".into());
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut resolved = ancestor.canonicalize()?;
    for name in suffix.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

fn read_retained_bundle_text(
    source: &mut RetainedFile,
    snapshot: FileSnapshot,
    expected_hash: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if source.snapshot()? != snapshot {
        return Err("original bundle text changed before staging".into());
    }
    source.file_mut().seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    source
        .file_mut()
        .take(MAX_BUNDLE_TEXT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BUNDLE_TEXT_BYTES
        || sha256_hex(&bytes) != expected_hash
        || source.snapshot()? != snapshot
    {
        return Err("original bundle text changed or exceeds its packaging bound".into());
    }
    Ok(bytes)
}

const MAX_BUNDLE_ARCHIVE_BYTES: u64 = 32 * 1024 * 1024 * 1024;

struct StagedArchive {
    file: SealedPrivateFile,
    snapshot: FileSnapshot,
    hash: String,
    pending_name: OsString,
    namespace: ReaderDirectory,
    namespace_snapshot: FileSnapshot,
}

impl StagedArchive {
    fn verify(&mut self) -> Result<(), Box<dyn Error>> {
        if self.file.snapshot()? != self.snapshot
            || sealed_archive_digest(&mut self.file)? != self.hash
            || self.file.snapshot()? != self.snapshot
            || self.namespace.snapshot()? != self.namespace_snapshot
        {
            return Err("private staged archive or namespace changed before publication".into());
        }
        Ok(())
    }
    fn refresh_namespace(&mut self) -> Result<(), Box<dyn Error>> {
        // One known completed directory publication changed the parent entry inventory.
        self.namespace_snapshot = self.namespace.snapshot()?;
        Ok(())
    }
}

fn copy_staged_archive(
    source: &mut RetainedImage,
    parent: &PrivateDirectory,
) -> Result<StagedArchive, Box<dyn Error>> {
    let (file, snapshot, hash) = source;
    if file.snapshot()? != *snapshot {
        return Err("original archive changed before staging".into());
    }
    let size = file.file().metadata()?.len();
    if size > MAX_BUNDLE_ARCHIVE_BYTES {
        return Err("archive exceeds packaging bound".into());
    }
    let pending_name = OsString::from(format!(
        ".mochi-archive-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let mut pending = parent
        .create_retained_private(&pending_name, usize::try_from(MAX_BUNDLE_ARCHIVE_BYTES)?)?;
    let namespace = ReaderDirectory::open(parent.path())?;
    let namespace_snapshot = namespace.snapshot()?;
    file.file_mut().seek(SeekFrom::Start(0))?;
    let copied = std::io::copy(
        &mut file
            .file_mut()
            .take(size.checked_add(1).ok_or("archive extent invalid")?),
        &mut pending,
    )?;
    if copied != size
        || file.snapshot()? != *snapshot
        || archive_digest_retained(file)? != *hash
        || file.snapshot()? != *snapshot
    {
        return Err("original archive changed while staging".into());
    }
    let file = pending.seal_read_only()?;
    let snapshot = file.snapshot()?;
    let mut staged = StagedArchive {
        file,
        snapshot,
        hash: hash.clone(),
        pending_name,
        namespace,
        namespace_snapshot,
    };
    staged.verify()?;
    Ok(staged)
}

fn sealed_archive_digest(file: &mut SealedPrivateFile) -> Result<String, Box<dyn Error>> {
    let snapshot = file.snapshot()?;
    file.seek(SeekFrom::Start(0))?;
    let (digest, _) = iroha_crypto::sha256_reader_bounded(&mut *file, MAX_BUNDLE_ARCHIVE_BYTES)?;
    if file.snapshot()? != snapshot {
        return Err("sealed staged archive changed while hashing".into());
    }
    Ok(hex::encode(digest))
}

// Stream the existing bounded artifact hash owner; never allocate an entire release archive.
fn archive_digest_retained(file: &mut RetainedFile) -> Result<String, Box<dyn Error>> {
    let snapshot = file.snapshot()?;
    file.file_mut().seek(SeekFrom::Start(0))?;
    let (digest, _) =
        iroha_crypto::sha256_reader_bounded(file.file_mut(), MAX_BUNDLE_ARCHIVE_BYTES)?;
    if file.snapshot()? != snapshot {
        return Err("Mochi archive changed while hashing".into());
    }
    Ok(hex::encode(digest))
}

fn build_runtime(profile: &str) -> Result<BTreeMap<String, PathBuf>, Box<dyn Error>> {
    validate_bundle_profile(profile)?;
    let mut child = Command::new("cargo")
        .args(runtime_build_args(profile))
        .current_dir(workspace_root())
        .stdout(Stdio::piped())
        .spawn()?;
    let stream = child
        .stdout
        .take()
        .ok_or("Cargo artifact stream is absent")?;
    let programs = collect_native_programs(BufReader::new(stream), &RUNTIME_BINARIES);
    let status = child.wait()?;
    if !status.success() {
        return Err("building the complete Mochi/Kagami/iroha3d runtime failed".into());
    }
    programs
}
fn runtime_build_args(profile: &str) -> Vec<OsString> {
    let mut args = vec![OsString::from("build")];
    if profile == "release" {
        args.push(OsString::from("--release"));
    } else if profile != "debug" {
        args.extend([OsString::from("--profile"), OsString::from(profile)]);
    }
    args.extend([
        OsString::from("--locked"),
        OsString::from("--message-format=json-render-diagnostics"),
        OsString::from("-p"),
        OsString::from("mochi-ui"),
        OsString::from("-p"),
        OsString::from("iroha_kagami"),
        OsString::from("-p"),
        OsString::from("irohad"),
        OsString::from("--features"),
        OsString::from("mochi-ui/gui"),
        OsString::from("--bin"),
        OsString::from(MOCHI_BIN_NAME),
        OsString::from("--bin"),
        OsString::from("kagami"),
        OsString::from("--bin"),
        OsString::from("iroha3d"),
    ]);
    args
}
fn mochi_ui_manifest_path() -> PathBuf {
    workspace_root().join(MOCHI_UI_MANIFEST_REL)
}
fn copy_runtime_binaries(
    programs: &BTreeMap<String, PathBuf>,
    bundle_root: &Path,
) -> Result<BundleCustody, Box<dyn Error>> {
    if programs.len() != RUNTIME_BINARIES.len() {
        return Err("Mochi runtime requires all three exact Cargo executables".into());
    }
    // Cargo owns each executable path, including configured target directories and native
    // host-triple subdirectories. Never guess a location or adopt an older neighboring build.
    let mut inputs = RUNTIME_BINARIES
        .iter()
        .map(|name| {
            let path = programs
                .get(*name)
                .ok_or("matching Cargo executable is absent")?;
            if !path.is_absolute() {
                return Err("Cargo executable path is not absolute".into());
            }
            let mut file = RetainedBuildInput::open(path)?;
            let snapshot = file.snapshot()?;
            admit_native_build_input(&mut file)?;
            let hash = digest(&mut file)?;
            if file.snapshot()? != snapshot {
                return Err("Mochi artifact changed during native admission".into());
            }
            Ok((*name, file, snapshot, hash))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    fs::create_dir_all(NativeBundleLayout::current().runtime_directory(bundle_root))?;
    let mut outputs = Vec::new();
    for (name, source, snapshot, hash) in &mut inputs {
        outputs.push((
            NativeBundleLayout::current().executable(Path::new(""), name),
            copy_program(
                source,
                *snapshot,
                hash,
                &NativeBundleLayout::current().executable(bundle_root, name),
            )?,
        ));
    }
    let custody_inputs = inputs
        .into_iter()
        .map(|(_, file, snapshot, hash)| (file, snapshot, hash))
        .collect();
    let mut custody_outputs = Vec::new();
    let mut created_outputs = Vec::new();
    for (relative, (file, snapshot, hash, created)) in outputs {
        custody_outputs.push((relative, (file, snapshot, hash)));
        created_outputs.push((created, snapshot));
    }
    let mut custody = BundleCustody {
        inputs: Vec::new(),
        build_inputs: custody_inputs,
        outputs: custody_outputs,
        created: created_outputs,
    };
    custody.verify()?;
    Ok(custody)
}
fn copy_into_bundle(
    source_rel: &str,
    destination: &Path,
) -> Result<(RetainedImage, RetainedImage), Box<dyn Error>> {
    let (bytes, input) = read_bundle_source(&workspace_root().join(source_rel))?;
    let output = write_bundle_file(destination, &bytes)?;
    Ok((input, output))
}

fn generate_manifest_json(bundle_root: &Path, profile: &str) -> Result<Value, Box<dyn Error>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(bundle_root).follow_root_links(false) {
        let entry = entry?;
        if entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            return Err("bundle inventory requires only direct files and directories".into());
        }
        let path = entry.path();
        if path == bundle_root.join("manifest.json") {
            continue;
        }
        let relative = path.strip_prefix(bundle_root)?;
        let relative = relative
            .to_str()
            .ok_or("Mochi inventory path is not Unicode")?
            .replace('\\', "/");
        let mut file = RetainedFile::open_regular(path)?;
        let snapshot = file.snapshot()?;
        let hash = digest(&mut file)?;
        if file.snapshot()? != snapshot {
            return Err("Mochi inventory file changed while hashing".into());
        }
        files.push((relative, file.file().metadata()?.len(), hash));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let files: Vec<Value> = files
        .into_iter()
        .map(|(path, size, sha256)| {
            let mut entry = norito::json::Map::new();
            entry.insert("path".into(), Value::from(path));
            entry.insert("size".into(), Value::from(size));
            entry.insert("sha256".into(), Value::from(sha256));
            Value::Object(entry)
        })
        .collect();
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let generated_unix_ms = u64::try_from(timestamp_ms).unwrap_or(u64::MAX);
    let mut manifest = norito::json::Map::new();
    manifest.insert("generated_unix_ms".into(), Value::from(generated_unix_ms));
    manifest.insert(
        "target".into(),
        Value::from(format!("{}-{}", env::consts::OS, env::consts::ARCH)),
    );
    manifest.insert("profile".into(), Value::from(profile));
    manifest.insert("files".into(), Value::Array(files));
    Ok(Value::Object(manifest))
}
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
fn create_archive(
    output_root: &Path,
    bundle_name: &str,
    bundle_root: &Path,
) -> Result<(PathBuf, RetainedImage), Box<dyn Error>> {
    let archive_path = output_root.join(format!("{bundle_name}.tar.gz"));
    refuse_existing(&archive_path)?;
    if bundle_root != output_root.join(bundle_name) {
        return Err("bundle root must be the requested direct child of the output root".into());
    }
    let parent = OwnerDirectory::open(output_root)?;
    // Tar writes only the exclusively created inherited descriptor. It cannot truncate an
    // existing archive or race a pathname substitution. Failed output remains private for
    // diagnosis; neither a partial archive nor an already complete bundle is reported success.
    let file = RetainedFile::create_new_private(&archive_path)?;
    // Capture the output namespace after this expected new entry. Tar creates no more names;
    // moving the original output root away and back must not authenticate a different tree.
    let namespace = ReaderDirectory::open(parent.path())?;
    let namespace_snapshot = namespace.snapshot()?;
    let status = Command::new("tar")
        .arg("-czf")
        .arg("-")
        .arg("-C")
        .arg(output_root)
        .arg(bundle_name)
        .stdout(Stdio::from(file.file().try_clone()?))
        .status()?;
    if !status.success() {
        return Err(format!("tar archive creation exited with status {status:?}").into());
    }
    file.file().sync_all()?;
    let mut retained = file.seal()?;
    let snapshot = retained.snapshot()?;
    let hash = archive_digest_retained(&mut retained)?;
    if retained.snapshot()? != snapshot {
        return Err("Mochi archive changed during completion".into());
    }
    let identity = retained.identity()?;
    let size = retained.file().metadata()?.len();
    parent.sync()?;
    // Sealing freezes metadata but keeps the writer's native access. Close it before opening
    // a reader, so Windows readers and smoke archive inspection can share the completed file.
    drop(retained);
    let retained = retain_created_output(&archive_path, identity, size, hash, false)?;
    if namespace.snapshot()? != namespace_snapshot {
        return Err("Mochi archive output namespace changed during creation".into());
    }
    Ok((archive_path, retained))
}
#[cfg(test)]
mod tests {
    use super::{
        MOCHI_BIN_NAME, MOCHI_HELP_HEADER, MOCHI_UI_MANIFEST_REL, RUNTIME_BINARIES,
        copy_runtime_binaries, create_archive, generate_manifest_json, mochi_ui_manifest_path,
        runtime_build_args, sha256_hex, stage_application_metadata, validate_mochi_help_output,
    };
    use iroha_deploy::{
        bootstrap::InstalledNetworkProfiles,
        managed::{NativeBundleLayout, macos_info_plist},
    };
    use std::{
        collections::BTreeMap,
        env,
        ffi::OsString,
        fs,
        io::Cursor,
        path::{Path, PathBuf},
        process::Command,
    };
    use tempfile::tempdir;

    fn native_sources(directory: &Path) -> BTreeMap<String, PathBuf> {
        fs::create_dir_all(directory).unwrap();
        RUNTIME_BINARIES
            .into_iter()
            .map(|name| {
                // Format fixtures exercise native-host admission without starting a process.
                let mut header = [0_u8; 128];
                match (env::consts::OS, env::consts::ARCH) {
                    ("macos", arch) => {
                        header[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
                        let cpu: u32 = if arch == "aarch64" {
                            0x0100_000c
                        } else {
                            0x0100_0007
                        };
                        header[4..8].copy_from_slice(&cpu.to_le_bytes());
                        header[12..16].copy_from_slice(&2_u32.to_le_bytes());
                    }
                    ("linux", arch) => {
                        header[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
                        header[16..18].copy_from_slice(&2_u16.to_le_bytes());
                        let cpu: u16 = if arch == "aarch64" { 183 } else { 62 };
                        header[18..20].copy_from_slice(&cpu.to_le_bytes());
                        header[24..32].copy_from_slice(&4096_u64.to_le_bytes());
                    }
                    ("windows", arch) => {
                        header[..2].copy_from_slice(b"MZ");
                        header[60..64].copy_from_slice(&64_u32.to_le_bytes());
                        header[64..68].copy_from_slice(b"PE\0\0");
                        let cpu: u16 = if arch == "aarch64" { 0xaa64 } else { 0x8664 };
                        header[68..70].copy_from_slice(&cpu.to_le_bytes());
                        header[86..88].copy_from_slice(&2_u16.to_le_bytes());
                        header[88..90].copy_from_slice(&0x20b_u16.to_le_bytes());
                    }
                    _ => panic!("unsupported native test host"),
                }
                let path = directory.join(format!("{name}{}", env::consts::EXE_SUFFIX));
                let mut bytes = header.to_vec();
                bytes.extend_from_slice(name.as_bytes());
                fs::write(&path, bytes).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                }
                (name.into(), path)
            })
            .collect()
    }

    // A complete admitted component package. Native format fixtures never execute; optional
    // archive bytes test retained copy/publication custody, not tar or runtime qualification.
    pub(super) fn bundle_fixture(
        root: &Path,
        archive: bool,
        profiles: Option<super::network_profiles::Selection>,
    ) -> super::MochiBundleResult {
        let root = fs::canonicalize(root).unwrap();
        let programs = native_sources(&root.join("source"));
        let publication = super::publish_bundle(
            &programs,
            &root.join("bundle"),
            "debug",
            profiles.as_ref(),
            &mut |_| Ok(()),
        )
        .unwrap();
        let archive = archive.then(|| {
            let bytes = b"original archive bytes";
            let parent = super::OwnerDirectory::open(&root).unwrap();
            parent
                .write_atomic("bundle.tar.gz", bytes, super::PublishMode::CreateNew)
                .unwrap();
            let path = root.join("bundle.tar.gz");
            let retained = super::retain_output(&path, sha256_hex(bytes)).unwrap();
            (path, retained)
        });
        let result = super::completed_bundle(publication, archive, profiles).unwrap();
        drop(super::retained_bundle(&result).unwrap());
        result
    }

    fn cargo_records(programs: &BTreeMap<String, PathBuf>) -> Vec<u8> {
        let mut records = Vec::new();
        for (name, path) in programs {
            records.extend(
                norito::json::to_vec(&norito::json!({
                    "reason": "compiler-artifact",
                    "target": {"name": name, "kind": ["bin"]},
                    "executable": (path.to_str().unwrap()),
                }))
                .unwrap(),
            );
            records.push(b'\n');
        }
        records
    }

    #[test]
    fn current_cargo_artifact_paths_override_stale_default_target_guesses() {
        let root = tempdir().unwrap();
        let stale = root.path().join("target/release");
        fs::create_dir_all(&stale).unwrap();
        for name in RUNTIME_BINARIES {
            fs::write(
                stale.join(format!("{name}{}", env::consts::EXE_SUFFIX)),
                b"stale build",
            )
            .unwrap();
        }
        let current = native_sources(
            &root
                .path()
                .join("configured cargo target/native-host-triple/release"),
        );
        let programs =
            super::collect_native_programs(Cursor::new(cargo_records(&current)), &RUNTIME_BINARIES)
                .unwrap();
        assert_eq!(programs, current);
        let bundle = root.path().join("bundle");
        copy_runtime_binaries(&programs, &bundle).unwrap();
        for name in RUNTIME_BINARIES {
            assert_eq!(
                fs::read(NativeBundleLayout::current().executable(&bundle, name)).unwrap(),
                fs::read(current.get(name).unwrap()).unwrap(),
            );
            assert_eq!(
                fs::read(stale.join(format!("{name}{}", env::consts::EXE_SUFFIX))).unwrap(),
                b"stale build"
            );
        }
    }

    #[test]
    fn clean_native_target_layout_needs_no_guessed_release_directory() {
        let root = tempdir().unwrap();
        let current = native_sources(&root.path().join("custom target/native-host-triple/debug"));
        assert!(!root.path().join("target/debug").exists());
        let programs =
            super::collect_native_programs(Cursor::new(cargo_records(&current)), &RUNTIME_BINARIES)
                .unwrap();
        let bundle = root.path().join("bundle");
        copy_runtime_binaries(&programs, &bundle).unwrap();
        for name in RUNTIME_BINARIES {
            assert_eq!(
                fs::read(NativeBundleLayout::current().executable(&bundle, name)).unwrap(),
                fs::read(current.get(name).unwrap()).unwrap(),
            );
        }
        assert!(!root.path().join("target/debug").exists());
    }

    #[test]
    fn cargo_linked_mochi_runtime_keeps_build_custody_and_single_link_private_outputs() {
        let root = tempdir().unwrap();
        let current = native_sources(&root.path().join("cargo target/native/debug"));
        for path in current.values() {
            fs::hard_link(path, path.with_extension("cargo-dependency-link")).unwrap();
            assert!(iroha_fs::RetainedFile::open_regular(path).is_err());
        }
        let programs =
            super::collect_native_programs(Cursor::new(cargo_records(&current)), &RUNTIME_BINARIES)
                .unwrap();
        let bundle = root.path().join("bundle");
        let mut custody = copy_runtime_binaries(&programs, &bundle).unwrap();
        assert_eq!(custody.build_inputs.len(), RUNTIME_BINARIES.len());
        assert!(custody.inputs.is_empty());
        custody.verify().unwrap();
        for name in RUNTIME_BINARIES {
            let output = NativeBundleLayout::current().executable(&bundle, name);
            assert_eq!(
                fs::read(&output).unwrap(),
                fs::read(&current[name]).unwrap()
            );
            iroha_fs::RetainedFile::open_regular(&output)
                .unwrap()
                .revalidate()
                .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(fs::metadata(&output).unwrap().nlink(), 1);
                assert_eq!(fs::metadata(&current[name]).unwrap().nlink(), 2);
            }
            assert!(
                current[name]
                    .with_extension("cargo-dependency-link")
                    .is_file()
            );
        }
        #[cfg(unix)]
        {
            fs::write(
                current["kagami"].with_extension("cargo-dependency-link"),
                b"changed after copy",
            )
            .unwrap();
            assert!(custody.verify().is_err());
        }
        #[cfg(windows)]
        {
            assert!(
                fs::OpenOptions::new()
                    .write(true)
                    .open(current["kagami"].with_extension("cargo-dependency-link"))
                    .is_err()
            );
            custody.verify().unwrap();
        }
    }

    #[test]
    fn desktop_artifact_set_requires_mochi_and_rejects_duplicate_records() {
        let root = tempdir().unwrap();
        let current = native_sources(&root.path().join("reported"));
        let mut missing = current.clone();
        missing.remove("mochi");
        missing.insert("iroha".into(), root.path().join("other-native-client"));
        assert!(
            super::collect_native_programs(Cursor::new(cargo_records(&missing)), &RUNTIME_BINARIES)
                .is_err()
        );
        let mut duplicate = cargo_records(&current);
        duplicate.extend(cargo_records(&BTreeMap::from([(
            "mochi".into(),
            current["mochi"].clone(),
        )])));
        assert!(super::collect_native_programs(Cursor::new(duplicate), &RUNTIME_BINARIES).is_err());
    }

    #[test]
    fn desktop_runtime_rejects_non_native_artifact_before_output_creation() {
        let root = tempdir().unwrap();
        let current = native_sources(&root.path().join("reported"));
        fs::write(&current["mochi"], b"not a native desktop executable").unwrap();
        let bundle = root.path().join("bundle");
        assert!(copy_runtime_binaries(&current, &bundle).is_err());
        assert!(!bundle.exists());
    }

    #[test]
    fn complete_mochi_bundle_publishes_once_and_retains_verified_final_outputs() {
        let root = tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        let programs = native_sources(&root_path.join("source"));
        let bundle = root_path.join("complete-mochi");
        let mut publication =
            super::publish_bundle(&programs, &bundle, "debug", None, &mut |_| Ok(())).unwrap();
        publication.verify().unwrap();
        publication.verify().unwrap();
        for name in RUNTIME_BINARIES {
            assert_eq!(
                fs::read(NativeBundleLayout::current().executable(&bundle, name)).unwrap(),
                fs::read(&programs[name]).unwrap()
            );
        }
        let manifest: norito::json::Value =
            norito::json::from_slice(&fs::read(bundle.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["files"],
            super::generate_manifest_json(&bundle, "debug").unwrap()["files"]
        );
        assert!(
            !manifest["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|file| file["path"].as_str() == Some("manifest.json"))
        );
        let manifest_bytes = fs::read(bundle.join("manifest.json")).unwrap();
        assert!(
            super::publish_bundle(&programs, &bundle, "debug", None, &mut |_| panic!(
                "occupied bundle must refuse before staging"
            ))
            .is_err()
        );
        assert_eq!(
            fs::read(bundle.join("manifest.json")).unwrap(),
            manifest_bytes
        );
    }

    #[test]
    fn existing_mochi_bundle_or_archive_refuses_before_profile_selection_or_cargo() {
        for existing_archive in [false, true] {
            let root = tempdir().unwrap();
            let root_path = fs::canonicalize(root.path()).unwrap();
            let name = format!("mochi-{}-{}-debug", env::consts::OS, env::consts::ARCH);
            let occupied = if existing_archive {
                let archive = root_path.join(format!("{name}.tar.gz"));
                fs::write(&archive, b"prior archive candidate").unwrap();
                archive
            } else {
                let programs = native_sources(&root_path.join("source"));
                let bundle = root_path.join(&name);
                let publication =
                    super::publish_bundle(&programs, &bundle, "debug", None, &mut |_| Ok(()))
                        .unwrap();
                publication.directory.revalidate().unwrap();
                drop(publication);
                bundle.join("manifest.json")
            };
            let bytes = fs::read(&occupied).unwrap();
            let count = fs::read_dir(&root_path).unwrap().count();
            let error = super::bundle_mochi(
                &root_path,
                "debug",
                true,
                Some(&root_path.join("deliberately-missing-profile-input")),
            )
            .unwrap_err();
            assert!(error.to_string().contains("bundle output already exists"));
            assert_eq!(fs::read(&occupied).unwrap(), bytes);
            assert_eq!(fs::read_dir(&root_path).unwrap().count(), count);
        }
    }

    #[test]
    fn foreign_native_candidate_never_publishes_or_erases_a_previous_mochi_bundle() {
        let root = tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        let programs = native_sources(&root_path.join("source"));
        let previous = root_path.join("prior-candidate");
        drop(super::publish_bundle(&programs, &previous, "debug", None, &mut |_| Ok(())).unwrap());
        let prior_manifest = fs::read(previous.join("manifest.json")).unwrap();
        let prior_programs: Vec<_> = RUNTIME_BINARIES
            .iter()
            .map(|name| {
                fs::read(NativeBundleLayout::current().executable(&previous, name)).unwrap()
            })
            .collect();
        let mut foreign = fs::read(&programs["mochi"]).unwrap();
        match (env::consts::OS, env::consts::ARCH) {
            ("macos", arch) => foreign[4..8].copy_from_slice(
                &(if arch == "aarch64" {
                    0x0100_0007_u32
                } else {
                    0x0100_000c_u32
                })
                .to_le_bytes(),
            ),
            ("linux", arch) => foreign[18..20]
                .copy_from_slice(&(if arch == "aarch64" { 62_u16 } else { 183_u16 }).to_le_bytes()),
            ("windows", arch) => foreign[68..70].copy_from_slice(
                &(if arch == "aarch64" {
                    0x8664_u16
                } else {
                    0xaa64_u16
                })
                .to_le_bytes(),
            ),
            _ => panic!("unsupported native test host"),
        }
        fs::write(&programs["mochi"], foreign).unwrap();
        let candidate = root_path.join("foreign-candidate");
        assert!(
            super::publish_bundle(&programs, &candidate, "debug", None, &mut |_| panic!(
                "foreign source must refuse before final publication"
            ))
            .is_err()
        );
        assert!(!candidate.exists());
        assert_eq!(
            fs::read(previous.join("manifest.json")).unwrap(),
            prior_manifest
        );
        for (name, bytes) in RUNTIME_BINARIES.iter().zip(prior_programs) {
            assert_eq!(
                fs::read(NativeBundleLayout::current().executable(&previous, name)).unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn destination_collision_preserves_the_other_candidate_at_atomic_mochi_publication() {
        let root = tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        let programs = native_sources(&root_path.join("source"));
        let candidate = root_path.join("occupied-at-publication");
        assert!(
            super::publish_bundle(&programs, &candidate, "debug", None, &mut |_| {
                fs::create_dir(&candidate)?;
                fs::write(
                    candidate.join("previous-candidate"),
                    b"keep exactly this candidate",
                )?;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(
            fs::read(candidate.join("previous-candidate")).unwrap(),
            b"keep exactly this candidate"
        );
        assert_eq!(fs::read_dir(&candidate).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn changed_staged_mochi_program_refuses_final_publication() {
        let root = tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        let programs = native_sources(&root_path.join("source"));
        let candidate = root_path.join("changed-output");
        assert!(
            super::publish_bundle(&programs, &candidate, "debug", None, &mut |staging| {
                fs::write(
                    NativeBundleLayout::current().executable(staging, "mochi"),
                    b"changed after copy",
                )?;
                Ok(())
            })
            .is_err()
        );
        assert!(!candidate.exists());
    }

    #[cfg(unix)]
    #[test]
    fn published_mochi_custody_refuses_equal_byte_replacement_before_result() {
        let root = tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        let programs = native_sources(&root_path.join("source"));
        let candidate = root_path.join("complete-output");
        let mut publication =
            super::publish_bundle(&programs, &candidate, "debug", None, &mut |_| Ok(())).unwrap();
        let output =
            NativeBundleLayout::current().executable(publication.directory.path(), "mochi");
        let bytes = fs::read(&output).unwrap();
        fs::rename(&output, root_path.join("retained-original-output")).unwrap();
        fs::write(&output, bytes).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(publication.verify().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn restored_bundle_or_runtime_directory_refuses_archive_custody_even_with_original_files() {
        for whole_bundle in [true, false] {
            let root = tempdir().unwrap();
            let root_path = fs::canonicalize(root.path()).unwrap();
            let programs = native_sources(&root_path.join("source"));
            let candidate = root_path.join("complete-output");
            let mut publication =
                super::publish_bundle(&programs, &candidate, "debug", None, &mut |_| Ok(()))
                    .unwrap();
            let output =
                NativeBundleLayout::current().executable(publication.directory.path(), "mochi");
            let original = iroha_fs::RetainedFile::open_regular(&output).unwrap();
            let identity = original.identity().unwrap();
            let bytes = fs::read(&output).unwrap();
            let moved = if whole_bundle {
                publication.directory.path().to_path_buf()
            } else {
                NativeBundleLayout::current().runtime_directory(publication.directory.path())
            };
            let away = root_path.join("temporarily-moved-directory");
            fs::rename(&moved, &away).unwrap();
            fs::rename(&away, &moved).unwrap();
            assert_eq!(
                iroha_fs::RetainedFile::open_regular(&output)
                    .unwrap()
                    .identity()
                    .unwrap(),
                identity
            );
            assert_eq!(fs::read(&output).unwrap(), bytes);
            assert!(
                publication.verify().is_err(),
                "a restored directory namespace cannot establish an unchanged archive source"
            );
        }
    }

    #[test]
    fn archive_creation_refuses_existing_name_without_running_tar_or_truncating_bytes() {
        let root = tempdir().unwrap();
        let archive = root.path().join("occupied.tar.gz");
        fs::write(&archive, b"complete previous archive").unwrap();
        assert!(
            create_archive(root.path(), "occupied", &root.path().join("absent-bundle")).is_err()
        );
        assert_eq!(fs::read(&archive).unwrap(), b"complete previous archive");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn local_release_is_rejected_before_build_profile_input_or_output_mutation() {
        let root = tempdir().unwrap();
        let existing = root.path().join("kept");
        fs::write(&existing, b"existing bundle").unwrap();
        let error = super::bundle_mochi(
            root.path(),
            "local-release",
            false,
            Some(&root.path().join("missing-network-profiles.nrt")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("local-release"));
        assert_eq!(fs::read(&existing).unwrap(), b"existing bundle");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        assert!(super::build_runtime("local-release").is_err());
        assert!(super::validate_bundle_profile("release").is_ok());
        assert!(super::validate_bundle_profile("debug").is_ok());
    }
    #[test]
    fn mochi_ui_manifest_path_declares_packaged_binary() {
        let manifest_path = mochi_ui_manifest_path();
        assert!(
            manifest_path.ends_with(MOCHI_UI_MANIFEST_REL),
            "unexpected MOCHI UI manifest path: {}",
            manifest_path.display()
        );
        let manifest = fs::read_to_string(&manifest_path)
            .unwrap_or_else(|_| panic!("missing manifest {}", manifest_path.display()));
        assert!(
            manifest.contains("[[bin]]")
                && manifest.contains(&format!("name = \"{MOCHI_BIN_NAME}\"")),
            "MOCHI UI manifest must declare the packaged `{MOCHI_BIN_NAME}` binary"
        );
    }
    #[test]
    fn mochi_ui_build_args_enable_gui_for_the_packaged_binary() {
        let args = runtime_build_args("debug");
        let expected_tail = [
            OsString::from("--features"),
            OsString::from("mochi-ui/gui"),
            OsString::from("--bin"),
            OsString::from(MOCHI_BIN_NAME),
            OsString::from("--bin"),
            OsString::from("kagami"),
            OsString::from("--bin"),
            OsString::from("iroha3d"),
        ];
        assert_eq!(args.first(), Some(&OsString::from("build")));
        assert_eq!(
            args.get(args.len() - expected_tail.len()..),
            Some(expected_tail.as_slice())
        );
    }
    #[test]
    fn mochi_ui_build_args_preserve_named_profiles() {
        let args = runtime_build_args("profiling");
        assert_eq!(
            args.get(0..3),
            Some(
                [
                    OsString::from("build"),
                    OsString::from("--profile"),
                    OsString::from("profiling"),
                ]
                .as_slice()
            )
        );
    }
    #[test]
    fn mochi_ui_build_args_preserve_release_profile() {
        let args = runtime_build_args("release");
        assert_eq!(
            args.get(0..2),
            Some([OsString::from("build"), OsString::from("--release")].as_slice())
        );
    }
    #[test]
    fn runtime_build_is_locked_and_includes_every_runtime_package() {
        let args = runtime_build_args("debug");
        assert!(args.contains(&OsString::from("--locked")));
        assert_eq!(
            args.iter()
                .filter(|arg| *arg == "--message-format=json-render-diagnostics")
                .count(),
            1
        );
        for binary in RUNTIME_BINARIES {
            assert!(
                args.windows(2)
                    .any(|pair| pair == [OsString::from("--bin"), OsString::from(binary)])
            );
        }
        for package in ["mochi-ui", "iroha_kagami", "irohad"] {
            assert!(
                args.windows(2)
                    .any(|pair| pair == [OsString::from("-p"), OsString::from(package)])
            );
        }
    }
    #[test]
    fn runtime_bundle_contains_daemon_without_path_dependency() {
        let root = tempdir().expect("temporary root");
        let source = root.path().join("source");
        let bundle = root.path().join("bundle");
        let programs = native_sources(&source);
        copy_runtime_binaries(&programs, &bundle).expect("complete runtime");
        for name in RUNTIME_BINARIES {
            assert_eq!(
                fs::read(NativeBundleLayout::current().executable(&bundle, name)).unwrap(),
                fs::read(programs.get(name).unwrap()).unwrap()
            );
        }
        if NativeBundleLayout::current() == NativeBundleLayout::MacOs {
            assert!(!bundle.join("bin").exists());
        }
    }

    #[test]
    fn app_metadata_uses_the_desktop_package_version_and_enters_the_inventory() {
        let root = tempdir().unwrap();
        drop(stage_application_metadata(root.path()).unwrap());
        let manifest = generate_manifest_json(root.path(), "release").unwrap();
        let files = manifest["files"].as_array().unwrap();
        if NativeBundleLayout::current() == NativeBundleLayout::MacOs {
            let source: toml::Value =
                toml::from_str(&fs::read_to_string(mochi_ui_manifest_path()).unwrap()).unwrap();
            let version = source["package"]["version"].as_str().unwrap();
            let expected = macos_info_plist(version).unwrap();
            assert_eq!(
                fs::read_to_string(root.path().join("Mochi.app/Contents/Info.plist")).unwrap(),
                expected
            );
            assert_eq!(files.len(), 1);
            assert_eq!(
                files[0]["path"].as_str(),
                Some("Mochi.app/Contents/Info.plist")
            );
            assert_eq!(
                files[0]["sha256"].as_str(),
                Some(sha256_hex(expected.as_bytes()).as_str())
            );
            assert!(
                NativeBundleLayout::MacOs
                    .resources_directory(root.path())
                    .is_dir()
            );
            assert!(!root.path().join("bin").exists());
        } else {
            assert!(files.is_empty());
        }
    }

    #[test]
    fn staging_and_inventory_propagate_missing_tree_errors() {
        let root = tempdir().unwrap();
        assert!(generate_manifest_json(&root.path().join("missing"), "release").is_err());
        let mut result = bundle_fixture(root.path(), false, None);
        result.bundle_root = root.path().join("missing");
        let destination = root.path().join("destination");
        assert!(super::stage_bundle(&result, &destination).is_err());
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn staging_and_inventory_reject_indirect_files_and_directories() {
        use std::os::unix::fs::symlink;
        for directory in [false, true] {
            let root = tempdir().unwrap();
            let result = bundle_fixture(root.path(), false, None);
            let outside = result.output_root.join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("data"), b"not bundle custody").unwrap();
            symlink(
                if directory {
                    outside
                } else {
                    outside.join("data")
                },
                result.bundle_root.join("indirect"),
            )
            .unwrap();
            assert!(generate_manifest_json(&result.bundle_root, "debug").is_err());
            let destination = result.output_root.join("destination");
            assert!(super::stage_bundle(&result, &destination).is_err());
            assert!(!destination.exists());
        }
    }

    #[test]
    fn staged_bundle_has_complete_sorted_identical_file_inventory_after_relocation() {
        let root = tempdir().unwrap();
        let profiles = super::network_profiles::development(
            &InstalledNetworkProfiles::new(Vec::new()).unwrap(),
        )
        .unwrap();
        let result = bundle_fixture(root.path(), true, Some(profiles));
        let before = generate_manifest_json(&result.bundle_root, "debug").unwrap();
        let destination = result.output_root.join("relocated");
        super::stage_bundle(&result, &destination).unwrap();
        let moved = destination.join(&result.bundle_name);
        let after = generate_manifest_json(&moved, "debug").unwrap();
        assert_eq!(before["files"], after["files"]);
        assert_eq!(
            fs::read(result.manifest_path.clone()).unwrap(),
            fs::read(moved.join("manifest.json")).unwrap()
        );
        let names = after["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["path"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(names.len(), if cfg!(target_os = "macos") { 7 } else { 6 });
        let runtime = iroha_deploy::managed::InstalledRuntime::from_directory(
            &NativeBundleLayout::current().runtime_directory(&moved),
        )
        .unwrap();
        assert!(runtime.network_profiles().is_ok());
        assert_eq!(
            fs::read(destination.join("bundle.tar.gz")).unwrap(),
            fs::read(result.archive_path.as_ref().unwrap()).unwrap()
        );
        let count = fs::read_dir(&destination).unwrap().count();
        assert!(super::stage_bundle(&result, &destination).is_err());
        assert_eq!(fs::read_dir(&destination).unwrap().count(), count);
        drop(super::retained_bundle(&result).unwrap());
    }

    #[test]
    fn distribution_refuses_any_occupied_bundle_or_archive_before_copying() {
        for occupied_archive in [false, true] {
            let root = tempdir().unwrap();
            let mut result = bundle_fixture(root.path(), true, None);
            let destination = result.output_root.join("destination");
            let parent = super::PrivateDirectory::open_or_create(&destination).unwrap();
            let name = if occupied_archive {
                "bundle.tar.gz"
            } else {
                "bundle"
            };
            parent
                .write_atomic(
                    name,
                    b"previous output bytes",
                    super::PublishMode::CreateNew,
                )
                .unwrap();
            let count = fs::read_dir(&destination).unwrap().count();
            // Occupied outputs refuse before even admitting this deliberately wrong report.
            result.profile = "release".into();
            let error = super::stage_bundle(&result, &destination).unwrap_err();
            assert!(error.to_string().contains("bundle output already exists"));
            assert_eq!(
                fs::read(destination.join(name)).unwrap(),
                b"previous output bytes"
            );
            assert_eq!(fs::read_dir(&destination).unwrap().count(), count);
        }
    }

    #[test]
    fn matrix_refuses_package_destination_before_changing_any_original_output() {
        let root = tempdir().unwrap();
        let result = bundle_fixture(root.path(), false, None);
        let original = fs::read(&result.manifest_path).unwrap();
        for path in [
            result.manifest_path.clone(),
            result.bundle_root.join("new-matrix.json"),
        ] {
            let error = super::update_bundle_matrix(&result, &path, true).unwrap_err();
            assert!(error.to_string().contains("matrix output must be outside"));
            assert_eq!(fs::read(&result.manifest_path).unwrap(), original);
            assert!(!result.bundle_root.join("new-matrix.json").exists());
            drop(super::retained_bundle(&result).unwrap());
        }
    }

    #[test]
    fn distribution_refuses_stage_root_inside_original_bundle_without_mutation() {
        let root = tempdir().unwrap();
        let result = bundle_fixture(root.path(), false, None);
        let nested = result.bundle_root.join("new-stage");
        assert!(super::stage_bundle(&result, &nested).is_err());
        assert!(!nested.exists());
        drop(super::retained_bundle(&result).unwrap());
    }

    #[test]
    fn distribution_directory_collision_preserves_the_foreign_destination() {
        let root = tempdir().unwrap();
        let result = bundle_fixture(root.path(), true, None);
        let destination = result.output_root.join("destination");
        let occupied = destination.join(&result.bundle_name);
        assert!(
            super::stage_bundle_checked(
                &result,
                &destination,
                &mut |_| {
                    fs::create_dir(&occupied)?;
                    fs::write(occupied.join("kept"), b"competing bundle")?;
                    Ok(())
                },
                &mut |_| panic!("collision cannot publish a directory"),
            )
            .is_err()
        );
        assert_eq!(
            fs::read(occupied.join("kept")).unwrap(),
            b"competing bundle"
        );
        assert_eq!(fs::read_dir(&occupied).unwrap().count(), 1);
        assert!(!destination.join("bundle.tar.gz").exists());
        drop(super::retained_bundle(&result).unwrap());
    }

    #[test]
    fn archive_collision_after_directory_publication_keeps_both_complete_outputs_and_errors() {
        let root = tempdir().unwrap();
        let result = bundle_fixture(root.path(), true, None);
        let destination = result.output_root.join("destination");
        let occupied = destination.join("bundle.tar.gz");
        let error =
            super::stage_bundle_checked(&result, &destination, &mut |_| Ok(()), &mut |_| {
                fs::write(&occupied, b"competing complete archive")?;
                Ok(())
            })
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("bundle directory was published at")
        );
        assert!(
            error
                .to_string()
                .contains("retain names for reconciliation")
        );
        assert_eq!(fs::read(&occupied).unwrap(), b"competing complete archive");
        let published = destination.join(&result.bundle_name);
        assert_eq!(
            generate_manifest_json(&published, "debug").unwrap()["files"],
            generate_manifest_json(&result.bundle_root, "debug").unwrap()["files"]
        );
        assert!(fs::read_dir(&destination).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".mochi-archive-")
        }));
        assert!(super::stage_bundle(&result, &destination).is_err());
        drop(super::retained_bundle(&result).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn distribution_refuses_missing_mutated_or_replaced_original_runtime_before_copying() {
        for mutation in ["missing", "changed", "replaced", "source", "manifest"] {
            let root = tempdir().unwrap();
            let result = bundle_fixture(root.path(), true, None);
            let output = NativeBundleLayout::current().executable(&result.bundle_root, "iroha3d");
            match mutation {
                "missing" => fs::remove_file(&output).unwrap(),
                "changed" => fs::write(&output, b"changed runtime").unwrap(),
                "replaced" => {
                    let bytes = fs::read(&output).unwrap();
                    fs::rename(&output, result.output_root.join("original-program")).unwrap();
                    fs::write(&output, bytes).unwrap();
                }
                "source" => fs::write(
                    result
                        .output_root
                        .join("source")
                        .join(format!("iroha3d{}", env::consts::EXE_SUFFIX)),
                    b"changed Cargo source",
                )
                .unwrap(),
                "manifest" => fs::write(&result.manifest_path, b"{}").unwrap(),
                _ => unreachable!(),
            }
            let destination = result.output_root.join("destination");
            assert!(super::stage_bundle(&result, &destination).is_err());
            assert!(!destination.exists());
            let matrix = result.output_root.join("matrix.json");
            assert!(super::update_bundle_matrix(&result, &matrix, true).is_err());
            assert!(!matrix.exists());
            assert!(super::run_bundle_smoke(&result).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn distribution_and_matrix_refuse_indirect_occupied_output_before_mutation() {
        use std::os::unix::fs::symlink;
        for name in ["bundle", "bundle.tar.gz"] {
            let root = tempdir().unwrap();
            let result = bundle_fixture(root.path(), true, None);
            let destination = result.output_root.join("destination");
            let parent = super::PrivateDirectory::open_or_create(&destination).unwrap();
            symlink(
                parent.path().join("absent-target"),
                parent.path().join(name),
            )
            .unwrap();
            assert!(super::stage_bundle(&result, &destination).is_err());
            assert!(
                fs::symlink_metadata(destination.join(name))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
            let alias = result.output_root.join("bundle-alias");
            symlink(&result.bundle_root, &alias).unwrap();
            assert!(
                super::update_bundle_matrix(&result, &alias.join("new-matrix.json"), true).is_err()
            );
            assert!(!result.bundle_root.join("new-matrix.json").exists());
            drop(super::retained_bundle(&result).unwrap());
        }
    }

    #[cfg(unix)]
    #[test]
    fn distribution_private_root_and_indirect_alias_refuse_without_hardening_or_copying() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let root = tempdir().unwrap();
        let result = bundle_fixture(root.path(), false, None);
        let public = result.output_root.join("public-stage");
        fs::create_dir(&public).unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(public.join("kept"), b"keep public stage").unwrap();
        assert!(super::stage_bundle(&result, &public).is_err());
        assert_eq!(
            fs::metadata(&public).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(fs::read_dir(&public).unwrap().count(), 1);
        let alias = result.output_root.join("bundle-alias");
        symlink(&result.bundle_root, &alias).unwrap();
        assert!(super::stage_bundle(&result, &alias.join("new-stage")).is_err());
        assert!(!result.bundle_root.join("new-stage").exists());
        drop(super::retained_bundle(&result).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn distribution_refuses_postcopy_program_or_original_source_mutation_before_publication() {
        for change_original in [false, true] {
            let root = tempdir().unwrap();
            let result = bundle_fixture(root.path(), true, None);
            let destination = result.output_root.join("destination");
            assert!(
                super::stage_bundle_checked(
                    &result,
                    &destination,
                    &mut |staging| {
                        let path = NativeBundleLayout::current().executable(
                            if change_original {
                                &result.bundle_root
                            } else {
                                staging
                            },
                            "mochi",
                        );
                        fs::write(path, b"changed after copy")?;
                        Ok(())
                    },
                    &mut |_| panic!("changed source/output cannot publish"),
                )
                .is_err()
            );
            assert!(!destination.join("bundle").exists());
            assert!(!destination.join("bundle.tar.gz").exists());
            if !change_original {
                drop(super::retained_bundle(&result).unwrap());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn distribution_refuses_restored_published_namespace_before_reporting_pair_success() {
        let root = tempdir().unwrap();
        let result = bundle_fixture(root.path(), true, None);
        let destination = result.output_root.join("destination");
        assert!(
            super::stage_bundle_checked(&result, &destination, &mut |_| Ok(()), &mut |published| {
                let away = destination.join("temporarily-moved");
                fs::rename(published, &away)?;
                fs::rename(&away, published)?;
                Ok(())
            },)
            .is_err()
        );
        assert!(destination.join("bundle").is_dir());
        assert!(super::stage_bundle(&result, &destination).is_err());
        drop(super::retained_bundle(&result).unwrap());
    }
    #[test]
    fn incomplete_runtime_is_rejected_before_any_binary_is_copied() {
        let root = tempdir().expect("temporary root");
        let source = root.path().join("source");
        let bundle = root.path().join("bundle");
        let mut programs = native_sources(&source);
        programs.remove("iroha3d");
        assert!(copy_runtime_binaries(&programs, &bundle).is_err());
        assert!(!bundle.exists());
    }
    #[test]
    fn explicit_installed_profiles_are_canonical_and_covered_by_the_bundle_inventory() {
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_deploy::bootstrap::{InstalledNetworkProfile, InstalledNetworkProfiles};
        let root = tempdir().unwrap();
        let profiles = InstalledNetworkProfiles::new(vec![
            InstalledNetworkProfile::new(
                "fixture".into(),
                KeyPair::from_seed(vec![21; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
                7,
                "https://release.example/checkpoint.nrt".into(),
            )
            .unwrap(),
        ])
        .unwrap();
        let bytes = profiles.encode_installation().unwrap();
        let source = root.path().join("installer-selected.nrt");
        fs::write(&source, &bytes).unwrap();
        let loaded = super::load_network_profiles(Some(&source))
            .unwrap()
            .unwrap();
        let bundle = root.path().join("bundle");
        fs::create_dir_all(NativeBundleLayout::current().runtime_directory(&bundle)).unwrap();
        loaded
            .stage(&NativeBundleLayout::current().profiles_path(&bundle))
            .unwrap();
        assert_eq!(
            fs::read(NativeBundleLayout::current().profiles_path(&bundle)).unwrap(),
            bytes
        );
        let manifest = super::generate_manifest_json(&bundle, "test").unwrap();
        let entries = manifest.as_object().unwrap()["files"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = entries[0].as_object().unwrap();
        assert_eq!(
            entry["path"].as_str(),
            Some(
                NativeBundleLayout::current()
                    .profiles_path(Path::new(""))
                    .to_string_lossy()
                    .replace('\\', "/")
                    .as_str()
            )
        );
        assert_eq!(entry["size"].as_u64(), Some(bytes.len() as u64));
        assert_eq!(
            entry["sha256"].as_str(),
            Some(super::sha256_hex(&bytes).as_str())
        );
        assert!(loaded.require_cli_names(br#"["taira"]"#).is_err());
    }
    #[test]
    fn missing_profile_option_installs_no_authority_and_invalid_input_is_rejected() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("bin")).unwrap();
        assert!(super::load_network_profiles(None).unwrap().is_none());
        super::stage_network_profiles(None, root.path()).unwrap();
        assert!(
            !NativeBundleLayout::current()
                .profiles_path(root.path())
                .exists()
        );
        let source = root.path().join("invalid.nrt");
        fs::write(&source, b"response-selected untrusted authority").unwrap();
        assert!(super::load_network_profiles(Some(&source)).is_err());
        assert!(super::load_network_profiles(Some(&root.path().join("missing.nrt"))).is_err());
        assert!(
            !NativeBundleLayout::current()
                .profiles_path(root.path())
                .exists()
        );
    }
    #[test]
    fn mochi_help_validation_accepts_workspace_desktop_usage() {
        let stdout = format!("{MOCHI_HELP_HEADER}\n");
        assert_eq!(validate_mochi_help_output(&stdout), Ok(()));
    }
    #[test]
    fn mochi_help_validation_rejects_default_feature_stub() {
        let error = validate_mochi_help_output(
            "MOCHI GUI is not enabled in the default workspace build.\n",
        )
        .expect_err("default-feature stub must not pass bundle smoke");
        assert_eq!(error, format!("missing `{MOCHI_HELP_HEADER}`"));
    }
    #[test]
    fn mochi_help_validation_rejects_retired_sandbox_usage() {
        let error = validate_mochi_help_output("MOCHI usage:\nmochi sandbox serve [options]")
            .expect_err("retired supervisor CLI must not pass bundle smoke");
        assert_eq!(error, format!("missing `{MOCHI_HELP_HEADER}`"));
    }
    #[test]
    fn create_archive_packages_bundle_directory() {
        let tempdir = tempdir().expect("tempdir");
        let output_root = tempdir.path();
        let bundle_name = "mochi-test-bundle";
        let bundle_root = output_root.join(bundle_name);
        fs::create_dir_all(NativeBundleLayout::current().runtime_directory(&bundle_root))
            .expect("bundle dir");
        fs::write(
            NativeBundleLayout::current().executable(&bundle_root, "mochi"),
            b"binary",
        )
        .expect("bundle file");
        let (archive_path, _custody) =
            create_archive(output_root, bundle_name, &bundle_root).expect("archive builds");
        assert!(archive_path.exists(), "archive should exist");
        let listing = Command::new("tar")
            .arg("-tzf")
            .arg(&archive_path)
            .output()
            .expect("archive listing");
        assert!(
            listing.status.success(),
            "archive listing should succeed: {:?}",
            listing.status
        );
        let stdout = String::from_utf8(listing.stdout).expect("utf8 listing");
        assert!(
            stdout.lines().any(|line| line
                == format!(
                    "{bundle_name}/{}",
                    NativeBundleLayout::current()
                        .executable(Path::new(""), "mochi")
                        .to_string_lossy()
                        .replace('\\', "/")
                )),
            "archive listing did not include bundle payload: {stdout}"
        );
    }
}

#[cfg(test)]
mod shared_namespace_tests {
    //! Native shared namespace custody keeps the original object and refuses substitution.
    use super::*;

    #[test]
    fn original_shared_namespace_admits_once_and_refuses_indirect_relative_paths() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir_all(temporary.path().join("one/two")).unwrap();
        let root = ReaderDirectory::open(temporary.path()).unwrap();
        let snapshot = root.snapshot().unwrap();
        let mut namespaces = BTreeMap::from([(PathBuf::new(), (root, snapshot))]);
        let identity = retain_bundle_directory(&mut namespaces, Path::new("one/two"))
            .unwrap()
            .snapshot()
            .unwrap();
        assert_eq!(namespaces.len(), 3);
        assert_eq!(
            retain_bundle_directory(&mut namespaces, Path::new("one/two"))
                .unwrap()
                .snapshot()
                .unwrap(),
            identity
        );
        assert_eq!(namespaces.len(), 3);
        for indirect in ["../one", "one/../two", "/one", "."] {
            assert!(retain_bundle_directory(&mut namespaces, Path::new(indirect)).is_err());
            assert_eq!(namespaces.len(), 3);
        }
        assert!(retain_bundle_directory(&mut namespaces, Path::new("missing")).is_err());
        assert!(!temporary.path().join("missing").exists());
    }

    #[cfg(unix)]
    #[test]
    fn original_shared_namespace_refuses_equal_file_directory_substitution() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir(temporary.path().join("original")).unwrap();
        fs::write(temporary.path().join("original/source"), b"original").unwrap();
        let root = ReaderDirectory::open(temporary.path()).unwrap();
        let snapshot = root.snapshot().unwrap();
        let mut namespaces = BTreeMap::from([(PathBuf::new(), (root, snapshot))]);
        let file = retain_bundle_directory(&mut namespaces, Path::new("original"))
            .unwrap()
            .open_retained_regular("source")
            .unwrap();
        fs::rename(
            temporary.path().join("original"),
            temporary.path().join("saved"),
        )
        .unwrap();
        fs::create_dir(temporary.path().join("original")).unwrap();
        fs::write(temporary.path().join("original/source"), b"original").unwrap();
        assert!(retain_bundle_directory(&mut namespaces, Path::new("original")).is_err());
        assert!(file.revalidate().is_err());
        assert_eq!(
            fs::read(temporary.path().join("saved/source")).unwrap(),
            b"original"
        );
    }
}
