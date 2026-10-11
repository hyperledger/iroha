//! Assemble the matching native client, developer worker and daemon without a desktop build dependency.

use crate::{network_profiles, workspace_root};
use iroha_deploy::managed::{
    InstalledRuntime, KagamiBundleLayout, admit_native_build_input, admit_native_program,
};
use iroha_fs::{
    FileIdentity, FileSnapshot, OwnerDirectory, PublishMode, RetainedBuildInput, RetainedFile,
};
use norito::json::{self, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    ffi::OsString,
    fs,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
use walkdir::WalkDir;

const PROGRAMS: [&str; 3] = ["iroha", "kagami", "iroha3d"];

pub(crate) fn validate_profile(profile: &str) -> Result<(), &'static str> {
    match profile {
        "debug" | "release" => Ok(()),
        _ => Err("kagami-bundle accepts only debug or release; local-release cannot be packaged"),
    }
}

fn build_args(profile: &str) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("build"),
        OsString::from("--locked"),
        OsString::from("--message-format=json-render-diagnostics"),
    ];
    if profile == "release" {
        args.push("--release".into());
    }
    for package in ["iroha_cli", "iroha_kagami", "irohad"] {
        args.extend([OsString::from("-p"), OsString::from(package)]);
    }
    for program in PROGRAMS {
        args.extend([OsString::from("--bin"), OsString::from(program)]);
    }
    args
}

/// Build the client, worker and daemon from this checkout in one locked native invocation, then publish once.
/// The inventory establishes local integrity, not authenticated release provenance.
pub(crate) fn bundle(
    output: &Path,
    profile: &str,
    profiles: Option<&Path>,
) -> Result<PathBuf, Box<dyn Error>> {
    bundle_at(&workspace_root(), output, profile, profiles)
}

fn bundle_at(
    source_root: &Path,
    output: &Path,
    profile: &str,
    profiles: Option<&Path>,
) -> Result<PathBuf, Box<dyn Error>> {
    validate_profile(profile)?;
    let package = output.join(format!(
        "kagami-{}-{}-{profile}",
        env::consts::OS,
        env::consts::ARCH,
    ));
    // An occupied name, including a broken link, cannot be an output candidate.
    // This preflight precedes profile admission and Cargo; publication still uses CreateNew.
    match fs::symlink_metadata(&package) {
        Ok(_) => {
            return Err("CLI package already exists; select a fresh --out directory".into());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let profiles = network_profiles::select(source_root, profile, profiles)?;
    // Reuse Cargo's active target and native jobserver; the daemon keeps its standard features.
    let mut child = Command::new("cargo")
        .args(build_args(profile))
        .current_dir(source_root)
        .stdout(Stdio::piped())
        .spawn()?;
    let stream = child
        .stdout
        .take()
        .ok_or("Cargo artifact stream is absent")?;
    let records = collect_programs(BufReader::new(stream));
    let status = child.wait()?;
    if !status.success() {
        return Err("building matching iroha, Kagami and iroha3d failed".into());
    }
    publish_cargo(&records?, &package, profile, profiles.as_ref())?;
    Ok(package)
}

fn collect_programs(stream: impl BufRead) -> Result<BTreeMap<String, PathBuf>, Box<dyn Error>> {
    collect_native_programs(stream, &PROGRAMS)
}

/// Read one bounded Cargo stream for the exact program set requested by a native packager.
/// Rejected Cargo records are drained before the caller reaps the original build process.
pub(crate) fn collect_native_programs(
    mut stream: impl BufRead,
    expected: &[&str],
) -> Result<BTreeMap<String, PathBuf>, Box<dyn Error>> {
    let mut programs = BTreeMap::new();
    let mut failure = None;
    loop {
        let mut line = Vec::new();
        let count = stream
            .by_ref()
            .take(1024 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if count == 0 {
            break;
        }
        let record = (|| {
            if line.len() > 1024 * 1024 {
                return Err("Cargo message exceeds fixed byte bound".into());
            }
            let limits = norito::DecodeLimits::new(8192, 1024 * 1024, 8192, 4 * 1024 * 1024, 128);
            json::preflight_slice(
                &line,
                json::JsonPreflightLimits::from_decode_limits(1024 * 1024, limits),
            )?;
            let value: Value =
                norito::with_decode_limits_scope(limits, || json::from_slice(&line))?;
            if value.get("reason").and_then(Value::as_str) != Some("compiler-artifact") {
                return Ok(());
            }
            let target = value.get("target").ok_or("Cargo artifact has no target")?;
            let Some(name) = target
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| expected.contains(name))
            else {
                return Ok(());
            };
            let kind = target
                .get("kind")
                .and_then(Value::as_array)
                .ok_or("Cargo native artifact has no target kind")?;
            // The SDK library is also named `iroha`. It is a dependency artifact,
            // never a substitute for the separately requested native client.
            if kind.len() == 1
                && kind[0].as_str() == Some("lib")
                && value.get("executable") == Some(&Value::Null)
            {
                return Ok(());
            }
            if kind.len() != 1 || kind[0].as_str() != Some("bin") {
                return Err("CLI artifact is not the requested native binary target".into());
            }
            let path = PathBuf::from(
                value
                    .get("executable")
                    .and_then(Value::as_str)
                    .ok_or("Cargo CLI artifact has no executable")?,
            );
            if !path.is_absolute() || programs.insert(name.into(), path).is_some() {
                return Err(
                    "Cargo CLI artifact is duplicated or lacks an absolute executable path".into(),
                );
            }
            Ok::<(), Box<dyn Error>>(())
        })();
        if let Err(error) = record {
            failure.get_or_insert(error);
        }
        if failure.is_some() {
            // Drain the original pipe so Cargo can finish and be reaped even after rejection.
            io::copy(&mut stream, &mut io::sink())?;
            break;
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    if programs.len() != expected.len() {
        return Err("Cargo did not report all three exact native executables".into());
    }
    Ok(programs)
}

/// A bounded stream adapter, without transferring the native original descriptor.
pub(crate) trait InputReader: Read + Seek {}
impl<T: Read + Seek + ?Sized> InputReader for T {}

/// The two explicit source roles share streaming; only their native owners grant custody.
pub(crate) trait NativeInput {
    fn reader(&mut self) -> &mut dyn InputReader;
    fn length(&self) -> io::Result<u64>;
    fn snapshot(&self) -> io::Result<FileSnapshot>;
    fn revalidate(&self) -> io::Result<()>;
}

impl NativeInput for RetainedFile {
    fn reader(&mut self) -> &mut dyn InputReader {
        self.file_mut()
    }
    fn length(&self) -> io::Result<u64> {
        Ok(self.file().metadata()?.len())
    }
    fn snapshot(&self) -> io::Result<FileSnapshot> {
        RetainedFile::snapshot(self)
    }
    fn revalidate(&self) -> io::Result<()> {
        RetainedFile::revalidate(self)
    }
}

impl NativeInput for RetainedBuildInput {
    fn reader(&mut self) -> &mut dyn InputReader {
        self
    }
    fn length(&self) -> io::Result<u64> {
        self.len()
    }
    fn snapshot(&self) -> io::Result<FileSnapshot> {
        RetainedBuildInput::snapshot(self)
    }
    fn revalidate(&self) -> io::Result<()> {
        RetainedBuildInput::revalidate(self)
    }
}

#[derive(Clone, Copy)]
enum ProgramKind {
    #[cfg(test)]
    Strict,
    Cargo,
}

enum ProgramInput {
    #[cfg(test)]
    Strict(RetainedFile),
    Cargo(RetainedBuildInput),
}

impl ProgramInput {
    fn capture(path: &Path, kind: ProgramKind) -> io::Result<Self> {
        match kind {
            #[cfg(test)]
            ProgramKind::Strict => RetainedFile::open_regular(path).map(Self::Strict),
            ProgramKind::Cargo => RetainedBuildInput::open(path).map(Self::Cargo),
        }
    }
    fn admit(&mut self) -> io::Result<()> {
        match self {
            #[cfg(test)]
            Self::Strict(file) => admit_native_program(file),
            Self::Cargo(file) => admit_native_build_input(file),
        }
    }
}

impl NativeInput for ProgramInput {
    fn reader(&mut self) -> &mut dyn InputReader {
        match self {
            #[cfg(test)]
            Self::Strict(file) => file.reader(),
            Self::Cargo(file) => file.reader(),
        }
    }
    fn length(&self) -> io::Result<u64> {
        match self {
            #[cfg(test)]
            Self::Strict(file) => file.length(),
            Self::Cargo(file) => file.length(),
        }
    }
    fn snapshot(&self) -> io::Result<FileSnapshot> {
        match self {
            #[cfg(test)]
            Self::Strict(file) => file.snapshot(),
            Self::Cargo(file) => file.snapshot(),
        }
    }
    fn revalidate(&self) -> io::Result<()> {
        match self {
            #[cfg(test)]
            Self::Strict(file) => file.revalidate(),
            Self::Cargo(file) => file.revalidate(),
        }
    }
}

pub(crate) fn digest(file: &mut impl NativeInput) -> Result<String, Box<dyn Error>> {
    file.revalidate()?;
    let length = file.length()?;
    file.revalidate()?;
    let limit = length
        .checked_add(1)
        .ok_or("CLI artifact extent is invalid")?;
    file.reader().seek(SeekFrom::Start(0))?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut hash = Sha256::new();
    let mut read = 0_u64;
    {
        let mut original = file.reader().take(limit);
        loop {
            let count = original.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            read += count as u64;
            hash.update(&buffer[..count]);
        }
    }
    if read != length {
        return Err("CLI artifact extent changed during hashing".into());
    }
    file.revalidate()?;
    Ok(hex::encode(hash.finalize()))
}

pub(crate) fn retain_output(
    path: &Path,
    expected_hash: String,
) -> Result<(RetainedFile, FileSnapshot, String), Box<dyn Error>> {
    let mut file = RetainedFile::open_regular(path)?;
    let snapshot = file.snapshot()?;
    if digest(&mut file)? != expected_hash || file.snapshot()? != snapshot {
        return Err("CLI package output changed during admission".into());
    }
    Ok((file, snapshot, expected_hash))
}

pub(crate) fn retain_published_output(
    path: &Path,
    snapshot: FileSnapshot,
    expected_hash: String,
    program: bool,
) -> Result<(RetainedFile, FileSnapshot, String), Box<dyn Error>> {
    admit_published_output(
        RetainedFile::open_regular(path)?,
        snapshot,
        expected_hash,
        program,
    )
}

pub(crate) fn admit_published_output(
    mut file: RetainedFile,
    snapshot: FileSnapshot,
    expected_hash: String,
    program: bool,
) -> Result<(RetainedFile, FileSnapshot, String), Box<dyn Error>> {
    if file.snapshot()? != snapshot {
        return Err("published package output differs from its exact staged object".into());
    }
    if program {
        admit_native_program(&mut file)?;
    }
    if digest(&mut file)? != expected_hash || file.snapshot()? != snapshot {
        return Err("published package output changed during final admission".into());
    }
    Ok((file, snapshot, expected_hash))
}

pub(crate) fn retain_created_output(
    path: &Path,
    identity: FileIdentity,
    size: u64,
    expected_hash: String,
    program: bool,
) -> Result<(RetainedFile, FileSnapshot, String), Box<dyn Error>> {
    let (mut file, snapshot, hash) = retain_output(path, expected_hash)?;
    // Windows finalizes write timestamps on last writer close. Join the closed writer to its
    // first read-only guard by native identity, extent and exact hash, then retain this stable
    // post-close full snapshot for every later publication fence.
    if file.identity()? != identity || file.file().metadata()?.len() != size {
        return Err("created package output differs from its original writer".into());
    }
    if program {
        admit_native_program(&mut file)?;
    }
    if file.snapshot()? != snapshot {
        return Err("created package output changed during final admission".into());
    }
    Ok((file, snapshot, hash))
}

pub(crate) fn copy_program(
    source: &mut impl NativeInput,
    source_snapshot: FileSnapshot,
    expected_hash: &str,
    destination: &Path,
) -> Result<(RetainedFile, FileSnapshot, String, Option<fs::File>), Box<dyn Error>> {
    let expected_size = source.length()?;
    if source.snapshot()? != source_snapshot {
        return Err("CLI artifact changed before copying".into());
    }
    let mut copied = RetainedFile::create_new_private(destination)?;
    source.reader().seek(SeekFrom::Start(0))?;
    let limit = expected_size
        .checked_add(1)
        .ok_or("CLI artifact extent is invalid")?;
    let size = io::copy(&mut source.reader().take(limit), copied.file_mut())?;
    if size != expected_size {
        return Err("CLI artifact extent changed during copying".into());
    }
    copied.file().sync_all()?;
    copied.revalidate()?;
    // Join the finalized executable to its exclusively created object. Unix may keep this
    // raw descriptor through directory publication; Windows must close its WRITE/DELETE
    // handles before independent readers or a directory rename can succeed.
    let created = copied.file().try_clone()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        created.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    created.sync_all()?;
    let created_identity = FileIdentity::of(&created)?;
    #[cfg(unix)]
    let created_snapshot = FileSnapshot::of(&created, false)?;
    drop(copied);
    #[cfg(windows)]
    drop(created);
    let (copied, copied_snapshot, copied_hash) = retain_created_output(
        destination,
        created_identity,
        expected_size,
        expected_hash.into(),
        true,
    )?;
    #[cfg(unix)]
    if copied_snapshot != created_snapshot {
        return Err("created CLI program changed during permission finalization".into());
    }
    if source.snapshot()? != source_snapshot
        || digest(source)? != expected_hash
        || source.snapshot()? != source_snapshot
    {
        return Err("matching CLI input changed during package publication".into());
    }
    #[cfg(unix)]
    let created = Some(created);
    #[cfg(windows)]
    let created = None;
    Ok((copied, copied_snapshot, copied_hash, created))
}

// Only the successful exact Cargo artifact set enters the build-input role. The strict
// publisher is test-only, preserving the original strict custody regressions.
fn publish_cargo(
    source: &BTreeMap<String, PathBuf>,
    package: &Path,
    profile: &str,
    profiles: Option<&network_profiles::Selection>,
) -> Result<(), Box<dyn Error>> {
    if source.len() != PROGRAMS.len()
        || PROGRAMS
            .iter()
            .any(|name| source.get(*name).is_none_or(|path| !path.is_absolute()))
    {
        return Err("CLI package requires the exact absolute Cargo executable set".into());
    }
    publish_inputs(
        source,
        package,
        profile,
        profiles,
        ProgramKind::Cargo,
        &mut || Ok(()),
        &mut |_| Ok(()),
    )
}

#[cfg(test)]
fn publish(
    source: &BTreeMap<String, PathBuf>,
    package: &Path,
    profile: &str,
    profiles: Option<&network_profiles::Selection>,
) -> Result<(), Box<dyn Error>> {
    publish_checked(
        source,
        package,
        profile,
        profiles,
        &mut || Ok(()),
        &mut |_| Ok(()),
    )
}

#[cfg(test)]
fn publish_checked(
    source: &BTreeMap<String, PathBuf>,
    package: &Path,
    profile: &str,
    profiles: Option<&network_profiles::Selection>,
    before_publication: &mut dyn FnMut() -> Result<(), Box<dyn Error>>,
    after_publication: &mut dyn FnMut(&Path) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    publish_inputs(
        source,
        package,
        profile,
        profiles,
        ProgramKind::Strict,
        before_publication,
        after_publication,
    )
}

fn publish_inputs(
    source: &BTreeMap<String, PathBuf>,
    package: &Path,
    profile: &str,
    profiles: Option<&network_profiles::Selection>,
    kind: ProgramKind,
    before_publication: &mut dyn FnMut() -> Result<(), Box<dyn Error>>,
    after_publication: &mut dyn FnMut(&Path) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    validate_profile(profile)?;
    network_profiles::require_for_profile(profile, profiles)?;
    let mut programs = PROGRAMS
        .into_iter()
        .map(|name| {
            let filename = format!("{name}{}", env::consts::EXE_SUFFIX);
            let mut file = ProgramInput::capture(
                source.get(name).ok_or("missing exact Cargo executable")?,
                kind,
            )?;
            let snapshot = file.snapshot()?;
            file.admit()?;
            let hash = digest(&mut file)?;
            if file.snapshot()? != snapshot {
                return Err("CLI artifact changed during admission".into());
            }
            Ok((filename, file, snapshot, hash))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let profile_bytes = profiles.map(network_profiles::Selection::bytes);
    let parent =
        OwnerDirectory::open_or_create(package.parent().ok_or("CLI package has no parent")?)?;
    let staging = parent.create_private_child(format!(
        ".kagami-stage-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ))?;
    let runtime = staging.create_child("bin")?;
    let mut retained_outputs = Vec::new();
    let mut created_outputs = Vec::new();
    for (filename, file, snapshot, hash) in &mut programs {
        let (copied, copied_snapshot, copied_hash, created) = copy_program(
            file,
            *snapshot,
            hash,
            &runtime.path().join(filename.as_str()),
        )?;
        retained_outputs.push((
            PathBuf::from("bin").join(filename.as_str()),
            copied,
            copied_snapshot,
            copied_hash,
            true,
        ));
        created_outputs.push((created, copied_snapshot));
    }
    if let Some(bytes) = profile_bytes {
        runtime.write_atomic(
            iroha_deploy::bootstrap::NETWORK_PROFILES_FILENAME,
            bytes,
            PublishMode::CreateNew,
        )?;
        let (file, snapshot, hash) = retain_output(
            &runtime
                .path()
                .join(iroha_deploy::bootstrap::NETWORK_PROFILES_FILENAME),
            hex::encode(Sha256::digest(bytes)),
        )?;
        retained_outputs.push((
            PathBuf::from("bin").join(iroha_deploy::bootstrap::NETWORK_PROFILES_FILENAME),
            file,
            snapshot,
            hash,
            false,
        ));
    }
    if let Some(profiles) = profiles {
        profiles.verify_installed(&KagamiBundleLayout::profiles_path(staging.path()))?;
    }
    InstalledRuntime::from_directory(runtime.path())?;
    let manifest = inventory(staging.path(), profile, profiles)?;
    let manifest_bytes = json::to_vec(&manifest)?;
    staging.write_atomic("manifest.json", &manifest_bytes, PublishMode::CreateNew)?;
    let (file, snapshot, hash) = retain_output(
        &staging.path().join("manifest.json"),
        hex::encode(Sha256::digest(&manifest_bytes)),
    )?;
    retained_outputs.push((PathBuf::from("manifest.json"), file, snapshot, hash, false));
    runtime.sync()?;
    drop(runtime);
    staging.sync()?;
    before_publication()?;
    for (_, file, snapshot, hash) in &mut programs {
        if file.snapshot()? != *snapshot || digest(file)? != *hash || file.snapshot()? != *snapshot
        {
            return Err("CLI artifact changed before atomic publication".into());
        }
    }
    for (_, file, snapshot, hash, _) in &mut retained_outputs {
        if file.snapshot()? != *snapshot || digest(file)? != *hash || file.snapshot()? != *snapshot
        {
            return Err("CLI package output changed before atomic publication".into());
        }
    }
    for (created, snapshot) in &created_outputs {
        if let Some(created) = created {
            if FileSnapshot::of(created, false)? != *snapshot {
                return Err("created CLI program changed before atomic publication".into());
            }
        }
    }
    if let Some(profiles) = profiles {
        profiles.verify_installed(&KagamiBundleLayout::profiles_path(staging.path()))?;
    }
    if inventory(staging.path(), profile, profiles)? != manifest {
        return Err("CLI package contents changed before atomic publication".into());
    }
    // Close path-sensitive descendant readers before the native directory rename. Windows
    // requires all output descriptors closed; Unix retains the created raw program anchors.
    // Original Cargo source authority stays live throughout, and the final reads must match
    // exact saved native snapshots as well as hashes, never merely equal replacement bytes.
    let output_snapshots: Vec<_> = retained_outputs
        .into_iter()
        .map(|(relative, file, snapshot, hash, program)| {
            drop(file);
            (relative, snapshot, hash, program)
        })
        .collect();
    let published = staging.rename_to_sibling(
        package.file_name().ok_or("CLI package has no name")?,
        PublishMode::CreateNew,
    )?;
    after_publication(published.path())?;
    let mut retained_outputs = output_snapshots
        .into_iter()
        .map(|(relative, snapshot, hash, program)| {
            retain_published_output(&published.path().join(relative), snapshot, hash, program)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (_, file, snapshot, hash) in &mut programs {
        if file.snapshot()? != *snapshot || digest(file)? != *hash || file.snapshot()? != *snapshot
        {
            return Err("CLI original artifact changed during atomic publication".into());
        }
    }
    for (created, snapshot) in &created_outputs {
        if let Some(created) = created {
            if FileSnapshot::of(created, false)? != *snapshot {
                return Err("created CLI program changed after atomic publication".into());
            }
        }
    }
    if let Some(profiles) = profiles {
        profiles.verify_installed(&KagamiBundleLayout::profiles_path(published.path()))?;
    }
    if inventory(published.path(), profile, profiles)? != manifest {
        return Err("CLI final inventory differs from the complete staged package".into());
    }
    for (file, snapshot, hash) in &mut retained_outputs {
        if file.snapshot()? != *snapshot || digest(file)? != *hash || file.snapshot()? != *snapshot
        {
            return Err("CLI output changed before returning the complete package".into());
        }
    }
    for (_, file, snapshot, hash) in &mut programs {
        if file.snapshot()? != *snapshot || digest(file)? != *hash || file.snapshot()? != *snapshot
        {
            return Err(
                "CLI original artifact changed before returning the complete package".into(),
            );
        }
    }
    published.revalidate()?;
    Ok(())
}

fn inventory(
    package: &Path,
    profile: &str,
    profiles: Option<&network_profiles::Selection>,
) -> Result<Value, Box<dyn Error>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(package).follow_root_links(false) {
        let entry = entry?;
        if entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            return Err("CLI inventory rejects indirect or nonregular entries".into());
        }
        // This manifest inventories the installed content, not its own encoding.
        // Its exact bytes are retained separately through the publication gate.
        if entry.path() == package.join("manifest.json") {
            continue;
        }
        let relative = entry.path().strip_prefix(package)?;
        let path = relative
            .to_str()
            .ok_or("CLI package path is not Unicode")?
            .replace('\\', "/");
        let mut file = RetainedFile::open_regular(entry.path())?;
        files.push((path, entry.metadata()?.len(), digest(&mut file)?));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let files = files
        .into_iter()
        .map(|(path, size, hash)| {
            Value::Object(Map::from([
                ("path".into(), Value::String(path)),
                ("size".into(), Value::from(size)),
                ("sha256".into(), Value::String(hash)),
            ]))
        })
        .collect();
    Ok(Value::Object(Map::from([
        (
            "schema".into(),
            Value::String("iroha.kagami-bundle.v1".into()),
        ),
        ("profile".into(), Value::String(profile.into())),
        (
            "network_profiles".into(),
            profiles.map_or(Value::Null, network_profiles::Selection::provenance),
        ),
        (
            "target".into(),
            Value::String(format!("{}-{}", env::consts::OS, env::consts::ARCH)),
        ),
        ("files".into(), Value::Array(files)),
    ])))
}

#[cfg(test)]
mod tests;
