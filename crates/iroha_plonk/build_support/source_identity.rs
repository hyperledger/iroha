//! Conservative workspace input identity shared by Cargo and focused freshness tests.
//!
//! This is an identity of canonical native inputs and explicit special
//! membership, not external dependency/toolchain attestation. Native mathematical
//! sources/assets belong under crate `src`/`build_support` roots, which are walked
//! regardless of ignore rules, as is root `.cargo`. Cargo.lock pins the external
//! package selection. Target/backend support is a separate predicate.
//! Unrelated client owners and prose are omitted; native package trees and declared
//! external inputs take precedence. Compiler/generated-input containment remains
//! a separate build check, not a claim made by the conservative reference scan.
//! Generated registry DATA is excluded from the digest to avoid a self-hash.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

/// The sole generated registry DATA file; all surrounding admission logic is hashed.
pub const GENERATED: &str = "crates/iroha_plonk/src/keys/keygen/builtin/generated.rs";
const SWIFT_OUTPUT_LINK: &str = "IrohaSwift/NoritoBridge.xcframework";
const SWIFT_OUTPUT_TARGET: &str = "../dist/NoritoBridge.xcframework";
const OPTIONAL_DOCS: &str = "iroha-docs";
const CLIENT_ROOTS: &[&str] = &[
    "python/",
    "IrohaSwift/",
    "kotlin/",
    "javascript/",
    "examples/android/",
    "examples/ios/",
];

// These public inputs are consumed by native code/tests despite their owner or
// prose suffix. Keep fixture families whole, including future inventory members.
const EXTERNAL_INPUTS: &[&str] = &[
    "norito.md",
    "generatediso20022.md",
    "specs/kotodama_grammar.md",
    "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift",
];
const EXTERNAL_INPUT_ROOTS: &[&str] = &["javascript/iroha_js/test/fixtures/"];

fn package_roots(entries: &BTreeMap<String, Entry>) -> BTreeSet<String> {
    entries
        .keys()
        .filter_map(|name| name.strip_suffix("/Cargo.toml").map(str::to_owned))
        .collect()
}

fn selected(name: &str, packages: &BTreeSet<String>) -> bool {
    if name == SWIFT_OUTPUT_LINK
        || EXTERNAL_INPUTS.contains(&name)
        || EXTERNAL_INPUT_ROOTS
            .iter()
            .any(|prefix| name.starts_with(prefix))
        || packages.iter().any(|package| {
            name.strip_prefix(package)
                .is_some_and(|rest| rest.starts_with('/'))
        })
    {
        return true;
    }
    if name == OPTIONAL_DOCS || CLIENT_ROOTS.iter().any(|prefix| name.starts_with(prefix)) {
        return false;
    }
    // Only Markdown prose in documentation owners is omitted. Unknown formats,
    // scripts, configuration, fixtures, tests and assets remain inputs by default.
    // Suffix rules are byte-exact, including dotfiles; case folding or extension
    // parsing would change source membership.
    !(name.as_bytes().ends_with(b".md")
        && (!name.contains('/') || name.starts_with("docs/") || name.starts_with("specs/")))
}

/// A complete stable source observation, suitable for a generated compile-time constant.
#[derive(Debug)]
pub struct Snapshot {
    /// Domain-separated identity of sorted paths, kinds and complete contents.
    pub digest: [u8; 32],
    /// Individually observed inputs, including excluded generated DATA.
    /// Membership is always rescanned by the build script, not directory watches.
    pub watched_paths: BTreeSet<PathBuf>,
}

#[derive(Clone, PartialEq, Eq)]
enum Entry {
    File,
    Link,
    DocsGitlink(String),
}

fn source_tree(
    root: &Path,
    directory: &Path,
    entries: &mut BTreeMap<String, Entry>,
) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("unreadable native source root".to_owned()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("native source root is not a regular directory".to_owned());
    }
    let children = fs::read_dir(directory).map_err(|_| "unreadable native source directory")?;
    for child in children {
        let child = child.map_err(|_| "incomplete native source directory")?;
        let path = child.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| "missing native source input")?;
        if metadata.is_dir() {
            source_tree(root, &path, entries)?;
        } else {
            let name = path
                .strip_prefix(root)
                .map_err(|_| "native source escapes workspace")?
                .to_str()
                .ok_or("non-UTF8 native source path")?;
            let name = relative_name(name.as_bytes())?;
            let kind = if metadata.file_type().is_symlink() {
                Entry::Link
            } else if metadata.is_file() {
                Entry::File
            } else {
                return Err("unsupported native source input kind".to_owned());
            };
            if entries.get(&name).is_some_and(|old| old != &kind) {
                return Err("native source changed kind".to_owned());
            }
            entries.insert(name, kind);
        }
    }
    Ok(())
}

fn required_source_roots(root: &Path, entries: &mut BTreeMap<String, Entry>) -> Result<(), String> {
    source_tree(root, &root.join(".cargo"), entries)?;
    // Native owners can also live under vendor, nested accelerators or an SDK
    // directory. Ownership wins over the surrounding non-native directory.
    for package in package_roots(entries) {
        source_tree(root, &root.join(&package).join("src"), entries)?;
        source_tree(root, &root.join(&package).join("build_support"), entries)?;
    }
    let crates = root.join("crates");
    let metadata = match fs::symlink_metadata(&crates) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("unreadable crates directory".to_owned()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("crates directory is not a regular directory".to_owned());
    }
    for package in fs::read_dir(&crates).map_err(|_| "unreadable crates directory")? {
        let package = package.map_err(|_| "incomplete crates directory")?;
        let metadata =
            fs::symlink_metadata(package.path()).map_err(|_| "missing crate directory")?;
        if metadata.file_type().is_symlink() {
            return Err("crate directory traverses a symlink".to_owned());
        }
        if metadata.is_dir() {
            source_tree(root, &package.path().join("src"), entries)?;
            source_tree(root, &package.path().join("build_support"), entries)?;
        }
    }
    Ok(())
}

fn relative_reference(base: &Path, value: &str) -> Option<String> {
    let mut parts = PathBuf::new();
    for part in base.join(value).components() {
        match part {
            Component::Normal(value) => parts.push(value),
            Component::CurDir => (),
            Component::ParentDir => {
                if !parts.pop() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    relative_name(parts.to_str()?.as_bytes()).ok()
}

// Conservative restoration, not a Rust parser or a proof of compiler closure.
// Literal include/path references (including doc attributes and concat! fragments) may
// bring an otherwise unrelated owner back into the census. False positives are
// retained. Actual compiler/build-producer containment is checked separately.
fn restore_references(
    root: &Path,
    all: &BTreeMap<String, Entry>,
    packages: &BTreeSet<String>,
    entries: &mut BTreeMap<String, Entry>,
) -> Result<(), String> {
    // Keep the same byte-exact Rust suffix for initial and restored sources,
    // including a file named `.rs`.
    let mut pending: Vec<_> = entries
        .keys()
        .filter(|name| name.as_bytes().ends_with(b".rs"))
        .cloned()
        .collect();
    let mut visited = BTreeSet::new();
    while let Some(name) = pending.pop() {
        if !visited.insert(name.clone()) || entries.get(&name) != Some(&Entry::File) {
            continue;
        }
        let (path, _) = regular_file(root, &name)?;
        let source = fs::read_to_string(path).map_err(|_| "unreadable native source input")?;
        let parent = Path::new(&name)
            .parent()
            .ok_or("native source has no parent")?;
        let package = packages
            .iter()
            .filter(|package| name.starts_with(&format!("{package}/")))
            .max_by_key(|package| package.len());
        let mut references = Vec::new();
        for token in ["include", "include_str", "include_bytes"] {
            for (index, _) in source.match_indices(token) {
                let tail = source[index + token.len()..].trim_start();
                let Some(tail) = tail.strip_prefix('!').map(str::trim_start) else {
                    continue;
                };
                if tail.starts_with('(') {
                    references.push(&tail[..tail.find(';').unwrap_or(tail.len())]);
                }
            }
        }
        for (index, _) in source.match_indices("#[path") {
            let tail = &source[index..];
            references.push(&tail[..tail.find(']').unwrap_or(tail.len())]);
        }
        for value in references
            .iter()
            .flat_map(|source| source.split('"').skip(1).step_by(2))
        {
            if value.contains(['\n', '\r', '\\']) || value.len() > 4096 {
                continue;
            }
            let mut candidates = BTreeSet::new();
            for base in [parent, Path::new("")] {
                if let Some(candidate) = relative_reference(base, value) {
                    candidates.insert(candidate);
                }
            }
            if let Some(package) = package {
                // CARGO_MANIFEST_DIR + "/../../..." has a leading separator
                // in the literal fragment, but is relative to that package.
                if let Some(candidate) =
                    relative_reference(Path::new(package), value.trim_start_matches('/'))
                {
                    candidates.insert(candidate);
                }
            }
            for candidate in candidates {
                if entries.contains_key(&candidate) || selected(&candidate, packages) {
                    continue;
                }
                let entry = if let Some(entry) = all.get(&candidate) {
                    entry.clone()
                } else {
                    let metadata = match fs::symlink_metadata(root.join(&candidate)) {
                        Ok(metadata) => metadata,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => return Err("unreadable referenced native input".to_owned()),
                    };
                    if metadata.file_type().is_symlink() {
                        Entry::Link
                    } else if metadata.is_file() {
                        Entry::File
                    } else {
                        continue;
                    }
                };
                if candidate.as_bytes().ends_with(b".rs") {
                    pending.push(candidate.clone());
                }
                entries.insert(candidate, entry);
            }
        }
    }
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|_| "cannot read Git source inventory".to_owned())?;
    if !output.status.success() {
        return Err("cannot read Git source inventory".to_owned());
    }
    Ok(output.stdout)
}

fn relative_name(bytes: &[u8]) -> Result<String, String> {
    let name = std::str::from_utf8(bytes).map_err(|_| "non-UTF8 source path")?;
    if name.is_empty()
        || name.contains(['\n', '\r', '\\'])
        || Path::new(name)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("noncanonical source path".to_owned());
    }
    Ok(name.to_owned())
}

fn inventory(root: &Path) -> Result<BTreeMap<String, Entry>, String> {
    let mut entries = BTreeMap::new();
    for record in git(root, &["ls-files", "--stage", "--cached", "-z"])?
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or("invalid Git record")?;
        let header = std::str::from_utf8(&record[..tab]).map_err(|_| "invalid Git record")?;
        let fields: Vec<_> = header.split(' ').collect();
        if fields.len() != 3 || fields[2] != "0" {
            return Err("unmerged source inventory".to_owned());
        }
        let name = relative_name(&record[tab + 1..])?;
        let entry = match fields[0] {
            "100644" | "100755" => Entry::File,
            "120000" => Entry::Link,
            "160000" if name == OPTIONAL_DOCS => Entry::DocsGitlink(fields[1].to_owned()),
            _ => return Err("unsupported source inventory kind".to_owned()),
        };
        if entries.insert(name, entry).is_some() {
            return Err("duplicate source inventory path".to_owned());
        }
    }
    for record in git(root, &["ls-files", "--others", "--exclude-standard", "-z"])?
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let name = relative_name(record)?;
        let metadata =
            fs::symlink_metadata(root.join(&name)).map_err(|_| "missing source input")?;
        let entry = if metadata.file_type().is_symlink() {
            Entry::Link
        } else {
            Entry::File
        };
        if entries.insert(name, entry).is_some() {
            return Err("duplicate source inventory path".to_owned());
        }
    }
    required_source_roots(root, &mut entries)?;
    let packages = package_roots(&entries);
    let all = entries.clone();
    entries.retain(|name, _| selected(name, &packages));
    restore_references(root, &all, &packages, &mut entries)?;
    if entries.is_empty() {
        return Err("empty source inventory".to_owned());
    }
    Ok(entries)
}

fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn regular_file(root: &Path, name: &str) -> Result<(PathBuf, fs::Metadata), String> {
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|_| "missing source input")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("source input changed kind".to_owned());
    }
    let resolved = path
        .canonicalize()
        .map_err(|_| "cannot resolve source input")?;
    if resolved != path {
        return Err("source input traverses a symlink or escapes the workspace".to_owned());
    }
    Ok((path, metadata))
}

/// Compute the current complete input identity, failing closed on partial observations.
pub fn snapshot(root: &Path) -> Result<Snapshot, String> {
    let root = root.canonicalize().map_err(|_| "missing workspace root")?;
    let reported = git(&root, &["rev-parse", "--show-toplevel"])?;
    let reported = std::str::from_utf8(&reported)
        .map_err(|_| "non-UTF8 workspace root")?
        .trim_end();
    if Path::new(reported)
        .canonicalize()
        .map_err(|_| "missing Git root")?
        != root
    {
        return Err("source root is not the Git workspace root".to_owned());
    }
    let entries = inventory(&root)?;
    let mut hash = Sha256::new();
    hash.update(b"iroha:plonk:closed-native-workspace-inputs:v2\0");
    let mut watched_paths = BTreeSet::new();
    let mut observed = Vec::new();
    let mut observed_links = Vec::new();
    for (name, entry) in &entries {
        let path = root.join(name);
        if !matches!(entry, Entry::DocsGitlink(_)) {
            if matches!(entry, Entry::File) {
                watched_paths.insert(path.clone());
            }
            let parent = path.parent().ok_or("source input has no parent")?;
            if parent.canonicalize().map_err(|_| "missing source parent")? != parent {
                return Err("source parent traverses a symlink".to_owned());
            }
        }
        if name == GENERATED {
            if !matches!(entry, Entry::File) {
                return Err("generated registry must be regular DATA".to_owned());
            }
            regular_file(&root, name)?;
            continue;
        }
        frame(&mut hash, name.as_bytes());
        match entry {
            Entry::File => {
                let (path, metadata) = regular_file(&root, name)?;
                frame(&mut hash, b"file");
                hash.update(metadata.len().to_le_bytes());
                let mut file = fs::File::open(&path).map_err(|_| "unreadable source input")?;
                let mut buffer = [0; 16384];
                let mut read = 0_u64;
                loop {
                    let size = file
                        .read(&mut buffer)
                        .map_err(|_| "unreadable source input")?;
                    if size == 0 {
                        break;
                    }
                    read = read
                        .checked_add(size as u64)
                        .ok_or("source input length overflow")?;
                    hash.update(&buffer[..size]);
                }
                if read != metadata.len() {
                    return Err("source changed during identity computation".to_owned());
                }
                observed.push((
                    path,
                    metadata.len(),
                    metadata
                        .modified()
                        .map_err(|_| "missing source timestamp")?,
                ));
            }
            Entry::Link => {
                let target = fs::read_link(&path).map_err(|_| "source symlink changed kind")?;
                let target_name = target.to_str().ok_or("non-UTF8 source symlink")?;
                frame(&mut hash, b"symlink");
                frame(&mut hash, target_name.as_bytes());
                if name == SWIFT_OUTPUT_LINK {
                    // This exact shipped-output link is not a mathematical input.
                    // Following it would hash the newly linked native library into
                    // its own source identity. Bind its spelling, never its target.
                    if target_name != SWIFT_OUTPUT_TARGET {
                        return Err("changed generated Swift bridge symlink".to_owned());
                    }
                } else {
                    let resolved = path
                        .canonicalize()
                        .map_err(|_| "unresolved source symlink")?;
                    let relative = resolved
                        .strip_prefix(&root)
                        .map_err(|_| "source symlink escapes workspace")?;
                    let relative = relative.to_str().ok_or("non-UTF8 source symlink target")?;
                    if relative == GENERATED || entries.get(relative) != Some(&Entry::File) {
                        return Err(
                            "source symlink target is not an included regular input".to_owned()
                        );
                    }
                    regular_file(&root, relative)?;
                }
                observed_links.push((path, target));
            }
            Entry::DocsGitlink(object) => {
                frame(&mut hash, b"optional-docs-gitlink:160000");
                frame(&mut hash, object.as_bytes());
            }
        }
    }
    for (path, target) in observed_links {
        if fs::read_link(path).ok().as_ref() != Some(&target) {
            return Err("source symlink changed during identity computation".to_owned());
        }
    }
    for (path, len, modified) in observed {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "source disappeared during identity computation")?;
        if !metadata.is_file()
            || metadata.len() != len
            || metadata.modified().ok() != Some(modified)
        {
            return Err("source changed during identity computation".to_owned());
        }
    }
    if inventory(&root)? != entries {
        return Err("source membership changed during identity computation".to_owned());
    }
    watched_paths.insert(root.join(GENERATED));
    watched_paths.insert(root.join(".git/index"));
    watched_paths.insert(root.join(".git/info/exclude"));
    Ok(Snapshot {
        digest: hash.finalize().into(),
        watched_paths,
    })
}

/// Reviewed native target families; this predicate is not evidence of target execution.
pub fn supported_target(arch: &str, os: &str, width: &str, endian: &str) -> bool {
    endian == "little"
        && matches!(
            (arch, os, width),
            ("aarch64", "android" | "ios" | "macos" | "linux", "64")
                | (
                    "x86_64",
                    "android" | "ios" | "macos" | "linux" | "windows",
                    "64"
                )
                | ("arm", "android", "32")
        )
}
