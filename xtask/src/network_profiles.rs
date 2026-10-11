//! Release-owned public preset selection and exact installed-image checks.
//!
//! The authenticated release source supplies authority; a profile label or HTTP response does not.

use iroha_deploy::bootstrap::{InstalledNetworkProfiles, MAX_INSTALLED_PROFILE_BYTES};
use norito::json::{self, Value};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

pub(crate) const RELEASE_PROFILES: &str = "defaults/developer/network-profiles.nrt";

#[derive(Debug, Clone)]
pub(crate) struct Selection {
    bytes: Vec<u8>,
    names: Vec<String>,
    source: Source,
}

#[derive(Debug, Clone)]
enum Source {
    Development,
    Release { commit: String },
}

/// Require the opaque release selection before publication or later verification.
pub(crate) fn require_for_profile(
    profile: &str,
    selected: Option<&Selection>,
) -> Result<(), Box<dyn Error>> {
    if profile == "release"
        && !matches!(
            selected.map(|selection| &selection.source),
            Some(Source::Release { .. })
        )
    {
        return Err("release bundle has no retained release-owned Taira profile selection".into());
    }
    Ok(())
}

pub(crate) fn validate_input(profile: &str, supplied: Option<&Path>) -> Result<(), &'static str> {
    if profile == "release" && supplied.is_some() {
        return Err(
            "release bundles use the committed release-owned network profiles; --network-profiles is development-only",
        );
    }
    Ok(())
}

pub(crate) fn select(
    root: &Path,
    profile: &str,
    supplied: Option<&Path>,
) -> Result<Option<Selection>, Box<dyn Error>> {
    validate_input(profile, supplied)?;
    if profile != "release" {
        return supplied
            .map(|path| development(&InstalledNetworkProfiles::load(path)?))
            .transpose();
    }
    // Missing release custody refuses before build, output creation or bundle replacement.
    let bytes = InstalledNetworkProfiles::load(&root.join(RELEASE_PROFILES))
        .and_then(|profiles| profiles.encode_installation())
        .map_err(|_| "approved release-owned network profiles are missing or unsafe")?;
    let head = git_line(root, &["rev-parse", "HEAD"])?;
    let object = git_line(root, &["rev-parse", &format!("HEAD:{RELEASE_PROFILES}")])?;
    let mut child = Command::new("git")
        .args(["hash-object", "--stdin"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let written = child
        .stdin
        .take()
        .ok_or("missing git input")?
        .write_all(&bytes);
    let output = child.wait_with_output()?;
    written?;
    if !output.status.success()
        || String::from_utf8(output.stdout)?.trim() != object
        || git_line(root, &["rev-parse", "HEAD"])? != head
    {
        return Err("release profile differs from its committed source image".into());
    }
    selected(&bytes, Some(&head)).map(Some)
}

fn git_line(root: &Path, args: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err("release profile is not owned by the current source commit".into());
    }
    let value = String::from_utf8(output.stdout)?.trim().to_owned();
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid source object identity".into());
    }
    Ok(value)
}

pub(crate) fn development(
    profiles: &InstalledNetworkProfiles,
) -> Result<Selection, Box<dyn Error>> {
    selected(&profiles.encode_installation()?, None)
}

fn selected(bytes: &[u8], release_commit: Option<&str>) -> Result<Selection, Box<dyn Error>> {
    let profiles = InstalledNetworkProfiles::from_installation_bytes(bytes)?;
    if profiles.encode_installation()? != bytes {
        return Err("installation profile image is not canonical".into());
    }
    if release_commit.is_some() {
        profiles.select("taira")?;
    }
    let names: Vec<String> = profiles.names().map(str::to_owned).collect();
    let source = release_commit.map_or(Source::Development, |commit| Source::Release {
        commit: commit.to_owned(),
    });
    Ok(Selection {
        bytes: bytes.to_vec(),
        names,
        source,
    })
}

impl Selection {
    /// Stage at the profile path selected by the canonical bundle layout.
    pub(crate) fn stage(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        std::fs::create_dir_all(path.parent().ok_or("profiles have no parent")?)?;
        std::fs::write(&path, &self.bytes)?;
        self.verify_installed(path)
    }

    /// Re-read and compare the exact retained image at the canonical layout path.
    pub(crate) fn verify_installed(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let bytes = InstalledNetworkProfiles::load(&path)?.encode_installation()?;
        if bytes.as_slice() != self.bytes {
            return Err(
                "installed network profiles differ from original packaging selection".into(),
            );
        }
        let decoded = InstalledNetworkProfiles::from_installation_bytes(&bytes)?;
        if decoded.names().ne(self.names.iter().map(String::as_str)) {
            return Err("installed network names differ from original packaging selection".into());
        }
        Ok(())
    }

    pub(crate) fn require_cli_names(&self, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        if bytes.len() > MAX_INSTALLED_PROFILE_BYTES {
            return Err("installed network listing exceeds bound".into());
        }
        let names: Vec<String> = json::from_slice(bytes)?;
        if names != self.names {
            return Err(
                "packaged Kagami did not expose the exact installed network profiles".into(),
            );
        }
        Ok(())
    }

    /// Original bounded image for a packager with an existing atomic private writer.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn provenance(&self) -> Value {
        let release_commit = match &self.source {
            Source::Development => None,
            Source::Release { commit } => Some(commit.as_str()),
        };
        norito::json!({
            "kind": (if release_commit.is_some() { "committed_release_source" } else { "explicit_development_input" }),
            "source_path": (release_commit.map(|_| RELEASE_PROFILES)),
            "source_commit": release_commit,
            "sha256": (hex::encode(Sha256::digest(&self.bytes))),
            "bytes": (self.bytes.len()),
            "networks": (self.names.clone()),
            "authentication": "installation release provenance must authenticate the selected source; label and digest alone do not",
        })
    }
}

#[cfg(test)]
mod tests;
