//! Static-site binding helpers backed by SoraFS storage.
use crate::secure_file_metadata::{
    SecureMetadata, from_file, from_path, is_direct_directory, is_direct_file, number_of_links,
    same_file, unchanged,
};
use http::uri::Authority;
use iroha_core::state::WorldReadOnly;
use iroha_crypto::Hash;
use iroha_data_model::soracloud::{
    SORA_SERVICE_CONFIG_ENTRY_VERSION_V1, SoraRouteVisibilityV1, SoraServiceConfigEntryV1,
};
use mv::storage::StorageReadOnly as _;
use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    net::IpAddr,
    path::{Component, Path, PathBuf},
};
/// Only supported static-site binding document schema.
pub const SITE_BINDINGS_SCHEMA_VERSION_V1: u8 = 1;
/// Maximum JSON container nesting accepted before parsing.
const SITE_BINDINGS_MAX_JSON_DEPTH: usize = 16;
/// Ledger service-config name carrying one authoritative public static-site binding.
pub(crate) const APP_STATIC_SITE_CONFIG_NAME: &str = "soracloud/app_static_site";
const APP_STATIC_SITE_BINDING_SCHEMA_VERSION_V1: u16 = 1;

#[derive(Clone, Debug, norito::derive::JsonDeserialize)]
struct AuthoritativeAppStaticSiteBindingV1 {
    schema_version: u16,
    hostname: String,
    mount_path: String,
    index_document: String,
    spa_fallback: bool,
    manifest_digest_hex: String,
}

/// Validated ledger-authoritative public static-site binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthoritativeAppSiteBinding {
    /// Canonical public hostname selected by the active service revision.
    pub(crate) hostname: String,
    /// Validated single-component document served for the site root.
    pub(crate) index_document: String,
    /// Whether an unresolved extensionless path falls back to the index document.
    pub(crate) spa_fallback: bool,
    /// Canonical lower-case digest of the locally stored site manifest.
    pub(crate) manifest_digest_hex: String,
}

/// Return whether one active public SoraCloud revision selects `host`.
///
/// This intentionally does not require a valid static-site config. Selecting
/// the host first lets the gateway return a stable service failure for a
/// malformed authoritative binding instead of falling through to an unrelated
/// Torii 404 or a weaker operator-file binding.
pub(crate) fn has_authoritative_public_site_host(world: &impl WorldReadOnly, host: &str) -> bool {
    world
        .soracloud_service_deployments()
        .iter()
        .any(|(service_id, deployment)| {
            world
                .soracloud_service_revisions()
                .get(&(
                    service_id.to_string(),
                    deployment.current_service_version.clone(),
                ))
                .and_then(|bundle| bundle.service.route.as_ref())
                .is_some_and(|route| {
                    route.visibility == SoraRouteVisibilityV1::Public
                        && normalize_host_header(&route.host).as_deref() == Some(host)
                })
        })
}

/// Resolve and validate the newest ledger-authoritative binding for `host`.
pub(crate) fn authoritative_app_site_binding(
    world: &impl WorldReadOnly,
    host: &str,
) -> Result<Option<AuthoritativeAppSiteBinding>, String> {
    let mut best_candidate: Option<(u64, String, SoraServiceConfigEntryV1)> = None;
    for (service_id, deployment) in world.soracloud_service_deployments().iter() {
        let service_name = service_id.to_string();
        let Some(bundle) = world.soracloud_service_revisions().get(&(
            service_name.clone(),
            deployment.current_service_version.clone(),
        )) else {
            continue;
        };
        let Some(route) = bundle.service.route.as_ref() else {
            continue;
        };
        if route.visibility != SoraRouteVisibilityV1::Public
            || normalize_host_header(&route.host).as_deref() != Some(host)
        {
            continue;
        }
        let Some(config_entry) = deployment.service_configs.get(APP_STATIC_SITE_CONFIG_NAME) else {
            continue;
        };
        let replace =
            best_candidate
                .as_ref()
                .is_none_or(|(best_sequence, best_service_name, _)| {
                    config_entry.last_update_sequence > *best_sequence
                        || (config_entry.last_update_sequence == *best_sequence
                            && service_name < *best_service_name)
                });
        if replace {
            best_candidate = Some((
                config_entry.last_update_sequence,
                service_name,
                config_entry.clone(),
            ));
        }
    }
    let Some((_sequence, service_name, config_entry)) = best_candidate else {
        return Ok(None);
    };
    if config_entry.schema_version != SORA_SERVICE_CONFIG_ENTRY_VERSION_V1
        || config_entry.config_name != APP_STATIC_SITE_CONFIG_NAME
    {
        return Err(format!(
            "service `{service_name}` has invalid static-site config metadata"
        ));
    }
    let encoded_value = norito::json::to_vec(&config_entry.value_json)
        .map_err(|_| format!("service `{service_name}` static-site config is not encodable"))?;
    if Hash::new(encoded_value) != config_entry.value_hash {
        return Err(format!(
            "service `{service_name}` static-site config hash does not match its value"
        ));
    }
    let binding = config_entry
        .value_json
        .try_into_any_norito::<AuthoritativeAppStaticSiteBindingV1>()
        .map_err(|_| format!("service `{service_name}` static-site config is not decodable"))?;
    if binding.schema_version != APP_STATIC_SITE_BINDING_SCHEMA_VERSION_V1 {
        return Err(format!(
            "service `{service_name}` static-site config has an unsupported schema"
        ));
    }
    if normalize_host_header(&binding.hostname).as_deref() != Some(host) {
        return Err(format!(
            "service `{service_name}` static-site config hostname does not match its route"
        ));
    }
    if binding.mount_path != "/" {
        return Err(format!(
            "service `{service_name}` static-site config mount path is unsupported"
        ));
    }
    validate_index_document_name(&binding.index_document)
        .map_err(|_| format!("service `{service_name}` static-site index document is invalid"))?;
    if binding.manifest_digest_hex.len() != 64
        || binding
            .manifest_digest_hex
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "service `{service_name}` static-site manifest digest is invalid"
        ));
    }
    Ok(Some(AuthoritativeAppSiteBinding {
        hostname: binding.hostname,
        index_document: binding.index_document,
        spa_fallback: binding.spa_fallback,
        manifest_digest_hex: binding.manifest_digest_hex,
    }))
}
/// Versioned JSON document loaded once from the configured startup path.
#[derive(
    Debug, Clone, PartialEq, Eq, norito::derive::JsonDeserialize, norito::derive::JsonSerialize,
)]
pub struct SiteBindingsDocument {
    /// Schema version. The first release accepts only version 1.
    pub version: u8,
    /// Host bindings served by Torii.
    #[norito(default)]
    pub sites: Vec<SiteBinding>,
}
/// Hostname to manifest mapping used for local static-site serving.
#[derive(
    Debug, Clone, norito::derive::JsonDeserialize, norito::derive::JsonSerialize, PartialEq, Eq,
)]
pub struct SiteBinding {
    /// Public hostname routed to the site.
    pub hostname: String,
    /// Hex-encoded manifest digest stored locally on the node.
    pub manifest_digest_hex: String,
    /// Optional index document. Defaults to `index.html`.
    #[norito(default)]
    pub index_document: Option<String>,
    /// Whether unknown extensionless paths should fall back to the index document.
    #[norito(default)]
    pub spa_fallback: Option<bool>,
}
impl SiteBinding {
    /// Return the configured index document or the default.
    #[must_use]
    pub fn index_document(&self) -> &str {
        self.index_document
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("index.html")
    }
    /// Return the SPA fallback toggle (defaults to `true`).
    #[must_use]
    pub fn spa_fallback_enabled(&self) -> bool {
        self.spa_fallback.unwrap_or(true)
    }
    /// Return the normalized host form used for lookup.
    #[must_use]
    pub fn normalized_hostname(&self) -> Option<String> {
        normalize_host_header(&self.hostname)
    }
}
/// Load, bound, and validate the configured static-site bindings.
///
/// The returned document is intended to be cached in Torii's immutable app state;
/// request handling must never reopen the operator-controlled path.
///
/// # Errors
///
/// Returns an error if the byte limit exceeds the platform address space or
/// the configured file fails secure loading, bounded decoding, or binding validation.
pub fn load_configured_site_bindings(
    config: &iroha_config::parameters::actual::SorafsGatewaySiteBindings,
) -> Result<Option<SiteBindingsDocument>, String> {
    let Some(path) = config.path.as_deref() else {
        return Ok(None);
    };
    let max_bytes = usize::try_from(config.max_bytes.get()).map_err(|_| {
        format!(
            "configured SoraFS site binding byte limit {} exceeds this platform's address space",
            config.max_bytes.get()
        )
    })?;
    load_site_bindings_file(path, max_bytes, config.max_sites.get()).map(Some)
}
/// Load one static-site binding document with explicit resource limits.
///
/// # Errors
///
/// Returns an error for zero limits, an unsafe path or file, I/O failures,
/// resource-limit violations, malformed JSON, or invalid site bindings.
pub fn load_site_bindings_file(
    path: &Path,
    max_bytes: usize,
    max_sites: usize,
) -> Result<SiteBindingsDocument, String> {
    if max_bytes == 0 {
        return Err("SoraFS site binding max_bytes must be non-zero".to_owned());
    }
    if max_sites == 0 {
        return Err("SoraFS site binding max_sites must be non-zero".to_owned());
    }
    let path = absolute_secure_path(path)?;
    let bytes = read_secure_bounded(&path, max_bytes)?;
    validate_json_depth(&bytes, SITE_BINDINGS_MAX_JSON_DEPTH)
        .map_err(|err| format!("invalid SoraFS site bindings `{}`: {err}", path.display()))?;
    let value = norito::json::from_slice::<norito::json::Value>(&bytes).map_err(|err| {
        format!(
            "failed to parse SoraFS site bindings `{}` as JSON: {err}",
            path.display()
        )
    })?;
    validate_binding_json_shape(&value, max_sites)
        .map_err(|err| format!("invalid SoraFS site bindings `{}`: {err}", path.display()))?;
    let mut document = norito::json::from_value::<SiteBindingsDocument>(value).map_err(|err| {
        format!(
            "failed to decode SoraFS site bindings `{}`: {err}",
            path.display()
        )
    })?;
    validate_site_bindings(&document, max_sites)
        .map_err(|err| format!("invalid SoraFS site bindings `{}`: {err}", path.display()))?;
    document
        .sites
        .sort_unstable_by(|left, right| left.hostname.cmp(&right.hostname));
    Ok(document)
}
fn absolute_secure_path(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("SoraFS site binding path must not be empty".to_owned());
    }
    for component in path.components() {
        if matches!(component, Component::CurDir | Component::ParentDir) {
            return Err(format!(
                "SoraFS site binding path `{}` contains a forbidden traversal component",
                path.display()
            ));
        }
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|err| format!("failed to resolve SoraFS site binding path: {err}"))
    }
}
type PinnedBindingAncestor = (PathBuf, SecureMetadata);

fn pin_binding_ancestors(path: &Path) -> Result<Vec<PinnedBindingAncestor>, String> {
    let mut current = PathBuf::new();
    let component_count = path.components().count();
    let mut ancestors = Vec::new();
    for (index, component) in path.components().enumerate() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        if index + 1 == component_count {
            break;
        }
        let metadata = from_path(&current).map_err(|err| {
            format!(
                "failed to inspect SoraFS site binding path component `{}`: {err}",
                current.display()
            )
        })?;
        if !is_direct_directory(&metadata) {
            return Err(format!(
                "SoraFS site binding ancestor `{}` must be a direct directory",
                current.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.mode() & 0o022 != 0 {
                return Err(format!(
                    "SoraFS site binding ancestor `{}` must not be group- or world-writable",
                    current.display()
                ));
            }
        }
        ancestors.push((current.clone(), metadata));
    }
    Ok(ancestors)
}

fn revalidate_binding_ancestors(ancestors: &[PinnedBindingAncestor]) -> Result<(), String> {
    for (path, before) in ancestors {
        let after = from_path(path).map_err(|err| {
            format!(
                "failed to re-inspect SoraFS site binding ancestor `{}`: {err}",
                path.display()
            )
        })?;
        if !is_direct_directory(&after) || !same_file(before, &after) {
            return Err(format!(
                "SoraFS site binding ancestor `{}` changed while the file was being read",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if after.mode() & 0o022 != 0 {
                return Err(format!(
                    "SoraFS site binding ancestor `{}` must not be group- or world-writable",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn open_read_only_no_follow(path: &Path) -> Result<File, String> {
    #[cfg(windows)]
    let opened = crate::secure_file_metadata::open_direct_file(path);
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY);
        options.open(path)
    };
    #[cfg(not(any(unix, windows)))]
    let opened = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure direct-file opening is unsupported on this platform",
    ));
    opened.map_err(|err| {
        format!(
            "failed to open SoraFS site bindings `{}`: {err}",
            path.display()
        )
    })
}
#[allow(unsafe_code)]
fn validate_binding_file_metadata(path: &Path, metadata: &SecureMetadata) -> Result<(), String> {
    if !is_direct_file(metadata) {
        return Err(format!(
            "SoraFS site binding path `{}` is not a direct regular file",
            path.display()
        ));
    }
    if number_of_links(metadata) != Some(1) {
        return Err(format!(
            "SoraFS site binding file `{}` must have exactly one hard link",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != effective_uid && metadata.uid() != 0 {
            return Err(format!(
                "SoraFS site binding file `{}` must be owned by the Torii user or root",
                path.display()
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(format!(
                "SoraFS site binding file `{}` must not be group- or world-writable",
                path.display()
            ));
        }
    }
    Ok(())
}
fn read_secure_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let ancestors = pin_binding_ancestors(path)?;
    let before = from_path(path).map_err(|err| {
        format!(
            "failed to inspect SoraFS site bindings `{}`: {err}",
            path.display()
        )
    })?;
    validate_binding_file_metadata(path, &before)?;
    revalidate_binding_ancestors(&ancestors)?;
    let max_bytes_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if before.len() > max_bytes_u64 {
        return Err(format!(
            "SoraFS site binding file `{}` is {} bytes, exceeding the {} byte limit",
            path.display(),
            before.len(),
            max_bytes
        ));
    }
    let mut file = open_read_only_no_follow(path)?;
    let opened_before = from_file(&file).map_err(|err| {
        format!(
            "failed to inspect opened SoraFS site bindings `{}`: {err}",
            path.display()
        )
    })?;
    let named_after_open = from_path(path).map_err(|err| {
        format!(
            "failed to re-inspect opened SoraFS site bindings `{}`: {err}",
            path.display()
        )
    })?;
    validate_binding_file_metadata(path, &opened_before)?;
    validate_binding_file_metadata(path, &named_after_open)?;
    if !same_file(&before, &opened_before)
        || !unchanged(&before, &opened_before)
        || !same_file(&opened_before, &named_after_open)
        || !unchanged(&opened_before, &named_after_open)
    {
        return Err(format!(
            "SoraFS site binding file `{}` changed while it was opened",
            path.display()
        ));
    }
    revalidate_binding_ancestors(&ancestors)?;
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_before.len())
            .unwrap_or(max_bytes)
            .min(max_bytes),
    );
    (&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|err| {
            format!(
                "failed to read SoraFS site bindings `{}`: {err}",
                path.display()
            )
        })?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "SoraFS site binding file `{}` grew beyond the {} byte limit while being read",
            path.display(),
            max_bytes
        ));
    }
    let opened_after = from_file(&file).map_err(|err| {
        format!(
            "failed to re-inspect opened SoraFS site bindings `{}`: {err}",
            path.display()
        )
    })?;
    let named_after_read = from_path(path).map_err(|err| {
        format!(
            "failed to re-inspect SoraFS site bindings `{}` after reading: {err}",
            path.display()
        )
    })?;
    validate_binding_file_metadata(path, &opened_after)?;
    validate_binding_file_metadata(path, &named_after_read)?;
    if !same_file(&opened_before, &opened_after)
        || !unchanged(&opened_before, &opened_after)
        || !same_file(&opened_after, &named_after_read)
        || !unchanged(&opened_after, &named_after_read)
        || !same_file(&before, &named_after_read)
        || !unchanged(&before, &named_after_read)
    {
        return Err(format!(
            "SoraFS site binding file `{}` changed while it was being read",
            path.display()
        ));
    }
    revalidate_binding_ancestors(&ancestors)?;
    if u64::try_from(bytes.len()).ok() != Some(opened_before.len()) {
        return Err(format!(
            "SoraFS site binding file `{}` changed size while being read",
            path.display()
        ));
    }
    Ok(bytes)
}
fn validate_json_depth(bytes: &[u8], max_depth: usize) -> Result<(), String> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > max_depth {
                    return Err(format!(
                        "JSON nesting exceeds the supported depth of {max_depth}"
                    ));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}
fn reject_unknown_keys(
    object: &norito::json::Map,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("{context} contains unknown field `{key}`"));
    }
    Ok(())
}
fn validate_binding_json_shape(
    value: &norito::json::Value,
    max_sites: usize,
) -> Result<(), String> {
    let norito::json::Value::Object(document) = value else {
        return Err("top-level binding document must be a JSON object".to_owned());
    };
    reject_unknown_keys(document, &["sites", "version"], "binding document")?;
    let sites = document
        .get("sites")
        .ok_or_else(|| "binding document is missing required field `sites`".to_owned())?;
    let norito::json::Value::Array(sites) = sites else {
        return Err("binding document field `sites` must be an array".to_owned());
    };
    if sites.len() > max_sites {
        return Err(format!(
            "binding document contains {} sites, exceeding the configured limit of {max_sites}",
            sites.len()
        ));
    }
    for (index, site) in sites.iter().enumerate() {
        let norito::json::Value::Object(site) = site else {
            return Err(format!("sites[{index}] must be a JSON object"));
        };
        reject_unknown_keys(
            site,
            &[
                "hostname",
                "index_document",
                "manifest_digest_hex",
                "spa_fallback",
            ],
            &format!("sites[{index}]"),
        )?;
    }
    Ok(())
}
fn validate_site_bindings(document: &SiteBindingsDocument, max_sites: usize) -> Result<(), String> {
    if document.version != SITE_BINDINGS_SCHEMA_VERSION_V1 {
        return Err(format!(
            "unsupported schema version {}; expected {SITE_BINDINGS_SCHEMA_VERSION_V1}",
            document.version
        ));
    }
    if document.sites.len() > max_sites {
        return Err(format!(
            "binding document contains {} sites, exceeding the configured limit of {max_sites}",
            document.sites.len()
        ));
    }
    let mut hostnames = BTreeSet::new();
    for (index, binding) in document.sites.iter().enumerate() {
        validate_site_binding(binding).map_err(|err| format!("sites[{index}]: {err}"))?;
        if !hostnames.insert(binding.hostname.as_str()) {
            return Err(format!(
                "sites[{index}] duplicates hostname `{}`",
                binding.hostname
            ));
        }
    }
    Ok(())
}
fn validate_site_binding(binding: &SiteBinding) -> Result<(), String> {
    validate_canonical_hostname(&binding.hostname)?;
    if binding.manifest_digest_hex.len() != 64
        || !binding
            .manifest_digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "manifest_digest_hex must be exactly 64 canonical lowercase hexadecimal characters"
                .to_owned(),
        );
    }
    if let Some(index_document) = binding.index_document.as_deref() {
        validate_index_document_name(index_document)?;
    }
    Ok(())
}
fn validate_index_document_name(index_document: &str) -> Result<(), String> {
    if index_document.is_empty()
        || index_document.len() > 255
        || index_document.trim() != index_document
        || matches!(index_document, "." | "..")
        || index_document
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '/' | '\\' | '?' | '#'))
    {
        return Err(
            "index_document must be a non-empty canonical file name of at most 255 bytes"
                .to_owned(),
        );
    }
    Ok(())
}
fn validate_canonical_hostname(hostname: &str) -> Result<(), String> {
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname.trim() != hostname
        || hostname.ends_with('.')
        || !hostname.is_ascii()
        || hostname.bytes().any(|byte| byte.is_ascii_uppercase())
        || hostname.parse::<IpAddr>().is_ok()
    {
        return Err("hostname must be a canonical lowercase DNS name".to_owned());
    }
    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("hostname must be a canonical lowercase DNS name".to_owned());
        }
    }
    Ok(())
}
/// Normalize an inbound `Host` header or configured hostname.
#[must_use]
pub fn normalize_host_header(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let authority = Authority::try_from(trimmed).ok()?;
    let host = authority
        .host()
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    // DNS names are bounded at 253 bytes, while textual IP literals are smaller. Keep the
    // normalized form suitable for persistent policy events even when an HTTP implementation
    // accepts a larger syntactically valid authority.
    (!host.is_empty() && host.len() <= 253).then_some(host)
}
/// Encode a raw CID byte sequence using lowercase multibase base32.
#[must_use]
pub fn encode_content_cid(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    if bytes.is_empty() {
        return "b".to_string();
    }
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity((bytes.len() * 8).div_ceil(5) + 1);
    out.push(b'b');
    for byte in bytes {
        acc = (acc << 8) | (*byte as u32);
        bits += 8;
        while bits >= 5 {
            let index = ((acc >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index]);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((acc << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index]);
    }
    String::from_utf8(out).expect("CID alphabet is valid UTF-8")
}
/// Decode a lowercase multibase base32 CID into raw bytes.
#[must_use]
pub fn decode_content_cid(raw: &str) -> Option<Vec<u8>> {
    let trimmed = raw.trim();
    let encoded = trimmed
        .strip_prefix('b')
        .or_else(|| trimmed.strip_prefix('B'))?;
    if encoded.is_empty() {
        return None;
    }
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity((encoded.len() * 5) / 8);
    for ch in encoded.chars() {
        let value = match ch {
            'a'..='z' => (ch as u8 - b'a') as u32,
            '2'..='7' => 26 + (ch as u8 - b'2') as u32,
            _ => return None,
        };
        acc = (acc << 5) | value;
        bits += 5;
        while bits >= 8 {
            out.push(((acc >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    if bits > 0 {
        let mask = (1u32 << bits) - 1;
        if (acc & mask) != 0 {
            return None;
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}
/// Resolve the binding matching the provided host.
#[must_use]
pub fn find_site_binding<'a>(
    document: &'a SiteBindingsDocument,
    host: &str,
) -> Option<&'a SiteBinding> {
    let normalized = normalize_host_header(host)?;
    document
        .sites
        .iter()
        .find(|binding| binding.normalized_hostname().as_deref() == Some(normalized.as_str()))
}
/// Convert a request path into dataset path components.
#[must_use]
pub fn path_components_for_request(raw_path: &str, index_document: &str) -> Option<Vec<String>> {
    const MAX_SITE_PATH_BYTES: usize = 4096;
    const MAX_SITE_PATH_COMPONENTS: usize = 128;
    const MAX_SITE_PATH_COMPONENT_BYTES: usize = 255;
    if raw_path.len() > MAX_SITE_PATH_BYTES || validate_index_document_name(index_document).is_err()
    {
        return None;
    }
    let trimmed = raw_path.trim_start_matches('/');
    let effective = if trimmed.is_empty() {
        index_document.to_string()
    } else if raw_path.ends_with('/') {
        format!("{trimmed}{index_document}")
    } else {
        trimmed.to_string()
    };
    if effective.len() > MAX_SITE_PATH_BYTES {
        return None;
    }
    let mut segments = Vec::new();
    for segment in effective.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.len() > MAX_SITE_PATH_COMPONENT_BYTES
            || segment.trim() != segment
            || segment.chars().any(|ch| ch.is_control() || ch == '\\')
            || segments.len() >= MAX_SITE_PATH_COMPONENTS
        {
            return None;
        }
        segments.push(segment.to_string());
    }
    if segments.is_empty() {
        return None;
    }
    Some(segments)
}
/// Decide whether an unknown path should fall back to the SPA entrypoint.
#[cfg(test)]
#[must_use]
pub fn should_use_spa_fallback(raw_path: &str, binding: &SiteBinding) -> bool {
    if !binding.spa_fallback_enabled() {
        return false;
    }
    let trimmed = raw_path.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or_default();
    !last.contains('.')
}
/// Best-effort content-type lookup for static site assets.
#[must_use]
pub fn content_type_for_path(path: &[String]) -> &'static str {
    path.last()
        .and_then(|segment| iroha_torii_shared::content_mime::media_type_for_path(segment))
        .unwrap_or("application/octet-stream")
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sample_document() -> SiteBindingsDocument {
        SiteBindingsDocument {
            version: SITE_BINDINGS_SCHEMA_VERSION_V1,
            sites: vec![SiteBinding {
                hostname: "taira.sora.org".to_owned(),
                manifest_digest_hex: "ab".repeat(32),
                index_document: Some("index.html".to_owned()),
                spa_fallback: Some(true),
            }],
        }
    }
    fn write_secure_fixture(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("create temporary site binding directory");
        let canonical_dir = fs::canonicalize(dir.path()).expect("canonical temporary directory");
        let path = canonical_dir.join("bindings.json");
        fs::write(&path, bytes).expect("write site bindings fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("restrict site bindings fixture permissions");
        }
        (dir, path)
    }
    fn encoded_sample_document() -> Vec<u8> {
        norito::json::to_vec(&sample_document()).expect("encode sample site bindings")
    }
    #[test]
    fn configured_loader_is_disabled_without_a_path() {
        let config = iroha_config::parameters::actual::SorafsGatewaySiteBindings::default();
        assert_eq!(
            load_configured_site_bindings(&config).expect("disabled bindings are valid"),
            None
        );
    }
    #[test]
    fn normalizes_hostnames_with_ports() {
        assert_eq!(
            normalize_host_header("taira.sora.org:443"),
            Some("taira.sora.org".to_string())
        );
        assert_eq!(
            normalize_host_header(&format!("{}.org", "a".repeat(254))),
            None
        );
    }
    #[test]
    fn request_path_defaults_to_index_document() {
        assert_eq!(
            path_components_for_request("/", "index.html"),
            Some(vec!["index.html".to_string()])
        );
        assert_eq!(
            path_components_for_request("/app/", "index.html"),
            Some(vec!["app".to_string(), "index.html".to_string()])
        );
        assert_eq!(
            path_components_for_request("/../secret", "index.html"),
            None
        );
        assert_eq!(path_components_for_request("/a\\b", "index.html"), None);
        assert_eq!(path_components_for_request("/ padded ", "index.html"), None);
        assert_eq!(path_components_for_request("/", "../index.html"), None);
        assert_eq!(
            path_components_for_request(&format!("/{}", "a".repeat(256)), "index.html"),
            None
        );
    }
    #[test]
    fn spa_fallback_skips_extensionful_assets() {
        let binding = SiteBinding {
            hostname: "taira.sora.org".to_string(),
            manifest_digest_hex: "ab".repeat(32),
            index_document: None,
            spa_fallback: Some(true),
        };
        assert!(should_use_spa_fallback("/swap", &binding));
        assert!(!should_use_spa_fallback("/assets/app.js", &binding));
    }
    #[test]
    fn cid_roundtrip_uses_lowercase_multibase_base32() {
        let encoded = encode_content_cid(&[0x01, 0x71, 0x1f, 0x20, 0xf3, 0x09, 0x6a, 0xe2]);
        assert_eq!(encoded, "bafyr6ihtbfvoe");
        assert_eq!(
            decode_content_cid(&encoded),
            Some(vec![0x01, 0x71, 0x1f, 0x20, 0xf3, 0x09, 0x6a, 0xe2])
        );
    }
    #[test]
    fn secure_loader_accepts_exact_resource_bound_and_sorts_hosts() {
        let mut document = sample_document();
        document.sites.push(SiteBinding {
            hostname: "alpha.sora.org".to_owned(),
            manifest_digest_hex: "cd".repeat(32),
            index_document: None,
            spa_fallback: None,
        });
        let bytes = norito::json::to_vec(&document).expect("encode site bindings");
        let (_dir, path) = write_secure_fixture(&bytes);
        let loaded = load_site_bindings_file(&path, bytes.len(), 2).expect("valid bindings");
        assert_eq!(loaded.sites[0].hostname, "alpha.sora.org");
        assert_eq!(loaded.sites[1].hostname, "taira.sora.org");
        assert!(load_site_bindings_file(&path, bytes.len() - 1, 2).is_err());
        assert!(load_site_bindings_file(&path, bytes.len(), 1).is_err());
    }
    #[test]
    fn loader_rejects_duplicate_hosts_and_noncanonical_fields() {
        let invalid_documents = [
            SiteBindingsDocument {
                version: 2,
                ..sample_document()
            },
            SiteBindingsDocument {
                sites: vec![sample_document().sites[0].clone(); 2],
                ..sample_document()
            },
            SiteBindingsDocument {
                sites: vec![SiteBinding {
                    hostname: "Taira.Sora.Org".to_owned(),
                    ..sample_document().sites[0].clone()
                }],
                ..sample_document()
            },
            SiteBindingsDocument {
                sites: vec![SiteBinding {
                    hostname: "taira.sora.org:443".to_owned(),
                    ..sample_document().sites[0].clone()
                }],
                ..sample_document()
            },
            SiteBindingsDocument {
                sites: vec![SiteBinding {
                    hostname: "127.0.0.1".to_owned(),
                    ..sample_document().sites[0].clone()
                }],
                ..sample_document()
            },
            SiteBindingsDocument {
                sites: vec![SiteBinding {
                    manifest_digest_hex: "AB".repeat(32),
                    ..sample_document().sites[0].clone()
                }],
                ..sample_document()
            },
            SiteBindingsDocument {
                sites: vec![SiteBinding {
                    index_document: Some("../index.html".to_owned()),
                    ..sample_document().sites[0].clone()
                }],
                ..sample_document()
            },
        ];
        for (index, document) in invalid_documents.into_iter().enumerate() {
            let bytes = norito::json::to_vec(&document).expect("encode invalid bindings");
            let (_dir, path) = write_secure_fixture(&bytes);
            assert!(
                load_site_bindings_file(&path, bytes.len(), 8).is_err(),
                "invalid document {index} must fail closed"
            );
        }
    }
    #[test]
    fn loader_rejects_unknown_duplicate_and_deep_json_fields() {
        let digest = "ab".repeat(32);
        let cases = [
            r#"{"version":1,"sites":[],"unexpected":true}"#.to_owned(),
            r#"{"version":1,"version":1,"sites":[]}"#.to_owned(),
            r#"{"sites":[]}"#.to_owned(),
            r#"{"version":null,"sites":[]}"#.to_owned(),
            format!(
                r#"{{"version":1,"sites":[{{"hostname":"taira.sora.org","manifest_digest_hex":"{digest}","unknown":0}}]}}"#
            ),
            r#"{"version":1,"sites":[{"hostname":"taira.sora.org"}]}"#.to_owned(),
            format!(
                r#"{{"version":1,"sites":[{{"hostname":"taira.sora.org","manifest_digest_hex":"{digest}","spa_fallback":"yes"}}]}}"#
            ),
            format!("{}0{}", "[".repeat(17), "]".repeat(17)),
        ];
        for (index, json) in cases.into_iter().enumerate() {
            let (_dir, path) = write_secure_fixture(json.as_bytes());
            assert!(
                load_site_bindings_file(&path, json.len(), 8).is_err(),
                "malformed schema case {index} must fail closed"
            );
        }
    }
    #[test]
    fn loader_caches_owned_document_instead_of_reopening_path() {
        let bytes = encoded_sample_document();
        let (_dir, path) = write_secure_fixture(&bytes);
        let loaded = load_site_bindings_file(&path, bytes.len(), 1).expect("load bindings");
        fs::write(&path, b"not json").expect("replace source after startup load");
        assert_eq!(loaded, sample_document());
    }
    #[cfg(unix)]
    #[test]
    fn secure_loader_rejects_symlinks_and_unsafe_permissions() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let bytes = encoded_sample_document();
        let (dir, path) = write_secure_fixture(&bytes);
        let canonical_dir = fs::canonicalize(dir.path()).expect("canonical fixture directory");
        let file_link = canonical_dir.join("bindings-link.json");
        symlink(&path, &file_link).expect("create binding symlink");
        assert!(load_site_bindings_file(&file_link, bytes.len(), 1).is_err());
        let nested = canonical_dir.join("nested");
        fs::create_dir(&nested).expect("create nested directory");
        let nested_file = nested.join("bindings.json");
        fs::write(&nested_file, &bytes).expect("write nested fixture");
        let parent_link = canonical_dir.join("nested-link");
        symlink(&nested, &parent_link).expect("create parent symlink");
        assert!(
            load_site_bindings_file(&parent_link.join("bindings.json"), bytes.len(), 1).is_err()
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o622))
            .expect("make fixture group writable");
        assert!(load_site_bindings_file(&path, bytes.len(), 1).is_err());
        let (unsafe_parent, unsafe_path) = write_secure_fixture(&bytes);
        fs::set_permissions(
            fs::canonicalize(unsafe_parent.path()).expect("canonical unsafe parent"),
            fs::Permissions::from_mode(0o777),
        )
        .expect("make parent world writable");
        assert!(load_site_bindings_file(&unsafe_path, bytes.len(), 1).is_err());
    }
    #[cfg(any(unix, windows))]
    #[test]
    fn secure_loader_rejects_multiply_linked_files() {
        let bytes = encoded_sample_document();
        let (directory, path) = write_secure_fixture(&bytes);
        let hard_link = directory.path().join("bindings-hardlink.json");
        fs::hard_link(&path, &hard_link).expect("create hard link");

        assert!(load_site_bindings_file(&path, bytes.len(), 1).is_err());
    }
    #[test]
    fn secure_loader_rejects_traversal_and_non_files() {
        let bytes = encoded_sample_document();
        let (dir, path) = write_secure_fixture(&bytes);
        let canonical_dir = fs::canonicalize(dir.path()).expect("canonical fixture directory");
        let traversal = canonical_dir
            .join("nested")
            .join("..")
            .join("bindings.json");
        assert!(load_site_bindings_file(&traversal, bytes.len(), 1).is_err());
        assert!(load_site_bindings_file(&canonical_dir, bytes.len(), 1).is_err());
        assert!(load_site_bindings_file(&path, 0, 1).is_err());
        assert!(load_site_bindings_file(&path, bytes.len(), 0).is_err());
    }
}
