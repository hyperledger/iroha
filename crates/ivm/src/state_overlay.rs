//! Bounded durable state storage for development and test hosts.
use crate::VMError;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64_STANDARD};
use iroha_model_base::state_path::StatePath;
use norito::json;
#[path = "state_overlay_fs.rs"]
mod state_overlay_fs;
use state_overlay_fs::RetainedOverlayTarget;
use std::{collections::BTreeMap, ops::Bound, path::PathBuf};
/// Maximum number of entries retained by one first-release development overlay.
pub(crate) const STATE_OVERLAY_MAX_ENTRIES_V1: usize = 4_096;
/// Maximum aggregate UTF-8 bytes retained in overlay paths.
pub(crate) const STATE_OVERLAY_MAX_PATH_BYTES_V1: usize = 4 * 1024 * 1024;
/// Maximum aggregate raw value bytes retained by one overlay.
pub(crate) const STATE_OVERLAY_MAX_VALUE_BYTES_V1: usize = 16 * 1024 * 1024;
/// Maximum encoded size of one persisted overlay file.
pub(crate) const STATE_OVERLAY_MAX_FILE_BYTES_V1: usize = 30 * 1024 * 1024;
const STATE_OVERLAY_MAX_BASE64_VALUE_BYTES_V1: usize =
    crate::syscalls::STATE_MAX_VALUE_BYTES.div_ceil(3) * 4;
const STATE_OVERLAY_MAX_RAW_JSON_PATH_BYTES_V1: usize = crate::syscalls::STATE_MAX_PATH_BYTES * 6;
const STATE_OVERLAY_MAX_RAW_JSON_VALUE_BYTES_V1: usize =
    STATE_OVERLAY_MAX_BASE64_VALUE_BYTES_V1 * 6;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OverlayResourceUsage {
    path_bytes: usize,
    value_bytes: usize,
}

#[derive(Debug)]
enum OverlayFlushError {
    BeforePublication(VMError),
    AfterPublication(VMError),
    Poisoned(VMError),
}

impl OverlayFlushError {
    const fn publication_happened(&self) -> bool {
        matches!(self, Self::AfterPublication(_))
    }

    fn into_vm_error(self) -> VMError {
        match self {
            Self::BeforePublication(error)
            | Self::AfterPublication(error)
            | Self::Poisoned(error) => error,
        }
    }
}

impl From<VMError> for OverlayFlushError {
    fn from(error: VMError) -> Self {
        Self::BeforePublication(error)
    }
}
/// Durable host-backed state overlay used by dev/test hosts.
///
/// Values are stored as raw `NoritoBytes` payloads keyed by a canonical state
/// path. Pointer-ABI envelopes exist only at the guest/host boundary.
/// When a persistence path is provided, the overlay writes a Norito JSON map
/// `{ path: base64(raw_payload_bytes) }` so test runs can survive VM restarts.
/// Persistence retains the deepest existing ancestor and resolves every later
/// component relative to that handle without following links. Once the final
/// parent exists, its exact handle is shared by all clones and used for every
/// leaf operation; publication is atomic. On Unix, the enforced trust policy
/// requires the final parent and existing leaf to be owned by the effective
/// user with no group/world write mode bits. Each containing namespace used
/// for component lookup must additionally be root/effective-user owned and
/// either mode-bit private or sticky. Same-UID, privileged, and writers
/// authorized through platform ACLs remain trusted.
/// A hostile direct final parent is therefore outside the supported boundary.
/// On Windows, newly created directories inherit their parent DACL. Retained
/// handles prevent later rebinding of components once resolved, but unresolved
/// lookup namespaces and the final directory remain trusted against principals
/// authorized by their DACLs.
/// Retained capabilities are process-local: reconstructing an overlay resolves
/// the configured path as it exists at that later time.
/// If the final durability barrier fails after an atomic replacement, the new
/// in-memory image is retained and the shared persistence target is poisoned;
/// later mutations and flushes fail until the overlay is reconstructed.
#[derive(Clone, Debug, Default)]
pub struct DurableStateOverlay {
    persist_target: Option<RetainedOverlayTarget>,
    data: BTreeMap<StatePath, Vec<u8>>,
    path_bytes: usize,
    value_bytes: usize,
}
/// Snapshot of a durable state overlay.
#[derive(Clone, Debug, Default)]
pub struct DurableStateSnapshot {
    data: BTreeMap<StatePath, Vec<u8>>,
}
impl DurableStateOverlay {
    fn validate_entry(path: &StatePath, value: &[u8]) -> Result<(), VMError> {
        crate::host::validate_state_path(path)?;
        crate::host::validate_state_value_payload_len(value.len())
    }
    fn ensure_resource_limits(
        entry_count: usize,
        path_bytes: usize,
        value_bytes: usize,
    ) -> Result<(), VMError> {
        if entry_count > STATE_OVERLAY_MAX_ENTRIES_V1
            || path_bytes > STATE_OVERLAY_MAX_PATH_BYTES_V1
            || value_bytes > STATE_OVERLAY_MAX_VALUE_BYTES_V1
        {
            return Err(VMError::NoritoInvalid);
        }
        Ok(())
    }
    fn validate_collection(
        data: &BTreeMap<StatePath, Vec<u8>>,
    ) -> Result<OverlayResourceUsage, VMError> {
        Self::ensure_resource_limits(data.len(), 0, 0)?;
        let mut usage = OverlayResourceUsage::default();
        for (path, value) in data {
            Self::validate_entry(path, value)?;
            usage.path_bytes = usage
                .path_bytes
                .checked_add(path.as_ref().len())
                .ok_or(VMError::NoritoInvalid)?;
            usage.value_bytes = usage
                .value_bytes
                .checked_add(value.len())
                .ok_or(VMError::NoritoInvalid)?;
            Self::ensure_resource_limits(data.len(), usage.path_bytes, usage.value_bytes)?;
        }
        Ok(usage)
    }
    /// Create an in-memory overlay with no persistence.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            persist_target: None,
            data: BTreeMap::new(),
            path_bytes: 0,
            value_bytes: 0,
        }
    }
    /// Create an overlay that persists to the given path.
    pub fn with_persist_path(path: PathBuf) -> Result<Self, VMError> {
        let persist_target =
            RetainedOverlayTarget::from_path(&path).map_err(|_| VMError::NoritoInvalid)?;
        let mut overlay = Self {
            persist_target: Some(persist_target),
            data: BTreeMap::new(),
            path_bytes: 0,
            value_bytes: 0,
        };
        overlay.reload_from_disk()?;
        Ok(overlay)
    }
    /// Return a copy of the raw `NoritoBytes` payload for a path, if present.
    pub fn get(&self, path: &StatePath) -> Option<Vec<u8>> {
        self.data.get(path).cloned()
    }
    /// Borrow a stored raw payload without materializing a copy.
    ///
    /// Stateful syscall handlers use this to inspect the response length and
    /// prove affordability before allocating or copying guest-visible output.
    pub fn get_ref(&self, path: &StatePath) -> Option<&[u8]> {
        self.data.get(path).map(Vec::as_slice)
    }
    /// Borrow a validated state-value payload.
    ///
    /// `set`, `restore`, and persisted-state loading enforce the payload-size
    /// bound before the value enters `data`. `STATE_LEN` can therefore read the
    /// stored vector length in constant time, independent of value size.
    pub(crate) fn value_payload_ref(&self, path: &StatePath) -> Result<Option<&[u8]>, VMError> {
        Ok(self.get_ref(path))
    }
    /// Insert or replace the raw payload for the provided path.
    pub fn set(&mut self, path: &StatePath, value: Vec<u8>) -> Result<(), VMError> {
        self.ensure_persistence_healthy()?;
        Self::validate_entry(path, &value)?;
        let previous_value_len = self.data.get(path).map_or(0, Vec::len);
        let is_new = !self.data.contains_key(path);
        let next_entry_count = self.data.len().saturating_add(if is_new { 1 } else { 0 });
        let next_path_bytes = if is_new {
            self.path_bytes
                .checked_add(path.as_ref().len())
                .ok_or(VMError::NoritoInvalid)?
        } else {
            self.path_bytes
        };
        let next_value_bytes = self
            .value_bytes
            .checked_sub(previous_value_len)
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(VMError::NoritoInvalid)?;
        Self::ensure_resource_limits(next_entry_count, next_path_bytes, next_value_bytes)?;
        let key = path.clone();
        let prev = self.data.insert(key.clone(), value);
        let previous_usage = OverlayResourceUsage {
            path_bytes: self.path_bytes,
            value_bytes: self.value_bytes,
        };
        self.path_bytes = next_path_bytes;
        self.value_bytes = next_value_bytes;
        if let Err(failure) = self.flush_internal() {
            let publication_happened = failure.publication_happened();
            let error = failure.into_vm_error();
            if !publication_happened {
                match prev {
                    Some(old) => {
                        self.data.insert(key, old);
                    }
                    None => {
                        self.data.remove(&key);
                    }
                }
                self.path_bytes = previous_usage.path_bytes;
                self.value_bytes = previous_usage.value_bytes;
            }
            return Err(error);
        }
        Ok(())
    }
    /// Iterate over the stored state paths.
    pub fn keys(&self) -> impl Iterator<Item = &StatePath> {
        self.data.keys()
    }
    /// Visit only keys in the ordered range sharing `prefix` as text.
    ///
    /// Callers apply any stricter path-segment rule. Starting at the ordered
    /// lower bound prevents an attacker-selected state prefix from charging or
    /// examining unrelated keys that sort before it.
    pub fn keys_with_text_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = &'a StatePath> + 'a {
        self.data
            .range::<str, _>((Bound::Included(prefix), Bound::Unbounded))
            .map(|(key, _)| key)
            .take_while(move |key| (*key).as_ref().starts_with(prefix))
    }
    /// Seek directly after a cursor and yield only keys sharing the map prefix.
    pub fn keys_after_with_text_prefix<'a>(
        &'a self,
        prefix: &'a str,
        after: Option<&'a str>,
    ) -> impl Iterator<Item = &'a StatePath> + 'a {
        let lower = after.map_or(Bound::Included(prefix), Bound::Excluded);
        self.data
            .range::<str, _>((lower, Bound::Unbounded))
            .map(|(key, _)| key)
            .take_while(move |key| (*key).as_ref().starts_with(prefix))
    }
    /// Delete the raw payload for the provided path.
    pub fn del(&mut self, path: &StatePath) -> Result<(), VMError> {
        self.ensure_persistence_healthy()?;
        let previous_usage = OverlayResourceUsage {
            path_bytes: self.path_bytes,
            value_bytes: self.value_bytes,
        };
        let next_usage = if let Some(value) = self.data.get(path) {
            OverlayResourceUsage {
                path_bytes: self
                    .path_bytes
                    .checked_sub(path.as_ref().len())
                    .ok_or(VMError::NoritoInvalid)?,
                value_bytes: self
                    .value_bytes
                    .checked_sub(value.len())
                    .ok_or(VMError::NoritoInvalid)?,
            }
        } else {
            previous_usage
        };
        let prev = self.data.remove(path);
        self.path_bytes = next_usage.path_bytes;
        self.value_bytes = next_usage.value_bytes;
        if let Err(failure) = self.flush_internal() {
            let publication_happened = failure.publication_happened();
            let error = failure.into_vm_error();
            if !publication_happened {
                if let Some(old) = prev {
                    self.data.insert(path.clone(), old);
                }
                self.path_bytes = previous_usage.path_bytes;
                self.value_bytes = previous_usage.value_bytes;
            }
            return Err(error);
        }
        Ok(())
    }
    /// Take a snapshot of the current overlay contents.
    #[must_use]
    pub fn checkpoint(&self) -> DurableStateSnapshot {
        DurableStateSnapshot {
            data: self.data.clone(),
        }
    }
    /// Restore from a previously taken snapshot and persist to disk if needed.
    pub fn restore(&mut self, snapshot: &DurableStateSnapshot) -> Result<(), VMError> {
        self.ensure_persistence_healthy()?;
        let usage = Self::validate_collection(&snapshot.data)?;
        let replacement = snapshot.data.clone();
        let previous_data = std::mem::replace(&mut self.data, replacement);
        let previous_usage = OverlayResourceUsage {
            path_bytes: std::mem::replace(&mut self.path_bytes, usage.path_bytes),
            value_bytes: std::mem::replace(&mut self.value_bytes, usage.value_bytes),
        };
        if let Err(failure) = self.flush_internal() {
            let publication_happened = failure.publication_happened();
            let error = failure.into_vm_error();
            if !publication_happened {
                self.data = previous_data;
                self.path_bytes = previous_usage.path_bytes;
                self.value_bytes = previous_usage.value_bytes;
            }
            return Err(error);
        }
        Ok(())
    }
    /// Force a flush of the current in-memory overlay to disk (no-op if no path).
    pub fn flush(&self) -> Result<(), VMError> {
        self.flush_internal()
            .map_err(OverlayFlushError::into_vm_error)
    }

    fn flush_internal(&self) -> Result<(), OverlayFlushError> {
        let Some(target) = &self.persist_target else {
            return Ok(());
        };
        if target.is_poisoned() {
            return Err(OverlayFlushError::Poisoned(VMError::NoritoInvalid));
        }
        let usage = Self::validate_collection(&self.data)?;
        if usage.path_bytes != self.path_bytes || usage.value_bytes != self.value_bytes {
            return Err(VMError::NoritoInvalid.into());
        }
        let encoded_len = persisted_json_encoded_len(&self.data)?;
        let mut serialized = String::with_capacity(encoded_len);
        serialized.push('{');
        for (index, (key, value)) in self.data.iter().enumerate() {
            if index != 0 {
                serialized.push(',');
            }
            json::write_json_string(key.as_ref(), &mut serialized);
            serialized.push(':');
            serialized.push('"');
            B64_STANDARD.encode_string(value, &mut serialized);
            serialized.push('"');
        }
        serialized.push('}');
        if serialized.len() != encoded_len || serialized.len() > STATE_OVERLAY_MAX_FILE_BYTES_V1 {
            return Err(VMError::NoritoInvalid.into());
        }
        match state_overlay_fs::atomic_write(target, serialized.as_bytes()) {
            Ok(()) => Ok(()),
            Err(state_overlay_fs::AtomicWriteError::BeforePublication(_error)) => {
                Err(OverlayFlushError::BeforePublication(VMError::NoritoInvalid))
            }
            Err(state_overlay_fs::AtomicWriteError::AfterPublication(_error)) => {
                Err(OverlayFlushError::AfterPublication(VMError::NoritoInvalid))
            }
            Err(state_overlay_fs::AtomicWriteError::Poisoned(_error)) => {
                Err(OverlayFlushError::Poisoned(VMError::NoritoInvalid))
            }
        }
    }

    fn ensure_persistence_healthy(&self) -> Result<(), VMError> {
        if self
            .persist_target
            .as_ref()
            .is_some_and(RetainedOverlayTarget::is_poisoned)
        {
            Err(VMError::NoritoInvalid)
        } else {
            Ok(())
        }
    }
    fn reload_from_disk(&mut self) -> Result<(), VMError> {
        let Some(target) = &self.persist_target else {
            return Ok(());
        };
        let Some(bytes) = state_overlay_fs::read_bounded(target, STATE_OVERLAY_MAX_FILE_BYTES_V1)
            .map_err(|_| VMError::NoritoInvalid)?
        else {
            return Ok(());
        };
        let (data, usage) = Self::decode_persisted(bytes)?;
        self.data = data;
        self.path_bytes = usage.path_bytes;
        self.value_bytes = usage.value_bytes;
        Ok(())
    }
    fn decode_persisted(
        bytes: Vec<u8>,
    ) -> Result<(BTreeMap<StatePath, Vec<u8>>, OverlayResourceUsage), VMError> {
        preflight_persisted_json(&bytes)?;
        let persisted: BTreeMap<String, String> =
            json::from_slice(&bytes).map_err(|_| VMError::NoritoInvalid)?;
        drop(bytes);
        let mut map = BTreeMap::new();
        let mut usage = OverlayResourceUsage::default();
        for (k, v) in persisted {
            if k.len() > crate::syscalls::STATE_MAX_PATH_BYTES {
                return Err(VMError::NoritoInvalid);
            }
            let path: StatePath = k.parse().map_err(|_| VMError::NoritoInvalid)?;
            let encoded = v.trim();
            if encoded.len() > STATE_OVERLAY_MAX_BASE64_VALUE_BYTES_V1 {
                return Err(VMError::NoritoInvalid);
            }
            let decoded = B64_STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| VMError::NoritoInvalid)?;
            Self::validate_entry(&path, &decoded)?;
            usage.path_bytes = usage
                .path_bytes
                .checked_add(path.as_ref().len())
                .ok_or(VMError::NoritoInvalid)?;
            usage.value_bytes = usage
                .value_bytes
                .checked_add(decoded.len())
                .ok_or(VMError::NoritoInvalid)?;
            Self::ensure_resource_limits(
                map.len().saturating_add(1),
                usage.path_bytes,
                usage.value_bytes,
            )?;
            if map.insert(path, decoded).is_some() {
                return Err(VMError::NoritoInvalid);
            }
        }
        Ok((map, usage))
    }
}
fn persisted_json_encoded_len(data: &BTreeMap<StatePath, Vec<u8>>) -> Result<usize, VMError> {
    let mut bytes = 2usize;
    for (index, (path, value)) in data.iter().enumerate() {
        if index != 0 {
            bytes = bytes.checked_add(1).ok_or(VMError::NoritoInvalid)?;
        }
        bytes = bytes
            .checked_add(json_string_encoded_len(path.as_ref())?)
            .and_then(|total| total.checked_add(1))
            .and_then(|total| total.checked_add(2))
            .ok_or(VMError::NoritoInvalid)?;
        let encoded_value = base64::encoded_len(value.len(), true).ok_or(VMError::NoritoInvalid)?;
        bytes = bytes
            .checked_add(encoded_value)
            .ok_or(VMError::NoritoInvalid)?;
        if bytes > STATE_OVERLAY_MAX_FILE_BYTES_V1 {
            return Err(VMError::NoritoInvalid);
        }
    }
    Ok(bytes)
}
fn json_string_encoded_len(value: &str) -> Result<usize, VMError> {
    value.chars().try_fold(2usize, |bytes, character| {
        let added = match character {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
            character if (character as u32) < 0x20 => 6,
            character => character.len_utf8(),
        };
        bytes.checked_add(added).ok_or(VMError::NoritoInvalid)
    })
}
fn preflight_persisted_json(bytes: &[u8]) -> Result<(), VMError> {
    if bytes.len() > STATE_OVERLAY_MAX_FILE_BYTES_V1 {
        return Err(VMError::NoritoInvalid);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| VMError::NoritoInvalid)?;
    let mut cursor = FlatOverlayJsonCursor::new(text.as_bytes());
    cursor.skip_whitespace();
    cursor.expect(b'{')?;
    cursor.skip_whitespace();
    if cursor.consume(b'}') {
        cursor.skip_whitespace();
        return cursor.finish();
    }
    let mut entries = 0usize;
    loop {
        if entries == STATE_OVERLAY_MAX_ENTRIES_V1 {
            return Err(VMError::NoritoInvalid);
        }
        cursor.scan_string(STATE_OVERLAY_MAX_RAW_JSON_PATH_BYTES_V1)?;
        cursor.skip_whitespace();
        cursor.expect(b':')?;
        cursor.skip_whitespace();
        cursor.scan_string(STATE_OVERLAY_MAX_RAW_JSON_VALUE_BYTES_V1)?;
        entries = entries.saturating_add(1);
        cursor.skip_whitespace();
        if cursor.consume(b'}') {
            cursor.skip_whitespace();
            return cursor.finish();
        }
        cursor.expect(b',')?;
        cursor.skip_whitespace();
    }
}
struct FlatOverlayJsonCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> FlatOverlayJsonCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn skip_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.offset),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.offset = self.offset.saturating_add(1);
        }
    }
    fn consume(&mut self, expected: u8) -> bool {
        if self.bytes.get(self.offset).copied() == Some(expected) {
            self.offset = self.offset.saturating_add(1);
            true
        } else {
            false
        }
    }
    fn expect(&mut self, expected: u8) -> Result<(), VMError> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(VMError::NoritoInvalid)
        }
    }
    fn scan_string(&mut self, maximum_raw_bytes: usize) -> Result<(), VMError> {
        self.expect(b'"')?;
        let start = self.offset;
        let mut escaped = false;
        while let Some(&byte) = self.bytes.get(self.offset) {
            if self.offset.saturating_sub(start) > maximum_raw_bytes {
                return Err(VMError::NoritoInvalid);
            }
            self.offset = self.offset.saturating_add(1);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return Ok(());
            }
        }
        Err(VMError::NoritoInvalid)
    }
    fn finish(&self) -> Result<(), VMError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(VMError::NoritoInvalid)
        }
    }
}
impl DurableStateSnapshot {
    #[must_use]
    pub fn new(data: BTreeMap<StatePath, Vec<u8>>) -> Self {
        Self { data }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io};
    fn path(value: &str) -> StatePath {
        value.parse().expect("canonical state path")
    }
    fn temporary_directory(label: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        std::env::temp_dir().join(format!(
            "ivm_state_overlay_{label}_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        ))
    }
    #[cfg(unix)]
    #[test]
    fn atomic_flush_rejects_replaced_symlink_without_writing_its_target() {
        use std::os::unix::fs::symlink;
        let directory = temporary_directory("symlink_swap");
        fs::create_dir_all(&directory).expect("create temporary directory");
        let overlay_path = directory.join("state.json");
        let victim_path = directory.join("victim.json");
        let mut overlay = DurableStateOverlay::with_persist_path(overlay_path.clone())
            .expect("create persisted overlay");
        overlay
            .set(&path("seed"), b"one".to_vec())
            .expect("seed persisted overlay");
        fs::write(&victim_path, b"do not replace").expect("write victim fixture");
        fs::remove_file(&overlay_path).expect("remove overlay leaf");
        symlink(&victim_path, &overlay_path).expect("replace leaf with symlink");

        assert!(matches!(
            overlay.set(&path("second"), b"two".to_vec()),
            Err(VMError::NoritoInvalid)
        ));
        assert_eq!(fs::read(&victim_path).unwrap(), b"do not replace");
        assert!(overlay.get_ref(&path("second")).is_none());
        fs::remove_dir_all(directory).expect("remove temporary directory");
    }
    #[test]
    fn retained_parent_rebinding_cannot_redirect_reads_or_writes() {
        let root = temporary_directory("retained_parent_rebinding");
        let configured_parent = root.join("configured");
        let replacement_parent = root.join("replacement");
        let retained_parent = root.join("retained");
        fs::create_dir_all(&root).expect("create retained ancestor");
        fs::create_dir_all(&replacement_parent).expect("create replacement parent");
        let configured_path = configured_parent.join("state.json");
        let replacement_path = replacement_parent.join("state.json");
        let mut overlay = DurableStateOverlay::with_persist_path(configured_path.clone())
            .expect("retain existing overlay ancestor");
        assert!(!configured_parent.exists());
        overlay
            .set(&path("seed"), b"one".to_vec())
            .expect("create and retain configured overlay parent");
        let retained_reader = overlay
            .persist_target
            .as_ref()
            .expect("overlay has retained target")
            .clone();
        fs::write(&replacement_path, br#"{"replacement":"YmFk"}"#)
            .expect("write replacement sentinel");

        fs::rename(&configured_parent, &retained_parent).expect("move configured parent aside");
        fs::rename(&replacement_parent, &configured_parent).expect("rebind configured pathname");

        let retained_bytes =
            state_overlay_fs::read_bounded(&retained_reader, STATE_OVERLAY_MAX_FILE_BYTES_V1)
                .expect("read through cloned retained parent")
                .expect("retained state exists");
        assert_eq!(
            retained_bytes,
            fs::read(retained_parent.join("state.json")).unwrap()
        );
        assert_ne!(retained_bytes, fs::read(&configured_path).unwrap());

        overlay
            .set(&path("second"), b"two".to_vec())
            .expect("publish through retained parent");
        assert_eq!(
            fs::read(&configured_path).unwrap(),
            br#"{"replacement":"YmFk"}"#
        );
        let reloaded = DurableStateOverlay::with_persist_path(retained_parent.join("state.json"))
            .expect("reload retained state");
        assert_eq!(reloaded.get_ref(&path("seed")), Some(b"one".as_slice()));
        assert_eq!(reloaded.get_ref(&path("second")), Some(b"two".as_slice()));
        drop((overlay, reloaded, retained_reader));
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[cfg(unix)]
    #[test]
    fn persisted_overlay_rejects_symlinked_ancestor() {
        use std::os::unix::fs::symlink;
        let root = temporary_directory("symlinked_ancestor");
        let external = root.join("external");
        let alias = root.join("alias");
        fs::create_dir_all(&external).expect("create external directory");
        symlink(&external, &alias).expect("create ancestor symlink");

        assert!(matches!(
            DurableStateOverlay::with_persist_path(alias.join("nested/state.json")),
            Err(VMError::NoritoInvalid)
        ));
        assert!(!external.join("nested").exists());
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[cfg(unix)]
    #[test]
    fn persisted_overlay_rejects_symlink_inserted_before_first_flush() {
        use std::{os::unix::fs::PermissionsExt as _, os::unix::fs::symlink};
        let root = temporary_directory("lazy_symlinked_ancestor");
        let external = root.join("external");
        fs::create_dir_all(&external).expect("create retained and external directories");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("make retained ancestor private");
        let pending = root.join("pending");
        let mut overlay = DurableStateOverlay::with_persist_path(pending.join("nested/state.json"))
            .expect("retain nearest existing ancestor");
        let mut clone = overlay.clone();
        symlink(&external, &pending).expect("insert pending ancestor symlink");

        assert!(matches!(
            overlay.set(&path("seed"), b"one".to_vec()),
            Err(VMError::NoritoInvalid)
        ));
        assert!(matches!(
            clone.set(&path("seed"), b"one".to_vec()),
            Err(VMError::NoritoInvalid)
        ));
        assert!(!external.join("nested").exists());
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[cfg(unix)]
    #[test]
    fn persisted_overlay_rejects_writable_final_parent() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = temporary_directory("writable_final_parent");
        fs::create_dir_all(&root).expect("create writable final parent");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777))
            .expect("make final parent attacker-writable");

        assert!(matches!(
            DurableStateOverlay::with_persist_path(root.join("state.json")),
            Err(VMError::NoritoInvalid)
        ));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("restore private permissions for cleanup");
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[cfg(unix)]
    #[test]
    fn persisted_overlay_rejects_writable_leaf() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = temporary_directory("writable_leaf");
        fs::create_dir_all(&root).expect("create private final parent");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("make final parent traversable but not writable");
        let overlay_path = root.join("state.json");
        fs::write(&overlay_path, br#"{"seed":"b25l"}"#).expect("write valid overlay JSON");
        fs::set_permissions(&overlay_path, fs::Permissions::from_mode(0o666))
            .expect("make overlay leaf attacker-writable");

        assert!(matches!(
            DurableStateOverlay::with_persist_path(overlay_path),
            Err(VMError::NoritoInvalid)
        ));
        fs::set_permissions(root.join("state.json"), fs::Permissions::from_mode(0o600))
            .expect("restore private leaf permissions for cleanup");
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[cfg(unix)]
    #[test]
    fn persisted_overlay_rejects_writable_pending_ancestor() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = temporary_directory("writable_pending_ancestor");
        fs::create_dir_all(&root).expect("create retained ancestor");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("make retained ancestor private");
        let pending = root.join("pending");
        let mut overlay = DurableStateOverlay::with_persist_path(pending.join("nested/state.json"))
            .expect("retain nearest existing ancestor");
        fs::create_dir(&pending).expect("substitute pending ancestor");
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o777))
            .expect("make pending ancestor attacker-writable");

        assert!(matches!(
            overlay.set(&path("seed"), b"one".to_vec()),
            Err(VMError::NoritoInvalid)
        ));
        assert!(!pending.join("nested").exists());
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o700))
            .expect("restore private permissions for cleanup");
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[cfg(unix)]
    #[test]
    fn persisted_overlay_rejects_rebound_unsafe_creation_parent() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = temporary_directory("unsafe_creation_parent");
        fs::create_dir_all(&root).expect("create retained ancestor");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("start with a private lookup parent");
        let pending = root.join("pending");
        let mut overlay = DurableStateOverlay::with_persist_path(pending.join("state.json"))
            .expect("retain safe existing ancestor");
        let victim = root.join("victim");
        fs::create_dir(&victim).expect("create victim-owned private directory");
        fs::write(victim.join("state.json"), b"do not replace").expect("write victim sentinel");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777))
            .expect("make retained creation parent non-sticky and writable");
        fs::rename(&victim, &pending).expect("substitute victim directory into pending name");

        assert!(matches!(
            overlay.set(&path("seed"), b"one".to_vec()),
            Err(VMError::NoritoInvalid)
        ));
        assert_eq!(
            fs::read(pending.join("state.json")).unwrap(),
            b"do not replace"
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("restore private permissions for cleanup");
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[cfg(unix)]
    #[test]
    fn persisted_overlay_allows_sticky_lookup_parent() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = temporary_directory("sticky_lookup_parent");
        fs::create_dir_all(&root).expect("create sticky lookup parent");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o1777))
            .expect("make lookup parent sticky");
        let overlay_path = root.join("private/state.json");
        let mut overlay = DurableStateOverlay::with_persist_path(overlay_path.clone())
            .expect("retain sticky lookup parent");

        overlay
            .set(&path("seed"), b"one".to_vec())
            .expect("create private child below sticky lookup parent");
        assert!(overlay_path.is_file());
        drop(overlay);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("restore private permissions for cleanup");
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[test]
    fn persisted_overlay_defers_missing_parent_creation_until_flush() {
        let root = temporary_directory("lazy_parent_creation");
        fs::create_dir_all(&root).expect("create retained ancestor");
        let missing_parent = root.join("missing/nested");
        let mut overlay = DurableStateOverlay::with_persist_path(missing_parent.join("state.json"))
            .expect("retain nearest existing ancestor");
        assert!(!missing_parent.exists());

        overlay
            .set(&path("seed"), b"one".to_vec())
            .expect("create and publish below retained ancestor");
        assert!(missing_parent.join("state.json").is_file());
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[cfg(unix)]
    #[test]
    fn persisted_overlay_supports_long_valid_leaf_names() {
        let root = temporary_directory("long_leaf");
        fs::create_dir_all(&root).expect("create final parent");
        let overlay_path = root.join("s".repeat(240));
        let mut overlay = DurableStateOverlay::with_persist_path(overlay_path.clone())
            .expect("retain overlay with long valid leaf");

        overlay
            .set(&path("seed"), b"one".to_vec())
            .expect("publish without expanding the temporary leaf name");
        assert!(overlay_path.is_file());
        drop(overlay);
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[test]
    fn post_publication_sync_failure_keeps_state_and_poison_is_shared() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;
        let root = temporary_directory("post_publication_sync_failure");
        fs::create_dir_all(&root).expect("create private final parent");
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("make final parent private");
        let overlay_path = root.join("state.json");
        let mut overlay = DurableStateOverlay::with_persist_path(overlay_path.clone())
            .expect("create persisted overlay");
        overlay
            .set(&path("seed"), b"one".to_vec())
            .expect("seed persisted overlay");
        let seed_snapshot = overlay.checkpoint();
        let poisoned_clone = overlay.clone();
        overlay
            .persist_target
            .as_ref()
            .expect("overlay has persistence target")
            .fail_next_publication_sync();

        assert!(matches!(
            overlay.set(&path("second"), b"two".to_vec()),
            Err(VMError::NoritoInvalid)
        ));
        assert_eq!(overlay.get_ref(&path("second")), Some(b"two".as_slice()));
        assert!(matches!(overlay.flush(), Err(VMError::NoritoInvalid)));
        assert!(matches!(
            poisoned_clone.flush(),
            Err(VMError::NoritoInvalid)
        ));
        assert!(matches!(
            overlay.set(&path("third"), b"three".to_vec()),
            Err(VMError::NoritoInvalid)
        ));
        assert!(overlay.get_ref(&path("third")).is_none());
        assert!(matches!(
            overlay.restore(&seed_snapshot),
            Err(VMError::NoritoInvalid)
        ));
        assert_eq!(overlay.get_ref(&path("second")), Some(b"two".as_slice()));

        let reloaded = DurableStateOverlay::with_persist_path(overlay_path)
            .expect("published image remains readable through a fresh target");
        assert_eq!(reloaded.get_ref(&path("seed")), Some(b"one".as_slice()));
        assert_eq!(reloaded.get_ref(&path("second")), Some(b"two".as_slice()));
        drop((overlay, poisoned_clone, reloaded));
        fs::remove_dir_all(root).expect("remove temporary directory");
    }
    #[test]
    fn atomic_flush_rejects_replaced_hard_link_without_writing_its_alias() {
        let directory = temporary_directory("hard_link_swap");
        fs::create_dir_all(&directory).expect("create temporary directory");
        let overlay_path = directory.join("state.json");
        let victim_path = directory.join("victim.json");
        let mut overlay = DurableStateOverlay::with_persist_path(overlay_path.clone())
            .expect("create persisted overlay");
        overlay
            .set(&path("seed"), b"one".to_vec())
            .expect("seed persisted overlay");
        fs::write(&victim_path, b"do not replace").expect("write victim fixture");
        fs::remove_file(&overlay_path).expect("remove overlay leaf");
        fs::hard_link(&victim_path, &overlay_path).expect("replace leaf with hard link");

        assert!(matches!(
            overlay.set(&path("second"), b"two".to_vec()),
            Err(VMError::NoritoInvalid)
        ));
        assert_eq!(fs::read(&victim_path).unwrap(), b"do not replace");
        assert!(overlay.get_ref(&path("second")).is_none());
        fs::remove_dir_all(directory).expect("remove temporary directory");
    }
    #[test]
    fn atomic_flush_rejects_replaced_directory_without_blocking() {
        let directory = temporary_directory("directory_swap");
        fs::create_dir_all(&directory).expect("create temporary directory");
        let overlay_path = directory.join("state.json");
        let mut overlay = DurableStateOverlay::with_persist_path(overlay_path.clone())
            .expect("create persisted overlay");
        overlay
            .set(&path("seed"), b"one".to_vec())
            .expect("seed persisted overlay");
        fs::remove_file(&overlay_path).expect("remove overlay leaf");
        fs::create_dir(&overlay_path).expect("replace leaf with directory");

        assert!(matches!(
            overlay.set(&path("second"), b"two".to_vec()),
            Err(VMError::NoritoInvalid)
        ));
        assert!(overlay_path.is_dir());
        assert!(overlay.get_ref(&path("second")).is_none());
        fs::remove_dir_all(directory).expect("remove temporary directory");
    }
    #[test]
    fn raw_payload_ingress_enforces_value_bound() {
        let mut overlay = DurableStateOverlay::in_memory();
        let maximum = vec![0xabu8; crate::syscalls::STATE_MAX_VALUE_BYTES];
        let bounded = path("bounded");
        overlay
            .set(&bounded, maximum.clone())
            .expect("maximum raw payload must fit");
        assert_eq!(
            overlay
                .value_payload_ref(&bounded)
                .expect("valid overlay")
                .expect("stored payload"),
            maximum
        );
        let oversized = vec![0xcdu8; crate::syscalls::STATE_MAX_VALUE_BYTES + 1];
        let oversized_path = path("oversized");
        assert!(matches!(
            overlay.set(&oversized_path, oversized),
            Err(VMError::NoritoInvalid)
        ));
        assert!(overlay.get_ref(&oversized_path).is_none());
    }
    #[test]
    fn restore_validates_all_entries_before_replacing_state() {
        let mut overlay = DurableStateOverlay::in_memory();
        let existing = path("existing");
        overlay
            .set(&existing, b"kept".to_vec())
            .expect("seed overlay");
        let snapshot = DurableStateSnapshot::new(BTreeMap::from([
            (path("valid"), b"value".to_vec()),
            (
                path("oversized"),
                vec![0u8; crate::syscalls::STATE_MAX_VALUE_BYTES + 1],
            ),
        ]));
        assert!(matches!(
            overlay.restore(&snapshot),
            Err(VMError::NoritoInvalid)
        ));
        assert_eq!(overlay.get_ref(&existing), Some(b"kept".as_slice()));
        assert!(overlay.get_ref(&path("valid")).is_none());
    }
    #[test]
    fn text_prefix_iterator_starts_at_the_ordered_lower_bound() {
        let mut overlay = DurableStateOverlay::in_memory();
        for path in ["accounts/1", "orders/1", "orders/2", "payments/1"] {
            overlay
                .set(&path.parse().expect("canonical state path"), Vec::new())
                .expect("insert bounded entry");
        }
        assert_eq!(
            overlay
                .keys_with_text_prefix("orders")
                .map(AsRef::<str>::as_ref)
                .collect::<Vec<_>>(),
            vec!["orders/1", "orders/2"]
        );
    }
    #[test]
    fn persisted_overlay_rejects_canonically_duplicate_state_paths() {
        let duplicate = r#"{"root/e\u0301":"AQ==","root/é":"Ag=="}"#;
        assert!(matches!(
            DurableStateOverlay::decode_persisted(duplicate.as_bytes().to_vec()),
            Err(VMError::NoritoInvalid)
        ));
    }
    #[test]
    fn aggregate_limits_accept_boundaries_and_reject_first_overflow() {
        assert!(matches!(
            DurableStateOverlay::ensure_resource_limits(
                STATE_OVERLAY_MAX_ENTRIES_V1,
                STATE_OVERLAY_MAX_PATH_BYTES_V1,
                STATE_OVERLAY_MAX_VALUE_BYTES_V1,
            ),
            Ok(())
        ));
        for overflow in [
            (
                STATE_OVERLAY_MAX_ENTRIES_V1 + 1,
                STATE_OVERLAY_MAX_PATH_BYTES_V1,
                STATE_OVERLAY_MAX_VALUE_BYTES_V1,
            ),
            (
                STATE_OVERLAY_MAX_ENTRIES_V1,
                STATE_OVERLAY_MAX_PATH_BYTES_V1 + 1,
                STATE_OVERLAY_MAX_VALUE_BYTES_V1,
            ),
            (
                STATE_OVERLAY_MAX_ENTRIES_V1,
                STATE_OVERLAY_MAX_PATH_BYTES_V1,
                STATE_OVERLAY_MAX_VALUE_BYTES_V1 + 1,
            ),
        ] {
            assert!(matches!(
                DurableStateOverlay::ensure_resource_limits(overflow.0, overflow.1, overflow.2),
                Err(VMError::NoritoInvalid)
            ));
        }
    }
    #[test]
    fn aggregate_value_overflow_is_rejected_before_mutation() {
        let mut overlay = DurableStateOverlay::in_memory();
        let full_values = STATE_OVERLAY_MAX_VALUE_BYTES_V1 / crate::syscalls::STATE_MAX_VALUE_BYTES;
        assert_eq!(
            full_values * crate::syscalls::STATE_MAX_VALUE_BYTES,
            STATE_OVERLAY_MAX_VALUE_BYTES_V1
        );
        for index in 0..full_values {
            overlay
                .set(
                    &path(&format!("bounded/{index}")),
                    vec![0xa5; crate::syscalls::STATE_MAX_VALUE_BYTES],
                )
                .expect("aggregate boundary must fit");
        }
        let overflow = path("bounded/overflow");
        assert!(matches!(
            overlay.set(&overflow, vec![0x5a]),
            Err(VMError::NoritoInvalid)
        ));
        assert!(overlay.get_ref(&overflow).is_none());
        assert_eq!(overlay.value_bytes, STATE_OVERLAY_MAX_VALUE_BYTES_V1);
    }
    #[test]
    fn persisted_json_rejects_entry_count_before_typed_decode() {
        let mut encoded = String::from("{");
        for index in 0..=STATE_OVERLAY_MAX_ENTRIES_V1 {
            if index != 0 {
                encoded.push(',');
            }
            encoded.push_str(&format!("\"key/{index}\":\"\""));
        }
        encoded.push('}');
        assert!(matches!(
            DurableStateOverlay::decode_persisted(encoded.into_bytes()),
            Err(VMError::NoritoInvalid)
        ));
    }
    #[test]
    fn persisted_reader_rejects_sparse_file_above_limit() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let directory = std::env::temp_dir().join(format!(
            "ivm_state_overlay_bound_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&directory).expect("create temporary directory");
        let file_path = directory.join("state.json");
        let file = fs::File::create(&file_path).expect("create sparse state file");
        file.set_len(
            u64::try_from(STATE_OVERLAY_MAX_FILE_BYTES_V1 + 1).expect("test length fits u64"),
        )
        .expect("extend sparse state file");
        drop(file);
        let target = RetainedOverlayTarget::from_path(&file_path).expect("retain sparse target");
        let error = state_overlay_fs::read_bounded(&target, STATE_OVERLAY_MAX_FILE_BYTES_V1)
            .expect_err("oversize must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(directory).expect("remove temporary directory");
    }
    #[cfg(windows)]
    #[test]
    fn windows_handle_snapshot_distinguishes_equal_files() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let directory = std::env::temp_dir().join(format!(
            "ivm_state_overlay_windows_identity_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&directory).expect("create temporary directory");
        let first_path = directory.join("first.json");
        let second_path = directory.join("second.json");
        fs::write(&first_path, b"same bytes").expect("write first fixture");
        fs::write(&second_path, b"same bytes").expect("write second fixture");
        assert!(state_overlay_fs::windows_test_same_identity(&first_path, &first_path).unwrap());
        assert!(!state_overlay_fs::windows_test_same_identity(&first_path, &second_path).unwrap());
        fs::remove_dir_all(directory).expect("remove temporary directory");
    }
    #[cfg(windows)]
    #[test]
    fn windows_persisted_reader_rejects_directory_as_invalid_data() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let directory = std::env::temp_dir().join(format!(
            "ivm_state_overlay_windows_directory_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&directory).expect("create temporary directory");
        let target = RetainedOverlayTarget::from_path(&directory).expect("retain directory target");
        state_overlay_fs::read_bounded(&target, STATE_OVERLAY_MAX_FILE_BYTES_V1)
            .expect_err("state overlay directory must fail closed");
        fs::remove_dir_all(directory).expect("remove temporary directory");
    }
}
