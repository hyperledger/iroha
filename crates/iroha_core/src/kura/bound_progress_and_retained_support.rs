impl BoundProgressNamespace {
    /// Return the descriptor-bound parent path as canonical UTF-8 components
    /// relative to the Kura root. The identity survives relocation of the
    /// entire Kura root while distinguishing same-named pairs in sibling lane
    /// directories.
    fn stable_relative_components(
        &self,
        data_path: &Path,
        index_path: &Path,
    ) -> std::result::Result<Vec<String>, &'static str> {
        if self.data_path != data_path || self.index_path != index_path {
            return Err("bound progress namespace names a different main pair");
        }
        let parent = data_path
            .parent()
            .ok_or("bound progress data path has no parent")?;
        if index_path.parent() != Some(parent) {
            return Err("bound progress main files do not share one parent");
        }
        let mut directories = self.directories.iter().rev();
        let root = directories
            .next()
            .ok_or("bound progress directory chain is empty")?;
        if root.entry_name.is_some() {
            return Err("bound progress root unexpectedly has a relative name");
        }
        let mut reconstructed = root.expected_path.clone();
        let mut components = Vec::with_capacity(self.directories.len().saturating_sub(1));
        for directory in directories {
            let name = directory
                .entry_name
                .as_deref()
                .ok_or("bound progress child directory has no relative name")?;
            let mut path_components = Path::new(name).components();
            if !matches!(
                path_components.next(),
                Some(std::path::Component::Normal(component)) if component == name
            ) || path_components.next().is_some()
            {
                return Err("bound progress relative directory name is not canonical");
            }
            let name = name
                .to_str()
                .ok_or("bound progress relative directory name is not UTF-8")?;
            reconstructed.push(name);
            if reconstructed != directory.expected_path {
                return Err("bound progress directory chain is not contiguous");
            }
            components.push(name.to_owned());
        }
        if reconstructed != parent {
            return Err("bound progress directory chain ends at the wrong parent");
        }
        Ok(components)
    }
}
#[derive(Debug)]
struct BoundProgressSidecar {
    namespace: BoundProgressNamespace,
    data: std::fs::File,
    index: std::fs::File,
    data_metadata: StableSidecarMetadata,
    index_metadata: StableSidecarMetadata,
}
#[derive(Debug)]
enum BoundProgressPair {
    Absent(BoundProgressNamespace),
    Present(BoundProgressSidecar),
}
#[derive(Debug)]
struct BoundProgressPromotionError {
    published: bool,
    source: std::io::Error,
}
/// Stable classification for a failed bound progress-sidecar recovery pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundProgressRecoveryFailure {
    /// The on-disk protocol state remains structurally recoverable, but an I/O
    /// or durability operation did not complete.
    RetryableIo,
    /// The namespace or protocol state is hostile, malformed, or ambiguous.
    InvalidData,
}
impl BoundProgressRecoveryFailure {
    fn from_io(error: &std::io::Error) -> Self {
        match error.kind() {
            ErrorKind::InvalidData
            | ErrorKind::InvalidInput
            | ErrorKind::NotFound
            | ErrorKind::AlreadyExists
            | ErrorKind::PermissionDenied
            | ErrorKind::UnexpectedEof => Self::InvalidData,
            _ => Self::RetryableIo,
        }
    }
    fn from_kura(error: &Error) -> Self {
        match error {
            Error::IO(source, _) | Error::MkDir(source, _) => Self::from_io(source),
            _ => Self::InvalidData,
        }
    }
}
#[derive(Debug)]
struct BoundSidecarIndexSnapshot {
    layout: SidecarIndexLayout,
    entries: Vec<SidecarIndexEntry>,
    indexed_end: u64,
}
/// Durable undo/redo record for one bounded progress-sidecar mutation.
///
/// The record is published before either main file is mutated. Its index byte
/// windows cover either a bounded sparse append/replacement or both complete
/// bounded index images for a prepend. Its structured parent
/// identity is relative to the authenticated Kura root: root relocation stays
/// valid, but same-basename sibling namespaces cannot exchange intents.
/// This is the first-release V1 layout; pre-release development markers that
/// omitted the relative identity intentionally fail closed instead of using a
/// legacy decoding fallback.
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_core::kura::BoundProgressAppendIntentV1")]
struct BoundProgressAppendIntentV1 {
    version: u16,
    namespace_components: Vec<String>,
    data_file: String,
    index_file: String,
    height: u64,
    pair_was_present: bool,
    old_data_len: u64,
    new_data_len: u64,
    payload_hash: Hash,
    old_index_len: u64,
    new_index_len: u64,
    index_write_offset: u64,
    old_index_bytes: Vec<u8>,
    new_index_bytes: Vec<u8>,
    integrity_hash: Hash,
}
impl BoundProgressAppendIntentV1 {
    fn is_prepend(&self) -> bool {
        self.index_write_offset == 0
            && self.old_index_len != 0
            && self.old_index_bytes.len() as u64 == self.old_index_len
            && self.new_index_len > self.old_index_len
    }
    fn encoded_byte_limit(&self) -> usize {
        if self.is_prepend() {
            BOUND_PROGRESS_APPEND_INTENT_DECODE_MAX_BYTES
        } else {
            BOUND_PROGRESS_APPEND_INTENT_MAX_BYTES
        }
    }
    /// Bound both images before reading or allocating a full prepend window.
    fn prepend_layout(
        old: SidecarIndexLayout,
        height: u64,
    ) -> std::result::Result<SidecarIndexLayout, &'static str> {
        let gap = old
            .base_height
            .checked_sub(height)
            .filter(|gap| *gap > 0 && *gap <= MAX_INDEXED_SIDECAR_GAP_ENTRIES)
            .ok_or("bound prepend gap is outside its hard limit")?;
        let count = old
            .entry_count
            .checked_add(gap)
            .filter(|count| *count <= MAX_BOUND_PROGRESS_INDEX_ENTRIES as u64)
            .ok_or("bound prepend complete index exceeds its hard entry limit")?;
        if old.aligned_len > BOUND_PROGRESS_PREPEND_INDEX_MAX_BYTES as u64 {
            return Err("bound prepend old index exceeds its hard byte limit");
        }
        let len = count
            .checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64)
            .and_then(|len| len.checked_add(INDEXED_SIDECAR_BASE_HEADER_SIZE_U64))
            .ok_or("bound prepend index length overflows")?;
        SidecarIndexLayout::based(height, len)
    }
    /// Count the canonical frame for bounded old/new windows. This is sizing
    /// data only: no integrity seal or write authority is produced. Canonical
    /// framing is uncompressed and byte-vector contents do not affect its size.
    fn prepend_encoded_len(
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        height: u64,
        old: SidecarIndexLayout,
        old_data_len: u64,
        payload_len: u64,
    ) -> std::result::Result<usize, &'static str> {
        let new = Self::prepend_layout(old, height)?;
        let bounded_zeros = |len: u64| {
            let len = usize::try_from(len).map_err(|_| "prepend sizing window overflows")?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(len)
                .map_err(|_| "cannot allocate bounded prepend sizing window")?;
            bytes.resize(len, 0);
            Ok::<_, &'static str>(bytes)
        };
        let shape = Self {
            version: BOUND_PROGRESS_APPEND_INTENT_VERSION,
            namespace_components: namespace.stable_relative_components(data_path, index_path)?,
            data_file: data_path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .ok_or("prepend sizing data name is invalid")?
                .to_owned(),
            index_file: index_path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .ok_or("prepend sizing index name is invalid")?
                .to_owned(),
            height,
            pair_was_present: true,
            old_data_len,
            new_data_len: old_data_len
                .checked_add(payload_len)
                .ok_or("prepend sizing data length overflows")?,
            payload_hash: Hash::prehashed([0; Hash::LENGTH]),
            old_index_len: old.aligned_len,
            new_index_len: new.aligned_len,
            index_write_offset: 0,
            old_index_bytes: bounded_zeros(old.aligned_len)?,
            new_index_bytes: bounded_zeros(new.aligned_len)?,
            integrity_hash: Hash::prehashed([0; Hash::LENGTH]),
        };
        let len = norito::canonical_frame_len(&shape)
            .map_err(|_| "cannot count canonical prepend intent frame")?;
        if len > BOUND_PROGRESS_APPEND_INTENT_DECODE_MAX_BYTES {
            return Err("prepend sizing frame exceeds its hard byte limit");
        }
        Ok(len)
    }
    fn for_prepend(
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        height: u64,
        old_data_len: u64,
        payload: &[u8],
        index: &mut std::fs::File,
    ) -> std::result::Result<Self, &'static str> {
        let old_index_len = index
            .metadata()
            .map_err(|_| "cannot stat bound prepend index")?
            .len();
        let old = SidecarIndexLayout::read_from(index, old_index_len)?;
        if old.aligned_len != old_index_len {
            return Err("bound prepend old index has a partial trailing entry");
        }
        let new = Self::prepend_layout(old, height)?;
        let mut old_index_bytes = Vec::new();
        old_index_bytes
            .try_reserve_exact(old_index_len as usize)
            .map_err(|_| "cannot allocate bounded prepend old window")?;
        old_index_bytes.resize(old_index_len as usize, 0);
        index
            .seek(SeekFrom::Start(0))
            .and_then(|_| index.read_exact(&mut old_index_bytes))
            .map_err(|_| "cannot read bound prepend old window")?;
        let mut new_index_bytes = Vec::new();
        new_index_bytes
            .try_reserve_exact(new.aligned_len as usize)
            .map_err(|_| "cannot allocate bounded prepend new window")?;
        new_index_bytes.extend_from_slice(&SidecarIndexLayout::base_header(height));
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| "bound prepend payload is oversized")?;
        new_index_bytes.extend_from_slice(
            &SidecarIndexEntry {
                offset: old_data_len,
                len: payload_len,
            }
            .to_bytes(),
        );
        let prefix_len =
            new.entries_offset + (old.base_height - height) * PIPELINE_INDEX_ENTRY_SIZE_U64;
        new_index_bytes.resize(prefix_len as usize, 0);
        new_index_bytes.extend_from_slice(&old_index_bytes[old.entries_offset as usize..]);
        let intent = Self {
            version: BOUND_PROGRESS_APPEND_INTENT_VERSION,
            namespace_components: namespace.stable_relative_components(data_path, index_path)?,
            data_file: data_path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .ok_or("bound prepend data name is invalid")?
                .to_owned(),
            index_file: index_path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .ok_or("bound prepend index name is invalid")?
                .to_owned(),
            height,
            pair_was_present: true,
            old_data_len,
            new_data_len: old_data_len
                .checked_add(payload_len)
                .ok_or("bound prepend data length overflows")?,
            payload_hash: Self::payload_digest(payload),
            old_index_len,
            new_index_len: new.aligned_len,
            index_write_offset: 0,
            old_index_bytes,
            new_index_bytes,
            integrity_hash: Hash::prehashed([0; Hash::LENGTH]),
        }
        .seal();
        intent.validate_for(namespace, data_path, index_path)?;
        intent.validate_against_old_layout(Some(old))?;
        Ok(intent)
    }
    /// Prepend recovery reads its old header from the durable preimage, because
    /// the main header may already be partly or completely replaced.
    fn prepend_old_layout(&self) -> std::result::Result<SidecarIndexLayout, &'static str> {
        if !self.is_prepend() {
            return Err("append intent is not a prepend");
        }
        SidecarIndexLayout::read_from(
            &mut std::io::Cursor::new(&self.old_index_bytes),
            self.old_index_len,
        )
    }
    fn payload_digest(payload: &[u8]) -> Hash {
        Hash::new_from_chunks(&[BOUND_PROGRESS_APPEND_DIGEST_DOMAIN, payload])
    }
    fn payload_len(&self) -> Option<u64> {
        self.new_data_len.checked_sub(self.old_data_len)
    }
    fn computed_integrity_hash(&self) -> Option<Hash> {
        let mut canonical = self.clone();
        canonical.integrity_hash = Hash::prehashed([0; Hash::LENGTH]);
        norito::encode_canonical(&canonical).ok().map(|bytes| {
            Hash::new_from_chunks(&[BOUND_PROGRESS_APPEND_INTENT_DIGEST_DOMAIN, &bytes])
        })
    }
    fn seal(mut self) -> Self {
        self.integrity_hash = self
            .computed_integrity_hash()
            .expect("fixed progress append intent must encode");
        self
    }
    fn validate_for(
        &self,
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
    ) -> std::result::Result<(), &'static str> {
        if self.version != BOUND_PROGRESS_APPEND_INTENT_VERSION {
            return Err("unsupported bound progress append intent version");
        }
        let expected_namespace = namespace.stable_relative_components(data_path, index_path)?;
        if self.namespace_components != expected_namespace {
            return Err("bound progress append intent names the wrong relative namespace");
        }
        if data_path.file_name().and_then(std::ffi::OsStr::to_str) != Some(self.data_file.as_str())
            || index_path.file_name().and_then(std::ffi::OsStr::to_str)
                != Some(self.index_file.as_str())
        {
            return Err("bound progress append intent names the wrong main pair");
        }
        if self.height == 0 || self.height == u64::MAX {
            return Err("bound progress append intent height is invalid");
        }
        let payload_len = self
            .payload_len()
            .ok_or("bound progress append intent data length regresses")?;
        if payload_len == 0 || payload_len > STRICT_INIT_MAX_BLOCK_BYTES {
            return Err("bound progress append intent payload length is invalid");
        }
        if !self.pair_was_present
            && (self.old_data_len != 0
                || self.old_index_len != 0
                || !self.old_index_bytes.is_empty())
        {
            return Err("absent bound progress pair has a non-empty preimage");
        }
        if self.old_index_len % PIPELINE_INDEX_ENTRY_SIZE_U64 != 0
            || self.new_index_len % PIPELINE_INDEX_ENTRY_SIZE_U64 != 0
            || self.index_write_offset % PIPELINE_INDEX_ENTRY_SIZE_U64 != 0
        {
            return Err("bound progress append intent index lengths are misaligned");
        }
        let old_bytes_len = u64::try_from(self.old_index_bytes.len())
            .map_err(|_| "bound progress append old index window is too large")?;
        let new_bytes_len = u64::try_from(self.new_index_bytes.len())
            .map_err(|_| "bound progress append new index window is too large")?;
        let max_index_window = INDEXED_SIDECAR_BASE_HEADER_SIZE_U64
            + (MAX_INDEXED_SIDECAR_GAP_ENTRIES + 1) * PIPELINE_INDEX_ENTRY_SIZE_U64;
        let prepend = self.is_prepend();
        let window_limit = if prepend {
            BOUND_PROGRESS_PREPEND_INDEX_MAX_BYTES as u64
        } else {
            max_index_window
        };
        if old_bytes_len > window_limit || new_bytes_len == 0 || new_bytes_len > window_limit {
            return Err("bound progress append new index window exceeds its hard limit");
        }
        if prepend {
            if !self.pair_was_present || new_bytes_len != self.new_index_len {
                return Err("bound progress prepend has incomplete index windows");
            }
            self.validate_against_old_layout(Some(self.prepend_old_layout()?))?;
        } else if self.index_write_offset == self.old_index_len {
            if old_bytes_len != 0
                || self
                    .old_index_len
                    .checked_add(new_bytes_len)
                    .is_none_or(|end| end != self.new_index_len)
            {
                return Err("bound progress append suffix has inconsistent index lengths");
            }
        } else if old_bytes_len != PIPELINE_INDEX_ENTRY_SIZE_U64
            || new_bytes_len != PIPELINE_INDEX_ENTRY_SIZE_U64
            || self.new_index_len != self.old_index_len
            || self
                .index_write_offset
                .checked_add(PIPELINE_INDEX_ENTRY_SIZE_U64)
                .is_none_or(|end| end > self.old_index_len)
        {
            return Err("bound progress append replacement has an invalid index window");
        }
        if self.computed_integrity_hash() != Some(self.integrity_hash) {
            return Err("bound progress append intent integrity hash is invalid");
        }
        Ok(())
    }
    fn validate_against_old_layout(
        &self,
        old_layout: Option<SidecarIndexLayout>,
    ) -> std::result::Result<(), &'static str> {
        match old_layout {
            Some(layout) if layout.aligned_len == self.old_index_len => {}
            Some(_) => {
                return Err("bound progress append intent names the wrong old index layout");
            }
            None if self.old_index_len == 0 && !self.pair_was_present => {}
            None => return Err("bound progress append intent has no old index layout"),
        }
        if self.is_prepend() {
            let old = old_layout.ok_or("bound prepend lacks its old layout")?;
            let new = Self::prepend_layout(old, self.height)?;
            if self.prepend_old_layout()? != old || new.aligned_len != self.new_index_len {
                return Err("bound prepend does not match its original layout");
            }
            let header = SidecarIndexLayout::base_header(self.height);
            let entry_start = INDEXED_SIDECAR_BASE_HEADER_SIZE;
            let entry_end = entry_start + PIPELINE_INDEX_ENTRY_SIZE;
            let old_start = usize::try_from(
                new.entries_offset
                    + (old.base_height - self.height) * PIPELINE_INDEX_ENTRY_SIZE_U64,
            )
            .map_err(|_| "bound prepend index offset overflows")?;
            let expected_entry = SidecarIndexEntry {
                offset: self.old_data_len,
                len: self
                    .payload_len()
                    .ok_or("bound prepend payload length regresses")?,
            }
            .to_bytes();
            if self.new_index_bytes.get(..entry_start) != Some(header.as_slice())
                || self.new_index_bytes.get(entry_start..entry_end)
                    != Some(expected_entry.as_slice())
                || self
                    .new_index_bytes
                    .get(entry_end..old_start)
                    .is_none_or(|gap| gap.iter().any(|byte| *byte != 0))
                || self.new_index_bytes.get(old_start..)
                    != self.old_index_bytes.get(old.entries_offset as usize..)
            {
                return Err("bound prepend changed its target, hole, or retained suffix");
            }
            return Ok(());
        }
        let payload_len = self
            .payload_len()
            .ok_or("bound progress append intent data length regresses")?;
        let expected_entry = SidecarIndexEntry {
            offset: self.old_data_len,
            len: payload_len,
        };
        let Some(encoded_entry) = self.new_index_bytes.get(
            self.new_index_bytes
                .len()
                .saturating_sub(PIPELINE_INDEX_ENTRY_SIZE)..,
        ) else {
            return Err("bound progress append intent has no target index entry");
        };
        let encoded_entry: [u8; PIPELINE_INDEX_ENTRY_SIZE] = encoded_entry
            .try_into()
            .map_err(|_| "bound progress append intent target entry has the wrong size")?;
        if SidecarIndexEntry::from_bytes(encoded_entry) != expected_entry {
            return Err("bound progress append intent target entry is inconsistent");
        }
        if self.index_write_offset != self.old_index_len {
            let old_layout =
                old_layout.ok_or("bound progress append replacement has no old index layout")?;
            if old_layout.entry_position(self.height) != Some(self.index_write_offset) {
                return Err("bound progress append replacement names the wrong height");
            }
            return Ok(());
        }
        let prefix_len = self
            .new_index_bytes
            .len()
            .checked_sub(PIPELINE_INDEX_ENTRY_SIZE)
            .ok_or("bound progress append suffix is truncated")?;
        let prefix = &self.new_index_bytes[..prefix_len];
        if let Some(old_layout) = old_layout {
            let expected_height = old_layout
                .next_height()
                .ok_or("bound progress append old index height overflows")?;
            let missing = self
                .height
                .checked_sub(expected_height)
                .ok_or("bound progress append target precedes the old index")?;
            if missing > MAX_INDEXED_SIDECAR_GAP_ENTRIES
                || missing
                    .checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64)
                    .and_then(|bytes| usize::try_from(bytes).ok())
                    != Some(prefix_len)
                || prefix.iter().any(|byte| *byte != 0)
            {
                return Err("bound progress append gap is not canonical");
            }
            return Ok(());
        }
        let initial = SidecarIndexLayout::read_from(
            &mut std::io::Cursor::new(&self.new_index_bytes),
            self.new_index_len,
        )?;
        let missing = self
            .height
            .checked_sub(initial.base_height)
            .ok_or("bound initial index starts after its target")?;
        let expected_header = SidecarIndexLayout::base_header(initial.base_height);
        if self.index_write_offset != 0
            || missing > MAX_INDEXED_SIDECAR_GAP_ENTRIES
            || initial.entry_count != missing + 1
            || prefix.get(..INDEXED_SIDECAR_BASE_HEADER_SIZE) != Some(expected_header.as_slice())
            || prefix
                .get(INDEXED_SIDECAR_BASE_HEADER_SIZE..)
                .is_none_or(|holes| holes.iter().any(|byte| *byte != 0))
        {
            return Err("bound progress initial V1 index header or gaps are not canonical");
        }
        Ok(())
    }
}
/// Raw and independently scanned Kura disk-usage state exposed only to crate tests.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DiskUsageAccountingSnapshotForTesting {
    /// Whether the enforced-usage cache is currently valid.
    pub(crate) enforced_initialized: bool,
    /// Whether the total-usage cache is currently valid.
    pub(crate) total_initialized: bool,
    /// Raw cached enforced bytes without triggering a refresh.
    pub(crate) cached_enforced_bytes: u64,
    /// Raw cached total bytes without triggering a refresh.
    pub(crate) cached_total_bytes: u64,
    /// Exact enforced bytes from a read-only filesystem scan.
    pub(crate) exact_enforced_bytes: u64,
    /// Exact total bytes from a read-only filesystem scan.
    pub(crate) exact_total_bytes: u64,
}
#[derive(Debug, Default)]
struct TotalDiskUsageAccountingState {
    generation: u64,
    mutations_in_flight: usize,
}
impl Kura {
    #[cfg(all(unix, not(target_os = "espidf")))]
    fn open_safety_wal_store_root_directory(
        store_root: &Path,
        store_root_lock_file: &std::fs::File,
    ) -> Result<BoundProgressDirectory> {
        use std::os::unix::fs::MetadataExt as _;
        let lock_path = store_root.join(STORE_ROOT_LOCK_FILE_NAME);
        let lock_before = store_root_lock_file
            .metadata()
            .map_err(|error| Error::IO(error, lock_path.clone()))?;
        let root = Self::open_bound_progress_directory(store_root, store_root)?;
        let entry_before = rustix::fs::statat(
            &root.file,
            STORE_ROOT_LOCK_FILE_NAME,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(std::io::Error::from)
        .map_err(|error| Error::IO(error, lock_path.clone()))?;
        let linked_lock = std::fs::File::from(
            rustix::fs::openat(
                &root.file,
                STORE_ROOT_LOCK_FILE_NAME,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from)
            .map_err(|error| Error::IO(error, lock_path.clone()))?,
        );
        let linked_metadata = linked_lock
            .metadata()
            .map_err(|error| Error::IO(error, lock_path.clone()))?;
        let entry_after = rustix::fs::statat(
            &root.file,
            STORE_ROOT_LOCK_FILE_NAME,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(std::io::Error::from)
        .map_err(|error| Error::IO(error, lock_path.clone()))?;
        let lock_after = store_root_lock_file
            .metadata()
            .map_err(|error| Error::IO(error, lock_path.clone()))?;
        if rustix::fs::FileType::from_raw_mode(entry_before.st_mode)
            != rustix::fs::FileType::RegularFile
            || entry_before.st_nlink as u64 != 1
            || entry_before.st_dev as u64 != linked_metadata.dev()
            || entry_before.st_ino as u64 != linked_metadata.ino()
            || entry_after.st_dev as u64 != linked_metadata.dev()
            || entry_after.st_ino as u64 != linked_metadata.ino()
            || !Self::sidecar_file_metadata_unchanged(&lock_before, &linked_metadata)
            || !Self::sidecar_file_metadata_unchanged(&lock_before, &lock_after)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "opened Kura store root does not retain its exact locked identity",
                ),
                lock_path,
            ));
        }
        Ok(root)
    }
    #[cfg(all(unix, not(target_os = "espidf")))]
    fn open_or_create_bound_storage_child_directory(
        &self,
        parent: &BoundProgressDirectory,
        name: &std::ffi::OsStr,
    ) -> Result<BoundProgressDirectory> {
        let expected_path = parent.expected_path.join(name);
        if !self.bound_storage_directory_unchanged(parent) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "safety-WAL parent directory changed before child binding",
                ),
                parent.expected_path.clone(),
            ));
        }
        match rustix::fs::mkdirat(&parent.file, name, rustix::fs::Mode::RWXU) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(Error::IO(std::io::Error::from(error), expected_path)),
        }
        let child =
            Self::open_bound_progress_child_directory(&self.store_root, parent, &expected_path)?;
        if !self.bound_storage_directory_unchanged(parent) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "safety-WAL parent directory changed while opening its child",
                ),
                parent.expected_path.clone(),
            ));
        }
        parent
            .file
            .sync_all()
            .map_err(|error| Error::IO(error, parent.expected_path.clone()))?;
        Ok(child)
    }
    #[cfg(all(unix, not(target_os = "espidf")))]
    fn bound_storage_directory_unchanged(&self, directory: &BoundProgressDirectory) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        let Ok(opened) = directory.file.metadata() else {
            return false;
        };
        if !opened.is_dir()
            || !Self::sidecar_directory_binding_unchanged(&directory.metadata, &opened)
        {
            return false;
        }
        if directory.entry_name.is_none() {
            let Ok(linked) = std::fs::symlink_metadata(&self.store_root) else {
                return false;
            };
            return !linked.file_type().is_symlink()
                && linked.is_dir()
                && linked.dev() == opened.dev()
                && linked.ino() == opened.ino();
        }
        let Ok(canonical) = std::fs::canonicalize(&directory.expected_path) else {
            return false;
        };
        canonical == directory.canonical_path
            && canonical.starts_with(&self.store_root_directory.canonical_path)
            && std::fs::symlink_metadata(&directory.expected_path).is_ok_and(|linked| {
                !linked.file_type().is_symlink()
                    && linked.is_dir()
                    && linked.dev() == opened.dev()
                    && linked.ino() == opened.ino()
            })
    }
}
