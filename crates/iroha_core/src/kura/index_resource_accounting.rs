// Included at Kura module scope. Index observations do not grant storage authority.
use resource_inventory::{Family as ResourceFamily, Usage as ResourceUsage};

const INDEX_RESOURCE_MAX_PATHS: usize = 48;
// Startup/retirement walks share the existing retained-tree traversal ceiling.
const INDEX_RESOURCE_MAX_TREE_ENTRIES: usize = 4_000_000;
const INDEX_RESOURCE_MAX_DEPTH: usize = 128;
type IndexResourceCounts = [ResourceUsage; resource_inventory::FAMILY_COUNT];

#[derive(Clone, Copy)]
enum IndexResourceFormat {
    Fixed(u64),
    SidecarV1,
    Singleton(u64),
    TemporarySingleton(u64),
}

/// Recognize only production-owned index formats and their exact temporary names.
fn index_resource_kind(path: &Path) -> Option<(ResourceFamily, IndexResourceFormat, bool)> {
    let file_name = path.file_name()?.to_str()?;
    let prepend = file_name.ends_with(".prepend.tmp");
    let (name, temporary) = if let Some(main) = file_name.strip_suffix(".prepend.tmp") {
        (main, true)
    } else if let Some(main) = file_name.strip_suffix(".tmp") {
        (main, true)
    } else if file_name == EVICTION_COMPACTION_INDEX_FILE_NAME {
        (INDEX_FILE_NAME, true)
    } else {
        (file_name, false)
    };

    let (family, format) = match name {
        crate::query::index_status::QueryIndexJournal::JOURNAL_FILE => (ResourceFamily::QueryMarkerRecords, IndexResourceFormat::Singleton(crate::query::index_status::QueryIndexJournal::JOURNAL_MAX_BYTES)),
        crate::query::projection_checkpoint_journal::QueryProjectionCheckpointJournal::JOURNAL_FILE => (ResourceFamily::QueryMarkerRecords, IndexResourceFormat::Singleton(crate::query::projection_checkpoint_journal::QUERY_PROJECTION_CHECKPOINT_JOURNAL_MAX_BYTES as u64)),
        INDEX_FILE_NAME => (ResourceFamily::CanonicalIndex, IndexResourceFormat::Fixed(BlockIndex::SIZE)),
        HASHES_FILE_NAME => (ResourceFamily::CanonicalHashes, IndexResourceFormat::Fixed(SIZE_OF_BLOCK_HASH)),
        PIPELINE_SIDECARS_INDEX_FILE => (ResourceFamily::PipelineIndex, IndexResourceFormat::SidecarV1),
        _ => return None,
    };
    if prepend && !matches!(format, IndexResourceFormat::SidecarV1) {
        return None;
    }
    Some((family, format, temporary))
}

// Bind the nearest existing parent for a present file or a proven absent path.
// Canonical equality rejects symlinked ancestors, not just a linked final file.
fn index_resource_parent_binding(
    path: &Path,
) -> std::result::Result<(PathBuf, SecureMetadata), resource_inventory::Unavailable> {
    use resource_inventory::Unavailable as Missing;
    if !path.is_absolute() {
        return Err(Missing::InvalidInventory);
    }
    for (depth, parent) in path.ancestors().skip(1).enumerate() {
        if depth >= INDEX_RESOURCE_MAX_DEPTH {
            return Err(Missing::InvalidInventory);
        }
        match secure_file_metadata::from_path(parent) {
            Ok(metadata) => {
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || parent
                        .canonicalize()
                        .map_err(|_| Missing::InvalidInventory)?
                        != parent
                {
                    return Err(Missing::InvalidInventory);
                }
                return Ok((parent.to_path_buf(), metadata));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(Missing::InvalidInventory),
        }
    }
    Err(Missing::InvalidInventory)
}

fn index_resource_parent_unchanged(parent: &Path, before: &SecureMetadata) -> bool {
    secure_file_metadata::from_path(parent).is_ok_and(|after| {
        after.is_dir()
            && !after.file_type().is_symlink()
            && Kura::sidecar_directory_binding_unchanged(before, &after)
            && parent
                .canonicalize()
                .is_ok_and(|canonical| canonical == parent)
    })
}

/// Observe one exact physical file; never decode or allocate its entry payloads.
fn index_resource_file_usage(
    path: &Path,
    format: IndexResourceFormat,
    temporary: bool,
) -> std::result::Result<ResourceUsage, resource_inventory::Unavailable> {
    index_resource_file_usage_with_admission_hooks(path, format, temporary, || {}, |_| {})
}

/// Preserve the production observer while exposing per-call test admission boundaries.
fn index_resource_file_usage_with_admission_hooks(
    path: &Path,
    format: IndexResourceFormat,
    temporary: bool,
    after_admission: impl FnOnce(),
    after_open: impl FnOnce(&std::fs::File),
) -> std::result::Result<ResourceUsage, resource_inventory::Unavailable> {
    use resource_inventory::Unavailable as Missing;
    let (parent, parent_before) = index_resource_parent_binding(path)?;
    let before = match secure_file_metadata::from_path(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if !index_resource_parent_unchanged(&parent, &parent_before) {
                return Err(Missing::InvalidInventory);
            }
            return Ok(ResourceUsage::default());
        }
        Err(_) => return Err(Missing::InvalidInventory),
    };
    if before.file_type().is_symlink()
        || !before.is_file()
        || !Kura::sidecar_is_single_link(&before)
    {
        return Err(Missing::InvalidInventory);
    }
    after_admission();
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(i32::from_ne_bytes(
            (rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC)
                .bits()
                .to_ne_bytes(),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path).map_err(|_| Missing::InvalidInventory)?;
    after_open(&file);
    let opened = secure_file_metadata::from_file(&file).map_err(|_| Missing::InvalidInventory)?;
    if !Kura::sidecar_file_metadata_unchanged(&before, &opened) {
        return Err(Missing::InvalidInventory);
    }
    let bytes = opened.len();
    let entries = match format {
        IndexResourceFormat::Fixed(width) if width != 0 && bytes % width == 0 => bytes / width,
        IndexResourceFormat::Fixed(_) => return Err(Missing::InvalidInventory),
        IndexResourceFormat::Singleton(maximum) if bytes > 0 && bytes <= maximum => 1,
        IndexResourceFormat::Singleton(_) => return Err(Missing::InvalidInventory),
        IndexResourceFormat::TemporarySingleton(maximum) if temporary && bytes <= maximum => 1,
        IndexResourceFormat::TemporarySingleton(_) => return Err(Missing::InvalidInventory),
        IndexResourceFormat::SidecarV1 => {
            let layout = SidecarIndexLayout::read_from(&mut file, bytes)
                .map_err(|_| Missing::InvalidInventory)?;
            if layout.aligned_len != bytes {
                return Err(Missing::InvalidInventory);
            }
            layout.entry_count
        }
    };
    let after_opened =
        secure_file_metadata::from_file(&file).map_err(|_| Missing::InvalidInventory)?;
    let after_path =
        secure_file_metadata::from_path(path).map_err(|_| Missing::InvalidInventory)?;
    if !index_resource_parent_unchanged(&parent, &parent_before)
        || !Kura::sidecar_file_metadata_unchanged(&opened, &after_opened)
        || !Kura::sidecar_file_metadata_unchanged(&opened, &after_path)
    {
        return Err(Missing::InvalidInventory);
    }
    // Physical slots in temporary files also consume represented index entries.
    // This is physical allocation, not an assertion of committed state.
    Ok(ResourceUsage {
        persisted_entries: entries,
        index_bytes: if temporary { 0 } else { bytes },
        temporary_index_bytes: if temporary { bytes } else { 0 },
        ..ResourceUsage::default()
    })
}

#[cfg(test)]
fn index_resource_paths_usage(
    paths: &[PathBuf],
) -> std::result::Result<IndexResourceCounts, resource_inventory::Unavailable> {
    use resource_inventory::Unavailable as Missing;
    if paths.is_empty() || paths.len() > INDEX_RESOURCE_MAX_PATHS {
        return Err(Missing::InvalidInventory);
    }
    let mut seen = BTreeSet::new();
    let mut result = [ResourceUsage::default(); resource_inventory::FAMILY_COUNT];
    for path in paths {
        if !seen.insert(path) {
            return Err(Missing::InvalidInventory);
        }
        let (family, format, temporary) =
            index_resource_kind(path).ok_or(Missing::OwnerMismatch)?;
        result[family as usize] = result[family as usize]
            .checked_add(index_resource_file_usage(path, format, temporary)?)?;
    }
    Ok(result)
}

/// Independent bounded inventory used by index-file regression tests.
#[cfg(test)]
fn index_resource_tree_usage(
    root: &Path,
) -> std::result::Result<IndexResourceCounts, resource_inventory::Unavailable> {
    use resource_inventory::Unavailable as Missing;
    let (parent, parent_before) = index_resource_parent_binding(root)?;
    let root_before = match secure_file_metadata::from_path(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return if index_resource_parent_unchanged(&parent, &parent_before) {
                Ok([ResourceUsage::default(); resource_inventory::FAMILY_COUNT])
            } else {
                Err(Missing::InvalidInventory)
            };
        }
        Err(_) => return Err(Missing::InvalidInventory),
    };
    if root_before.file_type().is_symlink()
        || !root_before.is_dir()
        || root.canonicalize().map_err(|_| Missing::InvalidInventory)? != root
    {
        return Err(Missing::InvalidInventory);
    }
    // Depth-first iterators bound open-directory state by depth, not file count.
    let entries = std::fs::read_dir(root).map_err(|_| Missing::InvalidInventory)?;
    let mut stack = vec![(root.to_path_buf(), root_before, entries)];
    let mut seen = 0_usize;
    let mut result = [ResourceUsage::default(); resource_inventory::FAMILY_COUNT];
    while let Some((directory, before, entries)) = stack.last_mut() {
        let Some(entry) = entries.next() else {
            let after = secure_file_metadata::from_path(directory)
                .map_err(|_| Missing::InvalidInventory)?;
            if !Kura::sidecar_directory_metadata_unchanged(before, &after) {
                return Err(Missing::InvalidInventory);
            }
            stack.pop();
            continue;
        };
        seen = seen.checked_add(1).ok_or(Missing::Arithmetic)?;
        if seen > INDEX_RESOURCE_MAX_TREE_ENTRIES {
            return Err(Missing::InvalidInventory);
        }
        let path = entry.map_err(|_| Missing::InvalidInventory)?.path();
        let metadata =
            secure_file_metadata::from_path(&path).map_err(|_| Missing::InvalidInventory)?;
        if metadata.file_type().is_symlink() {
            return Err(Missing::InvalidInventory);
        }
        if metadata.is_dir() {
            if stack.len() >= INDEX_RESOURCE_MAX_DEPTH {
                return Err(Missing::InvalidInventory);
            }
            let children = std::fs::read_dir(&path).map_err(|_| Missing::InvalidInventory)?;
            stack.push((path, metadata, children));
        } else if metadata.is_file() {
            if let Some((family, format, temporary)) = index_resource_kind(&path) {
                result[family as usize] = result[family as usize]
                    .checked_add(index_resource_file_usage(&path, format, temporary)?)?;
            } else if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains(".index") || name.starts_with("blocks.hashes"))
            {
                // New/obsolete formats require an explicit owner, never silent omission.
                return Err(Missing::OwnerMismatch);
            }
        } else {
            return Err(Missing::InvalidInventory);
        }
    }
    if !index_resource_parent_unchanged(&parent, &parent_before) {
        return Err(Missing::InvalidInventory);
    }
    Ok(result)
}

impl Kura {
    /// Observe only one registered component for owner tests; never a complete snapshot.
    #[cfg(test)]
    pub(crate) fn resource_inventory_component_for_tests(
        &self,
        family: resource_inventory::Family,
    ) -> std::result::Result<ResourceUsage, resource_inventory::Unavailable> {
        self.resource_inventory.component_usage_for_tests(family)
    }

    /// Nonblocking observation of a complete inventory while its owner remains recovered.
    #[cfg(any(test, feature = "telemetry"))]
    pub(crate) fn resource_inventory_snapshot(
        &self,
    ) -> std::result::Result<resource_inventory::Snapshot, resource_inventory::Unavailable> {
        self.resource_inventory_snapshot_after_observation(|| {})
    }

    /// The no-op production hook allows a deterministic poison race in owner tests.
    #[cfg(any(test, feature = "telemetry"))]
    fn resource_inventory_snapshot_after_observation(
        &self,
        after_observation: impl FnOnce(),
    ) -> std::result::Result<resource_inventory::Snapshot, resource_inventory::Unavailable> {
        self.resource_inventory_observation_allowed()?;
        let snapshot = self.resource_inventory.try_snapshot()?;
        after_observation();
        // A read-triggered fail-stop latch can change without a resource writer.
        // Never return the captured vector once that transition has been observed.
        self.resource_inventory_observation_allowed()?;
        Ok(snapshot)
    }

    /// Read only immutable and atomic completeness flags.
    #[cfg(any(test, feature = "telemetry"))]
    fn resource_inventory_observation_allowed(
        &self,
    ) -> std::result::Result<(), resource_inventory::Unavailable> {
        use resource_inventory::Unavailable;
        if self.canonical_storage_poisoned.load(Ordering::Acquire)
            || self.prune_recovery_is_required()
        {
            return Err(Unavailable::InvalidInventory);
        }
        if self.prune_in_progress.load(Ordering::Acquire) {
            return Err(Unavailable::Busy);
        }
        if self.auxiliary_history_deferred {
            return Err(Unavailable::Unregistered);
        }
        Ok(())
    }
}
