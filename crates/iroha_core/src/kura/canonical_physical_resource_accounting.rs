// Included at Kura module scope. The canonical writer owns all overlapping paths.

/// The finite mutation shapes of the live Kura canonical owner.
#[derive(Clone, Copy)]
enum CanonicalPhysicalOperation {
    Recovery,
    #[expect(
        dead_code,
        reason = "TODO: connect authorized eviction and pruning to exact physical accounting; preserve the operation distinction through recovery"
    )]
    Eviction,
    Append {
        start_height: u64,
        block_count: usize,
    },
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect authorized eviction and pruning to exact physical accounting; preserve the operation distinction through recovery"
        )
    )]
    Prune,
}

/// Retain the admitted parent and stage inode used to discover recovery image heights.
struct CanonicalPhysicalStageIdentity {
    path: PathBuf,
    parent: BoundProgressDirectory,
    file: Option<std::fs::File>,
    metadata: Option<StableSidecarMetadata>,
}

impl CanonicalPhysicalStageIdentity {
    fn capture(store: &BlockStore) -> Result<(Self, Option<DaBlockRewriteStageV1>)> {
        Self::capture_after_admission(store, || {})
    }

    /// The no-op production hook permits deterministic replacement controls after admission.
    fn capture_after_admission(
        store: &BlockStore,
        after_admission: impl FnOnce(),
    ) -> Result<(Self, Option<DaBlockRewriteStageV1>)> {
        let path = store.da_block_rewrite_stage_path();
        let parent = Kura::open_bound_progress_directory(
            &store.path_to_blockchain,
            &store.path_to_blockchain,
        )?;
        // Reject static FIFOs, devices, symlinks and extra links before opening.
        let metadata = Kura::regular_sidecar_metadata_for(
            &store.path_to_blockchain,
            &path,
            &store.path_to_blockchain,
        )?;
        if metadata.as_ref().is_some_and(|metadata| {
            metadata.file.len() > MAX_DA_BLOCK_REWRITE_STAGE_BYTES
                || !Kura::sidecar_directory_binding_unchanged(&parent.metadata, &metadata.directory)
        }) {
            return Err(store.invalid_da_block_rewrite_stage(
                "resource stage exceeds its bound or changed its admitted parent",
            ));
        }
        after_admission();
        let file = if metadata.is_some() {
            #[cfg(unix)]
            let file = std::fs::File::from(
                rustix::fs::openat(
                    &parent.file,
                    DA_BLOCK_REWRITE_STAGE_FILE_NAME,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(std::io::Error::from)
                .map_err(|error| Error::IO(error, path.clone()))?,
            );
            #[cfg(windows)]
            let file = {
                use std::os::windows::fs::OpenOptionsExt as _;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&path)
                    .map_err(|error| Error::IO(error, path.clone()))?
            };
            #[cfg(not(any(unix, windows)))]
            return Err(store.invalid_da_block_rewrite_stage(
                "resource stage requires a no-follow file identity reader",
            ));
            #[cfg(any(unix, windows))]
            Some(file)
        } else {
            None
        };
        let mut identity = Self {
            path,
            parent,
            file,
            metadata,
        };
        if !identity.unchanged() {
            return Err(store.invalid_da_block_rewrite_stage(
                "resource stage changed while opening its admitted inode",
            ));
        }
        let stage = if let (Some(file), Some(metadata)) = (&mut identity.file, &identity.metadata) {
            let expected_len = usize::try_from(metadata.file.len())?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(expected_len)?;
            bytes.resize(expected_len, 0);
            file.read_exact(&mut bytes)
                .map_err(|error| Error::IO(error, identity.path.clone()))?;
            let mut growth_probe = [0_u8; 1];
            if file
                .read(&mut growth_probe)
                .map_err(|error| Error::IO(error, identity.path.clone()))?
                != 0
            {
                return Err(store.invalid_da_block_rewrite_stage(
                    "resource stage grew beyond its admitted length",
                ));
            }
            // Share the canonical bounded decoder and complete image validator.
            // The retained descriptor is never reopened through the mutable name.
            Some(store.decode_da_block_rewrite_stage_bytes(bytes)?)
        } else {
            None
        };
        if !identity.unchanged() {
            return Err(store.invalid_da_block_rewrite_stage(
                "resource plan stage changed during exact image observation",
            ));
        }
        Ok((identity, stage))
    }

    fn unchanged(&self) -> bool {
        let Ok(opened_parent) = secure_file_metadata::from_file(&self.parent.file) else {
            return false;
        };
        let Ok(Some((canonical_parent, named_parent))) = Kura::canonical_sidecar_directory_for(
            &self.parent.expected_path,
            &self.parent.expected_path,
        ) else {
            return false;
        };
        if canonical_parent != self.parent.canonical_path
            || !opened_parent.is_dir()
            || !Kura::sidecar_directory_binding_unchanged(&self.parent.metadata, &opened_parent)
            || !Kura::sidecar_directory_binding_unchanged(&self.parent.metadata, &named_parent)
        {
            return false;
        }
        match (&self.file, &self.metadata) {
            (Some(file), Some(before)) => {
                let Ok(opened) = secure_file_metadata::from_file(file) else {
                    return false;
                };
                let Ok(named) = secure_file_metadata::from_path(&self.path) else {
                    return false;
                };
                opened.is_file()
                    && named.is_file()
                    && !named.file_type().is_symlink()
                    && Kura::sidecar_is_single_link(&opened)
                    && Kura::sidecar_is_single_link(&named)
                    && Kura::sidecar_file_metadata_unchanged(&before.file, &opened)
                    && Kura::sidecar_file_metadata_unchanged(&before.file, &named)
            }
            (None, None) => matches!(
                secure_file_metadata::from_path(&self.path),
                Err(error) if error.kind() == ErrorKind::NotFound
            ),
            _ => false,
        }
    }
}

/// One canonical operation pre-observes every disjoint bounded leaf before I/O.
#[must_use]
struct CanonicalPhysicalMutation<'a> {
    kura: &'a Kura,
    fence: TotalDiskUsageMutation<'a>,
    leaves: Vec<PhysicalResourceMutation<'a>>,
    _stage_identity: Option<CanonicalPhysicalStageIdentity>,
    complete: bool,
    recovery_is_read_only: bool,
}

impl CanonicalPhysicalMutation<'_> {
    fn publish_leaves(&mut self) -> bool {
        let mut complete = self.complete;
        for leaf in self.leaves.drain(..) {
            if let Err(reason) = leaf.finish() {
                self.kura
                    .resource_inventory
                    .invalidate(physical_resource_mask(), reason);
                complete = false;
            }
        }
        complete
    }

    fn finish(mut self) {
        if self.publish_leaves() {
            self.fence.finish();
        }
    }

    fn finish_resources_before_disk_rescan(mut self) {
        if self.publish_leaves() {
            if self.recovery_is_read_only {
                self.fence.finish();
            } else {
                self.fence.finish_resources_before_disk_rescan();
            }
        }
    }
}

impl Kura {
    fn canonical_physical_fixed_paths(store: &BlockStore) -> Vec<PathBuf> {
        [
            INDEX_FILE_NAME,
            HASHES_FILE_NAME,
            DATA_FILE_NAME,
            COUNT_FILE_NAME,
            EVICTION_COMPACTION_STAGE_FILE_NAME,
            EVICTION_COMPACTION_DATA_FILE_NAME,
            EVICTION_COMPACTION_INDEX_FILE_NAME,
            DA_BLOCK_REWRITE_STAGE_FILE_NAME,
        ]
        .into_iter()
        .map(|name| store.path_to_blockchain.join(name))
        .chain([store.commit_marker_path().with_extension("norito.tmp")])
        .collect()
    }

    fn canonical_physical_paths(
        store: &mut BlockStore,
        operation: CanonicalPhysicalOperation,
    ) -> Result<(Vec<PathBuf>, CanonicalPhysicalStageIdentity)> {
        let (identity, stage) = CanonicalPhysicalStageIdentity::capture(store)?;
        let mut paths = Self::canonical_physical_fixed_paths(store)
            .into_iter()
            .collect::<BTreeSet<_>>();
        if !matches!(operation, CanonicalPhysicalOperation::Prune) {
            if let Some(stage) = &stage {
                for image in stage.old_suffix.iter().chain(&stage.replacement) {
                    paths.insert(store.da_block_path(image.height));
                }
            }
            if let CanonicalPhysicalOperation::Append {
                start_height,
                block_count,
            } = operation
            {
                if block_count == 0 || block_count > MAX_DA_BLOCK_REWRITE_STAGE_ENTRIES {
                    return Err(store.invalid_da_block_rewrite_stage(
                        "resource append plan exceeds the canonical image bound",
                    ));
                }
                // Recovery runs first. Its exact currently published marker
                // determines the resolved journal count; all old image heights
                // remain independently included above, even after truncation.
                let previous_count = if let Some(stage) = &stage {
                    let selected = store.read_commit_marker()?.ok_or_else(|| {
                        store.invalid_da_block_rewrite_stage("resource plan has no selected marker")
                    })?;
                    if selected != stage.old_marker && selected != stage.new_marker {
                        return Err(store.invalid_da_block_rewrite_stage(
                            "resource plan marker matches neither exact stage image",
                        ));
                    }
                    selected.count
                } else {
                    store.read_index_count()?
                };
                let suffix = previous_count.saturating_sub(start_height);
                let count = u64::try_from(block_count)?;
                if suffix
                    .checked_add(count)
                    .is_none_or(|total| total > MAX_DA_BLOCK_REWRITE_STAGE_ENTRIES as u64)
                {
                    return Err(store.invalid_da_block_rewrite_stage(
                        "resource rewrite plan exceeds the canonical image bound",
                    ));
                }
                let end = start_height.checked_add(count).ok_or_else(|| {
                    store.invalid_da_block_rewrite_stage("resource append height overflowed")
                })?;
                let first = start_height.checked_add(1).ok_or_else(|| {
                    store.invalid_da_block_rewrite_stage("resource append height overflowed")
                })?;
                for height in first..=end.max(previous_count) {
                    paths.insert(store.da_block_path(height));
                }
            }
        }
        // At most one existing and one new bounded rewrite, plus the fixed 11.
        let maximum = MAX_DA_BLOCK_REWRITE_STAGE_ENTRIES
            .checked_mul(2)
            .and_then(|images| images.checked_add(11))
            .ok_or_else(|| {
                store.invalid_da_block_rewrite_stage("resource plan bound overflowed")
            })?;
        if paths.len() > maximum {
            return Err(
                store.invalid_da_block_rewrite_stage("resource plan union exceeds its bound")
            );
        }
        Ok((paths.into_iter().collect(), identity))
    }

    fn begin_canonical_physical_mutation(
        &self,
        store: &mut BlockStore,
        operation: CanonicalPhysicalOperation,
    ) -> CanonicalPhysicalMutation<'_> {
        let fence = self
            .begin_total_disk_usage_mutation()
            .with_resource_children(0);
        let mut result = CanonicalPhysicalMutation {
            kura: self,
            fence,
            leaves: Vec::new(),
            _stage_identity: None,
            complete: false,
            recovery_is_read_only: false,
        };
        let plan = Self::canonical_physical_paths(store, operation);
        let Ok((paths, identity)) = plan else {
            self.resource_inventory.invalidate(
                physical_resource_mask(),
                resource_inventory::Unavailable::InvalidInventory,
            );
            return result;
        };
        for chunk in paths.chunks(INDEX_RESOURCE_MAX_PATHS) {
            if !chunk
                .iter()
                .all(|path| self.physical_resource_path_within_store(path))
            {
                self.resource_inventory.invalidate(
                    physical_resource_mask(),
                    resource_inventory::Unavailable::OwnerMismatch,
                );
                return result;
            }
            let Some(leaf) = self.begin_physical_resource_mutation() else {
                return result;
            };
            match leaf.bind(PhysicalResourceTarget::Paths(chunk.to_vec())) {
                Ok(leaf) => result.leaves.push(leaf),
                Err(reason) => {
                    self.resource_inventory
                        .invalidate(physical_resource_mask(), reason);
                    return result;
                }
            }
        }
        if matches!(operation, CanonicalPhysicalOperation::Prune) {
            let root = &store.da_blocks_dir;
            if !self.physical_resource_path_within_store(root) {
                self.resource_inventory.invalidate(
                    physical_resource_mask(),
                    resource_inventory::Unavailable::OwnerMismatch,
                );
                return result;
            }
            let Some(leaf) = self.begin_physical_resource_mutation() else {
                return result;
            };
            match leaf.bind(PhysicalResourceTarget::StartupTree(root.clone())) {
                Ok(leaf) => result.leaves.push(leaf),
                Err(reason) => {
                    self.resource_inventory
                        .invalidate(physical_resource_mask(), reason);
                    return result;
                }
            }
        }
        // Retain the original file handle through the operation. Recheck after
        // all before-images, immediately before returning to its locked caller.
        result.recovery_is_read_only = matches!(operation, CanonicalPhysicalOperation::Recovery)
            && identity.file.is_none()
            && store.commit_marker_pending.is_none()
            && [
                EVICTION_COMPACTION_STAGE_FILE_NAME,
                EVICTION_COMPACTION_DATA_FILE_NAME,
                EVICTION_COMPACTION_INDEX_FILE_NAME,
            ]
            .into_iter()
            .all(|name| {
                matches!(
                    secure_file_metadata::from_path(&store.path_to_blockchain.join(name)),
                    Err(error) if error.kind() == ErrorKind::NotFound
                )
            });
        result.complete = identity.unchanged();
        if !result.complete {
            self.resource_inventory.invalidate(
                physical_resource_mask(),
                resource_inventory::Unavailable::InvalidInventory,
            );
        }
        CanonicalPhysicalMutation {
            _stage_identity: Some(identity),
            ..result
        }
    }

    fn flush_pending_fsync_with_resources(
        &self,
        store: &mut BlockStore,
        force: bool,
    ) -> Result<()> {
        let resources =
            self.begin_canonical_physical_mutation(store, CanonicalPhysicalOperation::Recovery);
        store.flush_pending_fsync(force)?;
        resources.finish_resources_before_disk_rescan();
        Ok(())
    }
}
