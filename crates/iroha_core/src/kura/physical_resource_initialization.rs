// Included at Kura module scope. Preparation/re-audit only; never a scrape path.

const PHYSICAL_RESOURCE_OWNED_TREE_NAMES: [&str; 4] = [
    "blocks",
    "retired/blocks",
    "retired/lane_geometry",
    fastpq_artifact_store::DIRECTORY,
];

/// Exact Kura-managed physical scope, excluding delegated consensus stores.
///
/// The total-byte owner enumerates these declared trees, eight fixed root files. In particular,
/// Consensus WAL/body/certificate files have independent writers and
/// are not part of this inventory. The `.kura.lock` process-control descriptor
/// is also excluded; it is not a retained data-budget artifact. No entire-store-root
/// traversal is permitted.
struct KuraPhysicalResourceScope {
    trees: Vec<PathBuf>,
    files: Vec<PathBuf>,
    bindings: Vec<(PathBuf, SecureMetadata)>,
}

impl KuraPhysicalResourceScope {
    fn retain_directory(
        &mut self,
        path: PathBuf,
        metadata: SecureMetadata,
    ) -> std::result::Result<(), resource_inventory::Unavailable> {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(resource_inventory::Unavailable::InvalidInventory);
        }
        if let Some((_, before)) = self.bindings.iter().find(|(prior, _)| *prior == path) {
            if !Kura::sidecar_directory_metadata_unchanged(before, &metadata) {
                return Err(resource_inventory::Unavailable::InvalidInventory);
            }
        } else {
            self.bindings.push((path, metadata));
        }
        Ok(())
    }

    fn validate_bindings(&self) -> std::result::Result<(), resource_inventory::Unavailable> {
        for (path, before) in &self.bindings {
            let after = secure_file_metadata::from_path(path)
                .map_err(|_| resource_inventory::Unavailable::InvalidInventory)?;
            if !after.is_dir()
                || after.file_type().is_symlink()
                || !Kura::sidecar_directory_metadata_unchanged(before, &after)
                || path.canonicalize().ok().as_ref() != Some(path)
            {
                return Err(resource_inventory::Unavailable::InvalidInventory);
            }
        }
        Ok(())
    }

    fn validate_disjoint(
        &self,
        store_root: &Path,
    ) -> std::result::Result<(), resource_inventory::Unavailable> {
        use resource_inventory::Unavailable as Missing;
        if self.trees.len() != PHYSICAL_RESOURCE_OWNED_TREE_NAMES.len() || self.files.len() != 8 {
            return Err(Missing::OwnerMismatch);
        }
        let canonical = |path: &Path| {
            path.is_absolute()
                && path != store_root
                && path.starts_with(store_root)
                && !path.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
        };
        let mut seen = BTreeSet::new();
        for (index, tree) in self.trees.iter().enumerate() {
            if !canonical(tree)
                || !seen.insert(tree)
                || self.trees[..index]
                    .iter()
                    .any(|prior| tree.starts_with(prior) || prior.starts_with(tree))
            {
                return Err(Missing::OwnerMismatch);
            }
        }
        for file in &self.files {
            if !canonical(file)
                || !seen.insert(file)
                || file.parent() != Some(store_root)
                || self
                    .trees
                    .iter()
                    .any(|tree| file.starts_with(tree) || tree.starts_with(file))
            {
                return Err(Missing::OwnerMismatch);
            }
        }
        Ok(())
    }

    fn observe(
        &self,
        limits: EvidenceResourceLimits,
    ) -> std::result::Result<IndexResourceCounts, resource_inventory::Unavailable> {
        self.validate_bindings()?;
        let mut result = [ResourceUsage::default(); resource_inventory::FAMILY_COUNT];
        let mut add = |observed: IndexResourceCounts| {
            for family in PHYSICAL_RESOURCE_FAMILIES {
                result[family as usize] =
                    result[family as usize].checked_add(observed[family as usize])?;
            }
            Ok::<_, resource_inventory::Unavailable>(())
        };
        // Each of the declared roots shares the existing 4M-entry/128-depth
        // physical traversal bounds. No unbounded set of traversal roots exists.
        for tree in &self.trees {
            add(physical_resource_tree_usage(tree, limits)?)?;
        }
        for files in self.files.chunks(INDEX_RESOURCE_MAX_PATHS) {
            add(physical_resource_paths_usage(files, limits)?)?;
        }
        self.validate_bindings()?;
        Ok(result)
    }
}

impl Kura {
    fn physical_resource_owned_trees(&self) -> [PathBuf; PHYSICAL_RESOURCE_OWNED_TREE_NAMES.len()] {
        PHYSICAL_RESOURCE_OWNED_TREE_NAMES.map(|name| self.store_root.join(name))
    }

    fn physical_resource_fixed_root_files(&self) -> [PathBuf; 8] {
        let root = &self.store_root;
        let query = root.join(crate::query::index_status::QueryIndexJournal::JOURNAL_FILE);
        let projection = root.join(crate::query::projection_checkpoint_journal::QueryProjectionCheckpointJournal::JOURNAL_FILE);
        let geometry = self.lane_geometry_journal_path();
        [
            query.with_extension("norito.tmp"),
            query,
            projection.with_extension("norito.tmp"),
            projection,
            geometry.with_extension("norito.tmp"),
            geometry.with_extension("norito.restore.tmp"),
            geometry,
            root.join(membership_storage::SEGMENT_NAME),
        ]
    }

    /// Pure writer-scope check shared with initialization; no new root silently
    /// enters the metric without an explicit ownership declaration. Root-level
    /// process temporaries are allowed during writes and must settle to validated
    /// quarantine or absence before a complete re-audit can publish.
    fn physical_resource_path_is_owned(&self, path: &Path) -> bool {
        let Ok(relative) = path.strip_prefix(&self.store_root) else {
            return false;
        };
        if !path.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return false;
        }
        if PHYSICAL_RESOURCE_OWNED_TREE_NAMES
            .iter()
            .any(|root| relative.starts_with(root))
        {
            return true;
        }
        if path.parent() != Some(self.store_root.as_path()) {
            return false;
        }
        let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
            return false;
        };
        let stable = name.strip_suffix(".tmp").unwrap_or(name);
        if [
            crate::query::index_status::QueryIndexJournal::JOURNAL_FILE,
            crate::query::projection_checkpoint_journal::QueryProjectionCheckpointJournal::JOURNAL_FILE,
            membership_storage::SEGMENT_NAME,
        ].contains(&stable)
            || (name.starts_with("lane_geometry_journal.norito")
                && lane_geometry::resource_evidence_file_kind(name).is_some())
        {
            return true;
        }
        false
    }

    fn physical_resource_scope(
        &self,
    ) -> std::result::Result<KuraPhysicalResourceScope, resource_inventory::Unavailable> {
        use resource_inventory::Unavailable as Missing;
        self.validate_physical_resource_owner_identity()?;
        Self::reject_retired_merge_storage(&self.store_root)
            .map_err(|_| Missing::InvalidInventory)?;
        let root = &self.store_root;
        let mut scope = KuraPhysicalResourceScope {
            trees: self.physical_resource_owned_trees().into(),
            files: self.physical_resource_fixed_root_files().into(),
            bindings: Vec::new(),
        };
        scope.retain_directory(
            root.clone(),
            secure_file_metadata::from_path(root).map_err(|_| Missing::InvalidInventory)?,
        )?;
        // Reject unrecognized journal temporaries without decoding retired protocol records.
        for (index, entry) in std::fs::read_dir(root)
            .map_err(|_| Missing::InvalidInventory)?
            .enumerate()
        {
            if index >= 4_096 {
                return Err(Missing::InvalidInventory);
            }
            let entry = entry.map_err(|_| Missing::InvalidInventory)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if (name.starts_with("prune_intent.")
                || matches!(name, "pending_merge_entries" | "merge_carriers"))
                || (name.starts_with("lane_geometry_journal.")
                    && !scope.files.contains(&entry.path()))
                || name.starts_with(".kura-sidecar-")
                || name.starts_with("autonomous_")
                || name.starts_with("native_amx_")
            {
                return Err(Missing::OwnerMismatch);
            }
        }
        scope.trees.sort();
        scope.files.sort();
        scope.validate_disjoint(root)?;
        for tree in scope.trees.clone() {
            let (parent, before) = index_resource_parent_binding(&tree)?;
            scope.retain_directory(parent, before)?;
            match secure_file_metadata::from_path(&tree) {
                Ok(metadata) => scope.retain_directory(tree, metadata)?,
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(_) => return Err(Missing::InvalidInventory),
            }
        }
        scope.validate_bindings()?;
        Ok(scope)
    }

    fn validate_physical_resource_owner_identity(
        &self,
    ) -> std::result::Result<(), resource_inventory::Unavailable> {
        use resource_inventory::Unavailable as Missing;
        if !self.store_root.is_absolute()
            || self.store_root.canonicalize().ok().as_ref() != Some(&self.store_root)
        {
            return Err(Missing::InvalidInventory);
        }
        #[cfg(all(unix, not(target_os = "espidf")))]
        if !self.bound_storage_directory_unchanged(&self.store_root_directory) {
            return Err(Missing::InvalidInventory);
        }
        Ok(())
    }

    fn physical_resource_reconciliation_allowed(&self) -> bool {
        !self.emergency_fast_startup_enabled()
            && !self.auxiliary_history_deferred
            && !self.canonical_storage_poisoned.load(Ordering::Acquire)
            && !self.prune_recovery_is_required()
    }

    /// Audit and atomically initialize every physical family after authorized recovery.
    ///
    /// This is startup/operator preparation work with bounded filesystem I/O.
    /// Resource scrapes never call it. Resident initialization is independent and
    /// must run after these guards drop. Failure leaves all physical families
    /// unavailable and never publishes a partial successful snapshot.
    pub(crate) fn reconcile_physical_resource_inventory(
        &self,
    ) -> std::result::Result<(), resource_inventory::Unavailable> {
        let result = (|| {
            if !self.physical_resource_reconciliation_allowed() {
                return Err(resource_inventory::Unavailable::Unregistered);
            }
            // This is the writer order, never sidecar -> canonical. Query and
            // resident writers remain covered by the shared registry generation.
            let _prune_guard = self.prune_lock.lock();
            #[cfg(all(test, unix, not(target_os = "espidf")))]
            original_inventory_release_tests::fence_boundary(self, 1);
            let _canonical_guard = self.canonical_chain_lock.lock();
            #[cfg(all(test, unix, not(target_os = "espidf")))]
            original_inventory_release_tests::fence_boundary(self, 2);
            if !self.physical_resource_reconciliation_allowed() {
                return Err(resource_inventory::Unavailable::Unregistered);
            }
            let generation = self.resource_inventory.reconciliation_generation()?;
            let scope = self.physical_resource_scope()?;
            self.validate_fastpq_artifact_inventory_on_startup()
                .map_err(|_| resource_inventory::Unavailable::InvalidInventory)?;
            let counts = scope.observe(self.evidence_resource_limits())?;
            self.validate_physical_resource_owner_identity()?;
            scope.validate_bindings()?;
            if !self.physical_resource_reconciliation_allowed() {
                return Err(resource_inventory::Unavailable::Unregistered);
            }
            self.resource_inventory.initialize(
                generation,
                &PHYSICAL_RESOURCE_FAMILIES
                    .iter()
                    .map(|family| (*family, counts[*family as usize]))
                    .collect::<Vec<_>>(),
            )
        })();
        if let Err(reason) = result {
            self.resource_inventory
                .invalidate(physical_resource_mask(), reason);
        }
        result
    }
}

/// Original physical sources through startup/re-audit family publication and invalidation.
#[cfg(all(test, unix, not(target_os = "espidf")))]
mod original_inventory_release_tests {
    include!("inventory_release_tests.rs");
}
