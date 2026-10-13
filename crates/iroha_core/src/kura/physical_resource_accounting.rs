// Included at Kura module scope. Existing storage locks own overlapping paths.

const PHYSICAL_RESOURCE_FAMILIES: [ResourceFamily; 6] = [
    ResourceFamily::CanonicalIndex,
    ResourceFamily::CanonicalHashes,
    ResourceFamily::PipelineIndex,
    ResourceFamily::QueryMarkerRecords,
    ResourceFamily::EvidenceKeyRecords,
    ResourceFamily::StorageBytes,
];

fn physical_resource_mask() -> u32 {
    PHYSICAL_RESOURCE_FAMILIES
        .iter()
        .fold(0, |mask, family| mask | family.mask())
}

/// Observe each declared physical path once in each distinct representation.
fn physical_resource_paths_usage(
    paths: &[PathBuf],
    limits: EvidenceResourceLimits,
) -> std::result::Result<IndexResourceCounts, resource_inventory::Unavailable> {
    use resource_inventory::Unavailable as Missing;
    if paths.is_empty() || paths.len() > INDEX_RESOURCE_MAX_PATHS {
        return Err(Missing::InvalidInventory);
    }
    let mut seen = BTreeSet::new();
    let mut result = [ResourceUsage::default(); resource_inventory::FAMILY_COUNT];
    for path in paths {
        if !seen.insert(path) {
            return Err(Missing::OwnerMismatch);
        }
        let index = index_resource_kind(path);
        let evidence = evidence_resource_kind(path, limits)?;
        let kind = match (index, evidence) {
            (Some(_), Some(_)) => return Err(Missing::OwnerMismatch),
            (Some(kind), None) => Some(kind),
            (None, Some((format, temporary))) => {
                Some((ResourceFamily::EvidenceKeyRecords, format, temporary))
            }
            (None, None) => {
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.contains(".index") || name.starts_with("blocks.hashes")
                    })
                {
                    return Err(Missing::OwnerMismatch);
                }
                None
            }
        };
        let storage_bytes = if let Some((family, format, temporary)) = kind {
            let usage = index_resource_file_usage(path, format, temporary)?;
            let bytes = usage
                .index_bytes
                .checked_add(usage.temporary_index_bytes)
                .ok_or(Missing::Arithmetic)?;
            result[family as usize] = result[family as usize].checked_add(usage)?;
            bytes
        } else {
            storage_resource_file_bytes(path)?
        };
        result[ResourceFamily::StorageBytes as usize] =
            result[ResourceFamily::StorageBytes as usize].checked_add(ResourceUsage {
                storage_bytes,
                ..ResourceUsage::default()
            })?;
    }
    Ok(result)
}

/// Bounded startup/retirement inventory; never used by a resource scrape.
fn physical_resource_tree_usage(
    root: &Path,
    limits: EvidenceResourceLimits,
) -> std::result::Result<IndexResourceCounts, resource_inventory::Unavailable> {
    use resource_inventory::Unavailable as Missing;
    let (parent, parent_before) = index_resource_parent_binding(root)?;
    let before = match secure_file_metadata::from_path(root) {
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
    if !before.is_dir()
        || before.file_type().is_symlink()
        || root.canonicalize().map_err(|_| Missing::InvalidInventory)? != root
    {
        return Err(Missing::InvalidInventory);
    }
    let entries = std::fs::read_dir(root).map_err(|_| Missing::InvalidInventory)?;
    let mut stack = vec![(root.to_path_buf(), before, entries)];
    let mut seen = 0_usize;
    let mut counts = [ResourceUsage::default(); resource_inventory::FAMILY_COUNT];
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
            let observed = physical_resource_paths_usage(std::slice::from_ref(&path), limits)?;
            for family in PHYSICAL_RESOURCE_FAMILIES {
                counts[family as usize] =
                    counts[family as usize].checked_add(observed[family as usize])?;
            }
        } else {
            return Err(Missing::InvalidInventory);
        }
    }
    if !index_resource_parent_unchanged(&parent, &parent_before) {
        return Err(Missing::InvalidInventory);
    }
    Ok(counts)
}

enum PhysicalResourceTarget {
    Paths(Vec<PathBuf>),
    StartupTree(PathBuf),
    DeletedTree(PathBuf),
    MovedTrees {
        source: PathBuf,
        destination: PathBuf,
    },
    // A declared child batch owns no file delta of its own.
    ChildBatch,
}

/// Retain the original namespace object across the entire filesystem mutation.
/// Child creation may change timestamps, but cannot replace the bound ancestor.
struct PhysicalResourceBindings(Vec<(PathBuf, SecureMetadata)>);

impl PhysicalResourceBindings {
    fn capture(
        target: &PhysicalResourceTarget,
    ) -> std::result::Result<Self, resource_inventory::Unavailable> {
        let paths: Vec<&Path> = match target {
            PhysicalResourceTarget::Paths(paths) => paths.iter().map(PathBuf::as_path).collect(),
            PhysicalResourceTarget::StartupTree(root)
            | PhysicalResourceTarget::DeletedTree(root) => vec![root],
            PhysicalResourceTarget::MovedTrees {
                source,
                destination,
            } => vec![source, destination],
            PhysicalResourceTarget::ChildBatch => Vec::new(),
        };
        if paths.len() > INDEX_RESOURCE_MAX_PATHS {
            return Err(resource_inventory::Unavailable::InvalidInventory);
        }
        let mut bindings = Vec::new();
        for path in paths {
            let binding = index_resource_parent_binding(path)?;
            if !bindings.iter().any(|(parent, _)| *parent == binding.0) {
                bindings.push(binding);
            }
        }
        // Recovery may modify children or create an absent root, but must not
        // replace an existing root while measuring only its replacement tree.
        if let PhysicalResourceTarget::StartupTree(root) = target {
            match secure_file_metadata::from_path(root) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    bindings.push((root.clone(), metadata));
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                _ => return Err(resource_inventory::Unavailable::InvalidInventory),
            }
        }
        let result = Self(bindings);
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> std::result::Result<(), resource_inventory::Unavailable> {
        if self
            .0
            .iter()
            .all(|(path, before)| index_resource_parent_unchanged(path, before))
        {
            Ok(())
        } else {
            Err(resource_inventory::Unavailable::InvalidInventory)
        }
    }
}

fn physical_resource_moved_trees_usage(
    source: &Path,
    destination: &Path,
    limits: EvidenceResourceLimits,
) -> std::result::Result<IndexResourceCounts, resource_inventory::Unavailable> {
    if source.starts_with(destination) || destination.starts_with(source) {
        return Err(resource_inventory::Unavailable::OwnerMismatch);
    }
    let mut usage = physical_resource_tree_usage(source, limits)?;
    let destination_usage = physical_resource_tree_usage(destination, limits)?;
    for family in PHYSICAL_RESOURCE_FAMILIES {
        usage[family as usize] =
            usage[family as usize].checked_add(destination_usage[family as usize])?;
    }
    Ok(usage)
}

/// One transaction over all physical resource families, including real data bytes.
struct PhysicalResourceMutation<'a> {
    mutation: resource_inventory::Mutation<'a>,
    before: IndexResourceCounts,
    target: PhysicalResourceTarget,
    bindings: PhysicalResourceBindings,
    limits: EvidenceResourceLimits,
}

impl PhysicalResourceMutation<'_> {
    fn bind(
        mut self,
        target: PhysicalResourceTarget,
    ) -> std::result::Result<Self, resource_inventory::Unavailable> {
        let bindings = PhysicalResourceBindings::capture(&target)?;
        let before = match &target {
            PhysicalResourceTarget::Paths(paths) => {
                physical_resource_paths_usage(paths, self.limits)?
            }
            PhysicalResourceTarget::StartupTree(root)
            | PhysicalResourceTarget::DeletedTree(root) => {
                physical_resource_tree_usage(root, self.limits)?
            }
            PhysicalResourceTarget::MovedTrees {
                source,
                destination,
            } => physical_resource_moved_trees_usage(source, destination, self.limits)?,
            PhysicalResourceTarget::ChildBatch => {
                [ResourceUsage::default(); resource_inventory::FAMILY_COUNT]
            }
        };
        bindings.validate()?;
        self.before = before;
        self.target = target;
        self.bindings = bindings;
        Ok(self)
    }

    fn finish(self) -> std::result::Result<(), resource_inventory::Unavailable> {
        self.bindings.validate()?;
        let after = match &self.target {
            PhysicalResourceTarget::Paths(paths) => {
                physical_resource_paths_usage(paths, self.limits)?
            }
            PhysicalResourceTarget::StartupTree(root) => {
                physical_resource_tree_usage(root, self.limits)?
            }
            PhysicalResourceTarget::DeletedTree(root) => {
                if !matches!(secure_file_metadata::from_path(root), Err(error) if error.kind() == ErrorKind::NotFound)
                {
                    return Err(resource_inventory::Unavailable::InvalidInventory);
                }
                [ResourceUsage::default(); resource_inventory::FAMILY_COUNT]
            }
            PhysicalResourceTarget::MovedTrees {
                source,
                destination,
            } => physical_resource_moved_trees_usage(source, destination, self.limits)?,
            PhysicalResourceTarget::ChildBatch => {
                [ResourceUsage::default(); resource_inventory::FAMILY_COUNT]
            }
        };
        self.bindings.validate()?;
        let values = PHYSICAL_RESOURCE_FAMILIES
            .iter()
            .map(|family| {
                (
                    *family,
                    self.before[*family as usize],
                    after[*family as usize],
                )
            })
            .collect::<Vec<_>>();
        self.mutation.publish(&values)
    }
}

impl Kura {
    fn begin_physical_resource_mutation(&self) -> Option<PhysicalResourceMutation<'_>> {
        match self.resource_inventory.begin(physical_resource_mask()) {
            Ok(mutation) => Some(PhysicalResourceMutation {
                mutation,
                before: [ResourceUsage::default(); resource_inventory::FAMILY_COUNT],
                target: PhysicalResourceTarget::ChildBatch,
                bindings: PhysicalResourceBindings(Vec::new()),
                limits: self.evidence_resource_limits(),
            }),
            Err(reason) => {
                self.resource_inventory
                    .invalidate(physical_resource_mask(), reason);
                None
            }
        }
    }

    fn physical_resource_path_within_store(&self, path: &Path) -> bool {
        path.is_absolute()
            && path.starts_with(&self.store_root)
            && self.physical_resource_path_is_owned(path)
            && !path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
    }
}

impl<'kura> TotalDiskUsageMutation<'kura> {
    // The first declaration owns the complete scope. A second one cannot erase
    // an earlier snapshot or reset a missing child's budget.
    fn classify_physical_scope(&mut self) -> bool {
        if self.physical_scope_classified {
            self.kura.resource_inventory.invalidate(
                physical_resource_mask(),
                resource_inventory::Unavailable::OwnerMismatch,
            );
            drop(self.physical_resources.take());
            return false;
        }
        self.physical_scope_classified = true;
        true
    }

    fn bind_physical_target(mut self, target: PhysicalResourceTarget) -> Self {
        if !self.classify_physical_scope() {
            return self;
        }
        let in_scope = match &target {
            PhysicalResourceTarget::Paths(paths) => paths
                .iter()
                .all(|path| self.kura.physical_resource_path_within_store(path)),
            PhysicalResourceTarget::StartupTree(root)
            | PhysicalResourceTarget::DeletedTree(root) => {
                self.kura.physical_resource_path_within_store(root)
            }
            PhysicalResourceTarget::MovedTrees {
                source,
                destination,
            } => {
                self.kura.physical_resource_path_within_store(source)
                    && self.kura.physical_resource_path_within_store(destination)
            }
            PhysicalResourceTarget::ChildBatch => true,
        };
        if let Some(resources) = self.physical_resources.take() {
            let observed = if in_scope {
                resources.bind(target)
            } else {
                Err(resource_inventory::Unavailable::OwnerMismatch)
            };
            match observed {
                Ok(resources) => self.physical_resources = Some(resources),
                Err(reason) => self
                    .kura
                    .resource_inventory
                    .invalidate(physical_resource_mask(), reason),
            }
        }
        self
    }

    /// Count one bounded startup namespace while its existing recovery owner is locked.
    fn with_startup_resource_tree(self, root: &Path) -> Self {
        self.bind_physical_target(PhysicalResourceTarget::StartupTree(root.to_path_buf()))
    }

    /// Observe both disjoint trees around a move, including classification changes.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect retained lane retirement to physical tree accounting; preserve original mutation/refund ownership through move and deletion"
        )
    )]
    fn with_resource_tree_move(self, source: &Path, destination: &Path) -> Self {
        self.bind_physical_target(PhysicalResourceTarget::MovedTrees {
            source: source.to_path_buf(),
            destination: destination.to_path_buf(),
        })
    }

    /// Count the exact authenticated retirement tree whose removal must complete.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect retained lane retirement to physical tree accounting; preserve original mutation/refund ownership through move and deletion"
        )
    )]
    fn removing_resource_tree(self, root: &Path) -> Self {
        self.bind_physical_target(PhysicalResourceTarget::DeletedTree(root.to_path_buf()))
    }

    /// Bind the complete file set before this operation's first filesystem mutation.
    pub(crate) fn with_resource_paths(self, paths: Vec<PathBuf>) -> Self {
        self.bind_physical_target(PhysicalResourceTarget::Paths(paths))
    }

    /// Require exactly this many bounded child publications under the outer owner.
    pub(crate) fn with_resource_children(mut self, expected_children: usize) -> Self {
        if self.classify_physical_scope() {
            self.physical_children_remaining = Some(expected_children);
        }
        self
    }

    /// Borrow the batch owner for one exact physical file set.
    pub(crate) fn resource_child(&mut self, paths: Vec<PathBuf>) -> ResourceChild<'_, 'kura> {
        let mut resources = None;
        if self.physical_resources.is_some()
            && self
                .physical_children_remaining
                .is_some_and(|remaining| remaining != 0)
            && paths
                .iter()
                .all(|path| self.kura.physical_resource_path_within_store(path))
        {
            if let Some(child) = self.kura.begin_physical_resource_mutation() {
                match child.bind(PhysicalResourceTarget::Paths(paths)) {
                    Ok(child) => resources = Some(child),
                    Err(reason) => self
                        .kura
                        .resource_inventory
                        .invalidate(physical_resource_mask(), reason),
                }
            }
        } else {
            self.kura.resource_inventory.invalidate(
                physical_resource_mask(),
                resource_inventory::Unavailable::OwnerMismatch,
            );
        }
        ResourceChild {
            owner: self,
            resources,
        }
    }

    /// Publish completed physical recovery while requiring the old disk-cache rescan.
    pub(crate) fn finish_resources_before_disk_rescan(mut self) {
        self.publish_physical_resources();
    }

    fn publish_physical_resources(&mut self) -> bool {
        if self.physical_scope_classified
            && self
                .physical_children_remaining
                .is_none_or(|remaining| remaining == 0)
        {
            if let Some(resources) = self.physical_resources.take() {
                match resources.finish() {
                    Ok(()) => return true,
                    Err(reason) => self
                        .kura
                        .resource_inventory
                        .invalidate(physical_resource_mask(), reason),
                }
            }
        }
        false
    }

    /// Borrow one parent slot for a nested batch without observing its paths twice.
    pub(crate) fn resource_batch(
        &mut self,
        expected_children: usize,
    ) -> ResourceBatchChild<'_, 'kura> {
        let may_discharge = self.physical_resources.is_some()
            && self
                .physical_children_remaining
                .is_some_and(|remaining| remaining != 0);
        if !may_discharge {
            self.kura.resource_inventory.invalidate(
                physical_resource_mask(),
                resource_inventory::Unavailable::OwnerMismatch,
            );
        }
        let nested = self
            .kura
            .begin_total_disk_usage_mutation()
            .with_resource_children(expected_children);
        ResourceBatchChild {
            owner: self,
            nested,
            may_discharge,
        }
    }
}

/// A nested declared batch owns no additional file snapshot or lookup associations.
#[must_use]
pub(crate) struct ResourceBatchChild<'guard, 'kura> {
    owner: &'guard mut TotalDiskUsageMutation<'kura>,
    nested: TotalDiskUsageMutation<'kura>,
    may_discharge: bool,
}

#[cfg(test)]
impl<'kura> ResourceBatchChild<'_, 'kura> {
    /// Access only this nested batch's exact child declarations.
    pub(crate) fn guard(&mut self) -> &mut TotalDiskUsageMutation<'kura> {
        &mut self.nested
    }
}

impl ResourceBatchChild<'_, '_> {
    /// Discharge one parent slot only after every nested child has completed.
    pub(crate) fn finish(mut self) {
        if self.may_discharge
            && self.nested.physical_children_remaining == Some(0)
            && self.nested.publish_physical_resources()
        {
            self.nested.published = true;
            if let Some(remaining) = self.owner.physical_children_remaining.as_mut() {
                if let Some(next) = remaining.checked_sub(1) {
                    *remaining = next;
                    return;
                }
            }
            self.owner.kura.resource_inventory.invalidate(
                physical_resource_mask(),
                resource_inventory::Unavailable::Arithmetic,
            );
        }
    }
}

/// One lexically owned child; an incomplete child leaves the batch unavailable.
#[must_use]
pub(crate) struct ResourceChild<'guard, 'kura> {
    owner: &'guard mut TotalDiskUsageMutation<'kura>,
    resources: Option<PhysicalResourceMutation<'kura>>,
}

impl ResourceChild<'_, '_> {
    /// Publish one child's complete physical delta and discharge exactly one child.
    pub(crate) fn finish(mut self) {
        if let Some(resources) = self.resources.take() {
            match resources.finish() {
                Ok(()) => {
                    if let Some(remaining) = self.owner.physical_children_remaining.as_mut() {
                        if let Some(next) = remaining.checked_sub(1) {
                            *remaining = next;
                            return;
                        }
                    }
                    self.owner.kura.resource_inventory.invalidate(
                        physical_resource_mask(),
                        resource_inventory::Unavailable::Arithmetic,
                    );
                }
                Err(reason) => self
                    .owner
                    .kura
                    .resource_inventory
                    .invalidate(physical_resource_mask(), reason),
            }
        }
    }
}

// TotalDiskUsageMutation owns these physical-resource guards and publishes only
// a fully classified scope with every declared child completed. Startup re-audit
// initializes all physical families together after validating the declared
// Kura-owned trees, root files and bounded process-generation residue. Delegated
// Sumeragi WAL, body and Certified-Serve stores have independent writers and are
// intentionally outside that inventory; new Kura writers must bind their exact
// owned scope before mutation or leave the affected families unavailable.
