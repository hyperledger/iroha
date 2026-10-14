//! Resumable owner for the single universal projection predicate.
//!
//! Ordinary immutable readers retain borrowed original keys. The frozen reader
//! retains only ordinals into its already admitted original row descriptors.
//! Neither representation copies a package, release, key or resolver row. The
//! original charged accumulator and completed semantic rows survive refusal.
//! Exact native lookup bounds and key geometry are retained at each fixed query site.

use super::*;
use iroha_data_model::musubi::{
    MusubiOrderedPackageEntryV1, MusubiPackageIdV1, MusubiPackageRecordV1, MusubiReleaseIdV1,
    MusubiResolverReleaseRowV1, MusubiVersionV1,
};
use std::cmp::Ordering;

/// Access to original row identities without imposing a borrow on retained scratch.
pub(in crate::state) trait UniversalSource {
    /// Original physical source refusal.
    type Error;
    /// Exact retained package-key identity.
    type Package: Copy;
    /// Exact retained resolver-version identity.
    type Version: Copy;
    /// Exact retained directory-entry identity.
    type Directory: Copy;
    /// The same immutable original source for cross-table predicates.
    fn world(&self) -> &impl MusubiRead<Error = Self::Error>;
    /// Original package identities and rows in canonical order.
    fn packages(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(Self::Package, &MusubiPackageIdV1, &MusubiPackageRecordV1), Self::Error>,
        >,
        Self::Error,
    >;
    /// Original resolver identities and rows in canonical order.
    fn resolvers(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<
                (
                    Self::Version,
                    &MusubiReleaseIdV1,
                    &MusubiResolverReleaseRowV1,
                ),
                Self::Error,
            >,
        >,
        Self::Error,
    >;
    /// Compare the original package key without cloning or replacing it.
    fn compare_package(
        &self,
        token: Self::Package,
        key: &MusubiPackageIdV1,
    ) -> Result<Ordering, Self::Error>;
    /// Reborrow the original version identified by its retained token.
    fn version(&self, token: Self::Version) -> Result<&MusubiVersionV1, Self::Error>;
    /// Charge and compare the two borrowed original package keys.
    fn compare_package_keys(
        &self,
        left: &MusubiPackageIdV1,
        right: &MusubiPackageIdV1,
    ) -> Result<Ordering, Self::Error>;

    /// Original directory identities without a second row index.
    fn directories(
        &self,
    ) -> Result<impl ExactSizeIterator<Item = Result<Self::Directory, Self::Error>>, Self::Error>;
    /// Reborrow the original entry identified by its retained token.
    fn directory(
        &self,
        token: Self::Directory,
    ) -> Result<&MusubiOrderedPackageEntryV1, Self::Error>;
    /// Compare original directory package keys for the retained sort.
    fn compare_directories(
        &self,
        left: Self::Directory,
        right: Self::Directory,
    ) -> Result<Ordering, Self::Error>;
}

/// Call-local borrowed tokens for the same ordinary immutable source.
pub(in crate::state) struct BorrowedUniversalSource<'cut, W: MusubiRead>(
    pub(in crate::state) &'cut W,
);
impl<'cut, W: MusubiRead> UniversalSource for BorrowedUniversalSource<'cut, W> {
    type Error = W::Error;
    type Package = &'cut MusubiPackageIdV1;
    type Version = &'cut MusubiVersionV1;
    type Directory = &'cut MusubiOrderedPackageEntryV1;
    fn world(&self) -> &impl MusubiRead<Error = Self::Error> {
        self.0
    }
    fn packages(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(Self::Package, &MusubiPackageIdV1, &MusubiPackageRecordV1), Self::Error>,
        >,
        Self::Error,
    > {
        let world: &'cut W = self.0;
        Ok(world
            .musubi_packages_rows()?
            .map(|row| row.map(|(key, value)| (key, key, value))))
    }
    fn resolvers(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<
                (
                    Self::Version,
                    &MusubiReleaseIdV1,
                    &MusubiResolverReleaseRowV1,
                ),
                Self::Error,
            >,
        >,
        Self::Error,
    > {
        let world: &'cut W = self.0;
        Ok(world
            .musubi_resolver_index_rows()?
            .map(|row| row.map(|(key, value)| (&key.version, key, value))))
    }
    fn compare_package(
        &self,
        token: Self::Package,
        key: &MusubiPackageIdV1,
    ) -> Result<Ordering, Self::Error> {
        Ok(token.cmp(key))
    }
    fn version(&self, token: Self::Version) -> Result<&MusubiVersionV1, Self::Error> {
        Ok(token)
    }
    fn compare_package_keys(
        &self,
        left: &MusubiPackageIdV1,
        right: &MusubiPackageIdV1,
    ) -> Result<Ordering, Self::Error> {
        Ok(left.cmp(right))
    }

    fn directories(
        &self,
    ) -> Result<impl ExactSizeIterator<Item = Result<Self::Directory, Self::Error>>, Self::Error>
    {
        let world: &'cut W = self.0;
        Ok(world
            .musubi_public_directory_rows()?
            .map(|row| row.map(|(_, value)| value)))
    }
    fn directory(
        &self,
        token: Self::Directory,
    ) -> Result<&MusubiOrderedPackageEntryV1, Self::Error> {
        Ok(token)
    }
    fn compare_directories(
        &self,
        left: Self::Directory,
        right: Self::Directory,
    ) -> Result<Ordering, Self::Error> {
        Ok(left.package.cmp(&right.package))
    }
}

/// Read-only stage/cursor facts, not a semantic validation certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) struct UniversalProgress {
    /// Current deterministic validation pass.
    pub phase: u8,
    /// Number of completed original rows in this pass.
    pub row: usize,
    /// Completed model checks in the current resolver or directory row.
    pub resolver_step: u8,
    /// Number of original package tokens held by charged scratch.
    pub package_accumulators: usize,
    /// Whether all universal projection checks have completed.
    pub complete: bool,
}

/// Original allocation and scalar cursors for one immutable source image.
pub(in crate::state) struct UniversalValidation<P, V> {
    queries: [crate::state::deserialize::musubi_source_read::LookupCursor; 4],
    search: Option<PackageSearch>,
    cut: ProjectionCut,
    packages: Option<ChargedBuffer<PackageRevision<P, V>>>,
    phase: u8,
    row: usize,
    resolver_step: u8,
    rejected: Option<ProjectionRejection>,
}
struct PackageSearch {
    first: usize,
    end: usize,
    found: Option<usize>,
    complete: bool,
}
fn allocation_error(error: ChargedBufferError) -> ExecutionAttemptError<ProjectionRejection> {
    ExecutionAttemptError::Deferred(match error {
        ChargedBufferError::Admission(refusal) => refusal.into(),
        ChargedBufferError::Allocator { .. } => {
            ivm::error::ExecutionDeferral::AllocationUnavailable.into()
        }
    })
}
impl<P: Copy, V: Copy> UniversalValidation<P, V> {
    /// Begin with no source access or allocation.
    pub(in crate::state) fn new(cut: ProjectionCut) -> Self {
        Self {
            queries: [crate::state::deserialize::musubi_source_read::LookupCursor::new(); 4],
            search: None,
            cut,
            packages: None,
            phase: 0,
            row: 0,
            resolver_step: 0,
            rejected: None,
        }
    }
    /// Inspect the original retained cursor without resolving rows.
    pub(in crate::state) fn progress(&self) -> UniversalProgress {
        UniversalProgress {
            phase: self.phase,
            row: self.row,
            resolver_step: self.resolver_step,
            package_accumulators: self
                .packages
                .as_ref()
                .map_or(0, |rows| rows.as_slice().len()),
            complete: self.phase == 6,
        }
    }
    #[cfg(test)]
    /// Exact allocation layout used by original scratch refusal controls.
    pub(in crate::state) fn scratch_bytes_for_test(count: usize) -> usize {
        std::alloc::Layout::array::<PackageRevision<P, V>>(count)
            .unwrap()
            .size()
    }
    fn next_phase(&mut self) {
        self.phase += 1;
        self.row = 0;
        self.resolver_step = 0;
    }
    fn find_package<S: UniversalSource<Package = P, Version = V>>(
        &mut self,
        source: &S,
        key: &MusubiPackageIdV1,
    ) -> Result<Option<usize>, ReadFailure<S::Error, ExecutionAttemptError<ProjectionRejection>>>
    {
        let rows = self
            .packages
            .as_ref()
            .expect("original package scratch")
            .as_slice();
        let search = self.search.get_or_insert(PackageSearch {
            first: 0,
            end: rows.len(),
            found: None,
            complete: false,
        });
        if search.complete {
            return Ok(search.found);
        }
        while search.first < search.end {
            let middle = search.first + (search.end - search.first) / 2;
            match source
                .compare_package(rows[middle].package, key)
                .map_err(ReadFailure::Source)?
            {
                Ordering::Less => search.first = middle + 1,
                Ordering::Equal => {
                    search.found = Some(middle);
                    search.complete = true;
                    return Ok(search.found);
                }
                Ordering::Greater => search.end = middle,
            }
        }
        search.complete = true;
        Ok(None)
    }
    /// Continue the same original source, preserving scratch and successful substeps.
    pub(in crate::state) fn advance<S: UniversalSource<Package = P, Version = V>>(
        &mut self,
        source: &S,
        execution_budget: &AllocationBudget,
    ) -> Result<(), ReadFailure<S::Error, ExecutionAttemptError<ProjectionRejection>>> {
        if let Some(original) = self.rejected {
            return Err(original.into());
        }
        if self.phase == 6 {
            return Ok(());
        }
        let result = self.advance_inner(source, execution_budget);
        if let Err(ReadFailure::Predicate(ExecutionAttemptError::Rejected(original))) = &result {
            self.rejected = Some(*original);
        }
        result
    }
    fn advance_inner<S: UniversalSource<Package = P, Version = V>>(
        &mut self,
        source: &S,
        execution_budget: &AllocationBudget,
    ) -> Result<(), ReadFailure<S::Error, ExecutionAttemptError<ProjectionRejection>>> {
        const RESOLVER: ProjectionTable = ProjectionTable::ResolverIndex;
        const DIRECTORY: ProjectionTable = ProjectionTable::PublicDirectory;
        let world = source.world();
        let cut = self.cut;
        let current_revision = world.musubi_revision();
        if self.phase == 0 {
            for original_row in source
                .packages()
                .map_err(ReadFailure::Source)?
                .skip(self.row)
            {
                let (_, package_id, package) = original_row.map_err(ReadFailure::Source)?;
                package
                    .validate()
                    .map_err(|error| invalid(cut, DIRECTORY, error.reason()))?;
                if package_id != &package.package {
                    return Err(invalid(
                        cut,
                        DIRECTORY,
                        "package lookup key differs from its canonical identity",
                    )
                    .into());
                }
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                self.search = None;
            }
            self.next_phase();
        }
        // Validate all package identities before scratch admission, preserving the
        // semantic error order. Source keys and versions stay borrowed from this cut.
        if self.phase == 1 {
            if self.packages.is_none() {
                self.packages = Some(
                    ChargedBuffer::new(
                        world.musubi_packages_len().map_err(ReadFailure::Source)?,
                        execution_budget,
                    )
                    .map_err(allocation_error)?,
                );
            }
            for original_row in source
                .packages()
                .map_err(ReadFailure::Source)?
                .skip(self.row)
            {
                let (token, _, _) = original_row.map_err(ReadFailure::Source)?;
                self.packages
                    .as_mut()
                    .expect("original scratch admitted before filling")
                    .push_reserved(PackageRevision::new(token));
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                self.search = None;
            }
            self.next_phase();
        }
        if self.phase == 2 {
            for original_row in source
                .resolvers()
                .map_err(ReadFailure::Source)?
                .skip(self.row)
            {
                let (version_token, release_id, row) = original_row.map_err(ReadFailure::Source)?;
                if self.resolver_step == 0 {
                    row.validate()
                        .map_err(|error| invalid(cut, RESOLVER, error.reason()))?;
                    self.resolver_step = 1;
                }
                let release = world
                    .musubi_releases_get_retained(release_id, &mut self.queries[0])
                    .map_err(ReadFailure::Source)?
                    .ok_or_else(|| {
                        invalid(cut, RESOLVER, "resolver row references a missing release")
                    })?;
                if self.resolver_step == 1 {
                    release
                        .validate()
                        .map_err(|error| invalid(cut, RESOLVER, error.reason()))?;
                    self.resolver_step = 2;
                }
                if release_id != &release.manifest.release
                    || world
                        .musubi_packages_get_retained(&release_id.package, &mut self.queries[1])
                        .map_err(ReadFailure::Source)?
                        .is_none()
                {
                    return Err(invalid(
                        cut,
                        RESOLVER,
                        "resolver row's release identity or package source is missing",
                    )
                    .into());
                }
                let archive = world
                    .musubi_archives_get_retained(
                        &release.manifest.archive_id,
                        &mut self.queries[2],
                    )
                    .map_err(ReadFailure::Source)?
                    .ok_or_else(|| {
                        invalid(cut, RESOLVER, "resolver row references a missing archive")
                    })?;
                let storage = world
                    .musubi_archive_availability_get_retained(
                        &release.manifest.archive_id,
                        &mut self.queries[3],
                    )
                    .map_err(ReadFailure::Source)?
                    .ok_or_else(|| {
                        invalid(
                            cut,
                            RESOLVER,
                            "resolver row is missing its authoritative storage projection",
                        )
                    })?;
                if release_id != &row.release
                    || row.release_digest != release.release_digest
                    || row.archive_id != release.manifest.archive_id
                    || row.source_digest != archive.commitment.source_tree_digest
                    || row.interface_digest != release.manifest.interface_digest
                    || row.abi != release.manifest.abi
                    || row.dependencies.as_slice() != release.manifest.dependencies.as_slice()
                    || row.selection.yank != release.yank
                    || row.selection.governance != release.artifact_governance
                    || row.selection.storage != *storage
                    || row.index_revision > current_revision
                {
                    return Err(invalid(
                        cut,
                        RESOLVER,
                        "resolver row diverges from authoritative release/archive projections",
                    )
                    .into());
                }
                let index = self
                    .find_package(source, &release_id.package)?
                    .ok_or_else(|| {
                        invalid(cut, RESOLVER, "resolver row references a missing package")
                    })?;
                let revision = &mut self
                    .packages
                    .as_mut()
                    .expect("original package scratch")
                    .as_mut_slice()[index];
                let latest = revision
                    .latest
                    .map(|token| source.version(token))
                    .transpose()
                    .map_err(ReadFailure::Source)?;
                revision.observe(
                    version_token,
                    row,
                    latest.is_none_or(|version| version < &release_id.version),
                );
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                self.search = None;
                self.resolver_step = 0;
            }
            self.next_phase();
        }
        if self.phase == 3 {
            for original_row in world
                .musubi_releases_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.row)
            {
                let (release_id, _) = original_row.map_err(ReadFailure::Source)?;
                if world
                    .musubi_resolver_index_get_retained(release_id, &mut self.queries[0])
                    .map_err(ReadFailure::Source)?
                    .is_none()
                {
                    return Err(invalid(
                        cut,
                        RESOLVER,
                        "release is missing its exact resolver row",
                    )
                    .into());
                }
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                self.search = None;
            }
            self.next_phase();
        }
        if self.phase == 4 {
            for original_row in world
                .musubi_public_directory_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.row)
            {
                let (selector, entry) = original_row.map_err(ReadFailure::Source)?;
                if self.resolver_step == 0 {
                    entry
                        .validate()
                        .map_err(|error| invalid(cut, DIRECTORY, error.reason()))?;
                    self.resolver_step = 1;
                }
                let package = world
                    .musubi_packages_get_retained(&entry.package, &mut self.queries[0])
                    .map_err(ReadFailure::Source)?
                    .ok_or_else(|| {
                        invalid(
                            cut,
                            DIRECTORY,
                            "directory entry references a missing package",
                        )
                    })?;
                let index = self.find_package(source, &entry.package)?.ok_or_else(|| {
                    invalid(
                        cut,
                        DIRECTORY,
                        "directory entry references a missing package",
                    )
                })?;
                let revision = &mut self
                    .packages
                    .as_mut()
                    .expect("original package scratch")
                    .as_mut_slice()[index];
                let latest = revision
                    .latest
                    .map(|token| source.version(token))
                    .transpose()
                    .map_err(ReadFailure::Source)?;
                if selector != &entry.selector
                    || entry.selector.namespace != package.claimed_namespace
                    || entry.selector.name != entry.package.name
                    || entry.metadata_revision != package.revisions.metadata
                    || entry.latest_selectable.as_ref() != latest
                    || entry.index_revision > current_revision
                {
                    return Err(invalid(
                        cut,
                        DIRECTORY,
                        "directory entry diverges from its package and resolver rows",
                    )
                    .into());
                }
                if let Some(maximum_row_revision) = revision.maximum {
                    if entry.index_revision < maximum_row_revision {
                        return Err(invalid(
                            cut,
                            DIRECTORY,
                            "directory entry predates its package resolver rows",
                        )
                        .into());
                    }
                }
                // A validated row has exactly this package's canonical selector. Marking
                // its borrowed accumulator avoids allocating a selector for the final
                // completeness pass, including when two package IDs share a selector.
                revision.directory_present = true;
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                self.search = None;
                self.resolver_step = 0;
            }
            self.next_phase();
        }
        if self.phase == 5 {
            for revision in self
                .packages
                .as_ref()
                .expect("original package scratch")
                .as_slice()
                .iter()
                .skip(self.row)
            {
                if !revision.directory_present {
                    return Err(invalid(
                        cut,
                        DIRECTORY,
                        "package is missing its exact public-directory entry",
                    )
                    .into());
                }
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                self.search = None;
            }
            self.next_phase();
        }
        Ok(())
    }
}
