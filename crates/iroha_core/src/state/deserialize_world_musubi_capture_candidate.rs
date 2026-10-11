//! Three exact semantic table readers on one validated native World borrow.
//!
//! Key/value codecs use literal schemas and bounded streaming; retained key,
//! staging, lookup and ordered-node backing keep the original allocation pool.
//! This scoped capture provides neither complete State authority nor finality.

use super::*;
use crate::state::authority_registry::leaf::{
    CanonicalTablePairedSnapshot, LeafError, LeafLimits, RetainedSemanticError,
    RetainedSemanticRows,
};

#[cfg(test)]
use crate::state::authority_registry::leaf::CanonicalTableLeafSet;

/// Closed semantic tables whose independently authoritative fields are reviewed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) enum MusubiSemanticTable {
    /// Archive anchor and independent availability revision.
    Availability,
    /// Independent revision of a source-checked release selection.
    Resolver,
    /// Independent revision of a source-checked package selection.
    Directory,
}

impl MusubiSemanticTable {
    /// Exact declared table identity; callers cannot supply another spelling.
    pub(in crate::state) const fn id(self) -> &'static str {
        match self {
            Self::Availability => "world.musubi_archive_availability",
            Self::Resolver => "world.musubi_resolver_index",
            Self::Directory => "world.musubi_public_directory",
        }
    }
}

impl<W: MusubiObservationCut> ValidatedMusubiSource<'_, W> {
    /// Read only the validated cut and copy the selected authority projection.
    pub(in crate::state) fn capture_table(
        &self,
        table: MusubiSemanticTable,
        limits: LeafLimits,
    ) -> Result<CanonicalTablePairedSnapshot, LeafError> {
        match table {
            MusubiSemanticTable::Availability => RetainedSemanticRows::once(
                table.id(),
                "iroha:state:musubi-availability-authority:v1",
                limits,
                self.execution_budget(),
                || self.world.source_musubi_archive_availability().iter(),
                MusubiAvailabilityAuthorityV1::from_record,
            )?
            .finish_once(),
            MusubiSemanticTable::Resolver => RetainedSemanticRows::once(
                table.id(),
                "iroha:state:musubi-resolver-authority:v1",
                limits,
                self.execution_budget(),
                || self.world.source_musubi_resolver_index().iter(),
                MusubiResolverAuthorityV1::from_record,
            )?
            .finish_once(),
            MusubiSemanticTable::Directory => RetainedSemanticRows::once(
                table.id(),
                "iroha:state:musubi-directory-authority:v1",
                limits,
                self.execution_budget(),
                || self.world.source_musubi_public_directory().iter(),
                MusubiDirectoryAuthorityV1::from_record,
            )?
            .finish_once(),
        }
    }

    /// Retain the exact validated availability iterator and original refund scope.
    /// Refusal keeps pending canonical rows and completed trees in this operation.
    /// TODO: the StatePublication semantic-plan producer must supply this actual
    /// immutable cut and its original scope; this borrows no new State authority.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect retained semantic materializers to the StatePublication semantic-plan producer"
        )
    )]
    pub(in crate::state) fn retain_availability_capture<'capture>(
        &'capture self,
        limits: LeafLimits,
        scope: &iroha_allocation::OwnedAllocationScope,
        work_limit: usize,
    ) -> Result<
        RetainedSemanticRows<
            'capture,
            ArchiveId,
            MusubiArchiveAvailabilityV1,
            MusubiAvailabilityAuthorityV1,
            impl ExactSizeIterator<Item = (&'capture ArchiveId, &'capture MusubiArchiveAvailabilityV1)>,
        >,
        RetainedSemanticError,
    > {
        RetainedSemanticRows::new(
            MusubiSemanticTable::Availability.id(),
            "iroha:state:musubi-availability-authority:v1",
            limits,
            self.execution_budget(),
            (scope, work_limit),
            || self.world.source_musubi_archive_availability().iter(),
            MusubiAvailabilityAuthorityV1::from_record,
        )
    }

    /// Retain the exact validated resolver iterator and original refund scope.
    /// Refusal keeps pending canonical rows and completed trees in this operation.
    /// TODO: the StatePublication semantic-plan producer must supply this actual
    /// immutable cut and its original scope; this borrows no new State authority.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect retained semantic materializers to the StatePublication semantic-plan producer"
        )
    )]
    pub(in crate::state) fn retain_resolver_capture<'capture>(
        &'capture self,
        limits: LeafLimits,
        scope: &iroha_allocation::OwnedAllocationScope,
        work_limit: usize,
    ) -> Result<
        RetainedSemanticRows<
            'capture,
            MusubiReleaseIdV1,
            MusubiResolverReleaseRowV1,
            MusubiResolverAuthorityV1,
            impl ExactSizeIterator<
                Item = (
                    &'capture MusubiReleaseIdV1,
                    &'capture MusubiResolverReleaseRowV1,
                ),
            >,
        >,
        RetainedSemanticError,
    > {
        RetainedSemanticRows::new(
            MusubiSemanticTable::Resolver.id(),
            "iroha:state:musubi-resolver-authority:v1",
            limits,
            self.execution_budget(),
            (scope, work_limit),
            || self.world.source_musubi_resolver_index().iter(),
            MusubiResolverAuthorityV1::from_record,
        )
    }

    /// Retain the exact validated directory iterator and original refund scope.
    /// Refusal keeps pending canonical rows and completed trees in this operation.
    /// TODO: the StatePublication semantic-plan producer must supply this actual
    /// immutable cut and its original scope; this borrows no new State authority.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect retained semantic materializers to the StatePublication semantic-plan producer"
        )
    )]
    pub(in crate::state) fn retain_directory_capture<'capture>(
        &'capture self,
        limits: LeafLimits,
        scope: &iroha_allocation::OwnedAllocationScope,
        work_limit: usize,
    ) -> Result<
        RetainedSemanticRows<
            'capture,
            MusubiPackageSelectorV1,
            MusubiOrderedPackageEntryV1,
            MusubiDirectoryAuthorityV1,
            impl ExactSizeIterator<
                Item = (
                    &'capture MusubiPackageSelectorV1,
                    &'capture MusubiOrderedPackageEntryV1,
                ),
            >,
        >,
        RetainedSemanticError,
    > {
        RetainedSemanticRows::new(
            MusubiSemanticTable::Directory.id(),
            "iroha:state:musubi-directory-authority:v1",
            limits,
            self.execution_budget(),
            (scope, work_limit),
            || self.world.source_musubi_public_directory().iter(),
            MusubiDirectoryAuthorityV1::from_record,
        )
    }

    /// Admit output rows before allocating any tree; source validation has its own policy.
    pub(in crate::state) fn admit_table_rows(
        &self,
        table: MusubiSemanticTable,
        limits: LeafLimits,
        remaining_rows: u64,
    ) -> Result<(), LeafError> {
        if limits.max_tables == 0 {
            return Err(LeafError::TableLimit);
        }
        let rows = match table {
            MusubiSemanticTable::Availability => {
                self.world.source_musubi_archive_availability().len()
            }
            MusubiSemanticTable::Resolver => self.world.source_musubi_resolver_index().len(),
            MusubiSemanticTable::Directory => self.world.source_musubi_public_directory().len(),
        };
        let rows = u64::try_from(rows).map_err(|_| LeafError::RowLimit)?;
        if rows > limits.max_rows || rows > remaining_rows {
            return Err(LeafError::RowLimit);
        }
        Ok(())
    }

    /// Test the complete semantic group on the same retained borrow and pool.
    #[cfg(test)]
    fn capture_tables_candidate(
        &self,
        limits: [LeafLimits; 3],
        max_total_rows: u64,
    ) -> Result<[CanonicalTablePairedSnapshot; 3], LeafError> {
        let rows = [
            self.world.source_musubi_archive_availability().len(),
            self.world.source_musubi_resolver_index().len(),
            self.world.source_musubi_public_directory().len(),
        ];
        let mut remaining = max_total_rows;
        for ((table, limit), rows) in SEMANTIC_TABLES.into_iter().zip(limits).zip(rows) {
            self.admit_table_rows(table, limit, remaining)?;
            remaining = remaining
                .checked_sub(u64::try_from(rows).map_err(|_| LeafError::RowLimit)?)
                .ok_or(LeafError::RowLimit)?;
        }
        Ok([
            self.capture_table(SEMANTIC_TABLES[0], limits[0])?,
            self.capture_table(SEMANTIC_TABLES[1], limits[1])?,
            self.capture_table(SEMANTIC_TABLES[2], limits[2])?,
        ])
    }
}

#[cfg(test)]
const SEMANTIC_TABLES: [MusubiSemanticTable; 3] = [
    MusubiSemanticTable::Availability,
    MusubiSemanticTable::Resolver,
    MusubiSemanticTable::Directory,
];
#[cfg(test)]
const TABLES: [&str; 3] = [
    SEMANTIC_TABLES[0].id(),
    SEMANTIC_TABLES[1].id(),
    SEMANTIC_TABLES[2].id(),
];

#[cfg(test)]
mod tests {
    use super::super::super::{SourceWorkLimits, validate};
    use super::*;
    use crate::state::deserialize::decode_tests::seeded_musubi_publication_snapshot;
    use iroha_data_model::musubi::source_work::SourceGeometryLimits;

    fn work() -> SourceWorkLimits {
        SourceWorkLimits {
            geometry: SourceGeometryLimits {
                elements: 1_000_000,
                variable_bytes: 1_000_000,
            },
            table_pass_rows: 1_000_000,
            lookup_index_entries: 1_000_000,
            model_operations: 1_000_000,
            signature_checks: 1_000_000,
        }
    }
    fn leaves() -> [LeafLimits; 3] {
        [LeafLimits {
            max_tables: 1,
            max_rows: 1,
            max_payload_bytes: 4096,
            max_ordered_table_bytes: 64 * 1024,
            max_streamed_value_bytes: 64 * 1024,
        }; 3]
    }

    #[test]
    fn actual_validated_rows_build_three_distinct_retained_pairs_and_paths() {
        let (world, release, archive, selector) = seeded_musubi_publication_snapshot();
        let view = world.view();
        let budget = AllocationBudget::new(8 * 1024 * 1024);
        let source = validate(&view, &budget, work()).unwrap();
        let nodes = source.capture_tables_candidate(leaves(), 3).unwrap();
        for (node, id) in nodes.iter().zip(TABLES) {
            assert_eq!(node.table_id(), id);
            assert_eq!(node.row_count(), 1);
        }
        assert_ne!(nodes[0].root(), nodes[1].root());
        assert_ne!(nodes[1].root(), nodes[2].root());
        macro_rules! check {
            ($index:expr, $key:expr) => {
                let node = &nodes[$index];
                let proof = node.prove_lookup(TABLES[$index], $key).unwrap();
                assert!(
                    CanonicalTableLeafSet::verify_paired_lookup(
                        TABLES[$index],
                        leaves()[$index],
                        &node.root(),
                        &node.ordered_root(),
                        $key,
                        &proof,
                    )
                    .unwrap()
                    .is_some()
                );
            };
        }
        check!(0, &archive);
        check!(1, &release);
        check!(2, &selector);
        assert!(budget.reserved_bytes() > 0);
        // Native storage publication does not alter the token's retained source cut.
        let mut changed = view.musubi_resolver_index().get(&release).unwrap().clone();
        changed.index_revision = 0;
        let mut update = world.musubi_resolver_index.block();
        update.insert(release, changed);
        update.commit();
        assert!(validate(&world.view(), &budget, work()).is_err());
        let same = source.capture_tables_candidate(leaves(), 3).unwrap();
        for (before, after) in nodes.iter().zip(&same) {
            assert_eq!(before.root(), after.root());
        }
        drop(same);
        drop(nodes);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn exact_authority_changes_alter_all_three_roots_after_full_revalidation() {
        let (world, release, archive, selector) = seeded_musubi_publication_snapshot();
        let budget = AllocationBudget::new(8 * 1024 * 1024);
        let old = {
            let view = world.view();
            let source = validate(&view, &budget, work()).unwrap();
            source.capture_tables_candidate(leaves(), 3).unwrap()
        };
        // Resolver and directory revisions need not equal the availability revision.
        // Advance the source revision instead of assuming the seed starts at one.
        let next_revision = world
            .musubi_resolver_index_revision
            .view()
            .get()
            .get()
            .checked_add(1)
            .expect("fixture revision can advance");
        let mut block = world.block();
        let availability = block.musubi_archive_availability.get_mut(&archive).unwrap();
        let old_availability = MusubiAvailabilityAuthorityV1::from_record(availability);
        availability.index_revision = next_revision;
        availability.finalized_block_hash[0] ^= 1;
        assert_ne!(
            old_availability,
            MusubiAvailabilityAuthorityV1::from_record(availability)
        );
        let availability = *availability;
        let resolver = block.musubi_resolver_index.get_mut(&release).unwrap();
        let old_resolver = MusubiResolverAuthorityV1::from_record(resolver);
        resolver.index_revision = next_revision;
        resolver.selection.storage = availability;
        assert_ne!(
            old_resolver,
            MusubiResolverAuthorityV1::from_record(resolver)
        );
        let directory = block.musubi_public_directory.get_mut(&selector).unwrap();
        let old_directory = MusubiDirectoryAuthorityV1::from_record(directory);
        directory.index_revision = next_revision;
        assert_ne!(
            old_directory,
            MusubiDirectoryAuthorityV1::from_record(directory)
        );
        *block.musubi_resolver_index_revision.get_mut() =
            MusubiResolverIndexRevisionV1::new(next_revision).unwrap();
        block.commit();
        let view = world.view();
        let source = validate(&view, &budget, work()).unwrap();
        let changed = source.capture_tables_candidate(leaves(), 3).unwrap();
        for ((old, changed), table) in old.iter().zip(&changed).zip(TABLES) {
            assert_ne!(old.root(), changed.root(), "{table}: paired root");
            assert_ne!(
                old.lookup_root(),
                changed.lookup_root(),
                "{table}: lookup root"
            );
            assert_ne!(
                old.ordered_root(),
                changed.ordered_root(),
                "{table}: ordered root"
            );
        }
        drop(changed);
        drop(old);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn aggregate_and_each_table_count_are_admitted_before_tree_allocations() {
        let (world, _, _, _) = seeded_musubi_publication_snapshot();
        let view = world.view();
        let budget = AllocationBudget::new(8 * 1024 * 1024);
        let source = validate(&view, &budget, work()).unwrap();
        let peak = budget.peak_reserved_bytes();
        assert!(matches!(
            source.capture_tables_candidate(leaves(), 2),
            Err(LeafError::RowLimit)
        ));
        for index in 0..3 {
            let mut short = leaves();
            short[index].max_rows = 0;
            assert!(matches!(
                source.capture_tables_candidate(short, 3),
                Err(LeafError::RowLimit)
            ));
            short = leaves();
            short[index].max_tables = 0;
            assert!(matches!(
                source.capture_tables_candidate(short, 3),
                Err(LeafError::TableLimit)
            ));
        }
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(budget.peak_reserved_bytes(), peak);
    }

    #[test]
    fn later_table_failure_releases_every_earlier_owner_from_the_original_pool() {
        let (world, _, _, _) = seeded_musubi_publication_snapshot();
        let view = world.view();
        let budget = AllocationBudget::new(8 * 1024 * 1024);
        let source = validate(&view, &budget, work()).unwrap();
        let mut short = leaves();
        short[2].max_streamed_value_bytes = 1;
        assert!(source.capture_tables_candidate(short, 3).is_err());
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(0);
        assert!(source.capture_tables_candidate(leaves(), 3).is_err());
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(8 * 1024 * 1024);
        let nodes = source.capture_tables_candidate(leaves(), 3).unwrap();
        drop(nodes);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn empty_validated_cut_has_explicit_schema_bound_roots_without_fabricated_rows() {
        let world = World::new();
        let view = world.view();
        let budget = AllocationBudget::new(8 * 1024 * 1024);
        let source = validate(&view, &budget, work()).unwrap();
        let nodes = source.capture_tables_candidate(leaves(), 0).unwrap();
        for (node, table) in nodes.iter().zip(TABLES) {
            assert_eq!(node.table_id(), table);
            assert_eq!(node.row_count(), 0);
        }
        assert_ne!(nodes[0].root(), nodes[1].root());
        assert_ne!(nodes[1].root(), nodes[2].root());
        drop(nodes);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[cfg(test)]
#[path = "deserialize_world_musubi_retained_capture_tests.rs"]
mod retained_tests;
