//! Same-cut directory revision checks with retained, caller-funded token scratch.
//!
//! Directory keys order namespace/name, while resolver keys order package/version.
//! The single checker sorts original borrowed references or frozen row ordinals.
//! A resumable heap sort retains every successful swap; no source key is cloned.
//! This prerequisite never grants complete State or publication authority.

use super::*;
use crate::state::deserialize::{
    musubi_source_read::{MusubiRead, ReadFailure, try_next_if_row},
    musubi_universal::cursor::{BorrowedUniversalSource, UniversalSource},
};
use iroha_allocation::{ChargedBuffer, ChargedBufferError};
use std::cmp::Ordering;

/// Scalar progress of the original directory sort and ordered revision merge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) struct DirectoryProgress {
    /// Capture, heap-build, heap-sort, merge, or completed phase.
    pub phase: u8,
    /// Number of original row tokens whose scratch backing is retained.
    pub captured: usize,
    /// Next exact directory token in the package-ordered merge.
    pub directory: usize,
    /// Number of original resolver rows consumed by the merge.
    pub resolver: usize,
    /// Whether every original directory revision has been checked.
    pub complete: bool,
}

/// One charged sort and scalar cursor over the original immutable image.
pub(in crate::state) struct DirectoryValidation<T> {
    entries: Option<ChargedBuffer<T>>,
    phase: u8,
    build_next: usize,
    sort_end: usize,
    sift_root: Option<usize>,
    sift_child: Option<usize>,
    directory: usize,
    resolver: usize,
    merge_stage: u8,
    maximum: Option<u64>,
    last_directory: Option<T>,
    rejected: Option<ProjectionRejection>,
}
impl<T: Copy> DirectoryValidation<T> {
    /// Start without allocating; the first advance admits its exact scratch.
    pub(in crate::state) fn new() -> Self {
        Self {
            entries: None,
            phase: 0,
            build_next: 0,
            sort_end: 0,
            sift_root: None,
            sift_child: None,
            directory: 0,
            resolver: 0,
            merge_stage: 0,
            maximum: None,
            last_directory: None,
            rejected: None,
        }
    }
    /// Observe only original cursor facts, without resolving any source row.
    pub(in crate::state) fn progress(&self) -> DirectoryProgress {
        DirectoryProgress {
            phase: self.phase,
            captured: self
                .entries
                .as_ref()
                .map_or(0, |entries| entries.as_slice().len()),
            directory: self.directory,
            resolver: self.resolver,
            complete: self.phase == 4,
        }
    }
    /// Continue the unchanged directory-revision predicate on the same image.
    pub(in crate::state) fn advance<S: UniversalSource<Directory = T>>(
        &mut self,
        source: &S,
        budget: &AllocationBudget,
    ) -> Result<(), ReadFailure<S::Error, ExecutionAttemptError<ProjectionRejection>>> {
        if let Some(original) = self.rejected {
            return Err(original.into());
        }
        if self.phase == 4 {
            return Ok(());
        }
        let result = self.advance_inner(source, budget);
        if let Err(ReadFailure::Predicate(ExecutionAttemptError::Rejected(original))) = &result {
            self.rejected = Some(*original);
        }
        result
    }
    fn advance_inner<S: UniversalSource<Directory = T>>(
        &mut self,
        source: &S,
        budget: &AllocationBudget,
    ) -> Result<(), ReadFailure<S::Error, ExecutionAttemptError<ProjectionRejection>>> {
        if self.phase == 0 {
            if self.entries.is_none() {
                self.entries = Some(
                    ChargedBuffer::new(
                        source
                            .world()
                            .musubi_public_directory_len()
                            .map_err(ReadFailure::Source)?,
                        budget,
                    )
                    .map_err(|error| {
                        ExecutionAttemptError::Deferred(match error {
                            ChargedBufferError::Admission(refusal) => refusal.into(),
                            ChargedBufferError::Allocator { .. } => {
                                ivm::error::ExecutionDeferral::AllocationUnavailable.into()
                            }
                        })
                    })?,
                );
            }
            let entries = self
                .entries
                .as_mut()
                .expect("original directory scratch admitted");
            for original in source
                .directories()
                .map_err(ReadFailure::Source)?
                .skip(entries.as_slice().len())
            {
                entries.push_reserved(original.map_err(ReadFailure::Source)?);
            }
            self.sort_end = entries.as_slice().len();
            self.build_next = self.sort_end / 2;
            self.phase = 1;
        }
        if self.phase == 1 {
            while self.build_next != 0 || self.sift_root.is_some() {
                if self.sift_root.is_none() {
                    self.build_next -= 1;
                    self.sift_root = Some(self.build_next);
                }
                self.sift(source).map_err(ReadFailure::Source)?;
            }
            self.phase = 2;
        }
        if self.phase == 2 {
            while self.sort_end > 1 || self.sift_root.is_some() {
                if self.sift_root.is_none() {
                    self.entries
                        .as_mut()
                        .expect("original directory scratch")
                        .as_mut_slice()
                        .swap(0, self.sort_end - 1);
                    self.sort_end -= 1;
                    self.sift_root = Some(0);
                }
                self.sift(source).map_err(ReadFailure::Source)?;
            }
            self.phase = 3;
        }
        if self.phase == 3 {
            // Reacquire only this original iterator and skip its retained prefix;
            // all rows consumed during this attempt share the same cursor.
            let mut rows = source
                .world()
                .musubi_resolver_index_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.resolver)
                .peekable();
            let entries = self
                .entries
                .as_ref()
                .expect("original directory scratch")
                .as_slice();
            while self.directory < entries.len() {
                let token = entries[self.directory];
                let entry = source.directory(token).map_err(ReadFailure::Source)?;
                if self.merge_stage == 0 {
                    if let Some(previous) = self.last_directory
                        && source
                            .compare_directories(previous, token)
                            .map_err(ReadFailure::Source)?
                            == Ordering::Equal
                    {
                        self.merge_stage = 3;
                    } else {
                        self.maximum = None;
                        self.merge_stage = 1;
                    }
                }
                if self.merge_stage == 1 {
                    while try_next_if_row(&mut rows, |(release, _)| {
                        source
                            .compare_package_keys(&release.package, &entry.package)
                            .map(|order| order == Ordering::Less)
                    })
                    .map_err(ReadFailure::Source)?
                    .is_some()
                    {
                        self.resolver += 1;
                    }
                    self.merge_stage = 2;
                }
                if self.merge_stage == 2 {
                    while let Some((_, row)) = try_next_if_row(&mut rows, |(release, _)| {
                        source
                            .compare_package_keys(&release.package, &entry.package)
                            .map(|order| order == Ordering::Equal)
                    })
                    .map_err(ReadFailure::Source)?
                    {
                        self.maximum = Some(
                            self.maximum
                                .map_or(row.index_revision, |old| old.max(row.index_revision)),
                        );
                        self.resolver += 1;
                    }
                    self.merge_stage = 3;
                }
                if self
                    .maximum
                    .is_some_and(|revision| entry.index_revision < revision)
                {
                    return Err(ProjectionRejection::new(
                        ProjectionTable::PublicDirectory,
                        "directory entry predates its package resolver rows",
                    )
                    .into());
                }
                self.last_directory = Some(token);
                self.directory += 1;
                self.merge_stage = 0;
            }
            self.phase = 4;
        }
        Ok(())
    }
    fn sift<S: UniversalSource<Directory = T>>(&mut self, source: &S) -> Result<(), S::Error> {
        while let Some(root) = self.sift_root {
            // A root with children is strictly below end/2, so 2*root+1 fits
            // usize. Check that condition before constructing the child index.
            if root >= self.sort_end / 2 {
                // For even end the last internal node is end/2-1; for odd end
                // the same exclusive bound applies.
                self.sift_root = None;
                break;
            }
            let entries = self
                .entries
                .as_mut()
                .expect("original directory scratch")
                .as_mut_slice();
            let child = if let Some(child) = self.sift_child {
                child
            } else {
                let mut child = root * 2 + 1;
                if child + 1 < self.sort_end
                    && source.compare_directories(entries[child], entries[child + 1])?
                        == Ordering::Less
                {
                    child += 1;
                }
                self.sift_child = Some(child);
                child
            };
            if source.compare_directories(entries[root], entries[child])? != Ordering::Less {
                self.sift_root = None;
                self.sift_child = None;
                break;
            }
            entries.swap(root, child);
            self.sift_root = Some(child);
            self.sift_child = None;
        }
        Ok(())
    }
}

pub(super) fn validate_directory_revisions<W: MusubiRead>(
    world: &W,
    execution_budget: &AllocationBudget,
) -> Result<(), ReadFailure<W::Error, ExecutionAttemptError<ProjectionRejection>>> {
    let source = BorrowedUniversalSource(world);
    DirectoryValidation::new().advance(&source, execution_budget)
}
