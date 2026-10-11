//! Retained structural reads of the original package current/undo pair.
//!
//! The actual State publisher owns the same field, scope, funded position buffers
//! and monotonically admitted traversal/resolve work across local refusal. These
//! raw physical rows are non-authorizing: undo alone is not the predecessor.
//! The optional fourteen-map structural owner shares the same cursor kernel.
//! The group also retains the actual staged revision pair.
//! TODO: connect the retained group predecessor descriptors to semantic read-plan
//! admission and the semantic
//! materializer before full-State use.

use super::*;
use iroha_allocation::{ChargedBuffer, ChargedBufferError, OwnedAllocationScope};

type PackageKey = iroha_data_model::musubi::MusubiPackageIdV1;
type PackageValue = iroha_data_model::musubi::MusubiPackageRecordV1;

/// Exact local structural/admission cause; no physical lock wait is fabricated.
#[derive(Debug)]
pub(crate) enum RetainedPackageReadError {
    /// Only the original completely frozen, nonterminal publisher may capture.
    NotFrozen,
    /// Another source, predecessor or State generation cannot replace this cut.
    SourceChanged,
    /// An equal foreign pool/scope supplies no funding for this original State.
    ScopeIdentity,
    /// Fixed index/control backing retains its actual original refusal.
    Allocation(ChargedBufferError),
    /// The finite structural kernel cannot proceed under its unchanged ceiling.
    Work {
        used: usize,
        required: usize,
        limit: usize,
    },
    /// Checked structural geometry or a private initialized count is inconsistent.
    Geometry,
    /// The original position stage is incomplete; no semantic completion is implied.
    Incomplete,
    /// An actual outside reader still retains a paired cursor after index retirement.
    ReadersRetained,
}

/// Observation of this retained plan; counts are physical current/raw-undo rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PackageReadProgress {
    pub(crate) current: usize,
    pub(crate) undo: usize,
    pub(crate) work: usize,
    pub(crate) complete: bool,
    pub(crate) retired: bool,
}

// Every actual position/cursor/read owner precedes the scope in the outer owner.
// The one-element control buffer also prepays this retained metadata shell.
type PackageReadData = super::retained_rows::OriginalTableRead<PackageKey, PackageValue>;

pub(super) struct RetainedPackageRead {
    data: Option<ChargedBuffer<PackageReadData>>,
    scope: OwnedAllocationScope,
    generation: u64,
    work: usize,
    finished: bool,
    pub(super) retired: bool,
}

impl RetainedPackageRead {
    fn observe(&self) -> PackageReadProgress {
        let data = self.data.as_ref().map(|data| &data.as_slice()[0]);
        PackageReadProgress {
            current: data
                .and_then(|data| data.current.as_ref())
                .map_or(0, |rows| rows.as_slice().len()),
            undo: data
                .and_then(|data| data.undo.as_ref())
                .map_or(0, |rows| rows.as_slice().len()),
            work: self.work,
            complete: self.finished,
            retired: self.retired,
        }
    }

    fn advance(&mut self, limit: usize) -> Result<PackageReadProgress, RetainedPackageReadError> {
        if self.retired {
            return Ok(self.observe());
        }
        let data = &mut self
            .data
            .as_mut()
            .ok_or(RetainedPackageReadError::NotFrozen)?
            .as_mut_slice()[0];
        data.advance(self.scope.allocation_budget(), &mut self.work, limit)?;
        self.finished = data.current_complete && data.undo_complete;
        Ok(self.observe())
    }
    fn current_row(
        &mut self,
        index: usize,
        limit: usize,
    ) -> Result<(&PackageKey, &PackageValue), RetainedPackageReadError> {
        self.data
            .as_ref()
            .ok_or(RetainedPackageReadError::NotFrozen)?
            .as_slice()[0]
            .current_row(index, &mut self.work, limit)
    }
    fn undo_row(
        &mut self,
        index: usize,
        limit: usize,
    ) -> Result<(&PackageKey, &Option<PackageValue>), RetainedPackageReadError> {
        self.data
            .as_ref()
            .ok_or(RetainedPackageReadError::NotFrozen)?
            .as_slice()[0]
            .undo_row(index, &mut self.work, limit)
    }
}

impl StateBlock<'_> {
    /// Start on the original frozen publisher after a real publication refusal.
    /// Return the same scope on every start failure, never acquire substitute credit.
    /// This request does not validate Musubi or authorize a State root/publication.
    #[expect(
        clippy::result_large_err,
        reason = "start refusal returns the actual move-only scope without allocating an error wrapper"
    )]
    pub(crate) fn start_original_package_read(
        &mut self,
        scope: OwnedAllocationScope,
    ) -> Result<(), (OwnedAllocationScope, RetainedPackageReadError)> {
        let state_ref = self
            .fields
            .as_ref()
            .expect("original retained State fields")
            .state_ref;
        let Some(publication) = self.publication.as_mut() else {
            return Err((scope, RetainedPackageReadError::NotFrozen));
        };
        if !publication.fields_frozen
            || publication.irreversible
            || publication.published
            || publication.poisoned
            || publication.package_read.is_some()
            || publication.musubi_group_read.is_some()
        {
            return Err((scope, RetainedPackageReadError::NotFrozen));
        }
        if !scope.belongs_to(&state_ref.ivm_execution_budget()) {
            return Err((scope, RetainedPackageReadError::ScopeIdentity));
        }
        if publication.predecessor_generation != Some(state_ref.state_view_generation()) {
            return Err((scope, RetainedPackageReadError::SourceChanged));
        }
        let fields = self.fields.as_mut().expect("same original State fields");
        if fields
            .world
            .musubi_packages
            .retained_read_matches_current(&state_ref.world.musubi_packages)
            != Some(true)
        {
            return Err((scope, RetainedPackageReadError::SourceChanged));
        }
        let Some(images) = fields.world.musubi_packages.frozen_images() else {
            return Err((scope, RetainedPackageReadError::NotFrozen));
        };
        // ExactSizeIterator::len is the original stored cursor count, not a scan.
        let (current_count, undo_count) =
            (images.current_entries().len(), images.undo_entries().len());
        let mut data = match ChargedBuffer::new(1, scope.allocation_budget()) {
            Ok(data) => data,
            Err(error) => return Err((scope, RetainedPackageReadError::Allocation(error))),
        };
        let Some(source) = fields.world.musubi_packages.retain_original_readers() else {
            return Err((scope, RetainedPackageReadError::NotFrozen));
        };
        data.push_reserved(PackageReadData::new(source, current_count, undo_count));
        publication.package_read = Some(RetainedPackageRead {
            data: Some(data),
            scope,
            generation: state_ref.state_view_generation(),
            work: 0,
            finished: false,
            retired: false,
        });
        Ok(())
    }

    fn check_original_package_read(&self) -> Result<(), RetainedPackageReadError> {
        let publication = self
            .publication
            .as_ref()
            .ok_or(RetainedPackageReadError::NotFrozen)?;
        let plan = publication
            .package_read
            .as_ref()
            .ok_or(RetainedPackageReadError::NotFrozen)?;
        if publication.published || publication.poisoned || publication.irreversible {
            return Err(RetainedPackageReadError::NotFrozen);
        }
        if !plan
            .scope
            .belongs_to(&self.state_ref.ivm_execution_budget())
        {
            return Err(RetainedPackageReadError::ScopeIdentity);
        }
        let original_field = &self
            .fields
            .as_ref()
            .expect("original retained State fields")
            .world
            .musubi_packages;
        if let Some(data) = plan.data.as_ref() {
            if !original_field.retained_read_matches_source(&data.as_slice()[0].source) {
                return Err(RetainedPackageReadError::SourceChanged);
            }
        }
        if plan.generation != self.state_ref.state_view_generation()
            || self
                .fields
                .as_ref()
                .expect("original retained State fields")
                .world
                .musubi_packages
                .retained_read_matches_current(&self.state_ref.world.musubi_packages)
                != Some(true)
        {
            return Err(RetainedPackageReadError::SourceChanged);
        }
        Ok(())
    }

    /// Observe retained physical-row progress without scanning or resetting work.
    pub(crate) fn original_package_read_progress(&self) -> Option<PackageReadProgress> {
        self.publication
            .as_ref()?
            .package_read
            .as_ref()
            .map(RetainedPackageRead::observe)
    }

    /// Continue the same positions/cursors/cumulative work; successful prefixes stay.
    /// A changed ceiling is explicit caller policy, never an implicit retry reset.
    pub(crate) fn advance_original_package_read(
        &mut self,
        limit: usize,
    ) -> Result<PackageReadProgress, RetainedPackageReadError> {
        self.check_original_package_read()?;
        self.publication
            .as_mut()
            .expect("checked original publication")
            .package_read
            .as_mut()
            .expect("checked retained read")
            .advance(limit)
    }

    /// Resolve one original current position with bounded admitted structural work.
    /// The borrow cannot outlive its retained source; no get/nth/key rescan runs.
    pub(crate) fn original_package_current_row(
        &mut self,
        index: usize,
        limit: usize,
    ) -> Result<(&PackageKey, &PackageValue), RetainedPackageReadError> {
        self.check_original_package_read()?;
        self.publication
            .as_mut()
            .expect("checked original publication")
            .package_read
            .as_mut()
            .expect("checked retained read")
            .current_row(index, limit)
    }

    /// Resolve a raw original undo row; it is not the complete predecessor image.
    pub(crate) fn original_package_undo_row(
        &mut self,
        index: usize,
        limit: usize,
    ) -> Result<(&PackageKey, &Option<PackageValue>), RetainedPackageReadError> {
        self.check_original_package_read()?;
        self.publication
            .as_mut()
            .expect("checked original publication")
            .package_read
            .as_mut()
            .expect("checked retained read")
            .undo_row(index, limit)
    }

    /// Retire actual positions/cursors/readers before recovering this same field.
    /// A remaining reader keeps the same scope and paired owner for another try.
    /// There is no physical writer lock to wait for; callers retire their handles.
    pub(crate) fn retire_original_package_read(&mut self) -> Result<(), RetainedPackageReadError> {
        self.check_original_package_read()?;
        let publication = self
            .publication
            .as_mut()
            .expect("checked original publication");
        let plan = publication
            .package_read
            .as_mut()
            .expect("checked original read");
        if !plan.finished {
            return Err(RetainedPackageReadError::Incomplete);
        }
        // Drop all index and reader owners while the exact scope remains retained.
        drop(plan.data.take());
        self.fields
            .as_mut()
            .expect("original State fields")
            .world
            .musubi_packages
            .try_retire_original_readers()
            .map_err(|error| match error {
                block_field::RetainedReadPhaseError::NotFrozen => {
                    RetainedPackageReadError::NotFrozen
                }
                block_field::RetainedReadPhaseError::ReadersRetained => {
                    RetainedPackageReadError::ReadersRetained
                }
            })?;
        plan.retired = true;
        Ok(())
    }
}

#[cfg(test)]
pub(in crate::state) fn retained_package_control_layout_for_test() -> std::alloc::Layout {
    std::alloc::Layout::array::<PackageReadData>(1).expect("actual control layout")
}

/// The native adversarial control keeps the same scope with its outside reader.
/// No raw reader handle or substitute scope is exposed by the production API.
#[cfg(test)]
pub(in crate::state) struct RetainedPackageReaderForTest {
    // Actual original cursor drops before its original refund owner.
    _reader: concread::bptree::BptreeMapFrozenReader<PackageKey, PackageValue>,
    _scope: OwnedAllocationScope,
}

#[cfg(test)]
impl StateBlock<'_> {
    pub(in crate::state) fn retain_package_reader_for_test(
        &mut self,
    ) -> Result<RetainedPackageReaderForTest, RetainedPackageReadError> {
        self.check_original_package_read()?;
        let plan = self
            .publication
            .as_ref()
            .expect("original publication")
            .package_read
            .as_ref()
            .expect("original read plan");
        let data = &plan
            .data
            .as_ref()
            .ok_or(RetainedPackageReadError::NotFrozen)?
            .as_slice()[0];
        Ok(RetainedPackageReaderForTest {
            _reader: data.source.current().clone(),
            _scope: plan.scope.clone(),
        })
    }
}
